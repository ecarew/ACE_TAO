// ace-tao-setup: prepares and checks a host's ACE/TAO security
// configuration (see tao/Security_Mode.h and orbsvcs/Security/Self_Check.h).
//
//   ace-tao-setup [--conf PATH] [--marker PATH] COMMAND [options]
//
//   status                      mode, configuration, enrollment, audit, clock
//   check [--svc-conf FILE] [--json]
//                               host checks; with a service configuration,
//                               also that service's startup self-check (run
//                               in-process, no port is opened).  Exit 0 all
//                               OK, 1 warnings, 2 failures.
//   init --mode MODE [--trust-anchor-file PEM]... [--trust-anchor SHA256]...
//        [--audit-sink SINK] [--allowed-protocols LIST] [--force] [--yes]
//                               writes the security configuration
//   set-mode MODE [--yes]       changes the mode of an existing configuration
//   enroll [--yes]              marks a prod host as enrolled, so that
//                               deleting or editing the configuration cannot
//                               downgrade it
//   unenroll --reason TEXT      removes the enrollment marker
//   install [--port N] [--label-prefix P] [--root DIR] [--no-start] [--dry-run]
//                               creates directories, the service account and
//                               the service definitions, recording each in a
//                               manifest (see install.cpp)
//   uninstall [--purge] [--force] [--dry-run]
//                               undoes exactly what the manifest records
//   run --svc-conf FILE -- COMMAND...
//                               check --gate, then exec the service (launchd)
//   key create|check ...        service keys in a keystore (see keys.cpp)
//   cert request|renew ...      certificates from step-ca (see keys.cpp)
//   denylist ...                the signed deny-list (see denylist.cpp)
//   access ...                  the signed access list (see access.cpp)
//
// --conf defaults to ACE_TAO_SECURITY_CONF or TAO_SECURITY_CONF_DEFAULT,
// --marker to TAO_SECURITY_ENROLLED_MARKER (the ORB_init guard always uses
// the built-in marker path; --marker exists for testing).  Every change is
// written to the audit log.  Exit codes: 0 success, 1 warnings (check), 2
// failure or refusal, 64 usage error.

#include "install.h"
#include "keys.h"

#include "orbsvcs/Security/Audit_Logger.h"
#include "orbsvcs/Security/Self_Check.h"
#include "tao/Security_Mode.h"
#include "tao/ORB.h"
#include "tao/SystemException.h"

#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_stat.h"
#include "ace/OS_NS_time.h"
#include "ace/OS_NS_unistd.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include <map>
#include <string>
#include <vector>

using TAO::Security::Audit_Logger;
using TAO::Security::Audit_Record;
using TAO::Security::Self_Check;
namespace Reason = TAO::Security::Audit_Reason;

namespace
{
  constexpr int EXIT_OK = 0;
  constexpr int EXIT_WARN = 1;
  constexpr int EXIT_FAIL = 2;
  constexpr int EXIT_USAGE = 64;

  std::string conf_path;
  std::string marker_path;
  std::string chronyc_path;   // check --chronyc; empty: search the usual places

  char const usage_text[] =
    "usage: ace-tao-setup [--conf PATH] [--marker PATH] COMMAND [options]\n"
    "  status\n"
    "  check [--svc-conf FILE] [--json] [--gate] [--chronyc PATH]\n"
    "  init --mode dev|test|prod|embedded [--trust-anchor-file PEM]... [--trust-anchor SHA256]...\n"
    "       [--audit-sink SINK] [--allowed-protocols LIST] [--force] [--yes]\n"
    "  set-mode dev|test|prod|embedded [--yes]\n"
    "  enroll [--yes]\n"
    "  unenroll --reason TEXT\n"
    "  install [--service naming] [--port N] [--listen ADDR] [--label-prefix P] [--user NAME]\n"
    "          [--root DIR] [--bin-dir DIR] [--no-start] [--dry-run]\n"
    "  uninstall [--root DIR] [--purge] [--force] [--dry-run]\n"
    "  run --svc-conf FILE -- COMMAND [ARGS...]\n"
    "  key create --type file|pkcs11|tpm2|sep ... | key check --key SPEC ...\n"
    "  cert request --key SPEC --token-file F --out PEM ... | cert renew --key SPEC --cert PEM ...\n"
    "  denylist add|remove|sign|check|pin ...\n"
    "  access sign|check|test ...\n"
    "  user add|passwd|lock|unlock|remove|groups|list ...\n"
    "  asserters sign|check ...\n"
    "  rights|grants|roles sign|check ..., roles test|import ...   (the role model)\n"
    "  (key, cert, denylist, access, asserters, user, rights, grants or roles alone prints their options)\n"
    "  (check --gate exits 2 only on failures, 0 otherwise)\n";

  int
  usage (char const *problem = nullptr)
  {
    if (problem)
      ACE_OS::fprintf (stderr, "ace-tao-setup: %s\n", problem);
    ACE_OS::fputs (usage_text, stderr);
    return EXIT_USAGE;
  }

  int
  refuse (std::string const &why)
  {
    ACE_OS::fprintf (stderr, "ace-tao-setup: %s\n", why.c_str ());
    return EXIT_FAIL;
  }

  constexpr bool
  is_apple ()
  {
#if defined (__APPLE__)
    return true;
#else
    return false;
#endif
  }

  bool
  valid_mode (std::string const &m)
  {
    return m == "dev" || m == "test" || m == "prod" || m == "embedded";
  }

  TAO_Security_Mode::Host_Config
  host ()
  {
    return TAO_Security_Mode::read (conf_path.c_str (), marker_path.c_str ());
  }

  bool
  confirm (char const *question, bool yes)
  {
    if (yes)
      return true;
    if (!ACE_OS::isatty (ACE_STDIN))
      return false;
    ACE_OS::printf ("%s [y/N] ", question);
    ACE_OS::fflush (stdout);
    char line[16];
    return ACE_OS::fgets (line, sizeof line, stdin) != nullptr && (line[0] == 'y' || line[0] == 'Y');
  }

  /// mkdir -p for the parent directory of @a path.
  bool
  make_parent (std::string const &path)
  {
    size_t const slash = path.rfind ('/');
    if (slash == std::string::npos || slash == 0)
      return true;
    std::string const dir = path.substr (0, slash);
    ACE_stat st;
    if (ACE_OS::stat (dir.c_str (), &st) == 0)
      return true;
    if (!make_parent (dir))
      return false;
    return ACE_OS::mkdir (dir.c_str (), 0755) == 0 || errno == EEXIST;
  }

  /// Writes @a text to @a path through a temporary file and rename, so a
  /// reader never sees a half-written configuration.
  bool
  write_atomic (std::string const &path, std::string const &text, mode_t mode, std::string &error)
  {
    if (!make_parent (path))
      {
        error = "cannot create the directory for " + path + ": " + ACE_OS::strerror (errno);
        return false;
      }
    std::string const tmp = path + ".tmp." + std::to_string (static_cast<long> (ACE_OS::getpid ()));
    FILE *const fp = ACE_OS::fopen (tmp.c_str (), ACE_TEXT ("w"));
    if (fp == nullptr)
      {
        error = "cannot write " + tmp + ": " + ACE_OS::strerror (errno);
        return false;
      }
    bool ok = ACE_OS::fputs (text.c_str (), fp) >= 0;
    ok = ACE_OS::fflush (fp) == 0 && ok;
    ok = ACE_OS::fclose (fp) == 0 && ok;
    ok = ok && ::chmod (tmp.c_str (), mode) == 0;
    ok = ok && ACE_OS::rename (tmp.c_str (), path.c_str ()) == 0;
    if (!ok)
      {
        error = "cannot write " + path + ": " + ACE_OS::strerror (errno);
        ACE_OS::unlink (tmp.c_str ());
      }
    return ok;
  }

  /// Audit record for a change, written with the configuration as it now
  /// stands.
  void
  audit (char const *reason, std::map<std::string, std::string> const &fields)
  {
    Audit_Logger logger;
    Audit_Logger::Options opts = Audit_Logger::options_from_config (conf_path.c_str ());
    opts.service = "ace-tao-setup";
    logger.configure (opts);
    Audit_Record r ("secenv", true, reason);
    r.field ("uid", std::to_string (static_cast<long> (ACE_OS::getuid ())));
    for (auto const &f : fields)
      r.field (f.first.c_str (), f.second);
    logger.write (r);
    if (!logger.healthy ())
      ACE_OS::fprintf (stderr, "ace-tao-setup: warning: the audit sink did not accept the record of this change\n");
  }

  struct Anchor
  {
    std::string subject;
    std::string sha256;
  };

  bool
  read_anchors (std::string const &pem, std::vector<Anchor> &out, std::string &error)
  {
    FILE *const fp = ACE_OS::fopen (pem.c_str (), ACE_TEXT ("r"));
    if (fp == nullptr)
      {
        error = "cannot read " + pem + ": " + ACE_OS::strerror (errno);
        return false;
      }
    size_t const before = out.size ();
    X509 *cert = nullptr;
    while ((cert = ::PEM_read_X509 (fp, nullptr, nullptr, nullptr)) != nullptr)
      {
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        ::X509_digest (cert, ::EVP_sha256 (), md, &len);
        char name[256];
        ::X509_NAME_oneline (::X509_get_subject_name (cert), name, sizeof name);
        ::X509_free (cert);
        std::string hex;
        char two[4];
        for (unsigned int i = 0; i < len; ++i)
          {
            ACE_OS::snprintf (two, sizeof two, "%02X", md[i]);
            if (i)
              hex += ':';
            hex += two;
          }
        out.push_back ({name, hex});
      }
    ACE_OS::fclose (fp);
    ::ERR_clear_error ();
    if (out.size () == before)
      {
        error = "no certificates in " + pem;
        return false;
      }
    return true;
  }

  /// The configuration's lines, so a rewrite keeps keys it does not set.
  std::vector<std::string>
  read_lines (std::string const &path)
  {
    std::vector<std::string> lines;
    FILE *const fp = ACE_OS::fopen (path.c_str (), ACE_TEXT ("r"));
    if (fp == nullptr)
      return lines;
    char buf[1024];
    while (ACE_OS::fgets (buf, sizeof buf, fp) != nullptr)
      {
        std::string l (buf);
        if (!l.empty () && l.back () == '\n')
          l.pop_back ();
        lines.push_back (l);
      }
    ACE_OS::fclose (fp);
    return lines;
  }

  std::string
  line_key (std::string const &line)
  {
    std::string l = line.substr (0, line.find ('#'));
    size_t const eq = l.find ('=');
    if (eq == std::string::npos)
      return std::string ();
    l = l.substr (0, eq);
    size_t const b = l.find_first_not_of (" \t");
    size_t const e = l.find_last_not_of (" \t");
    return b == std::string::npos ? std::string () : l.substr (b, e - b + 1);
  }

  /// Sets @a key in @a lines, replacing an existing line or appending.
  void
  set_key (std::vector<std::string> &lines, std::string const &key, std::string const &value)
  {
    for (auto &l : lines)
      if (line_key (l) == key)
        {
          l = key + " = " + value;
          return;
        }
    lines.push_back (key + " = " + value);
  }

  std::string
  join (std::vector<std::string> const &lines)
  {
    std::string s;
    for (auto const &l : lines)
      s += l + "\n";
    return s;
  }

  // ------------------------------------------------------------------
  // check

  struct Finding
  {
    std::string name;
    Self_Check::Status status;
    std::string detail;
  };

  char const *
  status_word (Self_Check::Status s)
  {
    return s == Self_Check::CHECK_OK ? "OK" : s == Self_Check::CHECK_WARN ? "WARN" : "FAIL";
  }

  std::string
  json_escape (std::string const &s)
  {
    std::string o;
    for (char const c : s)
      {
        if (c == '"' || c == '\\')
          {
            o += '\\';
            o += c;
          }
        else if (static_cast<unsigned char> (c) < 0x20)
          o += ' ';
        else
          o += c;
      }
    return o;
  }

  std::vector<Finding>
  host_findings (TAO_Security_Mode::Host_Config const &h)
  {
    std::vector<Finding> f;
    bool const prod = h.mode == TAO_Security_Mode::MODE_PROD;
    Self_Check::Status const bad = prod ? Self_Check::CHECK_FAIL : Self_Check::CHECK_WARN;

    if (h.mode == TAO_Security_Mode::MODE_INVALID)
      {
        f.push_back ({"config", Self_Check::CHECK_FAIL, h.error + " (" + h.path + ")"});
        return f;
      }
    if (!h.found)
      {
        f.push_back ({"config", Self_Check::CHECK_WARN,
                      "no security configuration at " + h.path + ": stock TAO, no checks (run init)"});
        return f;
      }
    f.push_back ({"config", Self_Check::CHECK_OK,
                  std::string ("mode=") + TAO_Security_Mode::name (h.mode) + " (" + h.path + ")"});

    ACE_stat st;
    if (ACE_OS::stat (h.path.c_str (), &st) == 0 && st.st_uid != 0)
      f.push_back ({"config_owner", Self_Check::CHECK_WARN,
                    h.path + " is owned by uid " + std::to_string (st.st_uid) + ", not root"});

    if (h.enrolled)
      f.push_back ({"enrollment", Self_Check::CHECK_OK, "enrolled in prod (" + marker_path + ")"});
    else if (prod)
      f.push_back ({"enrollment", Self_Check::CHECK_WARN,
                    "prod host not enrolled: removing or editing the configuration would downgrade it (run enroll)"});

    if (h.mode == TAO_Security_Mode::MODE_DEV || h.mode == TAO_Security_Mode::MODE_EMBEDDED)
      return f;   // These modes run no security checks.

    Audit_Logger logger;
    Audit_Logger::Options opts = Audit_Logger::options_from_config (h.path.c_str ());
    opts.service = "ace-tao-setup";
    logger.configure (opts);
    bool const audit_ok = logger.self_test ();
    f.push_back ({"audit", audit_ok ? Self_Check::CHECK_OK : bad,
                  (audit_ok ? "sink " : "sink does not accept records: ") + opts.sink});

    long err = 0;
    int const synced = Self_Check::clock_synchronized (err);
    long max_err = 1000;
    if (!h.get ("max_clock_error").empty ())
      max_err = ACE_OS::atoi (h.get ("max_clock_error").c_str ());
    if (synced < 0)
      f.push_back ({"time", Self_Check::CHECK_WARN, "cannot read the kernel clock state on this platform"});
    else if (synced == 1 && err <= max_err)
      f.push_back ({"time", Self_Check::CHECK_OK, "synchronized, error estimate " + std::to_string (err) + " ms"});
    else
      f.push_back ({"time", bad, "clock not synchronized or error estimate " + std::to_string (err)
                                 + " ms above max_clock_error " + std::to_string (max_err) + " ms"});

    // Authenticated time (NTS, RFC 8915): plain NTP can be spoofed to make
    // an expired certificate look valid.  chrony reports, per source,
    // whether NTS authenticates it.  Missing NTS warns; with
    // require_nts = yes it is as bad as unsynchronized time.
    {
      Self_Check::Status const nts_bad = h.get ("require_nts") == "yes" ? bad : Self_Check::CHECK_WARN;
      std::vector<std::string> candidates;
      if (!chronyc_path.empty ())
        candidates.push_back (chronyc_path);
      else
        candidates = {"/usr/bin/chronyc", "/usr/sbin/chronyc", "/opt/homebrew/bin/chronyc", "/usr/local/bin/chronyc"};
      std::string chronyc;
      for (auto const &c : candidates)
        if (ACE_OS::access (c.c_str (), X_OK) == 0 && c.find ('\'') == std::string::npos)
          {
            chronyc = c;
            break;
          }
      if (chronyc.empty ())
        f.push_back ({"nts", nts_bad, std::string ("cannot verify authenticated time: chrony not found")
                                      + (is_apple () ? " (the macOS time service does not support NTS)" : "")});
      else
        {
          int sources = 0, nts = 0;
          FILE *const pp = ::popen (("'" + chronyc + "' -c -n authdata 2>/dev/null").c_str (), "r");
          int rc = -1;
          if (pp != nullptr)
            {
              char line[512];
              while (ACE_OS::fgets (line, sizeof line, pp) != nullptr)
                {
                  std::string const l (line);
                  size_t const c1 = l.find (',');
                  if (c1 == std::string::npos)
                    continue;
                  ++sources;
                  size_t const c2 = l.find (',', c1 + 1);
                  if (l.substr (c1 + 1, c2 == std::string::npos ? std::string::npos : c2 - c1 - 1) == "NTS")
                    ++nts;
                }
              rc = ::pclose (pp);
            }
          if (rc != 0)
            f.push_back ({"nts", nts_bad, chronyc + " could not report its sources (is chronyd running?)"});
          else if (nts > 0)
            f.push_back ({"nts", Self_Check::CHECK_OK, "chrony: " + std::to_string (nts) + " of "
                                                       + std::to_string (sources) + " source(s) use NTS"});
          else
            f.push_back ({"nts", nts_bad, "chrony has no NTS sources (" + std::to_string (sources)
                                          + " plain NTP); add the nts option to its server lines"});
        }
    }

    if (h.get ("trust_anchor_sha256").empty ())
      f.push_back ({"trust_anchors", bad, "trust_anchor_sha256 is not set (init --trust-anchor-file CA.pem)"});
    else
      f.push_back ({"trust_anchors", Self_Check::CHECK_OK, h.get ("trust_anchor_sha256")});
    return f;
  }

  int
  cmd_check (int argc, ACE_TCHAR *argv[], char const *prog)
  {
    std::string svc_conf;
    bool json = false, gate = false;
    for (int i = 0; i < argc; ++i)
      {
        std::string const a = ACE_TEXT_ALWAYS_CHAR (argv[i]);
        if (a == "--json")
          json = true;
        else if (a == "--gate")
          gate = true;
        else if (a == "--chronyc" && i + 1 < argc)
          chronyc_path = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--svc-conf" && i + 1 < argc)
          svc_conf = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else
          return usage (("check: unknown option " + a).c_str ());
      }

    TAO_Security_Mode::Host_Config const h = host ();
    std::vector<Finding> findings = host_findings (h);

    if (!svc_conf.empty ())
      {
        // Run the service's own startup checks: the ORB_init guard and
        // the plugin self-check read the host configuration from the
        // environment, so point it at the one being checked.
        ACE_OS::setenv ("ACE_TAO_SECURITY_CONF", conf_path.c_str (), 1);
        std::string const p (prog);
        std::string const opt ("-ORBSvcConf");
        char *orb_argv[] = { const_cast<char *> (p.c_str ()), const_cast<char *> (opt.c_str ()),
                             const_cast<char *> (svc_conf.c_str ()), nullptr };
        int orb_argc = 3;
        try
          {
            CORBA::ORB_var orb = CORBA::ORB_init (orb_argc, orb_argv, "ace-tao-setup-check");
            findings.push_back ({"service", Self_Check::CHECK_OK, "startup checks passed for " + svc_conf});
            orb->destroy ();
          }
        catch (CORBA::INITIALIZE const &)
          {
            findings.push_back ({"service", Self_Check::CHECK_FAIL,
                                 "the service would refuse to start with " + svc_conf + " (reason above)"});
          }
        catch (CORBA::Exception const &ex)
          {
            findings.push_back ({"service", Self_Check::CHECK_FAIL,
                                 std::string ("ORB_init failed with ") + ex._name ()});
          }
        for (auto const &r : Self_Check::last_results ())
          findings.push_back ({"service." + r.name, r.status, r.detail});
      }

    int worst = EXIT_OK;
    for (auto const &f : findings)
      if (f.status == Self_Check::CHECK_FAIL)
        worst = EXIT_FAIL;
      else if (f.status == Self_Check::CHECK_WARN && worst == EXIT_OK)
        worst = EXIT_WARN;

    if (json)
      {
        ACE_OS::printf ("{\"mode\":\"%s\",\"conf\":\"%s\",\"result\":\"%s\",\"checks\":[",
                        TAO_Security_Mode::name (h.mode), json_escape (h.path).c_str (),
                        worst == EXIT_OK ? "ok" : worst == EXIT_WARN ? "warn" : "fail");
        for (size_t i = 0; i < findings.size (); ++i)
          ACE_OS::printf ("%s{\"name\":\"%s\",\"status\":\"%s\",\"detail\":\"%s\"}", i ? "," : "",
                          json_escape (findings[i].name).c_str (), status_word (findings[i].status),
                          json_escape (findings[i].detail).c_str ());
        ACE_OS::printf ("]}\n");
      }
    else
      for (auto const &f : findings)
        ACE_OS::printf ("%-5s %-22s %s\n", status_word (f.status), f.name.c_str (), f.detail.c_str ());
    return gate ? setup_gate_status (worst) : worst;
  }

  // ------------------------------------------------------------------

  int
  cmd_status ()
  {
    TAO_Security_Mode::Host_Config const h = host ();
    ACE_OS::printf ("configuration  %s (%s)\n", h.path.c_str (),
                    h.found ? "present" : "absent");
    ACE_OS::printf ("mode           %s%s%s\n", TAO_Security_Mode::name (h.mode),
                    h.error.empty () ? "" : ": ", h.error.c_str ());
    ACE_OS::printf ("enrolled       %s (%s)\n", h.enrolled ? "yes" : "no", marker_path.c_str ());
    if (h.found)
      {
        std::string const sum = Self_Check::sha256_file (h.path.c_str ());
        ACE_OS::printf ("sha256         %s\n", sum.c_str ());
        Audit_Logger::Options const o = Audit_Logger::options_from_config (h.path.c_str ());
        ACE_OS::printf ("audit sink     %s\n", o.sink.c_str ());
        ACE_OS::printf ("trust anchors  %s\n", h.get ("trust_anchor_sha256", "(none)").c_str ());
      }
    long err = 0;
    int const s = Self_Check::clock_synchronized (err);
    ACE_OS::printf ("clock          %s (error estimate %ld ms)\n",
                    s == 1 ? "synchronized" : s == 0 ? "NOT synchronized" : "unknown", err);
    return h.mode == TAO_Security_Mode::MODE_INVALID ? EXIT_FAIL : EXIT_OK;
  }

  int
  cmd_init (int argc, ACE_TCHAR *argv[])
  {
    std::string mode, sink, protocols;
    std::vector<std::string> anchor_files, anchors;
    bool force = false, yes = false;
    for (int i = 0; i < argc; ++i)
      {
        std::string const a = ACE_TEXT_ALWAYS_CHAR (argv[i]);
        auto value = [&] () -> std::string { return i + 1 < argc ? ACE_TEXT_ALWAYS_CHAR (argv[++i]) : ""; };
        if (a == "--mode")
          mode = value ();
        else if (a == "--trust-anchor-file")
          anchor_files.push_back (value ());
        else if (a == "--trust-anchor")
          anchors.push_back (value ());
        else if (a == "--audit-sink")
          sink = value ();
        else if (a == "--allowed-protocols")
          protocols = value ();
        else if (a == "--force")
          force = true;
        else if (a == "--yes")
          yes = true;
        else
          return usage (("init: unknown option " + a).c_str ());
      }
    if (!valid_mode (mode))
      return usage ("init: --mode must be dev, test, prod or embedded");

    TAO_Security_Mode::Host_Config const h = host ();
    if (h.found && !force)
      return refuse (conf_path + " exists (mode " + TAO_Security_Mode::name (h.mode)
                     + "); use set-mode, or init --force to rewrite it");
    if (h.enrolled && mode != "prod")
      return refuse ("this host is enrolled in prod (" + marker_path + "); mode " + mode
                     + " is refused until it is unenrolled");

    std::vector<Anchor> found;
    for (auto const &file : anchor_files)
      {
        std::string error;
        if (!read_anchors (file, found, error))
          return refuse (error);
      }
    for (auto const &a : anchors)
      found.push_back ({"(given on the command line)", a});
    if (!found.empty ())
      {
        ACE_OS::printf ("Trust anchors (root CAs this host will accept):\n");
        for (auto const &a : found)
          ACE_OS::printf ("  %s\n    sha256 %s\n", a.subject.c_str (), a.sha256.c_str ());
        if (!confirm ("Check these fingerprints against the CA's published ones. Trust them?", yes))
          return refuse ("trust anchors not confirmed (pass --yes to confirm non-interactively)");
      }
    else if (mode == "prod" || mode == "test")
      ACE_OS::fprintf (stderr, "ace-tao-setup: warning: no trust anchors given; SSLIOP services will fail "
                               "their self-check until trust_anchor_sha256 is set\n");

    std::vector<std::string> lines = force ? read_lines (conf_path) : std::vector<std::string> ();
    if (lines.empty ())
      {
        lines.push_back ("# ACE/TAO host security configuration (see tao/Security_Mode.h).");
        lines.push_back ("# Written by ace-tao-setup init on " + setup_iso_time () + ".");
      }
    set_key (lines, "mode", mode);
    if (!found.empty ())
      {
        std::string list;
        for (auto const &a : found)
          (list.empty () ? list : list += ",") += a.sha256;
        set_key (lines, "trust_anchor_sha256", list);
      }
    if (!sink.empty ())
      set_key (lines, "audit_sink", sink);
    if (!protocols.empty ())
      set_key (lines, "allowed_protocols", protocols);

    std::string error;
    if (!write_atomic (conf_path, join (lines), 0644, error))
      return refuse (error);

    TAO_Security_Mode::Host_Config const after = host ();
    if (after.mode == TAO_Security_Mode::MODE_INVALID)
      return refuse ("the written configuration is not valid: " + after.error);
    audit (Reason::MODE_SET, {{"old_mode", h.found ? TAO_Security_Mode::name (h.mode) : "none"},
                              {"new_mode", mode},
                              {"conf_sha256", Self_Check::sha256_file (conf_path.c_str ())}});
    ACE_OS::printf ("Wrote %s (mode %s).\n", conf_path.c_str (), mode.c_str ());
    if (mode == "prod")
      ACE_OS::printf ("Next: ace-tao-setup check --svc-conf <service.conf> for each service, then ace-tao-setup enroll.\n");
    else
      ACE_OS::printf ("Next: ace-tao-setup check --svc-conf <service.conf> for each service.\n");
    return EXIT_OK;
  }

  int
  cmd_set_mode (int argc, ACE_TCHAR *argv[])
  {
    if (argc < 1)
      return usage ("set-mode: give a mode");
    std::string const mode = ACE_TEXT_ALWAYS_CHAR (argv[0]);
    bool yes = false;
    for (int i = 1; i < argc; ++i)
      if (ACE_OS::strcmp (argv[i], ACE_TEXT ("--yes")) == 0)
        yes = true;
      else
        return usage ("set-mode: unknown option");
    if (!valid_mode (mode))
      return usage ("set-mode: mode must be dev, test, prod or embedded");

    TAO_Security_Mode::Host_Config const h = host ();
    if (!h.found)
      return refuse (conf_path + " does not exist; run init");
    if (h.enrolled && mode != "prod")
      return refuse ("this host is enrolled in prod (" + marker_path + "); run unenroll first (it is audited)");
    std::string const old = h.get ("mode");
    if (old == mode)
      {
        ACE_OS::printf ("Mode is already %s.\n", mode.c_str ());
        return EXIT_OK;
      }
    if (old == "prod" && !confirm (("Leave prod for " + mode + "? Prod checks will no longer be enforced.").c_str (), yes))
      return refuse ("leaving prod not confirmed (pass --yes)");

    std::vector<std::string> lines = read_lines (conf_path);
    set_key (lines, "mode", mode);
    std::string error;
    if (!write_atomic (conf_path, join (lines), 0644, error))
      return refuse (error);
    audit (Reason::MODE_SET, {{"old_mode", old.empty () ? "none" : old}, {"new_mode", mode},
                              {"conf_sha256", Self_Check::sha256_file (conf_path.c_str ())}});
    ACE_OS::printf ("Mode changed from %s to %s in %s. Restart services to apply it.\n",
                    old.empty () ? "(none)" : old.c_str (), mode.c_str (), conf_path.c_str ());
    return EXIT_OK;
  }

  int
  cmd_enroll (int argc, ACE_TCHAR *argv[])
  {
    bool yes = false;
    for (int i = 0; i < argc; ++i)
      if (ACE_OS::strcmp (argv[i], ACE_TEXT ("--yes")) == 0)
        yes = true;
      else
        return usage ("enroll: unknown option");

    TAO_Security_Mode::Host_Config const h = host ();
    if (h.enrolled)
      {
        ACE_OS::printf ("Already enrolled (%s).\n", marker_path.c_str ());
        return EXIT_OK;
      }
    if (h.mode != TAO_Security_Mode::MODE_PROD)
      return refuse ("only a host in mode prod can be enrolled (mode is "
                     + std::string (TAO_Security_Mode::name (h.mode)) + ")");
    for (auto const &f : host_findings (h))
      if (f.status == Self_Check::CHECK_FAIL)
        return refuse ("host check failed: " + f.name + ": " + f.detail);
    if (!confirm ("Enroll this host in prod? Only an audited unenroll can undo it.", yes))
      return refuse ("enrollment not confirmed (pass --yes)");

    std::string const sum = Self_Check::sha256_file (conf_path.c_str ());
    std::string error;
    if (!write_atomic (marker_path, "enrolled " + setup_iso_time () + " uid "
                       + std::to_string (static_cast<long> (ACE_OS::getuid ())) + " conf " + conf_path
                       + " sha256 " + sum + "\n", 0644, error))
      return refuse (error);
    audit (Reason::HOST_ENROLLED, {{"marker", marker_path}, {"conf_sha256", sum}});
    ACE_OS::printf ("Enrolled: %s. Every mode but prod, or a missing configuration, is now refused.\n",
                    marker_path.c_str ());
    return EXIT_OK;
  }

  int
  cmd_unenroll (int argc, ACE_TCHAR *argv[])
  {
    std::string reason;
    for (int i = 0; i < argc; ++i)
      if (ACE_OS::strcmp (argv[i], ACE_TEXT ("--reason")) == 0 && i + 1 < argc)
        reason = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
      else
        return usage ("unenroll: unknown option");
    if (reason.empty ())
      return usage ("unenroll: --reason TEXT is required (it goes into the audit log)");

    TAO_Security_Mode::Host_Config const h = host ();
    if (!h.enrolled)
      {
        ACE_OS::printf ("Not enrolled (%s).\n", marker_path.c_str ());
        return EXIT_OK;
      }
    if (ACE_OS::unlink (marker_path.c_str ()) != 0)
      return refuse ("cannot remove " + marker_path + ": " + ACE_OS::strerror (errno));
    audit (Reason::HOST_UNENROLLED, {{"marker", marker_path}, {"justification", reason}});
    ACE_OS::printf ("Unenrolled: %s removed.\n", marker_path.c_str ());
    return EXIT_OK;
  }
}

std::string
setup_iso_time (time_t t)
{
  if (t == 0)
    t = ACE_OS::time (nullptr);
  struct tm tm_buf;
  char buf[32] = "";
  if (ACE_OS::gmtime_r (&t, &tm_buf) != nullptr)
    ACE_OS::strftime (buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
  return buf;
}

void
setup_audit (char const *reason, std::map<std::string, std::string> const &fields)
{
  audit (reason, fields);
}

std::string
setup_conf_get (char const *key, char const *fallback)
{
  return host ().get (key, fallback);
}

int
ACE_TMAIN (int argc, ACE_TCHAR *argv[])
{
  char const *const prog = ACE_TEXT_ALWAYS_CHAR (argv[0]);
  int i = 1;
  for (; i < argc; ++i)
    {
      std::string const a = ACE_TEXT_ALWAYS_CHAR (argv[i]);
      if (a == "--conf" && i + 1 < argc)
        conf_path = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
      else if (a == "--marker" && i + 1 < argc)
        marker_path = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
      else if (a == "-h" || a == "--help")
        {
          ACE_OS::fputs (usage_text, stdout);
          return EXIT_OK;
        }
      else
        break;
    }
  if (conf_path.empty ())
    {
      char const *const env = ACE_OS::getenv ("ACE_TAO_SECURITY_CONF");
      conf_path = (env && *env) ? env : TAO_SECURITY_CONF_DEFAULT;
    }
  if (marker_path.empty ())
    marker_path = TAO_SECURITY_ENROLLED_MARKER;
  if (i >= argc)
    return usage ();

  std::string const cmd = ACE_TEXT_ALWAYS_CHAR (argv[i]);
  int const rest = argc - i - 1;
  ACE_TCHAR **const args = argv + i + 1;
  if (cmd == "status")
    return rest == 0 ? cmd_status () : usage ("status takes no options");
  if (cmd == "check")
    return cmd_check (rest, args, prog);
  if (cmd == "init")
    return cmd_init (rest, args);
  if (cmd == "set-mode")
    return cmd_set_mode (rest, args);
  if (cmd == "enroll")
    return cmd_enroll (rest, args);
  if (cmd == "unenroll")
    return cmd_unenroll (rest, args);
  if (cmd == "install")
    return setup_install (rest, args, prog);
  if (cmd == "uninstall")
    return setup_uninstall (rest, args);
  if (cmd == "key")
    return setup_key (rest, args);
  if (cmd == "cert")
    return setup_cert (rest, args);
  if (cmd == "denylist")
    return setup_denylist (rest, args);
  if (cmd == "access")
    return setup_access (rest, args);
  if (cmd == "user")
    return setup_user (rest, args);
  if (cmd == "asserters")
    return setup_asserters (rest, args);
  if (cmd == "rights" || cmd == "grants" || cmd == "roles")
    return setup_tables (cmd.c_str (), rest, args);
  if (cmd == "run")
    return setup_run (rest, args, prog, conf_path.c_str ());
  return usage (("unknown command " + cmd).c_str ());
}
