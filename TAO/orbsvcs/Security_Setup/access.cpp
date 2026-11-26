// ace-tao-setup access: sign, check and try out the access list that
// SSLIOP services decide identified callers with (see
// orbsvcs/SSLIOP/SSLIOP_Access_List.h for the format and the
// security.conf keys).
//
//   access sign  --key SPEC [--password-file F] [--file LIST] [--bump]
//   access check [--file LIST] [--signer PEM]
//   access test  --principal P --object PATH [--op OP] [--file LIST] [--signer PEM]
//   asserters sign  --key SPEC [--password-file F] [--file LIST] [--bump]
//   asserters check [--file LIST] [--signer PEM]
//
// The list is edited by hand.  sign checks its syntax and signs it into
// LIST.sig; --bump first sets its version to the next number and issued
// to now.  check verifies a list as a service would and prints its
// rules.  test verifies it and says what it decides for one request
// (exit 0 allowed, 2 refused).  LIST defaults to access_list in the
// security configuration; the signer to access_list_signer, else
// denylist_signer.  The signer's pin is printed by "denylist pin".
//
// "asserters" does the same for the CSIv2 asserter list
// (orbsvcs/SSLIOP/SSLIOP_Asserter_List.h): csiv2_asserters,
// csiv2_asserters_signer and csiv2_asserters_signer_sha256, each falling
// back to the deny-list's.

#include "keys.h"

#include "orbsvcs/SSLIOP/SSLIOP_Access_List.h"
#include "orbsvcs/SSLIOP/SSLIOP_Asserter_List.h"
#include "orbsvcs/SSLIOP/SSLIOP_Deny_List.h"
#include "orbsvcs/SSLIOP/SSLIOP_Signed_File.h"
#include "orbsvcs/Security/Audit_Logger.h"

#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_time.h"

#include <openssl/evp.h>

#include <memory>
#include <cctype>

using TAO::SSLIOP::Access_List;
using TAO::SSLIOP::Asserter_List;
using TAO::SSLIOP::Deny_List;
namespace Signed_File = TAO::SSLIOP::Signed_File;
namespace Reason = TAO::Security::Audit_Reason;

namespace
{
  constexpr int EXIT_OK = 0;
  constexpr int EXIT_FAIL = 2;
  constexpr int EXIT_USAGE = 64;

  char const usage_text[] =
    "usage: ace-tao-setup access sign  --key SPEC [--password-file F] [--file LIST] [--bump]\n"
    "       ace-tao-setup access check [--file LIST] [--signer PEM]\n"
    "       ace-tao-setup access test  --principal P --object PATH [--op OP] [--file LIST] [--signer PEM]\n"
    "  LIST defaults to access_list in the security configuration, PEM to access_list_signer\n"
    "  (else denylist_signer).  The list is signed into LIST.sig; --bump sets the next version\n"
    "  and the current time first.  test exits 0 if the request is allowed, 2 if refused.\n"
    "       ace-tao-setup asserters sign  --key SPEC [--password-file F] [--file LIST] [--bump]\n"
    "       ace-tao-setup asserters check [--file LIST] [--signer PEM]\n"
    "  The CSIv2 asserter list, the same way: LIST defaults to csiv2_asserters, PEM to\n"
    "  csiv2_asserters_signer (else denylist_signer).\n";

  int
  usage (std::string const &problem)
  {
    if (!problem.empty ())
      ACE_OS::fprintf (stderr, "ace-tao-setup: %s\n", problem.c_str ());
    ACE_OS::fputs (usage_text, stderr);
    return EXIT_USAGE;
  }

  int
  refuse (std::string const &why)
  {
    ACE_OS::fprintf (stderr, "ace-tao-setup: %s\n", why.c_str ());
    return EXIT_FAIL;
  }

  struct Free_PKEY { void operator() (EVP_PKEY *p) const { ::EVP_PKEY_free (p); } };
  using PKEY = std::unique_ptr<EVP_PKEY, Free_PKEY>;

  std::string
  lower (std::string s)
  {
    for (char &c : s)
      c = static_cast<char> (::tolower (static_cast<unsigned char> (c)));
    return s;
  }

  struct Options
  {
    std::string file, key, password_file, signer, principal, object, op;
    bool bump = false;
    bool asserters = false;   ///< the asserter list, not the access list
  };

  int
  parse (int argc, ACE_TCHAR *argv[], Options &o, std::string const &cmd)
  {
    std::string const what = o.asserters ? "asserters " : "access ";
    for (int i = 0; i < argc; ++i)
      {
        std::string const a = ACE_TEXT_ALWAYS_CHAR (argv[i]);
        bool const more = i + 1 < argc;
        if (a == "--file" && more) o.file = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--key" && more) o.key = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--password-file" && more) o.password_file = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--signer" && more) o.signer = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--principal" && more) o.principal = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--object" && more) o.object = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--op" && more) o.op = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--bump") o.bump = true;
        else
          return usage (what + cmd + ": unknown option " + a);
      }
    char const *const file_key = o.asserters ? "csiv2_asserters" : "access_list";
    char const *const signer_key = o.asserters ? "csiv2_asserters_signer" : "access_list_signer";
    if (o.file.empty ())
      o.file = setup_conf_get (file_key);
    if (o.signer.empty ())
      o.signer = setup_conf_get (signer_key, setup_conf_get ("denylist_signer").c_str ());
    return EXIT_OK;
  }

  /// The pinned signer for the list, lower-case, or "".
  std::string
  pinned (Options const &o)
  {
    return lower (setup_conf_get (o.asserters ? "csiv2_asserters_signer_sha256" : "access_list_signer_sha256",
                                  setup_conf_get ("denylist_signer_sha256").c_str ()));
  }

  /// Parses either list; @a count and @a version describe it.
  bool
  parse_list (Options const &o, std::string const &text, long &version, std::string &issued, size_t &count,
              std::string &error)
  {
    if (o.asserters)
      {
        Asserter_List::Content c;
        if (!Asserter_List::parse (text, c, error))
          return false;
        version = c.version;
        issued = c.issued;
        count = c.entries.size ();
        return true;
      }
    Access_List::Content c;
    if (!Access_List::parse (text, c, error))
      return false;
    version = c.version;
    issued = c.issued;
    count = c.rules.size ();
    return true;
  }

  /// Sets "version N+1" and "issued NOW" in @a text, keeping every other line.
  bool
  bump (std::string &text, long &version, std::string &error)
  {
    std::string out;
    bool saw_version = false, saw_issued = false;
    for (size_t p = 0; p < text.size (); )
      {
        size_t e = text.find ('\n', p);
        if (e == std::string::npos)
          e = text.size ();
        std::string line = text.substr (p, e - p);
        p = e + 1;
        std::string key, value;
        if (Signed_File::split_line (line, key, value))
          {
            if (key == "version")
              {
                version = ACE_OS::strtol (value.c_str (), nullptr, 10) + 1;
                line = "version " + std::to_string (version);
                saw_version = true;
              }
            else if (key == "issued")
              {
                line = "issued " + setup_iso_time ();
                saw_issued = true;
              }
          }
        out += line + "\n";
      }
    if (!saw_version || !saw_issued)
      {
        error = "the list has no version or issued line to bump";
        return false;
      }
    text = out;
    return true;
  }

  /// Reads and verifies LIST as a service would; prints nothing.
  bool
  load_verified (Options const &o, Access_List::Content &c, std::string &error)
  {
    if (o.file.empty () || o.signer.empty ())
      {
        error = "--file and --signer are required (or access_list and access_list_signer / denylist_signer)";
        return false;
      }
    std::string text;
    if (!Signed_File::read_verified (o.file, o.signer, pinned (o), text, error))
      return false;
    if (!Access_List::parse (text, c, error))
      {
        error = o.file + ": " + error;
        return false;
      }
    return true;
  }

  int
  cmd_sign (int argc, ACE_TCHAR *argv[], bool asserters = false)
  {
    Options o;
    o.asserters = asserters;
    if (int const rc = parse (argc, argv, o, "sign"))
      return rc;
    if (o.file.empty () || o.key.empty ())
      return usage (o.asserters ? "asserters sign: --file (or csiv2_asserters in the configuration) and --key are required"
                                : "access sign: --file (or access_list in the configuration) and --key are required");
    std::string text, error;
    if (!Signed_File::slurp (o.file, text))
      return refuse ("cannot read " + o.file);
    long version = 0;
    if (o.bump && !bump (text, version, error))
      return refuse (o.file + ": " + error);
    long list_version = 0;
    std::string issued;
    size_t count = 0;
    if (!parse_list (o, text, list_version, issued, count, error))
      return refuse (o.file + ": " + error);

    std::string password;
    if (!o.password_file.empty () && !setup_read_password (o.password_file, password, error))
      return refuse (error);
    PKEY key (setup_load_key (o.key, password, error));
    if (!key)
      return refuse (error);
    std::string const want = pinned (o);
    if (!want.empty () && Deny_List::spki_sha256 (key.get ()) != want)
      return refuse (std::string ("the key is not the pinned ") + (o.asserters ? "asserter-list" : "access-list")
                     + " signer (" + want + ")");

    std::string sig;
    if (!setup_sign_text (key.get (), text, sig, error))
      return refuse (error);
    PKEY pub (setup_public_key (key.get ()));
    if (!pub || !Deny_List::verify (text, sig, pub.get (), error))
      return refuse ("the new signature does not verify: " + error);
    if (!setup_write_atomic (o.file + ".sig", sig, 0644, error) || !setup_write_atomic (o.file, text, 0644, error))
      return refuse (error);
    char const *const unit = o.asserters ? "asserter(s)" : "rule(s)";
    setup_audit (o.asserters ? Reason::ASSERTER_LIST_SIGNED : Reason::ACCESS_LIST_SIGNED,
                 {{"file", o.file}, {"version", std::to_string (list_version)},
                  {o.asserters ? "asserters" : "rules", std::to_string (count)}});
    ACE_OS::printf ("%s: version %ld issued %s, %zu %s; signed into %s.sig\n",
                    o.file.c_str (), list_version, issued.c_str (), count, unit, o.file.c_str ());
    return EXIT_OK;
  }

  int
  cmd_check_asserters (Options const &o)
  {
    if (o.file.empty () || o.signer.empty ())
      return refuse ("--file and --signer are required (or csiv2_asserters and csiv2_asserters_signer / denylist_signer)");
    std::string text, error;
    Asserter_List::Content c;
    if (!Signed_File::read_verified (o.file, o.signer, pinned (o), text, error))
      return refuse (error);
    if (!Asserter_List::parse (text, c, error))
      return refuse (o.file + ": " + error);
    long const age = static_cast<long> ((ACE_OS::time (nullptr) - c.issued_time) / 86400);
    std::string const want = pinned (o);
    ACE_OS::printf ("OK: %s version %ld issued %s (%ld day(s) ago), %zu asserter(s)\n",
                    o.file.c_str (), c.version, c.issued.c_str (), age, c.entries.size ());
    ACE_OS::printf ("Signer %s%s\n", o.signer.c_str (),
                    want.empty () ? " (not pinned: set csiv2_asserters_signer_sha256 or denylist_signer_sha256)"
                                  : " (pinned)");
    for (auto const &e : c.entries)
      {
        std::string realms;
        for (auto const &r : e.realms)
          realms += (realms.empty () ? "" : ",") + r;
        ACE_OS::printf ("  %s types=%s realms=%s\n", e.principal.c_str (), Asserter_List::type_names (e.types).c_str (),
                        realms.empty () ? "(the service's gssup_target)" : realms.c_str ());
      }
    return EXIT_OK;
  }

  int
  cmd_check (int argc, ACE_TCHAR *argv[], bool asserters = false)
  {
    Options o;
    o.asserters = asserters;
    if (int const rc = parse (argc, argv, o, "check"))
      return rc;
    if (o.asserters)
      return cmd_check_asserters (o);
    Access_List::Content c;
    std::string error;
    if (!load_verified (o, c, error))
      return refuse (error);
    long const age = static_cast<long> ((ACE_OS::time (nullptr) - c.issued_time) / 86400);
    std::string const want = pinned (o);
    ACE_OS::printf ("OK: %s version %ld issued %s (%ld day(s) ago), %zu rule(s)\n",
                    o.file.c_str (), c.version, c.issued.c_str (), age, c.rules.size ());
    ACE_OS::printf ("Signer %s%s\n", o.signer.c_str (),
                    want.empty () ? " (not pinned: set access_list_signer_sha256 or denylist_signer_sha256)"
                                  : " (pinned)");
    for (auto const &r : c.rules)
      {
        std::string ops;
        for (auto const &op : r.operations)
          ops += " " + op;
        ACE_OS::printf ("  %-5s %s %s%s%s%s%s\n", r.allow ? "allow" : "deny", r.principal.c_str (), r.object.c_str (),
                        r.prefix ? "*" : "", ops.empty () ? " (all operations)" : ops.c_str (),
                        r.via.empty () ? "" : " via=", r.via.c_str ());
      }
    return EXIT_OK;
  }

  int
  cmd_test (int argc, ACE_TCHAR *argv[])
  {
    Options o;
    if (int const rc = parse (argc, argv, o, "test"))
      return rc;
    if (o.principal.empty () || o.object.empty ())
      return usage ("access test: --principal and --object are required");
    Access_List::Content c;
    std::string error;
    if (!load_verified (o, c, error))
      return refuse (error);

    // The principal is taken as the effective principal of a caller.
    TAO::Security::Caller caller;
    if (o.principal.compare (0, 9, "spiffe://") == 0)
      caller.spiffe_ids.push_back (o.principal);
    else if (o.principal != "anonymous")
      caller.subject = o.principal;

    bool const prod = setup_conf_get ("mode") == "prod";
    bool const dflt = !prod && setup_conf_get ("access_default", "allow") != "deny";

    TAO::Security::Caller_Policy::Result const r =
      Access_List::evaluate (c, caller, o.object.c_str (), o.op.c_str ());
    bool const allowed = r == TAO::Security::Caller_Policy::ALLOW
                         || (r == TAO::Security::Caller_Policy::NO_RULE && dflt);
    char const *const why = r == TAO::Security::Caller_Policy::ALLOW  ? "an allow rule"
                            : r == TAO::Security::Caller_Policy::DENY ? "a deny rule"
                            : dflt                                    ? "no rule; access_default allow"
                            : prod                                    ? "no rule; prod refuses"
                                                                      : "no rule; access_default deny";
    ACE_OS::printf ("%s: %s %s %s (%s)\n", allowed ? "ALLOWED" : "REFUSED", o.principal.c_str (), o.object.c_str (),
                    o.op.empty () ? "(any operation)" : o.op.c_str (), why);
    return allowed ? EXIT_OK : EXIT_FAIL;
  }
}

int
setup_access (int argc, ACE_TCHAR *argv[])
{
  if (argc < 1)
    return usage ("access: give sign, check or test");
  std::string const sub = ACE_TEXT_ALWAYS_CHAR (argv[0]);
  if (sub == "sign")
    return cmd_sign (argc - 1, argv + 1);
  if (sub == "check")
    return cmd_check (argc - 1, argv + 1);
  if (sub == "test")
    return cmd_test (argc - 1, argv + 1);
  return usage ("access: unknown subcommand " + sub);
}

int
setup_asserters (int argc, ACE_TCHAR *argv[])
{
  if (argc < 1)
    return usage ("asserters: give sign or check");
  std::string const sub = ACE_TEXT_ALWAYS_CHAR (argv[0]);
  if (sub == "sign")
    return cmd_sign (argc - 1, argv + 1, true);
  if (sub == "check")
    return cmd_check (argc - 1, argv + 1, true);
  return usage ("asserters: unknown subcommand " + sub);
}
