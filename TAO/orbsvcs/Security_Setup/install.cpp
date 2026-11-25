// ace-tao-setup install / uninstall / run.
//
// install creates the service directories and account, writes the service
// definitions (systemd units on Linux, LaunchDaemons on macOS) and starts
// them.  Each thing it creates is recorded, as it is created, in a
// manifest (<state>/install-manifest); uninstall undoes exactly the
// manifest in reverse order and nothing else: files changed since install
// are kept unless --force, files that existed before are restored from
// their backup, accounts that existed before are kept, and directories are
// removed only if empty (--purge first deletes what the service wrote
// inside the directories install created).

#include "install.h"

#include "orbsvcs/Security/Self_Check.h"

#include "ace/OS_NS_errno.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_stat.h"
#include "ace/OS_NS_unistd.h"
#include "ace/Process.h"

#include <cctype>
#include <filesystem>
#include <string>
#include <vector>

#include <grp.h>
#include <pwd.h>

#if defined (__APPLE__)
# include <mach-o/dyld.h>
#endif

using TAO::Security::Self_Check;

namespace
{
  constexpr int EXIT_OK = 0;
  constexpr int EXIT_FAIL = 2;
  constexpr int EXIT_USAGE = 64;

#if defined (__APPLE__)
  bool const is_mac = true;
#else
  bool const is_mac = false;
#endif

  struct Paths
  {
    std::string root, etc, state, log, run, units, manifest;
  };

  Paths
  make_paths (std::string const &root)
  {
    Paths p;
    p.root = root;
    p.etc = root + "/etc/ace-tao";
    p.state = root + "/var/lib/ace-tao";
    p.log = root + "/var/log/ace-tao";
    p.run = root + (is_mac ? "/var/run/ace-tao" : "/run/ace-tao");
    p.units = root + (is_mac ? "/Library/LaunchDaemons" : "/etc/systemd/system");
    p.manifest = p.state + "/install-manifest";
    return p;
  }

  int
  fail (std::string const &why)
  {
    ACE_OS::fprintf (stderr, "ace-tao-setup: %s\n", why.c_str ());
    return EXIT_FAIL;
  }

  bool
  exists (std::string const &path)
  {
    ACE_stat st;
    return ACE_OS::lstat (path.c_str (), &st) == 0;
  }

  std::string
  dirname (std::string const &path)
  {
    size_t const slash = path.rfind ('/');
    return slash == std::string::npos ? std::string (".") : slash == 0 ? std::string ("/") : path.substr (0, slash);
  }

  std::string
  xml (std::string const &s)
  {
    std::string o;
    for (char const c : s)
      switch (c)
        {
        case '&': o += "&amp;"; break;
        case '<': o += "&lt;"; break;
        case '>': o += "&gt;"; break;
        default: o += c;
        }
    return o;
  }

  /// Runs a program (no shell) and returns its exit status, or -1.
  int
  run_argv (std::vector<std::string> const &args)
  {
    std::vector<ACE_TCHAR const *> argv;
    for (auto const &a : args)
      argv.push_back (ACE_TEXT_CHAR_TO_TCHAR (a.c_str ()));
    argv.push_back (nullptr);
    ACE_Process_Options opts;
    opts.command_line (argv.data ());
    ACE_Process proc;
    if (proc.spawn (opts) == ACE_INVALID_PID)
      return -1;
    ACE_exitcode status = 0;
    proc.wait (&status);
    return WIFEXITED (status) ? WEXITSTATUS (status) : -1;
  }

  std::string
  show (std::vector<std::string> const &args)
  {
    std::string s;
    for (auto const &a : args)
      s += (s.empty () ? "" : " ") + (a.find (' ') != std::string::npos ? "'" + a + "'" : a);
    return s;
  }

  /// Carries out (or, dry, prints) the installation steps and keeps the
  /// manifest on disk up to date after every step.
  class Installer
  {
  public:
    Installer (Paths const &p, bool dry) : p_ (p), dry_ (dry) {}

    bool mkdirs (std::string const &path, mode_t mode)
    {
      if (path.empty () || exists (path))
        return true;
      for (auto const &planned : this->planned_)
        if (planned == path)
          return true;
      this->planned_.push_back (path);
      if (!this->mkdirs (dirname (path), 0755))
        return false;
      ACE_OS::printf ("  create directory %s\n", path.c_str ());
      if (!this->dry_ && ACE_OS::mkdir (path.c_str (), mode) != 0 && errno != EEXIST)
        {
          this->error_ = "cannot create " + path + ": " + ACE_OS::strerror (errno);
          return false;
        }
      return this->record ("dir " + path);
    }

    bool write_file (std::string const &path, std::string const &content, mode_t mode)
    {
      std::string backup;
      if (exists (path))
        {
          backup = path + ".ace-tao-setup-backup";
          if (exists (backup))
            {
              this->error_ = path + " exists and so does " + backup + "; resolve that first";
              return false;
            }
          ACE_OS::printf ("  back up %s to %s\n", path.c_str (), backup.c_str ());
          if (!this->dry_ && ACE_OS::rename (path.c_str (), backup.c_str ()) != 0)
            {
              this->error_ = "cannot back up " + path + ": " + ACE_OS::strerror (errno);
              return false;
            }
        }
      ACE_OS::printf ("  write %s\n", path.c_str ());
      if (!this->dry_)
        {
          FILE *const fp = ACE_OS::fopen (path.c_str (), ACE_TEXT ("w"));
          bool ok = fp != nullptr && ACE_OS::fputs (content.c_str (), fp) >= 0;
          if (fp)
            ok = ACE_OS::fclose (fp) == 0 && ok;
          ok = ok && ::chmod (path.c_str (), mode) == 0;
          if (!ok)
            {
              this->error_ = "cannot write " + path + ": " + ACE_OS::strerror (errno);
              return false;
            }
        }
      std::string const sum = this->dry_ ? std::string ("-") : Self_Check::sha256_file (path.c_str ());
      return this->record ("file " + path + " " + sum + (backup.empty () ? "" : " " + backup));
    }

    /// Runs a command; @a undo is the manifest line that lets uninstall
    /// reverse it (empty: nothing to record).
    bool command (std::vector<std::string> const &args, std::string const &undo)
    {
      ACE_OS::printf ("  run %s\n", show (args).c_str ());
      if (!this->dry_)
        {
          int const rc = run_argv (args);
          if (rc != 0)
            {
              this->error_ = show (args) + " failed (exit " + std::to_string (rc) + ")";
              return false;
            }
        }
      return undo.empty () || this->record (undo);
    }

    bool record (std::string const &line)
    {
      this->lines_.push_back (line);
      // Parents of the state directory are created before it exists; the
      // manifest is written as soon as it does, with them included.
      if (this->dry_ || !exists (this->p_.state))
        return true;
      std::string text = "# ace-tao-setup install manifest v1; uninstall reverses it bottom-up\n";
      for (auto const &l : this->lines_)
        text += l + "\n";
      std::string const tmp = this->p_.manifest + ".tmp";
      FILE *const fp = ACE_OS::fopen (tmp.c_str (), ACE_TEXT ("w"));
      bool ok = fp != nullptr && ACE_OS::fputs (text.c_str (), fp) >= 0;
      if (fp)
        ok = ACE_OS::fclose (fp) == 0 && ok;
      ok = ok && ACE_OS::rename (tmp.c_str (), this->p_.manifest.c_str ()) == 0;
      if (!ok)
        this->error_ = "cannot write the manifest " + this->p_.manifest + ": " + ACE_OS::strerror (errno);
      return ok;
    }

    std::string const &error () const { return this->error_; }

  private:
    Paths const p_;
    bool const dry_;
    std::vector<std::string> lines_;
    std::vector<std::string> planned_;
    std::string error_;
  };

  std::string
  self_path (char const *argv0)
  {
    char buf[4096];
#if defined (__APPLE__)
    uint32_t size = sizeof buf;
    if (_NSGetExecutablePath (buf, &size) == 0 && buf[0] == '/')
      return buf;
#elif defined (ACE_LINUX)
    ssize_t const n = ::readlink ("/proc/self/exe", buf, sizeof buf - 1);
    if (n > 0)
      {
        buf[n] = '\0';
        return buf;
      }
#endif
    char real[4096];
    return ::realpath (argv0, real) ? std::string (real) : std::string (argv0);
  }

  /// A free id in [300, 400) for both a user and a group (macOS service
  /// accounts live below 500).
  int
  free_mac_id ()
  {
    for (int id = 300; id < 400; ++id)
      if (::getpwuid (id) == nullptr && ::getgrgid (id) == nullptr)
        return id;
    return -1;
  }
}

int
setup_gate_status (int worst)
{
  return worst == EXIT_FAIL ? EXIT_FAIL : EXIT_OK;
}

int
setup_install (int argc, ACE_TCHAR *argv[], char const *self)
{
  std::string service = "naming", prefix = is_mac ? "org.ace-tao" : "ace-tao";
  std::string root, bin_dir, listen = "127.0.0.1";
  std::string user = is_mac ? "_acetao" : "ace-tao";
  int port = 2809;
  bool no_start = false, dry = false;
  for (int i = 0; i < argc; ++i)
    {
      std::string const a = ACE_TEXT_ALWAYS_CHAR (argv[i]);
      auto value = [&] () -> std::string { return i + 1 < argc ? ACE_TEXT_ALWAYS_CHAR (argv[++i]) : ""; };
      if (a == "--service") service = value ();
      else if (a == "--label-prefix") prefix = value ();
      else if (a == "--port") port = ACE_OS::atoi (value ().c_str ());
      else if (a == "--listen") listen = value ();
      else if (a == "--user") user = value ();
      else if (a == "--root") root = value ();
      else if (a == "--bin-dir") bin_dir = value ();
      else if (a == "--no-start") no_start = true;
      else if (a == "--dry-run") dry = true;
      else
        {
          ACE_OS::fprintf (stderr, "ace-tao-setup: install: unknown option %s\n", a.c_str ());
          return EXIT_USAGE;
        }
    }
  if (service != "naming")
    return fail ("install: only --service naming is supported so far");
  if (port <= 0 || port > 65535)
    return fail ("install: --port must be 1-65535");
  for (char const c : prefix)
    if (!(::isalnum (static_cast<unsigned char> (c)) || c == '.' || c == '-' || c == '_'))
      return fail ("install: --label-prefix may contain only letters, digits, '.', '-' and '_'");

  Paths const p = make_paths (root);
  bool const system_install = root.empty ();
  bool const is_root = ACE_OS::geteuid () == 0;
  if (system_install && !is_root && !dry)
    return fail ("install needs root for a system install (sudo), or --root DIR for a test tree, "
                 "or --dry-run to see the steps");
  if (exists (p.manifest))
    return fail ("already installed (" + p.manifest + "); run uninstall first");

  std::string const setup = self_path (self);
  if (bin_dir.empty ())
    bin_dir = dirname (setup);
  std::string const server = bin_dir + "/tao_cosnaming";
  if (!exists (server))
    return fail ("cannot find " + server + " (use --bin-dir)");

  char const sep = is_mac ? '.' : '-';
  std::string const job = prefix + sep + service;
  std::string const check_job = prefix + sep + "check";
  std::string const svc_conf = p.etc + "/" + service + ".svc.conf";
  std::string const sec_conf = p.etc + "/security.conf";
  bool const make_account = system_install && (is_root || dry);

  ACE_OS::printf ("%s ACE/TAO %s service %s (port %d) %s%s\n", dry ? "Would install" : "Installing",
                  service.c_str (), job.c_str (), port,
                  system_install ? "on this system" : ("under " + root).c_str (),
                  dry ? " (dry run: nothing is changed)" : "");

  Installer in (p, dry);
  bool ok = in.mkdirs (p.state, 0755);
  ok = ok && in.mkdirs (p.etc, 0755);
  ok = ok && in.mkdirs (p.log, 0755);
  ok = ok && in.mkdirs (p.run, 0755);
  ok = ok && in.mkdirs (p.state + "/" + service, 0750);
  ok = ok && in.mkdirs (p.units, 0755);

  // Service account.
  if (ok && make_account)
    {
      if (::getpwnam (user.c_str ()) != nullptr)
        {
          ACE_OS::printf ("  account %s exists already; it will be used and kept\n", user.c_str ());
        }
      else if (is_mac)
        {
          ACE_OS::printf ("  note: macOS may now ask whether Terminal (or the program running this) may\n"
                          "        administer this computer; that approval is for creating the service\n"
                          "        account. Unattended installs need it granted in advance.\n");
          int const id = free_mac_id ();
          if (id < 0)
            return fail ("no free id in 300-399 for the service account");
          std::string const ids = std::to_string (id);
          std::string const g = "/Groups/" + user, u = "/Users/" + user;
          ok = in.command ({"/usr/bin/dscl", ".", "-create", g}, "group " + user + " created")
            && in.command ({"/usr/bin/dscl", ".", "-create", g, "PrimaryGroupID", ids}, "")
            && in.command ({"/usr/bin/dscl", ".", "-create", g, "Password", "*"}, "")
            && in.command ({"/usr/bin/dscl", ".", "-create", u}, "user " + user + " created")
            && in.command ({"/usr/bin/dscl", ".", "-create", u, "UniqueID", ids}, "")
            && in.command ({"/usr/bin/dscl", ".", "-create", u, "PrimaryGroupID", ids}, "")
            && in.command ({"/usr/bin/dscl", ".", "-create", u, "UserShell", "/usr/bin/false"}, "")
            && in.command ({"/usr/bin/dscl", ".", "-create", u, "NFSHomeDirectory", "/var/empty"}, "")
            && in.command ({"/usr/bin/dscl", ".", "-create", u, "RealName", "ACE-TAO services"}, "")
            && in.command ({"/usr/bin/dscl", ".", "-create", u, "Password", "*"}, "")
            && in.command ({"/usr/bin/dscl", ".", "-create", u, "IsHidden", "1"}, "");
        }
      else
        {
          ok = in.command ({"useradd", "--system", "--user-group", "--no-create-home", "--home-dir", p.state,
                            "--shell", "/usr/sbin/nologin", user}, "user " + user + " created");
        }
      // The service writes only its own state, log and run directories.
      if (ok && !dry)
        if (struct passwd const *const pw = ::getpwnam (user.c_str ()))
          for (std::string const &d : {p.state + "/" + service, p.log, p.run})
            if (::chown (d.c_str (), pw->pw_uid, pw->pw_gid) != 0)
              {
                ok = false;
                ACE_OS::fprintf (stderr, "ace-tao-setup: cannot chown %s: %s\n", d.c_str (), ACE_OS::strerror (errno));
              }
    }
  else if (ok && system_install)
    ACE_OS::printf ("  (not root: the service account %s is not created)\n", user.c_str ());

  // Service configuration placeholder: the operator puts the SSLIOP
  // settings here; install never writes security.conf (use init).
  if (ok && !exists (svc_conf))
    ok = in.write_file (svc_conf,
                        "# Service configuration for the ACE/TAO " + service + " service (ace-tao-setup install).\n"
                        "# Add the SSLIOP_Factory and Resource_Factory lines for prod; see SSLIOP-USAGE.html.\n",
                        0644);

  std::string const endpoint = "iiop://" + listen + ":" + std::to_string (port);
  std::vector<std::string> const server_args = {
    server, "-ORBSvcConf", svc_conf, "-ORBListenEndpoints", endpoint,
    "-u", p.state + "/" + service, "-o", p.run + "/" + service + ".ior" };

  if (ok && is_mac)
    {
      std::string const plist = p.units + "/" + job + ".plist";
      std::string args;
      for (auto const &a : std::vector<std::string> {setup, "run", "--svc-conf", svc_conf, "--"})
        args += "    <string>" + xml (a) + "</string>\n";
      for (auto const &a : server_args)
        args += "    <string>" + xml (a) + "</string>\n";
      std::string const account = make_account
        ? "  <key>UserName</key><string>" + xml (user) + "</string>\n  <key>GroupName</key><string>" + xml (user) + "</string>\n"
        : std::string ();
      std::string const head =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<!-- Written by ace-tao-setup install; removed by ace-tao-setup uninstall. -->\n"
        "<plist version=\"1.0\">\n<dict>\n";
      std::string const env =
        "  <key>EnvironmentVariables</key>\n  <dict>\n    <key>ACE_TAO_SECURITY_CONF</key><string>"
        + xml (sec_conf) + "</string>\n  </dict>\n";
      ok = in.write_file (plist,
                          head + "  <key>Label</key><string>" + xml (job) + "</string>\n"
                          "  <key>ProgramArguments</key>\n  <array>\n" + args + "  </array>\n" + account + env +
                          "  <key>WorkingDirectory</key><string>" + xml (p.state + "/" + service) + "</string>\n"
                          "  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n"
                          "  <key>ThrottleInterval</key><integer>10</integer>\n"
                          "  <key>StandardOutPath</key><string>" + xml (p.log + "/" + service + ".log") + "</string>\n"
                          "  <key>StandardErrorPath</key><string>" + xml (p.log + "/" + service + ".log") + "</string>\n"
                          "</dict>\n</plist>\n", 0644);
      std::string const check_plist = p.units + "/" + check_job + ".plist";
      ok = ok && in.write_file (check_plist,
                                head + "  <key>Label</key><string>" + xml (check_job) + "</string>\n"
                                "  <key>ProgramArguments</key>\n  <array>\n    <string>" + xml (setup) + "</string>\n"
                                "    <string>check</string>\n    <string>--svc-conf</string>\n    <string>" + xml (svc_conf)
                                + "</string>\n  </array>\n" + env +
                                "  <key>StartInterval</key><integer>3600</integer>\n  <key>RunAtLoad</key><true/>\n"
                                "  <key>StandardOutPath</key><string>" + xml (p.log + "/check.log") + "</string>\n"
                                "  <key>StandardErrorPath</key><string>" + xml (p.log + "/check.log") + "</string>\n"
                                "</dict>\n</plist>\n", 0644);
      if (ok && !no_start && system_install)
        ok = in.command ({"/bin/launchctl", "bootstrap", "system", plist}, "launchd " + job)
          && in.command ({"/bin/launchctl", "bootstrap", "system", check_plist}, "launchd " + check_job);
    }
  else if (ok)
    {
      std::string exec;
      for (auto const &a : server_args)
        exec += (exec.empty () ? "" : " ") + a;
      std::string const target = prefix + ".target";
      std::string const unit = p.units + "/" + job + ".service";
      std::string const account = make_account ? "User=" + user + "\nGroup=" + user + "\n" : std::string ();
      ok = in.write_file (p.units + "/" + target,
                          "# Written by ace-tao-setup install; removed by ace-tao-setup uninstall.\n"
                          "[Unit]\nDescription=ACE/TAO services\n\n[Install]\nWantedBy=multi-user.target\n", 0644)
        && in.write_file (unit,
                          "# Written by ace-tao-setup install; removed by ace-tao-setup uninstall.\n"
                          "[Unit]\nDescription=ACE/TAO " + service + " service\n"
                          "After=network-online.target\nWants=network-online.target\nPartOf=" + target + "\n\n"
                          "[Service]\n" + account +
                          "Environment=ACE_TAO_SECURITY_CONF=" + sec_conf + "\n"
                          "ExecStartPre=" + setup + " check --gate --svc-conf " + svc_conf + "\n"
                          "ExecStart=" + exec + "\n"
                          "Restart=on-failure\nRestartSec=5\n"
                          "NoNewPrivileges=yes\nProtectSystem=strict\nPrivateTmp=yes\nLimitCORE=0\n"
                          "ReadWritePaths=" + p.state + "/" + service + " " + p.log + " " + p.run + "\n\n"
                          "[Install]\nWantedBy=" + target + "\n", 0644)
        && in.write_file (p.units + "/" + check_job + ".service",
                          "# Written by ace-tao-setup install; removed by ace-tao-setup uninstall.\n"
                          "[Unit]\nDescription=ACE/TAO hourly security check\n\n"
                          "[Service]\nType=oneshot\nEnvironment=ACE_TAO_SECURITY_CONF=" + sec_conf + "\n"
                          "ExecStart=" + setup + " check --svc-conf " + svc_conf + "\n", 0644)
        && in.write_file (p.units + "/" + check_job + ".timer",
                          "# Written by ace-tao-setup install; removed by ace-tao-setup uninstall.\n"
                          "[Unit]\nDescription=Run the ACE/TAO security check hourly\n\n"
                          "[Timer]\nOnCalendar=hourly\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n", 0644);
      if (ok && !no_start && system_install)
        ok = in.command ({"systemctl", "daemon-reload"}, "")
          && in.command ({"systemctl", "enable", "--now", target, job + ".service"}, "systemd " + target + " " + job + ".service")
          && in.command ({"systemctl", "enable", "--now", check_job + ".timer"}, "systemd " + check_job + ".timer");
    }

  if (!ok)
    {
      ACE_OS::fprintf (stderr, "ace-tao-setup: install stopped: %s\n", in.error ().c_str ());
      if (!dry)
        ACE_OS::fprintf (stderr, "ace-tao-setup: what was done so far is in %s; run uninstall to undo it\n",
                         p.manifest.c_str ());
      return EXIT_FAIL;
    }
  if (dry)
    ACE_OS::printf ("Dry run complete; nothing was changed.\n");
  else
    ACE_OS::printf ("Installed. Manifest: %s. Undo with: ace-tao-setup uninstall%s%s\n", p.manifest.c_str (),
                    root.empty () ? "" : " --root ", root.c_str ());
  return EXIT_OK;
}

int
setup_uninstall (int argc, ACE_TCHAR *argv[])
{
  std::string root;
  bool purge = false, force = false, dry = false;
  for (int i = 0; i < argc; ++i)
    {
      std::string const a = ACE_TEXT_ALWAYS_CHAR (argv[i]);
      if (a == "--root" && i + 1 < argc) root = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
      else if (a == "--purge") purge = true;
      else if (a == "--force") force = true;
      else if (a == "--dry-run") dry = true;
      else
        {
          ACE_OS::fprintf (stderr, "ace-tao-setup: uninstall: unknown option %s\n", a.c_str ());
          return EXIT_USAGE;
        }
    }
  Paths const p = make_paths (root);
  if (root.empty () && ACE_OS::geteuid () != 0 && !dry)
    return fail ("uninstall needs root for a system install (sudo), or --dry-run to see the steps");

  std::vector<std::string> lines;
  {
    FILE *const fp = ACE_OS::fopen (p.manifest.c_str (), ACE_TEXT ("r"));
    if (fp == nullptr)
      return fail ("nothing to uninstall: no manifest at " + p.manifest);
    char buf[4096];
    while (ACE_OS::fgets (buf, sizeof buf, fp) != nullptr)
      {
        std::string l (buf);
        while (!l.empty () && (l.back () == '\n' || l.back () == '\r'))
          l.pop_back ();
        if (!l.empty () && l[0] != '#')
          lines.push_back (l);
      }
    ACE_OS::fclose (fp);
  }

  ACE_OS::printf ("%s what %s recorded%s\n", dry ? "Would undo" : "Undoing", p.manifest.c_str (),
                  dry ? " (dry run: nothing is changed)" : "");
  std::vector<bool> kept (lines.size (), false);
  std::vector<std::string> removed;   // removed, or (dry run) would be
  auto is_removed = [&] (std::string const &path)
    {
      for (auto const &r : removed)
        if (r == path)
          return true;
      return false;
    };
  bool account_note = false;
  int problems = 0;
  bool reload_systemd = false;
  auto act = [&] (std::vector<std::string> const &args, bool tolerate) -> bool
    {
      ACE_OS::printf ("  run %s\n", show (args).c_str ());
      if (dry)
        return true;
      int const rc = run_argv (args);
      if (rc != 0 && !tolerate)
        {
          ACE_OS::fprintf (stderr, "ace-tao-setup:   failed (exit %d)\n", rc);
          return false;
        }
      return true;
    };
  auto words = [] (std::string const &line)
    {
      std::vector<std::string> w;
      size_t start = 0;
      while (start < line.size ())
        {
          size_t const sp = line.find (' ', start);
          w.push_back (line.substr (start, sp == std::string::npos ? std::string::npos : sp - start));
          if (sp == std::string::npos)
            break;
          start = sp + 1;
        }
      return w;
    };

  // Everything but directories, last recorded first.
  std::vector<size_t> dir_index;
  for (size_t n = lines.size (); n-- > 0; )
    {
      std::vector<std::string> const w = words (lines[n]);
      if (w.empty ())
        continue;
      std::string const &kind = w[0];
      if (kind == "dir" && w.size () >= 2)
        dir_index.push_back (n);
      else if (kind == "launchd" && w.size () >= 2)
        act ({"/bin/launchctl", "bootout", "system/" + w[1]}, true);
      else if (kind == "systemd" && w.size () >= 2)
        {
          std::vector<std::string> args = {"systemctl", "disable", "--now"};
          args.insert (args.end (), w.begin () + 1, w.end ());
          act (args, true);
          reload_systemd = true;
        }
      else if (kind == "file" && w.size () >= 3)
        {
          std::string const &path = w[1];
          if (exists (path))
            {
              std::string const now = Self_Check::sha256_file (path.c_str ());
              if (now != w[2] && w[2] != "-" && !force)
                {
                  ++problems;
                  kept[n] = true;
                  ACE_OS::printf ("  keep %s: changed since install (use --force to remove it)\n", path.c_str ());
                  continue;
                }
              ACE_OS::printf ("  remove %s\n", path.c_str ());
              if (!dry && ACE_OS::unlink (path.c_str ()) != 0)
                {
                  ++problems;
                  kept[n] = true;
                  ACE_OS::fprintf (stderr, "ace-tao-setup:   %s\n", ACE_OS::strerror (errno));
                  continue;
                }
              removed.push_back (path);
            }
          if (w.size () >= 4)
            {
              ACE_OS::printf ("  restore %s from %s\n", path.c_str (), w[3].c_str ());
              if (!dry && ACE_OS::rename (w[3].c_str (), path.c_str ()) != 0)
                {
                  ++problems;
                  ACE_OS::fprintf (stderr, "ace-tao-setup:   %s\n", ACE_OS::strerror (errno));
                }
            }
        }
      else if ((kind == "user" || kind == "group") && w.size () >= 3 && w[2] == "created")
        {
          bool ok;
          if (is_mac && !account_note)
            {
              account_note = true;
              ACE_OS::printf ("  note: macOS may now ask whether Terminal (or the program running this) may\n"
                              "        administer this computer; that approval is for deleting the service account.\n");
            }
          if (is_mac)
            ok = act ({"/usr/bin/dscl", ".", "-delete", (kind == "user" ? "/Users/" : "/Groups/") + w[1]}, false);
          else
            ok = act ({kind == "user" ? "userdel" : "groupdel", w[1]}, false);
          if (!ok)
            {
              ++problems;
              kept[n] = true;
            }
        }
    }
  if (reload_systemd)
    act ({"systemctl", "daemon-reload"}, true);

  // The manifest sits in a directory install created; take it out of the
  // way, and write back whatever had to stay so a later run can finish.
  if (!dry)
    ACE_OS::unlink (p.manifest.c_str ());
  removed.push_back (p.manifest);

  std::vector<std::string> kept_dirs;
  auto is_kept_dir = [&] (std::string const &path)
    {
      for (auto const &k : kept_dirs)
        if (k == path)
          return true;
      return false;
    };
  // Empty once everything removed (or, dry, to be removed) is gone.
  auto effectively_empty = [&] (std::string const &d)
    {
      std::error_code ec;
      for (auto const &entry : std::filesystem::directory_iterator (d, ec))
        if (!is_removed (entry.path ().string ()))
          return false;
      return true;
    };
  auto holds_only_kept = [&] (std::string const &d)
    {
      std::error_code ec;
      for (auto const &entry : std::filesystem::directory_iterator (d, ec))
        {
          std::string const e = entry.path ().string ();
          if (!is_removed (e) && !is_kept_dir (e))
            return false;
        }
      return true;
    };

  for (size_t const n : dir_index)   // deepest (latest created) first
    {
      std::string const d = words (lines[n])[1];
      if (!exists (d))
        continue;
      std::error_code ec;
      bool empty = effectively_empty (d);
      bool const service_data = d.find ("/ace-tao") != std::string::npos
        && (d.rfind (p.state, 0) == 0 || d == p.log || d == p.run);
      if (!empty && purge && service_data && !holds_only_kept (d))
        {
          for (auto const &entry : std::filesystem::directory_iterator (d, ec))
            {
              std::string const e = entry.path ().string ();
              if (is_kept_dir (e) || is_removed (e))
                continue;
              ACE_OS::printf ("  purge %s\n", e.c_str ());
              if (!dry)
                std::filesystem::remove_all (entry.path (), ec);
              removed.push_back (e);
            }
          empty = effectively_empty (d);
        }
      if (!empty)
        {
          kept[n] = true;
          if (holds_only_kept (d))
            ACE_OS::printf ("  keep %s: holds items kept above\n", d.c_str ());
          else
            {
              ++problems;
              ACE_OS::printf ("  keep %s: not empty (uninstall --purge removes service data)\n", d.c_str ());
            }
          kept_dirs.push_back (d);
          continue;
        }
      ACE_OS::printf ("  remove directory %s\n", d.c_str ());
      if (!dry && ACE_OS::rmdir (d.c_str ()) != 0)
        {
          ++problems;
          kept[n] = true;
          kept_dirs.push_back (d);
          ACE_OS::fprintf (stderr, "ace-tao-setup:   %s\n", ACE_OS::strerror (errno));
          continue;
        }
      removed.push_back (d);
    }

  bool any_kept = false;
  for (bool const k : kept)
    any_kept = any_kept || k;
  if (any_kept && !dry)
    {
      std::string text = "# ace-tao-setup install manifest v1: items left by an uninstall\n";
      if (!exists (p.state))
        {
          // Keep a home for the manifest, recorded so it goes too.
          ACE_OS::mkdir (p.state.c_str (), 0755);
          text += "dir " + p.state + "\n";
        }
      for (size_t n = 0; n < lines.size (); ++n)
        if (kept[n])
          text += lines[n] + "\n";
      FILE *const fp = ACE_OS::fopen (p.manifest.c_str (), ACE_TEXT ("w"));
      if (fp)
        {
          ACE_OS::fputs (text.c_str (), fp);
          ACE_OS::fclose (fp);
        }
    }

  if (dry)
    ACE_OS::printf ("Dry run complete; nothing was changed.\n");
  else if (any_kept)
    ACE_OS::printf ("Uninstalled, with %d item(s) left in place (listed above); %s records them, so "
                    "uninstall can be run again (--purge, --force) to finish.\n", problems, p.manifest.c_str ());
  else
    ACE_OS::printf ("Uninstalled; everything install created is gone.\n");
  return any_kept ? EXIT_FAIL : EXIT_OK;
}

int
setup_run (int argc, ACE_TCHAR *argv[], char const *self, char const *conf_path)
{
  std::string svc_conf;
  int i = 0;
  for (; i < argc; ++i)
    {
      std::string const a = ACE_TEXT_ALWAYS_CHAR (argv[i]);
      if (a == "--svc-conf" && i + 1 < argc)
        svc_conf = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
      else if (a == "--")
        {
          ++i;
          break;
        }
      else
        {
          ACE_OS::fprintf (stderr, "ace-tao-setup: run: unknown option %s\n", a.c_str ());
          return EXIT_USAGE;
        }
    }
  if (i >= argc)
    {
      ACE_OS::fprintf (stderr, "ace-tao-setup: run: give the service command after --\n");
      return EXIT_USAGE;
    }

  std::vector<std::string> check = {self_path (self), "--conf", conf_path, "check", "--gate"};
  if (!svc_conf.empty ())
    {
      check.push_back ("--svc-conf");
      check.push_back (svc_conf);
    }
  int const rc = run_argv (check);
  if (rc != 0)
    {
      ACE_OS::fprintf (stderr, "ace-tao-setup: run: the security check failed (exit %d); not starting %s\n",
                       rc, ACE_TEXT_ALWAYS_CHAR (argv[i]));
      return rc < 0 ? EXIT_FAIL : rc;
    }

  std::vector<char *> args;
  for (int j = i; j < argc; ++j)
    args.push_back (ACE_TEXT_ALWAYS_CHAR (argv[j]));
  args.push_back (nullptr);
  ACE_OS::execv (args[0], args.data ());
  ACE_OS::fprintf (stderr, "ace-tao-setup: run: cannot start %s: %s\n", args[0], ACE_OS::strerror (errno));
  return EXIT_FAIL;
}
