// ace-tao-setup user: maintain the CSIv2 GSSUP password store that
// SSLIOP services check logins against (see
// orbsvcs/SSLIOP/SSLIOP_GSSUP_Store.h for the format and the
// security.conf keys).
//
//   user add    USER [--store F] [--password-stdin] [--cost LOG2N] [--owner ACCOUNT]
//   user passwd USER [--store F] [--password-stdin] [--cost LOG2N]
//   user lock   USER [--store F]
//   user unlock USER [--store F]
//   user remove USER [--store F]
//   user list        [--store F]
//
// The store defaults to gssup_store in the security configuration.  A
// password is read from the terminal without echo, twice, or with
// --password-stdin as one line from standard input; never from the
// command line.  Passwords under 12 characters are refused.  The store
// is rewritten through a temporary file (mode 0600, the owner of the
// file it replaces, or --owner for a new one) and renamed into place;
// services pick the change up on their next login.  list prints names,
// states and scrypt costs, never hashes.

#include "keys.h"

#include "orbsvcs/SSLIOP/SSLIOP_GSSUP_Store.h"
#include "orbsvcs/SSLIOP/SSLIOP_Signed_File.h"
#include "orbsvcs/Security/Audit_Logger.h"

#include "ace/OS_NS_fcntl.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_stat.h"
#include "ace/OS_NS_unistd.h"

#include <openssl/crypto.h>

#include <pwd.h>
#if defined (ACE_HAS_TERMIOS)
# include <termios.h>
#endif

#include <cerrno>
#include <vector>

using TAO::SSLIOP::GSSUP_Store;
namespace Signed_File = TAO::SSLIOP::Signed_File;
namespace Reason = TAO::Security::Audit_Reason;

namespace
{
  constexpr int EXIT_OK = 0;
  constexpr int EXIT_FAIL = 2;
  constexpr int EXIT_USAGE = 64;
  constexpr size_t MIN_PASSWORD = 12;
  constexpr size_t MAX_PASSWORD = 256;

  char const usage_text[] =
    "usage: ace-tao-setup user add    USER [--store F] [--password-stdin] [--cost LOG2N] [--owner ACCOUNT]\n"
    "       ace-tao-setup user passwd USER [--store F] [--password-stdin] [--cost LOG2N]\n"
    "       ace-tao-setup user lock|unlock|remove USER [--store F]\n"
    "       ace-tao-setup user list [--store F]\n"
    "  F defaults to gssup_store in the security configuration.  Passwords come from the\n"
    "  terminal (asked twice, not echoed) or, with --password-stdin, one line of standard\n"
    "  input; at least 12 characters.  --cost sets scrypt N = 2^LOG2N (default 15).\n";

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

  void
  wipe (std::string &s)
  {
    if (!s.empty ())
      ::OPENSSL_cleanse (&s[0], s.size ());
    s.clear ();
  }

  struct Options
  {
    std::string user, store, owner;
    bool password_stdin = false;
    unsigned cost = 0;
  };

  int
  parse (int argc, ACE_TCHAR *argv[], Options &o, std::string const &cmd, bool wants_user)
  {
    for (int i = 0; i < argc; ++i)
      {
        std::string const a = ACE_TEXT_ALWAYS_CHAR (argv[i]);
        bool const more = i + 1 < argc;
        if (a == "--store" && more) o.store = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--owner" && more) o.owner = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--cost" && more) o.cost = static_cast<unsigned> (ACE_OS::atoi (ACE_TEXT_ALWAYS_CHAR (argv[++i])));
        else if (a == "--password-stdin") o.password_stdin = true;
        else if (a == "--password" || a.compare (0, 11, "--password=") == 0)
          return usage ("user " + cmd + ": passwords are never taken from the command line");
        else if (wants_user && o.user.empty () && !a.empty () && a[0] != '-') o.user = a;
        else
          return usage ("user " + cmd + ": unexpected " + a);
      }
    if (wants_user && o.user.empty ())
      return usage ("user " + cmd + ": give a user name");
    if (wants_user && !GSSUP_Store::valid_user (o.user))
      return usage ("user " + cmd + ": bad user name " + o.user + " (1 to 64 of A-Z a-z 0-9 . _ -)");
    if (o.store.empty ())
      o.store = setup_conf_get ("gssup_store");
    if (o.store.empty ())
      return usage ("user " + cmd + ": no store: give --store or set gssup_store in the security configuration");
    return EXIT_OK;
  }

  /// One line from the terminal without echo, or from stdin.
  bool
  read_line (char const *prompt, bool no_echo, std::string &out)
  {
    out.clear ();
#if defined (ACE_HAS_TERMIOS)
    struct termios old_tio;
    bool restore = false;
    if (no_echo && ACE_OS::isatty (ACE_STDIN))
      {
        ACE_OS::fprintf (stderr, "%s", prompt);
        if (::tcgetattr (ACE_STDIN, &old_tio) == 0)
          {
            struct termios tio = old_tio;
            tio.c_lflag &= ~static_cast<tcflag_t> (ECHO);
            restore = ::tcsetattr (ACE_STDIN, TCSANOW, &tio) == 0;
          }
      }
#else
    ACE_UNUSED_ARG (prompt);
    ACE_UNUSED_ARG (no_echo);
#endif
    bool got = false;
    for (int c; (c = ::getchar ()) != EOF;)
      {
        got = true;
        if (c == '\n')
          break;
        if (out.size () <= MAX_PASSWORD)
          out += static_cast<char> (c);
      }
#if defined (ACE_HAS_TERMIOS)
    if (restore)
      {
        ::tcsetattr (ACE_STDIN, TCSANOW, &old_tio);
        ACE_OS::fprintf (stderr, "\n");
      }
#endif
    if (!out.empty () && out[out.size () - 1] == '\r')
      out.erase (out.size () - 1);
    return got;
  }

  /// The new password, checked; false with @a error.
  bool
  new_password (Options const &o, std::string &out, std::string &error)
  {
    if (o.password_stdin)
      {
        if (!read_line ("", false, out))
          {
            error = "no password on standard input";
            return false;
          }
      }
    else
      {
        if (!ACE_OS::isatty (ACE_STDIN))
          {
            error = "standard input is not a terminal: use --password-stdin";
            return false;
          }
        std::string again;
        read_line ("New password: ", true, out);
        read_line ("Again: ", true, again);
        bool const same = out == again;
        wipe (again);
        if (!same)
          {
            wipe (out);
            error = "the passwords differ";
            return false;
          }
      }
    if (out.size () < MIN_PASSWORD || out.size () > MAX_PASSWORD)
      {
        wipe (out);
        error = "a password must be " + std::to_string (MIN_PASSWORD) + " to " + std::to_string (MAX_PASSWORD)
                + " characters";
        return false;
      }
    return true;
  }

  /// Reads the store; a missing store is empty when @a may_be_missing.
  bool
  load (std::string const &path, bool may_be_missing, std::vector<GSSUP_Store::Entry> &out, std::string &error)
  {
    out.clear ();
    ACE_stat st;
    if (ACE_OS::stat (path.c_str (), &st) != 0)
      {
        if (may_be_missing && errno == ENOENT)
          return true;
        error = "cannot read " + path + ": " + ACE_OS::strerror (errno);
        return false;
      }
    std::string text;
    if (!Signed_File::slurp (path, text))
      {
        error = "cannot read " + path;
        return false;
      }
    bool const ok = GSSUP_Store::parse (text, out, error);
    wipe (text);
    if (!ok)
      error = path + ": " + error;
    return ok;
  }

  /// Writes the store through PATH.tmp (created exclusively, so two
  /// changes at once cannot lose one), mode 0600, then renames it.
  bool
  save (std::string const &path, std::vector<GSSUP_Store::Entry> const &entries, std::string const &owner,
        std::string &error)
  {
    std::string const tmp = path + ".tmp";
    ACE_HANDLE const fd = ACE_OS::open (tmp.c_str (), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd == ACE_INVALID_HANDLE)
      {
        error = errno == EEXIST ? tmp + " exists: another change is in progress (or one was interrupted; "
                                        "remove it if no other change is running)"
                                : "cannot create " + tmp + ": " + ACE_OS::strerror (errno);
        return false;
      }
    std::string text = GSSUP_Store::format (entries);
    bool ok = ACE_OS::write (fd, text.data (), text.size ()) == static_cast<ssize_t> (text.size ());
    wipe (text);
    ok = ok && ACE_OS::fsync (fd) == 0;

    // Keep the owner of the store being replaced; a new store goes to
    // --owner if given (this needs root), else stays with the caller.
    ACE_stat st;
    if (ok && ACE_OS::stat (path.c_str (), &st) == 0)
      {
        if ((st.st_uid != ACE_OS::geteuid () || st.st_gid != ACE_OS::getegid ())
            && ::fchown (fd, st.st_uid, st.st_gid) != 0)
          {
            error = "cannot give " + tmp + " the owner of " + path + " (uid " + std::to_string (static_cast<long> (st.st_uid))
                    + "): " + ACE_OS::strerror (errno);
            ok = false;
          }
      }
    else if (ok && !owner.empty ())
      {
        struct passwd const *const pw = ::getpwnam (owner.c_str ());
        if (pw == nullptr)
          {
            error = "no account " + owner;
            ok = false;
          }
        else if (::fchown (fd, pw->pw_uid, pw->pw_gid) != 0)
          {
            error = "cannot give " + tmp + " to " + owner + ": " + ACE_OS::strerror (errno);
            ok = false;
          }
      }
    ok = ACE_OS::close (fd) == 0 && ok;
    if (ok && ACE_OS::rename (tmp.c_str (), path.c_str ()) != 0)
      {
        error = "cannot replace " + path + ": " + ACE_OS::strerror (errno);
        ok = false;
      }
    if (!ok)
      {
        if (error.empty ())
          error = "cannot write " + tmp + ": " + ACE_OS::strerror (errno);
        ACE_OS::unlink (tmp.c_str ());
      }
    return ok;
  }

  GSSUP_Store::Entry *
  find (std::vector<GSSUP_Store::Entry> &entries, std::string const &user)
  {
    for (GSSUP_Store::Entry &e : entries)
      if (e.user == user)
        return &e;
    return nullptr;
  }

  int
  changed (char const *action, Options const &o)
  {
    setup_audit (Reason::GSSUP_USER_CHANGED, {{"action", action}, {"user", o.user}, {"file", o.store}});
    return EXIT_OK;
  }

  int
  cmd_set_password (int argc, ACE_TCHAR *argv[], bool adding)
  {
    char const *const cmd = adding ? "add" : "passwd";
    Options o;
    if (int const r = parse (argc, argv, o, cmd, true))
      return r;
    std::vector<GSSUP_Store::Entry> entries;
    std::string error;
    if (!load (o.store, adding, entries, error))
      return refuse (error);
    GSSUP_Store::Entry *const existing = find (entries, o.user);
    if (adding && existing != nullptr)
      return refuse ("user " + o.user + " exists (use passwd to change the password)");
    if (!adding && existing == nullptr)
      return refuse ("no user " + o.user + " in " + o.store);

    GSSUP_Store::Params params;
    if (o.cost != 0)
      params.log2n = o.cost;
    else if (existing != nullptr)
      params = existing->params;
    std::string password;
    if (!new_password (o, password, error))
      return refuse (error);
    GSSUP_Store::Entry e;
    bool const made = GSSUP_Store::make_entry (o.user, password, params, e, error);
    wipe (password);
    if (!made)
      return refuse (error);
    if (existing != nullptr)
      {
        e.locked = existing->locked;
        *existing = e;
      }
    else
      entries.push_back (e);
    if (!save (o.store, entries, o.owner, error))
      return refuse (error);
    ACE_OS::printf ("%s %s in %s\n", adding ? "Added" : "Changed the password of", o.user.c_str (), o.store.c_str ());
    if (e.locked)
      ACE_OS::printf ("%s is still locked (user unlock %s).\n", o.user.c_str (), o.user.c_str ());
    return changed (cmd, o);
  }

  int
  cmd_state (int argc, ACE_TCHAR *argv[], char const *cmd)
  {
    Options o;
    if (int const r = parse (argc, argv, o, cmd, true))
      return r;
    std::vector<GSSUP_Store::Entry> entries;
    std::string error;
    if (!load (o.store, false, entries, error))
      return refuse (error);
    GSSUP_Store::Entry *const e = find (entries, o.user);
    if (e == nullptr)
      return refuse ("no user " + o.user + " in " + o.store);
    std::string const what = cmd;
    if (what == "remove")
      entries.erase (entries.begin () + (e - entries.data ()));
    else
      e->locked = what == "lock";
    if (!save (o.store, entries, std::string (), error))
      return refuse (error);
    ACE_OS::printf ("%s %s in %s\n",
                    what == "remove" ? "Removed" : what == "lock" ? "Locked" : "Unlocked", o.user.c_str (),
                    o.store.c_str ());
    return changed (cmd, o);
  }

  int
  cmd_list (int argc, ACE_TCHAR *argv[])
  {
    Options o;
    if (int const r = parse (argc, argv, o, "list", false))
      return r;
    std::vector<GSSUP_Store::Entry> entries;
    std::string error;
    if (!load (o.store, false, entries, error))
      return refuse (error);
    bool const prod = setup_conf_get ("mode") == "prod";
    if (!GSSUP_Store::check_file (o.store, true, error))
      ACE_OS::fprintf (stderr, "ace-tao-setup: %s: %s\n", prod ? "error" : "warning (refused in prod)", error.c_str ());
    for (GSSUP_Store::Entry const &e : entries)
      ACE_OS::printf ("%-24s %-6s scrypt N=2^%u r=%u p=%u\n", e.user.c_str (), e.locked ? "locked" : "active",
                      e.params.log2n, e.params.r, e.params.p);
    ACE_OS::printf ("%u user(s) in %s\n", static_cast<unsigned> (entries.size ()), o.store.c_str ());
    return EXIT_OK;
  }
}

int
setup_user (int argc, ACE_TCHAR *argv[])
{
  if (argc < 1)
    return usage ("user: give add, passwd, lock, unlock, remove or list");
  std::string const sub = ACE_TEXT_ALWAYS_CHAR (argv[0]);
  if (sub == "add")
    return cmd_set_password (argc - 1, argv + 1, true);
  if (sub == "passwd")
    return cmd_set_password (argc - 1, argv + 1, false);
  if (sub == "lock" || sub == "unlock" || sub == "remove")
    return cmd_state (argc - 1, argv + 1, sub == "lock" ? "lock" : sub == "unlock" ? "unlock" : "remove");
  if (sub == "list")
    return cmd_list (argc - 1, argv + 1);
  return usage ("user: unknown subcommand " + sub);
}
