// ace-tao-setup rights | grants | roles: sign and check the role model's
// signed policy tables (Phase 3 T1, R40; format and security.conf keys in
// orbsvcs/SSLIOP/SSLIOP_Policy_Tables.h).
//
//   KIND sign  --key SPEC [--password-file F] --file DRAFT [--dir DIR]
//   KIND check [--dir DIR] [--signer PEM]
//
// KIND is rights, grants or roles.  sign takes a hand-edited DRAFT (its
// body; any table, version or issued lines in it are replaced), gives it
// the next version (above every KIND file in DIR and the roles_state
// mark), issues it now, and writes DIR/KIND-YYYY-MM-DD.txt (or .N.txt for
// a further revision that day) with its signature beside it.  The
// signature is written first, so a service never sees the table
// unsigned.  The key must be the pinned roles signer and must not be the
// deny-list signer (D3.7).  check shows which file a service would load
// and why each other one is refused (exit 0 if one qualifies, else 2).
// DIR defaults to roles_dir, PEM to roles_signer.  ("test", which
// answers whether a caller may call an operation, comes with the
// tables' contents in T2.)

#include "keys.h"

#include "orbsvcs/SSLIOP/SSLIOP_Deny_List.h"
#include "orbsvcs/SSLIOP/SSLIOP_Policy_Tables.h"
#include "orbsvcs/SSLIOP/SSLIOP_Signed_File.h"
#include "orbsvcs/Security/Audit_Logger.h"

#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_ctype.h"
#include "ace/OS_NS_sys_stat.h"

#include <openssl/evp.h>

#include <memory>

using TAO::SSLIOP::Deny_List;
using TAO::SSLIOP::Policy_Tables;
namespace Signed_File = TAO::SSLIOP::Signed_File;
namespace Reason = TAO::Security::Audit_Reason;

namespace
{
  constexpr int EXIT_OK = 0;
  constexpr int EXIT_FAIL = 2;
  constexpr int EXIT_USAGE = 64;

  char const usage_text[] =
    "usage: ace-tao-setup rights|grants|roles sign  --key SPEC [--password-file F] --file DRAFT [--dir DIR]\n"
    "       ace-tao-setup rights|grants|roles check [--dir DIR] [--signer PEM]\n"
    "  sign gives DRAFT the next version and today's date and writes DIR/KIND-YYYY-MM-DD[.N].txt\n"
    "  with its .sig; check shows which file a service would load.  DIR defaults to roles_dir,\n"
    "  PEM to roles_signer; the key must match roles_signer_sha256.\n";

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
      c = static_cast<char> (ACE_OS::ace_tolower (c));
    return s;
  }

  struct Options
  {
    std::string file, key, password_file, signer, dir;
  };

  int
  parse (int argc, ACE_TCHAR *argv[], Options &o, std::string const &what)
  {
    for (int i = 0; i < argc; ++i)
      {
        std::string const a = ACE_TEXT_ALWAYS_CHAR (argv[i]);
        bool const more = i + 1 < argc;
        if (a == "--file" && more) o.file = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--key" && more) o.key = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--password-file" && more) o.password_file = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--signer" && more) o.signer = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--dir" && more) o.dir = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else
          return usage (what + ": unknown option " + a);
      }
    if (o.dir.empty ())
      o.dir = setup_conf_get ("roles_dir");
    while (o.dir.size () > 1 && o.dir[o.dir.size () - 1] == '/')
      o.dir.erase (o.dir.size () - 1);
    if (o.signer.empty ())
      o.signer = setup_conf_get ("roles_signer");
    return EXIT_OK;
  }

  /// The table's body: DRAFT without any table, version or issued line.
  std::string
  body_of (std::string const &draft, size_t &lines)
  {
    std::string out;
    lines = 0;
    for (size_t p = 0; p < draft.size (); )
      {
        size_t e = draft.find ('\n', p);
        if (e == std::string::npos)
          e = draft.size ();
        std::string const line = draft.substr (p, e - p);
        p = e + 1;
        std::string key;
        std::string value;
        bool const content = Signed_File::split_line (line, key, value);
        if (content && (key == "table" || key == "version" || key == "issued"))
          continue;
        if (content)
          ++lines;
        out += line + "\n";
      }
    return out;
  }

  int
  cmd_sign (Policy_Tables::Kind kind, int argc, ACE_TCHAR *argv[])
  {
    std::string const name = Policy_Tables::kind_name (kind);
    Options o;
    if (int const rc = parse (argc, argv, o, name + " sign"))
      return rc;
    if (o.file.empty () || o.key.empty () || o.dir.empty ())
      return usage (name + " sign: --file, --key and --dir (or roles_dir in the configuration) are required");
    ACE_stat st;
    if (ACE_OS::stat (o.dir.c_str (), &st) != 0 || (st.st_mode & S_IFMT) != S_IFDIR)
      return refuse (o.dir + " is not a directory");
    std::string draft;
    if (!Signed_File::slurp (o.file, draft))
      return refuse ("cannot read " + o.file);
    size_t lines = 0;
    std::string const body = body_of (draft, lines);

    // The key: the pinned roles signer, never the deny-list signer.
    std::string password;
    std::string error;
    if (!o.password_file.empty () && !setup_read_password (o.password_file, password, error))
      return refuse (error);
    PKEY key (setup_load_key (o.key, password, error));
    if (!key)
      return refuse (error);
    std::string const spki = Deny_List::spki_sha256 (key.get ());
    std::string const want = lower (setup_conf_get ("roles_signer_sha256"));
    if (!want.empty () && spki != want)
      return refuse ("the key is not the pinned roles signer (roles_signer_sha256 " + want + ")");
    std::string const deny_pin = lower (setup_conf_get ("denylist_signer_sha256"));
    if (!deny_pin.empty () && spki == deny_pin)
      return refuse ("the key is the deny-list signer: policy tables need their own key (D3.7)");

    // The next version: above every KIND file present and the
    // service's recorded mark; the next free name for today.
    long version = 0;
    std::string const issued = setup_iso_time ();
    std::string const date = issued.substr (0, 10);
    unsigned revision = 1;
    for (Policy_Tables::Candidate const &c : Policy_Tables::list (o.dir, kind))
      {
        std::string text;
        Policy_Tables::Table t;
        std::string e;
        if (Signed_File::slurp (c.file, text) && Policy_Tables::parse (text, t, e) && t.version > version)
          version = t.version;
        if (c.date == date && c.revision >= revision)
          revision = c.revision + 1;
      }
    std::map<std::string, long> const state = Policy_Tables::read_state (setup_conf_get ("roles_state"));
    auto const mark = state.find (name);
    if (mark != state.end () && mark->second > version)
      version = mark->second;
    ++version;
    if (revision > 999)
      return refuse ("more than 999 " + name + " tables signed today in " + o.dir);

    std::string const text =
      "table " + name + "\nversion " + std::to_string (version) + "\nissued " + issued + "\n" + body;
    Policy_Tables::Table check;
    if (!Policy_Tables::parse (text, check, error))
      return refuse (o.file + ": " + error);

    std::string sig;
    if (!setup_sign_text (key.get (), text, sig, error))
      return refuse (error);
    PKEY pub (setup_public_key (key.get ()));
    if (!pub || !Deny_List::verify (text, sig, pub.get (), error))
      return refuse ("the new signature does not verify: " + error);
    std::string const path = o.dir + "/" + Policy_Tables::file_name (kind, date, revision);
    // The signature first: a table never appears without it.
    if (!setup_write_atomic (path + ".sig", sig, 0644, error) || !setup_write_atomic (path, text, 0644, error))
      return refuse (error);
    setup_audit (Reason::ROLES_TABLE_SIGNED,
                 {{"table", name}, {"file", path}, {"version", std::to_string (version)},
                  {"lines", std::to_string (lines)}});
    ACE_OS::printf ("%s: table %s version %ld issued %s, %zu line(s); signed into %s.sig\n",
                    path.c_str (), name.c_str (), version, issued.c_str (), lines, path.c_str ());
    return EXIT_OK;
  }

  int
  cmd_check (Policy_Tables::Kind kind, int argc, ACE_TCHAR *argv[])
  {
    std::string const name = Policy_Tables::kind_name (kind);
    Options o;
    if (int const rc = parse (argc, argv, o, name + " check"))
      return rc;
    if (o.dir.empty () || o.signer.empty ())
      return refuse (name + " check: --dir and --signer are required (or roles_dir and roles_signer)");
    std::string const pin = lower (setup_conf_get ("roles_signer_sha256"));
    std::string const state_path = setup_conf_get ("roles_state");
    long floor = 0;
    std::map<std::string, long> const state = Policy_Tables::read_state (state_path);
    auto const mark = state.find (name);
    if (mark != state.end ())
      floor = mark->second;

    std::vector<Policy_Tables::Candidate> cands = Policy_Tables::list (o.dir, kind);
    Policy_Tables::Table t;
    bool const found = Policy_Tables::choose (kind, cands, o.signer, pin, floor, t);
    if (found)
      ACE_OS::printf ("OK: %s version %ld issued %s from %s, %zu line(s)\n", name.c_str (), t.version,
                      t.issued.c_str (), t.file.c_str (), t.lines.size ());
    else
      ACE_OS::printf ("FAIL: no acceptable %s table in %s\n", name.c_str (), o.dir.c_str ());
    ACE_OS::printf ("Signer %s%s; floor %ld%s\n", o.signer.c_str (),
                    pin.empty () ? " (not pinned: set roles_signer_sha256)" : " (pinned)", floor,
                    state_path.empty () ? " (roles_state not set)" : (" (" + state_path + ")").c_str ());
    for (Policy_Tables::Candidate const &c : cands)
      ACE_OS::printf ("  %s  %s\n", c.file.c_str (),
                      c.accepted ? ("loaded, version " + std::to_string (c.version)).c_str ()
                                 : ("refused: " + c.why).c_str ());
    return found ? EXIT_OK : EXIT_FAIL;
  }
}

int
setup_tables (char const *what, int argc, ACE_TCHAR *argv[])
{
  Policy_Tables::Kind kind = Policy_Tables::RIGHTS;
  std::string const w = what;
  if (w == "grants")
    kind = Policy_Tables::GRANTS;
  else if (w == "roles")
    kind = Policy_Tables::ROLES;
  if (argc < 1)
    return usage (w + ": give sign or check");
  std::string const sub = ACE_TEXT_ALWAYS_CHAR (argv[0]);
  if (sub == "sign")
    return cmd_sign (kind, argc - 1, argv + 1);
  if (sub == "check")
    return cmd_check (kind, argc - 1, argv + 1);
  if (sub == "test")
    return usage (w + " test: answers come with the tables' contents (Phase 3 T2)");
  return usage (w + ": unknown subcommand " + sub);
}
