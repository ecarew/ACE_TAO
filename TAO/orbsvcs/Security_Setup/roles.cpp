// ace-tao-setup rights | grants | roles: sign and check the role model's
// signed policy tables (Phase 3 T1, R40; format and security.conf keys in
// orbsvcs/SSLIOP/SSLIOP_Policy_Tables.h).
//
//   KIND sign  --key SPEC [--password-file F] --file DRAFT [--dir DIR]
//   KIND check [--dir DIR] [--signer PEM]
//   roles test --principal P --interface ID --op OP [--object PATH] [--dir DIR] [--signer PEM]
//              [--cert NAME] [--groups G,...] [--sids SID,...]
//              [--asserted NAME --via ASSERTER [--cap ROLE,...]] [--anonymous]
//   roles import [--access LIST] [--out DRAFT]
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
// DIR defaults to roles_dir, PEM to roles_signer.  test loads the three
// tables as a service would and says whether principal P may call OP on
// an object of interface ID (repository ID) at PATH, and why, with prod's
// rules (exit 0 allowed, 2 refused).  The interim access list's explicit
// denies, which a service checks first, are not consulted.  P is a SPIFFE
// ID or subject DN (a certificate) or user@realm (a login); --cert adds
// the certificate a login came over (for factors=tls+gssup), --groups the
// login's store groups, --sids its ticket's group SIDs.  --asserted makes
// NAME the caller, asserted by --via (P is then the asserter), and --cap
// is that asserter's roles= from the asserter list.  --anonymous asks
// about a caller with no identity.
//
// import drafts a role map from the interim access list (LIST defaults to
// access_list; the draft goes to stdout or DRAFT): one role for each
// distinct set of allow rules, a role line for each principal, with
// via= kept, and comments listing the rules each role stands for.  The
// draft still needs review and grants for its roles; deny rules and
// "allow *" rules are listed as not imported.

#include "keys.h"

#include "orbsvcs/SSLIOP/SSLIOP_Access_List.h"
#include "orbsvcs/SSLIOP/SSLIOP_Deny_List.h"
#include "orbsvcs/SSLIOP/SSLIOP_Policy_Tables.h"
#include "orbsvcs/SSLIOP/SSLIOP_Role_Model.h"
#include "orbsvcs/SSLIOP/SSLIOP_Signed_File.h"
#include "orbsvcs/Security/Audit_Logger.h"

#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_ctype.h"
#include "ace/OS_NS_sys_stat.h"

#include <openssl/evp.h>

#include <map>
#include <memory>
#include <set>
#include <sstream>

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
    "       ace-tao-setup roles test --principal P --interface ID --op OP [--object PATH] [--dir DIR]\n"
    "            [--cert NAME] [--groups G,...] [--sids SID,...]\n"
    "            [--asserted NAME --via ASSERTER [--cap ROLE,...]] [--anonymous]\n"
    "       ace-tao-setup roles import [--access LIST] [--out DRAFT]\n"
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
    std::string principal, interface_id, op, object;
    std::string cert, groups, sids, asserted, via, cap, access, out;
    bool has_cap = false;
    bool anonymous = false;
  };

  std::vector<std::string>
  split_list (std::string const &s)
  {
    std::vector<std::string> out;
    std::istringstream in (s);
    for (std::string item; std::getline (in, item, ','); )
      if (!item.empty ())
        out.push_back (item);
    return out;
  }

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
        else if (a == "--principal" && more) o.principal = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--interface" && more) o.interface_id = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--op" && more) o.op = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--object" && more) o.object = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--cert" && more) o.cert = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--groups" && more) o.groups = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--sids" && more) o.sids = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--asserted" && more) o.asserted = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--via" && more) o.via = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--cap" && more) { o.cap = ACE_TEXT_ALWAYS_CHAR (argv[++i]); o.has_cap = true; }
        else if (a == "--access" && more) o.access = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--out" && more) o.out = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--anonymous") o.anonymous = true;
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
    // The syntax a service checks before loading (line numbers count the
    // three header lines sign adds).
    if (!TAO::SSLIOP::Role_Model::check_body (check, error))
      return refuse (o.file + ": " + error + " (line numbers include the 3 header lines)");

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

namespace
{
  int
  cmd_test (int argc, ACE_TCHAR *argv[])
  {
    namespace RM = TAO::SSLIOP::Role_Model;
    Options o;
    if (int const rc = parse (argc, argv, o, "roles test"))
      return rc;
    if ((o.principal.empty () && !o.anonymous) || o.interface_id.empty () || o.op.empty ())
      return usage ("roles test: --principal (or --anonymous), --interface and --op are required");
    if (o.anonymous && (!o.principal.empty () || !o.asserted.empty ()))
      return usage ("roles test: --anonymous takes no --principal or --asserted");
    if (!o.asserted.empty () && o.via.empty ())
      return usage ("roles test: --asserted needs --via (the asserter)");
    if (o.has_cap && o.asserted.empty ())
      return usage ("roles test: --cap applies to an asserted caller (--asserted)");
    if (o.dir.empty () || o.signer.empty ())
      return refuse ("roles test: --dir and --signer are required (or roles_dir and roles_signer)");
    if (o.object.empty ())
      o.object = "/RootPOA/object";
    std::string const pin = lower (setup_conf_get ("roles_signer_sha256"));
    std::map<std::string, long> const state = Policy_Tables::read_state (setup_conf_get ("roles_state"));

    Policy_Tables::Table t[Policy_Tables::KIND_COUNT];
    std::string versions;
    for (int k = 0; k < Policy_Tables::KIND_COUNT; ++k)
      {
        Policy_Tables::Kind const kind = static_cast<Policy_Tables::Kind> (k);
        auto const mark = state.find (Policy_Tables::kind_name (kind));
        std::vector<Policy_Tables::Candidate> cands = Policy_Tables::list (o.dir, kind);
        if (!Policy_Tables::choose (kind, cands, o.signer, pin, mark != state.end () ? mark->second : 0, t[k]))
          return refuse (std::string ("no acceptable ") + Policy_Tables::kind_name (kind) + " table in " + o.dir
                         + " (see: ace-tao-setup " + Policy_Tables::kind_name (kind) + " check)");
        versions += (k == 0 ? "" : ", ") + std::string (Policy_Tables::kind_name (kind)) + " v"
                    + std::to_string (t[k].version);
      }
    RM::Rights_Table rights;
    RM::Grants_Table grants;
    RM::Role_Map roles;
    std::string error;
    if (!RM::parse (t[0], rights, error) || !RM::parse (t[1], grants, error) || !RM::parse (t[2], roles, error))
      return refuse (error);

    // The caller as a service would see it: a certificate (SPIFFE ID or
    // subject), a login (user@realm, GSSUP or Kerberos) perhaps over a
    // certificate, perhaps asserting another caller.
    TAO::Security::Caller caller;
    auto set_cert = [&caller] (std::string const &n)
    {
      if (n.compare (0, 9, "spiffe://") == 0)
        caller.spiffe_ids.push_back (n);
      else
        caller.subject = n;
    };
    if (!o.principal.empty ())
      {
        if (o.principal.compare (0, 9, "spiffe://") == 0 || o.principal.find ('=') != std::string::npos)
          set_cert (o.principal);
        else
          {
            caller.authenticated = o.principal;
            caller.authenticated_mech = "gssup";
          }
      }
    if (!o.cert.empty ())
      set_cert (o.cert);
    caller.login_groups = split_list (o.groups);
    caller.groups = split_list (o.sids);
    if (!o.asserted.empty ())
      {
        caller.asserted = o.asserted;
        caller.asserter = o.via;
      }
    std::set<std::string> cap;
    for (std::string const &r : split_list (o.cap))
      cap.insert (r);
    RM::Decision const d = RM::decide (rights, grants, roles, caller, o.interface_id, o.object, o.op, false,
                                       o.has_cap ? &cap : nullptr);
    std::string held, from, capped;
    for (std::string const &role : d.roles)
      held += (held.empty () ? "" : ",") + role;
    for (std::string const &f : d.sources)
      from += (from.empty () ? "" : "; ") + f;
    for (std::string const &c : d.capped)
      capped += (capped.empty () ? "" : ",") + c;
    std::string const who = o.anonymous ? std::string ("anonymous") : caller.effective ();
    ACE_OS::printf ("%s: %s %s on %s (%s)\n", d.allowed ? "ALLOWED" : "REFUSED", who.c_str (), o.op.c_str (),
                    o.object.c_str (), o.interface_id.c_str ());
    if (!from.empty ())
      ACE_OS::printf ("  roles from: %s\n", from.c_str ());
    if (!capped.empty ())
      ACE_OS::printf ("  removed by the asserter's cap: %s\n", capped.c_str ());
    ACE_OS::printf ("  roles %s; requires %s; %s domain; %s\n", held.empty () ? "(none)" : held.c_str (),
                    d.listed ? ((d.required.any ? "any of " : "") + RM::rights_text (d.required.rights)).c_str ()
                             : "(not listed)",
                    d.domain.c_str (), d.why.c_str ());
    ACE_OS::printf ("  tables: %s\n", versions.c_str ());
    return d.allowed ? EXIT_OK : EXIT_FAIL;
  }

  /// One access-list rule as text (for the draft's comments).
  std::string
  rule_text (TAO::SSLIOP::Access_List::Rule const &r)
  {
    std::string t = r.object.empty () && r.prefix ? std::string ("*") : r.object + (r.prefix ? "*" : "");
    if (r.operations.empty ())
      t += " (all operations)";
    for (std::string const &op : r.operations)
      t += " " + op;
    return t;
  }

  int
  cmd_import (int argc, ACE_TCHAR *argv[])
  {
    using TAO::SSLIOP::Access_List;
    Options o;
    if (int const rc = parse (argc, argv, o, "roles import"))
      return rc;
    if (o.access.empty ())
      o.access = setup_conf_get ("access_list");
    if (o.access.empty ())
      return usage ("roles import: --access (or access_list in the configuration) is required");
    std::string text;
    if (!Signed_File::slurp (o.access, text))
      return refuse ("cannot read " + o.access);
    Access_List::Content c;
    std::string error;
    if (!Access_List::parse (text, c, error))
      return refuse (o.access + ": " + error);

    // (principal, via) -> its allow rules, as text, in order.
    std::map<std::pair<std::string, std::string>, std::vector<std::string>> by_who;
    std::vector<std::string> skipped;
    for (Access_List::Rule const &r : c.rules)
      {
        std::string const line = std::string (r.allow ? "allow " : "deny ") + r.principal + " " + rule_text (r)
                                 + (r.via.empty () ? "" : " via=" + r.via);
        if (!r.allow)
          skipped.push_back (line + "  (deny: stays in the access list, applied first)");
        else if (r.principal == "*")
          skipped.push_back (line + "  (any identified caller: name the principals or a group)");
        else
          by_who[std::make_pair (r.principal, r.via)].push_back (rule_text (r));
      }

    // One role for each distinct set of rules.
    std::map<std::vector<std::string>, std::string> role_of;
    std::vector<std::vector<std::string>> order;
    for (auto const &w : by_who)
      if (role_of.find (w.second) == role_of.end ())
        {
          role_of[w.second] = "imported-" + std::to_string (role_of.size () + 1);
          order.push_back (w.second);
        }

    std::string out = "# Role map drafted by \"ace-tao-setup roles import\" from " + o.access + " (version "
                      + std::to_string (c.version) + ", " + std::to_string (c.rules.size ()) + " rule(s)).\n"
                      "# Review it before signing: rename the roles, give each role its rights in\n"
                      "# the grants table (with a domain for objects that need one), and list the\n"
                      "# operations in the rights table.  Roles grant rights, not objects, so a\n"
                      "# role's rules below are what it replaces, not what it will allow.\n";
    for (auto const &rules : order)
      {
        out += "#\n# " + role_of[rules] + " stands for:\n";
        for (std::string const &r : rules)
          out += "#   allow " + r + "\n";
      }
    out += "\n";
    for (auto const &w : by_who)
      out += "role " + w.first.first + " " + role_of[w.second] + (w.first.second.empty () ? "" : " via=" + w.first.second)
             + "\n";
    if (!skipped.empty ())
      {
        out += "\n# Not imported:\n";
        for (std::string const &l : skipped)
          out += "#   " + l + "\n";
      }
    if (o.out.empty ())
      ACE_OS::fputs (out.c_str (), stdout);
    else
      {
        FILE *const f = ACE_OS::fopen (o.out.c_str (), "w");
        if (f == nullptr || ACE_OS::fputs (out.c_str (), f) < 0 || ACE_OS::fclose (f) != 0)
          return refuse ("cannot write " + o.out);
        ACE_OS::printf ("drafted %zu role line(s) and %zu role(s) into %s; %zu rule(s) not imported\n",
                        by_who.size (), order.size (), o.out.c_str (), skipped.size ());
      }
    return EXIT_OK;
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
  if (sub == "test" && kind == Policy_Tables::ROLES)
    return cmd_test (argc - 1, argv + 1);
  if (sub == "import" && kind == Policy_Tables::ROLES)
    return cmd_import (argc - 1, argv + 1);
  return usage (w + ": unknown subcommand " + sub);
}
