#include "orbsvcs/SSLIOP/SSLIOP_Role_Model.h"
#include "ace/OS_NS_time.h"
#include "orbsvcs/SSLIOP/SSLIOP_Kerberos.h"
#include "orbsvcs/SSLIOP/SSLIOP_Asserter_List.h"

#include "tao/Security_Mode.h"

#include "ace/Guard_T.h"

#include <cctype>
#include <sstream>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  namespace RM = TAO::SSLIOP::Role_Model;
  using Tables = TAO::SSLIOP::Policy_Tables;

  std::vector<std::string>
  words (std::string const &line)
  {
    std::istringstream in (line);
    std::vector<std::string> out;
    for (std::string w; in >> w; )
      out.push_back (w);
    return out;
  }

  std::string
  at (unsigned line, std::string const &what)
  {
    return "line " + std::to_string (line) + ": " + what;
  }

  /// A role name: letters, digits, '-', '_', '.', starting with a letter.
  bool
  role_name (std::string const &r)
  {
    if (r.empty () || r.size () > 64 || !::isalpha (static_cast<unsigned char> (r[0])))
      return false;
    for (char c : r)
      if (!::isalnum (static_cast<unsigned char> (c)) && c != '-' && c != '_' && c != '.')
        return false;
    return true;
  }

  /// The principals the role map is asked about: the asserted name alone
  /// when one is asserted (its asserter's identities are not the
  /// caller's), else the authenticated name and the certificate's names.
  std::vector<std::string>
  names_of (TAO::Security::Caller const &caller)
  {
    std::vector<std::string> out;
    if (!caller.asserted.empty ())
      {
        out.push_back (caller.asserted);
        return out;
      }
    if (!caller.authenticated.empty ())
      out.push_back (caller.authenticated);
    for (std::string const &s : caller.spiffe_ids)
      out.push_back (s);
    if (!caller.subject.empty ())
      out.push_back (caller.subject);
    return out;
  }

  /// No identity at all: no certificate, no login, nothing asserted; or
  /// an asserted anonymous caller (ITTAnonymous).
  bool
  anonymous_caller (TAO::Security::Caller const &caller)
  {
    if (!caller.asserted.empty ())
      return caller.asserted == "anonymous";
    return !caller.local && caller.authenticated.empty () && caller.spiffe_ids.empty () && caller.subject.empty ();
  }

  /// The rest of @a line after its first @a n words, blanks collapsed.
  std::string
  rest_after (std::vector<std::string> const &w, size_t n)
  {
    std::string out;
    for (size_t i = n; i < w.size (); ++i)
      out += (out.empty () ? "" : " ") + w[i];
    return out;
  }

  /// "S-1-" then dash-separated decimal numbers.
  bool
  sid_text (std::string const &s)
  {
    if (s.size () < 5 || s.size () > 184 || s.compare (0, 4, "S-1-") != 0)
      return false;
    bool digit = false;
    for (size_t i = 4; i < s.size (); ++i)
      {
        if (::isdigit (static_cast<unsigned char> (s[i])))
          digit = true;
        else if (s[i] == '-' && digit)
          digit = false;
        else
          return false;
      }
    return digit;
  }
}

bool
TAO::SSLIOP::Role_Model::parse_rights (std::string const &text, unsigned &rights)
{
  rights = 0;
  std::string item;
  std::istringstream in (text);
  bool any = false;
  while (std::getline (in, item, ','))
    {
      if (item == "get") rights |= RIGHT_GET;
      else if (item == "set") rights |= RIGHT_SET;
      else if (item == "manage") rights |= RIGHT_MANAGE;
      else if (item == "use") rights |= RIGHT_USE;
      else
        return false;
      any = true;
    }
  return any;
}

std::string
TAO::SSLIOP::Role_Model::rights_text (unsigned rights)
{
  std::string out;
  char const *const names[] = { "get", "set", "manage", "use" };
  for (unsigned i = 0; i < 4; ++i)
    if ((rights & (1u << i)) != 0)
      out += (out.empty () ? "" : ",") + std::string (names[i]);
  return out.empty () ? "none" : out;
}

bool
TAO::SSLIOP::Role_Model::builtin_operation (std::string const &op)
{
  return op == "_is_a" || op == "_non_existent" || op == "_interface" || op == "_repository_id";
}

bool
TAO::SSLIOP::Role_Model::parse (Policy_Tables::Table const &t, Rights_Table &out, std::string &error)
{
  out = Rights_Table ();
  out.version = t.version;
  for (auto const &l : t.lines)
    {
      std::vector<std::string> const w = words (l.second);
      // inherit DERIVED BASE
      if (!w.empty () && w[0] == "inherit")
        {
          if (w.size () != 3 || w[1].compare (0, 4, "IDL:") != 0 || w[2].compare (0, 4, "IDL:") != 0 || w[1] == w[2])
            {
              error = at (l.first, "expected \"inherit DERIVED BASE\" (two different repository IDs)");
              return false;
            }
          out.bases[w[1]].push_back (w[2]);
          continue;
        }
      // require INTERFACE OPERATION RIGHTS [all|any]
      if (w.empty () || w[0] != "require" || w.size () < 4 || w.size () > 5)
        {
          error = at (l.first, "expected \"require INTERFACE OPERATION RIGHTS [all|any]\" or \"inherit DERIVED BASE\"");
          return false;
        }
      if (w[1].compare (0, 4, "IDL:") != 0)
        {
          error = at (l.first, "the interface must be a repository ID (IDL:...)");
          return false;
        }
      Requirement r;
      r.line = l.first;
      if (!parse_rights (w[3], r.rights))
        {
          error = at (l.first, "unknown right in \"" + w[3] + "\" (get, set, manage, use)");
          return false;
        }
      if (w.size () == 5)
        {
          if (w[4] == "any")
            r.any = true;
          else if (w[4] != "all")
            {
              error = at (l.first, "expected all or any, not \"" + w[4] + "\"");
              return false;
            }
        }
      if (!out.ops.emplace (std::make_pair (w[1], w[2]), r).second)
        {
          error = at (l.first, "a second line for " + w[1] + " " + w[2]);
          return false;
        }
    }
  return true;
}

bool
TAO::SSLIOP::Role_Model::parse (Policy_Tables::Table const &t, Grants_Table &out, std::string &error)
{
  out = Grants_Table ();
  out.version = t.version;
  std::map<std::string, unsigned> *domain = &out.service;
  for (auto const &l : t.lines)
    {
      std::vector<std::string> const w = words (l.second);
      if (!w.empty () && w[0] == "domain")
        {
          if (w.size () != 2 || w[1].size () < 2 || w[1][0] != '/' || w[1][w[1].size () - 1] == '/')
            {
              error = at (l.first, "expected \"domain /POA/path\"");
              return false;
            }
          if (out.poas.count (w[1]) != 0)
            {
              error = at (l.first, "domain " + w[1] + " appears twice");
              return false;
            }
          domain = &out.poas[w[1]];
          continue;
        }
      // grant ROLE RIGHTS
      if (w.size () != 3 || w[0] != "grant")
        {
          error = at (l.first, "expected \"grant ROLE RIGHTS\" or \"domain /POA/path\"");
          return false;
        }
      if (!role_name (w[1]))
        {
          error = at (l.first, "bad role name \"" + w[1] + "\"");
          return false;
        }
      unsigned rights = 0;
      if (!parse_rights (w[2], rights))
        {
          error = at (l.first, "unknown right in \"" + w[2] + "\" (get, set, manage, use)");
          return false;
        }
      (*domain)[w[1]] |= rights;
    }
  return true;
}

bool
TAO::SSLIOP::Role_Model::parse (Policy_Tables::Table const &t, Role_Map &out, std::string &error)
{
  out = Role_Map ();
  out.version = t.version;
  for (auto const &l : t.lines)
    {
      std::vector<std::string> const w = words (l.second);
      if (w.empty ())
        continue;
      if (w[0] == "group")
        {
          // group NAME PRINCIPAL (the rest of the line)
          if (w.size () < 3 || !role_name (w[1]))
            {
              error = at (l.first, "expected \"group NAME PRINCIPAL\" (NAME as a role name)");
              return false;
            }
          std::string const member = rest_after (w, 2);
          if (member == "anonymous" || member.compare (0, 6, "group:") == 0 || member.compare (0, 4, "sid:") == 0)
            {
              error = at (l.first, "a group member is a principal, not \"" + member + "\"");
              return false;
            }
          out.members[w[1]].insert (member);
          continue;
        }
      if (w[0] == "sid")
        {
          // sid SID NAME... (the rest of the line)
          if (w.size () < 3 || !sid_text (w[1]))
            {
              error = at (l.first, "expected \"sid S-1-... NAME\"");
              return false;
            }
          out.sid_names[w[1]] = rest_after (w, 2);
          continue;
        }
      // role WHO ROLE[,ROLE...] [via=ASSERTER] [factors=tls+gssup] [maxage=DURATION]
      if (w[0] != "role" || w.size () < 3)
        {
          error = at (l.first, "expected \"role WHO ROLE[,ROLE...] [via=ASSERTER] [factors=tls+gssup] "
                               "[maxage=DURATION]\", \"group NAME PRINCIPAL\" or \"sid SID NAME\"");
          return false;
        }
      Role_Line rl;
      rl.line = l.first;
      size_t last = w.size ();
      while (last > 3)
        {
          std::string const &o = w[last - 1];
          if (o.compare (0, 4, "via=") == 0)
            {
              if (o.size () == 4 || !rl.via.empty ())
                {
                  error = at (l.first, "via= needs one asserter");
                  return false;
                }
              rl.via = o.substr (4);
            }
          else if (o.compare (0, 8, "factors=") == 0)
            {
              if (o != "factors=tls+gssup" || rl.two_factor)
                {
                  error = at (l.first, "factors= takes tls+gssup (once)");
                  return false;
                }
              rl.two_factor = true;
            }
          else if (o.compare (0, 7, "maxage=") == 0)
            {
              long const age = TAO::SSLIOP::Kerberos::parse_duration (o.substr (7), 30L * 86400);
              if (age <= 0 || rl.max_age != 0)
                {
                  error = at (l.first, "maxage= takes one duration up to 30d (90, 15m, 1h, 1d)");
                  return false;
                }
              rl.max_age = age;
            }
          else
            break;
          --last;
        }
      std::string const who = rest_after (std::vector<std::string> (w.begin (), w.begin () + (last - 1)), 1);
      std::string const &role_list = w[last - 1];
      if (who.empty ())
        {
          error = at (l.first, "no principal");
          return false;
        }
      if (who.compare (0, 6, "group:") == 0 && !role_name (who.substr (6)))
        {
          error = at (l.first, "bad group name \"" + who.substr (6) + "\"");
          return false;
        }
      if (who.compare (0, 4, "sid:") == 0 && !sid_text (who.substr (4)))
        {
          error = at (l.first, "bad SID \"" + who.substr (4) + "\"");
          return false;
        }
      if (who == "anonymous" && rl.two_factor)
        {
          error = at (l.first, "an anonymous caller proves no factors");
          return false;
        }
      if (who == "anonymous" && rl.max_age != 0)
        {
          error = at (l.first, "an anonymous caller has no login to be recent");
          return false;
        }
      std::istringstream in (role_list);
      for (std::string r; std::getline (in, r, ','); )
        {
          if (!role_name (r))
            {
              error = at (l.first, "bad role name \"" + r + "\"");
              return false;
            }
          rl.roles.insert (r);
        }
      if (rl.roles.empty ())
        {
          error = at (l.first, "no role");
          return false;
        }
      out.by_key[who].push_back (rl);
    }
  return true;
}

std::set<std::string>
TAO::SSLIOP::Role_Model::roles_of (Role_Map const &roles, TAO::Security::Caller const &caller,
                                   std::vector<std::string> *sources)
{
  bool const asserted = !caller.asserted.empty ();
  // The keys this caller answers to (R35, R37).
  std::vector<std::string> keys;
  if (anonymous_caller (caller))
    keys.push_back ("anonymous");
  else
    {
      std::vector<std::string> const names = names_of (caller);
      keys = names;
      std::set<std::string> groups;
      for (auto const &g : roles.members)
        for (std::string const &n : names)
          if (g.second.count (n) != 0)
            groups.insert (g.first);
      // Ticket and store groups belong to the authenticated login: an
      // asserted caller does not have them.
      if (!asserted)
        {
          groups.insert (caller.login_groups.begin (), caller.login_groups.end ());
          for (std::string const &sid : caller.groups)
            keys.push_back ("sid:" + sid);
        }
      for (std::string const &g : groups)
        keys.push_back ("group:" + g);
    }

  bool const two_factor = !asserted && caller.authenticated_mech == "gssup" && !caller.transport ().empty ();
  // How long ago the caller logged in (maxage=): only a login of its own.
  long long const login_age = !asserted && caller.auth_time > 0 && !caller.authenticated.empty ()
                              ? static_cast<long long> (ACE_OS::time (nullptr)) - caller.auth_time
                              : -1;
  std::set<std::string> out;
  for (std::string const &k : keys)
    {
      auto const r = roles.by_key.find (k);
      if (r == roles.by_key.end ())
        continue;
      bool used = false;
      for (Role_Line const &rl : r->second)
        {
          if (!rl.via.empty () && !(asserted && !caller.asserter.empty () && (rl.via == "*" || rl.via == caller.asserter)))
            continue;
          if (rl.two_factor && !two_factor)
            continue;
          if (rl.max_age != 0 && (login_age < 0 || login_age > rl.max_age))
            continue;
          out.insert (rl.roles.begin (), rl.roles.end ());
          used = true;
        }
      if (used && sources != nullptr)
        {
          std::string label = k;
          if (k.compare (0, 4, "sid:") == 0)
            {
              auto const n = roles.sid_names.find (k.substr (4));
              if (n != roles.sid_names.end ())
                label += "(" + n->second + ")";
            }
          sources->push_back (label);
        }
    }
  return out;
}

bool
TAO::SSLIOP::Role_Model::check_body (Policy_Tables::Table const &t, std::string &error)
{
  switch (t.kind)
    {
    case Policy_Tables::RIGHTS: { Rights_Table r; return parse (t, r, error); }
    case Policy_Tables::GRANTS: { Grants_Table g; return parse (t, g, error); }
    case Policy_Tables::ROLES: { Role_Map m; return parse (t, m, error); }
    default: error = "unknown table"; return false;
    }
}

namespace
{
  /// Searches @a iface and, breadth first, the interfaces it inherits
  /// from for (interface, @a op); depth and size bounded (a table with an
  /// inheritance cycle cannot loop).
  bool
  find_in_hierarchy (RM::Rights_Table const &rights, std::string const &iface, std::string const &op,
                     RM::Requirement &out)
  {
    std::vector<std::string> level (1, iface);
    std::set<std::string> seen;
    for (int depth = 0; depth < 16 && !level.empty (); ++depth)
      {
        std::vector<std::string> next;
        for (std::string const &i : level)
          {
            if (!seen.insert (i).second)
              continue;
            auto const it = rights.ops.find (std::make_pair (i, op));
            if (it != rights.ops.end ())
              {
                out = it->second;
                return true;
              }
            auto const b = rights.bases.find (i);
            if (b != rights.bases.end ())
              next.insert (next.end (), b->second.begin (), b->second.end ());
          }
        level.swap (next);
      }
    return false;
  }
}

bool
TAO::SSLIOP::Role_Model::lookup (Rights_Table const &rights,
                                 std::string const &interface_id,
                                 std::string const &operation,
                                 Requirement &out)
{
  if (find_in_hierarchy (rights, interface_id, operation, out))
    return true;
  if (!builtin_operation (operation) && find_in_hierarchy (rights, interface_id, "*", out))
    return true;
  if (builtin_operation (operation))
    {
      out = Requirement ();
      out.rights = RIGHT_GET;
      return true;
    }
  return false;
}

TAO::SSLIOP::Role_Model::Decision
TAO::SSLIOP::Role_Model::decide (Rights_Table const &rights,
                                 Grants_Table const &grants,
                                 Role_Map const &roles,
                                 TAO::Security::Caller const &caller,
                                 std::string const &interface_id,
                                 std::string const &object_path,
                                 std::string const &operation,
                                 bool unlisted_allowed,
                                 std::set<std::string> const *cap)
{
  Decision d;

  // What the operation requires (R33).
  d.listed = lookup (rights, interface_id, operation, d.required);

  // The caller's roles (R35 to R37), within its asserter's cap (R36).
  d.roles = roles_of (roles, caller, &d.sources);
  if (cap != nullptr && !caller.asserted.empty ())
    {
      for (auto i = d.roles.begin (); i != d.roles.end (); )
        {
          if (cap->count (*i) == 0)
            {
              d.capped.insert (*i);
              i = d.roles.erase (i);
            }
          else
            ++i;
        }
    }

  // The domain: the longest POA domain the object is in, else the
  // service (R34).
  std::string const poa = object_path.substr (0, object_path.rfind ('/'));
  std::map<std::string, unsigned> const *domain = &grants.service;
  d.domain = "service";
  size_t best = 0;
  for (auto const &p : grants.poas)
    if ((poa == p.first || poa.compare (0, p.first.size () + 1, p.first + "/") == 0) && p.first.size () > best)
      {
        best = p.first.size ();
        domain = &p.second;
        d.domain = p.first;
      }
  for (std::string const &r : d.roles)
    {
      auto const g = domain->find (r);
      if (g != domain->end ())
        d.held |= g->second;
    }

  if (!d.listed)
    {
      d.allowed = unlisted_allowed;
      d.why = "the operation is not in the required-rights table"
              + std::string (unlisted_allowed ? " (allowed: access_default = allow, test mode)" : "");
      return d;
    }
  unsigned const need = d.required.rights;
  d.allowed = d.required.any ? (d.held & need) != 0 : (d.held & need) == need;
  if (d.allowed)
    d.why = "roles hold " + rights_text (d.held & need);
  else if (d.roles.empty ())
    d.why = d.capped.empty () ? "the caller has no role" : "the caller's roles are outside its asserter's roles= cap";
  else
    d.why = "roles hold " + rights_text (d.held) + " in the " + d.domain + " domain, " + (d.required.any ? "any of " : "")
            + rights_text (need) + " required";
  return d;
}

// ------------------------------------------------------------------
// Engine

TAO::SSLIOP::Role_Model::Engine *
TAO::SSLIOP::Role_Model::Engine::instance ()
{
  static Engine engine;
  return &engine;
}

bool
TAO::SSLIOP::Role_Model::Engine::active () const
{
  return Policy_Tables::instance ()->configured ();
}

bool
TAO::SSLIOP::Role_Model::Engine::current (std::shared_ptr<Rights_Table const> &r,
                                          std::shared_ptr<Grants_Table const> &g,
                                          std::shared_ptr<Role_Map const> &m,
                                          std::string &why)
{
  Policy_Tables *const tables = Policy_Tables::instance ();
  std::shared_ptr<Policy_Tables::Table const> raw[Policy_Tables::KIND_COUNT];
  for (int k = 0; k < Policy_Tables::KIND_COUNT; ++k)
    raw[k] = tables->table (static_cast<Policy_Tables::Kind> (k));

  ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, false);
  for (int k = 0; k < Policy_Tables::KIND_COUNT; ++k)
    {
      if (!raw[k])
        {
          why = std::string ("no ") + Policy_Tables::kind_name (static_cast<Policy_Tables::Kind> (k))
                + " table is loaded";
          return false;
        }
      if (raw[k] == this->raw_[k])
        continue;
      std::string error;
      bool ok = false;
      switch (k)
        {
        case Policy_Tables::RIGHTS:
          {
            auto p = std::make_shared<Rights_Table> ();
            ok = parse (*raw[k], *p, error);
            if (ok)
              this->rights_ = p;
            break;
          }
        case Policy_Tables::GRANTS:
          {
            auto p = std::make_shared<Grants_Table> ();
            ok = parse (*raw[k], *p, error);
            if (ok)
              this->grants_ = p;
            break;
          }
        default:
          {
            auto p = std::make_shared<Role_Map> ();
            ok = parse (*raw[k], *p, error);
            if (ok)
              this->roles_ = p;
          }
        }
      if (!ok)
        {
          // The loader checks bodies, so this means a bug: refuse.
          why = std::string (Policy_Tables::kind_name (static_cast<Policy_Tables::Kind> (k))) + ": " + error;
          return false;
        }
      this->raw_[k] = raw[k];
    }
  r = this->rights_;
  g = this->grants_;
  m = this->roles_;
  return true;
}

TAO::SSLIOP::Role_Model::Decision
TAO::SSLIOP::Role_Model::Engine::decide (TAO::Security::Caller const &caller,
                                         std::string const &interface_id,
                                         std::string const &object_path,
                                         std::string const &operation,
                                         std::string &versions)
{
  std::shared_ptr<Rights_Table const> r;
  std::shared_ptr<Grants_Table const> g;
  std::shared_ptr<Role_Map const> m;
  std::string why;
  Decision d;
  if (!this->current (r, g, m, why))
    {
      d.why = "policy tables incomplete: " + why;
      return d;
    }
  versions = "rights v" + std::to_string (r->version) + ", grants v" + std::to_string (g->version) + ", roles v"
             + std::to_string (m->version);

  TAO_Security_Mode::Host_Config const &h = TAO_Security_Mode::host ();
  bool const unlisted_allowed = h.mode != TAO_Security_Mode::MODE_PROD && h.get ("access_default", "allow") == "allow";

  // An asserted caller is bounded by its asserter's roles= (R36).
  std::set<std::string> cap;
  bool capped = false;
  if (!caller.asserted.empty () && !caller.asserter.empty ())
    {
      Asserter_List::Entry e;
      if (Asserter_List::instance ()->find (std::vector<std::string> (1, caller.asserter), e) && e.capped)
        {
          cap = e.roles;
          capped = true;
        }
    }

  // Test-mode RequiredRights changes (R41) apply over the table.
  std::map<std::pair<std::string, std::string>, Requirement> overrides;
  {
    ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, d);
    overrides = this->overrides_;
  }
  if (overrides.empty ())
    return Role_Model::decide (*r, *g, *m, caller, interface_id, object_path, operation, unlisted_allowed,
                               capped ? &cap : nullptr);
  Rights_Table merged = *r;
  for (auto const &o : overrides)
    merged.ops[o.first] = o.second;
  return Role_Model::decide (merged, *g, *m, caller, interface_id, object_path, operation, unlisted_allowed,
                             capped ? &cap : nullptr);
}

bool
TAO::SSLIOP::Role_Model::Engine::required (std::string const &interface_id, std::string const &operation,
                                           Requirement &out)
{
  {
    ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, false);
    auto const o = this->overrides_.find (std::make_pair (interface_id, operation));
    if (o != this->overrides_.end ())
      {
        out = o->second;
        return true;
      }
  }
  std::shared_ptr<Rights_Table const> r;
  std::shared_ptr<Grants_Table const> g;
  std::shared_ptr<Role_Map const> m;
  std::string why;
  if (!this->current (r, g, m, why))
    return false;
  return lookup (*r, interface_id, operation, out);
}

void
TAO::SSLIOP::Role_Model::Engine::override_required (std::string const &interface_id, std::string const &operation,
                                                    Requirement const &r)
{
  ACE_GUARD (TAO_SYNCH_MUTEX, guard, this->lock_);
  this->overrides_[std::make_pair (interface_id, operation)] = r;
}

TAO_END_VERSIONED_NAMESPACE_DECL
