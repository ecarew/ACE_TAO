#include "orbsvcs/SSLIOP/SSLIOP_Policy_Tables.h"
#include "orbsvcs/SSLIOP/SSLIOP_Signed_File.h"
#include "orbsvcs/SSLIOP/SSLIOP_Role_Model.h"
#include "orbsvcs/Security/Audit_Logger.h"

#include "tao/Security_Mode.h"

#include "ace/Dirent.h"
#include "ace/Guard_T.h"
#include "ace/OS_NS_fcntl.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_sys_stat.h"
#include "ace/OS_NS_time.h"
#include "ace/OS_NS_unistd.h"

#include <algorithm>
#include <cctype>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  using TAO::Security::Audit_Logger;
  using TAO::Security::Audit_Record;
  namespace Reason = TAO::Security::Audit_Reason;
  namespace Signed_File = TAO::SSLIOP::Signed_File;
  using Tables = TAO::SSLIOP::Policy_Tables;

  bool
  digits (std::string const &s, size_t from, size_t n)
  {
    if (from + n > s.size ())
      return false;
    for (size_t i = from; i < from + n; ++i)
      if (!::isdigit (static_cast<unsigned char> (s[i])))
        return false;
    return true;
  }

  /// "YYYY-MM-DD", checked as a real calendar date.
  bool
  valid_date (std::string const &d)
  {
    if (d.size () != 10 || d[4] != '-' || d[7] != '-' || !digits (d, 0, 4) || !digits (d, 5, 2) || !digits (d, 8, 2))
      return false;
    time_t t = 0;
    return Signed_File::parse_time (d + "T00:00:00Z", t);
  }
}

char const *
TAO::SSLIOP::Policy_Tables::kind_name (Kind k)
{
  switch (k)
    {
    case RIGHTS: return "rights";
    case GRANTS: return "grants";
    case ROLES: return "roles";
    default: return "?";
    }
}

bool
TAO::SSLIOP::Policy_Tables::parse_name (std::string const &name, Kind &kind, std::string &date, unsigned &revision)
{
  for (int k = 0; k < KIND_COUNT; ++k)
    {
      std::string const prefix = std::string (kind_name (static_cast<Kind> (k))) + "-";
      if (name.compare (0, prefix.size (), prefix) != 0)
        continue;
      std::string rest = name.substr (prefix.size ());
      if (rest.size () < 14 || rest.compare (rest.size () - 4, 4, ".txt") != 0)
        return false;
      rest.erase (rest.size () - 4);                 // YYYY-MM-DD or YYYY-MM-DD.N
      std::string const d = rest.substr (0, 10);
      if (!valid_date (d))
        return false;
      unsigned rev = 1;
      if (rest.size () > 10)
        {
          if (rest[10] != '.' || rest.size () > 14 || !digits (rest, 11, rest.size () - 11) || rest[11] == '0')
            return false;
          rev = static_cast<unsigned> (ACE_OS::atoi (rest.c_str () + 11));
          if (rev < 2)
            return false;
        }
      kind = static_cast<Kind> (k);
      date = d;
      revision = rev;
      return true;
    }
  return false;
}

std::string
TAO::SSLIOP::Policy_Tables::file_name (Kind kind, std::string const &date, unsigned revision)
{
  std::string n = std::string (kind_name (kind)) + "-" + date;
  if (revision > 1)
    n += "." + std::to_string (revision);
  return n + ".txt";
}

bool
TAO::SSLIOP::Policy_Tables::parse (std::string const &text, Table &out, std::string &error)
{
  out = Table ();
  unsigned header = 0;   // header lines seen: table, version, issued
  unsigned number = 0;
  for (size_t p = 0; p < text.size (); )
    {
      size_t e = text.find ('\n', p);
      if (e == std::string::npos)
        e = text.size ();
      std::string const line = text.substr (p, e - p);
      p = e + 1;
      ++number;
      std::string key;
      std::string value;
      if (!Signed_File::split_line (line, key, value))
        continue;
      if (header < 3)
        {
          char const *const want[] = { "table", "version", "issued" };
          if (key != want[header])
            {
              error = "line " + std::to_string (number) + ": expected \"" + want[header] + "\"";
              return false;
            }
          if (header == 0)
            {
              bool found = false;
              for (int k = 0; k < KIND_COUNT; ++k)
                if (value == kind_name (static_cast<Kind> (k)))
                  {
                    out.kind = static_cast<Kind> (k);
                    found = true;
                  }
              if (!found)
                {
                  error = "line " + std::to_string (number) + ": unknown table \"" + value + "\"";
                  return false;
                }
            }
          else if (header == 1)
            {
              char *end = nullptr;
              long const v = ACE_OS::strtol (value.c_str (), &end, 10);
              if (value.empty () || *end != '\0' || v <= 0)
                {
                  error = "line " + std::to_string (number) + ": bad version \"" + value + "\"";
                  return false;
                }
              out.version = v;
            }
          else
            {
              if (!Signed_File::parse_time (value, out.issued_time))
                {
                  error = "line " + std::to_string (number) + ": bad issued time \"" + value + "\"";
                  return false;
                }
              out.issued = value;
            }
          ++header;
          continue;
        }
      out.lines.emplace_back (number, Signed_File::trim (line));
    }
  if (header < 3)
    {
      error = "no table, version and issued header";
      return false;
    }
  return true;
}

std::vector<TAO::SSLIOP::Policy_Tables::Candidate>
TAO::SSLIOP::Policy_Tables::list (std::string const &dir, Kind kind)
{
  std::vector<Candidate> out;
  ACE_Dirent d;
  if (dir.empty () || d.open (ACE_TEXT_CHAR_TO_TCHAR (dir.c_str ())) == -1)
    return out;
  for (ACE_DIRENT *e = d.read (); e != nullptr; e = d.read ())
    {
#if defined (ACE_LACKS_STRUCT_DIR)
      // ACE's own dirent (Windows): an ACE_TCHAR name.
      std::string const name = ACE_TEXT_ALWAYS_CHAR (e->d_name);
#else
      std::string const name = e->d_name;
#endif /* ACE_LACKS_STRUCT_DIR */
      Kind k = RIGHTS;
      Candidate c;
      if (!parse_name (name, k, c.date, c.revision) || k != kind)
        continue;
      c.file = dir + "/" + name;
      out.push_back (c);
    }
  d.close ();
  std::sort (out.begin (), out.end (), [] (Candidate const &a, Candidate const &b) {
    return a.date != b.date ? a.date > b.date : a.revision > b.revision;
  });
  return out;
}

bool
TAO::SSLIOP::Policy_Tables::choose (Kind kind,
                                    std::vector<Candidate> &cands,
                                    std::string const &signer,
                                    std::string const &pin,
                                    long floor,
                                    Table &out)
{
  Candidate *best = nullptr;
  Table best_table;
  for (Candidate &c : cands)
    {
      std::string text;
      std::string error;
      Table t;
      if (!Signed_File::read_verified (c.file, signer, pin, text, error))
        {
          c.why = error;
          continue;
        }
      if (!parse (text, t, error))
        {
          c.why = error;
          continue;
        }
      c.version = t.version;
      if (t.kind != kind)
        {
          c.why = std::string ("its header names table \"") + kind_name (t.kind) + "\"";
          continue;
        }
      if (!TAO::SSLIOP::Role_Model::check_body (t, error))
        {
          c.why = "its body does not parse: " + error;
          continue;
        }
      if (t.issued.compare (0, 10, c.date) != 0)
        {
          c.why = "its signed issued date " + t.issued.substr (0, 10) + " does not match the date in its name"
                  " (renamed?)";
          continue;
        }
      if (t.version < floor)
        {
          c.why = "version " + std::to_string (t.version) + " is below " + std::to_string (floor)
                  + ", the lowest acceptable (the version in force, or the last one recorded in roles_state)";
          continue;
        }
      // Highest version wins; a tie goes to the newer name (first seen).
      if (best == nullptr || t.version > best_table.version)
        {
          best = &c;
          t.file = c.file;
          best_table = t;
        }
    }
  for (Candidate &c : cands)
    {
      if (&c == best)
        c.accepted = true;
      else if (c.why.empty () && best != nullptr)
        c.why = "version " + std::to_string (c.version) + " is not the highest ("
                + std::to_string (best_table.version) + " is)";
    }
  if (best == nullptr)
    return false;
  out = best_table;
  return true;
}

std::map<std::string, long>
TAO::SSLIOP::Policy_Tables::read_state (std::string const &path)
{
  std::map<std::string, long> out;
  std::string text;
  if (path.empty () || !Signed_File::slurp (path, text))
    return out;
  for (size_t p = 0; p < text.size (); )
    {
      size_t e = text.find ('\n', p);
      if (e == std::string::npos)
        e = text.size ();
      std::string key;
      std::string value;
      if (Signed_File::split_line (text.substr (p, e - p), key, value))
        out[key] = ACE_OS::strtol (value.c_str (), nullptr, 10);
      p = e + 1;
    }
  return out;
}

TAO::SSLIOP::Policy_Tables::Policy_Tables ()
{
  TAO_Security_Mode::Host_Config const &h = TAO_Security_Mode::host ();
  this->dir_ = h.get ("roles_dir");
  while (this->dir_.size () > 1 && this->dir_.back () == '/')
    this->dir_.pop_back ();
  this->signer_path_ = h.get ("roles_signer");
  this->signer_pin_ = h.get ("roles_signer_sha256");
  for (char &c : this->signer_pin_)
    c = static_cast<char> (::tolower (static_cast<unsigned char> (c)));
  this->state_path_ = h.get ("roles_state");
  long const r = ACE_OS::atoi (h.get ("roles_reload", "30").c_str ());
  this->reload_seconds_ = r > 0 ? r : 30;
}

TAO::SSLIOP::Policy_Tables *
TAO::SSLIOP::Policy_Tables::instance ()
{
  static Policy_Tables tables;
  return &tables;
}

bool
TAO::SSLIOP::Policy_Tables::configured () const
{
  return !this->dir_.empty ();
}

std::shared_ptr<TAO::SSLIOP::Policy_Tables::Table const>
TAO::SSLIOP::Policy_Tables::table (Kind kind) const
{
  ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, std::shared_ptr<Table const> ());
  return kind < KIND_COUNT ? this->tables_[kind] : std::shared_ptr<Table const> ();
}

long
TAO::SSLIOP::Policy_Tables::version (Kind kind) const
{
  std::shared_ptr<Table const> const t = this->table (kind);
  return t ? t->version : 0;
}

std::string
TAO::SSLIOP::Policy_Tables::stamp () const
{
  std::string s;
  for (int k = 0; k < KIND_COUNT; ++k)
    for (Candidate const &c : list (this->dir_, static_cast<Kind> (k)))
      s += c.file + "=" + Signed_File::stamp (c.file) + ";";
  return s;
}

void
TAO::SSLIOP::Policy_Tables::save_state (Kind kind, long version)
{
  if (this->state_path_.empty ())
    return;
  std::map<std::string, long> state = read_state (this->state_path_);
  long &mark = state[kind_name (kind)];
  if (version <= mark)
    return;
  mark = version;
  std::string text = "# Highest policy table versions accepted (written by the service).\n";
  for (auto const &e : state)
    text += e.first + " " + std::to_string (e.second) + "\n";
  std::string const tmp = this->state_path_ + ".tmp";
  ACE_HANDLE const fd = ACE_OS::open (tmp.c_str (), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  bool ok = fd != ACE_INVALID_HANDLE
            && ACE_OS::write (fd, text.data (), text.size ()) == static_cast<ssize_t> (text.size ());
  if (fd != ACE_INVALID_HANDLE)
    ACE_OS::close (fd);
  ok = ok && ACE_OS::rename (tmp.c_str (), this->state_path_.c_str ()) == 0;
  if (!ok)
    Audit_Logger::instance ()->write (
      Audit_Record ("roles", false, Reason::ROLES_TABLE_REJECTED)
        .field ("table", kind_name (kind))
        .field ("state", this->state_path_)
        .text ("cannot record the accepted version in roles_state: a restart could roll this table back"));
}

bool
TAO::SSLIOP::Policy_Tables::update (Kind kind, bool startup, std::string &error)
{
  std::shared_ptr<Table const> const current = this->table (kind);
  long floor = 0;
  if (!this->state_path_.empty ())
    {
      std::map<std::string, long> const state = read_state (this->state_path_);
      auto const it = state.find (kind_name (kind));
      if (it != state.end ())
        floor = it->second;
    }
  // A reload needs a higher version than the table in force.
  if (current && current->version + 1 > floor)
    floor = current->version + 1;

  std::vector<Candidate> cands = list (this->dir_, kind);
  Table t;
  bool const found = choose (kind, cands, this->signer_path_, this->signer_pin_, floor, t);

  // Audit each refusal once per file version on disk (not every reload),
  // but skip files older than the table in force, which a reload always
  // passes over.
  for (Candidate const &c : cands)
    {
      if (c.accepted || c.why.empty ())
        continue;
      if (current && c.file == current->file)
        continue;
      if (!startup && current && c.version > 0 && c.version <= current->version
          && c.why.compare (0, 8, "version ") == 0)
        continue;
      std::string const key = c.file + "=" + Signed_File::stamp (c.file);
      {
        ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, false);
        if (!this->reported_.insert (key).second)
          continue;
      }
      Audit_Logger::instance ()->write (
        Audit_Record ("roles", false, Reason::ROLES_TABLE_REJECTED)
          .field ("table", kind_name (kind))
          .field ("file", c.file)
          .text (c.why.c_str ()));
    }

  if (!found)
    {
      if (!current)
        error = std::string (kind_name (kind)) + ": "
                + (cands.empty () ? "no " + std::string (kind_name (kind)) + "-YYYY-MM-DD.txt file in " + this->dir_
                                  : "no file verifies and qualifies (see ROLES_TABLE_REJECTED)");
      return current != nullptr;
    }

  std::shared_ptr<Table const> const fresh = std::make_shared<Table const> (t);
  {
    ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, false);
    this->tables_[kind] = fresh;
  }
  this->save_state (kind, fresh->version);
  Audit_Record rec ("roles", true, Reason::ROLES_TABLE_LOADED);
  rec.field ("table", kind_name (kind))
    .field ("version", std::to_string (fresh->version))
    .field ("issued", fresh->issued)
    .field ("file", fresh->file)
    .field ("lines", std::to_string (fresh->lines.size ()));
  if (current)
    rec.field ("replaces", std::to_string (current->version));
  Audit_Logger::instance ()->write (rec);
  return true;
}

bool
TAO::SSLIOP::Policy_Tables::load (std::string &summary, std::string &error)
{
  if (!this->configured ())
    {
      error = "roles_dir is not set";
      return false;
    }
  {
    ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, false);
    this->last_check_ = ACE_OS::time (nullptr);
  }
  std::string const stamp = this->stamp ();
  bool ok = true;
  for (int k = 0; k < KIND_COUNT; ++k)
    {
      std::string e;
      if (!this->update (static_cast<Kind> (k), true, e))
        {
          ok = false;
          error += (error.empty () ? "" : "; ") + e;
        }
    }
  {
    ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, false);
    this->stamp_ = stamp;
  }
  summary.clear ();
  for (int k = 0; k < KIND_COUNT; ++k)
    {
      long const v = this->version (static_cast<Kind> (k));
      summary += (k == 0 ? "" : ", ") + std::string (kind_name (static_cast<Kind> (k)))
                 + (v > 0 ? " v" + std::to_string (v) : " missing");
    }
  return ok;
}

void
TAO::SSLIOP::Policy_Tables::refresh ()
{
  if (!this->configured ())
    return;
  time_t const now = ACE_OS::time (nullptr);
  {
    ACE_GUARD (TAO_SYNCH_MUTEX, guard, this->lock_);
    if (now - this->last_check_ < this->reload_seconds_)
      return;
    this->last_check_ = now;
  }
  std::string const stamp = this->stamp ();
  {
    ACE_GUARD (TAO_SYNCH_MUTEX, guard, this->lock_);
    if (stamp == this->stamp_)
      return;
    this->stamp_ = stamp;
  }
  for (int k = 0; k < KIND_COUNT; ++k)
    {
      std::string error;
      (void) this->update (static_cast<Kind> (k), false, error);
    }
}

TAO_END_VERSIONED_NAMESPACE_DECL
