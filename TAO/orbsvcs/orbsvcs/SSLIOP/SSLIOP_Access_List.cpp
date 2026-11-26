#include "orbsvcs/SSLIOP/SSLIOP_Access_List.h"
#include "orbsvcs/SSLIOP/SSLIOP_Signed_File.h"

#include "orbsvcs/Security/Audit_Logger.h"
#include "tao/Security_Mode.h"
#include "tao/orbconf.h"

#include "ace/Guard_T.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_time.h"
#include <cctype>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  using TAO::Security::Audit_Logger;
  using TAO::Security::Audit_Record;
  namespace Reason = TAO::Security::Audit_Reason;
  namespace Signed_File = TAO::SSLIOP::Signed_File;

  std::string
  lower (std::string s)
  {
    for (char &c : s)
      c = static_cast<char> (::tolower (static_cast<unsigned char> (c)));
    return s;
  }

  /// Splits @a value at blanks.
  std::vector<std::string>
  words (std::string const &value)
  {
    std::vector<std::string> out;
    size_t p = 0;
    while (p < value.size ())
      {
        size_t const b = value.find_first_not_of (" \t", p);
        if (b == std::string::npos)
          break;
        size_t const e = value.find_first_of (" \t", b);
        out.push_back (value.substr (b, e == std::string::npos ? std::string::npos : e - b));
        p = e == std::string::npos ? value.size () : e;
      }
    return out;
  }
}

bool
TAO::SSLIOP::Access_List::parse (std::string const &text, Content &out, std::string &error)
{
  out = Content ();
  size_t line_no = 0;
  for (size_t p = 0; p < text.size (); )
    {
      size_t e = text.find ('\n', p);
      if (e == std::string::npos)
        e = text.size ();
      std::string const raw = text.substr (p, e - p);
      p = e + 1;
      ++line_no;
      std::string key, value;
      if (!Signed_File::split_line (raw, key, value))
        continue;
      std::string const where = "line " + std::to_string (line_no) + ": ";
      if (value.empty ())
        {
          error = where + "\"" + key + "\" has no value";
          return false;
        }
      if (key == "version")
        {
          char *end = nullptr;
          long const v = ACE_OS::strtol (value.c_str (), &end, 10);
          if (end == nullptr || *end != '\0' || v <= 0 || out.version != 0)
            {
              error = where + "version must be one positive integer";
              return false;
            }
          out.version = v;
        }
      else if (key == "issued")
        {
          if (!Signed_File::parse_time (value, out.issued_time) || !out.issued.empty ())
            {
              error = where + "issued must be one time like 2026-11-24T12:00:00Z";
              return false;
            }
          out.issued = value;
        }
      else if (key == "allow" || key == "deny")
        {
          std::vector<std::string> const w = words (value);
          if (w.size () < 2)
            {
              error = where + key + " needs a principal and an object";
              return false;
            }
          Rule r;
          r.allow = key == "allow";
          r.principal = w[0];
          std::string object = w[1];
          if (object != "*" && object[0] != '/')
            {
              error = where + "the object must be * or start with /";
              return false;
            }
          size_t const star = object.find ('*');
          if (star != std::string::npos && star != object.size () - 1)
            {
              error = where + "* may only end the object";
              return false;
            }
          r.prefix = star != std::string::npos;
          r.object = r.prefix ? object.substr (0, star) : object;
          for (size_t i = 2; i < w.size (); ++i)
            {
              if (w[i].compare (0, 4, "via=") == 0)
                {
                  if (w[i].size () == 4 || !r.via.empty ())
                    {
                      error = where + "via= needs one asserter";
                      return false;
                    }
                  r.via = w[i].substr (4);
                }
              else
                r.operations.insert (w[i]);
            }
          out.rules.push_back (r);
        }
      else
        {
          error = where + "unknown key \"" + key + "\"";
          return false;
        }
    }
  if (out.version == 0 || out.issued.empty ())
    {
      error = "version and issued are required";
      return false;
    }
  return true;
}

TAO::Security::Caller_Policy::Result
TAO::SSLIOP::Access_List::evaluate (Content const &list,
                                    TAO::Security::Caller const &caller,
                                    char const *object_path,
                                    char const *operation)
{
  std::string const who = caller.effective ();
  bool const identified = who != "anonymous";
  std::string const path = object_path == nullptr ? "" : object_path;
  std::string const op = operation == nullptr ? "" : operation;

  Result result = NO_RULE;
  for (Rule const &r : list.rules)
    {
      bool const principal_ok = r.principal == "*" ? identified : r.principal == who;
      bool const object_ok = r.prefix ? path.compare (0, r.object.size (), r.object) == 0 : path == r.object;
      bool const op_ok = r.operations.empty () || r.operations.count (op) != 0;
      bool const via_ok = r.via.empty () || (!caller.asserter.empty () && (r.via == "*" || r.via == caller.asserter));
      if (!(principal_ok && object_ok && op_ok && via_ok))
        continue;
      if (!r.allow)
        return DENY;
      result = ALLOW;
    }
  return result;
}

TAO::SSLIOP::Access_List::Access_List ()
{
  TAO_Security_Mode::Host_Config const &h = TAO_Security_Mode::host ();
  this->path_ = h.get ("access_list");
  this->signer_path_ = h.get ("access_list_signer", h.get ("denylist_signer").c_str ());
  this->signer_pin_ = lower (h.get ("access_list_signer_sha256", h.get ("denylist_signer_sha256").c_str ()));
  long const r = ACE_OS::atoi (h.get ("access_list_reload", "30").c_str ());
  this->reload_seconds_ = r > 0 ? r : 30;
}

TAO::SSLIOP::Access_List *
TAO::SSLIOP::Access_List::instance ()
{
  static Access_List list;
  return &list;
}

bool
TAO::SSLIOP::Access_List::configured () const
{
  return !this->path_.empty ();
}

bool
TAO::SSLIOP::Access_List::read (Content &out, std::string &error)
{
  if (this->signer_path_.empty ())
    {
      error = "access_list_signer (or denylist_signer) is not set";
      return false;
    }
  std::string text;
  if (!Signed_File::read_verified (this->path_, this->signer_path_, this->signer_pin_, text, error))
    {
      if (error.find ("is not the pinned signer") != std::string::npos)
        error += " (access_list_signer_sha256)";
      return false;
    }
  return parse (text, out, error);
}

bool
TAO::SSLIOP::Access_List::load (std::string &summary)
{
  if (!this->configured ())
    return false;
  Content c;
  std::string error;
  std::string const stamp = Signed_File::stamp (this->path_);
  if (!this->read (c, error))
    {
      summary = error;
      return false;
    }
  summary = "version " + std::to_string (c.version) + " issued " + c.issued + ", "
            + std::to_string (c.rules.size ()) + " rule(s)";
  ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, false);
  this->current_ = std::make_shared<Content const> (std::move (c));
  this->last_check_ = ACE_OS::time (nullptr);
  this->stamp_ = stamp;
  return true;
}

void
TAO::SSLIOP::Access_List::refresh ()
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
  std::string const stamp = Signed_File::stamp (this->path_);
  if (stamp.compare (0, 2, "-;") == 0)
    return;   // no file: keep the last good list
  {
    ACE_GUARD (TAO_SYNCH_MUTEX, guard, this->lock_);
    if (stamp == this->stamp_)
      return;
    this->stamp_ = stamp;
  }

  Content c;
  std::string error;
  bool ok = this->read (c, error);
  long const have = this->version ();
  if (ok && c.version <= have)
    {
      error = "version " + std::to_string (c.version) + " is not newer than the current version "
              + std::to_string (have);
      ok = false;
    }
  if (!ok)
    {
      Audit_Logger::instance ()->write (
        Audit_Record ("secenv", false, Reason::ACCESS_LIST_REJECTED)
          .field ("file", this->path_)
          .field ("current_version", std::to_string (have))
          .text (error.c_str ()));
      return;
    }
  long const version = c.version;
  std::string const issued = c.issued;
  size_t const rules = c.rules.size ();
  {
    ACE_GUARD (TAO_SYNCH_MUTEX, guard, this->lock_);
    this->current_ = std::make_shared<Content const> (std::move (c));
  }
  Audit_Logger::instance ()->write (
    Audit_Record ("secenv", true, Reason::ACCESS_LIST_LOADED)
      .field ("file", this->path_)
      .field ("version", std::to_string (version))
      .field ("issued", issued)
      .field ("rules", std::to_string (rules))
      .field ("previous_version", std::to_string (have)));
}

long
TAO::SSLIOP::Access_List::version () const
{
  ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, 0);
  return this->current_ ? this->current_->version : 0;
}

TAO::Security::Caller_Policy::Result
TAO::SSLIOP::Access_List::decide (TAO::Security::Caller const &caller,
                                  char const *object_path,
                                  char const *operation)
{
  this->refresh ();
  std::shared_ptr<Content const> c;
  {
    ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, DENY);
    c = this->current_;
  }
  if (!c)
    return NO_RULE;
  return evaluate (*c, caller, object_path, operation);
}

TAO_END_VERSIONED_NAMESPACE_DECL
