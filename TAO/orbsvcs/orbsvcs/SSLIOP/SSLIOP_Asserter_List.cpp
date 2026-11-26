#include "orbsvcs/SSLIOP/SSLIOP_Asserter_List.h"
#include "orbsvcs/SSLIOP/SSLIOP_Signed_File.h"

#include "orbsvcs/CSIC.h"
#include "orbsvcs/Security/Audit_Logger.h"
#include "tao/Security_Mode.h"

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

  std::vector<std::string>
  split (std::string const &s, char sep)
  {
    std::vector<std::string> out;
    size_t p = 0;
    for (;;)
      {
        size_t const c = s.find (sep, p);
        out.push_back (s.substr (p, c == std::string::npos ? std::string::npos : c - p));
        if (c == std::string::npos)
          return out;
        p = c + 1;
      }
  }

  struct Type_Name
  {
    char const *name;
    unsigned long bit;
  };
  Type_Name const type_table[] = {{"name", CSI::ITTPrincipalName},
                                  {"dn", CSI::ITTDistinguishedName},
                                  {"x509", CSI::ITTX509CertChain},
                                  {"anonymous", CSI::ITTAnonymous}};

  /// Parses "asserter PRINCIPAL [types=...] [realms=...]" (the value).
  bool
  parse_entry (std::string const &value, TAO::SSLIOP::Asserter_List::Entry &e, std::string &error)
  {
    // The principal is every word before the first option, so a subject
    // DN may hold blanks; the options are the words after it.
    std::vector<std::string> words;
    size_t p = 0;
    while (p < value.size ())
      {
        size_t const b = value.find_first_not_of (" \t", p);
        if (b == std::string::npos)
          break;
        size_t const end = value.find_first_of (" \t", b);
        words.push_back (value.substr (b, end == std::string::npos ? std::string::npos : end - b));
        p = end == std::string::npos ? value.size () : end;
      }
    size_t i = 0;
    for (; i < words.size (); ++i)
      {
        if (words[i].compare (0, 6, "types=") == 0 || words[i].compare (0, 7, "realms=") == 0)
          break;
        e.principal += (e.principal.empty () ? "" : " ") + words[i];
      }
    if (e.principal.empty ())
      {
        error = "asserter needs a principal";
        return false;
      }
    if (e.principal == "*")
      {
        error = "asserter * would trust every caller (presumed trust is not allowed)";
        return false;
      }
    e.types = CSI::ITTPrincipalName;
    for (; i < words.size (); ++i)
      {
        std::string const &w = words[i];
        if (w.compare (0, 6, "types=") == 0)
          {
            e.types = 0;
            for (std::string const &t : split (w.substr (6), ','))
              {
                unsigned long bit = 0;
                for (Type_Name const &n : type_table)
                  if (t == n.name)
                    bit = n.bit;
                if (bit == 0)
                  {
                    error = "unknown identity type \"" + t + "\" (name, dn, x509, anonymous)";
                    return false;
                  }
                e.types |= bit;
              }
          }
        else if (w.compare (0, 7, "realms=") == 0)
          {
            for (std::string r : split (w.substr (7), ','))
              {
                if (r.empty ())
                  {
                    error = "empty realm";
                    return false;
                  }
                if (r != "*" && r[0] != '@')
                  r = "@" + r;
                e.realms.insert (r);
              }
          }
        else
          {
            error = "unexpected \"" + w + "\" after the options";
            return false;
          }
      }
    return true;
  }
}

bool
TAO::SSLIOP::Asserter_List::parse (std::string const &text, Content &out, std::string &error)
{
  out = Content ();
  size_t line_no = 0;
  for (size_t p = 0; p < text.size ();)
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
              error = where + "issued must be one time like 2026-11-25T12:00:00Z";
              return false;
            }
          out.issued = value;
        }
      else if (key == "asserter")
        {
          Entry entry;
          if (!parse_entry (value, entry, error))
            {
              error = where + error;
              return false;
            }
          for (Entry const &o : out.entries)
            if (o.principal == entry.principal)
              {
                error = where + entry.principal + " appears twice";
                return false;
              }
          out.entries.push_back (entry);
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

std::string
TAO::SSLIOP::Asserter_List::type_names (unsigned long types)
{
  std::string s;
  for (Type_Name const &n : type_table)
    if ((types & n.bit) != 0)
      s += (s.empty () ? "" : ",") + std::string (n.name);
  return s;
}

TAO::SSLIOP::Asserter_List::Asserter_List ()
{
  TAO_Security_Mode::Host_Config const &h = TAO_Security_Mode::host ();
  this->path_ = h.get ("csiv2_asserters");
  this->signer_path_ = h.get ("csiv2_asserters_signer", h.get ("denylist_signer").c_str ());
  this->signer_pin_ = lower (h.get ("csiv2_asserters_signer_sha256", h.get ("denylist_signer_sha256").c_str ()));
  long const r = ACE_OS::atoi (h.get ("csiv2_asserters_reload", "30").c_str ());
  this->reload_seconds_ = r > 0 ? r : 30;
}

TAO::SSLIOP::Asserter_List *
TAO::SSLIOP::Asserter_List::instance ()
{
  static Asserter_List list;
  return &list;
}

bool
TAO::SSLIOP::Asserter_List::read (Content &out, std::string &error)
{
  if (this->signer_path_.empty ())
    {
      error = "csiv2_asserters_signer (or denylist_signer) is not set";
      return false;
    }
  std::string text;
  if (!Signed_File::read_verified (this->path_, this->signer_path_, this->signer_pin_, text, error))
    {
      if (error.find ("is not the pinned signer") != std::string::npos)
        error += " (csiv2_asserters_signer_sha256)";
      return false;
    }
  return parse (text, out, error);
}

bool
TAO::SSLIOP::Asserter_List::load (std::string &summary)
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
            + std::to_string (c.entries.size ()) + " asserter(s)";
  ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, false);
  this->current_ = std::make_shared<Content const> (std::move (c));
  this->last_check_ = ACE_OS::time (nullptr);
  this->stamp_ = stamp;
  return true;
}

void
TAO::SSLIOP::Asserter_List::refresh ()
{
  if (!this->configured ())
    return;
  time_t const now = ACE_OS::time (nullptr);
  bool first = false;
  {
    ACE_GUARD (TAO_SYNCH_MUTEX, guard, this->lock_);
    first = !this->current_ && this->last_check_ == 0;
    if (!first && now - this->last_check_ < this->reload_seconds_)
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
      Audit_Logger::instance ()->write (Audit_Record ("secenv", false, Reason::ASSERTER_LIST_REJECTED)
                                          .field ("file", this->path_)
                                          .field ("current_version", std::to_string (have))
                                          .text (error.c_str ()));
      return;
    }
  long const version = c.version;
  size_t const entries = c.entries.size ();
  {
    ACE_GUARD (TAO_SYNCH_MUTEX, guard, this->lock_);
    this->current_ = std::make_shared<Content const> (std::move (c));
  }
  Audit_Logger::instance ()->write (Audit_Record ("secenv", true, Reason::ASSERTER_LIST_LOADED)
                                      .field ("file", this->path_)
                                      .field ("version", std::to_string (version))
                                      .field ("asserters", std::to_string (entries))
                                      .field ("previous_version", std::to_string (have)));
}

long
TAO::SSLIOP::Asserter_List::version () const
{
  ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, 0);
  return this->current_ ? this->current_->version : 0;
}

bool
TAO::SSLIOP::Asserter_List::find (std::vector<std::string> const &candidates, Entry &out)
{
  this->refresh ();
  std::shared_ptr<Content const> c;
  {
    ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, false);
    c = this->current_;
  }
  if (!c)
    return false;
  for (std::string const &who : candidates)
    {
      if (who.empty ())
        continue;
      for (Entry const &e : c->entries)
        if (e.principal == who)
          {
            out = e;
            return true;
          }
    }
  return false;
}

TAO_END_VERSIONED_NAMESPACE_DECL
