#include "orbsvcs/SSLIOP/SSLIOP_Deny_List.h"
#include "orbsvcs/SSLIOP/SSLIOP_Signed_File.h"

#include "orbsvcs/Security/Audit_Logger.h"
#include "tao/Security_Mode.h"
#include "tao/orbconf.h"

#include "ace/OS_NS_ctype.h"
#include "ace/Guard_T.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_stat.h"
#include "ace/OS_NS_time.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <vector>
#include <cctype>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  using TAO::Security::Audit_Logger;
  using TAO::Security::Audit_Record;
  namespace Reason = TAO::Security::Audit_Reason;

  using TAO::SSLIOP::Signed_File::parse_time;
  using TAO::SSLIOP::Signed_File::ssl_error;
  using TAO::SSLIOP::Signed_File::trim;
}

std::string
TAO::SSLIOP::Deny_List::normalize_serial (std::string const &hex)
{
  std::string out;
  for (char const c : hex)
    if (c != ':' && c != ' ')
      out += static_cast<char> (::toupper (static_cast<unsigned char> (c)));
  size_t const nz = out.find_first_not_of ('0');
  return nz == std::string::npos ? (out.empty () ? out : std::string ("0")) : out.substr (nz);
}

bool
TAO::SSLIOP::Deny_List::parse (std::string const &text, Content &out, std::string &error)
{
  out = Content ();
  size_t line_no = 0;
  for (size_t p = 0; p < text.size (); )
    {
      size_t e = text.find ('\n', p);
      if (e == std::string::npos)
        e = text.size ();
      std::string const line = trim (text.substr (p, e - p));
      p = e + 1;
      ++line_no;
      if (line.empty () || line[0] == '#')
        continue;
      size_t const sp = line.find_first_of (" \t");
      std::string const key = line.substr (0, sp);
      std::string const value = sp == std::string::npos ? "" : trim (line.substr (sp));
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
          if (!parse_time (value, out.issued_time) || !out.issued.empty ())
            {
              error = where + "issued must be one time like 2026-11-23T12:00:00Z";
              return false;
            }
          out.issued = value;
        }
      else if (key == "serial")
        {
          std::string const s = normalize_serial (value);
          if (s.empty () || s.find_first_not_of ("0123456789ABCDEF") != std::string::npos)
            {
              error = where + "serial must be hexadecimal";
              return false;
            }
          out.serials.insert (s);
        }
      else if (key == "spiffe")
        {
          if (value.compare (0, 9, "spiffe://") != 0)
            {
              error = where + "spiffe must be a spiffe:// URI";
              return false;
            }
          out.spiffe.insert (value);
        }
      else if (key == "principal")
        {
          std::string const n = normalize_principal (value);
          if (n.empty ())
            {
              error = where + "principal must be one name@REALM";
              return false;
            }
          out.principals.insert (n);
        }
      else if (key == "sid")
        {
          std::string const n = normalize_sid (value);
          if (n.empty ())
            {
              error = where + "sid must be a SID like S-1-5-21-...";
              return false;
            }
          out.sids.insert (n);
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

bool
TAO::SSLIOP::Deny_List::verify (std::string const &text, std::string const &sig_b64, EVP_PKEY *signer,
                                std::string &error)
{
  std::string b64;
  for (char const c : sig_b64)
    if (c != '\n' && c != '\r' && c != ' ')
      b64 += c;
  std::vector<unsigned char> sig (b64.size ());
  int n = ::EVP_DecodeBlock (sig.data (), reinterpret_cast<unsigned char const *> (b64.data ()),
                             static_cast<int> (b64.size ()));
  if (n <= 0 || b64.size () % 4 != 0)
    {
      error = "the signature is not base64";
      return false;
    }
  for (size_t i = b64.size (); i > 0 && b64[i - 1] == '='; --i)
    --n;
  EVP_MD_CTX *const ctx = ::EVP_MD_CTX_new ();
  bool const ok = ::EVP_DigestVerifyInit_ex (ctx, nullptr, "SHA256", nullptr, nullptr, signer, nullptr) == 1
                  && ::EVP_DigestVerify (ctx, sig.data (), static_cast<size_t> (n),
                                         reinterpret_cast<unsigned char const *> (text.data ()), text.size ()) == 1;
  ::EVP_MD_CTX_free (ctx);
  ::ERR_clear_error ();
  if (!ok)
    error = "the signature does not verify";
  return ok;
}

EVP_PKEY *
TAO::SSLIOP::Deny_List::load_signer (char const *path, std::string &error)
{
  BIO *const b = ::BIO_new_file (path, "r");
  if (b == nullptr)
    {
      error = std::string ("cannot read the signer ") + path;
      ::ERR_clear_error ();
      return nullptr;
    }
  EVP_PKEY *key = ::PEM_read_bio_PUBKEY (b, nullptr, nullptr, nullptr);
  if (key == nullptr)
    {
      (void) BIO_reset (b);
      ::ERR_clear_error ();
      X509 *const x = ::PEM_read_bio_X509 (b, nullptr, nullptr, nullptr);
      if (x != nullptr)
        {
          key = ::X509_get_pubkey (x);
          ::X509_free (x);
        }
    }
  ::BIO_free (b);
  if (key == nullptr)
    error = std::string ("no public key or certificate in ") + path + " (" + ssl_error () + ")";
  ::ERR_clear_error ();
  return key;
}

std::string
TAO::SSLIOP::Deny_List::spki_sha256 (EVP_PKEY *key)
{
  unsigned char *der = nullptr;
  int const len = ::i2d_PUBKEY (key, &der);
  if (len <= 0)
    return "";
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int mdlen = 0;
  ::EVP_Digest (der, static_cast<size_t> (len), md, &mdlen, ::EVP_sha256 (), nullptr);
  ::OPENSSL_free (der);
  std::string out;
  char hex[3];
  for (unsigned int i = 0; i < mdlen; ++i)
    {
      ACE_OS::snprintf (hex, sizeof hex, "%02x", md[i]);
      out += hex;
    }
  return out;
}

std::string
TAO::SSLIOP::Deny_List::serial_of (X509 *cert)
{
  BIGNUM *const bn = ::ASN1_INTEGER_to_BN (::X509_get0_serialNumber (cert), nullptr);
  char *const hex = bn != nullptr ? ::BN_bn2hex (bn) : nullptr;
  std::string const s = hex != nullptr ? normalize_serial (hex) : "";
  ::OPENSSL_free (hex);
  ::BN_free (bn);
  return s;
}

std::set<std::string>
TAO::SSLIOP::Deny_List::spiffe_ids_of (X509 *cert)
{
  std::set<std::string> out;
  GENERAL_NAMES *const names =
    static_cast<GENERAL_NAMES *> (::X509_get_ext_d2i (cert, NID_subject_alt_name, nullptr, nullptr));
  if (names == nullptr)
    return out;
  for (int i = 0; i < sk_GENERAL_NAME_num (names); ++i)
    {
      GENERAL_NAME const *const g = sk_GENERAL_NAME_value (names, i);
      if (g->type != GEN_URI)
        continue;
      ASN1_IA5STRING const *const s = g->d.uniformResourceIdentifier;
      std::string const uri (reinterpret_cast<char const *> (::ASN1_STRING_get0_data (s)),
                             static_cast<size_t> (::ASN1_STRING_length (s)));
      if (uri.compare (0, 9, "spiffe://") == 0)
        out.insert (uri);
    }
  GENERAL_NAMES_free (names);
  return out;
}

TAO::SSLIOP::Deny_List::Deny_List ()
{
  TAO_Security_Mode::Host_Config const &h = TAO_Security_Mode::host ();
  this->path_ = h.get ("denylist");
  this->signer_path_ = h.get ("denylist_signer");
  this->signer_pin_ = h.get ("denylist_signer_sha256");
  for (char &c : this->signer_pin_)
    c = static_cast<char> (::tolower (static_cast<unsigned char> (c)));
  long const r = ACE_OS::atoi (h.get ("denylist_reload", "30").c_str ());
  this->reload_seconds_ = r > 0 ? r : 30;
  long const a = ACE_OS::atoi (h.get ("denylist_max_age", "7").c_str ());
  this->max_age_days_ = a > 0 ? a : 7;
}

TAO::SSLIOP::Deny_List *
TAO::SSLIOP::Deny_List::instance ()
{
  static Deny_List list;
  return &list;
}

bool
TAO::SSLIOP::Deny_List::configured () const
{
  return !this->path_.empty ();
}

bool
TAO::SSLIOP::Deny_List::read (Content &out, std::string &error)
{
  if (this->signer_path_.empty ())
    {
      error = "denylist_signer is not set";
      return false;
    }
  std::string text;
  if (!Signed_File::read_verified (this->path_, this->signer_path_, this->signer_pin_, text, error))
    {
      if (error.find ("is not the pinned signer") != std::string::npos)
        error += " (denylist_signer_sha256)";
      return false;
    }
  return parse (text, out, error);
}

std::string
TAO::SSLIOP::Deny_List::stamp () const
{
  return Signed_File::stamp (this->path_);
}

bool
TAO::SSLIOP::Deny_List::load (std::string &summary)
{
  if (!this->configured ())
    return false;
  Content c;
  std::string error;
  std::string const stamp = this->stamp ();
  if (!this->read (c, error))
    {
      summary = error;
      return false;
    }
  summary = "version " + std::to_string (c.version) + " issued " + c.issued + ", "
            + std::to_string (c.serials.size ()) + " serial(s), " + std::to_string (c.spiffe.size ())
            + " SPIFFE ID(s), " + std::to_string (c.principals.size ()) + " principal(s), "
            + std::to_string (c.sids.size ()) + " SID(s)";
  ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, false);
  this->current_ = std::make_shared<Content const> (std::move (c));
  this->last_check_ = ACE_OS::time (nullptr);
  this->stamp_ = stamp;
  return true;
}

void
TAO::SSLIOP::Deny_List::refresh ()
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
        Audit_Record ("secenv", false, Reason::DENYLIST_REJECTED)
          .field ("file", this->path_)
          .field ("current_version", std::to_string (have))
          .field ("current_age_days", std::to_string (this->age_days ()))
          .text (error.c_str ()));
      return;
    }
  long const version = c.version;
  std::string const issued = c.issued;
  {
    ACE_GUARD (TAO_SYNCH_MUTEX, guard, this->lock_);
    this->current_ = std::make_shared<Content const> (std::move (c));
  }
  Audit_Logger::instance ()->write (
    Audit_Record ("secenv", true, Reason::DENYLIST_LOADED)
      .field ("file", this->path_)
      .field ("version", std::to_string (version))
      .field ("issued", issued)
      .field ("previous_version", std::to_string (have)));
}

std::string
TAO::SSLIOP::Deny_List::check (X509 *peer)
{
  if (!this->configured () || peer == nullptr)
    return "";
  this->refresh ();
  std::shared_ptr<Content const> c;
  {
    ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, "");
    c = this->current_;
  }
  if (!c)
    return "";
  std::string const serial = serial_of (peer);
  if (c->serials.count (serial) != 0)
    return "serial " + serial;
  for (auto const &id : spiffe_ids_of (peer))
    if (c->spiffe.count (id) != 0)
      return id;
  return "";
}

std::string
TAO::SSLIOP::Deny_List::check_names (std::vector<std::string> const &names, std::vector<std::string> const &sids)
{
  if (!this->configured ())
    return "";
  this->refresh ();
  std::shared_ptr<Content const> c;
  {
    ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, "");
    c = this->current_;
  }
  if (!c || (c->principals.empty () && c->sids.empty ()))
    return "";
  for (std::string const &name : names)
    {
      std::string const n = normalize_principal (name);
      if (!n.empty () && c->principals.count (n) != 0)
        return "principal " + n;
    }
  for (std::string const &sid : sids)
    {
      std::string const n = normalize_sid (sid);
      if (!n.empty () && c->sids.count (n) != 0)
        return "sid " + n;
    }
  return "";
}

std::string
TAO::SSLIOP::Deny_List::normalize_principal (std::string const &value)
{
  size_t const at = value.rfind ('@');
  if (at == std::string::npos || at == 0 || at + 1 == value.size ())
    return "";
  std::string out;
  for (char const ch : value)
    {
      unsigned char const u = static_cast<unsigned char> (ch);
      if (u <= 0x20 || u >= 0x7f)
        return "";
      out += static_cast<char> (ACE_OS::ace_tolower (u));
    }
  return out;
}

std::string
TAO::SSLIOP::Deny_List::normalize_sid (std::string const &value)
{
  // S-1-<authority>-<sub>[-<sub>...]: digits between the dashes.
  if (value.size () < 5 || (value[0] != 'S' && value[0] != 's') || value[1] != '-')
    return "";
  size_t parts = 0;
  size_t digits = 0;
  for (size_t i = 2; i < value.size (); ++i)
    {
      char const ch = value[i];
      if (ch >= '0' && ch <= '9')
        {
          if (++digits > 10)
            return "";
        }
      else if (ch == '-' && digits > 0)
        {
          ++parts;
          digits = 0;
        }
      else
        return "";
    }
  if (digits == 0 || parts < 2 || value.compare (2, 2, "1-") != 0)
    return "";
  return "S" + value.substr (1);
}

long
TAO::SSLIOP::Deny_List::age_days () const
{
  ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, -1);
  if (!this->current_)
    return -1;
  return static_cast<long> ((ACE_OS::time (nullptr) - this->current_->issued_time) / 86400);
}

long
TAO::SSLIOP::Deny_List::version () const
{
  ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, 0);
  return this->current_ ? this->current_->version : 0;
}

TAO_END_VERSIONED_NAMESPACE_DECL
