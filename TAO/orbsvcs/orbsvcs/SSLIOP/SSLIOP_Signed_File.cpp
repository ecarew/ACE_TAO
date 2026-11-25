#include "orbsvcs/SSLIOP/SSLIOP_Signed_File.h"
#include "orbsvcs/SSLIOP/SSLIOP_Deny_List.h"

#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_stat.h"

#include <openssl/err.h>
#include <openssl/evp.h>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

bool
TAO::SSLIOP::Signed_File::slurp (std::string const &path, std::string &out)
{
  FILE *const fp = ACE_OS::fopen (path.c_str (), ACE_TEXT ("rb"));
  if (fp == nullptr)
    return false;
  out.clear ();
  char buf[4096];
  size_t n;
  while ((n = ACE_OS::fread (buf, 1, sizeof buf, fp)) > 0 && out.size () < (16u << 20))
    out.append (buf, n);
  ACE_OS::fclose (fp);
  return true;
}

std::string
TAO::SSLIOP::Signed_File::trim (std::string const &s)
{
  size_t const b = s.find_first_not_of (" \t\r");
  if (b == std::string::npos)
    return "";
  size_t const e = s.find_last_not_of (" \t\r");
  return s.substr (b, e - b + 1);
}

bool
TAO::SSLIOP::Signed_File::parse_time (std::string const &s, time_t &out)
{
  struct tm tm_buf;
  ACE_OS::memset (&tm_buf, 0, sizeof tm_buf);
  int y, mo, d, h, mi, se;
  char z = 0;
  if (s.size () != 20 || ::sscanf (s.c_str (), "%4d-%2d-%2dT%2d:%2d:%2d%c", &y, &mo, &d, &h, &mi, &se, &z) != 7
      || z != 'Z')
    return false;
  tm_buf.tm_year = y - 1900;
  tm_buf.tm_mon = mo - 1;
  tm_buf.tm_mday = d;
  tm_buf.tm_hour = h;
  tm_buf.tm_min = mi;
  tm_buf.tm_sec = se;
  out = ::timegm (&tm_buf);
  return out != static_cast<time_t> (-1);
}

std::string
TAO::SSLIOP::Signed_File::ssl_error ()
{
  unsigned long const e = ::ERR_get_error ();
  ::ERR_clear_error ();
  if (e == 0)
    return "no detail";
  char buf[256];
  ::ERR_error_string_n (e, buf, sizeof buf);
  return buf;
}

bool
TAO::SSLIOP::Signed_File::read_verified (std::string const &path,
                                         std::string const &signer_path,
                                         std::string const &pin,
                                         std::string &text,
                                         std::string &error)
{
  if (signer_path.empty ())
    {
      error = "no signer is configured";
      return false;
    }
  std::string sig;
  if (!slurp (path, text))
    {
      error = "cannot read " + path;
      return false;
    }
  if (!slurp (path + ".sig", sig))
    {
      error = "cannot read the signature " + path + ".sig";
      return false;
    }
  EVP_PKEY *const signer = Deny_List::load_signer (signer_path.c_str (), error);
  if (signer == nullptr)
    return false;
  bool ok = true;
  if (!pin.empty () && Deny_List::spki_sha256 (signer) != pin)
    {
      error = signer_path + " is not the pinned signer";
      ok = false;
    }
  ok = ok && Deny_List::verify (text, sig, signer, error);
  ::EVP_PKEY_free (signer);
  return ok;
}

std::string
TAO::SSLIOP::Signed_File::stamp (std::string const &path)
{
  std::string s;
  for (std::string const &p : {path, path + ".sig"})
    {
      ACE_stat st;
      if (ACE_OS::stat (p.c_str (), &st) == 0)
        s += std::to_string (static_cast<long long> (st.st_mtime)) + ":"
             + std::to_string (static_cast<long long> (st.st_size)) + ";";
      else
        s += "-;";
    }
  return s;
}

bool
TAO::SSLIOP::Signed_File::split_line (std::string const &raw, std::string &key, std::string &value)
{
  std::string const line = trim (raw);
  if (line.empty () || line[0] == '#')
    return false;
  size_t const sp = line.find_first_of (" \t");
  key = line.substr (0, sp);
  value = sp == std::string::npos ? "" : trim (line.substr (sp));
  return true;
}

TAO_END_VERSIONED_NAMESPACE_DECL
