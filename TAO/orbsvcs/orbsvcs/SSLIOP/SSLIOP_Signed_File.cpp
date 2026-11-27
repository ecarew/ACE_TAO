#include "orbsvcs/SSLIOP/SSLIOP_Signed_File.h"
#include "orbsvcs/SSLIOP/SSLIOP_Deny_List.h"

#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_stat.h"
#include "ace/OS_NS_time.h"

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
  // Exactly YYYY-MM-DDTHH:MM:SSZ: digits where the layout has digits
  // (sscanf's %2d also took signs and spaces).
  static char const layout[] = "dddd-dd-ddTdd:dd:ddZ";
  if (s.size () != sizeof layout - 1)
    return false;
  for (size_t i = 0; i < s.size (); ++i)
    if (layout[i] == 'd' ? (s[i] < '0' || s[i] > '9') : s[i] != layout[i])
      return false;
  auto const num = [&s] (size_t at, size_t len)
    {
      int v = 0;
      for (size_t i = at; i < at + len; ++i)
        v = v * 10 + (s[i] - '0');
      return v;
    };
  struct tm tm_buf;
  ACE_OS::memset (&tm_buf, 0, sizeof tm_buf);
  tm_buf.tm_year = num (0, 4) - 1900;
  tm_buf.tm_mon = num (5, 2) - 1;
  tm_buf.tm_mday = num (8, 2);
  tm_buf.tm_hour = num (11, 2);
  tm_buf.tm_min = num (14, 2);
  tm_buf.tm_sec = num (17, 2);
  struct tm const asked = tm_buf;
#if defined (ACE_WIN32)
  out = ::_mkgmtime (&tm_buf);
#else
  out = ::timegm (&tm_buf);
#endif
  if (out == static_cast<time_t> (-1))
    return false;
  // timegm () quietly normalizes impossible dates (February 31st, hour 24):
  // the time must convert back to the fields that were written.
  struct tm back;
  if (ACE_OS::gmtime_r (&out, &back) == nullptr)
    return false;
  return back.tm_year == asked.tm_year && back.tm_mon == asked.tm_mon && back.tm_mday == asked.tm_mday
         && back.tm_hour == asked.tm_hour && back.tm_min == asked.tm_min && back.tm_sec == asked.tm_sec;
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
