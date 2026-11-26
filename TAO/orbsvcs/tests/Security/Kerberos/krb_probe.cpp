// Kerberos test probe (Phase 3 K1): reports what SSLIOP's GSS-API
// support offers, without a KDC.
//
//   krb_probe          prints "built=0|1", "mech_der=<hex>",
//                      "offered=0|1 <detail>" and "status_text=<text>"
//                      for GSS_S_BAD_MECH (a fixed status code)
//
// Exits 0 when the report is consistent: a build with GSS-API must
// offer Kerberos V5 and give a status text; one without must say so.
//
//   krb_probe -pac FILE  parses FILE (hex digits, whitespace ignored) as
//                      a PAC logon-info buffer (Phase 3 K4) and prints
//                      "PAC OK user_sid=S domain=D", one "GROUP S" per
//                      group, or "PAC REFUSED <why>"; exits 0 either way

#include "orbsvcs/SSLIOP/SSLIOP_Kerberos.h"

#include "ace/OS_main.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_string.h"

#include <string>

namespace
{
  std::string
  hex (std::string const &s)
  {
    static char const digits[] = "0123456789abcdef";
    std::string out;
    for (unsigned char const c : s)
      {
        out += digits[c >> 4];
        out += digits[c & 0x0f];
      }
    return out;
  }
}

int
ACE_TMAIN (int argc, ACE_TCHAR *argv[])
{
  if (argc == 3 && ACE_OS::strcmp (argv[1], ACE_TEXT ("-pac")) == 0)
    {
      FILE *const fp = ACE_OS::fopen (argv[2], ACE_TEXT ("r"));
      if (fp == nullptr)
        {
          ACE_OS::printf ("cannot open the PAC file\n");
          return 1;
        }
      std::string bytes;
      int hi = -1;
      for (int c; (c = ACE_OS::fgetc (fp)) != EOF; )
        {
          int v = c >= 0x30 && c <= 0x39 ? c - 0x30 : c >= 0x61 && c <= 0x66 ? c - 0x61 + 10 : -1;
          if (v < 0)
            continue;
          if (hi < 0)
            hi = v;
          else
            {
              bytes += static_cast<char> ((hi << 4) | v);
              hi = -1;
            }
        }
      ACE_OS::fclose (fp);
      TAO::SSLIOP::Kerberos::Pac_Info info;
      std::string why;
      if (!TAO::SSLIOP::Kerberos::parse_logon_info (bytes, info, why))
        ACE_OS::printf ("PAC REFUSED %s\n", why.c_str ());
      else
        {
          ACE_OS::printf ("PAC OK user_sid=%s domain=%s\n", info.user_sid.c_str (), info.domain.c_str ());
          for (std::string const &g : info.groups)
            ACE_OS::printf ("GROUP %s\n", g.c_str ());
        }
      return 0;
    }

  bool const built = TAO::SSLIOP::Kerberos::built ();
  std::string detail;
  bool const offered = TAO::SSLIOP::Kerberos::mechanism_offered (detail);
  // GSS_S_BAD_MECH is routine error 1 (RFC 2744: 1 << 16).
  std::string const text = TAO::SSLIOP::Kerberos::status_text (1ul << 16, 0);

  ACE_OS::printf ("built=%d\n", built ? 1 : 0);
  ACE_OS::printf ("mech_der=%s\n", hex (TAO::SSLIOP::Kerberos::mech_der ()).c_str ());
  ACE_OS::printf ("offered=%d %s\n", offered ? 1 : 0, detail.c_str ());
  ACE_OS::printf ("status_text=%s\n", text.c_str ());

  bool const consistent = built ? (offered && !text.empty () && text != "GSS-API not built")
                                : (!offered && text == "GSS-API not built");
  return consistent ? 0 : 1;
}
