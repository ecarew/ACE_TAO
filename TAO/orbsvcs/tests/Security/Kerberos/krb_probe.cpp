// Kerberos test probe (Phase 3 K1): reports what SSLIOP's GSS-API
// support offers, without a KDC.
//
//   krb_probe          prints "built=0|1", "mech_der=<hex>",
//                      "offered=0|1 <detail>" and "status_text=<text>"
//                      for GSS_S_BAD_MECH (a fixed status code)
//
// Exits 0 when the report is consistent: a build with GSS-API must
// offer Kerberos V5 and give a status text; one without must say so.

#include "orbsvcs/SSLIOP/SSLIOP_Kerberos.h"

#include "ace/OS_main.h"
#include "ace/OS_NS_stdio.h"

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
ACE_TMAIN (int, ACE_TCHAR *[])
{
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
