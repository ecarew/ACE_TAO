#include "orbsvcs/SSLIOP/SSLIOP_Kerberos.h"

#if defined (TAO_HAS_GSSAPI)
# include <gssapi/gssapi.h>
# include <gssapi/gssapi_krb5.h>
#endif /* TAO_HAS_GSSAPI */

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  // 1.2.840.113554.1.2.2, without the DER tag and length.
  char const krb5_oid_body[] = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
  size_t const krb5_oid_length = sizeof krb5_oid_body - 1;

#if defined (TAO_HAS_GSSAPI)
  /// Appends gss_display_status text for one status code of @a type.
  void
  append_status (std::string &out, OM_uint32 code, int type)
  {
    OM_uint32 context = 0;
    do
      {
        OM_uint32 minor = 0;
        gss_buffer_desc text = GSS_C_EMPTY_BUFFER;
        OM_uint32 const major =
          ::gss_display_status (&minor, code, type, GSS_C_NO_OID, &context, &text);
        if (GSS_ERROR (major))
          break;
        if (!out.empty ())
          out += "; ";
        out.append (static_cast<char const *> (text.value), text.length);
        ::gss_release_buffer (&minor, &text);
      }
    while (context != 0);
  }
#endif /* TAO_HAS_GSSAPI */
}

bool
TAO::SSLIOP::Kerberos::built ()
{
#if defined (TAO_HAS_GSSAPI)
  return true;
#else
  return false;
#endif /* TAO_HAS_GSSAPI */
}

std::string
TAO::SSLIOP::Kerberos::mech_der ()
{
  std::string der ("\x06", 1);
  der += static_cast<char> (krb5_oid_length);
  der.append (krb5_oid_body, krb5_oid_length);
  return der;
}

bool
TAO::SSLIOP::Kerberos::mechanism_offered (std::string &detail)
{
#if defined (TAO_HAS_GSSAPI)
  OM_uint32 minor = 0;
  gss_OID_set mechs = GSS_C_NO_OID_SET;
  OM_uint32 const major = ::gss_indicate_mechs (&minor, &mechs);
  if (GSS_ERROR (major))
    {
      detail = "gss_indicate_mechs failed: " + status_text (major, minor);
      return false;
    }
  bool found = false;
  for (size_t i = 0; mechs != GSS_C_NO_OID_SET && i < mechs->count && !found; ++i)
    {
      gss_OID const m = &mechs->elements[i];
      found = m->length == krb5_oid_length && std::string (static_cast<char const *> (m->elements), m->length)
                                                == std::string (krb5_oid_body, krb5_oid_length);
    }
  ::gss_release_oid_set (&minor, &mechs);
  detail = found ? "Kerberos V5 mechanism offered" : "the GSS-API library does not offer Kerberos V5";
  return found;
#else
  detail = "SSLIOP was built without GSS-API (MPC feature gssapi)";
  return false;
#endif /* TAO_HAS_GSSAPI */
}

std::string
TAO::SSLIOP::Kerberos::status_text (unsigned long major, unsigned long minor)
{
#if defined (TAO_HAS_GSSAPI)
  std::string out;
  append_status (out, static_cast<OM_uint32> (major), GSS_C_GSS_CODE);
  if (minor != 0)
    append_status (out, static_cast<OM_uint32> (minor), GSS_C_MECH_CODE);
  return out.empty () ? "GSS status " + std::to_string (major) : out;
#else
  ACE_UNUSED_ARG (major);
  ACE_UNUSED_ARG (minor);
  return "GSS-API not built";
#endif /* TAO_HAS_GSSAPI */
}

TAO_END_VERSIONED_NAMESPACE_DECL
