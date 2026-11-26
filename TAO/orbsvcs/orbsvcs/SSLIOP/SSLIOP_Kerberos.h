// -*- C++ -*-

//=============================================================================
/**
 *  @file SSLIOP_Kerberos.h
 *
 *  GSS-API Kerberos support in SSLIOP (Phase 3, K1).
 *
 *  CSIv2 carries any GSS-API mechanism's initial context token in its
 *  client authentication layer (CORBA 3.3 Part 2, 10.2.4.1); Phase 3
 *  uses the Kerberos V5 mechanism (RFC 4121) there, beside GSSUP.  The
 *  library is optional: SSLIOP is built with it only with the MPC
 *  feature gssapi (ace_gssapi.mpb), which defines TAO_HAS_GSSAPI.
 *  These functions work in both builds, and this header names no GSS
 *  type, so code that includes it does not depend on the feature.
 */
//=============================================================================

#ifndef TAO_SSLIOP_KERBEROS_H
#define TAO_SSLIOP_KERBEROS_H

#include /**/ "ace/pre.h"

#include "orbsvcs/SSLIOP/SSLIOP_Export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "tao/Versioned_Namespace.h"

#include <string>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace SSLIOP
  {
    namespace Kerberos
    {
      /// True when SSLIOP was built with GSS-API (feature gssapi).
      TAO_SSLIOP_Export bool built ();

      /// DER encoding of the Kerberos V5 GSS mechanism OID,
      /// 1.2.840.113554.1.2.2 (06 09 2a 86 48 86 f7 12 01 02 02).
      TAO_SSLIOP_Export std::string mech_der ();

      /**
       * True when the GSS-API library offers the Kerberos V5 mechanism
       * (gss_indicate_mechs).  False in a build without GSS-API; @a
       * detail says why.
       */
      TAO_SSLIOP_Export bool mechanism_offered (std::string &detail);

      /**
       * The library's text for a GSS major status and, if non-zero, a
       * Kerberos minor status (gss_display_status), joined with "; ".
       * In a build without GSS-API: "GSS-API not built".
       */
      TAO_SSLIOP_Export std::string status_text (unsigned long major, unsigned long minor);
    }
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#include /**/ "ace/post.h"

#endif /* TAO_SSLIOP_KERBEROS_H */
