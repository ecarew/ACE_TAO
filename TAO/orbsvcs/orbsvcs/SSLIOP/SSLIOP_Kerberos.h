// -*- C++ -*-

//=============================================================================
/**
 *  @file SSLIOP_Kerberos.h
 *
 *  GSS-API Kerberos support in SSLIOP (Phase 3, K1 and K2).
 *
 *  CSIv2 carries any GSS-API mechanism's initial context token in its
 *  client authentication layer (CORBA 3.3 Part 2, 10.2.4.1); Phase 3
 *  uses the Kerberos V5 mechanism (RFC 4121) there, beside GSSUP.  The
 *  library is optional: SSLIOP is built with it only with the MPC
 *  feature gssapi (ace_gssapi.mpb), which defines TAO_HAS_GSSAPI.
 *  These functions work in both builds (without it they report that
 *  Kerberos is not built), and this header names no GSS type, so code
 *  that includes it does not depend on the feature.
 *
 *  The target accepts a token with the service's own keytab (R27): the
 *  stateless CSIv2 target needs it to complete in one step.  The MIT
 *  library's replay cache refuses a token seen before (R28).  The token
 *  may be bound to the TLS session it arrives on with GSS channel
 *  bindings carrying the target certificate's hash (RFC 5929
 *  tls-server-end-point), so that it cannot be replayed into another
 *  session (Phase 3 question Q3).
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

struct x509_st;

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

      /// RFC 2743 exported name of Kerberos principal @a principal
      /// (04 01, the mechanism OID, the name), for CSIv2 target names.
      TAO_SSLIOP_Export std::string exported_name (std::string const &principal);

      /**
       * RFC 5929 tls-server-end-point channel-binding data for the TLS
       * server certificate @a cert: "tls-server-end-point:" and the hash
       * of its DER (SHA-256, or the certificate's own signature hash when
       * that is stronger).  Empty if @a cert is null.
       */
      TAO_SSLIOP_Export std::string tls_server_end_point (x509_st *cert);

      /**
       * Checks the service keytab (R31): a regular file holding keys for
       * @a principal, none of them DES or RC4; in @a prod also mode 0600
       * or 0400 and owned by the effective user.  @a summary lists the key
       * versions and encryption types; false with @a error otherwise.
       */
      TAO_SSLIOP_Export bool check_keytab (std::string const &path,
                                           std::string const &principal,
                                           bool prod,
                                           std::string &summary,
                                           std::string &error);

      /// Outcome of accept().
      enum Accept_Status
      {
        ACCEPTED,      ///< @a client and @a reply are set
        REFUSED,       ///< the token was refused; @a why says why
        UNAVAILABLE    ///< no acceptor credential (keytab), or not built
      };

      /**
       * Accepts a Kerberos initial context token as @a principal, with
       * the keys in @a keytab (and the replay cache @a rcache, if not
       * empty).  @a binding is this TLS session's channel-binding data
       * (tls_server_end_point()), or empty.  With @a require_binding, a
       * token not bound to it is refused.  On success @a client is the
       * caller (user@REALM) and @a reply the token to return, if any (the
       * Kerberos AP-REP, when the client asked for mutual authentication).
       */
      TAO_SSLIOP_Export Accept_Status accept (std::string const &token,
                                              std::string const &binding,
                                              std::string const &principal,
                                              std::string const &keytab,
                                              std::string const &rcache,
                                              bool require_binding,
                                              std::string &client,
                                              std::string &reply,
                                              std::string &why);

      /**
       * Makes a Kerberos initial context token for service @a principal
       * from the caller's default ticket cache (KRB5CCNAME), asking for
       * mutual authentication, bound to @a binding if not empty.  False
       * with @a why if there is no usable ticket.
       */
      TAO_SSLIOP_Export bool initiate (std::string const &principal,
                                       std::string const &binding,
                                       std::string &token,
                                       std::string &why);
    }
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#include /**/ "ace/post.h"

#endif /* TAO_SSLIOP_KERBEROS_H */
