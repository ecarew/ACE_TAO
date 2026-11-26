// -*- C++ -*-

//=============================================================================
/**
 *  @file SSLIOP_SAS.h
 *
 *  The CSIv2 Security Attribute Service on the target (TSS), stateless,
 *  over TLS (Phase 2 spec, W3: R11-R14, R16).
 *
 *  A request's SAS service context (IOP::SecurityAttributeService, 15)
 *  carries an EstablishContext: a GSSUP client authentication token
 *  (username and password, checked by the installed GSSUP_Verifier), an
 *  identity token and an authorization token.  An accepted context is
 *  answered with CompleteEstablishContext (context_stateful false) and
 *  fills the request's caller record; anything else is answered with a
 *  ContextError (CORBA 3.3 Part 2, 10.3.5) and NO_PERMISSION, and
 *  audited.  Authorization tokens are ignored (audited).
 *
 *  Identity assertion (W5: R22-R24): an identity token is accepted only
 *  from an asserter on the signed asserter list (SSLIOP_Asserter_List.h),
 *  matched against the caller's own GSSUP login or its certificate, and
 *  only for the identity types and realms its entry allows.  Asserted
 *  names (user@realm), distinguished names and certificate chains (which
 *  must verify against the service's trust store and pass the deny-list)
 *  become the caller's asserted principal; the asserter is kept beside
 *  it.  Anything else is ContextError 1 (ASSERTION_REJECTED), or 2 for an
 *  unsupported token type or with no asserter list.
 *
 *  security.conf keys: csiv2 (off, supported, required: required means a
 *  request without a SAS context is refused), csiv2_gssup (off,
 *  supported, required), gssup_target (the service's GSSUP target
 *  name, a scoped name like "@lab.example"), csiv2_asserters and
 *  allow_anonymous_assertion.
 */
//=============================================================================

#ifndef TAO_SSLIOP_SAS_H
#define TAO_SSLIOP_SAS_H

#include /**/ "ace/pre.h"

#include "orbsvcs/SSLIOP/SSLIOP_Export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "orbsvcs/CSIC.h"
#include "orbsvcs/GSSUPC.h"
#include "orbsvcs/Security/Caller.h"
#include "tao/PI_Server/PI_Server.h"

#include <string>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace SSLIOP
  {
    class TAO_SSLIOP_Export SAS_Target
    {
    public:
      /// security.conf, read once.
      struct Config
      {
        int csiv2 = 0;          ///< 0 off, 1 supported, 2 required
        int gssup = 0;          ///< 0 off, 1 supported, 2 required
        std::string target;     ///< GSSUP target name, "@realm"
        bool audit_grants = false;
        bool assertion = false;  ///< csiv2_asserters is set
        bool anonymous = false;  ///< allow_anonymous_assertion = on
      };
      static Config const &config ();

      enum Result
      {
        NONE,      ///< no SAS context (and none required)
        ACCEPTED   ///< context accepted; @a caller updated
      };

      /**
       * Handles the request's SAS context.  Throws NO_PERMISSION (after
       * adding a ContextError reply context where there was a context to
       * answer, and an audit record) when the context is refused or a
       * required one is missing.  @a tls says whether the request came
       * over TLS: a SAS context on any other transport is refused.
       */
      static Result process (PortableInterceptor::ServerRequestInfo_ptr ri,
                             TAO::Security::Caller &caller,
                             bool tls,
                             char const *operation);

      /// @name GSSUP encoding (also used by clients and tests)
      //@{
      /// DER encoding of the GSSUP mechanism OID 2.23.130.1.1.1.
      static std::string gssup_mech_der ();

      /// RFC 2743 exported name: GSSUP mechanism, @a name.
      static std::string exported_name (std::string const &name);

      /// The name inside an RFC 2743 exported name; false if not one.
      static bool parse_exported_name (std::string const &octets, std::string &name);

      /// A GSSUP InitialContextToken in its GSS-API framing.
      static bool encode_gssup_token (std::string const &user,
                                      std::string const &password,
                                      std::string const &target_name_octets,
                                      CSI::GSSToken &out);

      enum Decode { DECODED, NOT_GSSUP, MALFORMED };

      /**
       * Decodes a client authentication token.  Its length may be DER
       * (RFC 2743) or JacORB's base-128 form; the mechanism must be GSSUP.
       */
      static Decode decode_gssup_token (CSI::GSSToken const &token, GSSUP::InitialContextToken &out);
      //@}
    };
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#include /**/ "ace/post.h"

#endif /* TAO_SSLIOP_SAS_H */
