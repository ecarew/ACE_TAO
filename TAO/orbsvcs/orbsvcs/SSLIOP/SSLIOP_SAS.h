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
 *  Anonymous assertion (allow_anonymous_assertion): off (default);
 *  listed (only listed asserters whose entry allows "anonymous"); on
 *  (any caller, authenticated or not: CSIv2 rule 4, CORBA 3.3 Part 2
 *  Table 10.4).  An anonymous caller is not an identified caller, so the
 *  access list decides what, if anything, it may do.
 *
 *  Kerberos (Phase 3 K2, R27, R28): with csiv2_kerberos on, a client
 *  authentication token of the Kerberos V5 mechanism is accepted with
 *  the service's keytab (SSLIOP_Kerberos.h) and the caller becomes
 *  user@REALM.  By default the token must be bound to the TLS session
 *  (krb_channel_binding = required).  At most one of csiv2_kerberos and
 *  csiv2_gssup may be required; a required mechanism refuses tokens of
 *  the other.
 *
 *  GSSUP usernames and asserted GSSUP names are scoped-usernames (10.2.5.2):
 *  "name", "name@scope" or "@scope", with '@' and '\' inside a part
 *  quoted by '\'.  A username's scope, when given, must be the service's
 *  gssup_target.
 *
 *  security.conf keys: csiv2 (off, supported, required: required means a
 *  request without a SAS context is refused), csiv2_gssup (off,
 *  supported, required), gssup_target (the service's GSSUP target
 *  name, a scoped name like "@lab.example"), csiv2_asserters,
 *  allow_anonymous_assertion, csiv2_kerberos (off, supported, required),
 *  krb_principal (the service principal, e.g.
 *  ace-tao/naming.lab.test@LAB.TEST), krb_keytab, krb_rcache (default:
 *  the library's replay cache), krb_channel_binding (off, supported,
 *  required; default required) and krb_max_ticket_age (a duration, e.g.
 *  1h: a ticket whose KDC login, its authtime, is older is refused, so
 *  the user returns with a fresh PAC; default no limit, which prod warns
 *  about).
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

struct ssl_st;

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
        /// allow_anonymous_assertion: 0 off, 1 listed, 2 on (any caller)
        int anonymous = 0;
        int kerberos = 0;          ///< csiv2_kerberos: 0 off, 1 supported, 2 required
        std::string krb_principal; ///< krb_principal: the service principal
        std::string krb_keytab;    ///< krb_keytab
        std::string krb_rcache;    ///< krb_rcache (empty: the library's default)
        int krb_binding = 2;       ///< krb_channel_binding: 0 off, 1 supported, 2 required
        long krb_max_age = 0;      ///< krb_max_ticket_age in seconds; 0: no limit
        /// Client side: assert the current request's caller on calls a
        /// servant makes (csiv2_assert_caller = on).
        bool assert_caller = false;
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
       * over TLS: a SAS context on any other transport is refused.  @a
       * ssl is that TLS session, for Kerberos channel binding.
       */
      static Result process (PortableInterceptor::ServerRequestInfo_ptr ri,
                             TAO::Security::Caller &caller,
                             bool tls,
                             char const *operation,
                             ssl_st *ssl = nullptr);

      /// The DER mechanism OID of a GSS initial context token (0x60,
      /// length, OID), or empty if it is not one.
      static std::string token_mech (std::string const &token);

      /// @name GSSUP encoding (also used by clients and tests)
      //@{
      /**
       * Splits a scoped-username (CORBA 3.3 Part 2, 10.2.5.2) at its
       * delimiting '@', unquoting both parts.  @a scope keeps the '@'
       * ("@lab.test") and is empty when there is none.  False when the
       * name is malformed: a second unquoted '@', a '\' that quotes
       * anything but '@' or '\', or an empty part beside the '@'.
       */
      static bool split_scoped (std::string const &name, std::string &value, std::string &scope);

      /// @a part with '@' and '\' quoted, for use in a scoped-username.
      static std::string quote_scoped (std::string const &part);

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
