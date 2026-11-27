// -*- C++ -*-

//=============================================================================
/**
 *  @file Caller.h
 *
 *  The caller of a request, as one record, whatever proved it.
 *
 *  A request reaches a service with up to three identities: the peer
 *  certificate of its TLS connection (the transport principal), a
 *  username and password checked by the service (the authenticated
 *  principal, CSIv2 GSSUP) and an identity asserted by a trusted middle
 *  tier (the asserted principal, CSIv2 identity assertion).  The record
 *  keeps all of them; the effective principal is the one access is
 *  decided on: asserted, else authenticated, else transport.
 *
 *  The server request interceptor builds the record once per request.
 *  The access decision receives it as SecurityLevel2 received
 *  credentials (Caller_Credentials) and a servant reads it through
 *  SecurityLevel3::SecurityCurrent::client_credentials().
 */
//=============================================================================

#ifndef TAO_SECURITY_CALLER_H
#define TAO_SECURITY_CALLER_H

#include /**/ "ace/pre.h"

#include "orbsvcs/Security/security_export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "orbsvcs/SecurityLevel2C.h"
#include "orbsvcs/SecurityLevel3C.h"
#include "tao/LocalObject.h"

#include <string>
#include <vector>

#if defined (_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4250)
#endif /* _MSC_VER */

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace Security
  {
    /// SecurityLevel3 name type of a SPIFFE ID (a URI SAN).
    constexpr char const NT_SPIFFE_ID[] = "TAO:SPIFFEID";

    /// SecurityLevel3 name type of a Kerberos realm: the authority of
    /// ticket groups (Phase 3 K4).
    constexpr char const NT_KERBEROS_REALM[] = "TAO:KerberosRealm";

    /// SecurityLevel3 privilege attribute type of an AD group SID from a
    /// verified Kerberos ticket (Phase 3 K4).
    constexpr char const PA_GROUP_SID[] = "TAO:ADGroupSID";

    struct TAO_Security_Export Caller
    {
      /// @name Transport principal, from the peer certificate
      //@{
      std::vector<std::string> spiffe_ids;  ///< URI SANs that are spiffe:// IDs
      std::string subject;                  ///< RFC 2253 subject DN
      std::string issuer;                   ///< RFC 2253 issuer DN
      std::string serial;                   ///< upper-case hex
      //@}

      /// Authenticated principal (CSIv2 GSSUP user@realm); empty if none.
      std::string authenticated;

      /// Asserted principal and the principal that asserted it.
      std::string asserted;
      std::string asserter;

      /// The mechanism each name belongs to (Phase 3 K5): "krb5" for a
      /// Kerberos principal, "gssup" for a GSSUP scoped-username, empty
      /// otherwise.  A middle tier asserts a name in its own mechanism.
      std::string authenticated_mech;
      std::string asserted_mech;

      /// The mechanism of effective(): asserted_mech if a name is
      /// asserted, else authenticated_mech.
      std::string const &effective_mech () const;

      /// Group SIDs from the authenticated principal's verified Kerberos
      /// ticket (its AD PAC, Phase 3 K4), and the realm that issued them.
      /// They belong to @c authenticated: when a name is asserted they
      /// are the asserter's groups, never the asserted caller's.
      std::vector<std::string> groups;
      std::string groups_authority;

      /// The account SID from that same verified ticket (its PAC's
      /// logon information); it also belongs to @c authenticated.
      std::string user_sid;

      /// When @c authenticated logged in (seconds since the epoch): a
      /// Kerberos ticket's authtime (its first KDC login, kept through
      /// renewals), the time of the request for a GSSUP login; 0 for a
      /// certificate alone.
      long long auth_time = 0;

      /// Groups the GSSUP verifier gives @c authenticated (the store
      /// line's groups=, Phase 3 T3).  Like @c groups, they belong to
      /// the authenticated login, never to an asserted caller.
      std::vector<std::string> login_groups;

      /// The peer's address, "host:port".
      std::string source;

      /// A collocated call: the process calling itself.
      bool local = false;

      /// The certificate's identity: its first SPIFFE ID, else its subject.
      std::string transport () const;

      /// Asserted, else authenticated, else transport, else "anonymous"
      /// ("local" for a collocated call).
      std::string effective () const;

      /// Every principal the record names, effective first, no duplicates.
      std::vector<std::string> principals () const;
    };

    /**
     * Decides requests from identified callers.  Installed in TAO's
     * AccessDecision with AccessDecision::caller_policy(); the SSLIOP
     * signed access list is one.
     */
    class TAO_Security_Export Caller_Policy
    {
    public:
      enum Result
      {
        NO_RULE,  ///< nothing covers the request: the default decides
        ALLOW,
        DENY
      };

      virtual ~Caller_Policy ();

      /// @a object_path names the target: "/" + POA names + "/" + object id.
      virtual Result decide (Caller const &caller,
                             char const *object_path,
                             char const *operation) = 0;
    };

    /**
     * SecurityLevel2 received credentials carrying a Caller.  Its
     * attributes are the standard ones: AccessId and AuditId hold the
     * effective principal.  Code that needs the rest of the record
     * (who asserted it, the certificate's serial) uses caller_of().
     */
    class TAO_Security_Export Caller_Credentials
      : public virtual SecurityLevel2::ReceivedCredentials,
        public virtual ::CORBA::LocalObject
    {
    public:
      Caller_Credentials (Caller const &caller, char const *mechanism);

      Caller const &caller () const;

      /// The Caller behind @a creds, or null if they are not Caller_Credentials.
      static Caller const *caller_of (SecurityLevel2::Credentials_ptr creds);

      /// @name SecurityLevel2::Credentials
      //@{
      SecurityLevel2::Credentials_ptr copy () override;
      void destroy () override;
      ::Security::InvocationCredentialsType credentials_type () override;
      ::Security::AuthenticationStatus authentication_state () override;
      char * mechanism () override;
      ::Security::AssociationOptions accepting_options_supported () override;
      void accepting_options_supported (::Security::AssociationOptions) override;
      ::Security::AssociationOptions accepting_options_required () override;
      void accepting_options_required (::Security::AssociationOptions) override;
      ::Security::AssociationOptions invocation_options_supported () override;
      void invocation_options_supported (::Security::AssociationOptions) override;
      ::Security::AssociationOptions invocation_options_required () override;
      void invocation_options_required (::Security::AssociationOptions) override;
      ::CORBA::Boolean get_security_feature (::Security::CommunicationDirection direction,
                                             ::Security::SecurityFeature feature) override;
      ::CORBA::Boolean set_attributes (::Security::AttributeList const &requested,
                                       ::Security::AttributeList_out actual) override;
      ::Security::AttributeList * get_attributes (::Security::AttributeTypeList const &attributes) override;
      ::CORBA::Boolean is_valid (::Security::UtcT_out expiry_time) override;
      ::CORBA::Boolean refresh (::CORBA::Any const &refresh_data) override;
      //@}

      /// @name SecurityLevel2::ReceivedCredentials
      //@{
      SecurityLevel2::Credentials_ptr accepting_credentials () override;
      ::Security::AssociationOptions association_options_used () override;
      ::Security::DelegationState delegation_state () override;
      ::Security::DelegationMode delegation_mode () override;
      //@}

    protected:
      ~Caller_Credentials () override;

    private:
      Caller const caller_;
      std::string const mechanism_;
    };

    /// The SecurityLevel3 principal of @a caller: a SimplePrincipal
    /// named by the effective principal, its other names as alternates.
    TAO_Security_Export SecurityLevel3::Principal *
    principal_of (Caller const &caller);
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#if defined (_MSC_VER)
#pragma warning(pop)
#endif /* _MSC_VER */

#include /**/ "ace/post.h"

#endif /* TAO_SECURITY_CALLER_H */
