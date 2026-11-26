// -*- C++ -*-

//=============================================================================
/**
 *  @file   SSLIOP_Kerberos_Credentials.h
 *
 *  CSIv2 Kerberos credentials for TAO clients (Phase 3 K3, R29),
 *  acquired through SecurityLevel3 with the "SL3Kerberos" acquisition
 *  method and an SSLIOP::KerberosAuthData argument.  They name where the
 *  tickets are (a ticket cache, or a client keytab); no password or key
 *  is held here.  The client SAS interceptor (SSLIOP_SAS_Client) logs in
 *  with them to targets whose Kerberos service principal they allow,
 *  and checks each target's reply (mutual authentication).
 */
//=============================================================================

#ifndef TAO_SSLIOP_KERBEROS_CREDENTIALS_H
#define TAO_SSLIOP_KERBEROS_CREDENTIALS_H

#include /**/ "ace/pre.h"

#include "orbsvcs/SSLIOP/SSLIOP_Export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "orbsvcs/SSLIOP/SSLIOP_Kerberos.h"
#include "orbsvcs/Security/SL3_CredentialsCurator.h"
#include "orbsvcs/Security/SL3_CredentialsAcquirerFactory.h"
#include "orbsvcs/SecurityLevel3C.h"
#include "tao/LocalObject.h"

#include <string>

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4250)
#endif /* _MSC_VER */

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace SSLIOP
  {
    /**
     * @class Kerberos_OwnCredentials
     *
     * The ticket source, the client principal it yields and the target
     * names (one service principal, or "@REALM") it may log in to.
     */
    class TAO_SSLIOP_Export Kerberos_OwnCredentials
      : public virtual SecurityLevel3::OwnCredentials,
        public virtual ::CORBA::LocalObject
    {
    public:
      Kerberos_OwnCredentials (Kerberos::Client_Source const &source,
                               std::string const &client,
                               std::string const &target,
                               long lifetime);

      Kerberos::Client_Source const &source () const;
      std::string const &client () const;
      std::string const &target () const;

      /// Valid (not released).
      bool usable () const;

      /// True if these credentials may log in to service principal @a
      /// service: it equals the target name, or the target name is
      /// "@REALM" and @a service is in that realm.
      bool allows (std::string const &service) const;

      /// The Kerberos credentials in @a creds, or null.
      static Kerberos_OwnCredentials *of (SecurityLevel3::Credentials_ptr creds);

      /// @name SecurityLevel3::Credentials
      //@{
      char * creds_id () override;
      SecurityLevel3::CredentialsType creds_type () override;
      SecurityLevel3::CredentialsUsage creds_usage () override;
      TimeBase::UtcT expiry_time () override;
      SecurityLevel3::CredentialsState creds_state () override;
      char * add_relinquished_listener (
          SecurityLevel3::RelinquishedCredentialsListener_ptr listener) override;
      void remove_relinquished_listener (const char * id) override;
      //@}

      /// @name SecurityLevel3::OwnCredentials
      //@{
      SecurityLevel3::CredsInitiator_ptr creds_initiator () override;
      SecurityLevel3::CredsAcceptor_ptr creds_acceptor () override;
      void release_credentials () override;
      //@}

    protected:
      ~Kerberos_OwnCredentials () override;

    private:
      Kerberos::Client_Source const source_;
      std::string const client_;
      std::string const target_;
      /// Expiry of the ticket seen at acquisition (UTC seconds since
      /// 1970), or 0 if unknown.  A renewed ticket is used regardless:
      /// each login reads the cache afresh.
      long const expiry_;
      SecurityLevel3::CredentialsState state_;
    };

    /**
     * @class Kerberos_CredentialsAcquirer
     *
     * One-step acquisition: checks that the source yields a usable
     * ticket (or key) and returns Kerberos_OwnCredentials.  Fails with
     * BAD_PARAM if there is none, or if SSLIOP was built without GSS-API.
     */
    class TAO_SSLIOP_Export Kerberos_CredentialsAcquirer
      : public virtual SecurityLevel3::CredentialsAcquirer,
        public virtual ::CORBA::LocalObject
    {
    public:
      Kerberos_CredentialsAcquirer (TAO::SL3::CredentialsCurator_ptr curator,
                                    CORBA::Any const &acquisition_arguments);

      char * acquisition_method () override;
      SecurityLevel3::AcquisitionStatus current_status () override;
      CORBA::ULong nth_iteration () override;
      CORBA::Any * get_continuation_data () override;
      SecurityLevel3::AcquisitionStatus continue_acquisition (
          CORBA::Any const & acquisition_arguments) override;
      SecurityLevel3::OwnCredentials_ptr get_credentials (CORBA::Boolean on_list) override;
      void destroy () override;

    protected:
      ~Kerberos_CredentialsAcquirer () override;

    private:
      TAO_SYNCH_MUTEX lock_;
      TAO::SL3::CredentialsCurator_var curator_;
      CORBA::Any const acquisition_arguments_;
      bool destroyed_;
    };

    /// The "SL3Kerberos" acquirer factory.
    class TAO_SSLIOP_Export Kerberos_CredentialsAcquirerFactory
      : public virtual TAO::SL3::CredentialsAcquirerFactory
    {
    public:
      SecurityLevel3::CredentialsAcquirer_ptr make (
        TAO::SL3::CredentialsCurator_ptr curator,
        CORBA::Any const & acquisition_arguments) override;
    };
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#if defined(_MSC_VER)
#pragma warning(pop)
#endif /* _MSC_VER */

#include /**/ "ace/post.h"

#endif /* TAO_SSLIOP_KERBEROS_CREDENTIALS_H */
