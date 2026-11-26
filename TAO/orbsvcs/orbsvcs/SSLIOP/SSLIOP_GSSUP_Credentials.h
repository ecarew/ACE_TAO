// -*- C++ -*-

//=============================================================================
/**
 *  @file   SSLIOP_GSSUP_Credentials.h
 *
 *  CSIv2 GSSUP (username/password) credentials for TAO clients, acquired
 *  through SecurityLevel3 with the "SL3GSSUP" acquisition method and an
 *  SSLIOP::GSSUPAuthData argument.  The client SAS interceptor
 *  (SSLIOP_SAS_Client) sends them in an EstablishContext to targets
 *  whose GSSUP target name matches theirs.
 */
//=============================================================================

#ifndef TAO_SSLIOP_GSSUP_CREDENTIALS_H
#define TAO_SSLIOP_GSSUP_CREDENTIALS_H

#include /**/ "ace/pre.h"

#include "orbsvcs/SSLIOP/SSLIOP_Export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

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
     * @class GSSUP_OwnCredentials
     *
     * A username, its password and the GSSUP target name ("@realm") they
     * may be sent to.  The password is wiped when the credentials are
     * released or destroyed.
     */
    class TAO_SSLIOP_Export GSSUP_OwnCredentials
      : public virtual SecurityLevel3::OwnCredentials,
        public virtual ::CORBA::LocalObject
    {
    public:
      GSSUP_OwnCredentials (std::string const &username,
                            std::string const &password,
                            std::string const &target);

      std::string const &username () const;
      std::string const &password () const;
      std::string const &target () const;

      /// Valid (not released).
      bool usable () const;

      /// The GSSUP credentials in @a creds, or null.
      static GSSUP_OwnCredentials *of (SecurityLevel3::Credentials_ptr creds);

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
      ~GSSUP_OwnCredentials () override;

    private:
      void wipe ();

      std::string const username_;
      std::string password_;
      std::string const target_;
      SecurityLevel3::CredentialsState state_;
    };

    /**
     * @class GSSUP_CredentialsAcquirer
     *
     * One-step acquisition: reads the password from the source the
     * SSLIOP::GSSUPAuthData names and returns GSSUP_OwnCredentials.
     * Nothing is checked with a server here; a wrong password shows on
     * the first call (NO_PERMISSION).
     */
    class TAO_SSLIOP_Export GSSUP_CredentialsAcquirer
      : public virtual SecurityLevel3::CredentialsAcquirer,
        public virtual ::CORBA::LocalObject
    {
    public:
      GSSUP_CredentialsAcquirer (TAO::SL3::CredentialsCurator_ptr curator,
                                 CORBA::Any const &acquisition_arguments);

      char * acquisition_method () override;
      SecurityLevel3::AcquisitionStatus current_status () override;
      CORBA::ULong nth_iteration () override;
      CORBA::Any * get_continuation_data () override;
      SecurityLevel3::AcquisitionStatus continue_acquisition (
          CORBA::Any const & acquisition_arguments) override;
      SecurityLevel3::OwnCredentials_ptr get_credentials (CORBA::Boolean on_list) override;
      void destroy () override;

      /**
       * Reads a password from @a source ("prompt", "fd:N", "file:PATH";
       * see SSLIOP.idl).  False with @a error if it cannot, or if the
       * file is not owned by this user or is readable by others.
       */
      static bool read_password (std::string const &source,
                                 std::string const &username,
                                 std::string &password,
                                 std::string &error);

      /// The target name for @a username when none is given: "@realm".
      static std::string default_target (std::string const &username);

    protected:
      ~GSSUP_CredentialsAcquirer () override;

    private:
      TAO_SYNCH_MUTEX lock_;
      TAO::SL3::CredentialsCurator_var curator_;
      CORBA::Any const acquisition_arguments_;
      bool destroyed_;
    };

    /// The "SL3GSSUP" acquirer factory.
    class TAO_SSLIOP_Export GSSUP_CredentialsAcquirerFactory
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

#endif /* TAO_SSLIOP_GSSUP_CREDENTIALS_H */
