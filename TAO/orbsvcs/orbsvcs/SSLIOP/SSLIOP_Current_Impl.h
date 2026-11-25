// -*- C++ -*-

// ===================================================================
/**
 *  @file   SSLIOP_Current_Impl.h
 *
 *  @author Ossama Othman <ossama@uci.edu>
 */
// ===================================================================

#ifndef TAO_SSLIOP_CURRENT_IMPL_H
#define TAO_SSLIOP_CURRENT_IMPL_H

#include /**/ "ace/pre.h"

#include "ace/config-all.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "orbsvcs/SSLIOPC.h"
#include "orbsvcs/Security/SL3_SecurityCurrent_Impl.h"
#include "orbsvcs/Security/Caller.h"

#include <openssl/ssl.h>

#include <memory>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace SSLIOP
  {
    /**
     * @class Current_Impl
     *
     * @brief TSS portion of the TAO SSLIOP::Current extension, and
     *        the SSLIOP-specific SecurityLevel3::SecurityCurrent
     *        object.
     *
     * This class encapsulates the thread-specific state of an SSL
     * session during a given upcall.
     */
    class Current_Impl : public TAO::SL3::SecurityCurrent_Impl
    {
    public:
      /// Constructor.
      Current_Impl ();

      /// Destructor
      ~Current_Impl () override;

      /// Implementation of the SSLIOP-specific
      /// SecurityLevel3::client_credentials() method.
      SecurityLevel3::ClientCredentials_ptr client_credentials () override;

      /// Implementation of the SSLIOP-specific
      /// SecurityLevel3::request_is_local() method.
      CORBA::Boolean request_is_local () override;

      /// Return the SSL peer certificate associated with the
      /// current request as an octet sequence, i.e. a DER encoded
      /// certificate.
      void get_peer_certificate (::SSLIOP::ASN_1_Cert *certificate);

      /// Return the SSL peer certificate chain associated with the
      /// current request as a sequence of DER encoded certificates.
      void get_peer_certificate_chain (::SSLIOP::SSL_Cert *cert_chain);

      /// Set the pointer to the underlying SSL session state.
      void ssl (SSL *s);

      /// Return pointer to the SSL session state for the current upcall.
      SSL *ssl ();

      /// A caller record built from the TLS session: the peer
      /// certificate's SPIFFE IDs, subject, issuer and serial, and the
      /// peer's address.
      TAO::Security::Caller make_caller () const;

      /// The caller of the current request, once the server request
      /// interceptor has built it (null before).
      void caller (std::shared_ptr<TAO::Security::Caller const> c);
      std::shared_ptr<TAO::Security::Caller const> caller () const;

    protected:
      /// Return the unique tag that identifies the concrete subclass.
      CORBA::ULong tag () const override;

    private:
      Current_Impl (const Current_Impl &) = delete;
      void operator= (const Current_Impl &) = delete;

    private:
      /// The SSL session state corresponding to the current upcall.
      SSL *ssl_ {};

      /// The caller of the current request.
      std::shared_ptr<TAO::Security::Caller const> caller_;
    };
  }  // End SSLIOP namespace.
}  // End TAO namespace.

TAO_END_VERSIONED_NAMESPACE_DECL

#if defined (__ACE_INLINE__)
# include "orbsvcs/SSLIOP/SSLIOP_Current_Impl.inl"
#endif /* __ACE_INLINE__ */

#include /**/ "ace/post.h"

#endif  /* TAO_SSLIOP_CURRENT_IMPL_H */
