// -*- C++ -*-

//=============================================================================
/**
 *  @file   SSLIOP_SAS_Client.h
 *
 *  The client side of the CSIv2 SAS protocol (R15): a client request
 *  interceptor that sends a stateless EstablishContext to targets whose
 *  CSIv2 component (TAG_CSI_SEC_MECH_LIST) asks for one, and turns a
 *  ContextError reply into NO_PERMISSION.
 *
 *  - Client authentication: GSSUP credentials acquired with "SL3GSSUP",
 *    sent only over TLS and only to a target whose GSSUP target name
 *    equals the credentials' target name.  A target that requires GSSUP
 *    and has no matching credentials is refused locally (NO_PERMISSION,
 *    SAS_CLIENT_NO_CREDENTIALS) without contacting it.
 *  - Identity assertion: with csiv2_assert_caller = on, a call a servant
 *    makes while serving a request asserts that request's caller (its
 *    user@realm as a principal name, or its certificate chain) to targets
 *    that support identity assertion.
 */
//=============================================================================

#ifndef TAO_SSLIOP_SAS_CLIENT_H
#define TAO_SSLIOP_SAS_CLIENT_H

#include /**/ "ace/pre.h"

#include "orbsvcs/SSLIOP/SSLIOP_Export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "orbsvcs/SSLIOPC.h"
#include "orbsvcs/SecurityC.h"
#include "orbsvcs/Security/SL3_CredentialsCurator.h"
#include "tao/PI/PI.h"
#include "tao/LocalObject.h"

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4250)
#endif /* _MSC_VER */

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace SSLIOP
  {
    class TAO_SSLIOP_Export SAS_Client_Interceptor
      : public virtual PortableInterceptor::ClientRequestInterceptor,
        public virtual ::CORBA::LocalObject
    {
    public:
      SAS_Client_Interceptor (TAO::SL3::CredentialsCurator_ptr curator,
                              ::SSLIOP::Current_ptr current,
                              ::Security::QOP default_qop);

      char * name () override;
      void destroy () override;
      void send_request (PortableInterceptor::ClientRequestInfo_ptr ri) override;
      void send_poll (PortableInterceptor::ClientRequestInfo_ptr ri) override;
      void receive_reply (PortableInterceptor::ClientRequestInfo_ptr ri) override;
      void receive_exception (PortableInterceptor::ClientRequestInfo_ptr ri) override;
      void receive_other (PortableInterceptor::ClientRequestInfo_ptr ri) override;

    protected:
      ~SAS_Client_Interceptor () override;

    private:
      /// A ContextError in the reply: audit it and raise NO_PERMISSION.
      void check_reply (PortableInterceptor::ClientRequestInfo_ptr ri, bool exception);

      TAO::SL3::CredentialsCurator_var curator_;
      ::SSLIOP::Current_var current_;
      ::Security::QOP const default_qop_;
    };
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#if defined(_MSC_VER)
#pragma warning(pop)
#endif /* _MSC_VER */

#include /**/ "ace/post.h"

#endif /* TAO_SSLIOP_SAS_CLIENT_H */
