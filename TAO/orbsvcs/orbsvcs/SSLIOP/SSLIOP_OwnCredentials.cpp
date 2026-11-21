#include "orbsvcs/SSLIOP/SSLIOP_OwnCredentials.h"

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

TAO::SSLIOP::OwnCredentials::OwnCredentials (X509 *cert, EVP_PKEY *evp)
  : SSLIOP_Credentials (cert, evp),
    chain_ (nullptr)
{
}

TAO::SSLIOP::OwnCredentials::OwnCredentials (X509 *cert,
                                             EVP_PKEY *evp,
                                             STACK_OF (X509) *chain)
  : SSLIOP_Credentials (cert, evp),
    chain_ (chain == nullptr ? nullptr : ::X509_chain_up_ref (chain))
{
}

TAO::SSLIOP::OwnCredentials::~OwnCredentials ()
{
  ::sk_X509_pop_free (this->chain_, ::X509_free);
}

STACK_OF (X509) *
TAO::SSLIOP::OwnCredentials::chain () const
{
  return this->chain_;
}

TAO::SSLIOP::OwnCredentials_ptr
TAO::SSLIOP::OwnCredentials::_duplicate (TAO::SSLIOP::OwnCredentials_ptr obj)
{
  if (!CORBA::is_nil (obj))
    obj->_add_ref ();

  return obj;
}

TAO::SSLIOP::OwnCredentials_ptr
TAO::SSLIOP::OwnCredentials::_narrow (CORBA::Object_ptr obj)
{
  return  TAO::SSLIOP::OwnCredentials::_duplicate (
              dynamic_cast<TAO::SSLIOP::OwnCredentials *> (obj));
}

TAO::SSLIOP::OwnCredentials_ptr
TAO::SSLIOP::OwnCredentials::_nil ()
{
  return nullptr;
}

SecurityLevel3::CredentialsType
TAO::SSLIOP::OwnCredentials::creds_type ()
{
  return SecurityLevel3::CT_OwnCredentials;
}

SecurityLevel3::CredsInitiator_ptr
TAO::SSLIOP::OwnCredentials::creds_initiator ()
{
  throw CORBA::NO_IMPLEMENT ();
}

SecurityLevel3::CredsAcceptor_ptr
TAO::SSLIOP::OwnCredentials::creds_acceptor ()
{
  throw CORBA::NO_IMPLEMENT ();
}

void
TAO::SSLIOP::OwnCredentials::release_credentials ()
{
  this->creds_state_ = SecurityLevel3::CS_PendingRelease;
}

TAO_END_VERSIONED_NAMESPACE_DECL
