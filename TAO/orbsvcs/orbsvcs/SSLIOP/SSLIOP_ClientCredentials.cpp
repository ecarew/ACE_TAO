#include "orbsvcs/SSLIOP/SSLIOP_ClientCredentials.h"
#include "orbsvcs/SSLIOP/SSLIOP_OwnCredentials.h"
#include "orbsvcs/SSLIOP/SSLIOP_Current_Impl.h"

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

TAO::SSLIOP::ClientCredentials::ClientCredentials (
  X509 * cert,
  EVP_PKEY *evp,
  SSL * ssl,
  std::shared_ptr<TAO::Security::Caller const> caller)
  : SSLIOP_Credentials (cert, evp),
    ssl_ (TAO::SSLIOP::OpenSSL_traits< ::SSL >::_duplicate (ssl)),
    caller_ (std::move (caller))
{
}

TAO::SSLIOP::ClientCredentials::~ClientCredentials ()
{
}

SecurityLevel3::CredentialsType
TAO::SSLIOP::ClientCredentials::creds_type ()
{
  return SecurityLevel3::CT_ClientCredentials;
}

char *
TAO::SSLIOP::ClientCredentials::context_id ()
{
  throw CORBA::NO_IMPLEMENT ();
}

SecurityLevel3::Principal *
TAO::SSLIOP::ClientCredentials::client_principal ()
{
  // The request's caller record names the effective principal (an
  // asserted or password-authenticated identity when there is one);
  // without one, the peer certificate alone.
  if (this->caller_)
    return TAO::Security::principal_of (*this->caller_);

  TAO::SSLIOP::Current_Impl impl;
  impl.ssl (this->ssl_.in ());
  return TAO::Security::principal_of (impl.make_caller ());
}

SecurityLevel3::StatementList *
TAO::SSLIOP::ClientCredentials::client_supporting_statements ()
{
  throw CORBA::NO_IMPLEMENT ();
}

SecurityLevel3::ResourceNameList *
TAO::SSLIOP::ClientCredentials::client_restricted_resources ()
{
  throw CORBA::NO_IMPLEMENT ();
}

SecurityLevel3::Principal *
TAO::SSLIOP::ClientCredentials::target_principal ()
{
  throw CORBA::NO_IMPLEMENT ();
}

SecurityLevel3::StatementList *
TAO::SSLIOP::ClientCredentials::target_supporting_statements ()
{
  throw CORBA::NO_IMPLEMENT ();
}

SecurityLevel3::ResourceNameList *
TAO::SSLIOP::ClientCredentials::target_restricted_resources ()
{
  throw CORBA::NO_IMPLEMENT ();
}

SecurityLevel3::OwnCredentials_ptr
TAO::SSLIOP::ClientCredentials::parent_credentials ()
{
  SecurityLevel3::OwnCredentials_ptr creds =
    SecurityLevel3::OwnCredentials::_nil ();

  ACE_NEW_THROW_EX (creds,
                    TAO::SSLIOP::OwnCredentials (
                      ::SSL_get_certificate (this->ssl_.in ()),
                      ::SSL_get_privatekey (this->ssl_.in ())),
                    CORBA::NO_MEMORY ());

  return creds;
}

CORBA::Boolean
TAO::SSLIOP::ClientCredentials::client_authentication ()
{
  // If the client presented no certificate (i.e. cert_.ptr() == nullptr),
  // the client was not authenticated.  Otherwise, verify the peer's
  // certificate.

  return
    this->x509_.in () != nullptr
    && SSL_get_verify_result (this->ssl_.in ()) == X509_V_OK;
}

CORBA::Boolean
TAO::SSLIOP::ClientCredentials::target_authentication ()
{
  throw CORBA::NO_IMPLEMENT ();
}

CORBA::Boolean
TAO::SSLIOP::ClientCredentials::confidentiality ()
{
  throw CORBA::NO_IMPLEMENT ();
}

CORBA::Boolean
TAO::SSLIOP::ClientCredentials::integrity ()
{
  // TAO's SSLIOP pluggable transport always provides integrity.  Note
  // that if we

  return true;
}

TAO_END_VERSIONED_NAMESPACE_DECL
