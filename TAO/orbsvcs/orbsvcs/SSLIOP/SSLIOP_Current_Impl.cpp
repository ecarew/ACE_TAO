#include "orbsvcs/SSLIOP/SSLIOP_Current_Impl.h"

#if !defined (__ACE_INLINE__)
# include "orbsvcs/SSLIOP/SSLIOP_Current_Impl.inl"
#endif /* __ACE_INLINE__ */

#include "orbsvcs/SSLIOP/SSLIOP_X509.h"
#include "orbsvcs/SSLIOP/SSLIOP_ClientCredentials.h"
#include "orbsvcs/SSLIOP/SSLIOP_Deny_List.h"

#include "tao/ORB_Constants.h"

#include "ace/INET_Addr.h"
#include "ace/SOCK_Stream.h"

#include <openssl/bio.h>
#include <openssl/x509.h>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

TAO::SSLIOP::Current_Impl::~Current_Impl ()
{
}

SecurityLevel3::ClientCredentials_ptr
TAO::SSLIOP::Current_Impl::client_credentials ()
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  TAO::SSLIOP::X509_var cert = ::SSL_get1_peer_certificate(this->ssl_);
#else
  TAO::SSLIOP::X509_var cert = ::SSL_get_peer_certificate(this->ssl_);
#endif
  if (cert.ptr () == nullptr)
    throw CORBA::BAD_OPERATION ();

  SecurityLevel3::ClientCredentials_ptr creds;
  ACE_NEW_THROW_EX (creds,
                    TAO::SSLIOP::ClientCredentials (cert.in (),
                                                    nullptr,
                                                    this->ssl_,
                                                    this->caller_),
                    CORBA::NO_MEMORY (
                      CORBA::SystemException::_tao_minor_code (
                        TAO::VMCID,
                        ENOMEM),
                      CORBA::COMPLETED_NO));

  return creds;
}

namespace
{
  std::string
  rfc2253 (X509_NAME *name)
  {
    if (name == nullptr)
      return "";
    BIO *const b = ::BIO_new (::BIO_s_mem ());
    if (b == nullptr)
      return "";
    ::X509_NAME_print_ex (b, name, 0, XN_FLAG_RFC2253);
    char *data = nullptr;
    long const n = BIO_get_mem_data (b, &data);
    std::string const out = n > 0 ? std::string (data, static_cast<size_t> (n)) : std::string ();
    ::BIO_free (b);
    return out;
  }
}

TAO::Security::Caller
TAO::SSLIOP::Current_Impl::make_caller () const
{
  TAO::Security::Caller c;
  if (this->ssl_ == nullptr)
    return c;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  TAO::SSLIOP::X509_var cert = ::SSL_get1_peer_certificate (this->ssl_);
#else
  TAO::SSLIOP::X509_var cert = ::SSL_get_peer_certificate (this->ssl_);
#endif
  if (cert.ptr () != nullptr)
    {
      for (auto const &id : TAO::SSLIOP::Deny_List::spiffe_ids_of (cert.in ()))
        c.spiffe_ids.push_back (id);
      c.subject = rfc2253 (::X509_get_subject_name (cert.in ()));
      c.issuer = rfc2253 (::X509_get_issuer_name (cert.in ()));
      c.serial = TAO::SSLIOP::Deny_List::serial_of (cert.in ());
    }

  int const fd = ::SSL_get_fd (this->ssl_);
  if (fd >= 0)
    {
      ACE_SOCK_Stream peer;
#if defined (ACE_WIN32)
      // OpenSSL keeps the SOCKET as an int.
      peer.set_handle (reinterpret_cast<ACE_HANDLE> (static_cast<intptr_t> (fd)));
#else
      peer.set_handle (static_cast<ACE_HANDLE> (fd));
#endif
      ACE_INET_Addr addr;
      if (peer.get_remote_addr (addr) == 0)
        {
          char host[INET6_ADDRSTRLEN + 1] = "";
          addr.get_host_addr (host, sizeof host);
          std::string const h = host;
          c.source = (h.find (':') != std::string::npos ? "[" + h + "]" : h) + ":"
                     + std::to_string (addr.get_port_number ());
        }
      peer.set_handle (ACE_INVALID_HANDLE);   // not ours to close
    }
  return c;
}

void
TAO::SSLIOP::Current_Impl::caller (std::shared_ptr<TAO::Security::Caller const> c)
{
  this->caller_ = std::move (c);
}

std::shared_ptr<TAO::Security::Caller const>
TAO::SSLIOP::Current_Impl::caller () const
{
  return this->caller_;
}

CORBA::Boolean
TAO::SSLIOP::Current_Impl::request_is_local ()
{
  throw CORBA::NO_IMPLEMENT ();
}

void
TAO::SSLIOP::Current_Impl::get_peer_certificate (
  ::SSLIOP::ASN_1_Cert *certificate)
{
  if (this->ssl_ == nullptr)
    return;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  TAO::SSLIOP::X509_var cert = ::SSL_get1_peer_certificate(this->ssl_);
#else
  TAO::SSLIOP::X509_var cert = ::SSL_get_peer_certificate(this->ssl_);
#endif
  if (cert.ptr () == nullptr)
    return;

  // Get the size of the ASN.1 encoding.
  int const cert_length = ::i2d_X509 (cert.in (), nullptr);
  if (cert_length <= 0)
    return;

  certificate->length (cert_length);

  CORBA::Octet *buffer = certificate->get_buffer ();

  // Convert from the internal X509 representation to the DER encoding
  // representation.
  (void) ::i2d_X509 (cert.in (), &buffer);
}

void
TAO::SSLIOP::Current_Impl::get_peer_certificate_chain (
  ::SSLIOP::SSL_Cert *cert_chain)
{
  if (this->ssl_ == nullptr)
    return;

  STACK_OF (X509) *certs = ::SSL_get_peer_cert_chain (this->ssl_);
  if (certs == nullptr)
    return;

  int const chain_length = sk_X509_num (certs);
  cert_chain->length (chain_length);

  // Copy the peer certificate chain to the SSLIOP::SSL_Cert
  // sequence.
  for (int i = 0; i < chain_length; ++i)
    {
      // Extract the certificate from the OpenSSL X509 stack.
      ::X509 *x = sk_X509_value (certs, i);

      // Get the size of the ASN.1 encoding.
      int const cert_length = ::i2d_X509 (x, nullptr);
      if (cert_length <= 0)
        continue;  // @@ What do we do if there is an error?

      ::SSLIOP::ASN_1_Cert &certificate = (*cert_chain)[i];
      certificate.length (cert_length);

      CORBA::Octet *buffer = certificate.get_buffer ();

      // Convert from the internal X509 representation to the DER
      // encoding representation.
      (void) ::i2d_X509 (x, &buffer);
    }
}

CORBA::ULong
TAO::SSLIOP::Current_Impl::tag () const
{
  return ::SSLIOP::TAG_SSL_SEC_TRANS;
}

TAO_END_VERSIONED_NAMESPACE_DECL
