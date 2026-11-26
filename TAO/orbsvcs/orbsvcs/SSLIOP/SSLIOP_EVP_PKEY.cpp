// -*- C++ -*-
#include "orbsvcs/SSLIOP/SSLIOP_EVP_PKEY.h"

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include "orbsvcs/SSLIOP/params_dup.h"

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

::EVP_PKEY *
TAO::SSLIOP::OpenSSL_traits< ::EVP_PKEY >::copy (::EVP_PKEY const & key)
{
  ::EVP_PKEY * pkey = const_cast< ::EVP_PKEY *> (&key);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  // A deep copy of any key type (RSA, DSA, DH, EC, EdDSA, ...).
  return ::EVP_PKEY_dup (pkey);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
  // No EVP_PKEY_dup before OpenSSL 3: share the key instead.  TAO never
  // modifies a key once loaded, so a reference serves as a copy, for
  // every key type.
  if (::EVP_PKEY_up_ref (pkey) != 1)
    return nullptr;
  return pkey;
#else
  // We're using the EVP_PKEY_var even though it depends on this
  // trait function.  This works since we're not actually using
  // any of the EVP_PKEY_var methods that call this copy()
  // trait.  This allows us to maintain exception safety.
  TAO::SSLIOP::EVP_PKEY_var p = ::EVP_PKEY_new ();

  int const pkey_id = ::EVP_PKEY_type (pkey->type);
  switch (pkey_id)
    {
    case EVP_PKEY_RSA:
      {
        RSA * rsa = ::EVP_PKEY_get1_RSA (pkey);
        if (rsa != nullptr)
          {
            // set1 takes its own reference: release the duplicate's.
            RSA * dup = RSAPrivateKey_dup (rsa);
            ::EVP_PKEY_set1_RSA (p.in (), dup);
            ::RSA_free (dup);
            ::RSA_free (rsa);
          }
      }
      break;

    case EVP_PKEY_DSA:
      {
        DSA * dsa = ::EVP_PKEY_get1_DSA (pkey);
        if (dsa != nullptr)
          {
            // Not exception safe!
            ::EVP_PKEY_set1_DSA (p.in (), DSAPARAMS_DUP_WRAPPER_NAME (dsa));
            ::DSA_free (dsa);
          }
      }
      break;

    case EVP_PKEY_DH:
      {
        DH * dh = ::EVP_PKEY_get1_DH (pkey);
        if (dh != nullptr)
          {
            // Not exception safe!
            ::EVP_PKEY_set1_DH (p.in (), DHPARAMS_DUP_WRAPPER_NAME (dh));
            ::DH_free (dh);
          }
      }
      break;

    default:
      // We should never get here!
      return nullptr;
    }

  return p._retn ();
#endif /* OPENSSL_VERSION_NUMBER */
}

TAO_END_VERSIONED_NAMESPACE_DECL
