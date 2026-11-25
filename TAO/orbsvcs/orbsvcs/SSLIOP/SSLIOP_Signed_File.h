// -*- C++ -*-

//=============================================================================
/**
 *  @file SSLIOP_Signed_File.h
 *
 *  Reading the small signed policy files SSLIOP loads (the deny-list,
 *  the access list): FILE next to FILE.sig, the base64 signature
 *  (SHA-256, ECDSA or RSA PKCS#1 v1.5) of FILE's exact bytes, verified
 *  with a signer's public key whose SubjectPublicKeyInfo SHA-256 may be
 *  pinned.  Every file starts with "version N" and "issued TIME" lines.
 */
//=============================================================================

#ifndef TAO_SSLIOP_SIGNED_FILE_H
#define TAO_SSLIOP_SIGNED_FILE_H

#include /**/ "ace/pre.h"

#include "orbsvcs/SSLIOP/SSLIOP_Export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "tao/Versioned_Namespace.h"

#include <ctime>
#include <string>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace SSLIOP
  {
    namespace Signed_File
    {
      /// Reads at most 16 MB of @a path.
      TAO_SSLIOP_Export bool slurp (std::string const &path, std::string &out);

      /// @a s without leading and trailing blanks.
      TAO_SSLIOP_Export std::string trim (std::string const &s);

      /// Parses YYYY-MM-DDTHH:MM:SSZ.
      TAO_SSLIOP_Export bool parse_time (std::string const &s, time_t &out);

      /// The pending OpenSSL error as text (and clears the queue).
      TAO_SSLIOP_Export std::string ssl_error ();

      /**
       * Reads @a path and @a path.sig and verifies the signature with the
       * key in @a signer_path (PEM public key or certificate).  If @a pin
       * is not empty the signer's SPKI SHA-256 (lower-case hex) must
       * equal it.  False with @a error otherwise.
       */
      TAO_SSLIOP_Export bool read_verified (std::string const &path,
                                            std::string const &signer_path,
                                            std::string const &pin,
                                            std::string &text,
                                            std::string &error);

      /// Modification time and size of @a path and @a path.sig, to see
      /// when either changes; starts with "-;" when @a path is missing.
      TAO_SSLIOP_Export std::string stamp (std::string const &path);

      /**
       * Splits one line into a key and its value; false for a blank or
       * comment line.
       */
      TAO_SSLIOP_Export bool split_line (std::string const &line, std::string &key, std::string &value);
    }
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#include /**/ "ace/post.h"

#endif /* TAO_SSLIOP_SIGNED_FILE_H */
