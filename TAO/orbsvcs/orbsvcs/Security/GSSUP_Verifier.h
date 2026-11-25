// -*- C++ -*-

//=============================================================================
/**
 *  @file GSSUP_Verifier.h
 *
 *  Checks the username and password of a CSIv2 GSSUP login.
 *
 *  The SAS layer (SSLIOP) decodes a client's GSSUP InitialContextToken
 *  and asks the installed verifier.  With none installed every GSSUP
 *  login is refused.  A verifier never logs the password.
 */
//=============================================================================

#ifndef TAO_SECURITY_GSSUP_VERIFIER_H
#define TAO_SECURITY_GSSUP_VERIFIER_H

#include /**/ "ace/pre.h"

#include "orbsvcs/Security/security_export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "tao/Versioned_Namespace.h"

#include <string>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace Security
  {
    class TAO_Security_Export GSSUP_Verifier
    {
    public:
      virtual ~GSSUP_Verifier ();

      /**
       * True if @a password is right for @a user at @a target (the
       * service's GSSUP target name, e.g. "@lab.example").  On false,
       * @a detail says why, for the audit record (never the password).
       */
      virtual bool verify (std::string const &user,
                           std::string const &password,
                           std::string const &target,
                           std::string &detail) = 0;

      /// Installs the process-wide verifier (not owned; null removes it).
      static void install (GSSUP_Verifier *verifier);

      /// The installed verifier, or null.
      static GSSUP_Verifier *installed ();
    };
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#include /**/ "ace/post.h"

#endif /* TAO_SECURITY_GSSUP_VERIFIER_H */
