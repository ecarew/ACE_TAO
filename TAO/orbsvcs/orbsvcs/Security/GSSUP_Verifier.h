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
#include <vector>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace Security
  {
    class TAO_Security_Export GSSUP_Verifier
    {
    public:
      virtual ~GSSUP_Verifier ();

      /// The outcome of one login.  Every outcome but ACCEPTED is the
      /// same refusal on the wire (ContextError 1, GSSUP UNSPECIFIED);
      /// the difference is only for the audit record.
      enum Result
      {
        ACCEPTED,
        REJECTED,       ///< wrong password, unknown user or user locked by an administrator
        LOCKED,         ///< too many recent failures for this user
        RATE_LIMITED,   ///< too many recent failures from this source
        UNAVAILABLE     ///< the verifier cannot check (e.g. its store is unusable)
      };

      /**
       * Checks @a password for @a user at @a target (the service's GSSUP
       * target name, e.g. "@lab.example"), from @a source (the caller's
       * "host:port").  @a detail says why on refusal, for the audit
       * record; it never holds the password.
       */
      virtual Result verify (std::string const &user,
                             std::string const &password,
                             std::string const &target,
                             std::string const &source,
                             std::string &detail) = 0;

      /**
       * The groups of @a user, asked once verify() has accepted it (the
       * role map's group:NAME lines, Phase 3 T3).  The default has none.
       */
      virtual std::vector<std::string> groups (std::string const &user);

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
