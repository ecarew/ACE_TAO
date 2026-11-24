// -*- C++ -*-

//=============================================================================
/**
 *  @file SSLIOP_Deny_List.h
 *
 *  Signed deny-list of certificate serials and SPIFFE IDs.
 *
 *  Revocation without CRLs or OCSP: whoever holds the deny-list signing
 *  key publishes a small text file, signed, and every service refuses a
 *  peer certificate it names, at the TLS handshake and on each request.
 *  The file
 *
 *  @code
 *    # comments and blank lines are ignored
 *    version 7
 *    issued 2026-11-23T12:00:00Z
 *    serial 053497ED7A9571E13B25E619A39AFC45
 *    spiffe spiffe://ace-tao.test/sweeper
 *  @endcode
 *
 *  sits next to FILE.sig, the base64 signature (SHA-256 with ECDSA or
 *  RSA PKCS#1 v1.5) of its exact bytes.  security.conf keys:
 *
 *  - @c denylist: the file;
 *  - @c denylist_signer: PEM public key or certificate of the signer;
 *  - @c denylist_signer_sha256: hex SHA-256 of the signer's
 *    SubjectPublicKeyInfo (required in prod);
 *  - @c denylist_reload: seconds between checks for a new file (30);
 *  - @c denylist_max_age: days after @c issued before a warning (7).
 *
 *  A new file replaces the current list only if its signature verifies
 *  and its version is higher; otherwise the service keeps the last good
 *  list and records why, with that list's age.
 */
//=============================================================================

#ifndef TAO_SSLIOP_DENY_LIST_H
#define TAO_SSLIOP_DENY_LIST_H

#include /**/ "ace/pre.h"

#include "orbsvcs/SSLIOP/SSLIOP_Export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "tao/Versioned_Namespace.h"
#include "ace/Thread_Mutex.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <ctime>
#include <memory>
#include <set>
#include <string>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace SSLIOP
  {
    class TAO_SSLIOP_Export Deny_List
    {
    public:
      struct Content
      {
        long version = 0;
        std::string issued;
        time_t issued_time = 0;
        std::set<std::string> serials;   ///< upper-case hex, no leading zeros
        std::set<std::string> spiffe;
      };

      /// Parses deny-list text.
      static bool parse (std::string const &text, Content &out, std::string &error);

      /// Verifies @a sig_b64 over @a text with @a signer.
      static bool verify (std::string const &text, std::string const &sig_b64, EVP_PKEY *signer,
                          std::string &error);

      /// Loads a PEM public key or certificate.
      static EVP_PKEY *load_signer (char const *path, std::string &error);

      /// Lower-case hex SHA-256 of the SubjectPublicKeyInfo of @a key.
      static std::string spki_sha256 (EVP_PKEY *key);

      /// Canonical serial: upper-case hex without leading zeros.
      static std::string normalize_serial (std::string const &hex);

      /// The serial (canonical) and SPIFFE IDs (URI SANs) of @a cert.
      static std::string serial_of (X509 *cert);
      static std::set<std::string> spiffe_ids_of (X509 *cert);

      /// The process-wide list, configured from the host's security.conf.
      static Deny_List *instance ();

      /// True when security.conf names a deny-list.
      bool configured () const;

      /**
       * Loads the list now (at startup).  Returns false with a reason if
       * it cannot be loaded or verified; @a summary describes a good list.
       */
      bool load (std::string &summary);

      /// Re-reads the file if it changed and the reload interval passed.
      void refresh ();

      /**
       * What @a peer matches on the list ("serial X" or the SPIFFE ID),
       * or "" if it is allowed (or no list is configured).
       */
      std::string check (X509 *peer);

      /// Days since the current list was issued (-1: none loaded).
      long age_days () const;

      /// The current list's version (0: none loaded).
      long version () const;

      /// denylist_max_age, in days.
      long max_age_days () const { return this->max_age_days_; }

    private:
      Deny_List ();

      /// Reads, verifies and parses the file; false with @a error.
      bool read (Content &out, std::string &error);

      std::string path_;
      std::string signer_path_;
      std::string signer_pin_;
      long reload_seconds_ = 30;
      long max_age_days_ = 7;

      mutable ACE_Thread_Mutex lock_;
      std::shared_ptr<Content const> current_;
      time_t last_check_ = 0;
      /// Modification time and size of the list and of its signature
      /// when last read: either changing triggers a re-read, so a list
      /// and signature replaced one after the other are both seen.
      std::string stamp_;

      std::string stamp () const;
    };
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#include /**/ "ace/post.h"

#endif /* TAO_SSLIOP_DENY_LIST_H */
