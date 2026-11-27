// -*- C++ -*-

//=============================================================================
/**
 *  @file SSLIOP_Asserter_List.h
 *
 *  Signed list of the principals trusted to assert identities (CSIv2
 *  identity assertion, Phase 2 R22 and R23).
 *
 *  Accepting an assertion means trusting the asserter completely, so a
 *  service accepts one only from a principal named here.  The file
 *
 *  @code
 *    # comments and blank lines are ignored
 *    version 2
 *    issued 2026-11-25T12:00:00Z
 *    asserter spiffe://ace-tao.test/gateway
 *    asserter spiffe://ace-tao.test/portal  types=name,x509  realms=@lab.test,@partner.test
 *    asserter CN=legacy gateway,O=Example   types=dn
 *    asserter spiffe://ace-tao.test/kiosk   roles=reader
 *  @endcode
 *
 *  - principal: a SPIFFE ID or an RFC 2253 certificate subject, matched
 *    against the caller's certificate, or a GSSUP user@realm matched
 *    against the caller's own GSSUP login (CSIv2 backward trust);
 *    everything before the first option;
 *  - types: the identity token types it may assert: name
 *    (ITTPrincipalName), dn (ITTDistinguishedName), x509
 *    (ITTX509CertChain), anonymous (ITTAnonymous, also needs
 *    allow_anonymous_assertion = on).  Default: name;
 *  - realms: for asserted names, the realms it may assert, or *.
 *    Default: the service's own (gssup_target);
 *  - roles: the roles its asserted callers can reach under the role
 *    model (Phase 3 T3, R36): an asserted caller holds the role map's
 *    roles for it that are also in this list.  Default: no cap.
 *
 *  The file sits next to FILE.sig like the deny-list
 *  (SSLIOP_Signed_File.h).  security.conf keys:
 *
 *  - @c csiv2_asserters: the file (none: identity assertion is off);
 *  - @c csiv2_asserters_signer: signer's PEM public key or certificate
 *    (default: denylist_signer);
 *  - @c csiv2_asserters_signer_sha256: pinned SPKI SHA-256 of the signer
 *    (default: denylist_signer_sha256; required in prod);
 *  - @c csiv2_asserters_reload: seconds between checks for a new file (30);
 *  - @c allow_anonymous_assertion: on lets listed asserters with
 *    types=anonymous assert an anonymous caller (default off).
 *
 *  A new file replaces the current list only if it verifies and its
 *  version is higher; otherwise the last good list stays.
 */
//=============================================================================

#ifndef TAO_SSLIOP_ASSERTER_LIST_H
#define TAO_SSLIOP_ASSERTER_LIST_H

#include /**/ "ace/pre.h"

#include "orbsvcs/SSLIOP/SSLIOP_Export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "tao/Versioned_Namespace.h"
#include "tao/orbconf.h"

#include "ace/Synch_Traits.h"
#include "ace/Thread_Mutex.h"

#include <ctime>
#include <memory>
#include <set>
#include <string>
#include <vector>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace SSLIOP
  {
    class TAO_SSLIOP_Export Asserter_List
    {
    public:
      struct Entry
      {
        std::string principal;
        unsigned long types = 0;          ///< CSI::ITT* bits
        std::set<std::string> realms;     ///< "@realm"; "*" any; empty: the service's
        bool capped = false;              ///< roles= given (R36)
        std::set<std::string> roles;      ///< the cap
      };

      struct Content
      {
        long version = 0;
        std::string issued;
        time_t issued_time = 0;
        std::vector<Entry> entries;
      };

      /// Parses asserter-list text.
      static bool parse (std::string const &text, Content &out, std::string &error);

      /// "name,dn" for CSI::ITT* bits.
      static std::string type_names (unsigned long types);

      /// The process-wide list, configured from the host's security.conf.
      static Asserter_List *instance ();

      /// True when security.conf names an asserter list.
      bool configured () const { return !this->path_.empty (); }

      /// Loads the list now (at startup); false with a reason.
      bool load (std::string &summary);

      /// The entry for the first of @a candidates on the list (refreshing
      /// first); false if none is listed or no list is loaded.
      bool find (std::vector<std::string> const &candidates, Entry &out);

      /// The current list's version (0: none loaded).
      long version () const;

    private:
      Asserter_List ();
      bool read (Content &out, std::string &error);
      void refresh ();

      std::string path_;
      std::string signer_path_;
      std::string signer_pin_;
      long reload_seconds_ = 30;

      mutable TAO_SYNCH_MUTEX lock_;
      std::shared_ptr<Content const> current_;
      time_t last_check_ = 0;
      std::string stamp_;
    };
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#include /**/ "ace/post.h"

#endif /* TAO_SSLIOP_ASSERTER_LIST_H */
