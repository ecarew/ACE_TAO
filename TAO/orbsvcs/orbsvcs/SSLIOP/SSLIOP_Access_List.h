// -*- C++ -*-

//=============================================================================
/**
 *  @file SSLIOP_Access_List.h
 *
 *  Signed list of which callers may reach which objects.
 *
 *  The interim rights table of the Phase 2 specification (R25): until a
 *  rights model is chosen, each rule names a principal, an object and
 *  optionally operations.  The file
 *
 *  @code
 *    # comments and blank lines are ignored
 *    version 3
 *    issued 2026-11-24T12:00:00Z
 *    allow spiffe://ace-tao.test/admin    *
 *    allow spiffe://ace-tao.test/sweeper  /RootPOA/NameService*   resolve list
 *    deny  spiffe://ace-tao.test/sweeper  /RootPOA/NameService*   destroy
 *    allow *                              /RootPOA/Status/info
 *  @endcode
 *
 *  - principal: the caller's effective principal exactly (a SPIFFE ID,
 *    a certificate subject DN in RFC 2253 form, later user@realm), or
 *    @c * for any identified caller;
 *  - object: "/" + POA names + "/" + object id, exactly, or a prefix
 *    ending in @c *, or @c * alone for every object;
 *  - operations: none means all;
 *  - via=ASSERTER after the object: the rule matches only a caller whose
 *    identity ASSERTER asserted (CSIv2 identity assertion), or any
 *    asserted caller with via=*.
 *
 *  @code
 *    allow alice@lab.test /RootPOA/Ledger/accounts read via=spiffe://ace-tao.test/portal
 *  @endcode
 *
 *  A matching deny wins over any allow; a request no rule matches gets
 *  the default (access_default; always deny in prod).  The file sits
 *  next to FILE.sig like the deny-list (SSLIOP_Signed_File.h).
 *  security.conf keys:
 *
 *  - @c access_list: the file;
 *  - @c access_list_signer: signer's PEM public key or certificate
 *    (default: denylist_signer);
 *  - @c access_list_signer_sha256: pinned SPKI SHA-256 of the signer
 *    (default: denylist_signer_sha256; required in prod);
 *  - @c access_list_reload: seconds between checks for a new file (30);
 *  - @c access_default: allow or deny for a request no rule covers
 *    (allow; prod refuses anything but deny).
 */
//=============================================================================

#ifndef TAO_SSLIOP_ACCESS_LIST_H
#define TAO_SSLIOP_ACCESS_LIST_H

#include /**/ "ace/pre.h"

#include "orbsvcs/SSLIOP/SSLIOP_Export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "orbsvcs/Security/Caller.h"
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
    class TAO_SSLIOP_Export Access_List : public TAO::Security::Caller_Policy
    {
    public:
      struct Rule
      {
        bool allow = true;
        std::string principal;           ///< "*" for any identified caller
        std::string object;              ///< without the trailing '*' when prefix
        bool prefix = false;
        std::set<std::string> operations;  ///< empty: all
        std::string via;                 ///< required asserter; "*" any; empty: none required
      };

      struct Content
      {
        long version = 0;
        std::string issued;
        time_t issued_time = 0;
        std::vector<Rule> rules;
      };

      /// Parses access-list text.
      static bool parse (std::string const &text, Content &out, std::string &error);

      /// What @a rules say about the request (no I/O, for tests too).
      static Result evaluate (Content const &rules,
                              TAO::Security::Caller const &caller,
                              char const *object_path,
                              char const *operation);

      /// The process-wide list, configured from the host's security.conf.
      static Access_List *instance ();

      /// True when security.conf names an access list.
      bool configured () const;

      /// Loads the list now (at startup); false with a reason.
      bool load (std::string &summary);

      /// Re-reads the file if it changed and the reload interval passed.
      void refresh ();

      /// The current list's version (0: none loaded).
      long version () const;

      /// Caller_Policy: refreshes, then evaluates the current list.
      Result decide (TAO::Security::Caller const &caller,
                     char const *object_path,
                     char const *operation) override;

    private:
      Access_List ();

      bool read (Content &out, std::string &error);

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

#endif /* TAO_SSLIOP_ACCESS_LIST_H */
