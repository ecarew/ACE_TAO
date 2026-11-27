// -*- C++ -*-

//=============================================================================
/**
 *  @file SSLIOP_GSSUP_Store.h
 *
 *  The default CSIv2 GSSUP verifier: a local file of scrypt password
 *  hashes, with guessing limits.
 *
 *  The file (security.conf @c gssup_store) has one line per user:
 *
 *  @code
 *    # comments and blank lines are ignored
 *    alice scrypt:15:8:1:SALT:HASH active
 *    bob   scrypt:15:8:1:SALT:HASH locked
 *    carol scrypt:15:8:1:SALT:HASH active groups=operators,auditors
 *  @endcode
 *
 *  scrypt:LOG2N:R:P:SALT:HASH gives the scrypt parameters (N = 2^LOG2N),
 *  a base64 salt and a base64 hash (OpenSSL 3 EVP_KDF "SCRYPT").  A
 *  user name is 1 to 64 of A-Z a-z 0-9 . _ - (no "@": the realm is the
 *  service's gssup_target).  "locked" is an administrator's lock.  The
 *  file is maintained with "ace-tao-setup user"; it is re-read when it
 *  changes.  groups= names the user's groups for the role map's
 *  group:NAME lines (Phase 3 T3; group names as role names).  In prod it must be mode 0600 (or 0400) and owned by the
 *  service's user, or it is refused.  A store that cannot be read or
 *  parsed refuses every login (fail closed); the reason is audited.
 *
 *  Guessing limits (R19), counted in memory per process:
 *
 *  - @c gssup_max_failures (10) failures for one user within
 *    @c gssup_failure_window seconds (900) lock that user for
 *    @c gssup_lockout seconds (1800);
 *  - @c gssup_source_max_failures (50) failures from one host within
 *    the window refuse that host's logins for @c gssup_lockout.
 *
 *  A locked user or limited host gets the same answer as a wrong
 *  password; only the audit record (GSSUP_LOCKED, GSSUP_RATE_LIMITED)
 *  differs.  An unknown user costs one scrypt like a known one, so the
 *  time taken does not tell whether the name exists.
 */
//=============================================================================

#ifndef TAO_SSLIOP_GSSUP_STORE_H
#define TAO_SSLIOP_GSSUP_STORE_H

#include /**/ "ace/pre.h"

#include "orbsvcs/SSLIOP/SSLIOP_Export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "orbsvcs/Security/GSSUP_Verifier.h"

#include "tao/Versioned_Namespace.h"
#include "tao/orbconf.h"

#include "ace/Synch_Traits.h"
#include "ace/Thread_Mutex.h"

#include <chrono>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace SSLIOP
  {
    class TAO_SSLIOP_Export GSSUP_Store : public TAO::Security::GSSUP_Verifier
    {
    public:
      /// scrypt cost.  The default (N = 2^15, r = 8, p = 1) takes 32 MiB
      /// and tens of milliseconds per login.
      struct Params
      {
        unsigned log2n = 15;
        unsigned r = 8;
        unsigned p = 1;
      };

      struct Entry
      {
        std::string user;
        Params params;
        std::string salt;   ///< raw bytes
        std::string hash;   ///< raw bytes
        bool locked = false;
        std::vector<std::string> groups;  ///< groups= (Phase 3 T3)
      };

      /// True for a group name (as a role name: a letter, then letters,
      /// digits, '-', '_', '.'; at most 64).
      static bool valid_group (std::string const &group);

      /// True for a name the store accepts (see the file format above).
      static bool valid_user (std::string const &user);

      /// Parses store text.  False with @a error (naming the line).
      static bool parse (std::string const &text, std::vector<Entry> &out, std::string &error);

      /// Store text for @a entries, with a header comment.
      static std::string format (std::vector<Entry> const &entries);

      /// A new entry for @a user: random salt, scrypt of @a password.
      static bool make_entry (std::string const &user,
                              std::string const &password,
                              Params const &params,
                              Entry &out,
                              std::string &error);

      /// True if @a password matches @a entry (constant-time compare).
      static bool matches (Entry const &entry, std::string const &password);

      /**
       * Checks that @a path may hold password hashes: in prod, mode 0600
       * or 0400 and owned by this process's user.  False with @a error.
       */
      static bool check_file (std::string const &path, bool prod, std::string &error);

      /// The process-wide store, configured from the host's security.conf.
      static GSSUP_Store *instance ();

      /// True when security.conf names a store.
      bool configured () const { return !this->path_.empty (); }

      /// The store file.
      std::string const &path () const { return this->path_; }

      /**
       * Loads the store now (at startup).  False with a reason if it is
       * unusable; @a summary describes a good store.
       */
      bool load (std::string &summary);

      Result verify (std::string const &user,
                     std::string const &password,
                     std::string const &target,
                     std::string const &source,
                     std::string &detail) override;

      /// The store line's groups= for @a user (none if unknown).
      std::vector<std::string> groups (std::string const &user) override;

      /// Forgets every failure and lock (tests).
      void reset_limits ();

    private:
      GSSUP_Store ();

      using Clock = std::chrono::steady_clock;

      /// Failures of one user or host within the window, and its lock.
      struct Track
      {
        std::deque<Clock::time_point> failures;
        Clock::time_point locked_until {};
      };

      /// Re-reads the file if it changed.  Called with lock_ held.
      void refresh_i (Clock::time_point now);

      /// Reads and parses the file into @a out; false with @a error.
      bool read (std::map<std::string, Entry> &out, std::string &error) const;

      /// Drops failures older than the window; true if @a t is locked.
      bool locked_i (Track &t, Clock::time_point now) const;

      /// Records a failure; true if it starts a lock.
      bool fail_i (Track &t, Clock::time_point now, unsigned max) const;

      /// Keeps the tracking maps bounded.  Called with lock_ held.
      void prune_i (Clock::time_point now);

      std::string path_;
      bool prod_ = false;
      unsigned max_failures_ = 10;
      unsigned source_max_failures_ = 50;
      std::chrono::seconds window_ {900};
      std::chrono::seconds lockout_ {1800};

      mutable TAO_SYNCH_MUTEX lock_;
      std::shared_ptr<std::map<std::string, Entry> const> users_;
      std::string load_error_;
      std::string stamp_;
      Clock::time_point last_check_ {};
      std::map<std::string, Track> by_user_;
      std::map<std::string, Track> by_source_;
    };
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#include /**/ "ace/post.h"

#endif /* TAO_SSLIOP_GSSUP_STORE_H */
