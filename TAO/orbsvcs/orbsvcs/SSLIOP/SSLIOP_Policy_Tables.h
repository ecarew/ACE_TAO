// -*- C++ -*-

//=============================================================================
/**
 *  @file SSLIOP_Policy_Tables.h
 *
 *  The signed policy tables of the role model (Phase 3 T1, R39): one
 *  loader for the required-rights, grants and role-map tables.  Each
 *  table is a dated file in one directory with a detached signature
 *  beside it:
 *
 *  @code
 *    rights-2026-11-26.txt     rights-2026-11-26.txt.sig
 *    rights-2026-11-26.2.txt   (a second revision the same day)
 *    grants-2026-11-20.txt     roles-2026-11-25.txt   ...
 *  @endcode
 *
 *  A table starts with three signed header lines, then its body (read by
 *  the table's own parser, T2 and T3):
 *
 *  @code
 *    table rights
 *    version 7
 *    issued 2026-11-26T14:00:00Z
 *  @endcode
 *
 *  security.conf keys:
 *  - @c roles_dir: the directory (the role model is off without it);
 *  - @c roles_signer: PEM public key or certificate of the roles signer;
 *  - @c roles_signer_sha256: its pinned SPKI SHA-256 (required in prod),
 *    a key distinct from the deny-list signer (D3.7);
 *  - @c roles_reload: seconds between checks for new files (30);
 *  - @c roles_state: a file recording the highest version accepted for
 *    each table, so a restart cannot roll a table back.
 *
 *  For each table the winner is the file with the highest version among
 *  those that verify with the pinned signer, whose header names that
 *  table, and whose signed issued date equals the date in its name (an
 *  older file renamed to look newer is refused).  A version below the
 *  recorded high-water mark is refused.  A reload takes a new winner
 *  only if its version is higher than the table in force; otherwise the
 *  last good table stays, and the refusal is audited once per file.
 */
//=============================================================================

#ifndef TAO_SSLIOP_POLICY_TABLES_H
#define TAO_SSLIOP_POLICY_TABLES_H

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
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace SSLIOP
  {
    class TAO_SSLIOP_Export Policy_Tables
    {
    public:
      /// The three tables.
      enum Kind
      {
        RIGHTS,    ///< required rights per operation (R33)
        GRANTS,    ///< rights per role, per domain (R34)
        ROLES,     ///< principals and groups to roles (R35)
        KIND_COUNT
      };

      /// "rights", "grants" or "roles": the file prefix and the header.
      static char const *kind_name (Kind k);

      /// A verified, accepted table.
      struct Table
      {
        Kind kind = RIGHTS;
        long version = 0;
        std::string issued;
        time_t issued_time = 0;
        std::string file;        ///< its path
        /// The body: (line number, text) of every line after the header
        /// that is not blank or a comment.
        std::vector<std::pair<unsigned, std::string>> lines;
      };

      /// A file in the directory and what became of it.
      struct Candidate
      {
        std::string file;        ///< its path
        std::string date;        ///< YYYY-MM-DD from its name
        unsigned revision = 1;   ///< 1, or N from NAME-DATE.N.txt
        long version = 0;        ///< from its header, if it parsed
        bool accepted = false;   ///< the winner
        std::string why;         ///< why it was refused
      };

      /**
       * Splits a file name (no directory) "KIND-YYYY-MM-DD.txt" or
       * "KIND-YYYY-MM-DD.N.txt" (N from 2 to 999).  False for any other
       * name, including the .sig files.
       */
      static bool parse_name (std::string const &name, Kind &kind, std::string &date, unsigned &revision);

      /// The file name for a table of @a kind dated @a date, revision @a revision.
      static std::string file_name (Kind kind, std::string const &date, unsigned revision);

      /**
       * Parses a table's text: the header (table, version, issued, in
       * that order before any other line) and the body lines.  False with
       * @a error if the header is missing or malformed.
       */
      static bool parse (std::string const &text, Table &out, std::string &error);

      /// The candidates for @a kind in @a dir, newest name first.
      static std::vector<Candidate> list (std::string const &dir, Kind kind);

      /**
       * Chooses the table for @a kind among @a cands (from list()): the
       * highest version among files that verify with @a signer (pinned to
       * @a pin if not empty), name their own kind, whose body parses
       * (Role_Model::check_body), carry a signed issued date equal to
       * their name's, and are not below @a floor.  Fills
       * each candidate's version, accepted and why; @a out gets the
       * winner.  False if none qualifies.
       */
      static bool choose (Kind kind,
                          std::vector<Candidate> &cands,
                          std::string const &signer,
                          std::string const &pin,
                          long floor,
                          Table &out);

      /// Reads a roles_state file: "KIND VERSION" lines.
      static std::map<std::string, long> read_state (std::string const &path);

      /// The process-wide tables, configured from the host's security.conf.
      static Policy_Tables *instance ();

      /// True when security.conf names a roles_dir.
      bool configured () const;

      std::string const &dir () const { return this->dir_; }
      std::string const &signer () const { return this->signer_path_; }
      std::string const &pin () const { return this->signer_pin_; }
      std::string const &state_path () const { return this->state_path_; }

      /**
       * Loads every table now (at startup).  False with @a error naming
       * each table that has no acceptable file; @a summary lists the
       * tables loaded ("rights v7, grants v3, roles v5").
       */
      bool load (std::string &summary, std::string &error);

      /// Re-reads the directory if the reload interval passed and a file changed.
      void refresh ();

      /// The table in force for @a kind, or null.
      std::shared_ptr<Table const> table (Kind kind) const;

      /// Its version (0: none).
      long version (Kind kind) const;

    private:
      Policy_Tables ();

      /// Loads or reloads one table; false with @a error if nothing acceptable.
      bool update (Kind kind, bool startup, std::string &error);

      /// Records @a version as the high-water mark of @a kind.
      void save_state (Kind kind, long version);

      /// Names, sizes and times of every table file, to see a change.
      std::string stamp () const;

      std::string dir_;
      std::string signer_path_;
      std::string signer_pin_;
      std::string state_path_;
      long reload_seconds_ = 30;

      mutable TAO_SYNCH_MUTEX lock_;
      std::shared_ptr<Table const> tables_[KIND_COUNT];
      time_t last_check_ = 0;
      std::string stamp_;
      /// Refusals already audited, by file and its stamp.
      std::set<std::string> reported_;
    };
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#include /**/ "ace/post.h"

#endif /* TAO_SSLIOP_POLICY_TABLES_H */
