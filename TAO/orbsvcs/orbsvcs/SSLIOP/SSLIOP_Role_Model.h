// -*- C++ -*-

//=============================================================================
/**
 *  @file SSLIOP_Role_Model.h
 *
 *  The role model's decision (Phase 3 T2, D3 = C): a request is allowed
 *  when the caller's roles, in the target's domain, hold the rights its
 *  operation requires.  The three signed tables (SSLIOP_Policy_Tables.h)
 *  say so; their bodies are parsed here.
 *
 *  Required rights (table rights, R33): one line per interface and
 *  operation, the Security Service rights it needs (get, set, manage,
 *  use) and whether all of them or any one is needed (default all).
 *  "*" as the operation covers that interface's operations not listed;
 *  an operation covered by no line is refused in prod.  CORBA's built-in
 *  operations (_is_a, _non_existent, _interface, _repository_id) need get
 *  unless a line names them.
 *
 *  @code
 *    require IDL:omg.org/CosNaming/NamingContext:1.0  resolve  get
 *    require IDL:omg.org/CosNaming/NamingContext:1.0  bind     set
 *    require IDL:omg.org/CosNaming/NamingContext:1.0  destroy  manage
 *    require IDL:example/Ledger:1.0                   *        get,use any
 *    inherit IDL:omg.org/CosNaming/NamingContextExt:1.0 IDL:omg.org/CosNaming/NamingContext:1.0
 *  @endcode
 *
 *  Requests are matched on the target's most-derived interface; an
 *  "inherit DERIVED BASE" line lets DERIVED fall back to BASE's lines
 *  (exact operation first through the whole hierarchy, then "*").
 *
 *  Grants (table grants, R34): the rights each role holds.  Grants apply
 *  to the whole service (one domain per service, D3.1) until a "domain"
 *  line makes a POA subtree its own domain; the grants after it apply
 *  there, and only there.
 *
 *  @code
 *    grant reader    get
 *    grant publisher get,set
 *    grant ns-admin  get,set,manage,use
 *    domain /RootPOA/NameService/Admin
 *    grant ns-admin  get,set,manage,use
 *  @endcode
 *
 *  Role map (table roles, R35 to R37): who holds which roles.
 *
 *  @code
 *    role spiffe://ace-tao.test/portal      reader
 *    role alice@lab.test                    publisher
 *    role CN=legacy gateway,O=Example       reader
 *    group operators bob@lab.test
 *    group operators spiffe://ace-tao.test/ops-console
 *    role group:operators                   ns-admin  factors=tls+gssup
 *    role sid:S-1-5-21-1-2-3-1105           ns-admin
 *    sid  S-1-5-21-1-2-3-1105               AD.LAB.TEST\ns-admins
 *    role carol@lab.test                    publisher via=spiffe://ace-tao.test/portal
 *    role anonymous                         reader
 *  @endcode
 *
 *  "role WHO ROLE[,ROLE...] [via=ASSERTER] [factors=tls+gssup]": WHO is a
 *  principal (a SPIFFE ID, a certificate subject DN, user@realm or a
 *  Kerberos principal; a DN may hold blanks), "group:NAME", "sid:SID" or
 *  "anonymous".  The roles are the last word before the options.
 *
 *  - group:NAME matches a member named by "group NAME PRINCIPAL" lines
 *    (one member a line, the principal is the rest of the line), or a
 *    caller whose own GSSUP login has NAME in its store line's groups=.
 *  - sid:SID matches an AD group SID from the caller's verified Kerberos
 *    ticket (R30).  "sid SID NAME..." gives it a readable name for audit
 *    records and "roles test" (Q4).
 *  - anonymous matches only a caller with no identity (no certificate
 *    and no login), or an asserted anonymous caller (R37); no other line
 *    gives such a caller roles.
 *  - via=ASSERTER: only when ASSERTER asserted the caller's identity (via=*
 *    any listed asserter).  A line without via= also matches an asserted
 *    caller of that name; asserter caps (R36) bound what it can reach.
 *  - factors=tls+gssup: only when the caller itself proved a certificate
 *    and a GSSUP password on this request (never an asserted caller).
 *
 *  An asserted caller is matched by its asserted name only, and through
 *  role-map groups only: the ticket groups and store groups on the
 *  request belong to its asserter.  The certificate OU is never a role.
 */
//=============================================================================

#ifndef TAO_SSLIOP_ROLE_MODEL_H
#define TAO_SSLIOP_ROLE_MODEL_H

#include /**/ "ace/pre.h"

#include "orbsvcs/SSLIOP/SSLIOP_Export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "orbsvcs/SSLIOP/SSLIOP_Policy_Tables.h"
#include "orbsvcs/Security/Caller.h"
#include "tao/Versioned_Namespace.h"
#include "tao/orbconf.h"
#include "ace/Synch_Traits.h"
#include "ace/Thread_Mutex.h"

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
    namespace Role_Model
    {
      /// The Security Service rights (family "corba").
      enum Right : unsigned
      {
        RIGHT_GET = 1,
        RIGHT_SET = 2,
        RIGHT_MANAGE = 4,
        RIGHT_USE = 8
      };

      /// Parses "get,set,..." into a set of Right bits; false if a name is unknown.
      TAO_SSLIOP_Export bool parse_rights (std::string const &text, unsigned &rights);

      /// "get,set,..." for a set of Right bits ("none" for 0).
      TAO_SSLIOP_Export std::string rights_text (unsigned rights);

      /// What an operation requires.
      struct Requirement
      {
        unsigned rights = 0;
        bool any = false;       ///< any one right suffices (else all)
        unsigned line = 0;      ///< where the table says so (0: built-in default)
      };

      struct Rights_Table
      {
        long version = 0;
        /// (interface, operation) and (interface, "*").
        std::map<std::pair<std::string, std::string>, Requirement> ops;
        /// Interface -> the interfaces it inherits from ("inherit" lines).
        std::map<std::string, std::vector<std::string>> bases;
      };

      /**
       * The requirement for (interface, operation): an exact line for the
       * interface or any interface it inherits from, else a "*" line
       * likewise, else get for a built-in operation.  False if nothing
       * covers it.
       */
      TAO_SSLIOP_Export bool lookup (Rights_Table const &rights,
                                     std::string const &interface_id,
                                     std::string const &operation,
                                     Requirement &out);

      struct Grants_Table
      {
        long version = 0;
        /// The service domain: role -> rights.
        std::map<std::string, unsigned> service;
        /// POA domains, by POA path ("/RootPOA/NameService/Admin").
        std::map<std::string, std::map<std::string, unsigned>> poas;
      };

      /// One "role" line.
      struct Role_Line
      {
        std::set<std::string> roles;
        std::string via;          ///< asserter required ("*": any); empty: none
        bool two_factor = false;  ///< factors=tls+gssup
        /// maxage=DURATION in seconds (0: none): held only by a caller
        /// who logged in that recently, with Kerberos (the ticket's
        /// authtime) or with GSSUP on the request; never on a certificate
        /// alone or by an asserted caller.
        long max_age = 0;
        unsigned line = 0;
      };

      struct Role_Map
      {
        long version = 0;
        /// Principal, "group:NAME", "sid:SID" or "anonymous" -> its lines.
        std::map<std::string, std::vector<Role_Line>> by_key;
        /// Role-map group -> members.
        std::map<std::string, std::set<std::string>> members;
        /// SID -> readable name.
        std::map<std::string, std::string> sid_names;
      };

      /**
       * Checks and parses a table's body (the loader's syntax check:
       * a table that fails is refused like a bad signature).  False with
       * @a error ("line N: ...").
       */
      TAO_SSLIOP_Export bool check_body (Policy_Tables::Table const &table, std::string &error);

      TAO_SSLIOP_Export bool parse (Policy_Tables::Table const &table, Rights_Table &out, std::string &error);
      TAO_SSLIOP_Export bool parse (Policy_Tables::Table const &table, Grants_Table &out, std::string &error);
      TAO_SSLIOP_Export bool parse (Policy_Tables::Table const &table, Role_Map &out, std::string &error);

      /// True for CORBA's built-in operations that need get by default.
      TAO_SSLIOP_Export bool builtin_operation (std::string const &operation);

      /// A decision and its grounds, for the audit record.
      struct Decision
      {
        bool allowed = false;
        std::string why;              ///< one line for the record
        std::set<std::string> roles;  ///< roles held
        /// What gave them: the role-map keys matched ("group:operators",
        /// "sid:S-1-...(AD.LAB.TEST\ns-admins)", "anonymous", a principal).
        std::vector<std::string> sources;
        /// Roles the asserter's cap removed (R36).
        std::set<std::string> capped;
        Requirement required;
        bool listed = false;          ///< a rights line (or the built-in default) covers the operation
        std::string domain;           ///< "service" or the POA domain
        unsigned held = 0;            ///< rights the roles hold in the domain
      };

      /**
       * Decides one request from parsed tables.  @a interface_id is the
       * target's most-derived repository ID; @a object_path is "/" + POA
       * names + "/" + object id.  An operation no line covers is allowed
       * only when @a unlisted_allowed (test mode with access_default =
       * allow); prod passes false.  @a cap, for an asserted caller whose
       * asserter-list entry has roles=, is the roles it may reach (R36).
       */
      TAO_SSLIOP_Export Decision decide (Rights_Table const &rights,
                                         Grants_Table const &grants,
                                         Role_Map const &roles,
                                         TAO::Security::Caller const &caller,
                                         std::string const &interface_id,
                                         std::string const &object_path,
                                         std::string const &operation,
                                         bool unlisted_allowed,
                                         std::set<std::string> const *cap = nullptr);

      /**
       * The caller's roles from the role map alone (R35 to R37), with the
       * keys that gave them in @a sources.
       */
      TAO_SSLIOP_Export std::set<std::string> roles_of (Role_Map const &roles,
                                                        TAO::Security::Caller const &caller,
                                                        std::vector<std::string> *sources = nullptr);

      /**
       * @class Engine
       *
       * The process-wide decision: the tables in force (Policy_Tables),
       * parsed once per version, plus RequiredRights changes made in test
       * mode (R41).
       */
      class TAO_SSLIOP_Export Engine
      {
      public:
        static Engine *instance ();

        /// True when the role model is configured (roles_dir).
        bool active () const;

        /**
         * Decides a request with the tables in force.  If a table is
         * missing, refuses with that reason.  @a versions gets
         * "rights vN, grants vN, roles vN".
         */
        Decision decide (TAO::Security::Caller const &caller,
                         std::string const &interface_id,
                         std::string const &object_path,
                         std::string const &operation,
                         std::string &versions);

        /// The requirement for (interface, operation), with test-mode
        /// overrides applied; false if nothing covers it.
        bool required (std::string const &interface_id, std::string const &operation, Requirement &out);

        /// Test mode only (R41): changes the in-memory requirement.
        void override_required (std::string const &interface_id, std::string const &operation,
                                Requirement const &r);

      private:
        Engine () = default;

        /// Reparses tables whose version changed; false if one is missing.
        bool current (std::shared_ptr<Rights_Table const> &r,
                      std::shared_ptr<Grants_Table const> &g,
                      std::shared_ptr<Role_Map const> &m,
                      std::string &why);

        mutable TAO_SYNCH_MUTEX lock_;
        std::shared_ptr<Policy_Tables::Table const> raw_[Policy_Tables::KIND_COUNT];
        std::shared_ptr<Rights_Table const> rights_;
        std::shared_ptr<Grants_Table const> grants_;
        std::shared_ptr<Role_Map const> roles_;
        std::map<std::pair<std::string, std::string>, Requirement> overrides_;
      };
    }
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#include /**/ "ace/post.h"

#endif /* TAO_SSLIOP_ROLE_MODEL_H */
