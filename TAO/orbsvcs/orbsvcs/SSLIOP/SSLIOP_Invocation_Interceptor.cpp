#include "orbsvcs/Log_Macros.h"
#include "orbsvcs/SSLIOP/SSLIOP_Invocation_Interceptor.h"
#include "orbsvcs/SSLIOP/SSLIOP_Policy_Tables.h"
#include "orbsvcs/SSLIOP/SSLIOP_Role_Model.h"
#include "orbsvcs/SSLIOP/SSLIOP_Required_Rights.h"
#include "orbsvcs/SSLIOP/SSLIOP_Current.h"
#include "orbsvcs/SSLIOP/SSLIOP_Deny_List.h"
#include "orbsvcs/SSLIOP/SSLIOP_Access_List.h"
#include "orbsvcs/SSLIOP/SSLIOP_SAS.h"
#include "orbsvcs/Security/Caller.h"
#include "orbsvcs/Security/SL2_SecurityManager.h"
#include "orbsvcs/Security/Audit_Logger.h"

#include <openssl/x509.h>

#include "orbsvcs/SecurityLevel2C.h"

#include "tao/ORB_Constants.h"
#include "tao/PortableServer/PS_CurrentC.h"
#include "tao/PortableServer/POAC.h"
#include "tao/debug.h"
#include "tao/Security_Mode.h"

#include <cctype>
#include <memory>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

TAO::SSLIOP::Server_Invocation_Interceptor::Server_Invocation_Interceptor (
  PortableInterceptor::ORBInitInfo_ptr info,
  ::Security::QOP default_qop,
  size_t tss_slot,
  bool collocated)
  : qop_ (default_qop),
    collocated_ (collocated)
{
  /*
   * Cache references to the "Current" objects that we'll need during
   * during invocations.
   */
  CORBA::Object_var obj =
    info->resolve_initial_references ("SSLIOPCurrent");

  this->ssliop_current_ = ::SSLIOP::Current::_narrow (obj.in ());

  if (!CORBA::is_nil (this->ssliop_current_.in ()))
    {
      TAO::SSLIOP::Current *tao_current =
        dynamic_cast<TAO::SSLIOP::Current *> (this->ssliop_current_.in ());

      if (tao_current != nullptr)
        {
          if (TAO_debug_level > 3)
            ORBSVCS_DEBUG ((LM_DEBUG, "TAO (%P|%t) SSLIOP_Invocation_Interceptor::CTOR--setting up SSLIOP Current with slot %d\n", tss_slot));
          tao_current->tss_slot (tss_slot);
        }
      else
        throw CORBA::INTERNAL ();
    }

  obj = info->resolve_initial_references ("SecurityLevel2:SecurityManager");
  this->sec2manager_ = SecurityLevel2::SecurityManager::_narrow (obj.in ());

  // Identified (TLS) callers are decided by the signed access list when
  // one is configured.  A request no rule covers is refused in prod and
  // otherwise gets access_default (allow unless set to deny).
  TAO_Security_Mode::Host_Config const &host = TAO_Security_Mode::host ();
  bool const prod = host.mode == TAO_Security_Mode::MODE_PROD;
  this->audit_grants_ = host.get ("audit_grants") == "on";
  if (!CORBA::is_nil (this->sec2manager_.in ()))
    {
      SecurityLevel2::AccessDecision_var ad = this->sec2manager_->access_decision ();
      TAO::Security::AccessDecision *const tao_ad = dynamic_cast<TAO::Security::AccessDecision *> (ad.in ());
      if (tao_ad != nullptr)
        {
          tao_ad->default_caller_decision (!prod && host.get ("access_default", "allow") != "deny");
          if (TAO::SSLIOP::Access_List::instance ()->configured ())
            tao_ad->caller_policy (TAO::SSLIOP::Access_List::instance ());
        }
      // SecurityLevel2 RequiredRights from the signed required-rights
      // table, when the role model is configured (Phase 3 T2, R41).
      TAO::Security::SecurityManager *const sm =
        dynamic_cast<TAO::Security::SecurityManager *> (this->sec2manager_.in ());
      if (sm != nullptr && TAO::SSLIOP::Role_Model::Engine::instance ()->active ())
        {
          SecurityLevel2::RequiredRights_var rr;
          ACE_NEW_THROW_EX (rr, TAO::SSLIOP::Required_Rights, CORBA::NO_MEMORY ());
          sm->required_rights (rr.in ());
        }
    }
}

namespace
{
  /// "/" + POA names + "/" + object id, the object id as text when it
  /// is printable and as hex otherwise.
  std::string
  object_path_of (PortableInterceptor::ServerRequestInfo_ptr ri)
  {
    std::string path;
    try
      {
        PortableInterceptor::AdapterName_var names = ri->adapter_name ();
        for (CORBA::ULong i = 0; i < names->length (); ++i)
          path += std::string ("/") + names[i].in ();
      }
    catch (CORBA::Exception const &)
      {
      }
    CORBA::OctetSeq_var oid = ri->object_id ();
    bool printable = oid->length () > 0;
    for (CORBA::ULong i = 0; printable && i < oid->length (); ++i)
      printable = ::isprint (oid[i]) != 0 && oid[i] != '/';
    path += "/";
    static char const hex[] = "0123456789abcdef";
    for (CORBA::ULong i = 0; i < oid->length (); ++i)
      {
        if (printable)
          path += static_cast<char> (oid[i]);
        else
          {
            path += hex[oid[i] >> 4];
            path += hex[oid[i] & 0xF];
          }
      }
    return path;
  }
}

TAO::SSLIOP::Server_Invocation_Interceptor::~Server_Invocation_Interceptor ()
{
}

char *
TAO::SSLIOP::Server_Invocation_Interceptor::name ()
{
  if (this->collocated_)
    return CORBA::string_dup ("TAO::SSLIOP::Server_Invocation_Interceptor::Collocated");
  else
    return CORBA::string_dup ("TAO::SSLIOP::Server_Invocation_Interceptor::Remote");
}

void
TAO::SSLIOP::Server_Invocation_Interceptor::destroy ()
{
}

void
TAO::SSLIOP::Server_Invocation_Interceptor::receive_request_service_contexts (
                                              PortableInterceptor::ServerRequestInfo_ptr /*ri*/)
{
}

void
TAO::SSLIOP::Server_Invocation_Interceptor::receive_request (
    PortableInterceptor::ServerRequestInfo_ptr ri)
{
  SecurityLevel2::AccessDecision_var ad_tmp =
    this->sec2manager_->access_decision ();
  TAO::SL2::AccessDecision_var ad =
    TAO::SL2::AccessDecision::_narrow (ad_tmp.in ());

  CORBA::Boolean const no_ssl =
    this->ssliop_current_->no_context ();

  if (TAO_debug_level >= 3)
    ORBSVCS_DEBUG ((LM_DEBUG, "SSLIOP (%P|%t) Interceptor (context), ssl=%d collocated=%d\n", !(no_ssl), this->collocated_));

  // Pick up newly signed policy tables (Phase 3 T1); a cheap check
  // between reload intervals.
  TAO::SSLIOP::Policy_Tables::instance ()->refresh ();

  // The deny-list is checked on every request too, so a certificate
  // listed after its connection was made is refused from then on.
  TAO::SSLIOP::Deny_List *const deny = TAO::SSLIOP::Deny_List::instance ();
  if (!no_ssl && !this->collocated_ && deny->configured ())
    {
      ::SSLIOP::ASN_1_Cert_var der = this->ssliop_current_->get_peer_certificate ();
      unsigned char const *p = der->get_buffer ();
      X509 *const peer = der->length () > 0 ? ::d2i_X509 (nullptr, &p, static_cast<long> (der->length ())) : nullptr;
      std::string const hit = deny->check (peer);
      if (!hit.empty ())
        {
          char subject[256] = "";
          ::X509_NAME_oneline (::X509_get_subject_name (peer), subject, sizeof subject);
          CORBA::String_var op = ri->operation ();
          TAO::Security::Audit_Logger::instance ()->write (
            TAO::Security::Audit_Record ("authz", false, TAO::Security::Audit_Reason::CERT_DENYLISTED)
              .field ("subject", subject)
              .field ("cert_serial", TAO::SSLIOP::Deny_List::serial_of (peer))
              .field ("denylist_entry", hit)
              .field ("op", op.in ()));
          ::X509_free (peer);
          throw CORBA::NO_PERMISSION ();
        }
      ::X509_free (peer);
    }

  // An identified (TLS) caller: build its record, give it to the
  // servant through SecurityCurrent and decide the request on it.
  if (!no_ssl && !this->collocated_)
    {
      TAO::SSLIOP::Current *const tao_current =
        dynamic_cast<TAO::SSLIOP::Current *> (this->ssliop_current_.in ());
      TAO::SSLIOP::Current_Impl *const impl = tao_current != nullptr ? tao_current->request_impl () : nullptr;
      if (impl != nullptr)
        {
          CORBA::String_var op = ri->operation ();

          // The CSIv2 SAS layer (R16: after TLS and the deny-list, before
          // the decision) may add an authenticated (GSSUP) principal, or
          // refuse the request.
          TAO::Security::Caller record = impl->make_caller ();
          TAO::SSLIOP::SAS_Target::process (ri, record, true, op.in (), impl->ssl ());

          // The deny-list's principals and SIDs: every name the request
          // carries (authenticated, asserted, asserter) and the account
          // and group SIDs of its verified ticket.  An AD account that is
          // disabled keeps its tickets until they expire; this stops it
          // within denylist_reload.
          if (deny->configured ())
            {
              std::vector<std::string> sids = record.groups;
              if (!record.user_sid.empty ())
                sids.push_back (record.user_sid);
              std::string const hit = deny->check_names (record.principals (), sids);
              if (!hit.empty ())
                {
                  TAO::Security::Audit_Record rec ("authz", false, TAO::Security::Audit_Reason::PRINCIPAL_DENYLISTED);
                  rec.field ("principal", record.effective ());
                  if (!record.asserter.empty ())
                    rec.field ("asserter", record.asserter);
                  rec.field ("subject", record.subject)
                    .field ("src", record.source)
                    .field ("denylist_entry", hit)
                    .field ("op", op.in ());
                  TAO::Security::Audit_Logger::instance ()->write (rec);
                  throw CORBA::NO_PERMISSION ();
                }
            }

          auto caller = std::make_shared<TAO::Security::Caller const> (std::move (record));
          impl->caller (caller);

          std::string const path = object_path_of (ri);

          SecurityLevel2::CredentialsList cred_list (1);
          cred_list.length (1);
          cred_list[0] = new TAO::Security::Caller_Credentials (*caller, caller->authenticated.empty () ? "TLS" : "TLS+GSSUP");
          // The role model (Phase 3 T2, R38) when roles_dir is set: the
          // interim list's explicit denies first, then the three tables.
          // Otherwise the interim access list decides (Phase 2 R25).
          TAO::SSLIOP::Role_Model::Engine *const engine = TAO::SSLIOP::Role_Model::Engine::instance ();
          bool const role_model = engine->active ();
          TAO::SSLIOP::Role_Model::Decision rd;
          std::string versions;
          std::string interface_id;
          bool acl_denied = false;
          long acl_version = 0;
          CORBA::Boolean allowed = false;
          if (role_model)
            {
              try
                {
                  CORBA::String_var rid = ri->target_most_derived_interface ();
                  interface_id = rid.in ();
                }
              catch (CORBA::Exception const &)
                {
                  // Unknown interface: no rights line covers it.
                }
              TAO::SSLIOP::Access_List *const acl = TAO::SSLIOP::Access_List::instance ();
              if (acl->configured () && acl->denies (*caller, path.c_str (), op.in (), acl_version))
                acl_denied = true;
              else
                {
                  rd = engine->decide (*caller, interface_id, path, op.in (), versions);
                  allowed = rd.allowed;
                }
            }
          else
            allowed = CORBA::is_nil (ad.in ()) ? false : ad->access_allowed_caller (cred_list, path.c_str (), op.in ());

          if (TAO_debug_level >= 3)
            ORBSVCS_DEBUG ((LM_DEBUG, "SSLIOP (%P|%t) caller %C %C %C -> %C\n",
                            caller->effective ().c_str (), path.c_str (), op.in (),
                            allowed ? "allowed" : "denied"));

          if (!allowed || this->audit_grants_)
            {
              TAO::Security::Audit_Record rec ("authz", allowed != 0,
                                               allowed ? TAO::Security::Audit_Reason::ACCESS_GRANTED
                                                       : TAO::Security::Audit_Reason::ACCESS_DENIED);
              rec.field ("principal", caller->effective ());
              // R24: an asserted caller's record names who vouched for it.
              if (!caller->asserter.empty ())
                rec.field ("asserter", caller->asserter);
              rec.field ("subject", caller->subject)
                .field ("cert_serial", caller->serial)
                .field ("src", caller->source)
                .field ("object", path)
                .field ("op", op.in ());
              if (role_model)
                {
                  // R38: the roles held, the rights required, the tables used.
                  std::string held;
                  for (std::string const &role : rd.roles)
                    held += (held.empty () ? "" : ",") + role;
                  rec.field ("interface", interface_id);
                  if (acl_denied)
                    rec.field ("access_list_version", std::to_string (acl_version))
                      .text ("an explicit deny rule in the access list");
                  else
                    {
                      rec.field ("roles", held.empty () ? std::string ("(none)") : held)
                        .field ("rights_required",
                                rd.listed ? (rd.required.any ? "any:" : "") + TAO::SSLIOP::Role_Model::rights_text (rd.required.rights)
                                          : std::string ("(unlisted)"))
                        .field ("domain", rd.domain)
                        .field ("tables", versions);
                      // T3: which role-map lines gave the roles, and what
                      // an asserter's cap took away (R36).
                      std::string from, capped;
                      for (std::string const &s : rd.sources)
                        from += (from.empty () ? "" : ";") + s;
                      for (std::string const &s : rd.capped)
                        capped += (capped.empty () ? "" : ",") + s;
                      if (!from.empty ())
                        rec.field ("roles_from", from);
                      if (!capped.empty ())
                        rec.field ("roles_capped", capped);
                      rec.text (rd.why.c_str ());
                    }
                }
              else
                {
                  long const v = TAO::SSLIOP::Access_List::instance ()->version ();
                  if (v > 0)
                    rec.field ("access_list_version", std::to_string (v));
                }
              TAO::Security::Audit_Logger::instance ()->write (rec);
            }
          if (!allowed)
            throw CORBA::NO_PERMISSION ();
        }
      else
        {
          // A TLS session without its TSS state: refuse rather than let
          // the request through undecided.
          throw CORBA::NO_PERMISSION ();
        }
    }

  // if
  // (1) no SSL session state is available (which means that the
  //     invocation is received across a non-SSL transport)
  // AND
  // (2) the required Quality of Protection is something other
  //     than SecQOPNoProtection (set via -SSLNoProtection)
  // A SAS context over a plain transport is refused (GSSUP passwords
  // only travel inside TLS); csiv2 = required refuses a plain request
  // without one too.
  if (no_ssl && !this->collocated_)
    {
      CORBA::String_var op = ri->operation ();
      TAO::Security::Caller plain;
      TAO::SSLIOP::SAS_Target::process (ri, plain, false, op.in ());
    }

  if (no_ssl && this->qop_ != ::Security::SecQOPNoProtection)
    {
      /*
       * Set up all the arguments needed by the call
       * to AccessDecision::access_allowed()
       */

      // No TLS session, so no identified caller: the decision is the
      // per-object insecure-access flag (add_object) or its default.
      SecurityLevel2::CredentialsList cred_list;
      /* Gather the elements that uniquely identify the target object */
      CORBA::ORBid_var orb_id = ri->orb_id ();
      CORBA::OctetSeq_var adapter_id = ri->adapter_id ();
      CORBA::OctetSeq_var object_id = ri->object_id ();
      CORBA::String_var operation_name = ri->operation ();

      CORBA::Boolean const it_should_happen =
        ad->access_allowed_ex (orb_id.in (),
                               adapter_id.in (),
                               object_id.in (),
                               cred_list,
                               operation_name.in(),
                               this->collocated_);

      if (TAO_debug_level >= 3)
        {
          ORBSVCS_DEBUG ((LM_DEBUG,
            "TAO (%P|%t) SL2::access_allowed_ex returned %C\n",
            it_should_happen ? "true" : "false"));
        }

      if (! it_should_happen)
        throw CORBA::NO_PERMISSION ();
    }
}

void
TAO::SSLIOP::Server_Invocation_Interceptor::send_reply (
    PortableInterceptor::ServerRequestInfo_ptr /* ri */)
{
}

void
TAO::SSLIOP::Server_Invocation_Interceptor::send_exception (
    PortableInterceptor::ServerRequestInfo_ptr /* ri */)
{
}

void
TAO::SSLIOP::Server_Invocation_Interceptor::send_other (
    PortableInterceptor::ServerRequestInfo_ptr /* ri */)
{
}

TAO_END_VERSIONED_NAMESPACE_DECL
