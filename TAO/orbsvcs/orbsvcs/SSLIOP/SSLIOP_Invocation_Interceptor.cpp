#include "orbsvcs/Log_Macros.h"
#include "orbsvcs/SSLIOP/SSLIOP_Invocation_Interceptor.h"
#include "orbsvcs/SSLIOP/SSLIOP_Current.h"
#include "orbsvcs/SSLIOP/SSLIOP_Deny_List.h"
#include "orbsvcs/SSLIOP/SSLIOP_Access_List.h"
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
          auto caller = std::make_shared<TAO::Security::Caller const> (impl->make_caller ());
          impl->caller (caller);

          std::string const path = object_path_of (ri);
          CORBA::String_var op = ri->operation ();

          SecurityLevel2::CredentialsList cred_list (1);
          cred_list.length (1);
          cred_list[0] = new TAO::Security::Caller_Credentials (*caller, "TLS");
          CORBA::Boolean const allowed =
            CORBA::is_nil (ad.in ()) ? false : ad->access_allowed_caller (cred_list, path.c_str (), op.in ());

          if (TAO_debug_level >= 3)
            ORBSVCS_DEBUG ((LM_DEBUG, "SSLIOP (%P|%t) caller %C %C %C -> %C\n",
                            caller->effective ().c_str (), path.c_str (), op.in (),
                            allowed ? "allowed" : "denied"));

          if (!allowed || this->audit_grants_)
            {
              TAO::Security::Audit_Record rec ("authz", allowed != 0,
                                               allowed ? TAO::Security::Audit_Reason::ACCESS_GRANTED
                                                       : TAO::Security::Audit_Reason::ACCESS_DENIED);
              rec.field ("principal", caller->effective ())
                .field ("subject", caller->subject)
                .field ("cert_serial", caller->serial)
                .field ("src", caller->source)
                .field ("object", path)
                .field ("op", op.in ());
              long const v = TAO::SSLIOP::Access_List::instance ()->version ();
              if (v > 0)
                rec.field ("access_list_version", std::to_string (v));
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
