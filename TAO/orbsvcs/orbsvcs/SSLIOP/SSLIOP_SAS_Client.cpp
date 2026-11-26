#include "orbsvcs/Log_Macros.h"
#include "orbsvcs/SSLIOP/SSLIOP_SAS_Client.h"
#include "orbsvcs/SSLIOP/SSLIOP_SAS.h"
#include "orbsvcs/SSLIOP/SSLIOP_GSSUP_Credentials.h"
#include "orbsvcs/SSLIOP/SSLIOP_Kerberos_Credentials.h"
#include "orbsvcs/SSLIOP/SSLIOP_Connection_Handler.h"
#include "orbsvcs/SSLIOP/SSLIOP_Current.h"
#include "orbsvcs/SSLIOP/SSLIOP_Current_Impl.h"
#include "orbsvcs/Security/Audit_Logger.h"
#include "orbsvcs/Security/Caller.h"
#include "orbsvcs/Security/CSI_Utils.h"
#include "orbsvcs/SecurityLevel2C.h"
#include "orbsvcs/SecurityLevel3C.h"
#include "orbsvcs/CSIC.h"
#include "orbsvcs/CSIIOPC.h"

#include "tao/CDR.h"
#include "tao/Profile.h"
#include "tao/Stub.h"
#include "tao/Tagged_Components.h"
#include "tao/Transport.h"
#include "tao/PI/ClientRequestInfo.h"
#include "tao/debug.h"

#include "ace/OS_NS_string.h"

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <cerrno>
#include <string>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  namespace Reason = TAO::Security::Audit_Reason;
  using TAO::SSLIOP::SAS_Target;

  template <typename SEQ, typename T>
  bool
  decapsulate (SEQ const &data, T &value)
  {
    TAO_InputCDR cdr (reinterpret_cast<char const *> (data.get_buffer ()), data.length ());
    CORBA::Boolean byte_order;
    if (!(cdr >> ACE_InputCDR::to_boolean (byte_order)))
      return false;
    cdr.reset_byte_order (static_cast<int> (byte_order));
    return (cdr >> value) != 0;
  }

  template <typename SEQ>
  std::string
  octets (SEQ const &s)
  {
    return std::string (reinterpret_cast<char const *> (s.get_buffer ()), s.length ());
  }

  template <typename SEQ>
  void
  assign (SEQ &s, std::string const &o)
  {
    s.length (static_cast<CORBA::ULong> (o.size ()));
    if (!o.empty ())
      ACE_OS::memcpy (s.get_buffer (), o.data (), o.size ());
  }

  /// DER length octets.
  std::string
  der_length (size_t n)
  {
    std::string out;
    if (n < 0x80)
      out += static_cast<char> (n);
    else
      {
        std::string be;
        for (size_t v = n; v != 0; v >>= 8)
          be.insert (be.begin (), static_cast<char> (v & 0xFF));
        out += static_cast<char> (0x80 | be.size ());
        out += be;
      }
    return out;
  }

  /// The profile the request goes out on, or null.
  TAO_Profile *
  profile_of (PortableInterceptor::ClientRequestInfo_ptr ri)
  {
    CORBA::Object_var target = ri->effective_target ();
    TAO_Stub *const stub = CORBA::is_nil (target.in ()) ? nullptr : target->_stubobj ();
    return stub == nullptr ? nullptr : stub->profile_in_use ();
  }

  TAO_Stub *
  stub_of (PortableInterceptor::ClientRequestInfo_ptr ri)
  {
    CORBA::Object_var target = ri->effective_target ();
    return CORBA::is_nil (target.in ()) ? nullptr : target->_stubobj ();
  }

  bool
  has_mech_list (TAO_Profile *profile)
  {
    if (profile == nullptr)
      return false;
    IOP::TaggedComponent c;
    c.tag = IOP::TAG_CSI_SEC_MECH_LIST;
    return profile->tagged_components ().get_component (c) != 0;
  }

  /// The SAS context body in the reply, if there is one.
  bool
  reply_sas (PortableInterceptor::ClientRequestInfo_ptr ri, CSI::SASContextBody &body)
  {
    IOP::ServiceContext_var sc;
    try
      {
        sc = ri->get_reply_service_context (IOP::SecurityAttributeService);
      }
    catch (CORBA::BAD_PARAM const &)
      {
        return false;
      }
    return TAO::CSI_Utils::extract_sas_service_context (sc.in (), body);
  }

  /// RFC 5929 tls-server-end-point data for the TLS connection the
  /// request goes out on (the server certificate's hash), or empty if
  /// it is not an SSLIOP connection.  Empty in a build without TAO's
  /// interceptor support (CORBA/e), which has no TAO_ClientRequestInfo:
  /// there TAO sends no Kerberos login.
  std::string
  connection_binding (PortableInterceptor::ClientRequestInfo_ptr ri)
  {
#if (TAO_HAS_INTERCEPTORS == 1)
    TAO_ClientRequestInfo *const cri = dynamic_cast<TAO_ClientRequestInfo *> (ri);
    TAO_Transport *const transport = cri == nullptr ? nullptr : cri->tao_transport ();
    TAO_Connection_Handler *const handler = transport == nullptr ? nullptr : transport->connection_handler ();
    TAO::SSLIOP::Connection_Handler *const ssl_handler = dynamic_cast<TAO::SSLIOP::Connection_Handler *> (handler);
    SSL *const ssl = ssl_handler == nullptr ? nullptr : ssl_handler->peer ().ssl ();
    X509 *const cert = ssl == nullptr ? nullptr : ::SSL_get_peer_certificate (ssl);
    if (cert == nullptr)
      return std::string ();
    std::string const binding = TAO::SSLIOP::Kerberos::tls_server_end_point (cert);
    ::X509_free (cert);
    return binding;
#else
    ACE_UNUSED_ARG (ri);
    return std::string ();
#endif /* TAO_HAS_INTERCEPTORS */
  }

  /// The same key at every interception point of one request.
  void const *
  invocation_key (PortableInterceptor::ClientRequestInfo_ptr ri)
  {
#if (TAO_HAS_INTERCEPTORS == 1)
    TAO_ClientRequestInfo *const cri = dynamic_cast<TAO_ClientRequestInfo *> (ri);
    return cri == nullptr ? nullptr : static_cast<void const *> (cri->tao_invocation ());
#else
    ACE_UNUSED_ARG (ri);
    return nullptr;
#endif /* TAO_HAS_INTERCEPTORS */
  }

  /// The inbound request's caller certificate chain (leaf first) as a
  /// DER SEQUENCE OF Certificate, or empty.
  std::string
  peer_chain_der (SSL *ssl)
  {
    if (ssl == nullptr)
      return std::string ();
    X509 *const leaf = ::SSL_get_peer_certificate (ssl);
    if (leaf == nullptr)
      return std::string ();
    std::string body;
    auto add = [&body] (X509 *x) {
      int const n = ::i2d_X509 (x, nullptr);
      if (n <= 0)
        return false;
      std::string der (static_cast<size_t> (n), '\0');
      unsigned char *p = reinterpret_cast<unsigned char *> (&der[0]);
      if (::i2d_X509 (x, &p) != n)
        return false;
      body += der;
      return true;
    };
    bool ok = add (leaf);
    // On the server side the peer chain does not hold the leaf.
    STACK_OF (X509) *const rest = ::SSL_get_peer_cert_chain (ssl);
    for (int i = 0; ok && rest != nullptr && i < sk_X509_num (rest); ++i)
      {
        X509 *const x = sk_X509_value (rest, i);
        if (::X509_cmp (x, leaf) != 0)
          ok = add (x);
      }
    ::X509_free (leaf);
    if (!ok)
      return std::string ();
    return std::string (1, '\x30') + der_length (body.size ()) + body;
  }
}

TAO::SSLIOP::SAS_Client_Interceptor::SAS_Client_Interceptor (
    TAO::SL3::CredentialsCurator_ptr curator,
    ::SSLIOP::Current_ptr current,
    ::Security::QOP default_qop)
  : curator_ (TAO::SL3::CredentialsCurator::_duplicate (curator)),
    current_ (::SSLIOP::Current::_duplicate (current)),
    default_qop_ (default_qop)
{
}

TAO::SSLIOP::SAS_Client_Interceptor::~SAS_Client_Interceptor () = default;

char *
TAO::SSLIOP::SAS_Client_Interceptor::name ()
{
  return CORBA::string_dup ("TAO_SSLIOP_SAS_Client");
}

void
TAO::SSLIOP::SAS_Client_Interceptor::destroy ()
{
  this->curator_ = TAO::SL3::CredentialsCurator::_nil ();
  this->current_ = ::SSLIOP::Current::_nil ();
}

void
TAO::SSLIOP::SAS_Client_Interceptor::send_request (PortableInterceptor::ClientRequestInfo_ptr ri)
{
  TAO_Stub *const stub = stub_of (ri);
  TAO_Profile *const profile = stub == nullptr ? nullptr : stub->profile_in_use ();
  if (profile == nullptr)
    return;

  IOP::TaggedComponent mechs;
  mechs.tag = IOP::TAG_CSI_SEC_MECH_LIST;
  if (profile->tagged_components ().get_component (mechs) == 0)
    return;  // not a CSIv2 target
  CSIIOP::CompoundSecMechList list;
  if (!decapsulate (mechs.component_data, list) || list.mechanism_list.length () == 0)
    return;

  // The application (or an interceptor before this one) built its own
  // SAS context: leave the request alone.
  try
    {
      IOP::ServiceContext_var own = ri->get_request_service_context (IOP::SecurityAttributeService);
      return;
    }
  catch (CORBA::BAD_PARAM const &)
    {
    }

  // Will the request go over TLS?  The SSLIOP connector uses TLS when
  // the reference has a TLS port, unless the QOP policy asks for no
  // protection and no trust is to be established.
  bool tls_port = false;
  {
    IOP::TaggedComponent ssl;
    ssl.tag = ::SSLIOP::TAG_SSL_SEC_TRANS;
    ::SSLIOP::SSL ssl_comp;
    if (profile->tagged_components ().get_component (ssl) != 0
        && decapsulate (ssl.component_data, ssl_comp) && ssl_comp.port != 0)
      tls_port = true;
  }
  // The ContextEstablishmentPolicy, if the application set one.
  SecurityLevel3::OwnCredentialsList_var policy_creds;
  bool client_auth_off = false;
  {
    CORBA::Policy_var p = stub->get_policy (SecurityLevel3::ContextEstablishmentPolicyType);
    SecurityLevel3::ContextEstablishmentPolicy_var cp = SecurityLevel3::ContextEstablishmentPolicy::_narrow (p.in ());
    if (!CORBA::is_nil (cp.in ()))
      {
        policy_creds = cp->creds_list ();
        client_auth_off = cp->use_client_auth () == SecurityLevel3::FD_DoNotUse;
      }
  }
  // The policy's own credentials if it names any, else the default list.
  SecurityLevel3::OwnCredentialsList_var creds;
  if (policy_creds.ptr () != nullptr && policy_creds->length () > 0)
    creds = new SecurityLevel3::OwnCredentialsList (policy_creds.in ());
  else if (!CORBA::is_nil (this->curator_.in ()))
    creds = this->curator_->default_creds_list ();
  else
    creds = new SecurityLevel3::OwnCredentialsList;

  // Kerberos credentials allowed to log in to mechanism @a m's service
  // principal (its target name), which goes to @a service.
  auto kerberos_for = [&] (CSIIOP::CompoundSecMech const &m, std::string &service)
    -> TAO::SSLIOP::Kerberos_OwnCredentials * {
    CSIIOP::AS_ContextSec const &a = m.as_context_mech;
    if (client_auth_off || (a.target_supports & CSIIOP::EstablishTrustInClient) == 0
        || octets (a.client_authentication_mech) != TAO::SSLIOP::Kerberos::mech_der ()
        || !TAO::SSLIOP::Kerberos::parse_exported_name (octets (a.target_name), service))
      return nullptr;
    for (CORBA::ULong i = 0; i < creds->length (); ++i)
      {
        TAO::SSLIOP::Kerberos_OwnCredentials *const k = TAO::SSLIOP::Kerberos_OwnCredentials::of (creds[i].in ());
        if (k != nullptr && k->usable () && k->allows (service))
          return k;
      }
    return nullptr;
  };

  // The TLS mechanism to use: first one this client can log in to with
  // Kerberos (preferred, R29), then the first whose authentication layer
  // it can otherwise use (none, or GSSUP), then the first TLS mechanism.
  CORBA::ULong chosen = list.mechanism_list.length ();
  for (int pass = 0; pass < 3 && chosen == list.mechanism_list.length (); ++pass)
    for (CORBA::ULong i = 0; i < list.mechanism_list.length (); ++i)
      {
        CSIIOP::CompoundSecMech const &m = list.mechanism_list[i];
        CSIIOP::TLS_SEC_TRANS tls;
        if (m.transport_mech.tag != CSIIOP::TAG_TLS_SEC_TRANS
            || !decapsulate (m.transport_mech.component_data, tls) || tls.addresses.length () == 0)
          continue;
        tls_port = true;
        bool usable = false;
        if (pass == 0)
          {
            std::string service;
            usable = kerberos_for (m, service) != nullptr;
          }
        else
          {
            std::string const as_oid = octets (m.as_context_mech.client_authentication_mech);
            usable = pass == 2 || (m.as_context_mech.target_supports & CSIIOP::EstablishTrustInClient) == 0
                     || as_oid.empty () || as_oid == SAS_Target::gssup_mech_der ();
          }
        if (usable)
          {
            chosen = i;
            break;
          }
      }
  if (chosen == list.mechanism_list.length ())
    chosen = 0;  // e.g. JacORB: TAG_NULL_TAG here, TLS in TAG_SSL_SEC_TRANS

  bool over_tls = tls_port;
  if (over_tls)
    {
      ::Security::QOP qop = this->default_qop_;
      CORBA::Policy_var p = stub->get_policy (::Security::SecQOPPolicy);
      SecurityLevel2::QOPPolicy_var qp = SecurityLevel2::QOPPolicy::_narrow (p.in ());
      if (!CORBA::is_nil (qp.in ()))
        qop = qp->qop ();
      p = stub->get_policy (::Security::SecEstablishTrustPolicy);
      SecurityLevel2::EstablishTrustPolicy_var tp = SecurityLevel2::EstablishTrustPolicy::_narrow (p.in ());
      bool trust = false;
      if (!CORBA::is_nil (tp.in ()))
        {
          ::Security::EstablishTrust const t = tp->trust ();
          trust = t.trust_in_target || t.trust_in_client;
        }
      if (qop == ::Security::SecQOPNoProtection && !trust)
        over_tls = false;
    }

  CSIIOP::CompoundSecMech const &mech = list.mechanism_list[chosen];
  CORBA::String_var op = ri->operation ();

  // --- Client authentication layer: Kerberos.
  CSI::GSSToken krb_token;
  std::string krb_user;
  std::string krb_service;
  std::unique_ptr<TAO::SSLIOP::Kerberos::Initiator> krb_login;
  CSIIOP::AS_ContextSec const &as = mech.as_context_mech;
  bool const as_required = (as.target_requires & CSIIOP::EstablishTrustInClient) != 0;
  if ((as.target_supports & CSIIOP::EstablishTrustInClient) != 0
      && octets (as.client_authentication_mech) == TAO::SSLIOP::Kerberos::mech_der ()
      && !client_auth_off)
    {
      TAO::SSLIOP::Kerberos_OwnCredentials *const found = kerberos_for (mech, krb_service);
      std::string why;
      if (found == nullptr)
        why = krb_service.empty () ? "the target names no Kerberos service principal"
                                   : "there are no Kerberos credentials for " + krb_service;
      else if (!over_tls)
        why = "the call would not go over TLS";
      else
        {
          // Bound to this connection (Phase 3 Q3): the target refuses a
          // token relayed into another TLS session.
          std::string const binding = connection_binding (ri);
          std::string token;
          if (binding.empty ())
            why = "cannot read the TLS server certificate to bind the Kerberos token to";
          else
            {
              krb_login.reset (new TAO::SSLIOP::Kerberos::Initiator);
              if (krb_login->start (found->source (), krb_service, binding, token, why))
                {
                  assign (krb_token, token);
                  krb_user = found->client ();
                }
              else
                krb_login.reset ();
            }
        }
      if (krb_user.empty () && (as_required || found != nullptr))
        {
          // Required: refused here.  Not required, but the credentials
          // could not log in (expired ticket, no TLS): audited, and the
          // call goes on without client authentication.
          TAO::Security::Audit_Record rec ("sas_client", false, Reason::SAS_CLIENT_NO_CREDENTIALS);
          rec.field ("target", krb_service.empty () ? std::string ("(none)") : krb_service)
            .field ("op", op.in ())
            .field ("mech", "kerberos")
            .text ((std::string (as_required ? "the target requires Kerberos and " : "Kerberos not used: ") + why).c_str ());
          TAO::Security::Audit_Logger::instance ()->write (rec);
          if (TAO_debug_level > 0)
            ORBSVCS_DEBUG ((LM_DEBUG, ACE_TEXT ("(%P|%t) SSLIOP SAS client: Kerberos: %C\n"), why.c_str ()));
          if (as_required)
            throw CORBA::NO_PERMISSION (CORBA::SystemException::_tao_minor_code (TAO::VMCID, EPERM),
                                        CORBA::COMPLETED_NO);
        }
    }

  // --- Client authentication layer: GSSUP.
  CSI::GSSToken gssup_token;
  std::string gssup_user;
  if ((as.target_supports & CSIIOP::EstablishTrustInClient) != 0
      && octets (as.client_authentication_mech) == SAS_Target::gssup_mech_der ()
      && !client_auth_off)
    {
      std::string target;
      std::string const target_octets = octets (as.target_name);
      if (!SAS_Target::parse_exported_name (target_octets, target))
        target.clear ();

      TAO::SSLIOP::GSSUP_OwnCredentials *found = nullptr;
      for (CORBA::ULong i = 0; found == nullptr && i < creds->length (); ++i)
        {
          TAO::SSLIOP::GSSUP_OwnCredentials *const g = TAO::SSLIOP::GSSUP_OwnCredentials::of (creds[i].in ());
          if (g != nullptr && g->usable () && !target.empty () && g->target () == target)
            found = g;
        }

      // The username goes as a scoped-username (CORBA 3.3 Part 2,
      // 10.2.4.1.1): a user of the target's own scope as its quoted name
      // alone ("alice" for target "@lab.test"), any other in full.
      std::string wire_user = found != nullptr ? found->username () : std::string ();
      {
        std::string value;
        std::string scope;
        if (SAS_Target::split_scoped (wire_user, value, scope) && !value.empty () && scope == target)
          wire_user = SAS_Target::quote_scoped (value);
      }

      if (found != nullptr && over_tls
          && SAS_Target::encode_gssup_token (wire_user, found->password (), target_octets, gssup_token))
        {
          gssup_user = found->username ();
        }
      else if (as_required)
        {
          char const *const why =
            found == nullptr ? "the target requires GSSUP and there are no GSSUP credentials for its target name"
                             : "the target requires GSSUP and the call would not go over TLS";
          TAO::Security::Audit_Record rec ("sas_client", false, Reason::SAS_CLIENT_NO_CREDENTIALS);
          rec.field ("target", target.empty () ? std::string ("(none)") : target)
            .field ("op", op.in ())
            .text (why);
          TAO::Security::Audit_Logger::instance ()->write (rec);
          if (TAO_debug_level > 0)
            ORBSVCS_DEBUG ((LM_DEBUG, ACE_TEXT ("(%P|%t) SSLIOP SAS client: %C\n"), why));
          throw CORBA::NO_PERMISSION (CORBA::SystemException::_tao_minor_code (TAO::VMCID, EPERM),
                                      CORBA::COMPLETED_NO);
        }
    }

  // --- Attribute layer: identity assertion of the current caller.
  CSI::IdentityToken id;
  id.absent (true);
  std::string asserted;
  CSIIOP::SAS_ContextSec const &sas = mech.sas_context_mech;
  if (SAS_Target::config ().assert_caller && over_tls
      && (sas.target_supports & CSIIOP::IdentityAssertion) != 0)
    {
      TAO::SSLIOP::Current *const cur = dynamic_cast<TAO::SSLIOP::Current *> (this->current_.in ());
      TAO::SSLIOP::Current_Impl *const impl = cur != nullptr ? cur->request_impl () : nullptr;
      std::shared_ptr<TAO::Security::Caller const> const caller =
        impl != nullptr ? impl->caller () : std::shared_ptr<TAO::Security::Caller const> ();
      if (caller && !caller->local)
        {
          std::string const name = !caller->asserted.empty () ? caller->asserted : caller->authenticated;
          // A name goes in its own mechanism (K5): a Kerberos principal
          // as a Kerberos exported name, to a target that names Kerberos
          // among its naming mechanisms; never re-labelled as GSSUP.
          bool const kerberos_name = caller->effective_mech () == "krb5";
          bool gssup_naming = false;
          bool krb_naming = false;
          for (CORBA::ULong i = 0; i < sas.supported_naming_mechanisms.length (); ++i)
            {
              std::string const m = octets (sas.supported_naming_mechanisms[i]);
              gssup_naming = gssup_naming || m == SAS_Target::gssup_mech_der ();
              krb_naming = krb_naming || m == TAO::SSLIOP::Kerberos::mech_der ();
            }
          if (!name.empty ())
            {
              if ((sas.supported_identity_types & CSI::ITTPrincipalName) != 0
                  && (kerberos_name ? krb_naming : gssup_naming))
                {
                  CSI::GSS_NT_ExportedName n;
                  assign (n, kerberos_name ? TAO::SSLIOP::Kerberos::exported_name (name)
                                           : SAS_Target::exported_name (name));
                  id.principal_name (n);
                  asserted = name;
                }
            }
          else if ((sas.supported_identity_types & CSI::ITTX509CertChain) != 0)
            {
              std::string const chain = peer_chain_der (impl->ssl ());
              if (!chain.empty ())
                {
                  CSI::X509CertificateChain c;
                  assign (c, chain);
                  id.certificate_chain (c);
                  asserted = caller->transport ();
                }
            }
        }
    }

  if (gssup_user.empty () && krb_user.empty () && asserted.empty ())
    return;

  CSI::EstablishContext ec;
  ec.client_context_id = 0;  // stateless
  ec.authorization_token.length (0);
  ec.identity_token = id;
  ec.client_authentication_token = krb_user.empty () ? gssup_token : krb_token;
  CSI::SASContextBody body;
  body.establish_msg (ec);
  IOP::ServiceContext sc;
  TAO::CSI_Utils::create_sas_service_context (body, sc);
  ri->add_request_service_context (sc, true);

  // The request holds its own copy now: wipe ours (they carry the password).
  auto wipe = [] (auto &seq) {
    if (seq.length () > 0)
      ::OPENSSL_cleanse (seq.get_buffer (), seq.length ());
  };
  wipe (gssup_token);
  wipe (ec.client_authentication_token);
  wipe (body.establish_msg ().client_authentication_token);
  wipe (sc.context_data);

  // The reply must prove the service (mutual authentication): keep the
  // login until it arrives.  A oneway call gets no reply to check.
  if (krb_login && ri->response_expected ())
    {
      void const *const key = invocation_key (ri);
      if (key != nullptr)
        {
          ACE_GUARD (TAO_SYNCH_MUTEX, guard, this->pending_lock_);
          this->pending_[key] = std::move (krb_login);
        }
    }

  if (SAS_Target::config ().audit_grants)
    {
      TAO::Security::Audit_Record rec ("sas_client", true, Reason::SAS_CLIENT_SENT);
      if (!krb_user.empty ())
        rec.field ("user", krb_user).field ("mech", "kerberos").field ("target", krb_service);
      else if (!gssup_user.empty ())
        rec.field ("user", gssup_user);
      if (!asserted.empty ())
        rec.field ("asserted", asserted);
      rec.field ("op", op.in ());
      TAO::Security::Audit_Logger::instance ()->write (rec);
    }
}

std::unique_ptr<TAO::SSLIOP::Kerberos::Initiator>
TAO::SSLIOP::SAS_Client_Interceptor::take_pending (PortableInterceptor::ClientRequestInfo_ptr ri)
{
  std::unique_ptr<Kerberos::Initiator> login;
  void const *const key = invocation_key (ri);
  if (key == nullptr)
    return login;
  ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->pending_lock_, login);
  auto const it = this->pending_.find (key);
  if (it != this->pending_.end ())
    {
      login = std::move (it->second);
      this->pending_.erase (it);
    }
  return login;
}

void
TAO::SSLIOP::SAS_Client_Interceptor::check_reply (PortableInterceptor::ClientRequestInfo_ptr ri, bool exception)
{
  std::unique_ptr<Kerberos::Initiator> const login = this->take_pending (ri);
  if (!has_mech_list (profile_of (ri)))
    return;
  CSI::SASContextBody body;
  bool const have_sas = reply_sas (ri, body);

  if (login && !(have_sas && body._d () == CSI::MTContextError))
    {
      // R29: the reply must carry the service's Kerberos reply token
      // (AP-REP), or it cannot be trusted to come from the service.  An
      // exception without one (raised before the target's security
      // layer ran) is left as it is: it claims no success.
      std::string reply_token;
      if (have_sas && body._d () == CSI::MTCompleteEstablishContext)
        reply_token = octets (body.complete_msg ().final_context_token);
      std::string why;
      if (!(exception && reply_token.empty ()) && !login->finish (reply_token, why))
        {
          CORBA::String_var op = ri->operation ();
          TAO::Security::Audit_Record rec ("sas_client", false, Reason::KRB_SERVER_UNVERIFIED);
          rec.field ("op", op.in ()).text (why.c_str ());
          TAO::Security::Audit_Logger::instance ()->write (rec);
          if (TAO_debug_level > 0)
            ORBSVCS_DEBUG ((LM_DEBUG, ACE_TEXT ("(%P|%t) SSLIOP SAS client: %C\n"), why.c_str ()));
          // The target may have run the operation: COMPLETED_MAYBE.
          throw CORBA::NO_PERMISSION (CORBA::SystemException::_tao_minor_code (TAO::VMCID, EPERM),
                                      CORBA::COMPLETED_MAYBE);
        }
    }

  if (!have_sas || body._d () != CSI::MTContextError)
    return;
  CSI::ContextError const &e = body.error_msg ();
  CORBA::String_var op = ri->operation ();
  TAO::Security::Audit_Record rec ("sas_client", false, Reason::SAS_CLIENT_REFUSED);
  rec.field ("op", op.in ())
    .field ("context_error", std::to_string (e.major_status))
    .field ("minor", std::to_string (e.minor_status));
  TAO::Security::Audit_Logger::instance ()->write (rec);

  if (exception)
    {
      CORBA::String_var id = ri->received_exception_id ();
      if (ACE_OS::strcmp (id.in (), "IDL:omg.org/CORBA/NO_PERMISSION:1.0") == 0)
        return;
    }
  throw CORBA::NO_PERMISSION (CORBA::SystemException::_tao_minor_code (TAO::VMCID, EPERM),
                              CORBA::COMPLETED_NO);
}

void
TAO::SSLIOP::SAS_Client_Interceptor::send_poll (PortableInterceptor::ClientRequestInfo_ptr)
{
}

void
TAO::SSLIOP::SAS_Client_Interceptor::receive_reply (PortableInterceptor::ClientRequestInfo_ptr ri)
{
  this->check_reply (ri, false);
}

void
TAO::SSLIOP::SAS_Client_Interceptor::receive_exception (PortableInterceptor::ClientRequestInfo_ptr ri)
{
  this->check_reply (ri, true);
}

void
TAO::SSLIOP::SAS_Client_Interceptor::receive_other (PortableInterceptor::ClientRequestInfo_ptr ri)
{
  // A forward or retry: the next attempt logs in afresh.
  (void) this->take_pending (ri);
}

TAO_END_VERSIONED_NAMESPACE_DECL
