#include "orbsvcs/Log_Macros.h"
#include "orbsvcs/SSLIOP/SSLIOP_Acceptor.h"
#include "orbsvcs/SSLIOP/SSLIOP_Profile.h"
#include "orbsvcs/SSLIOP/SSLIOP_SAS.h"
#include "orbsvcs/SSLIOP/SSLIOP_Kerberos.h"

#include "tao/MProfile.h"
#include "tao/ORB_Core.h"
#include "tao/Server_Strategy_Factory.h"
#include "tao/Codeset_Manager.h"
#include "tao/CDR.h"
#include "tao/debug.h"
#include "tao/Security_Mode.h"
#include "ace/SSL/SSL_Context.h"

#if !defined(__ACE_INLINE__)
#include "orbsvcs/SSLIOP/SSLIOP_Acceptor.inl"
#endif /* __ACE_INLINE__ */

#include <algorithm>

#include <vector>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

TAO::SSLIOP::Acceptor::Acceptor (::Security::QOP qop,
                                 const ACE_Time_Value & timeout,
                                 bool check_host)
  : TAO::IIOP_SSL_Acceptor (),
    ssl_acceptor_ (this),
    timeout_ (timeout),
    check_host_ (check_host)
{
  // Prod listens only for TLS: no plain IIOP port at all.
  this->plain_listener (TAO_Security_Mode::host ().mode != TAO_Security_Mode::MODE_PROD);

  // CSIv2 IOR component (TAG_CSI_SEC_MECH_LIST): on by default in prod.
  {
    bool const prod = TAO_Security_Mode::host ().mode == TAO_Security_Mode::MODE_PROD;
    std::string const v = TAO_Security_Mode::host ().get ("csiv2", prod ? "supported" : "off");
    this->csiv2_mode_ = v == "required" ? 2 : v == "supported" ? 1 : 0;
  }

  // --- CSIv1 ---

  // Clear all bits in the SSLIOP::SSL association option fields.
  this->ssl_component_.target_supports = 0;
  this->ssl_component_.target_requires = 0;

  // SSLIOP requires these Security::AssociationOptions by default.
  ACE_SET_BITS (this->ssl_component_.target_requires,
                ::Security::Integrity
                | ::Security::Confidentiality
                | ::Security::NoDelegation);

  // SSLIOP supports these Security::AssociationOptions by default.
  ACE_SET_BITS (this->ssl_component_.target_supports,
                ::Security::Integrity
                | ::Security::Confidentiality
                | ::Security::EstablishTrustInTarget
                | ::Security::NoDelegation);

  // Initialize the default SSL port to zero (wild card port).
  this->ssl_component_.port = 0;

  // @@ This should go away once we support setting security
  //    association options through policies.
  if (qop == ::Security::SecQOPNoProtection)
    ACE_SET_BITS (this->ssl_component_.target_supports,
                  ::Security::NoProtection);


  // --- CSIv2 ---

  // Clear all bits in the CSIIOP::TLS_SEC_TRANS association option
  // fields.
  this->csiv2_component_.target_supports = 0;
  this->csiv2_component_.target_requires = 0;

  // SSLIOP requires these CSIIOP::AssociationOptions by default.
  ACE_SET_BITS (this->csiv2_component_.target_requires,
                CSIIOP::Integrity
                | CSIIOP::Confidentiality
                | CSIIOP::NoDelegation);

  // SSLIOP supports these CSIIOP::AssociationOptions by default.
  ACE_SET_BITS (this->csiv2_component_.target_supports,
                CSIIOP::Integrity
                | CSIIOP::Confidentiality
                | CSIIOP::EstablishTrustInTarget
                | CSIIOP::NoDelegation);

  // @@ This should go away once we support setting security
  //    association options through policies.
  if (qop == CSIIOP::NoProtection)
    ACE_SET_BITS (this->csiv2_component_.target_supports,
                  CSIIOP::NoProtection);
}

TAO::SSLIOP::Acceptor::~Acceptor ()
{
  // Make sure we are closed before we start destroying the
  // strategies.
  this->close ();

  delete this->creation_strategy_;
  delete this->concurrency_strategy_;
  delete this->accept_strategy_;
}

namespace
{
  /// An encapsulation (byte-order flag + CDR) of @a value in @a out.
  template <typename T, typename SEQ>
  bool
  encapsulate (T const &value, SEQ &out)
  {
    TAO_OutputCDR cdr;
    if (!(cdr << TAO_OutputCDR::from_boolean (TAO_ENCAP_BYTE_ORDER)) || !(cdr << value))
      return false;
    CORBA::ULong const length = static_cast<CORBA::ULong> (cdr.total_length ());
    out.length (length);
    CORBA::Octet *buf = out.get_buffer ();
    for (ACE_Message_Block const *mb = cdr.begin (); mb != nullptr; mb = mb->cont ())
      {
        ACE_OS::memcpy (buf, mb->rd_ptr (), mb->length ());
        buf += mb->length ();
      }
    return true;
  }
}

void
TAO::SSLIOP::Acceptor::add_csiv2_component (TAO_SSLIOP_Profile *pfile, size_t first, size_t count)
{
  if (this->csiv2_mode_ == 0 || pfile == nullptr)
    return;

  // The TLS layer: what the TLS endpoint supports and requires, and
  // where it is.  A service that verifies its clients' certificates
  // supports (and, if it refuses clients without one, requires)
  // EstablishTrustInClient.
  CSIIOP::TLS_SEC_TRANS tls = this->csiv2_component_;
  int const verify = ACE_SSL_Context::instance ()->default_verify_mode ();
  if ((verify & SSL_VERIFY_PEER) != 0)
    {
      ACE_SET_BITS (tls.target_supports, CSIIOP::EstablishTrustInClient);
      if ((verify & SSL_VERIFY_FAIL_IF_NO_PEER_CERT) != 0)
        ACE_SET_BITS (tls.target_requires, CSIIOP::EstablishTrustInClient);
    }
  tls.addresses.length (static_cast<CORBA::ULong> (count));
  for (size_t i = 0; i < count; ++i)
    {
      tls.addresses[static_cast<CORBA::ULong> (i)].host_name = CORBA::string_dup (this->hosts_[first + i]);
      tls.addresses[static_cast<CORBA::ULong> (i)].port = this->ssl_component_.port;
    }

  // One compound mechanism per client authentication mechanism, sharing
  // the TLS transport and the attribute layer: Kerberos first, then
  // GSSUP (Phase 3 Q5).  A required mechanism is offered alone; with
  // none on, one mechanism with an empty authentication layer.
  CSIIOP::CompoundSecMech base;
  base.target_requires = tls.target_requires;
  base.transport_mech.tag = CSIIOP::TAG_TLS_SEC_TRANS;
  if (!encapsulate (tls, base.transport_mech.component_data))
    return;
  base.as_context_mech.target_supports = 0;
  base.as_context_mech.target_requires = 0;
  base.as_context_mech.client_authentication_mech.length (0);
  base.as_context_mech.target_name.length (0);

  TAO::SSLIOP::SAS_Target::Config const &sas = TAO::SSLIOP::SAS_Target::config ();
  base.sas_context_mech.target_supports = 0;
  base.sas_context_mech.target_requires = 0;
  base.sas_context_mech.privilege_authorities.length (0);
  base.sas_context_mech.supported_naming_mechanisms.length (0);
  base.sas_context_mech.supported_identity_types = 0;
  // Attribute layer: identity assertion when an asserter list is
  // configured (W5).  Every type a listed asserter could be allowed is
  // advertised; the list limits each asserter.
  // With allow_anonymous_assertion = on, ITTAnonymous is offered to any
  // caller even without an asserter list (CSIv2 rule 4).
  if (sas.anonymous == 2 && !sas.assertion)
    {
      base.sas_context_mech.target_supports = CSIIOP::IdentityAssertion;
      base.sas_context_mech.supported_identity_types = CSI::ITTAnonymous;
    }
  if (sas.assertion)
    {
      base.sas_context_mech.target_supports = CSIIOP::IdentityAssertion;
      base.sas_context_mech.supported_identity_types =
        CSI::ITTPrincipalName | CSI::ITTDistinguishedName | CSI::ITTX509CertChain | (sas.anonymous != 0 ? CSI::ITTAnonymous : 0);
      // Names of the GSSUP mechanism, and of Kerberos where it is on
      // (R32, Phase 3 K5).
      std::vector<std::string> naming (1, TAO::SSLIOP::SAS_Target::gssup_mech_der ());
      if (sas.kerberos != 0)
        naming.push_back (TAO::SSLIOP::Kerberos::mech_der ());
      base.sas_context_mech.supported_naming_mechanisms.length (static_cast<CORBA::ULong> (naming.size ()));
      for (CORBA::ULong i = 0; i < naming.size (); ++i)
        {
          base.sas_context_mech.supported_naming_mechanisms[i].length (static_cast<CORBA::ULong> (naming[i].size ()));
          ACE_OS::memcpy (base.sas_context_mech.supported_naming_mechanisms[i].get_buffer (), naming[i].data (),
                          naming[i].size ());
        }
    }

  std::vector<CSIIOP::CompoundSecMech> mechs;
  auto with_as = [&] (std::string const &oid, std::string const &name, bool required) {
    CSIIOP::CompoundSecMech m = base;
    m.as_context_mech.target_supports = CSIIOP::EstablishTrustInClient;
    if (required)
      {
        m.as_context_mech.target_requires = CSIIOP::EstablishTrustInClient;
        ACE_SET_BITS (m.target_requires, CSIIOP::EstablishTrustInClient);
      }
    m.as_context_mech.client_authentication_mech.length (static_cast<CORBA::ULong> (oid.size ()));
    ACE_OS::memcpy (m.as_context_mech.client_authentication_mech.get_buffer (), oid.data (), oid.size ());
    m.as_context_mech.target_name.length (static_cast<CORBA::ULong> (name.size ()));
    ACE_OS::memcpy (m.as_context_mech.target_name.get_buffer (), name.data (), name.size ());
    mechs.push_back (m);
  };
  bool const krb = sas.kerberos != 0 && !sas.krb_principal.empty () && TAO::SSLIOP::Kerberos::built ();
  bool const gssup = sas.gssup != 0 && !sas.target.empty ();
  if (krb && !(gssup && sas.gssup == 2))
    with_as (TAO::SSLIOP::Kerberos::mech_der (), TAO::SSLIOP::Kerberos::exported_name (sas.krb_principal),
             sas.kerberos == 2);
  if (gssup && !(krb && sas.kerberos == 2))
    with_as (TAO::SSLIOP::SAS_Target::gssup_mech_der (), TAO::SSLIOP::SAS_Target::exported_name (sas.target),
             sas.gssup == 2);
  if (mechs.empty ())
    mechs.push_back (base);

  CSIIOP::CompoundSecMechList list;
  list.stateful = false;
  list.mechanism_list.length (static_cast<CORBA::ULong> (mechs.size ()));
  for (size_t i = 0; i < mechs.size (); ++i)
    list.mechanism_list[static_cast<CORBA::ULong> (i)] = mechs[i];

  IOP::TaggedComponent component;
  component.tag = IOP::TAG_CSI_SEC_MECH_LIST;
  if (encapsulate (list, component.component_data))
    pfile->tagged_components ().set_component (component);
}

int
TAO::SSLIOP::Acceptor::create_profile (const TAO::ObjectKey &object_key,
                                       TAO_MProfile &mprofile,
                                       CORBA::Short priority)
{
  // Sanity check.
  if (this->endpoint_count_ == 0)
    return -1;

  // Check if multiple endpoints should be put in one profile or
  // if they should be spread across multiple profiles.
  if (priority == TAO_INVALID_PRIORITY)
    return this->create_new_profile (object_key,
                                     mprofile,
                                     priority);
  else
    return this->create_shared_profile (object_key,
                                        mprofile,
                                        priority);
}

int
TAO::SSLIOP::Acceptor::create_new_profile (const TAO::ObjectKey &object_key,
                                           TAO_MProfile &mprofile,
                                           CORBA::Short priority)
{
  // Adding this->endpoint_count_ to the TAO_MProfile.
  const int count = mprofile.profile_count ();
  if ((mprofile.size () - count) < this->endpoint_count_
      && mprofile.grow (count + this->endpoint_count_) == -1)
    return -1;

  // Create a profile for each acceptor endpoint.
  for (size_t i = 0; i < this->endpoint_count_; ++i)
    {
      TAO_SSLIOP_Profile *pfile = nullptr;

      // @@ We need to create an SSLIOP::SSL component for the object
      //    we're creating an MProfile for.  This will allow us to
      //    properly embed secure invocation policies in the generated
      //    IOR, i.e. secure invocation policies on a per-object
      //    basis, rather than on a per-endpoint basis.  If no secure
      //    invocation policies have been set then we should use the
      //    below default SSLIOP::SSL component.
      ACE_NEW_RETURN (pfile,
                      TAO_SSLIOP_Profile (this->hosts_[i],
                                            this->addrs_[i].get_port_number (),
                                            object_key,
                                            this->addrs_[i],
                                            this->version_,
                                            this->orb_core_,
                                            &(this->ssl_component_)),
                      -1);
      pfile->endpoint ()->priority (priority);

      if (mprofile.give_profile (pfile) == -1)
        {
          pfile->_decr_refcnt ();
          pfile = nullptr;
          return -1;
        }

      if (this->orb_core_->orb_params ()->std_profile_components () == 0)
        continue;

      pfile->tagged_components ().set_orb_type (TAO_ORB_TYPE);

      TAO_Codeset_Manager *csm = this->orb_core_->codeset_manager();
      if (csm)
        csm->set_codeset (pfile->tagged_components());

      IOP::TaggedComponent component;
      component.tag = ::SSLIOP::TAG_SSL_SEC_TRANS;

      // @@???? Check this code, only intended as guideline...
      TAO_OutputCDR cdr;
      cdr << TAO_OutputCDR::from_boolean (TAO_ENCAP_BYTE_ORDER);

      // @@ We need to create an SSLIOP::SSL component for the object
      //    we're creating an MProfile for.  This will allow us to
      //    properly embed secure invocation policies in the generated
      //    IOR, i.e. secure invocation policies on a per-object
      //    basis, rather than on a per-endpoint basis.  If no secure
      //    invocation policies have been set then we should use the
      //    below default SSLIOP::SSL component.
      cdr << this->ssl_component_;

      // TAO extension, replace the contents of the octet sequence with
      // the CDR stream
      CORBA::ULong const length = static_cast<CORBA::ULong> (cdr.total_length ());
      component.component_data.length (length);
      CORBA::Octet *buf = component.component_data.get_buffer ();
      for (ACE_Message_Block const *mb = cdr.begin ();
           mb != nullptr;
           mb = mb->cont ())
        {
          ACE_OS::memcpy (buf, mb->rd_ptr (), mb->length ());
          buf += mb->length ();
        }

      pfile->tagged_components ().set_component (component);

      this->add_csiv2_component (pfile, i, 1);
    }

  return 0;
}


int
TAO::SSLIOP::Acceptor::create_shared_profile (const TAO::ObjectKey &object_key,
                                              TAO_MProfile &mprofile,
                                              CORBA::Short priority)
{
  size_t index = 0;
  TAO_Profile *pfile = nullptr;
  TAO_SSLIOP_Profile *ssliop_profile = nullptr;

  // First see if <mprofile> already contains a SSLIOP profile.
  for (TAO_PHandle i = 0; i != mprofile.profile_count (); ++i)
    {
      pfile = mprofile.get_profile (i);
      if (pfile->tag () == IOP::TAG_INTERNET_IOP)
        {
          ssliop_profile = dynamic_cast<TAO_SSLIOP_Profile *> (pfile);
          if (ssliop_profile == nullptr)
            return -1;
          break;
        }
    }

  // If <mprofile> doesn't contain SSLIOP_Profile, we need to create
  // one.
  if (ssliop_profile == nullptr)
    {
      // @@ We need to create an SSLIOP::SSL component for the object
      //    we're creating an MProfile for.  This will allow us to
      //    properly embed secure invocation policies in the generated
      //    IOR, i.e. secure invocation policies on a per-object
      //    basis, rather than on a per-endpoint basis.  If no secure
      //    invocation policies have been set then we should use the
      //    below default SSLIOP::SSL component.
      ACE_NEW_RETURN (ssliop_profile,
                      TAO_SSLIOP_Profile (this->hosts_[0],
                                            this->addrs_[0].get_port_number (),
                                            object_key,
                                            this->addrs_[0],
                                            this->version_,
                                            this->orb_core_,
                                            &(this->ssl_component_)),
                      -1);

      TAO_SSLIOP_Endpoint * const ssliop_endp =
        dynamic_cast<TAO_SSLIOP_Endpoint *> (ssliop_profile->endpoint ());

      if (!ssliop_endp)
        return -1;

      ssliop_endp->priority (priority);
      ssliop_endp->iiop_endpoint ()->priority (priority);

      if (mprofile.give_profile (ssliop_profile) == -1)
        {
          ssliop_profile->_decr_refcnt ();
          ssliop_profile = nullptr;
          return -1;
        }

      if (this->orb_core_->orb_params ()->std_profile_components () != 0)
        {
          ssliop_profile->tagged_components ().set_orb_type (TAO_ORB_TYPE);

          TAO_Codeset_Manager *csm = this->orb_core_->codeset_manager();
          if (csm)
            csm->set_codeset(ssliop_profile->tagged_components());

          IOP::TaggedComponent component;
          component.tag = ::SSLIOP::TAG_SSL_SEC_TRANS;
          // @@???? Check this code, only intended as guideline...
          TAO_OutputCDR cdr;
          cdr << TAO_OutputCDR::from_boolean (TAO_ENCAP_BYTE_ORDER);

          // @@ We need to create an SSLIOP::SSL component for the
          //    object we're creating an MProfile for.  This will
          //    allow us to properly embed secure invocation policies
          //    in the generated IOR, i.e. secure invocation policies
          //    on a per-object basis, rather than on a per-endpoint
          //    basis.  If no secure invocation policies have been set
          //    then we should use the below default SSLIOP::SSL
          //    component.
          cdr << this->ssl_component_;

          // TAO extension, replace the contents of the octet sequence with
          // the CDR stream
          CORBA::ULong const length = static_cast<CORBA::ULong> (cdr.total_length ());
          component.component_data.length (length);
          CORBA::Octet *buf = component.component_data.get_buffer ();
          for (const ACE_Message_Block *i = cdr.begin ();
               i != nullptr;
               i = i->cont ())
            {
              ACE_OS::memcpy (buf, i->rd_ptr (), i->length ());
              buf += i->length ();
            }

          ssliop_profile->tagged_components ().set_component (component);
        }

      index = 1;
    }

  // Add any remaining endpoints to the SSLIOP_Profile.
  for (;
       index < this->endpoint_count_;
       ++index)
    {
      TAO_SSLIOP_Endpoint *ssl_endp = nullptr;
      TAO_IIOP_Endpoint *iiop_endp = nullptr;
      ACE_NEW_RETURN (iiop_endp,
                      TAO_IIOP_Endpoint (this->hosts_[index],
                                         this->addrs_[index].get_port_number (),
                                         this->addrs_[index]),
                      -1);
      iiop_endp->priority (priority);

      ACE_NEW_RETURN (ssl_endp,
                      TAO_SSLIOP_Endpoint (&(this->ssl_component_),
                                           iiop_endp),
                      -1);

      ssl_endp->priority (priority);
      ssliop_profile->add_endpoint (ssl_endp);
    }

  if (this->orb_core_->orb_params ()->std_profile_components () != 0)
    this->add_csiv2_component (ssliop_profile, 0, this->endpoint_count_);

  return 0;
}

int
TAO::SSLIOP::Acceptor::is_collocated (const TAO_Endpoint *endpoint)
{
  const TAO_SSLIOP_Endpoint *endp =
    dynamic_cast<const TAO_SSLIOP_Endpoint *> (endpoint);

  // Make sure the dynamically cast pointer is valid.
  if (endp == nullptr)
    return 0;

  const TAO_IIOP_Endpoint *iiop = endp->iiop_endpoint ();

  for (size_t i = 0; i < this->endpoint_count_; ++i)
    {
      // Without a plain listener every IIOP port is 0, so the SSL port
      // tells this acceptor's endpoints apart.
      bool const same_port = this->addrs_[i].get_port_number () != 0
        ? iiop->port () == this->addrs_[i].get_port_number ()
        : endp->ssl_component ().port == this->ssl_component_.port;
      if (same_port && ACE_OS::strcmp (iiop->host (), this->hosts_[i]) == 0)
        return 1;
    }

  return 0;
}

int
TAO::SSLIOP::Acceptor::close ()
{
  int r = this->ssl_acceptor_.close ();
  if (this->IIOP_SSL_Acceptor::close () != 0)
    r = -1;

  return r;
}

int
TAO::SSLIOP::Acceptor::open (TAO_ORB_Core *orb_core,
                             ACE_Reactor *reactor,
                             int major,
                             int minor,
                             const char *address,
                             const char *options)
{
  // Ensure that neither the endpoint configuration nor the ORB
  // configuration violate security measures.
  if (this->verify_secure_configuration (orb_core,
                                         major,
                                         minor) != 0)
    return -1;

  ACE_INET_Addr addr;
  ACE_CString specified_hostname;
  if (this->parse_address (address, addr, specified_hostname) == -1)
    return -1;

  // Open the non-SSL enabled endpoints, then open the SSL enabled
  // endpoints.
  if (this->IIOP_SSL_Acceptor::open (orb_core,
                                     reactor,
                                     major,
                                     minor,
                                     address,
                                     options) != 0)
    return -1;

  // The SSL port is set in the parse_options() method. All we have
  // to do is call open_i()
  addr.set_port_number (this->ssl_component_.port);

  return this->ssliop_open_i (orb_core,
                              addr,
                              reactor);
}

int
TAO::SSLIOP::Acceptor::open_default (TAO_ORB_Core *orb_core,
                                     ACE_Reactor *reactor,
                                     int major,
                                     int minor,
                                     const char *options)
{
  // Ensure that neither the endpoint configuration nor the ORB
  // configuration violate security measures.
  if (this->verify_secure_configuration (orb_core,
                                         major,
                                         minor) != 0)
    return -1;

  // Open the non-SSL enabled endpoints, then open the SSL enabled
  // endpoints.
  if (this->IIOP_SSL_Acceptor::open_default (orb_core,
                                             reactor,
                                             major,
                                             minor,
                                             options) == -1)
    return -1;

  // Now that each network interface's hostname has been cached, open
  // an endpoint on each network interface using the INADDR_ANY
  // address.
  ACE_INET_Addr addr;

  // this->ssl_component_.port is initialized to zero or it is set in
  // this->parse_options().
  if (addr.set (this->ssl_component_.port,
                static_cast<ACE_UINT32> (INADDR_ANY),
                1) != 0)
    return -1;

  return this->ssliop_open_i (orb_core,
                              addr,
                              reactor);
}

int
TAO::SSLIOP::Acceptor::ssliop_open_i (TAO_ORB_Core *orb_core,
                                      const ACE_INET_Addr& addr,
                                      ACE_Reactor *reactor)
{
  this->orb_core_ = orb_core;

  ACE_NEW_RETURN (this->creation_strategy_,
                  CREATION_STRATEGY (this->orb_core_),
                  -1);

  ACE_NEW_RETURN (this->concurrency_strategy_,
                  CONCURRENCY_STRATEGY (this->orb_core_),
                  -1);

  ACE_NEW_RETURN (this->accept_strategy_,
                  ACCEPT_STRATEGY (this->orb_core_,
                                   this->timeout_,
                                   this->check_host_),
                  -1);

  u_short requested_port = addr.get_port_number ();
  if (requested_port == 0)
    {
      // don't care, i.e., let the OS choose an ephemeral port
      if (this->ssl_acceptor_.open (addr,
                                    reactor,
                                    this->creation_strategy_,
                                    this->accept_strategy_,
                                    this->concurrency_strategy_,
                                    0, 0, 0, 1,
                                    this->reuse_addr_) == -1)
        {
          if (TAO_debug_level > 0)
            ORBSVCS_DEBUG ((LM_DEBUG,
                        ACE_TEXT ("\n\nTAO (%P|%t) ")
                        ACE_TEXT ("SSLIOP_Acceptor::open_i - %p\n\n"),
                        ACE_TEXT ("cannot open acceptor")));
          return -1;
        }
    }
  else
    {
      ACE_INET_Addr a(addr);

      int found_a_port = 0;
      ACE_UINT32 const last_port = (std::min) (requested_port + this->port_span_ - 1, ACE_MAX_DEFAULT_PORT);

      for (ACE_UINT32 p = requested_port; p <= last_port; p++)
        {
          if (TAO_debug_level > 5)
            ORBSVCS_DEBUG ((LM_DEBUG,
                        ACE_TEXT ("TAO (%P|%t) IIOP_Acceptor::open_i() ")
                        ACE_TEXT ("trying to listen on port %d\n"), p));

          // Now try to actually open on that port
          a.set_port_number ((u_short)p);
          if (this->ssl_acceptor_.open (a,
                                        reactor,
                                        this->creation_strategy_,
                                        this->accept_strategy_,
                                        this->concurrency_strategy_,
                                        0, 0, 0, 1,
                                        this->reuse_addr_) != -1)
            {
              found_a_port = 1;
              break;
            }
        }

      // Now, if we couldn't locate a port, we punt
      if (! found_a_port)
        {
          if (TAO_debug_level > 0)
            ORBSVCS_DEBUG ((LM_DEBUG,
                        ACE_TEXT ("\n\nTAO (%P|%t) ")
                        ACE_TEXT ("SSLIOP_Acceptor::open_i - %p\n\n"),
                        ACE_TEXT ("cannot open acceptor")));
          return -1;
        }
    }

  ACE_INET_Addr ssl_address;

  // We do this to make sure the port number the endpoint is listening
  // on gets set in the addr.
  if (this->ssl_acceptor_.acceptor ().get_local_addr (ssl_address) != 0)
    {
      // @@ Should this be a catastrophic error???
      if (TAO_debug_level > 0)
        ORBSVCS_DEBUG ((LM_DEBUG,
                    ACE_TEXT ("\n\nTAO (%P|%t) ")
                    ACE_TEXT ("SSLIOP_Acceptor::open_i - %p\n\n"),
                    ACE_TEXT ("cannot get local addr")));
      return -1;
    }

  // Reset the SSL endpoint port to the one chosen by the OS (or by
  // the user if provided.
  this->ssl_component_.port = ssl_address.get_port_number ();

  (void) this->ssl_acceptor_.acceptor().enable (ACE_CLOEXEC);
  // This avoids having child processes acquire the listen socket
  // thereby denying the server the opportunity to restart on a
  // well-known endpoint.  This does not affect the aberrent behavior
  // on Win32 platforms.

  if (TAO_debug_level > 5)
    {
      for (size_t i = 0; i < this->endpoint_count_; ++i)
        {
          ORBSVCS_DEBUG ((LM_DEBUG,
                      ACE_TEXT ("TAO (%P|%t) ")
                      ACE_TEXT ("SSLIOP_Acceptor::open_i - ")
                      ACE_TEXT ("listening on: <%C:%u>\n"),
                      this->hosts_[i],
                      this->ssl_component_.port));
        }
    }

  // In the event that an accept() fails, we can examine the reason.  If
  // the reason warrants it, we can try accepting again at a later time.
  // The amount of time we wait to accept again is governed by this orb
  // parameter.
  this->set_error_retry_delay (
    this->orb_core_->orb_params ()->accept_error_delay());

  return 0;
}

int
TAO::SSLIOP::Acceptor::parse_options_i (int &argc, ACE_CString ** argv)
{
  //first, do the base class parser, then parse the leftovers.
  int const result = this->IIOP_SSL_Acceptor::parse_options_i(argc,argv);
  if (result == -1)
    return result;

  // then parse out our own options.
  int i = 0;
  while (i < argc)
    {
      // since the base class has already iterated over the list once,
      // it has vound any ill-formed options. Therefore we don't need
      // to do that again here.
      size_t const slot = argv[i]->find ("=");
      ACE_CString name = argv[i]->substring (0, slot);
      ACE_CString value = argv[i]->substring (slot + 1);

      if (name == "priority")
        {
          ORBSVCS_ERROR_RETURN ((LM_ERROR,
                             ACE_TEXT ("TAO (%P|%t) Invalid SSLIOP endpoint format: ")
                             ACE_TEXT ("endpoint priorities no longer supported.\n"),
                             value.c_str ()),
                            -1);
        }
      else if (ACE_OS::strcmp (name.c_str (), "ssl_port") == 0)
        {
          int ssl_port = ACE_OS::atoi (value.c_str ());

          if (ssl_port >= 0 && ssl_port < 65536)
            this->ssl_component_.port = static_cast<CORBA::UShort> (ssl_port);
          else
            ORBSVCS_ERROR_RETURN ((LM_ERROR,
                               ACE_TEXT ("TAO (%P|%t) Invalid ")
                               ACE_TEXT ("IIOP/SSL endpoint ")
                               ACE_TEXT ("port: <%s>\n"),
                               value.c_str ()),
                              -1);
        }
      else
        {
          // the name is not known, skip to the next option
          i++;
          continue;
        }
      // at the end, we've consumed this argument. Shift the list and
      // put this one on the end. This technique has the effect of
      // putting them in reverse order, but that doesn't matter, since
      // these arguments are only whole strings.
      argc--;
      ACE_CString *temp = argv[i];
      for (int j = i; j <= argc-1; j++)
        argv[j] = argv[j+1];
      argv[argc] = temp;
    }
  return 0;
}

int
TAO::SSLIOP::Acceptor::verify_secure_configuration (TAO_ORB_Core *orb_core,
                                                    int major,
                                                    int minor)
{
  // Sanity check.
  if (major < 1)
    {
      // There is no such thing as IIOP 0.x.
      errno = EINVAL;
      return -1;
    }

  // In order to support a secure connection, the SSLIOP::SSL tagged
  // component must be embedded in the IOR.  This isn't possible if
  // the user elects to disable standard profile components.
  // Similarly, IIOP 1.0 does not support tagged components, which
  // makes it impossible to embed the SSLIOP::SSL tagged component
  // within the IOR.  If the given object explicitly disallows
  // insecure invocations and standard profile components are
  // disabled, then return with an error since secure invocations
  // cannot be supported without standard profile components.
  //
  // Note that it isn't enough to support NoProtection.  NoProtection
  // must be required since "support" does not preclude the secure
  // port from being used.

  if ((orb_core->orb_params ()->std_profile_components () == 0
       || (major == 1 && minor == 0))
      && ACE_BIT_DISABLED (this->ssl_component_.target_requires,
                           ::Security::NoProtection))
    {
      if (TAO_debug_level > 0)
        ORBSVCS_ERROR ((LM_ERROR,
                    ACE_TEXT ("(%P|%t) Cannot support secure ")
                    ACE_TEXT ("IIOP over SSL connection if\n")
                    ACE_TEXT ("(%P|%t) standard profile ")
                    ACE_TEXT ("components are disabled\n")
                    ACE_TEXT ("(%P|%t) or IIOP 1.0 endpoint is ")
                    ACE_TEXT ("used.\n")));

      errno = EINVAL;
      return -1;
    }

  return 0;
}

TAO_END_VERSIONED_NAMESPACE_DECL
