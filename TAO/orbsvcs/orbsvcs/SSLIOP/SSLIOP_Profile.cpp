#include "orbsvcs/Log_Macros.h"
#include "orbsvcs/SSLIOP/SSLIOP_Profile.h"
#include "orbsvcs/SSLIOP/ssl_endpointsC.h"
#include "orbsvcs/Security/Audit_Logger.h"
#include "orbsvcs/CSIIOPC.h"
#include "tao/CDR.h"
#include "tao/debug.h"
#include "ace/OS_NS_string.h"

#include <string>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

TAO_SSLIOP_Profile::TAO_SSLIOP_Profile (const ACE_INET_Addr & addr,
                               const TAO::ObjectKey & object_key,
                               const TAO_GIOP_Message_Version & version,
                               TAO_ORB_Core * orb_core,
                               const ::SSLIOP::SSL * ssl_component)
  : TAO_IIOP_Profile (addr,
                      object_key,
                      version,
                      orb_core),
  ssl_endpoint_ (ssl_component, nullptr),
  ssl_only_ (0)
{
  this->ssl_endpoint_.iiop_endpoint (&this->endpoint_, true);
}

TAO_SSLIOP_Profile::TAO_SSLIOP_Profile (const char * host,
                               CORBA::UShort port,
                               const TAO::ObjectKey & object_key,
                               const ACE_INET_Addr & addr,
                               const TAO_GIOP_Message_Version & version,
                               TAO_ORB_Core * orb_core,
                               const ::SSLIOP::SSL * ssl_component)
  : TAO_IIOP_Profile (host,
                      port,
                      object_key,
                      addr,
                      version,
                      orb_core),
  ssl_endpoint_ (ssl_component, nullptr),
  ssl_only_ (0)
{
  this->ssl_endpoint_.iiop_endpoint (&this->endpoint_, true);
}

TAO_SSLIOP_Profile::TAO_SSLIOP_Profile (TAO_ORB_Core * orb_core,
                               const ::SSLIOP::SSL * ssl_component)
  : TAO_IIOP_Profile (orb_core),
    ssl_endpoint_ (ssl_component, nullptr),
    ssl_only_ (0)
{
  this->ssl_endpoint_.iiop_endpoint (&this->endpoint_, true);
}

TAO_SSLIOP_Profile::TAO_SSLIOP_Profile (TAO_ORB_Core * orb_core, int ssl_only)
  : TAO_IIOP_Profile (orb_core),
    ssl_endpoint_ (nullptr, nullptr),
    ssl_only_ (ssl_only)
{
  this->ssl_endpoint_.iiop_endpoint (&this->endpoint_, true);
}

TAO_SSLIOP_Profile::~TAO_SSLIOP_Profile ()
{
  // Clean up the list of endpoints since we own it.
  // Skip the head, since it is not dynamically allocated.
  TAO_Endpoint *tmp = nullptr;

  for (TAO_Endpoint *next = this->ssl_endpoint_.next ();
       next != nullptr;
       next = tmp)
    {
      tmp = next->next ();
      delete next;
    }
}

// return codes:
// -1 -> error
//  0 -> can't understand this version
//  1 -> success.
int
TAO_SSLIOP_Profile::decode (TAO_InputCDR & cdr)
{
  int const r = this->decode_ssl (cdr);
  if (r != 1)
    return r;
  return this->apply_csiv2 () == 0 ? 1 : -1;
}

namespace
{
  /// Decodes the encapsulation @a data into @a value.
  template <typename T, typename SEQ>
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
}

int
TAO_SSLIOP_Profile::apply_csiv2 ()
{
  IOP::TaggedComponent mechs;
  mechs.tag = IOP::TAG_CSI_SEC_MECH_LIST;
  if (!this->tagged_components ().get_component (mechs))
    return 0;

  // The first compound mechanism whose transport is TLS.
  CSIIOP::CompoundSecMechList list;
  if (!decapsulate (mechs.component_data, list))
    {
      if (TAO_debug_level > 0)
        ORBSVCS_DEBUG ((LM_DEBUG, ACE_TEXT ("TAO (%P|%t) - SSLIOP_Profile: ")
                                  ACE_TEXT ("undecodable TAG_CSI_SEC_MECH_LIST ignored\n")));
      return 0;
    }
  CSIIOP::TLS_SEC_TRANS tls;
  bool found = false;
  for (CORBA::ULong i = 0; !found && i < list.mechanism_list.length (); ++i)
    if (list.mechanism_list[i].transport_mech.tag == CSIIOP::TAG_TLS_SEC_TRANS)
      found = decapsulate (list.mechanism_list[i].transport_mech.component_data, tls);
  if (!found || tls.addresses.length () == 0)
    return 0;

  IOP::TaggedComponent ssl;
  ssl.tag = ::SSLIOP::TAG_SSL_SEC_TRANS;
  if (this->tagged_components ().get_component (ssl))
    {
      // Both: a TAO server.  The TLS port they name must be the same.
      CORBA::UShort const port = this->ssl_endpoint_.ssl_component_.port;
      std::string ports;
      for (CORBA::ULong i = 0; i < tls.addresses.length (); ++i)
        {
          if (tls.addresses[i].port == port)
            return 0;
          ports += (ports.empty () ? "" : ",") + std::to_string (tls.addresses[i].port);
        }
      TAO::Security::Audit_Logger::instance ()->write (
        TAO::Security::Audit_Record ("ior", false, TAO::Security::Audit_Reason::IOR_TLS_MISMATCH)
          .field ("host", this->endpoint_.host ())
          .field ("ssl_port", std::to_string (port))
          .field ("tls_sec_trans_ports", ports));
      return -1;
    }

  // CSIv2 only: each endpoint takes the TLS address for its host; the
  // only endpoint of a profile takes the first address, host and all.
  for (TAO_SSLIOP_Endpoint *ep = &this->ssl_endpoint_; ep != nullptr; ep = ep->next_)
    {
      TAO_IIOP_Endpoint *const iiop = ep->iiop_endpoint ();
      if (iiop == nullptr)
        continue;
      CORBA::ULong match = tls.addresses.length ();
      for (CORBA::ULong i = 0; i < tls.addresses.length (); ++i)
        if (ACE_OS::strcmp (tls.addresses[i].host_name.in (), iiop->host ()) == 0)
          {
            match = i;
            break;
          }
      if (match == tls.addresses.length ())
        {
          if (this->count_ > 1)
            continue;
          match = 0;
          iiop->host (tls.addresses[0].host_name.in ());
        }
      ep->ssl_component_.port = tls.addresses[match].port;
      ep->ssl_component_.target_supports = tls.target_supports;
      ep->ssl_component_.target_requires = tls.target_requires;
      // A TLS endpoint: never fall back to the plain port.
      ACE_CLR_BITS (ep->ssl_component_.target_supports, ::Security::NoProtection);
    }
  return 0;
}

int
TAO_SSLIOP_Profile::decode_ssl (TAO_InputCDR & cdr)
{
  int r = this->TAO_IIOP_Profile::decode (cdr);
  if (r != 1)
    return r;

  // Attempt to decode SSLIOP::SSL tagged component.  It may not be
  // there if we are dealing with pure IIOP profile.
  int ssl_component_found = 0;
  IOP::TaggedComponent component;
  component.tag = ::SSLIOP::TAG_SSL_SEC_TRANS;

  if (this->tagged_components ().get_component (component))
    {
      TAO_InputCDR cdr_component (reinterpret_cast<char const *> (component.component_data.get_buffer ()),
                                  component.component_data.length ());
      CORBA::Boolean byte_order;
      if ((cdr_component >> ACE_InputCDR::to_boolean (byte_order)) == 0)
        return -1;
      cdr_component.reset_byte_order (static_cast<int> (byte_order));

      if (cdr_component >> this->ssl_endpoint_.ssl_component_)
        ssl_component_found = 1;
      else
        return -1;
    }

  // Since IIOP portion of the profile has already been decoded, we
  // know how many endpoints it should contain and can finish
  // initialization accordingly.
  if (this->count_ < 2)
    {
      // This profile contains only one endpoint.  Finish initializing
      // it.
      this->ssl_endpoint_.iiop_endpoint (&this->endpoint_, true);
      this->ssl_endpoint_.priority (this->endpoint_.priority ());
      return 1;
    }
  else
    {
      // This profile contains more than one endpoint.
      if (ssl_component_found)
        {
          // It is true ssl profile, i.e., not just IIOP, so must have
          // ssl endpoints encoded.

          if (this->decode_tagged_endpoints () == -1)
            return -1;

          return 1;
        }
      else
        {
          // IIOP profile - doesn't have ssl endpoints encoded.  We
          // must create 'dummy' ssl endpoint list anyways, in order to
          // make iiop endpoints accessable and usable. Since we've
          // already got one ssliop endpoint, only add the extra
          // endpoints (count_ - 1).
          for (size_t i = 0;
               i < this->count_ -1;
               ++i)
            {
              TAO_SSLIOP_Endpoint *endpoint = nullptr;
              ACE_NEW_RETURN (endpoint,
                              TAO_SSLIOP_Endpoint (nullptr, nullptr),
                              -1);
              this->add_endpoint (endpoint);
            }

          // Now that we have a complete list of ssl endpoins, we can
          // connect them with their iiop counterparts.
          TAO_IIOP_Endpoint *iiop_endp = &this->endpoint_;

          for (TAO_SSLIOP_Endpoint * ssl_endp = &this->ssl_endpoint_;
               ssl_endp != nullptr;
               ssl_endp = ssl_endp->next_)
            {
              ssl_endp->iiop_endpoint (iiop_endp, true);
              ssl_endp->priority (iiop_endp->priority ());
              iiop_endp = iiop_endp->next_;
            }

          return 1;
        }
    }
}

CORBA::Boolean
TAO_SSLIOP_Profile::do_is_equivalent (const TAO_Profile * other_profile)
{
  const TAO_SSLIOP_Profile *op =
    dynamic_cast<const TAO_SSLIOP_Profile *> (other_profile);

  // Make sure we have a TAO_SSLIOP_Profile.
  if (op == nullptr)
    return 0;

  // Now verify TAO_SSLIOP_Endpoint equivalence.
  const TAO_SSLIOP_Endpoint *other_endp = &op->ssl_endpoint_;
  for (TAO_SSLIOP_Endpoint *endp = &this->ssl_endpoint_;
       endp != nullptr;
       endp = endp->next_)
    {
      if (endp->is_equivalent (other_endp))
        other_endp = other_endp->next_;
      else
        return 0;
    }

  return 1;
}

TAO_Endpoint*
TAO_SSLIOP_Profile::endpoint ()
{
  return &this->ssl_endpoint_;
}

void
TAO_SSLIOP_Profile::add_endpoint (TAO_SSLIOP_Endpoint * endp)
{
  endp->next_ = this->ssl_endpoint_.next_;
  this->ssl_endpoint_.next_ = endp;

  // We do not want to add our IIOP endpoint counterpart when we are
  // decoding a profile, and IIOP endpoints have been added before we
  // even get to SSLIOP-specific decoding.
  if (endp->iiop_endpoint () != nullptr)
    this->TAO_IIOP_Profile::add_endpoint (endp->iiop_endpoint ());
}

int
TAO_SSLIOP_Profile::encode_endpoints ()
{
  // If we have more than one endpoint, we encode info about others
  // into a tagged component for wire transfer.
  if (this->count_ > 1)
    {
      // Encode all endpoints except the first one, since it is always
      // transferred through standard profile component.

      // Create a data structure and fill it with endpoint info for wire
      // transfer.
      TAO_SSLEndpointSequence endpoints;
      endpoints.length (this->count_ - 1);

      const TAO_SSLIOP_Endpoint *endpoint = this->ssl_endpoint_.next_;
      for (CORBA::ULong i = 0; i < this->count_ - 1; ++i)
        {
          endpoints[i] = endpoint->ssl_component ();
          endpoint = endpoint->next_;
        }

      // Encode the data structure.
      TAO_OutputCDR out_cdr;
      if (((out_cdr << ACE_OutputCDR::from_boolean (TAO_ENCAP_BYTE_ORDER))
           == 0)
          || (out_cdr << endpoints) == 0)
        return -1;

      CORBA::ULong const length = static_cast<CORBA::ULong> (out_cdr.total_length ());

      IOP::TaggedComponent tagged_component;
      tagged_component.tag = TAO::TAG_SSL_ENDPOINTS;
      tagged_component.component_data.length (length);
      CORBA::Octet *buf =
        tagged_component.component_data.get_buffer ();

      for (const ACE_Message_Block *iterator = out_cdr.begin ();
           iterator != nullptr;
           iterator = iterator->cont ())
        {
          CORBA::ULong const i_length = static_cast<CORBA::ULong> (iterator->length ());
          ACE_OS::memcpy (buf, iterator->rd_ptr (), i_length);

          buf += i_length;
        }

      // Add component with encoded endpoint data to this profile's
      // TaggedComponents.
      tagged_components_.set_component (tagged_component);
    }

  return this->TAO_IIOP_Profile::encode_endpoints ();
}

int
TAO_SSLIOP_Profile::decode_tagged_endpoints ()
{
  IOP::TaggedComponent tagged_component;
  tagged_component.tag = TAO::TAG_SSL_ENDPOINTS;

  if (this->tagged_components_.get_component (tagged_component))
    {
      const CORBA::Octet *buf =
        tagged_component.component_data.get_buffer ();

      TAO_InputCDR in_cdr (reinterpret_cast<const char* > (buf),
                           tagged_component.component_data.length ());

      // Extract the Byte Order.
      CORBA::Boolean byte_order;
      if ((in_cdr >> ACE_InputCDR::to_boolean (byte_order)) == 0)
        return -1;
      in_cdr.reset_byte_order (static_cast<int> (byte_order));

      // Extract endpoints sequence.
      TAO_SSLEndpointSequence endpoints;
      if ((in_cdr >> endpoints) == 0)
        return -1;

      // Use information extracted from the tagged component to
      // populate the profile.  Begin from the end of the sequence to
      // preserve endpoint order, since <add_endpoint> method reverses
      // the order of endpoints in the list.
      for (CORBA::ULong i = endpoints.length () - 1;
           (i + 1) != 0;
           --i)
        {
          TAO_SSLIOP_Endpoint *endpoint = nullptr;
          ACE_NEW_RETURN (endpoint,
                          TAO_SSLIOP_Endpoint (nullptr, nullptr),
                          -1);
          endpoint->ssl_component_ = endpoints[i];
          this->add_endpoint (endpoint);
        }

      // Now that we have a complete list of ssl endpoins, we can
      // connect them with their iiop counterparts, which have been
      // extracted/chained during the IIOP profile decoding.
      TAO_IIOP_Endpoint *iiop_endp = &this->endpoint_;

      for (TAO_SSLIOP_Endpoint * ssl_endp = &this->ssl_endpoint_;
           ssl_endp != nullptr;
           ssl_endp = ssl_endp->next_)
        {
          ssl_endp->iiop_endpoint (iiop_endp, true);
          ssl_endp->priority (iiop_endp->priority ());
          iiop_endp = iiop_endp->next_;
        }

      return 0;
    }

  // Since this method is only called if we are expecting
  // TAO_TAG_SSL_ENDPOINTS component, failure to find it is an error.
  return -1;
}

void
TAO_SSLIOP_Profile::parse_string (const char * ior)
{
   TAO_IIOP_Profile::parse_string (ior);

   this->ssl_endpoint_.iiop_endpoint (&this->endpoint_, true);

   if( ssl_only_)
   {
      this->ssl_endpoint_.ssl_component_.port = this->endpoint_.port_;

      // Note that the Security::NoProtection bit is cleared since we
      // are sure the server supports SSL (we're told so)
      ACE_CLR_BITS (this->ssl_endpoint_.ssl_component_.target_supports,
            Security::NoProtection);
   }
}


void
TAO_SSLIOP_Profile::remove_endpoint (TAO_SSLIOP_Endpoint *endp)
{
  if (endp == nullptr)
    return;

  // special handling for the target matching the base endpoint
  if (endp == &this->ssl_endpoint_)
    {
      if (--this->count_ > 0)
        {
          TAO_SSLIOP_Endpoint* ssl_n = this->ssl_endpoint_.next_;
          this->ssl_endpoint_ = *ssl_n;
          // since the assignment operator does not copy the next_
          // pointer, we must do it by hand
          this->ssl_endpoint_.next_ = ssl_n->next_;
          delete ssl_n;
          TAO_IIOP_Endpoint *n = this->endpoint_.next_;
          this->endpoint_ = *n;
          this->endpoint_.next_ = n->next_;
          delete n;
        }
      return;
    }

  TAO_SSLIOP_Endpoint* last = &this->ssl_endpoint_;
  TAO_SSLIOP_Endpoint* cur = this->ssl_endpoint_.next_;

  while (cur != nullptr)
  {
    if (cur == endp)
      break;
    last = cur;
    cur = cur->next_;
  }

  if (cur != nullptr)
  {
    TAO_IIOP_Endpoint *base = cur->iiop_endpoint();
    last->iiop_endpoint(base->next_, true);
    last->next_ = cur->next_;
    cur->next_ = nullptr;
    --this->count_;
    delete cur;
  }
}

void
TAO_SSLIOP_Profile::remove_generic_endpoint (TAO_Endpoint *ep)
{
  this->remove_endpoint(dynamic_cast<TAO_SSLIOP_Endpoint *>(ep));
}

TAO_END_VERSIONED_NAMESPACE_DECL
