// CSIv2_IOR test tool: shows and rewrites the security components of an
// object reference.  It loads no SSLIOP factory, so profiles are decoded
// as plain IIOP and their tagged components are left as they are.
//
//   ior_tool -k IOR                 print each profile's components
//   ior_tool -k IOR -s -o FILE      write the reference without
//                                   TAG_SSL_SEC_TRANS (a CSIv2-only server)
//   ior_tool -k IOR -p -o FILE      write it with every TAG_TLS_SEC_TRANS
//                                   port one higher (tag 20 disagrees)

#include "orbsvcs/CSIIOPC.h"
#include "orbsvcs/SSLIOPC.h"

#include "tao/IIOP_Profile.h"
#include "tao/IIOP_Endpoint.h"
#include "tao/MProfile.h"
#include "tao/Stub.h"
#include "tao/Tagged_Components.h"
#include "tao/CDR.h"

#include "ace/Get_Opt.h"
#include "ace/OS_NS_stdio.h"

#include <string>
#include "ace/OS_NS_string.h"

namespace
{
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

  template <typename T, typename SEQ>
  bool
  encapsulate (T const &value, SEQ &out)
  {
    TAO_OutputCDR cdr;
    if (!(cdr << TAO_OutputCDR::from_boolean (TAO_ENCAP_BYTE_ORDER)) || !(cdr << value))
      return false;
    out.length (static_cast<CORBA::ULong> (cdr.total_length ()));
    CORBA::Octet *buf = out.get_buffer ();
    for (ACE_Message_Block const *mb = cdr.begin (); mb != nullptr; mb = mb->cont ())
      {
        ACE_OS::memcpy (buf, mb->rd_ptr (), mb->length ());
        buf += mb->length ();
      }
    return true;
  }

  void
  show (TAO_Profile *p, CORBA::ULong n)
  {
    TAO_IIOP_Profile *const iiop = dynamic_cast<TAO_IIOP_Profile *> (p);
    TAO_IIOP_Endpoint *const ep = iiop != nullptr ? dynamic_cast<TAO_IIOP_Endpoint *> (iiop->endpoint ()) : nullptr;
    ACE_OS::printf ("PROFILE %u host=%s iiop_port=%u\n", n, ep != nullptr ? ep->host () : "?",
                    ep != nullptr ? static_cast<unsigned> (ep->port ()) : 0u);

    IOP::TaggedComponent c;
    c.tag = ::SSLIOP::TAG_SSL_SEC_TRANS;
    ::SSLIOP::SSL ssl;
    if (p->tagged_components ().get_component (c) && decapsulate (c.component_data, ssl))
      ACE_OS::printf ("  TAG_SSL_SEC_TRANS port=%u supports=0x%x requires=0x%x\n", static_cast<unsigned> (ssl.port),
                      static_cast<unsigned> (ssl.target_supports), static_cast<unsigned> (ssl.target_requires));

    c.tag = IOP::TAG_CSI_SEC_MECH_LIST;
    CSIIOP::CompoundSecMechList list;
    if (!p->tagged_components ().get_component (c))
      return;
    if (!decapsulate (c.component_data, list))
      {
        ACE_OS::printf ("  TAG_CSI_SEC_MECH_LIST undecodable\n");
        return;
      }
    ACE_OS::printf ("  TAG_CSI_SEC_MECH_LIST stateful=%d mechanisms=%u\n", list.stateful ? 1 : 0,
                    list.mechanism_list.length ());
    for (CORBA::ULong i = 0; i < list.mechanism_list.length (); ++i)
      {
        CSIIOP::CompoundSecMech const &m = list.mechanism_list[i];
        ACE_OS::printf ("    MECH %u requires=0x%x transport=%u\n", i, static_cast<unsigned> (m.target_requires),
                        static_cast<unsigned> (m.transport_mech.tag));
        CSIIOP::TLS_SEC_TRANS tls;
        if (m.transport_mech.tag == CSIIOP::TAG_TLS_SEC_TRANS && decapsulate (m.transport_mech.component_data, tls))
          {
            ACE_OS::printf ("      TLS supports=0x%x requires=0x%x addresses=", static_cast<unsigned> (tls.target_supports),
                            static_cast<unsigned> (tls.target_requires));
            for (CORBA::ULong a = 0; a < tls.addresses.length (); ++a)
              ACE_OS::printf ("%s%s:%u", a == 0 ? "" : ",", tls.addresses[a].host_name.in (),
                              static_cast<unsigned> (tls.addresses[a].port));
            ACE_OS::printf ("\n");
          }
        ACE_OS::printf ("      AS supports=0x%x requires=0x%x mech_octets=%u\n",
                        static_cast<unsigned> (m.as_context_mech.target_supports),
                        static_cast<unsigned> (m.as_context_mech.target_requires),
                        m.as_context_mech.client_authentication_mech.length ());
        {
          // The GSSUP target name, printable octets as they are, others
          // as \xNN (an exported name starts with 04 01).
          std::string t;
          CSI::GSS_NT_ExportedName const &n = m.as_context_mech.target_name;
          for (CORBA::ULong k = 0; k < n.length (); ++k)
            {
              char buf[8];
              if (n[k] >= 0x20 && n[k] < 0x7F && n[k] != '\\')
                t += static_cast<char> (n[k]);
              else
                {
                  ACE_OS::snprintf (buf, sizeof buf, "\\x%02x", static_cast<unsigned> (n[k]));
                  t += buf;
                }
            }
          ACE_OS::printf ("        target_name=%s\n", t.empty () ? "(empty)" : t.c_str ());
        }
        ACE_OS::printf ("      SAS supports=0x%x requires=0x%x identity_types=0x%x\n",
                        static_cast<unsigned> (m.sas_context_mech.target_supports),
                        static_cast<unsigned> (m.sas_context_mech.target_requires),
                        static_cast<unsigned> (m.sas_context_mech.supported_identity_types));
      }
  }

  /// Every TAG_TLS_SEC_TRANS port one higher.
  bool
  bump_tls_ports (TAO_Profile *p)
  {
    IOP::TaggedComponent c;
    c.tag = IOP::TAG_CSI_SEC_MECH_LIST;
    CSIIOP::CompoundSecMechList list;
    if (!p->tagged_components ().get_component (c) || !decapsulate (c.component_data, list))
      return false;
    for (CORBA::ULong i = 0; i < list.mechanism_list.length (); ++i)
      {
        CSIIOP::CompoundSecMech &m = list.mechanism_list[i];
        CSIIOP::TLS_SEC_TRANS tls;
        if (m.transport_mech.tag != CSIIOP::TAG_TLS_SEC_TRANS || !decapsulate (m.transport_mech.component_data, tls))
          continue;
        for (CORBA::ULong a = 0; a < tls.addresses.length (); ++a)
          tls.addresses[a].port = static_cast<CORBA::UShort> (tls.addresses[a].port + 1);
        if (!encapsulate (tls, m.transport_mech.component_data))
          return false;
      }
    if (!encapsulate (list, c.component_data))
      return false;
    // set_component() adds a second component with the same tag; replace it.
    p->tagged_components ().remove_component (IOP::TAG_CSI_SEC_MECH_LIST);
    p->tagged_components ().set_component (c);
    return true;
  }
}

int
ACE_TMAIN (int argc, ACE_TCHAR *argv[])
{
  try
    {
      CORBA::ORB_var orb = CORBA::ORB_init (argc, argv);
      char const *ior = nullptr;
      char const *out = nullptr;
      bool strip = false;
      bool bump = false;
      ACE_Get_Opt opts (argc, argv, ACE_TEXT ("k:o:sp"));
      for (int c; (c = opts ()) != -1; )
        switch (c)
          {
          case 'k': ior = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          case 'o': out = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          case 's': strip = true; break;
          case 'p': bump = true; break;
          default: break;
          }
      if (ior == nullptr || ((strip || bump) && out == nullptr))
        {
          ACE_OS::fprintf (stderr, "usage: ior_tool -k IOR [-s | -p] [-o FILE]\n");
          return 64;
        }

      CORBA::Object_var obj = orb->string_to_object (ior);
      TAO_MProfile &profiles = obj->_stubobj ()->base_profiles ();
      for (CORBA::ULong i = 0; i < profiles.profile_count (); ++i)
        {
          TAO_Profile *const p = profiles.get_profile (i);
          if (strip)
            p->tagged_components ().remove_component (::SSLIOP::TAG_SSL_SEC_TRANS);
          else if (bump && !bump_tls_ports (p))
            {
              ACE_OS::fprintf (stderr, "profile %u has no TAG_TLS_SEC_TRANS\n", i);
              return 1;
            }
          else if (!strip && !bump)
            show (p, i);
        }

      if (out != nullptr)
        {
          CORBA::String_var s = orb->object_to_string (obj.in ());
          FILE *const fp = ACE_OS::fopen (out, ACE_TEXT ("w"));
          if (fp == nullptr)
            return 1;
          ACE_OS::fprintf (fp, "%s", s.in ());
          ACE_OS::fclose (fp);
          ACE_OS::printf ("WROTE %s\n", out);
        }
      orb->destroy ();
    }
  catch (CORBA::Exception const &ex)
    {
      ex._tao_print_exception ("ior_tool");
      return 1;
    }
  return 0;
}
