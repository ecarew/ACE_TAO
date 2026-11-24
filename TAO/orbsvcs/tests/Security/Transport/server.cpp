// Transport test server: a Ping object over SSLIOP.  Writes its IOR to
// the file given with -o and prints the ports its reference advertises
// ("PORTS iiop=N ssl=M"), so the test can see that prod opens no plain
// IIOP listener.

#include "TestS.h"

#include "orbsvcs/SSLIOP/SSLIOP_Endpoint.h"
#include "tao/Stub.h"
#include "tao/Profile.h"
#include "tao/MProfile.h"

#include "ace/Get_Opt.h"
#include "ace/OS_NS_stdio.h"

namespace
{
  class Ping_i : public virtual POA_Ping
  {
  public:
    explicit Ping_i (CORBA::ORB_ptr orb) : orb_ (CORBA::ORB::_duplicate (orb)) {}
    void hello () override {}
    void shutdown () override { this->orb_->shutdown (false); }

  private:
    CORBA::ORB_var orb_;
  };
}

int
ACE_TMAIN (int argc, ACE_TCHAR *argv[])
{
  try
    {
      CORBA::ORB_var orb = CORBA::ORB_init (argc, argv);
      char const *ior_file = "server.ior";
      ACE_Get_Opt opts (argc, argv, ACE_TEXT ("o:"));
      for (int c; (c = opts ()) != -1; )
        if (c == 'o')
          ior_file = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ());

      CORBA::Object_var obj = orb->resolve_initial_references ("RootPOA");
      PortableServer::POA_var poa = PortableServer::POA::_narrow (obj.in ());
      PortableServer::POAManager_var mgr = poa->the_POAManager ();
      PortableServer::Servant_var<Ping_i> servant = new Ping_i (orb.in ());
      PortableServer::ObjectId_var id = poa->activate_object (servant.in ());
      obj = poa->id_to_reference (id.in ());

      TAO_Profile *const profile = obj->_stubobj ()->base_profiles ().get_profile (0);
      TAO_SSLIOP_Endpoint const *const ep = dynamic_cast<TAO_SSLIOP_Endpoint const *> (profile->endpoint ());
      if (ep != nullptr)
        ACE_OS::printf ("PORTS iiop=%u ssl=%u\n", static_cast<unsigned> (ep->iiop_endpoint ()->port ()),
                        static_cast<unsigned> (ep->ssl_component ().port));

      CORBA::String_var ior = orb->object_to_string (obj.in ());
      FILE *const fp = ACE_OS::fopen (ior_file, ACE_TEXT ("w"));
      if (fp == nullptr)
        return 1;
      ACE_OS::fprintf (fp, "%s", ior.in ());
      ACE_OS::fclose (fp);
      ACE_OS::printf ("SERVER READY\n");
      ACE_OS::fflush (stdout);

      mgr->activate ();
      orb->run ();
      orb->destroy ();
    }
  catch (CORBA::INITIALIZE const &ex)
    {
      ACE_OS::printf ("ORB_INIT REFUSED: %s\n", ex._name ());
      return 2;
    }
  catch (CORBA::Exception const &ex)
    {
      ex._tao_print_exception ("server");
      return 1;
    }
  return 0;
}
