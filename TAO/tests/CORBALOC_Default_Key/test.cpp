// Parses corbaloc URLs with several addresses and checks the profiles they
// produce.  Nothing is contacted: string_to_object only builds the stub.
//
// TAO_Connector::corbaloc_scan computed a garbage address length when a
// URL had more than one address but no object key (default "NameService"),
// e.g. corbaloc::host1:2809,:host2:2809, and the ORB crashed.  corbaname
// URLs with several addresses and no key went through the same code.

#include "tao/ORB.h"
#include "tao/Object.h"
#include "tao/Stub.h"
#include "tao/MProfile.h"
#include "tao/Profile.h"
#include "tao/IIOP_Endpoint.h"
#include "tao/SystemException.h"
#include "ace/Log_Msg.h"
#include "ace/OS_NS_string.h"

namespace
{
  struct Case
  {
    const char *url;
    CORBA::ULong profiles;
    const char *key;
    u_short ports[3];
  };

  const Case cases[] = {
    { "corbaloc::127.0.0.1:1111,:127.0.0.1:2222", 2, "NameService", { 1111, 2222, 0 } },
    { "corbaloc::127.0.0.1:1111,:127.0.0.1:2222,:127.0.0.1:3333", 3, "NameService", { 1111, 2222, 3333 } },
    { "corbaloc:iiop:127.0.0.1:1111,iiop:127.0.0.1:2222/Key", 2, "Key", { 1111, 2222, 0 } },
    { "corbaloc::127.0.0.1:1111,:127.0.0.1:2222/a/b", 2, "a/b", { 1111, 2222, 0 } },
    { "corbaloc::127.0.0.1:1111", 1, "NameService", { 1111, 0, 0 } },
    { "corbaloc::127.0.0.1:1111/Key", 1, "Key", { 1111, 0, 0 } },
  };

  int check (CORBA::ORB_ptr orb, const Case &c)
  {
    CORBA::Object_var obj = orb->string_to_object (c.url);
    TAO_MProfile &mp = obj->_stubobj ()->base_profiles ();
    int errors = 0;

    if (mp.profile_count () != c.profiles)
      {
        ACE_ERROR ((LM_ERROR, "ERROR: <%C>: %u profiles, expected %u\n",
                    c.url, mp.profile_count (), c.profiles));
        return 1;
      }

    for (CORBA::ULong i = 0; i < c.profiles; ++i)
      {
        TAO_Profile *p = mp.get_profile (i);
        const TAO::ObjectKey &k = p->object_key ();
        if (k.length () != ACE_OS::strlen (c.key)
            || ACE_OS::memcmp (k.get_buffer (), c.key, k.length ()) != 0)
          {
            ACE_ERROR ((LM_ERROR, "ERROR: <%C>: profile %u has the wrong object key\n",
                        c.url, i));
            ++errors;
          }
        TAO_IIOP_Endpoint *ep = dynamic_cast<TAO_IIOP_Endpoint *> (p->endpoint ());
        if (ep == nullptr || ep->port () != c.ports[i])
          {
            ACE_ERROR ((LM_ERROR, "ERROR: <%C>: profile %u port %d, expected %d\n",
                        c.url, i, ep ? ep->port () : -1, c.ports[i]));
            ++errors;
          }
      }
    return errors;
  }
}

int
ACE_TMAIN (int argc, ACE_TCHAR *argv[])
{
  int errors = 0;
  try
    {
      CORBA::ORB_var orb = CORBA::ORB_init (argc, argv);
      for (const Case &c : cases)
        errors += check (orb.in (), c);
      orb->destroy ();
    }
  catch (const CORBA::Exception &ex)
    {
      ex._tao_print_exception ("ERROR: CORBALOC_Default_Key");
      return 1;
    }

  if (errors == 0)
    ACE_DEBUG ((LM_DEBUG, "CORBALOC_Default_Key: passed\n"));
  return errors == 0 ? 0 : 1;
}
