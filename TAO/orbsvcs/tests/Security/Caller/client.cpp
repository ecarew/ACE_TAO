// Caller test client.
//
//   client -k IOR -c whoami|poke|shutdown
//
// Prints "WHOAMI <what the servant saw>", "POKE OK", or
// "<OPERATION> EXCEPTION <name>".

#include "TestC.h"

#include "ace/Get_Opt.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_string.h"

int
ACE_TMAIN (int argc, ACE_TCHAR *argv[])
{
  char const *what = "whoami";
  try
    {
      CORBA::ORB_var orb = CORBA::ORB_init (argc, argv);
      char const *ior = nullptr;
      ACE_Get_Opt opts (argc, argv, ACE_TEXT ("k:c:"));
      for (int c; (c = opts ()) != -1; )
        switch (c)
          {
          case 'k': ior = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          case 'c': what = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          default: break;
          }
      if (ior == nullptr)
        {
          ACE_OS::fprintf (stderr, "usage: client -k IOR -c whoami|poke|shutdown\n");
          return 64;
        }

      CORBA::Object_var obj = orb->string_to_object (ior);
      Who_var who = Who::_unchecked_narrow (obj.in ());
      try
        {
          if (ACE_OS::strcmp (what, "poke") == 0)
            {
              who->poke ();
              ACE_OS::printf ("POKE OK\n");
            }
          else if (ACE_OS::strcmp (what, "shutdown") == 0)
            {
              who->shutdown ();
              ACE_OS::printf ("SHUTDOWN SENT\n");
            }
          else
            {
              CORBA::String_var s = who->whoami ();
              ACE_OS::printf ("WHOAMI %s\n", s.in ());
            }
        }
      catch (CORBA::Exception const &ex)
        {
          ACE_OS::printf ("%s EXCEPTION %s\n", what, ex._name ());
        }
      orb->destroy ();
    }
  catch (CORBA::Exception const &ex)
    {
      ex._tao_print_exception ("client");
      return 1;
    }
  return 0;
}
