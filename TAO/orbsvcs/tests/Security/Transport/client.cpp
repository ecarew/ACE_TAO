// Transport test client.
//
//   client -k IOR [-n CALLS] [-s SECONDS] [-x]
//          [-m SL3TLS|SL3TLSKeystore -c CERT -K KEY [-p PASSWORD]]
//
// Calls hello() CALLS times, SECONDS apart, printing "CALL i OK" or
// "CALL i EXCEPTION <name>"; -x then asks the server to shut down.  With
// -m it first acquires SecurityLevel3 credentials with that method
// ("ACQUIRE OK" / "ACQUIRE FAILED <name>") and makes the calls with them.

#include "TestC.h"

#include "orbsvcs/SecurityLevel3C.h"
#include "orbsvcs/SSLIOPC.h"

#include "ace/Get_Opt.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_unistd.h"

int
ACE_TMAIN (int argc, ACE_TCHAR *argv[])
{
  try
    {
      CORBA::ORB_var orb = CORBA::ORB_init (argc, argv);
      char const *ior = nullptr;
      char const *method = nullptr;
      char const *cert = nullptr;
      char const *key = nullptr;
      char const *password = "";
      int calls = 1;
      int pause = 0;
      bool shutdown = false;
      ACE_Get_Opt opts (argc, argv, ACE_TEXT ("k:n:s:xm:c:K:p:"));
      for (int c; (c = opts ()) != -1; )
        switch (c)
          {
          case 'k': ior = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          case 'n': calls = ACE_OS::atoi (opts.opt_arg ()); break;
          case 's': pause = ACE_OS::atoi (opts.opt_arg ()); break;
          case 'x': shutdown = true; break;
          case 'm': method = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          case 'c': cert = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          case 'K': key = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          case 'p': password = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          default: break;
          }
      if (ior == nullptr)
        {
          ACE_OS::fprintf (stderr, "usage: client -k IOR [-n CALLS] [-s SECONDS] [-x] [-m METHOD -c CERT -K KEY [-p PW]]\n");
          return 64;
        }

      CORBA::Object_var obj = orb->string_to_object (ior);

      if (method != nullptr)
        {
          try
            {
              obj = orb->resolve_initial_references ("SecurityLevel3:CredentialsCurator");
              SecurityLevel3::CredentialsCurator_var curator =
                SecurityLevel3::CredentialsCurator::_narrow (obj.in ());
              SSLIOP::AuthData data;
              data.certificate.type = SSLIOP::PEM;
              data.certificate.filename = cert;
              data.certificate.password = "";
              data.key.type = SSLIOP::PEM;
              data.key.filename = key;
              data.key.password = password;
              CORBA::Any args;
              args <<= data;
              SecurityLevel3::CredentialsAcquirer_var acquirer = curator->acquire_credentials (method, args);
              SecurityLevel3::OwnCredentials_var creds = acquirer->get_credentials (false);
              ACE_OS::printf ("ACQUIRE OK\n");

              SecurityLevel3::ContextEstablishmentPolicyArgument arg;
              arg.creds_directive = SecurityLevel3::CD_Default;
              arg.creds_list.length (1);
              arg.creds_list[0] = SecurityLevel3::OwnCredentials::_duplicate (creds.in ());
              arg.use_client_auth = SecurityLevel3::FD_Use;
              arg.use_target_auth = SecurityLevel3::FD_Use;
              arg.use_confidentiality = SecurityLevel3::FD_Use;
              arg.use_integrity = SecurityLevel3::FD_Use;
              CORBA::Any any;
              any <<= arg;
              CORBA::PolicyList policies (1);
              policies.length (1);
              policies[0] = orb->create_policy (SecurityLevel3::ContextEstablishmentPolicyType, any);
              obj = orb->string_to_object (ior);
              obj = obj->_set_policy_overrides (policies, CORBA::ADD_OVERRIDE);
              policies[0]->destroy ();
            }
          catch (CORBA::Exception const &ex)
            {
              ACE_OS::printf ("ACQUIRE FAILED %s\n", ex._name ());
              orb->destroy ();
              return 0;
            }
        }

      Ping_var ping = Ping::_narrow (obj.in ());
      if (CORBA::is_nil (ping.in ()))
        {
          // The reference was reached (_narrow asked the server) but is
          // not a Ping: the TLS session worked.
          ACE_OS::printf ("NOT A PING\n");
          orb->destroy ();
          return 0;
        }
      for (int i = 1; i <= calls; ++i)
        {
          if (i > 1 && pause > 0)
            ACE_OS::sleep (pause);
          try
            {
              ping->hello ();
              ACE_OS::printf ("CALL %d OK\n", i);
            }
          catch (CORBA::Exception const &ex)
            {
              ACE_OS::printf ("CALL %d EXCEPTION %s\n", i, ex._name ());
            }
          ACE_OS::fflush (stdout);
        }
      if (shutdown)
        ping->shutdown ();
      orb->destroy ();
    }
  catch (CORBA::Exception const &ex)
    {
      ACE_OS::printf ("CLIENT EXCEPTION %s\n", ex._name ());
      return 1;
    }
  return 0;
}
