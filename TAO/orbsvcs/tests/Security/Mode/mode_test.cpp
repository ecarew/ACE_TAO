// Test of the host security mode: the ORB_init guard in libTAO
// (tao/Security_Mode.h) and the Security library's self-check and
// running monitor (orbsvcs/Security/Self_Check.h).
//
//   mode_test [ORB options]            ORB_init, print "ORB_INIT OK" or the
//                                      exception; exit 0 / 2
//   mode_test -clock                   print the kernel clock state the time
//                                      check sees: synced, unsynced, unknown
//   mode_test -unit                    configuration evaluation, including
//                                      the prod enrollment marker
//   mode_test -degrade SOCK [ORB opts] prod: requests are refused with
//                                      TRANSIENT while the audit sink SOCK
//                                      is down and served again after it
//                                      recovers
//
// run_test.pl points ACE_TAO_SECURITY_CONF at configurations it writes.

#include "TestS.h"

#include "orbsvcs/Security/Audit_Logger.h"
#include "orbsvcs/Security/Self_Check.h"
#include "tao/Security_Mode.h"

#include "ace/ACE.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_socket.h"
#include "ace/OS_NS_unistd.h"
#include "ace/Thread_Manager.h"
#include "ace/UNIX_Addr.h"

#include <string>

namespace
{
  int failures = 0;

  void
  check (bool ok, char const *what)
  {
    if (!ok)
      ++failures;
    ACE_OS::printf ("%s: %s\n", ok ? "ok" : "FAIL", what);
  }

  class Ping_i : public virtual POA_Ping
  {
  public:
    void hello () override {}
  };

  void
  write_file (std::string const &path, char const *text)
  {
    FILE *const fp = ACE_OS::fopen (path.c_str (), ACE_TEXT ("w"));
    ACE_OS::fputs (text, fp);
    ACE_OS::fclose (fp);
  }

  int
  unit ()
  {
    std::string const base = "mode_unit_" + std::to_string (static_cast<long> (ACE_OS::getpid ()));
    std::string const conf = base + ".conf";
    std::string const marker = base + ".enrolled";
    std::string const missing = base + ".missing";

    TAO_Security_Mode::Host_Config c = TAO_Security_Mode::read (missing.c_str (), missing.c_str ());
    check (c.mode == TAO_Security_Mode::MODE_NONE && !c.found, "no file, not enrolled: none");

    write_file (marker, "");
    c = TAO_Security_Mode::read (missing.c_str (), marker.c_str ());
    check (c.mode == TAO_Security_Mode::MODE_INVALID && c.error.find ("enrolled") != std::string::npos,
           "enrolled host without a configuration: refused");

    write_file (conf, "mode = test\n");
    c = TAO_Security_Mode::read (conf.c_str (), marker.c_str ());
    check (c.mode == TAO_Security_Mode::MODE_INVALID && c.error.find ("mode = test") != std::string::npos,
           "enrolled host with mode = test: refused (no downgrade)");

    write_file (conf, "mode = dev\n");
    c = TAO_Security_Mode::read (conf.c_str (), marker.c_str ());
    check (c.mode == TAO_Security_Mode::MODE_INVALID && c.error.find ("mode = dev") != std::string::npos,
           "enrolled host with mode = dev: refused");

    write_file (conf, "mode = embedded\n");
    c = TAO_Security_Mode::read (conf.c_str (), marker.c_str ());
    check (c.mode == TAO_Security_Mode::MODE_INVALID && c.error.find ("mode = embedded") != std::string::npos,
           "enrolled host with mode = embedded: refused");

    c = TAO_Security_Mode::read (conf.c_str (), missing.c_str ());
    check (c.mode == TAO_Security_Mode::MODE_EMBEDDED
           && ACE_OS::strcmp (TAO_Security_Mode::name (c.mode), "embedded") == 0,
           "embedded without enrollment: embedded");

    write_file (conf, "mode = dev\n");
    c = TAO_Security_Mode::read (conf.c_str (), missing.c_str ());
    check (c.mode == TAO_Security_Mode::MODE_DEV && ACE_OS::strcmp (TAO_Security_Mode::name (c.mode), "dev") == 0,
           "dev without enrollment: dev");

    write_file (conf, "# prod host\nmode = prod   # trailing comment\naudit_rate = \"5/30\"\n");
    c = TAO_Security_Mode::read (conf.c_str (), marker.c_str ());
    check (c.mode == TAO_Security_Mode::MODE_PROD && c.get ("audit_rate") == "5/30",
           "enrolled host with mode = prod: prod; comments and quotes handled");

    c = TAO_Security_Mode::read (conf.c_str (), missing.c_str ());
    check (c.mode == TAO_Security_Mode::MODE_PROD && !c.enrolled, "prod without enrollment: prod");

    write_file (conf, "mode = Prod\n");
    c = TAO_Security_Mode::read (conf.c_str (), missing.c_str ());
    check (c.mode == TAO_Security_Mode::MODE_INVALID, "mode values are exact (Prod is invalid)");

    std::string const sum = TAO::Security::Self_Check::sha256_file (conf.c_str ());
    write_file (conf, "abc");
    check (TAO::Security::Self_Check::sha256_file (conf.c_str ())
             == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
           && sum.size () == 64, "SHA-256 of \"abc\" matches FIPS 180-4");

    ACE_OS::unlink (conf.c_str ());
    ACE_OS::unlink (marker.c_str ());
    return failures == 0 ? 0 : 1;
  }

  /// A datagram socket standing in for the audit sink.
  ACE_HANDLE
  open_sink (char const *path)
  {
    ACE_OS::unlink (path);
    ACE_HANDLE const h = ACE_OS::socket (AF_UNIX, SOCK_DGRAM, 0);
    ACE_UNIX_Addr const addr (path);
    ACE_OS::bind (h, static_cast<sockaddr *> (addr.get_addr ()), addr.get_size ());
    return h;
  }

  void
  drain (ACE_HANDLE h)
  {
    char buf[4096];
    ACE_Time_Value tv (0, 50000);
    while (ACE::handle_read_ready (h, &tv) == 1 && ACE_OS::recv (h, buf, sizeof buf) > 0)
      tv = ACE_Time_Value (0, 50000);
  }

  ACE_THR_FUNC_RETURN
  run_orb (void *arg)
  {
    CORBA::ORB_ptr const orb = static_cast<CORBA::ORB_ptr> (arg);
    try
      {
        orb->run ();
      }
    catch (CORBA::Exception const &)
      {
      }
    return 0;
  }

  bool
  ping_ok (Ping_ptr p)
  {
    try
      {
        p->hello ();
        return true;
      }
    catch (CORBA::TRANSIENT const &)
      {
        return false;
      }
  }

  int
  degrade (char const *sock, int argc, ACE_TCHAR *argv[])
  {
    ACE_HANDLE sink = open_sink (sock);

    CORBA::ORB_var orb = CORBA::ORB_init (argc, argv);
    CORBA::Object_var obj = orb->resolve_initial_references ("RootPOA");
    PortableServer::POA_var poa = PortableServer::POA::_narrow (obj.in ());
    PortableServer::POAManager_var mgr = poa->the_POAManager ();
    mgr->activate ();
    PortableServer::Servant_var<Ping_i> servant = new Ping_i;
    PortableServer::ObjectId_var id = poa->activate_object (servant.in ());
    obj = poa->id_to_reference (id.in ());
    Ping_var ping = Ping::_narrow (obj.in ());

    // The server side needs its own thread: the TLS handshake of the
    // client call must be answered while the calling thread waits.
    ACE_Thread_Manager::instance ()->spawn (run_orb, orb.in ());

    check (ping_ok (ping.in ()), "request served while the audit sink is up");
    drain (sink);

    ACE_OS::closesocket (sink);
    ACE_OS::unlink (sock);
    TAO::Security::Audit_Logger::instance ()->write (
      TAO::Security::Audit_Record ("authz", true, nullptr).field ("op", "sink_goes_away"));
    check (TAO::Security::Self_Check::degraded (), "degraded after the audit sink failed");
    check (!ping_ok (ping.in ()), "request refused with TRANSIENT while degraded");

    sink = open_sink (sock);
    ACE_OS::sleep (ACE_Time_Value (2, 200000));
    TAO::Security::Audit_Logger::instance ()->flush ();
    check (!TAO::Security::Self_Check::degraded (), "not degraded after the sink recovered");
    check (ping_ok (ping.in ()), "request served again after recovery");

    ACE_OS::closesocket (sink);
    ACE_OS::unlink (sock);
    orb->shutdown (true);
    ACE_Thread_Manager::instance ()->wait ();
    orb->destroy ();
    return failures == 0 ? 0 : 1;
  }
}

int
ACE_TMAIN (int argc, ACE_TCHAR *argv[])
{
  if (argc > 1 && ACE_OS::strcmp (argv[1], ACE_TEXT ("-unit")) == 0)
    return unit ();
  if (argc > 1 && ACE_OS::strcmp (argv[1], ACE_TEXT ("-clock")) == 0)
    {
      long err = 0;
      int const s = TAO::Security::Self_Check::clock_synchronized (err);
      ACE_OS::printf ("%s %ld\n", s == 1 && err <= 1000 ? "synced" : s < 0 ? "unknown" : "unsynced", err);
      return 0;
    }

  try
    {
      if (argc > 2 && ACE_OS::strcmp (argv[1], ACE_TEXT ("-degrade")) == 0)
        {
          char const *const sock = ACE_TEXT_ALWAYS_CHAR (argv[2]);
          argv[2] = argv[0];
          int n = argc - 2;
          return degrade (sock, n, argv + 2);
        }

      CORBA::ORB_var orb = CORBA::ORB_init (argc, argv);
      ACE_OS::printf ("ORB_INIT OK\n");
      for (auto const &r : TAO::Security::Self_Check::last_results ())
        ACE_OS::printf ("check %s %s\n", r.name.c_str (),
                        r.status == TAO::Security::Self_Check::CHECK_OK ? "OK"
                        : r.status == TAO::Security::Self_Check::CHECK_WARN ? "WARN" : "FAIL");
      orb->destroy ();
    }
  catch (CORBA::INITIALIZE const &ex)
    {
      ACE_OS::printf ("ORB_INIT REFUSED: %s\n", ex._name ());
      return 2;
    }
  catch (CORBA::Exception const &ex)
    {
      ex._tao_print_exception ("mode_test");
      return 1;
    }
  return failures == 0 ? 0 : 1;
}
