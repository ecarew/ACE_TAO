// Regression test for TAO::Security::Audit_Logger and the SecurityLevel2
// AuditDecision/AuditChannel built on it.  The test receives its own
// syslog traffic on a local socket (and a TCP port), so it needs no syslog
// daemon and writes nothing to the system log except the SECURITY_DEGRADED
// alarm of the sink-failure case.

#include "orbsvcs/Security/Audit_Logger.h"
#include "orbsvcs/Security/SL2_Audit.h"
#include "orbsvcs/Security/Security_ORBInitializer.h"
#include "orbsvcs/SecurityLevel2C.h"

#include "tao/ORBInitializer_Registry.h"
#include "tao/AnyTypeCode/Any.h"

#include "ace/ACE.h"
#include "ace/Get_Opt.h"
#include "ace/INET_Addr.h"
#include "ace/OS_NS_fcntl.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_socket.h"
#include "ace/OS_NS_unistd.h"
#include "ace/SOCK_Acceptor.h"
#include "ace/SOCK_Stream.h"
#include "ace/Thread_Manager.h"
#include "ace/UNIX_Addr.h"

#include <string>
#include <vector>

using TAO::Security::Audit_Logger;
using TAO::Security::Audit_Record;
namespace Reason = TAO::Security::Audit_Reason;

namespace
{
  int failures = 0;

  void
  check (bool ok, char const *what, std::string const &detail = std::string ())
  {
    if (!ok)
      {
        ++failures;
        ACE_ERROR ((LM_ERROR, ACE_TEXT ("FAIL: %C\n"), what));
        if (!detail.empty ())
          ACE_ERROR ((LM_ERROR, ACE_TEXT ("      got: %C\n"), detail.c_str ()));
      }
    else
      ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("ok: %C\n"), what));
  }

  bool
  contains (std::string const &s, std::string const &part)
  {
    return s.find (part) != std::string::npos;
  }

#if !defined (ACE_LACKS_UNIX_DOMAIN_SOCKETS)
  /// A bound datagram socket standing in for /dev/log.
  class Unix_Receiver
  {
  public:
    explicit Unix_Receiver (std::string const &path) : path_ (path) { this->open (); }
    ~Unix_Receiver () { this->close (); }

    void open ()
    {
      ACE_OS::unlink (this->path_.c_str ());
      this->h_ = ACE_OS::socket (AF_UNIX, SOCK_DGRAM, 0);
      ACE_UNIX_Addr const addr (this->path_.c_str ());
      if (ACE_OS::bind (this->h_, static_cast<sockaddr *> (addr.get_addr ()), addr.get_size ()) == -1)
        ACE_ERROR ((LM_ERROR, ACE_TEXT ("bind %C: %p\n"), this->path_.c_str (), ACE_TEXT ("")));
    }

    void close ()
    {
      if (this->h_ != ACE_INVALID_HANDLE)
        ACE_OS::closesocket (this->h_);
      this->h_ = ACE_INVALID_HANDLE;
      ACE_OS::unlink (this->path_.c_str ());
    }

    /// Next datagram, or "" after @a msec without one.
    std::string recv (int msec = 1000)
    {
      ACE_Time_Value tv (0, msec * 1000);
      if (ACE::handle_read_ready (this->h_, &tv) != 1)
        return std::string ();
      char buf[4096];
      ssize_t const n = ACE_OS::recv (this->h_, buf, sizeof buf);
      return n > 0 ? std::string (buf, n) : std::string ();
    }

    std::vector<std::string> drain (int msec = 300)
    {
      std::vector<std::string> v;
      for (std::string s = this->recv (msec); !s.empty (); s = this->recv (msec))
        v.push_back (s);
      return v;
    }

  private:
    std::string path_;
    ACE_HANDLE h_ {ACE_INVALID_HANDLE};
  };

  struct Alarm_Log
  {
    std::vector<std::pair<bool, std::string>> events;
  };

  void
  on_alarm (bool healthy, char const *detail, void *arg)
  {
    static_cast<Alarm_Log *> (arg)->events.emplace_back (healthy, detail);
  }

  /// Sends stderr to a file while alive.
  class Stderr_Capture
  {
  public:
    explicit Stderr_Capture (std::string const &path) : path_ (path)
    {
      ACE_OS::fflush (stderr);
      this->saved_ = ACE_OS::dup (ACE_STDERR);
      ACE_HANDLE const f = ACE_OS::open (path.c_str (), O_WRONLY | O_CREAT | O_TRUNC, 0600);
      ACE_OS::dup2 (f, ACE_STDERR);
      ACE_OS::close (f);
    }

    std::string finish ()
    {
      ACE_OS::fflush (stderr);
      ACE_OS::dup2 (this->saved_, ACE_STDERR);
      ACE_OS::close (this->saved_);
      std::string out;
      FILE *const fp = ACE_OS::fopen (this->path_.c_str (), ACE_TEXT ("r"));
      if (fp)
        {
          char buf[1024];
          while (ACE_OS::fgets (buf, sizeof buf, fp))
            out += buf;
          ACE_OS::fclose (fp);
        }
      ACE_OS::unlink (this->path_.c_str ());
      return out;
    }

  private:
    std::string path_;
    ACE_HANDLE saved_;
  };

  Audit_Logger::Options
  test_options (std::string const &sink)
  {
    Audit_Logger::Options o;
    o.sink = sink;
    o.service = "audit_test";
    o.mode = "test";
    return o;
  }

  void
  test_format (Audit_Logger &logger, Unix_Receiver &rx)
  {
    std::string const pid = std::to_string (static_cast<long> (ACE_OS::getpid ()));

    logger.write (Audit_Record ("authz", false, Reason::NO_ROLE)
                    .field ("src", "10.20.4.17:51544")
                    .field ("peer", "spiffe://hospital.example/user/jdoe")
                    .field ("op", "bind")
                    .field ("target", "evil\"] x=\"y\\\n"));
    std::string const deny = rx.recv ();
    check (deny.compare (0, 4, "<85>") == 0, "deny is authpriv.notice <85>", deny);
    check (contains (deny, " ace-tao-audit[" + pid + "]: [audit@32473 mode=\"test\" svc=\"audit_test\""
                           " event=\"authz\" result=\"deny\" reason=\"NO_ROLE\" src=\"10.20.4.17:51544\""
                           " peer=\"spiffe://hospital.example/user/jdoe\" op=\"bind\""),
           "deny record fields in order", deny);
    check (contains (deny, "target=\"evil\\\"\\] x=\\\"y\\\\?\"]"),
           "quote, bracket and backslash escaped; newline replaced", deny);
    check (deny.find ('\n') == std::string::npos, "record is one line", deny);

    logger.write (Audit_Record ("authn", true, nullptr).field ("peer", "spiffe://x/svc").field ("", "skipped")
                    .field ("bad name", "skipped").field ("empty", "").text ("line one\nline two"));
    std::string const ok = rx.recv ();
    check (ok.compare (0, 4, "<86>") == 0, "success is authpriv.info <86>", ok);
    check (contains (ok, "event=\"authn\" result=\"ok\" reason=\"OK\" peer=\"spiffe://x/svc\"] line one?line two"),
           "success record, free text sanitized", ok);
    check (!contains (ok, "skipped") && !contains (ok, "empty="), "invalid names and empty values dropped", ok);
  }

  void
  test_rate_limit (Audit_Logger &logger, Unix_Receiver &rx)
  {
    Audit_Logger::Options o = logger.options ();
    o.rate_count = 3;
    o.rate_window = ACE_Time_Value (2);
    logger.configure (o);

    for (int i = 0; i < 10; ++i)
      logger.write (Audit_Record ("tls", false, Reason::TLS_HANDSHAKE_FAILED)
                      .field ("src", "10.0.0.1:" + std::to_string (40000 + i)));
    logger.write (Audit_Record ("tls", false, Reason::TLS_HANDSHAKE_FAILED).field ("src", "10.0.0.2:5000"));
    for (int i = 0; i < 5; ++i)
      logger.write (Audit_Record ("tls", true, nullptr).field ("src", "10.0.0.1:41000"));

    std::vector<std::string> const got = rx.drain ();
    size_t fail1 = 0, fail2 = 0, oks = 0;
    for (auto const &s : got)
      {
        if (contains (s, "result=\"fail\"") && contains (s, "src=\"10.0.0.1:"))
          ++fail1;
        else if (contains (s, "result=\"fail\"") && contains (s, "src=\"10.0.0.2:"))
          ++fail2;
        else if (contains (s, "result=\"ok\""))
          ++oks;
      }
    check (fail1 == 3, "10 failures from one host: 3 written", std::to_string (fail1));
    check (fail2 == 1, "another host has its own limit", std::to_string (fail2));
    check (oks == 5, "successes are not rate limited", std::to_string (oks));

    ACE_OS::sleep (ACE_Time_Value (2, 200000));
    logger.flush ();
    std::vector<std::string> const sum = rx.drain ();
    check (sum.size () == 1, "one summary after the window", std::to_string (sum.size ()));
    if (!sum.empty ())
      {
        check (sum[0].compare (0, 4, "<84>") == 0, "summary is authpriv.warning <84>", sum[0]);
        check (contains (sum[0], "event=\"ratelimit\" result=\"fail\" reason=\"RATE_LIMITED\" src=\"10.0.0.1\""
                                 " suppressed=\"7\" window=\"2s\""),
               "summary counts the 7 suppressed records", sum[0]);
      }

    o.rate_count = 20;
    o.rate_window = ACE_Time_Value (60);
    logger.configure (o);
  }

  void
  test_sink_failure (Audit_Logger &logger, Unix_Receiver &rx, std::string const &tmp)
  {
    Alarm_Log alarms;
    logger.add_alarm_callback (on_alarm, &alarms);
    check (logger.self_test (), "self_test succeeds with the sink up");
    rx.drain ();

    rx.close ();
    Stderr_Capture cap (tmp + ".stderr");
    logger.write (Audit_Record ("authz", false, Reason::NO_ROLE).field ("op", "first_lost"));
    logger.write (Audit_Record ("authz", false, Reason::NO_ROLE).field ("op", "second_lost"));
    bool const healthy_after = logger.healthy ();
    unsigned long const fallback = logger.fallback_count ();
    bool const self_test_down = logger.self_test ();
    std::string const err = cap.finish ();

    check (!healthy_after, "logger unhealthy after the sink failed");
    check (fallback == 2, "both records counted as fallback", std::to_string (fallback));
    check (!self_test_down, "self_test fails with the sink down");
    check (contains (err, "ACE/TAO SECURITY_DEGRADED: audit sink unix:"), "SECURITY_DEGRADED on stderr", err);
    check (contains (err, "AUDIT-FALLBACK [audit@32473") && contains (err, "op=\"first_lost\"")
           && contains (err, "op=\"second_lost\""), "lost records on stderr", err);
    check (alarms.events.size () == 1 && !alarms.events[0].first, "one alarm callback (unhealthy)",
           std::to_string (alarms.events.size ()));

    rx.open ();
    ACE_OS::sleep (ACE_Time_Value (2, 100000));   // past the retry backoff
    logger.write (Audit_Record ("authz", true, nullptr).field ("op", "after_recovery"));
    std::vector<std::string> const got = rx.drain ();
    check (logger.healthy (), "logger healthy after the sink came back");
    check (got.size () == 2, "recovery record and the new record", std::to_string (got.size ()));
    if (got.size () == 2)
      {
        check (contains (got[0], "event=\"audit\" result=\"ok\" reason=\"AUDIT_SINK_RECOVERED\"")
               && contains (got[0], "fallback_records=\"3\""),
               "recovery record counts the records that went to stderr", got[0]);
        check (contains (got[1], "op=\"after_recovery\""), "new record delivered", got[1]);
      }
    check (alarms.events.size () == 2 && alarms.events[1].first, "second alarm callback (healthy)",
           std::to_string (alarms.events.size ()));
    logger.remove_alarm_callback (on_alarm, &alarms);
  }
  ACE_THR_FUNC_RETURN
  writer (void *arg)
  {
    Audit_Logger *const logger = static_cast<Audit_Logger *> (arg);
    for (int i = 0; i < 250; ++i)
      logger->write (Audit_Record ("invoke", true, nullptr).field ("op", "concurrent"));
    return 0;
  }

  void
  test_concurrent (Audit_Logger &logger, Unix_Receiver &rx)
  {
    int const threads = 8;
    if (ACE_Thread_Manager::instance ()->spawn_n (threads, writer, &logger) == -1)
      {
        check (false, "spawn writer threads");
        return;
      }
    size_t got = 0, bad = 0;
    for (std::string s = rx.recv (2000); !s.empty (); s = rx.recv (500))
      {
        ++got;
        if (s.compare (0, 4, "<86>") != 0 || !contains (s, "op=\"concurrent\"]"))
          ++bad;
      }
    ACE_Thread_Manager::instance ()->wait ();
    check (got == threads * 250 && bad == 0, "8 threads x 250 records: all delivered intact",
           std::to_string (got) + " received, " + std::to_string (bad) + " malformed");
    check (logger.healthy (), "logger healthy after concurrent writes");
  }
#endif /* !ACE_LACKS_UNIX_DOMAIN_SOCKETS */

  void
  test_tcp ()
  {
    ACE_SOCK_Acceptor acceptor;
    ACE_INET_Addr any (u_short (0), "127.0.0.1");
    if (acceptor.open (any, 1) == -1)
      {
        check (false, "listen on 127.0.0.1");
        return;
      }
    ACE_INET_Addr bound;
    acceptor.get_local_addr (bound);

    Audit_Logger logger;
    logger.configure (test_options ("tcp:127.0.0.1:" + std::to_string (bound.get_port_number ())));
    logger.write (Audit_Record ("authn", false, Reason::CERT_EXPIRED).field ("cert_serial", "4f:9a"));

    ACE_SOCK_Stream peer;
    ACE_Time_Value timeout (2);
    if (acceptor.accept (peer, nullptr, &timeout) == -1)
      {
        check (false, "tcp sink connected");
        return;
      }
    std::string data;
    char buf[2048];
    ACE_Time_Value rt (1);
    ssize_t n;
    while ((n = peer.recv (buf, sizeof buf, &rt)) > 0)
      {
        data.append (buf, n);
        if (data.find (']') != std::string::npos)
          break;
      }
    size_t const sp = data.find (' ');
    std::string const frame = sp == std::string::npos ? std::string () : data.substr (sp + 1);
    check (sp != std::string::npos && std::to_string (frame.size ()) == data.substr (0, sp),
           "RFC 6587 octet count matches the record", data);
    check (frame.compare (0, 7, "<85>1 2") == 0 && contains (frame, "Z "),
           "RFC 5424 header with a UTC timestamp", frame);
    check (contains (frame, " ace-tao-audit " + std::to_string (static_cast<long> (ACE_OS::getpid ()))
                     + " authn [audit@32473 mode=\"test\""),
           "APP-NAME, PROCID and MSGID", frame);
    check (contains (frame, "reason=\"CERT_EXPIRED\" cert_serial=\"4f:9a\"]"), "tcp record fields", frame);

    // The collector restarts: the next record must reconnect, not vanish
    // into the dead connection's send buffer.
    peer.close ();
    ACE_OS::sleep (ACE_Time_Value (0, 100000));
    logger.write (Audit_Record ("authn", true, nullptr).field ("op", "after_reconnect"));
    ACE_SOCK_Stream peer2;
    std::string again;
    if (acceptor.accept (peer2, nullptr, &timeout) != -1)
      {
        while ((n = peer2.recv (buf, sizeof buf, &rt)) > 0)
          {
            again.append (buf, n);
            if (again.find (']') != std::string::npos)
              break;
          }
        peer2.close ();
      }
    check (contains (again, "op=\"after_reconnect\""), "record after a collector restart reconnects", again);
    check (logger.healthy (), "logger healthy after reconnecting");
    acceptor.close ();
  }

  int
  test_sl2 (int argc, ACE_TCHAR *argv[])
  {
    PortableInterceptor::ORBInitializer_var init = new TAO::Security::ORBInitializer;
    PortableInterceptor::register_orb_initializer (init.in ());

    CORBA::ORB_var orb = CORBA::ORB_init (argc, argv);
    CORBA::Object_var obj = orb->resolve_initial_references ("SecurityLevel2:SecurityManager");
    SecurityLevel2::SecurityManager_var sm = SecurityLevel2::SecurityManager::_narrow (obj.in ());
    check (!CORBA::is_nil (sm.in ()), "SecurityLevel2:SecurityManager resolved");

    SecurityLevel2::AuditDecision_var decision = sm->audit_decision ();
    check (!CORBA::is_nil (decision.in ()), "audit_decision() returns an AuditDecision");

    Security::AuditEventType type;
    type.event_family.family_definer = 0;
    type.event_family.family = 7;
    type.event_type = Security::AuditAuthorization;
    Security::SelectorValueList none;
    check (decision->audit_needed (type, none), "audit_needed() is true");

    SecurityLevel2::AuditChannel_var channel = decision->audit_channel ();
    check (channel->audit_channel_id () == 1, "audit_channel_id() is 1");

    Security::SelectorValueList sv (6);
    sv.length (6);
    sv[0].selector = Security::SuccessFailure;
    sv[0].value <<= CORBA::Any::from_boolean (false);
    sv[1].selector = Security::Operation;
    sv[1].value <<= "resolve";
    sv[2].selector = TAO::Security::Audit_Selector::Reason;
    sv[2].value <<= Reason::NO_ROLE;
    sv[3].selector = TAO::Security::Audit_Selector::Source;
    sv[3].value <<= "[::1]:4000";
    sv[4].selector = TAO::Security::Audit_Selector::Peer;
    sv[4].value <<= "spiffe://hospital.example/user/jdoe";
    sv[5].selector = TAO::Security::Audit_Selector::TokenId;
    sv[5].value <<= "b1c2";
    CORBA::Any text;
    text <<= "denied by policy";
    Security::UtcT now {};
    SecurityLevel2::CredentialsList creds;
    channel->audit_write (type, creds, now, sv, text);

    orb->destroy ();
    return 0;
  }
}

int
ACE_TMAIN (int argc, ACE_TCHAR *argv[])
{
  try
    {
      std::string const tmp = "audit_test_" + std::to_string (static_cast<long> (ACE_OS::getpid ()));

#if !defined (ACE_LACKS_UNIX_DOMAIN_SOCKETS)
      std::string const sock = tmp + ".sock";
      Unix_Receiver rx (sock);
      {
        Audit_Logger logger;
        logger.configure (test_options ("unix:" + sock));
        test_format (logger, rx);
        test_rate_limit (logger, rx);
        test_sink_failure (logger, rx, tmp);
        test_concurrent (logger, rx);
      }

      // The SL2 objects write to the process-wide logger.
      Audit_Logger::instance ()->configure (test_options ("unix:" + sock));
      test_sl2 (argc, argv);
      std::string const sl2 = rx.recv ();
      check (contains (sl2, "event=\"authz\" result=\"deny\" reason=\"NO_ROLE\" op=\"resolve\" src=\"[::1\\]:4000\""
                            " peer=\"spiffe://hospital.example/user/jdoe\" jti=\"b1c2\"] denied by policy"),
             "SL2 audit_write record", sl2);
#else
      test_sl2 (argc, argv);
#endif /* !ACE_LACKS_UNIX_DOMAIN_SOCKETS */

      test_tcp ();

      {
        Stderr_Capture cap (tmp + ".bad");
        Audit_Logger bad;
        bad.configure (test_options ("udp:127.0.0.1:514"));
        ACE_OS::sleep (ACE_Time_Value (1, 200000));
        bad.write (Audit_Record ("authz", false, Reason::NO_ROLE).field ("op", "misconfigured"));
        bool const bad_healthy = bad.healthy () || bad.self_test ();
        std::string const err = cap.finish ();
        check (!bad_healthy, "unknown sink stays unhealthy after the retry delay");
        check (contains (err, "unknown audit sink \"udp:127.0.0.1:514\"")
               && contains (err, "AUDIT-FALLBACK") && contains (err, "op=\"misconfigured\""),
               "unknown sink: alarm and records on stderr", err);
      }

      Audit_Logger::Options const conf = Audit_Logger::options_from_config ("does-not-exist.conf");
      check (conf.mode == "none" && conf.rate_count == 20, "missing config file gives defaults");
    }
  catch (CORBA::Exception const &ex)
    {
      ex._tao_print_exception ("audit_test");
      return 1;
    }

  if (failures != 0)
    {
      ACE_ERROR ((LM_ERROR, ACE_TEXT ("audit_test: %d check(s) failed\n"), failures));
      return 1;
    }
  ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("audit_test: all checks passed\n")));
  return 0;
}
