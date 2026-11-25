#include "orbsvcs/Log_Macros.h"
#include "orbsvcs/Security/Self_Check.h"
#include "orbsvcs/Security/Audit_Logger.h"

#include "tao/Security_Mode.h"
#include "tao/ORB_Core.h"
#include "tao/Resource_Factory.h"
#include "tao/LocalObject.h"
#include "tao/PI_Server/PI_Server.h"
#include "tao/PortableInterceptorC.h"
#include "tao/debug.h"

#include "ace/Event_Handler.h"
#include "ace/Guard_T.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_resource.h"
#include "ace/OS_NS_sys_stat.h"
#include "ace/OS_NS_sys_time.h"
#include "ace/OS_NS_unistd.h"
#include "ace/Reactor.h"
#include "tao/orbconf.h"
#include "ace/Synch_Traits.h"
#include "ace/Thread_Mutex.h"

#include <atomic>
#include <cstdint>

#if defined (ACE_LINUX) || defined (__APPLE__) || defined (__FreeBSD__)
# include <sys/timex.h>
# define TAO_SECURITY_HAS_NTP_ADJTIME
#endif

#if defined (ACE_LINUX)
# include <sys/prctl.h>
#endif

#if !defined (ACE_LACKS_UNIX_SYSLOG)
# include <syslog.h>
#endif /* !ACE_LACKS_UNIX_SYSLOG */

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  using TAO::Security::Self_Check;
  using TAO::Security::Audit_Logger;
  using TAO::Security::Audit_Record;

  // Syslog priorities, spelled out for platforms without <syslog.h>.
  constexpr int PRI_ERR = 3;
  constexpr int PRI_WARNING = 4;
  constexpr int PRI_NOTICE = 5;

  ACE_Time_Value const MONITOR_INTERVAL (30);
  ACE_Time_Value const TIME_ALARM_REPEAT (300);
  ACE_Time_Value const TEST_REMINDER (3600);

  TAO_SYNCH_MUTEX &
  state_lock ()
  {
    static TAO_SYNCH_MUTEX lock;
    return lock;
  }

  std::vector<Self_Check::Result> &
  contributions ()
  {
    static std::vector<Self_Check::Result> c;
    return c;
  }

  std::vector<std::pair<std::string, std::string>> &
  banner_fields ()
  {
    static std::vector<std::pair<std::string, std::string>> f;
    return f;
  }

  std::vector<Self_Check::Result> &
  last ()
  {
    static std::vector<Self_Check::Result> r;
    return r;
  }

  std::atomic<bool> degraded_flag {false};

  char const *
  status_name (Self_Check::Status s)
  {
    switch (s)
      {
      case Self_Check::CHECK_OK: return "OK";
      case Self_Check::CHECK_WARN: return "WARN";
      default: return "FAIL";
      }
  }

  long
  config_number (TAO_Security_Mode::Host_Config const &host, char const *key, long fallback)
  {
    std::string const v = host.get (key);
    if (v.empty ())
      return fallback;
    char *end = nullptr;
    long const n = ACE_OS::strtol (v.c_str (), &end, 10);
    return (end && *end == '\0' && n >= 0) ? n : fallback;
  }

  // ------------------------------------------------------------------
  // SHA-256 (FIPS 180-4), for the configuration hash in the banner.

  class Sha256
  {
  public:
    Sha256 () { this->reset (); }

    void update (unsigned char const *p, size_t n)
    {
      for (size_t i = 0; i < n; ++i)
        {
          this->buf_[this->used_++] = p[i];
          if (this->used_ == 64)
            {
              this->block (this->buf_);
              this->used_ = 0;
            }
          this->bits_ += 8;
        }
    }

    std::string hex ()
    {
      std::uint64_t const bits = this->bits_;
      unsigned char pad = 0x80;
      this->update (&pad, 1);
      unsigned char zero = 0;
      while (this->used_ != 56)
        this->update (&zero, 1);
      unsigned char len[8];
      for (int i = 0; i < 8; ++i)
        len[i] = static_cast<unsigned char> (bits >> (56 - 8 * i));
      this->update (len, 8);
      char out[65];
      for (int i = 0; i < 8; ++i)
        ACE_OS::snprintf (out + 8 * i, 9, "%08x", this->h_[i]);
      return std::string (out, 64);
    }

  private:
    void reset ()
    {
      static std::uint32_t const init[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
      for (int i = 0; i < 8; ++i)
        this->h_[i] = init[i];
      this->used_ = 0;
      this->bits_ = 0;
    }

    static std::uint32_t rotr (std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

    void block (unsigned char const *p)
    {
      static std::uint32_t const k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
      std::uint32_t w[64];
      for (int i = 0; i < 16; ++i)
        w[i] = (std::uint32_t (p[4 * i]) << 24) | (std::uint32_t (p[4 * i + 1]) << 16)
             | (std::uint32_t (p[4 * i + 2]) << 8) | std::uint32_t (p[4 * i + 3]);
      for (int i = 16; i < 64; ++i)
        {
          std::uint32_t const s0 = rotr (w[i - 15], 7) ^ rotr (w[i - 15], 18) ^ (w[i - 15] >> 3);
          std::uint32_t const s1 = rotr (w[i - 2], 17) ^ rotr (w[i - 2], 19) ^ (w[i - 2] >> 10);
          w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
      std::uint32_t a = this->h_[0], b = this->h_[1], c = this->h_[2], d = this->h_[3];
      std::uint32_t e = this->h_[4], f = this->h_[5], g = this->h_[6], h = this->h_[7];
      for (int i = 0; i < 64; ++i)
        {
          std::uint32_t const t1 = h + (rotr (e, 6) ^ rotr (e, 11) ^ rotr (e, 25))
            + ((e & f) ^ (~e & g)) + k[i] + w[i];
          std::uint32_t const t2 = (rotr (a, 2) ^ rotr (a, 13) ^ rotr (a, 22))
            + ((a & b) ^ (a & c) ^ (b & c));
          h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
      this->h_[0] += a; this->h_[1] += b; this->h_[2] += c; this->h_[3] += d;
      this->h_[4] += e; this->h_[5] += f; this->h_[6] += g; this->h_[7] += h;
    }

    std::uint32_t h_[8];
    unsigned char buf_[64];
    size_t used_;
    std::uint64_t bits_;
  };

  // ------------------------------------------------------------------
  // Running monitor.

  class Mode_Monitor : public ACE_Event_Handler
  {
  public:
    Mode_Monitor (bool prod, long max_error_ms)
      : prod_ (prod),
        max_error_ms_ (max_error_ms),
        next_reminder_ (ACE_OS::gettimeofday () + TEST_REMINDER)
    {
      this->reference_counting_policy ().value (
        ACE_Event_Handler::Reference_Counting_Policy::ENABLED);
    }

    int handle_timeout (ACE_Time_Value const &now, void const *) override
    {
      // Writes due rate-limit summaries and retries a failed sink, so
      // recovery is noticed even when no records are being written.
      Audit_Logger::instance ()->flush ();

      long err = 0;
      int const synced = Self_Check::clock_synchronized (err);
      bool const ok = synced != 0 && (synced < 0 || err <= this->max_error_ms_);
      if (!ok)
        {
          if (now >= this->next_time_alarm_)
            {
              this->next_time_alarm_ = now + TIME_ALARM_REPEAT;
              this->time_lost_ = true;
              std::string const msg = "ACE/TAO security: TIME_UNSYNCED: clock not synchronized (kernel error estimate "
                + std::to_string (err) + " ms, max_clock_error " + std::to_string (this->max_error_ms_)
                + " ms); certificate and token expiry checks are unreliable";
              TAO_Security_Mode::announce (PRI_WARNING, msg.c_str ());
              Audit_Logger::instance ()->write (
                Audit_Record ("secenv", false, TAO::Security::Audit_Reason::TIME_UNSYNCED)
                  .field ("max_error_ms", std::to_string (err)));
            }
        }
      else if (this->time_lost_)
        {
          this->time_lost_ = false;
          this->next_time_alarm_ = ACE_Time_Value::zero;
          TAO_Security_Mode::announce (PRI_NOTICE, "ACE/TAO security: clock synchronized again");
          Audit_Logger::instance ()->write (
            Audit_Record ("secenv", true, TAO::Security::Audit_Reason::TIME_SYNCED));
        }

      if (!this->prod_ && now >= this->next_reminder_)
        {
          this->next_reminder_ = now + TEST_REMINDER;
          TAO_Security_Mode::announce (PRI_WARNING,
            "ACE/TAO security: TEST MODE: this service is not configured for production data");
        }
      return 0;
    }

  private:
    bool const prod_;
    long const max_error_ms_;
    ACE_Time_Value next_reminder_;
    ACE_Time_Value next_time_alarm_;
    bool time_lost_ {false};
  };

  void
  on_audit_alarm (bool healthy, char const *detail, void *)
  {
    bool const was = degraded_flag.exchange (!healthy);
    if (was == !healthy)
      return;
    std::string const msg = healthy
      ? std::string ("ACE/TAO security: audit sink recovered (") + detail + "); accepting requests again"
      : std::string ("ACE/TAO security: SECURITY_DEGRADED: ") + detail
        + "; refusing new requests until the audit sink recovers";
    TAO_Security_Mode::announce (healthy ? PRI_NOTICE : PRI_ERR, msg.c_str ());
  }

  /// Refuses requests while the security state is degraded (prod).
  class Mode_Interceptor
    : public virtual PortableInterceptor::ServerRequestInterceptor,
      public virtual ::CORBA::LocalObject
  {
  public:
    char *name () override { return CORBA::string_dup ("TAO_Security_Mode"); }
    void destroy () override {}

    void receive_request_service_contexts (PortableInterceptor::ServerRequestInfo_ptr) override
    {
      if (degraded_flag.load ())
        throw CORBA::TRANSIENT (
          CORBA::SystemException::_tao_minor_code (TAO::VMCID, EACCES),
          CORBA::COMPLETED_NO);
    }

    void receive_request (PortableInterceptor::ServerRequestInfo_ptr) override {}
    void send_reply (PortableInterceptor::ServerRequestInfo_ptr) override {}
    void send_exception (PortableInterceptor::ServerRequestInfo_ptr) override {}
    void send_other (PortableInterceptor::ServerRequestInfo_ptr) override {}
  };
}

namespace TAO
{
  namespace Security
  {
    void
    Self_Check::contribute (char const *name, Status status, char const *detail)
    {
      ACE_GUARD (TAO_SYNCH_MUTEX, guard, state_lock ());
      contributions ().push_back ({name ? name : "unnamed", status, detail ? detail : ""});
    }

    void
    Self_Check::banner_field (char const *key, char const *value)
    {
      ACE_GUARD (TAO_SYNCH_MUTEX, guard, state_lock ());
      for (auto &f : banner_fields ())
        if (f.first == key)
          {
            f.second = value ? value : "";
            return;
          }
      banner_fields ().emplace_back (key ? key : "", value ? value : "");
    }

    std::vector<Self_Check::Result>
    Self_Check::last_results ()
    {
      ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, state_lock (), std::vector<Result> ());
      return last ();
    }

    bool
    Self_Check::degraded ()
    {
      return degraded_flag.load ();
    }

    std::string
    Self_Check::sha256_file (char const *path)
    {
      FILE *const fp = ACE_OS::fopen (path, ACE_TEXT ("rb"));
      if (fp == nullptr)
        return std::string ();
      Sha256 h;
      unsigned char buf[4096];
      size_t n;
      while ((n = ACE_OS::fread (buf, 1, sizeof buf, fp)) > 0)
        h.update (buf, n);
      ACE_OS::fclose (fp);
      return h.hex ();
    }

    int
    Self_Check::clock_synchronized (long &max_error_ms)
    {
#if defined (TAO_SECURITY_HAS_NTP_ADJTIME)
      struct timex tx;
      ACE_OS::memset (&tx, 0, sizeof tx);
      int const state = ::ntp_adjtime (&tx);
      max_error_ms = static_cast<long> (tx.maxerror / 1000);
      if (state == -1)
        return -1;
      return (state == TIME_ERROR || (tx.status & STA_UNSYNC) != 0) ? 0 : 1;
#else
      max_error_ms = 0;
      return -1;
#endif /* TAO_SECURITY_HAS_NTP_ADJTIME */
    }

    bool
    Self_Check::run (TAO_ORB_Core *orb_core, PortableInterceptor::ORBInitInfo_ptr info)
    {
      TAO_Security_Mode::Host_Config const &host = TAO_Security_Mode::host ();
      // Only test and prod run the self-check.  dev and embedded are
      // announced by the ORB_init guard; no mode is stock behaviour; an
      // invalid configuration is refused by the guard.
      if (host.mode != TAO_Security_Mode::MODE_TEST && host.mode != TAO_Security_Mode::MODE_PROD)
        return true;

      bool const prod = host.mode == TAO_Security_Mode::MODE_PROD;
      Status const bad = prod ? CHECK_FAIL : CHECK_WARN;
      std::vector<Result> results;

      // Configuration file.  Group/world-writable is refused by the guard.
      {
        ACE_stat st;
        if (ACE_OS::stat (host.path.c_str (), &st) == 0 && st.st_uid != 0)
          results.push_back ({"config", CHECK_WARN,
                              host.path + " is owned by uid " + std::to_string (st.st_uid)
                              + ", not root"});
        else
          results.push_back ({"config", CHECK_OK, host.path});
      }

      // Audit sink.
      Audit_Logger *const logger = Audit_Logger::instance ();
      std::string const sink = logger->options ().sink;
      bool const audit_ok = logger->self_test ();
      results.push_back ({"audit", audit_ok ? CHECK_OK : bad,
                          audit_ok ? "sink " + sink + " accepted a record"
                                   : "audit sink " + sink + " does not accept records"});

      // Clock.
      long const max_error_ms = config_number (host, "max_clock_error", 1000);
      long const wait_s = config_number (host, "time_sync_wait", 300);
      std::string time_field = "unknown";
      {
        long err = 0;
        int synced = Self_Check::clock_synchronized (err);
        auto good = [&] () { return synced == 1 && err <= max_error_ms; };
        if (synced == -1)
          results.push_back ({"time", CHECK_WARN, "cannot read the kernel clock state on this platform"});
        else
          {
            if (!good () && prod && wait_s > 0)
              {
                // Just after boot the time daemon may not have synchronized yet.
                ACE_Time_Value const deadline = ACE_OS::gettimeofday () + ACE_Time_Value (wait_s);
                ACE_Time_Value next_log;
                while (!good () && ACE_OS::gettimeofday () < deadline)
                  {
                    ACE_Time_Value const now = ACE_OS::gettimeofday ();
                    if (now >= next_log)
                      {
                        next_log = now + ACE_Time_Value (30);
                        std::string const msg = "ACE/TAO security: waiting for time synchronization ("
                          + std::to_string ((deadline - now).sec ()) + " s left)";
                        TAO_Security_Mode::announce (PRI_WARNING, msg.c_str ());
                      }
                    ACE_OS::sleep (ACE_Time_Value (5));
                    synced = Self_Check::clock_synchronized (err);
                  }
              }
            if (good ())
              {
                time_field = "synced";
                results.push_back ({"time", CHECK_OK, "synchronized, kernel error estimate "
                                    + std::to_string (err) + " ms"});
              }
            else
              {
                time_field = "unsynced";
                results.push_back ({"time", bad,
                                    std::string (synced == 1 ? "clock error estimate " : "clock not synchronized, error estimate ")
                                    + std::to_string (err) + " ms (max_clock_error " + std::to_string (max_error_ms)
                                    + " ms)" + (prod ? " after waiting " + std::to_string (wait_s) + " s" : "")});
              }
          }
      }

      // Core dumps: a dump of a service holding card or patient data in
      // memory is that data at rest.
      if (prod)
        {
#if defined (ACE_LACKS_RLIMIT)
          // No resource limits here (Windows): crash dumps are governed by
          // Windows Error Reporting, outside the process.
          results.push_back ({"core_dumps", CHECK_WARN,
                              "not controlled by the service on this platform (configure crash dumps for the host)"});
#else
          rlimit rl;
          rl.rlim_cur = 0;
          rl.rlim_max = 0;
          bool ok = ACE_OS::setrlimit (RLIMIT_CORE, &rl) == 0;
# if defined (ACE_LINUX)
          ok = ::prctl (PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 && ok;
# endif
          results.push_back ({"core_dumps", ok ? CHECK_OK : CHECK_FAIL,
                              ok ? "turned off" : std::string ("cannot turn off core dumps: ")
                                                  + ACE_OS::strerror (errno)});
#endif /* ACE_LACKS_RLIMIT */
        }
      else
        results.push_back ({"core_dumps", CHECK_OK, "left as configured (test mode)"});

      // Protocols: only TLS.
      {
        std::string const allowed = " " + host.get ("allowed_protocols", "SSLIOP_Factory") + " ";
        std::string loaded, refused;
        TAO_ProtocolFactorySet *const pfs = orb_core->protocol_factories ();
        if (pfs != nullptr)
          for (TAO_ProtocolFactorySetItor i = pfs->begin (); i != pfs->end (); ++i)
            {
              std::string const n ((*i)->protocol_name ().c_str ());
              (loaded.empty () ? loaded : loaded += ",") += n;
              std::string spaced = allowed;
              for (char &c : spaced)
                if (c == ',')
                  c = ' ';
              if (spaced.find (" " + n + " ") == std::string::npos)
                (refused.empty () ? refused : refused += ",") += n;
            }
        if (loaded.empty ())
          results.push_back ({"protocols", bad, "no protocol factory is loaded"});
        else if (!refused.empty ())
          results.push_back ({"protocols", bad, "protocol factory " + refused
                              + " is not in allowed_protocols (plain IIOP must be closed in prod)"});
        else
          results.push_back ({"protocols", CHECK_OK, loaded});
      }

      std::vector<std::pair<std::string, std::string>> fields;
      {
        ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, state_lock (), false);
        for (auto const &c : contributions ())
          results.push_back (c);
        fields = banner_fields ();
      }

      // Report.
      int counts[3] = {0, 0, 0};
      std::string failures;
      for (auto const &r : results)
        {
          ++counts[r.status];
          if (r.status != CHECK_OK)
            {
              std::string const msg = std::string ("ACE/TAO security: ") + status_name (r.status)
                + " " + r.name + ": " + r.detail;
              TAO_Security_Mode::announce (r.status == CHECK_FAIL ? PRI_ERR : PRI_WARNING, msg.c_str ());
            }
          if (r.status == CHECK_FAIL)
            (failures.empty () ? failures : failures += "; ") += r.name + ": " + r.detail;
        }

      std::string const hash = Self_Check::sha256_file (host.path.c_str ());
      std::string banner = std::string ("ACE/TAO security: MODE=") + (prod ? "PROD" : "TEST")
        + "  svc=" + logger->options ().service;
      for (auto const &f : fields)
        banner += "  " + f.first + "=" + f.second;
      banner += "  time=" + time_field + "  audit=" + (audit_ok ? "ok" : "failed")
        + "  conf=sha256:" + hash.substr (0, 16)
        + "  checks: " + std::to_string (counts[CHECK_OK]) + " ok, " + std::to_string (counts[CHECK_WARN])
        + " warn, " + std::to_string (counts[CHECK_FAIL]) + " fail";
      TAO_Security_Mode::announce (counts[CHECK_FAIL] ? PRI_ERR : PRI_NOTICE, banner.c_str ());

      logger->write (Audit_Record ("secenv", counts[CHECK_FAIL] == 0,
                                   counts[CHECK_FAIL] ? Audit_Reason::SELF_CHECK_FAILED : Audit_Reason::OK)
                       .field ("phase", "startup")
                       .field ("conf_sha256", hash)
                       .field ("checks", std::to_string (counts[CHECK_OK]) + "/" + std::to_string (counts[CHECK_WARN])
                                         + "/" + std::to_string (counts[CHECK_FAIL]))
                       .text (failures.empty () ? banner.c_str () : failures.c_str ()));

      {
        ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, state_lock (), false);
        last () = results;
      }

      TAO_Security_Mode::report_plugin (orb_core, "TAO_Security", counts[CHECK_FAIL] == 0, failures.c_str ());

      // Running monitor.
      if (counts[CHECK_FAIL] == 0 && !CORBA::is_nil (info))
        {
          if (prod)
            {
              static std::atomic<bool> callback_added {false};
              if (!callback_added.exchange (true))
                logger->add_alarm_callback (on_audit_alarm, nullptr);
              PortableInterceptor::ServerRequestInterceptor_var interceptor = new Mode_Interceptor;
              info->add_server_request_interceptor (interceptor.in ());
            }
          Mode_Monitor *const monitor = new Mode_Monitor (prod, max_error_ms);
          ACE_Event_Handler_var holder (monitor);
          if (orb_core->reactor ()->schedule_timer (monitor, nullptr, MONITOR_INTERVAL, MONITOR_INTERVAL) == -1)
            ORBSVCS_ERROR ((LM_ERROR, ACE_TEXT ("(%P|%t) Self_Check: cannot schedule the security monitor\n")));
        }

      return counts[CHECK_FAIL] == 0;
    }
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL
