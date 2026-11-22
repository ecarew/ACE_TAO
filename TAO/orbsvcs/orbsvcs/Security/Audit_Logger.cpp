#include "orbsvcs/Log_Macros.h"
#include "orbsvcs/Security/Audit_Logger.h"

#include "ace/ACE.h"
#include "ace/Guard_T.h"
#include "ace/INET_Addr.h"
#include "ace/OS_NS_errno.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_socket.h"
#include "ace/OS_NS_sys_time.h"
#include "ace/OS_NS_time.h"
#include "ace/OS_NS_unistd.h"
#include "ace/SOCK_Connector.h"
#include "ace/SOCK_Stream.h"
#include "ace/UNIX_Addr.h"
#include "ace/os_include/os_netdb.h"

#include <algorithm>

#if !defined (ACE_LACKS_UNIX_SYSLOG)
# include <syslog.h>
#endif /* !ACE_LACKS_UNIX_SYSLOG */

#if !defined (TAO_SECURITY_CONF_DEFAULT)
# define TAO_SECURITY_CONF_DEFAULT "/etc/ace-tao/security.conf"
#endif /* !TAO_SECURITY_CONF_DEFAULT */

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  // Syslog severities (RFC 5424) and the authpriv facility, spelled out
  // so the framing works where <syslog.h> is missing.
  constexpr int SEV_ALERT = 1;
  constexpr int SEV_WARNING = 4;
  constexpr int SEV_NOTICE = 5;
  constexpr int SEV_INFO = 6;
  constexpr int FACILITY_AUTHPRIV = 10;

  // RFC 5612 documentation enterprise number until one is assigned.
  constexpr char const SD_ID[] = "audit@32473";

  constexpr size_t MAX_VALUE = 256;
  constexpr size_t MAX_TEXT = 512;
  constexpr size_t MAX_FIELDS = 24;

  ACE_Time_Value const SEND_TIMEOUT (0, 250000);
  ACE_Time_Value const CONNECT_TIMEOUT (2);
  ACE_Time_Value const RETRY_MIN (1);
  ACE_Time_Value const RETRY_MAX (30);
  ACE_Time_Value const ALARM_REPEAT (60);
  ACE_Time_Value const SWEEP_INTERVAL (1);

  bool
  valid_name (std::string const &name)
  {
    if (name.empty () || name.size () > 32)
      return false;
    for (char const c : name)
      if (c <= ' ' || c > '~' || c == '=' || c == ']' || c == '"')
        return false;
    return true;
  }

  std::string
  sanitize_text (std::string const &text, size_t max)
  {
    std::string out;
    for (char const c : text)
      {
        if (out.size () >= max)
          break;
        unsigned char const u = static_cast<unsigned char> (c);
        out += (u < 0x20 || u == 0x7f) ? '?' : c;
      }
    return out;
  }

  std::string
  trim (std::string const &s)
  {
    size_t const b = s.find_first_not_of (" \t\r\n");
    if (b == std::string::npos)
      return std::string ();
    size_t const e = s.find_last_not_of (" \t\r\n");
    std::string v = s.substr (b, e - b + 1);
    if (v.size () >= 2 && (v.front () == '"' || v.front () == '\'') && v.back () == v.front ())
      v = v.substr (1, v.size () - 2);
    return v;
  }

  std::string
  iso_time (ACE_Time_Value const &tv)
  {
    time_t const secs = tv.sec ();
    struct tm tm_buf;
    if (ACE_OS::gmtime_r (&secs, &tm_buf) == nullptr)
      return "-";
    char buf[64];
    ACE_OS::snprintf (buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ",
                      tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                      tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
                      static_cast<long> (tv.usec ()));
    return buf;
  }

  std::string
  bsd_time (ACE_Time_Value const &tv)
  {
    time_t const secs = tv.sec ();
    struct tm tm_buf;
    char buf[32];
    if (ACE_OS::localtime_r (&secs, &tm_buf) == nullptr
        || ACE_OS::strftime (buf, sizeof buf, "%b %e %H:%M:%S", &tm_buf) == 0)
      return "Jan  1 00:00:00";
    return buf;
  }

  std::string
  error_text (int error)
  {
    char const *const s = ACE_OS::strerror (error);
    return s ? s : "unknown error";
  }
}

namespace TAO
{
  namespace Security
  {
    // ------------------------------------------------------------------
    // Audit_Record

    Audit_Record::Audit_Record (char const *event, bool success, char const *reason)
      : time (ACE_Time_Value::zero),
        event_ (event ? event : "other"),
        success_ (success),
        reason_ (reason ? reason : (success ? Audit_Reason::OK : ""))
    {
    }

    Audit_Record &
    Audit_Record::field (char const *name, char const *value)
    {
      if (name != nullptr && value != nullptr && *value != '\0')
        this->fields_.emplace_back (name, value);
      return *this;
    }

    Audit_Record &
    Audit_Record::field (char const *name, std::string const &value)
    {
      return this->field (name, value.c_str ());
    }

    Audit_Record &
    Audit_Record::text (char const *text)
    {
      this->text_ = text ? text : "";
      return *this;
    }

    char const *
    Audit_Record::event () const
    {
      return this->event_.c_str ();
    }

    bool
    Audit_Record::success () const
    {
      return this->success_;
    }

    char const *
    Audit_Record::result () const
    {
      if (this->event_ == "authz")
        return this->success_ ? "allow" : "deny";
      return this->success_ ? "ok" : "fail";
    }

    char const *
    Audit_Record::reason () const
    {
      return this->reason_.c_str ();
    }

    char const *
    Audit_Record::find (char const *name) const
    {
      for (auto const &f : this->fields_)
        if (f.first == name)
          return f.second.c_str ();
      return nullptr;
    }

    Audit_Record::Fields const &
    Audit_Record::fields () const
    {
      return this->fields_;
    }

    std::string const &
    Audit_Record::text () const
    {
      return this->text_;
    }

    // ------------------------------------------------------------------
    // Audit_Logger

    Audit_Logger::Options::Options ()
      : sink (
#if defined (__APPLE__)
              "syslog"
#elif !defined (ACE_LACKS_UNIX_DOMAIN_SOCKETS)
              "unix:/dev/log"
#else
              "stderr"
#endif
              ),
        mode ("none"),
        app_name ("ace-tao-audit"),
        rate_count (20),
        rate_window (60),
        rate_sources (4096)
    {
      char const *const prog = ACE_OS::getprogname ();
      this->service = (prog && *prog) ? prog : "unknown";
    }

    Audit_Logger::Audit_Logger ()
      : kind_ (SINK_STDERR),
        handle_ (ACE_INVALID_HANDLE),
        healthy_ (true),
        fallback_count_ (0),
        retry_delay_ (RETRY_MIN),
        last_error_ (0),
        pid_ (static_cast<long> (ACE_OS::getpid ()))
    {
      char host[MAXHOSTNAMELEN + 1];
      if (ACE_OS::hostname (host, sizeof host) == 0)
        {
          host[MAXHOSTNAMELEN] = '\0';
          this->hostname_ = host;
        }
      else
        this->hostname_ = "-";
      this->configure (Options ());
    }

    Audit_Logger::~Audit_Logger ()
    {
      std::vector<Alarm> alarms;
      {
        ACE_GUARD (ACE_Thread_Mutex, guard, this->lock_);
        this->sweep_i (ACE_OS::gettimeofday (), true, alarms);
        this->close_i ();
      }
    }

    Audit_Logger *
    Audit_Logger::instance ()
    {
      // Never destroyed: records can be written by threads that outlive
      // static destruction.
      static Audit_Logger *const logger = []
        {
          Audit_Logger *const l = new Audit_Logger;
          l->configure (Audit_Logger::options_from_config (nullptr));
          return l;
        } ();
      return logger;
    }

    Audit_Logger::Options
    Audit_Logger::options_from_config (char const *path)
    {
      Options opts;
      if (path == nullptr)
        {
          path = ACE_OS::getenv ("ACE_TAO_SECURITY_CONF");
          if (path == nullptr || *path == '\0')
            path = TAO_SECURITY_CONF_DEFAULT;
        }

      FILE *const fp = ACE_OS::fopen (path, ACE_TEXT ("r"));
      if (fp != nullptr)
        {
          char line[1024];
          while (ACE_OS::fgets (line, sizeof line, fp) != nullptr)
            {
              std::string l (line);
              size_t const hash = l.find ('#');
              if (hash != std::string::npos)
                l.erase (hash);
              size_t const eq = l.find ('=');
              if (eq == std::string::npos)
                continue;
              std::string const key = trim (l.substr (0, eq));
              std::string const value = trim (l.substr (eq + 1));
              if (key == "mode")
                opts.mode = value;
              else if (key == "audit_sink")
                opts.sink = value;
              else if (key == "audit_rate")
                {
                  unsigned int count = 0;
                  unsigned int secs = 0;
                  if (::sscanf (value.c_str (), "%u/%u", &count, &secs) == 2 && secs > 0)
                    {
                      opts.rate_count = count;
                      opts.rate_window = ACE_Time_Value (secs);
                    }
                  else
                    ORBSVCS_ERROR ((LM_ERROR,
                                    ACE_TEXT ("(%P|%t) Audit_Logger: %C: bad audit_rate ")
                                    ACE_TEXT ("\"%C\" (want COUNT/SECONDS); using %u/%d\n"),
                                    path, value.c_str (), opts.rate_count,
                                    static_cast<int> (opts.rate_window.sec ())));
                }
            }
          ACE_OS::fclose (fp);
        }

      char const *const svc = ACE_OS::getenv ("ACE_TAO_AUDIT_SERVICE");
      if (svc != nullptr && *svc != '\0')
        opts.service = svc;
      return opts;
    }

    void
    Audit_Logger::configure (Options const &options)
    {
      std::vector<Alarm> alarms;
      {
        ACE_GUARD (ACE_Thread_Mutex, guard, this->lock_);
        this->close_i ();
        this->options_ = options;
        this->buckets_.clear ();
        this->healthy_ = true;
        this->fallback_count_ = 0;
        this->retry_delay_ = RETRY_MIN;
        this->next_retry_ = ACE_Time_Value::zero;
        this->last_error_ = 0;
        this->config_error_.clear ();

        std::string const &s = options.sink;
        if (s == "syslog")
          {
#if defined (ACE_LACKS_UNIX_SYSLOG)
            this->kind_ = SINK_STDERR;
#else
            this->kind_ = SINK_SYSLOG;
#endif /* ACE_LACKS_UNIX_SYSLOG */
            this->target_.clear ();
          }
        else if (s.compare (0, 5, "unix:") == 0 && s.size () > 5)
          {
            this->kind_ = SINK_UNIX;
            this->target_ = s.substr (5);
          }
        else if (s.compare (0, 4, "tcp:") == 0 && s.size () > 4)
          {
            this->kind_ = SINK_TCP;
            this->target_ = s.substr (4);
          }
        else if (s == "stderr")
          {
            this->kind_ = SINK_STDERR;
            this->target_.clear ();
          }
        else
          {
            // An unknown sink must not silently drop the audit trail.
            this->kind_ = SINK_STDERR;
            this->target_.clear ();
            this->config_error_ = "unknown audit sink \"" + s + "\"";
            this->failed_i (EINVAL, this->config_error_, ACE_OS::gettimeofday (), alarms);
          }
      }
      this->notify (alarms);
    }

    Audit_Logger::Options
    Audit_Logger::options () const
    {
      ACE_GUARD_RETURN (ACE_Thread_Mutex, guard, this->lock_, Options ());
      return this->options_;
    }

    void
    Audit_Logger::write (Audit_Record const &record)
    {
      std::vector<Alarm> alarms;
      {
        ACE_GUARD (ACE_Thread_Mutex, guard, this->lock_);
        this->write_i (record, alarms);
      }
      this->notify (alarms);
    }

    void
    Audit_Logger::flush ()
    {
      std::vector<Alarm> alarms;
      {
        ACE_GUARD (ACE_Thread_Mutex, guard, this->lock_);
        ACE_Time_Value const now = ACE_OS::gettimeofday ();
        this->sweep_i (now, false, alarms);
        if (!this->healthy_ && now >= this->next_retry_)
          {
            // Probe the sink so recovery is noticed without new records.
            Audit_Record probe ("audit", true, Audit_Reason::AUDIT_SELF_TEST);
            this->emit_i (probe, SEV_INFO, alarms);
          }
        else if (!this->healthy_ && now >= this->next_alarm_)
          {
            this->next_alarm_ = now + ALARM_REPEAT;
            this->alarm_text_i (("audit sink still failing: " + error_text (this->last_error_)).c_str ());
          }
      }
      this->notify (alarms);
    }

    bool
    Audit_Logger::self_test ()
    {
      std::vector<Alarm> alarms;
      bool ok = false;
      {
        ACE_GUARD_RETURN (ACE_Thread_Mutex, guard, this->lock_, false);
        // Bypass the retry delay: a self-check wants the current answer.
        this->next_retry_ = ACE_Time_Value::zero;
        Audit_Record probe ("audit", true, Audit_Reason::AUDIT_SELF_TEST);
        ok = this->emit_i (probe, SEV_INFO, alarms) && this->healthy_;
      }
      this->notify (alarms);
      return ok;
    }

    bool
    Audit_Logger::healthy () const
    {
      ACE_GUARD_RETURN (ACE_Thread_Mutex, guard, this->lock_, false);
      return this->healthy_;
    }

    unsigned long
    Audit_Logger::fallback_count () const
    {
      ACE_GUARD_RETURN (ACE_Thread_Mutex, guard, this->lock_, 0);
      return this->fallback_count_;
    }

    void
    Audit_Logger::add_alarm_callback (Alarm_Callback cb, void *arg)
    {
      ACE_GUARD (ACE_Thread_Mutex, guard, this->lock_);
      this->callbacks_.emplace_back (cb, arg);
    }

    void
    Audit_Logger::remove_alarm_callback (Alarm_Callback cb, void *arg)
    {
      ACE_GUARD (ACE_Thread_Mutex, guard, this->lock_);
      for (auto i = this->callbacks_.begin (); i != this->callbacks_.end (); ++i)
        if (i->first == cb && i->second == arg)
          {
            this->callbacks_.erase (i);
            return;
          }
    }

    std::string
    Audit_Logger::escape_value (std::string const &value, size_t max)
    {
      std::string out;
      for (char const c : value)
        {
          unsigned char const u = static_cast<unsigned char> (c);
          size_t const need = (c == '"' || c == '\\' || c == ']') ? 2 : 1;
          if (out.size () + need > max)
            break;
          if (need == 2)
            out += '\\';
          out += (u < 0x20 || u == 0x7f) ? '?' : c;
        }
      return out;
    }

    char const *
    Audit_Logger::sd_id ()
    {
      return SD_ID;
    }

    void
    Audit_Logger::write_i (Audit_Record const &record, std::vector<Alarm> &alarms)
    {
      ACE_Time_Value const now = ACE_OS::gettimeofday ();
      if (now >= this->next_sweep_)
        {
          this->next_sweep_ = now + SWEEP_INTERVAL;
          this->sweep_i (now, false, alarms);
        }

      if (this->rate_limited_i (record, now, alarms))
        return;

      this->emit_i (record, record.success () ? SEV_INFO : SEV_NOTICE, alarms);
    }

    bool
    Audit_Logger::rate_limited_i (Audit_Record const &record,
                                  ACE_Time_Value const &now,
                                  std::vector<Alarm> &alarms)
    {
      if (record.success () || this->options_.rate_count == 0)
        return false;

      std::string key = source_key (record);
      auto it = this->buckets_.find (key);
      if (it == this->buckets_.end ())
        {
          if (this->buckets_.size () >= this->options_.rate_sources)
            this->sweep_i (now, false, alarms);
          if (this->buckets_.size () >= this->options_.rate_sources)
            key = "*";
          it = this->buckets_.emplace (key, Bucket ()).first;
          it->second.start = now;
        }

      Bucket &b = it->second;
      if (now - b.start >= this->options_.rate_window)
        {
          if (b.suppressed > 0)
            this->summary_i (key, b, alarms);
          b.start = now;
          b.count = 0;
          b.suppressed = 0;
        }

      if (++b.count > this->options_.rate_count)
        {
          ++b.suppressed;
          return true;
        }
      return false;
    }

    void
    Audit_Logger::sweep_i (ACE_Time_Value const &now, bool all,
                           std::vector<Alarm> &alarms)
    {
      for (auto it = this->buckets_.begin (); it != this->buckets_.end (); )
        {
          if (all || now - it->second.start >= this->options_.rate_window)
            {
              if (it->second.suppressed > 0)
                this->summary_i (it->first, it->second, alarms);
              it = this->buckets_.erase (it);
            }
          else
            ++it;
        }
    }

    void
    Audit_Logger::summary_i (std::string const &source, Bucket const &bucket,
                             std::vector<Alarm> &alarms)
    {
      Audit_Record r ("ratelimit", false, Audit_Reason::RATE_LIMITED);
      r.field ("src", source)
       .field ("suppressed", std::to_string (bucket.suppressed))
       .field ("window", std::to_string (this->options_.rate_window.sec ()) + "s");
      r.time = bucket.start;
      this->emit_i (r, SEV_WARNING, alarms);
    }

    bool
    Audit_Logger::emit_i (Audit_Record const &record, int severity,
                          std::vector<Alarm> &alarms)
    {
      ACE_Time_Value const now = ACE_OS::gettimeofday ();
      std::string const sd = this->structured_data_i (record);

      if (!this->healthy_)
        {
          if (now < this->next_retry_ || !this->config_error_.empty ())
            {
              ++this->fallback_count_;
              ACE_OS::fprintf (stderr, "%s[%ld]: AUDIT-FALLBACK %s\n",
                               this->options_.app_name.c_str (), this->pid_, sd.c_str ());
              if (now >= this->next_alarm_)
                {
                  this->next_alarm_ = now + ALARM_REPEAT;
                  this->alarm_text_i ((this->config_error_.empty ()
                                       ? "audit sink still failing: " + error_text (this->last_error_)
                                       : this->config_error_).c_str ());
                }
              return false;
            }

          // Retry: announce the recovery first, so the gap is on record.
          Audit_Record rec ("audit", true, Audit_Reason::AUDIT_SINK_RECOVERED);
          rec.field ("sink", this->options_.sink)
             .field ("fallback_records", std::to_string (this->fallback_count_))
             .field ("down_for", std::to_string ((now - this->failed_at_).sec ()) + "s");
          std::string const rsd = this->structured_data_i (rec);
          if (!this->send_i (this->frame_i (rec, rsd, SEV_WARNING), SEV_WARNING))
            {
              int const err = this->last_error_;
              ++this->fallback_count_;
              ACE_OS::fprintf (stderr, "%s[%ld]: AUDIT-FALLBACK %s\n",
                               this->options_.app_name.c_str (), this->pid_, sd.c_str ());
              this->failed_i (err, "audit sink " + this->options_.sink + " failed: "
                              + error_text (err), now, alarms);
              return false;
            }
          this->healthy_ = true;
          this->fallback_count_ = 0;
          this->retry_delay_ = RETRY_MIN;
          alarms.push_back ({true, "audit sink " + this->options_.sink + " recovered"});
        }

      if (this->send_i (this->frame_i (record, sd, severity), severity))
        return true;

      int const err = this->last_error_;
      ++this->fallback_count_;
      ACE_OS::fprintf (stderr, "%s[%ld]: AUDIT-FALLBACK %s\n",
                       this->options_.app_name.c_str (), this->pid_, sd.c_str ());
      this->failed_i (err, "audit sink " + this->options_.sink + " failed: "
                      + error_text (err), now, alarms);
      return false;
    }

    std::string
    Audit_Logger::structured_data_i (Audit_Record const &record) const
    {
      std::string sd ("[");
      sd += SD_ID;
      auto add = [&sd] (char const *name, std::string const &value)
        {
          sd += ' ';
          sd += name;
          sd += "=\"";
          sd += escape_value (value, MAX_VALUE);
          sd += '"';
        };
      add ("mode", this->options_.mode);
      add ("svc", this->options_.service);
      add ("event", record.event ());
      add ("result", record.result ());
      if (*record.reason () != '\0')
        add ("reason", record.reason ());

      size_t n = 0;
      for (auto const &f : record.fields ())
        {
          if (n++ >= MAX_FIELDS)
            break;
          if (valid_name (f.first))
            add (f.first.c_str (), f.second);
        }
      sd += ']';

      if (!record.text ().empty ())
        {
          sd += ' ';
          sd += sanitize_text (record.text (), MAX_TEXT);
        }
      return sd;
    }

    std::string
    Audit_Logger::frame_i (Audit_Record const &record, std::string const &sd,
                           int severity) const
    {
      ACE_Time_Value const when =
        record.time == ACE_Time_Value::zero ? ACE_OS::gettimeofday () : record.time;
      int const pri = FACILITY_AUTHPRIV * 8 + severity;
      std::string const pid = std::to_string (this->pid_);

      switch (this->kind_)
        {
        case SINK_UNIX:
          // RFC 3164, as syslog(3) sends it to the local socket.
          return "<" + std::to_string (pri) + ">" + bsd_time (when) + " "
            + this->options_.app_name + "[" + pid + "]: " + sd;
        case SINK_TCP:
          {
            std::string msgid = sanitize_text (record.event (), 32);
            for (char &c : msgid)
              if (c == ' ' || c == '?')
                c = '_';
            std::string const line = "<" + std::to_string (pri) + ">1 " + iso_time (when)
              + " " + this->hostname_ + " " + this->options_.app_name + " " + pid
              + " " + msgid + " " + sd;
            // RFC 6587 octet counting.
            return std::to_string (line.size ()) + " " + line;
          }
        case SINK_STDERR:
          return iso_time (when) + " " + this->options_.app_name + "[" + pid + "]: " + sd + "\n";
        case SINK_SYSLOG:
        default:
          return sd;
        }
    }

    bool
    Audit_Logger::send_i (std::string const &line, int severity)
    {
      switch (this->kind_)
        {
        case SINK_SYSLOG:
#if !defined (ACE_LACKS_UNIX_SYSLOG)
          ::syslog (LOG_AUTHPRIV | severity, "%s", line.c_str ());
#else
          ACE_UNUSED_ARG (severity);
#endif /* !ACE_LACKS_UNIX_SYSLOG */
          return true;

        case SINK_STDERR:
          if (ACE_OS::fputs (line.c_str (), stderr) < 0 || ACE_OS::fflush (stderr) != 0)
            {
              this->last_error_ = errno ? errno : EIO;
              return false;
            }
          return true;

        case SINK_UNIX:
        case SINK_TCP:
          ACE_UNUSED_ARG (severity);
          if (this->kind_ == SINK_TCP && this->handle_ != ACE_INVALID_HANDLE)
            {
              // The collector never sends, so a readable socket means it
              // closed the connection (or reset it).  A send would still
              // succeed into the kernel buffer and the record be lost.
              ACE_Time_Value poll (ACE_Time_Value::zero);
              char c;
              if (ACE::handle_read_ready (this->handle_, &poll) == 1
                  && ACE_OS::recv (this->handle_, &c, 1, MSG_PEEK) <= 0)
                this->close_i ();
            }
          if (this->handle_ == ACE_INVALID_HANDLE && !this->open_i ())
            return false;
          {
            ssize_t sent = 0;
            if (this->kind_ == SINK_UNIX)
              {
                // A full local socket blocks on Linux (up to SO_SNDTIMEO)
                // but fails at once with ENOBUFS on macOS and the BSDs;
                // give a slow reader the same grace there.
                ACE_Time_Value const deadline = ACE_OS::gettimeofday () + SEND_TIMEOUT;
                while ((sent = ACE_OS::send (this->handle_, line.data (), line.size ())) < 0
                       && (errno == ENOBUFS || errno == EAGAIN || errno == EWOULDBLOCK)
                       && ACE_OS::gettimeofday () < deadline)
                  ACE_OS::sleep (ACE_Time_Value (0, 1000));
              }
            else
              {
                ACE_SOCK_Stream stream (this->handle_);
                int flags = 0;
#if defined (MSG_NOSIGNAL)
                flags = MSG_NOSIGNAL;
#endif /* MSG_NOSIGNAL */
                sent = stream.send_n (line.data (), line.size (), flags, &SEND_TIMEOUT);
              }
            if (sent == static_cast<ssize_t> (line.size ()))
              return true;
            this->last_error_ = (sent < 0 && errno != 0) ? errno : EIO;
            this->close_i ();
            return false;
          }
        }
      return false;
    }

    bool
    Audit_Logger::open_i ()
    {
      if (this->kind_ == SINK_UNIX)
        {
#if defined (ACE_LACKS_UNIX_DOMAIN_SOCKETS)
          this->last_error_ = ENOTSUP;
          return false;
#else
          ACE_HANDLE const h = ACE_OS::socket (AF_UNIX, SOCK_DGRAM, 0);
          if (h == ACE_INVALID_HANDLE)
            {
              this->last_error_ = errno;
              return false;
            }
          timeval tv = SEND_TIMEOUT;
          ACE_OS::setsockopt (h, SOL_SOCKET, SO_SNDTIMEO,
                              reinterpret_cast<char const *> (&tv), sizeof tv);
          ACE_UNIX_Addr const addr (this->target_.c_str ());
          if (ACE_OS::connect (h, static_cast<sockaddr *> (addr.get_addr ()),
                               addr.get_size ()) == -1)
            {
              this->last_error_ = errno;
              ACE_OS::closesocket (h);
              return false;
            }
          this->handle_ = h;
          return true;
#endif /* ACE_LACKS_UNIX_DOMAIN_SOCKETS */
        }

      if (this->kind_ == SINK_TCP)
        {
          ACE_INET_Addr addr;
          if (addr.set (this->target_.c_str ()) == -1)
            {
              this->last_error_ = errno ? errno : EINVAL;
              return false;
            }
          ACE_SOCK_Stream stream;
          ACE_SOCK_Connector connector;
          if (connector.connect (stream, addr, &CONNECT_TIMEOUT) == -1)
            {
              this->last_error_ = errno ? errno : ECONNREFUSED;
              stream.close ();
              return false;
            }
#if defined (SO_NOSIGPIPE)
          int one = 1;
          stream.set_option (SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif /* SO_NOSIGPIPE */
          this->handle_ = stream.get_handle ();
          return true;
        }
      return true;
    }

    void
    Audit_Logger::close_i ()
    {
      if (this->handle_ != ACE_INVALID_HANDLE)
        {
          ACE_OS::closesocket (this->handle_);
          this->handle_ = ACE_INVALID_HANDLE;
        }
    }

    void
    Audit_Logger::failed_i (int error, std::string const &msg,
                            ACE_Time_Value const &now, std::vector<Alarm> &alarms)
    {
      this->last_error_ = error;
      if (this->healthy_)
        {
          this->healthy_ = false;
          this->failed_at_ = now;
          this->retry_delay_ = RETRY_MIN;
          this->next_alarm_ = now + ALARM_REPEAT;
          this->alarm_text_i ((msg + "; audit records go to stderr until it recovers").c_str ());
          alarms.push_back ({false, msg});
        }
      this->next_retry_ = now + this->retry_delay_;
      this->retry_delay_ = std::min (this->retry_delay_ * 2, RETRY_MAX);
    }

    void
    Audit_Logger::alarm_text_i (char const *text)
    {
      ACE_OS::fprintf (stderr, "%s[%ld]: ACE/TAO SECURITY_DEGRADED: %s (%s)\n",
                       this->options_.app_name.c_str (), this->pid_, text,
                       Audit_Reason::AUDIT_SINK_FAILED);
#if !defined (ACE_LACKS_UNIX_SYSLOG)
      // A second path, in case only the configured sink is broken.
      if (this->kind_ != SINK_SYSLOG)
        ::syslog (LOG_AUTHPRIV | SEV_ALERT, "ACE/TAO SECURITY_DEGRADED: %s (%s)",
                  text, Audit_Reason::AUDIT_SINK_FAILED);
#endif /* !ACE_LACKS_UNIX_SYSLOG */
    }

    void
    Audit_Logger::notify (std::vector<Alarm> const &alarms)
    {
      if (alarms.empty ())
        return;
      std::vector<std::pair<Alarm_Callback, void *>> callbacks;
      {
        ACE_GUARD (ACE_Thread_Mutex, guard, this->lock_);
        callbacks = this->callbacks_;
      }
      for (auto const &a : alarms)
        for (auto const &cb : callbacks)
          cb.first (a.healthy, a.detail.c_str (), cb.second);
    }

    std::string
    Audit_Logger::source_key (Audit_Record const &record)
    {
      char const *src = record.find ("src");
      if (src == nullptr)
        {
          char const *const peer = record.find ("peer");
          return peer ? peer : "-";
        }
      std::string const s (src);
      if (!s.empty () && s[0] == '[')
        {
          size_t const close = s.find (']');
          return close == std::string::npos ? s : s.substr (1, close - 1);
        }
      size_t const colon = s.find (':');
      if (colon != std::string::npos && s.find (':', colon + 1) == std::string::npos)
        return s.substr (0, colon);
      return s;
    }
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL
