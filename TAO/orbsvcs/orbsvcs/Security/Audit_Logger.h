// -*- C++ -*-

//=============================================================================
/**
 * @file Audit_Logger.h
 *
 * Security audit records for TAO services: one structured syslog line per
 * security decision, kept apart from debug logging.
 *
 * Each record is an RFC 5424 structured-data element,
 * @code
 *   [audit@32473 mode="prod" svc="naming" event="authz" result="deny"
 *    reason="NO_ROLE" src="10.20.4.17:51544" op="bind"]
 * @endcode
 * sent with facility authpriv.  Repeated failures from one source are
 * rate limited into a summary record, and when the sink fails the records
 * go to stderr and the registered alarm callbacks are told, so a lost
 * audit trail never goes unnoticed.
 */
//=============================================================================

#ifndef TAO_SECURITY_AUDIT_LOGGER_H
#define TAO_SECURITY_AUDIT_LOGGER_H

#include /**/ "ace/pre.h"
#include "orbsvcs/Security/security_export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "tao/Versioned_Namespace.h"
#include "ace/Time_Value.h"
#include "tao/orbconf.h"
#include "ace/Synch_Traits.h"
#include "ace/Thread_Mutex.h"

#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace Security
  {
    /// Reason codes for audit records.  Dashboards and alerts match on
    /// these, so they are a fixed list rather than free text.
    namespace Audit_Reason
    {
      constexpr char const OK[] = "OK";
      constexpr char const TLS_HANDSHAKE_FAILED[] = "TLS_HANDSHAKE_FAILED";
      constexpr char const CERT_EXPIRED[] = "CERT_EXPIRED";
      constexpr char const CERT_UNTRUSTED[] = "CERT_UNTRUSTED";
      constexpr char const CERT_DENIED[] = "CERT_DENIED";
      constexpr char const NO_CLIENT_CERT[] = "NO_CLIENT_CERT";
      constexpr char const PLAINTEXT_REFUSED[] = "PLAINTEXT_REFUSED";
      constexpr char const TOKEN_EXPIRED[] = "TOKEN_EXPIRED";
      constexpr char const TOKEN_INVALID[] = "TOKEN_INVALID";
      constexpr char const TOKEN_REPLAY[] = "TOKEN_REPLAY";
      constexpr char const CNF_MISMATCH[] = "CNF_MISMATCH";
      constexpr char const NO_ROLE[] = "NO_ROLE";
      constexpr char const LOCKED_OUT[] = "LOCKED_OUT";
      constexpr char const RATE_LIMITED[] = "RATE_LIMITED";
      constexpr char const AUDIT_SELF_TEST[] = "AUDIT_SELF_TEST";
      constexpr char const AUDIT_SINK_FAILED[] = "AUDIT_SINK_FAILED";
      constexpr char const AUDIT_SINK_RECOVERED[] = "AUDIT_SINK_RECOVERED";
      constexpr char const SELF_CHECK_FAILED[] = "SELF_CHECK_FAILED";
      constexpr char const TIME_UNSYNCED[] = "TIME_UNSYNCED";
      constexpr char const TIME_SYNCED[] = "TIME_SYNCED";
      constexpr char const MODE_SET[] = "MODE_SET";
      constexpr char const HOST_ENROLLED[] = "HOST_ENROLLED";
      constexpr char const HOST_UNENROLLED[] = "HOST_UNENROLLED";
      constexpr char const KEY_CREATED[] = "KEY_CREATED";
      constexpr char const CERT_ISSUED[] = "CERT_ISSUED";
      constexpr char const CERT_RENEWED[] = "CERT_RENEWED";
      constexpr char const CERT_DENYLISTED[] = "CERT_DENYLISTED";
      constexpr char const DENYLIST_LOADED[] = "DENYLIST_LOADED";
      constexpr char const DENYLIST_REJECTED[] = "DENYLIST_REJECTED";
      constexpr char const DENYLIST_SIGNED[] = "DENYLIST_SIGNED";
      constexpr char const CONNECTION_REFUSED[] = "CONNECTION_REFUSED";
      constexpr char const ACCESS_DENIED[] = "ACCESS_DENIED";
      constexpr char const ACCESS_GRANTED[] = "ACCESS_GRANTED";
      constexpr char const ACCESS_LIST_LOADED[] = "ACCESS_LIST_LOADED";
      constexpr char const ACCESS_LIST_REJECTED[] = "ACCESS_LIST_REJECTED";
      constexpr char const ACCESS_LIST_SIGNED[] = "ACCESS_LIST_SIGNED";
      constexpr char const IOR_TLS_MISMATCH[] = "IOR_TLS_MISMATCH";
      constexpr char const SAS_ACCEPTED[] = "SAS_ACCEPTED";
      constexpr char const SAS_MISSING[] = "SAS_MISSING";
      constexpr char const SAS_INVALID_EVIDENCE[] = "SAS_INVALID_EVIDENCE";
      constexpr char const SAS_INVALID_MECH[] = "SAS_INVALID_MECH";
      constexpr char const SAS_NO_CONTEXT[] = "SAS_NO_CONTEXT";
      constexpr char const SAS_NO_TLS[] = "SAS_NO_TLS";
      constexpr char const SAS_AUTHZ_TOKEN_IGNORED[] = "SAS_AUTHZ_TOKEN_IGNORED";
      constexpr char const GSSUP_FAILED[] = "GSSUP_FAILED";
      constexpr char const GSSUP_LOCKED[] = "GSSUP_LOCKED";
      constexpr char const GSSUP_RATE_LIMITED[] = "GSSUP_RATE_LIMITED";
      constexpr char const GSSUP_STORE_LOADED[] = "GSSUP_STORE_LOADED";
      constexpr char const GSSUP_STORE_REJECTED[] = "GSSUP_STORE_REJECTED";
      constexpr char const GSSUP_USER_CHANGED[] = "GSSUP_USER_CHANGED";
      constexpr char const ASSERTION_REJECTED[] = "ASSERTION_REJECTED";
      constexpr char const ASSERTER_LIST_LOADED[] = "ASSERTER_LIST_LOADED";
      constexpr char const ASSERTER_LIST_REJECTED[] = "ASSERTER_LIST_REJECTED";
      constexpr char const ASSERTER_LIST_SIGNED[] = "ASSERTER_LIST_SIGNED";
      // Client side (W6)
      constexpr char const SAS_CLIENT_NO_CREDENTIALS[] = "SAS_CLIENT_NO_CREDENTIALS";
      constexpr char const SAS_CLIENT_REFUSED[] = "SAS_CLIENT_REFUSED";
      constexpr char const SAS_CLIENT_SENT[] = "SAS_CLIENT_SENT";
      constexpr char const GSSUP_CREDENTIALS_ACQUIRED[] = "GSSUP_CREDENTIALS_ACQUIRED";
    }

    /**
     * @class Audit_Record
     *
     * @brief One security decision.
     *
     * The event names what was decided ("tls", "authn", "authz",
     * "invoke", ...); @a success and the event give the result field
     * ("allow"/"deny" for authz, "ok"/"fail" otherwise).  Fields are
     * written in the order they are added.  Never put payloads, tokens or
     * anything that could hold card or patient data in a field: log
     * certificate serials and token ids instead.
     */
    class TAO_Security_Export Audit_Record
    {
    public:
      Audit_Record (char const *event, bool success, char const *reason);

      /// Adds a field; a null or empty value is skipped.
      Audit_Record &field (char const *name, char const *value);
      Audit_Record &field (char const *name, std::string const &value);

      /// Free text after the structured data, for people reading the log.
      Audit_Record &text (char const *text);

      char const *event () const;
      bool success () const;
      char const *result () const;
      char const *reason () const;
      /// Value of the named field, or nullptr.
      char const *find (char const *name) const;

      using Fields = std::vector<std::pair<std::string, std::string>>;
      Fields const &fields () const;
      std::string const &text () const;

      /// Event time; ACE_Time_Value::zero means "when written".
      ACE_Time_Value time;

    private:
      std::string event_;
      bool success_;
      std::string reason_;
      Fields fields_;
      std::string text_;
    };

    /**
     * @class Audit_Logger
     *
     * @brief Writes Audit_Records to syslog.
     *
     * Sinks:
     *   - @c syslog: syslog(3) with facility authpriv (the macOS default;
     *     records reach the unified log).  syslog(3) reports no errors, so
     *     a failed sink cannot be detected with it.
     *   - @c unix:PATH: datagrams to a local syslog socket, RFC 3164
     *     framing (the default elsewhere, @c unix:/dev/log).  macOS
     *     syslogd discards datagrams on /var/run/syslog; use it only for
     *     a socket that syslog-ng listens on.
     *   - @c tcp:HOST:PORT: RFC 5424 records with octet-counting framing
     *     (RFC 6587), e.g. syslog-ng's syslog() source on port 601.
     *   - @c stderr: one line per record, for containers and tests.
     *
     * A failed write sends the record to stderr, marks the logger
     * unhealthy, raises a SECURITY_DEGRADED alarm (stderr, syslog(3) at
     * LOG_ALERT and the alarm callbacks), and retries the sink with
     * backoff.  The first successful write afterwards logs an
     * AUDIT_SINK_RECOVERED record with the number of records that went
     * only to stderr.
     *
     * Failures (deny/fail) are rate limited per source host: past the
     * limit within one window they are counted, not written, and one
     * RATE_LIMITED summary record reports the count when the window ends.
     * Summaries are written by the next write() or flush() after the
     * window; call flush() from a timer if records may stop arriving.
     *
     * The logger is thread safe.
     */
    class TAO_Security_Export Audit_Logger
    {
    public:
      struct TAO_Security_Export Options
      {
        Options ();

        /// Sink, as described above.
        std::string sink;
        /// Value of the svc field: the service writing the records.
        std::string service;
        /// Value of the mode field ("test", "prod", or "none").
        std::string mode;
        /// Syslog APP-NAME / tag.
        std::string app_name;
        /// Failures written per source within @a rate_window; 0 disables
        /// rate limiting.
        unsigned int rate_count;
        ACE_Time_Value rate_window;
        /// Sources tracked at once; further sources share one bucket.
        size_t rate_sources;
      };

      /// Called with false when the sink fails and true when it
      /// recovers, outside the logger's lock.
      using Alarm_Callback = void (*) (bool healthy, char const *detail, void *arg);

      Audit_Logger ();
      ~Audit_Logger ();

      /**
       * The process-wide logger.  On first use it is configured from the
       * host security configuration (TAO_Security_Mode::host()): keys
       * mode, audit_sink and audit_rate (COUNT/SECONDS).  The svc field comes from ACE_TAO_AUDIT_SERVICE
       * or the program name.
       */
      static Audit_Logger *instance ();

      /// Options from a security configuration file and the
      /// environment.  A missing file gives the defaults.
      static Options options_from_config (char const *path);

      /// Replaces the options and reopens the sink.
      void configure (Options const &options);
      Options options () const;

      /// Writes (or rate limits) one record.
      void write (Audit_Record const &record);

      /// Writes due rate-limit summaries and retries a failed sink.
      void flush ();

      /// Writes an AUDIT_SELF_TEST record; true if the sink accepted it.
      bool self_test ();

      /// False after a write failed, until the sink recovers.
      bool healthy () const;

      /// Records written only to stderr since the sink failed.
      unsigned long fallback_count () const;

      void add_alarm_callback (Alarm_Callback cb, void *arg);
      void remove_alarm_callback (Alarm_Callback cb, void *arg);

      /// Escapes an RFC 5424 PARAM-VALUE: '"', '\' and ']' get a
      /// backslash, control characters become '?', and the result is cut
      /// to @a max bytes.
      static std::string escape_value (std::string const &value, size_t max);

      /// The RFC 5424 SD-ID of audit records.
      static char const *sd_id ();

    private:
      Audit_Logger (Audit_Logger const &) = delete;
      Audit_Logger &operator= (Audit_Logger const &) = delete;

      struct Bucket
      {
        ACE_Time_Value start;
        unsigned int count {0};
        unsigned long suppressed {0};
      };

      struct Alarm
      {
        bool healthy;
        std::string detail;
      };

      // All *_i methods are called with lock_ held.
      void write_i (Audit_Record const &record, std::vector<Alarm> &alarms);
      bool rate_limited_i (Audit_Record const &record, ACE_Time_Value const &now,
                           std::vector<Alarm> &alarms);
      void sweep_i (ACE_Time_Value const &now, bool all, std::vector<Alarm> &alarms);
      void summary_i (std::string const &source, Bucket const &bucket,
                      std::vector<Alarm> &alarms);
      bool emit_i (Audit_Record const &record, int severity, std::vector<Alarm> &alarms);
      bool send_i (std::string const &line, int severity);
      bool open_i ();
      void close_i ();
      void failed_i (int error, std::string const &msg, ACE_Time_Value const &now,
                     std::vector<Alarm> &alarms);
      void alarm_text_i (char const *text);
      std::string structured_data_i (Audit_Record const &record) const;
      std::string frame_i (Audit_Record const &record, std::string const &sd,
                           int severity) const;
      void notify (std::vector<Alarm> const &alarms);

      static std::string source_key (Audit_Record const &record);

      mutable TAO_SYNCH_MUTEX lock_;
      Options options_;

      enum Sink_Kind { SINK_SYSLOG, SINK_UNIX, SINK_TCP, SINK_STDERR };
      Sink_Kind kind_;
      std::string target_;
      ACE_HANDLE handle_;

      bool healthy_;
      unsigned long fallback_count_;
      ACE_Time_Value failed_at_;
      ACE_Time_Value next_retry_;
      ACE_Time_Value retry_delay_;
      ACE_Time_Value next_alarm_;
      int last_error_;
      /// Set when the options name no usable sink; the logger then stays
      /// unhealthy and writes to stderr until configure() fixes it.
      std::string config_error_;

      std::unordered_map<std::string, Bucket> buckets_;
      ACE_Time_Value next_sweep_;

      std::string hostname_;
      long pid_;

      std::vector<std::pair<Alarm_Callback, void *>> callbacks_;
    };
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#include /**/ "ace/post.h"

#endif /* TAO_SECURITY_AUDIT_LOGGER_H */
