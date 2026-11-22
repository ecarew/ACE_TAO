// -*- C++ -*-

//=============================================================================
/**
 * @file Self_Check.h
 *
 * The security plugin's startup self-check and its running monitor, for
 * hosts in mode test or prod (see tao/Security_Mode.h); dev and embedded
 * run no checks.
 *
 * At ORB initialization the self-check verifies, for this process:
 *   - the security configuration is not writable by others;
 *   - the audit sink accepts a record;
 *   - the clock is synchronized, within max_clock_error (prod waits up to
 *     time_sync_wait for synchronization after boot);
 *   - core dumps are off (prod turns them off);
 *   - only TLS protocol factories are loaded (allowed_protocols);
 *   - whatever other libraries contributed (SSLIOP: protected key,
 *     passphrase source, trust anchors).
 * In prod a failed check fails the ORB; in test it is a warning.  Every
 * result, and a one-line banner, goes to stderr and syslog, and the
 * banner also to the audit log.  The result is reported to
 * TAO_Security_Mode, whose guard in ORB_init refuses a failed prod ORB.
 *
 * While the ORB runs, the monitor fails closed: in prod, while the audit
 * sink is down, new requests are refused with CORBA::TRANSIENT and
 * SECURITY_DEGRADED alarms are logged; service resumes when the sink
 * recovers.  Lost time synchronization raises TIME_UNSYNCED alarms every
 * 5 minutes but never stops the service.  In test, a TEST MODE reminder
 * is logged every hour.
 */
//=============================================================================

#ifndef TAO_SECURITY_SELF_CHECK_H
#define TAO_SECURITY_SELF_CHECK_H

#include /**/ "ace/pre.h"
#include "orbsvcs/Security/security_export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "tao/PI/ORBInitInfo.h"

#include <string>
#include <vector>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

class TAO_ORB_Core;

namespace TAO
{
  namespace Security
  {
    class TAO_Security_Export Self_Check
    {
    public:
      enum Status { CHECK_OK, CHECK_WARN, CHECK_FAIL };

      struct Result
      {
        std::string name;
        Status status;
        std::string detail;
      };

      /**
       * Adds a check result computed by another library before the ORB
       * initializers run (SSLIOP does this while parsing its options).
       * Pass the status for the current mode: CHECK_FAIL only where prod
       * must refuse.  Results are per process and used by every ORB.
       */
      static void contribute (char const *name, Status status, char const *detail);

      /// Adds a "key=value" field to the startup banner.
      static void banner_field (char const *key, char const *value);

      /**
       * Runs the self-check for @a orb_core, logs it, reports it to
       * TAO_Security_Mode, and in prod or test registers the running
       * monitor on @a info.  Does nothing on a host without a security
       * mode.  Returns false if a check failed.
       */
      static bool run (TAO_ORB_Core *orb_core, PortableInterceptor::ORBInitInfo_ptr info);

      /// The checks of the last run(), for tests.
      static std::vector<Result> last_results ();

      /// True while the monitor refuses requests (prod, audit sink down).
      static bool degraded ();

      /// Lower-case hex SHA-256 of a file, or "" if unreadable.
      static std::string sha256_file (char const *path);

      /// Clock state from the kernel: 1 synchronized, 0 not, -1 unknown.
      /// @a max_error_ms receives the kernel's error estimate.
      static int clock_synchronized (long &max_error_ms);
    };
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#include /**/ "ace/post.h"

#endif /* TAO_SECURITY_SELF_CHECK_H */
