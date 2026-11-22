// -*- C++ -*-

//=============================================================================
/**
 * @file Security_Mode.h
 *
 * The host-wide security mode and the ORB_init guard that enforces it.
 *
 * A host opts in to these checks with a security configuration file,
 * ACE_TAO_SECURITY_CONF or TAO_SECURITY_CONF_DEFAULT
 * (/etc/ace-tao/security.conf), holding @c mode among other
 * "key = value" lines.  Without the file (and without the prod
 * enrollment marker) TAO behaves as it always has.  The modes:
 *   - @c dev: developer machines and labs, synthetic data only.  The
 *     security plugin is optional and no self-check runs.
 *   - @c test: QA or staging that mirrors prod (test CA, no live data).
 *     The full self-check runs and its findings are warnings.
 *   - @c prod: live data.  Everything is enforced.
 *   - @c embedded: a constrained device that cannot run the security
 *     plugin, declared as such.  Runs without it, with a loud banner.
 * Every mode but prod is refused on a host enrolled in prod.
 *
 * At the end of CORBA::ORB_init():
 *   - no file, host not enrolled: nothing happens (mode "none");
 *   - file without a valid mode, unreadable, or writable by others: the
 *     ORB refuses to initialize;
 *   - host enrolled in prod (TAO_SECURITY_ENROLLED_MARKER exists) but the
 *     file is missing or names another mode: refused, so a production
 *     host cannot be downgraded by deleting or editing one file;
 *   - modes dev, test and embedded: allowed (dev and embedded announce
 *     themselves once per process, since they may run without a plugin);
 *   - mode prod: allowed only if a security plugin reported, for this
 *     ORB, that its self-check passed (report_plugin()), and no library
 *     recorded a prod_violation().
 *
 * The check lives in libTAO, not in the plugin, so removing the plugin
 * cannot remove the check.  A refusal is written to stderr and syslog and
 * raised as CORBA::INITIALIZE before the ORB opens any listening port.
 */
//=============================================================================

#ifndef TAO_SECURITY_MODE_H
#define TAO_SECURITY_MODE_H

#include /**/ "ace/pre.h"

#include "tao/TAO_Export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "tao/Versioned_Namespace.h"

#include <map>
#include <string>

#if !defined (TAO_SECURITY_CONF_DEFAULT)
# define TAO_SECURITY_CONF_DEFAULT "/etc/ace-tao/security.conf"
#endif /* !TAO_SECURITY_CONF_DEFAULT */

#if !defined (TAO_SECURITY_ENROLLED_MARKER)
# define TAO_SECURITY_ENROLLED_MARKER "/var/lib/ace-tao/enrolled-prod"
#endif /* !TAO_SECURITY_ENROLLED_MARKER */

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

class TAO_ORB_Core;

class TAO_Export TAO_Security_Mode
{
public:
  enum Mode
  {
    /// No configuration: stock TAO behaviour.
    MODE_NONE,
    MODE_TEST,
    MODE_PROD,
    /// The configuration cannot be used; ORB_init refuses to run.
    MODE_INVALID,
    MODE_DEV,
    MODE_EMBEDDED
  };

  struct Host_Config
  {
    Mode mode {MODE_NONE};
    /// The configuration file that was looked for.
    std::string path;
    bool found {false};
    /// The prod enrollment marker exists.
    bool enrolled {false};
    /// Why the mode is MODE_INVALID.
    std::string error;
    /// Every "key = value" line of the file.
    std::map<std::string, std::string> values;

    /// Value of @a key, or @a fallback.
    std::string get (char const *key, char const *fallback = "") const;
  };

  /// Reads and evaluates a configuration.  A null @a conf_path means
  /// ACE_TAO_SECURITY_CONF or TAO_SECURITY_CONF_DEFAULT; a null
  /// @a marker_path means TAO_SECURITY_ENROLLED_MARKER (deliberately not
  /// settable from the environment).
  static Host_Config read (char const *conf_path = nullptr,
                           char const *marker_path = nullptr);

  /// This host's configuration, read once per process.
  static Host_Config const &host ();

  static char const *name (Mode mode);

  /// Called by a security plugin during ORB initialization (normally
  /// from its ORBInitializer::post_init()) with the result of its
  /// self-check.  @a detail says what failed.
  static void report_plugin (TAO_ORB_Core *orb_core,
                             char const *plugin,
                             bool passed,
                             char const *detail);

  /**
   * Records that this process is configured in a way prod forbids (for
   * example, the Notification Service's event persistence).  In prod,
   * every later ORB_init refuses to run, naming @a reason.  Service
   * objects call this from init(), whose failures ORB_init otherwise
   * tolerates.
   */
  static void prod_violation (char const *reason);

  /// @internal Called by CORBA::ORB_init() before the ORB initializers
  /// run, and at its end.  enforce() throws CORBA::INITIALIZE when the
  /// ORB must not run.
  static void begin (TAO_ORB_Core *orb_core);
  static void enforce (TAO_ORB_Core *orb_core);

  /// Writes a security message to stderr and to syslog (authpriv).
  static void announce (int priority, char const *message);

  /// This program's name (never null or empty), for messages and the
  /// audit svc field.
  static char const *program_name ();
};

TAO_END_VERSIONED_NAMESPACE_DECL

#include /**/ "ace/post.h"

#endif /* TAO_SECURITY_MODE_H */
