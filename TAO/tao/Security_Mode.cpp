#include "tao/Security_Mode.h"
#include "tao/ORB_Core.h"
#include "tao/ORB_Constants.h"
#include "tao/SystemException.h"
#include "tao/debug.h"

#include "ace/Guard_T.h"
#include "ace/OS_NS_errno.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_stat.h"
#include "ace/OS_NS_unistd.h"
#include "ace/Thread_Mutex.h"

#if !defined (ACE_LACKS_UNIX_SYSLOG)
# include <syslog.h>
#endif /* !ACE_LACKS_UNIX_SYSLOG */

#if defined (ACE_LINUX)
# include <errno.h>   // program_invocation_short_name
#endif

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  struct Plugin_Report
  {
    std::string plugin;
    bool passed {false};
    std::string detail;
  };

  ACE_Thread_Mutex &
  reports_lock ()
  {
    static ACE_Thread_Mutex lock;
    return lock;
  }

  std::map<TAO_ORB_Core *, Plugin_Report> &
  reports ()
  {
    static std::map<TAO_ORB_Core *, Plugin_Report> r;
    return r;
  }

  std::string &
  violations ()
  {
    static std::string v;
    return v;
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

  void
  refuse (TAO_Security_Mode::Host_Config const &host, std::string const &reason)
  {
    std::string const msg = std::string ("SECURITY: MODE=")
      + (host.mode == TAO_Security_Mode::MODE_INVALID ? "INVALID" : TAO_Security_Mode::name (host.mode))
      + " (" + host.path + "): " + reason + "; refusing to run";
    TAO_Security_Mode::announce (2 /* LOG_CRIT */, msg.c_str ());
    throw ::CORBA::INITIALIZE (
      CORBA::SystemException::_tao_minor_code (TAO_ORB_CORE_INIT_LOCATION_CODE, EACCES),
      CORBA::COMPLETED_NO);
  }
}

std::string
TAO_Security_Mode::Host_Config::get (char const *key, char const *fallback) const
{
  auto const i = this->values.find (key);
  return i == this->values.end () ? std::string (fallback) : i->second;
}

TAO_Security_Mode::Host_Config
TAO_Security_Mode::read (char const *conf_path, char const *marker_path)
{
  Host_Config cfg;

  if (conf_path == nullptr)
    {
      conf_path = ACE_OS::getenv ("ACE_TAO_SECURITY_CONF");
      if (conf_path == nullptr || *conf_path == '\0')
        conf_path = TAO_SECURITY_CONF_DEFAULT;
    }
  if (marker_path == nullptr)
    marker_path = TAO_SECURITY_ENROLLED_MARKER;

  cfg.path = conf_path;
  cfg.enrolled = ACE_OS::access (marker_path, F_OK) == 0;

  FILE *const fp = ACE_OS::fopen (conf_path, ACE_TEXT ("r"));
  if (fp == nullptr)
    {
      if (errno == ENOENT)
        {
          if (cfg.enrolled)
            {
              cfg.mode = MODE_INVALID;
              cfg.error = std::string ("host is enrolled in prod (") + marker_path
                + ") but the security configuration is missing";
            }
          return cfg;
        }
      cfg.found = true;
      cfg.mode = MODE_INVALID;
      cfg.error = std::string ("cannot read the security configuration: ") + ACE_OS::strerror (errno);
      return cfg;
    }
  cfg.found = true;

  ACE_stat st;
  if (ACE_OS::fstat (ACE_OS::fileno (fp), &st) == 0
#if defined (S_IWGRP) && defined (S_IWOTH)
      && (st.st_mode & (S_IWGRP | S_IWOTH)) != 0
#else
      && false
#endif
      )
    {
      ACE_OS::fclose (fp);
      cfg.mode = MODE_INVALID;
      cfg.error = "the security configuration is writable by group or others";
      return cfg;
    }

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
      if (!key.empty ())
        cfg.values[key] = trim (l.substr (eq + 1));
    }
  ACE_OS::fclose (fp);

  std::string const mode = cfg.get ("mode");
  if (mode == "prod")
    cfg.mode = MODE_PROD;
  else if (mode == "test")
    cfg.mode = MODE_TEST;
  else if (mode == "dev")
    cfg.mode = MODE_DEV;
  else if (mode == "embedded")
    cfg.mode = MODE_EMBEDDED;
  else
    {
      cfg.mode = MODE_INVALID;
      cfg.error = mode.empty ()
        ? std::string ("the security configuration has no mode "
                       "(want mode = dev, test, prod or embedded)")
        : "unknown mode \"" + mode + "\" (want dev, test, prod or embedded)";
      return cfg;
    }

  if (cfg.enrolled && cfg.mode != MODE_PROD)
    {
      cfg.error = std::string ("host is enrolled in prod (") + marker_path
        + ") but the security configuration says mode = " + mode;
      cfg.mode = MODE_INVALID;
    }
  return cfg;
}

TAO_Security_Mode::Host_Config const &
TAO_Security_Mode::host ()
{
  static Host_Config const cfg = TAO_Security_Mode::read ();
  return cfg;
}

char const *
TAO_Security_Mode::name (Mode mode)
{
  switch (mode)
    {
    case MODE_DEV: return "dev";
    case MODE_TEST: return "test";
    case MODE_PROD: return "prod";
    case MODE_EMBEDDED: return "embedded";
    case MODE_INVALID: return "invalid";
    case MODE_NONE:
    default: return "none";
    }
}

void
TAO_Security_Mode::report_plugin (TAO_ORB_Core *orb_core,
                                  char const *plugin,
                                  bool passed,
                                  char const *detail)
{
  ACE_GUARD (ACE_Thread_Mutex, guard, reports_lock ());
  Plugin_Report &r = reports ()[orb_core];
  r.plugin = plugin ? plugin : "unknown";
  r.passed = passed;
  r.detail = detail ? detail : "";
}

void
TAO_Security_Mode::prod_violation (char const *reason)
{
  ACE_GUARD (ACE_Thread_Mutex, guard, reports_lock ());
  std::string &v = violations ();
  if (!v.empty ())
    v += "; ";
  v += reason ? reason : "unspecified";
}

void
TAO_Security_Mode::begin (TAO_ORB_Core *orb_core)
{
  // A report left by an ORB core that failed to initialize at the same
  // address must not count for this one.
  ACE_GUARD (ACE_Thread_Mutex, guard, reports_lock ());
  reports ().erase (orb_core);
}

void
TAO_Security_Mode::enforce (TAO_ORB_Core *orb_core)
{
  Host_Config const &host = TAO_Security_Mode::host ();

  Plugin_Report report;
  bool reported = false;
  std::string violation;
  {
    ACE_GUARD (ACE_Thread_Mutex, guard, reports_lock ());
    violation = violations ();
    auto const i = reports ().find (orb_core);
    if (i != reports ().end ())
      {
        report = i->second;
        reported = true;
        reports ().erase (i);
      }
  }

  switch (host.mode)
    {
    case MODE_NONE:
    case MODE_TEST:
      return;
    case MODE_DEV:
    case MODE_EMBEDDED:
      {
        // These may run without the security plugin, so say so here,
        // once per process, rather than rely on the plugin's banner.
        static bool announced = false;
        ACE_GUARD (ACE_Thread_Mutex, guard, reports_lock ());
        if (!announced)
          {
            announced = true;
            std::string const msg = host.mode == MODE_DEV
              ? "ACE/TAO security: MODE=DEV (" + host.path + "): development use only, "
                "synthetic data only; security checks are not run"
              : "ACE/TAO security: MODE=EMBEDDED (" + host.path + "): declared constrained "
                "device, running without the security plugin; not permitted on a prod host";
            TAO_Security_Mode::announce (host.mode == MODE_DEV ? 5 /* LOG_NOTICE */
                                                               : 4 /* LOG_WARNING */,
                                         msg.c_str ());
          }
      }
      return;
    case MODE_INVALID:
      refuse (host, host.error);
      return;
    case MODE_PROD:
      if (!violation.empty ())
        refuse (host, violation);
      if (!reported)
        refuse (host, "no security plugin is loaded in this process "
                      "(load SSLIOP with the Security library)");
      if (!report.passed)
        refuse (host, "security plugin " + report.plugin + " failed its self-check: " + report.detail);
      if (TAO_debug_level > 0)
        TAOLIB_DEBUG ((LM_DEBUG,
                       ACE_TEXT ("TAO (%P|%t) - Security_Mode: prod, plugin %C passed\n"),
                       report.plugin.c_str ()));
      return;
    }
}

void
TAO_Security_Mode::announce (int priority, char const *message)
{
  ACE_OS::fprintf (stderr, "%s[%ld]: %s\n", TAO_Security_Mode::program_name (),
                   static_cast<long> (ACE_OS::getpid ()), message);
  ACE_OS::fflush (stderr);
#if !defined (ACE_LACKS_UNIX_SYSLOG)
  ::syslog (LOG_AUTHPRIV | priority, "%s", message);
#else
  ACE_UNUSED_ARG (priority);
#endif /* !ACE_LACKS_UNIX_SYSLOG */
}

char const *
TAO_Security_Mode::program_name ()
{
  // ACE_OS::getprogname() is an emulation that knows the name only after
  // setprogname(); ask the C library where it can tell.
#if defined (__APPLE__) || defined (__FreeBSD__) || defined (__NetBSD__) || defined (__OpenBSD__)
  char const *const prog = ::getprogname ();
#elif defined (ACE_LINUX) && defined (__GLIBC__)
  char const *const prog = program_invocation_short_name;
#else
  char const *const prog = ACE_OS::getprogname ();
#endif
  return (prog != nullptr && *prog != '\0') ? prog : "tao";
}

TAO_END_VERSIONED_NAMESPACE_DECL
