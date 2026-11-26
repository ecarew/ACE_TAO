#include "orbsvcs/Log_Macros.h"
#include "orbsvcs/SSLIOP/SSLIOP_GSSUP_Credentials.h"
#include "orbsvcs/SSLIOP/SSLIOP_SAS.h"
#include "orbsvcs/Security/Audit_Logger.h"
#include "orbsvcs/SSLIOPC.h"

#include "tao/debug.h"

#include "ace/OS_NS_fcntl.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_stat.h"
#include "ace/OS_NS_unistd.h"

#include <openssl/crypto.h>

#if defined (ACE_HAS_TERMIOS)
# include <termios.h>
#endif

#include <cctype>
#include <cerrno>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  constexpr size_t MAX_PASSWORD = 1024;

  /// Reads up to the first newline from @a fd, one byte at a time so
  /// nothing after it is consumed.
  bool
  read_line (ACE_HANDLE fd, std::string &out, std::string &error)
  {
    out.clear ();
    char c;
    for (;;)
      {
        ssize_t const n = ACE_OS::read (fd, &c, 1);
        if (n < 0)
          {
            if (errno == EINTR)
              continue;
            error = ACE_OS::strerror (errno);
            OPENSSL_cleanse (&out[0], out.size ());
            out.clear ();
            return false;
          }
        if (n == 0 || c == '\n')
          break;
        if (out.size () >= MAX_PASSWORD)
          {
            error = "longer than " + std::to_string (MAX_PASSWORD) + " characters";
            OPENSSL_cleanse (&out[0], out.size ());
            out.clear ();
            return false;
          }
        out += c;
      }
    if (!out.empty () && out[out.size () - 1] == '\r')
      out.erase (out.size () - 1);
    return true;
  }

  bool
  printable (std::string const &s)
  {
    for (unsigned char c : s)
      if (c < 0x20 || c == 0x7F)
        return false;
    return true;
  }
}

// ------------------------------------------------------------------
// GSSUP_OwnCredentials

TAO::SSLIOP::GSSUP_OwnCredentials::GSSUP_OwnCredentials (std::string const &username,
                                                         std::string const &password,
                                                         std::string const &target)
  : username_ (username),
    password_ (password),
    target_ (target),
    state_ (SecurityLevel3::CS_Valid)
{
}

TAO::SSLIOP::GSSUP_OwnCredentials::~GSSUP_OwnCredentials ()
{
  this->wipe ();
}

void
TAO::SSLIOP::GSSUP_OwnCredentials::wipe ()
{
  if (!this->password_.empty ())
    OPENSSL_cleanse (&this->password_[0], this->password_.size ());
  this->password_.clear ();
}

std::string const &
TAO::SSLIOP::GSSUP_OwnCredentials::username () const
{
  return this->username_;
}

std::string const &
TAO::SSLIOP::GSSUP_OwnCredentials::password () const
{
  return this->password_;
}

std::string const &
TAO::SSLIOP::GSSUP_OwnCredentials::target () const
{
  return this->target_;
}

bool
TAO::SSLIOP::GSSUP_OwnCredentials::usable () const
{
  return this->state_ == SecurityLevel3::CS_Valid && !this->password_.empty ();
}

TAO::SSLIOP::GSSUP_OwnCredentials *
TAO::SSLIOP::GSSUP_OwnCredentials::of (SecurityLevel3::Credentials_ptr creds)
{
  return dynamic_cast<GSSUP_OwnCredentials *> (creds);
}

char *
TAO::SSLIOP::GSSUP_OwnCredentials::creds_id ()
{
  return CORBA::string_dup (("GSSUP:" + this->username_ + " " + this->target_).c_str ());
}

SecurityLevel3::CredentialsType
TAO::SSLIOP::GSSUP_OwnCredentials::creds_type ()
{
  return SecurityLevel3::CT_OwnCredentials;
}

SecurityLevel3::CredentialsUsage
TAO::SSLIOP::GSSUP_OwnCredentials::creds_usage ()
{
  return SecurityLevel3::CU_InitiateOnly;
}

TimeBase::UtcT
TAO::SSLIOP::GSSUP_OwnCredentials::expiry_time ()
{
  // No expiry of their own: the server decides (lockout, password change).
  TimeBase::UtcT t;
  t.time = 0;
  t.inacclo = 0;
  t.inacchi = 0;
  t.tdf = 0;
  return t;
}

SecurityLevel3::CredentialsState
TAO::SSLIOP::GSSUP_OwnCredentials::creds_state ()
{
  return this->state_;
}

char *
TAO::SSLIOP::GSSUP_OwnCredentials::add_relinquished_listener (
    SecurityLevel3::RelinquishedCredentialsListener_ptr)
{
  throw CORBA::NO_IMPLEMENT ();
}

void
TAO::SSLIOP::GSSUP_OwnCredentials::remove_relinquished_listener (const char *)
{
  throw CORBA::NO_IMPLEMENT ();
}

SecurityLevel3::CredsInitiator_ptr
TAO::SSLIOP::GSSUP_OwnCredentials::creds_initiator ()
{
  throw CORBA::NO_IMPLEMENT ();
}

SecurityLevel3::CredsAcceptor_ptr
TAO::SSLIOP::GSSUP_OwnCredentials::creds_acceptor ()
{
  throw CORBA::NO_IMPLEMENT ();
}

void
TAO::SSLIOP::GSSUP_OwnCredentials::release_credentials ()
{
  // Nothing is pending on GSSUP credentials: released at once.
  this->state_ = SecurityLevel3::CS_Invalid;
  this->wipe ();
}

// ------------------------------------------------------------------
// GSSUP_CredentialsAcquirer

TAO::SSLIOP::GSSUP_CredentialsAcquirer::GSSUP_CredentialsAcquirer (
    TAO::SL3::CredentialsCurator_ptr curator,
    CORBA::Any const &acquisition_arguments)
  : lock_ (),
    curator_ (TAO::SL3::CredentialsCurator::_duplicate (curator)),
    acquisition_arguments_ (acquisition_arguments),
    destroyed_ (false)
{
}

TAO::SSLIOP::GSSUP_CredentialsAcquirer::~GSSUP_CredentialsAcquirer () = default;

char *
TAO::SSLIOP::GSSUP_CredentialsAcquirer::acquisition_method ()
{
  return CORBA::string_dup ("SL3GSSUP");
}

SecurityLevel3::AcquisitionStatus
TAO::SSLIOP::GSSUP_CredentialsAcquirer::current_status ()
{
  if (this->destroyed_)
    throw CORBA::BAD_INV_ORDER ();
  return SecurityLevel3::AQST_Succeeded;
}

CORBA::ULong
TAO::SSLIOP::GSSUP_CredentialsAcquirer::nth_iteration ()
{
  if (this->destroyed_)
    throw CORBA::BAD_INV_ORDER ();
  return 1;
}

CORBA::Any *
TAO::SSLIOP::GSSUP_CredentialsAcquirer::get_continuation_data ()
{
  throw CORBA::BAD_INV_ORDER ();
}

SecurityLevel3::AcquisitionStatus
TAO::SSLIOP::GSSUP_CredentialsAcquirer::continue_acquisition (CORBA::Any const &)
{
  throw CORBA::BAD_INV_ORDER ();
}

std::string
TAO::SSLIOP::GSSUP_CredentialsAcquirer::default_target (std::string const &username)
{
  std::string value;
  std::string scope;
  if (!TAO::SSLIOP::SAS_Target::split_scoped (username, value, scope))
    return std::string ();
  return scope;
}

bool
TAO::SSLIOP::GSSUP_CredentialsAcquirer::read_password (std::string const &source,
                                                       std::string const &username,
                                                       std::string &password,
                                                       std::string &error)
{
  password.clear ();
  if (source == "prompt")
    {
#if defined (ACE_HAS_TERMIOS)
      ACE_HANDLE const tty = ACE_OS::open ("/dev/tty", O_RDWR);
      if (tty == ACE_INVALID_HANDLE)
        {
          error = "no terminal to prompt on";
          return false;
        }
      std::string const prompt = "GSSUP password for " + username + ": ";
      (void) ACE_OS::write (tty, prompt.data (), prompt.size ());
      struct termios old_tio;
      bool restore = false;
      if (::tcgetattr (tty, &old_tio) == 0)
        {
          struct termios tio = old_tio;
          tio.c_lflag &= ~static_cast<tcflag_t> (ECHO);
          restore = ::tcsetattr (tty, TCSANOW, &tio) == 0;
        }
      bool const ok = read_line (tty, password, error);
      if (restore)
        ::tcsetattr (tty, TCSANOW, &old_tio);
      (void) ACE_OS::write (tty, "\n", 1);
      ACE_OS::close (tty);
      if (!ok)
        return false;
#else
      ACE_UNUSED_ARG (username);
      error = "password_source \"prompt\" is not supported on this platform";
      return false;
#endif
    }
  else if (source.compare (0, 3, "fd:") == 0)
    {
      std::string const n = source.substr (3);
      if (n.empty () || n.size () > 6 || n.find_first_not_of ("0123456789") != std::string::npos)
        {
          error = "bad file descriptor in password_source \"" + source + "\"";
          return false;
        }
#if defined (ACE_WIN32)
      error = "password_source \"fd:N\" is not supported on this platform";
      return false;
#else
      ACE_HANDLE const fd = ACE_OS::atoi (n.c_str ());
      if (!read_line (fd, password, error))
        {
          error = "cannot read " + source + ": " + error;
          return false;
        }
#endif
    }
  else if (source.compare (0, 5, "file:") == 0)
    {
      std::string const path = source.substr (5);
      if (path.empty ())
        {
          error = "no path in password_source \"file:\"";
          return false;
        }
      int flags = O_RDONLY;
#if defined (O_NOFOLLOW)
      flags |= O_NOFOLLOW;
#endif
      ACE_HANDLE const fd = ACE_OS::open (path.c_str (), flags);
      if (fd == ACE_INVALID_HANDLE)
        {
          error = "cannot open " + path + ": " + ACE_OS::strerror (errno);
          return false;
        }
      ACE_stat st;
      if (ACE_OS::fstat (fd, &st) != 0 || !S_ISREG (st.st_mode))
        {
          ACE_OS::close (fd);
          error = path + " is not a regular file";
          return false;
        }
#if !defined (ACE_WIN32)
      if (st.st_uid != ACE_OS::geteuid ())
        {
          ACE_OS::close (fd);
          error = path + " is not owned by this process's user";
          return false;
        }
      if ((st.st_mode & 077) != 0)
        {
          ACE_OS::close (fd);
          error = path + " is readable or writable by others (chmod 600)";
          return false;
        }
#endif
      bool const ok = read_line (fd, password, error);
      ACE_OS::close (fd);
      if (!ok)
        {
          error = "cannot read " + path + ": " + error;
          return false;
        }
    }
  else
    {
      error = "unknown password_source \"" + source + "\" (prompt, fd:N or file:PATH)";
      return false;
    }

  if (password.empty ())
    {
      error = "empty password from " + source;
      return false;
    }
  return true;
}

SecurityLevel3::OwnCredentials_ptr
TAO::SSLIOP::GSSUP_CredentialsAcquirer::get_credentials (CORBA::Boolean on_list)
{
  if (this->destroyed_)
    throw CORBA::BAD_INV_ORDER ();

  ::SSLIOP::GSSUPAuthData const *data {};
  if (!(this->acquisition_arguments_ >>= data))
    throw CORBA::BAD_PARAM ();

  std::string const username = data->username.in ();
  std::string target = data->target_name.in ();
  if (target.empty ())
    target = default_target (username);

  std::string error;
  std::string user_value;
  std::string user_scope;
  if (username.empty () || !printable (username)
      || !TAO::SSLIOP::SAS_Target::split_scoped (username, user_value, user_scope) || user_value.empty ())
    error = "bad username (a scoped-username: user or user@realm, with @ and \\ quoted by \\)";
  else if (target.empty ())
    error = "no target name: give one, or a username of the form user@realm";
  else if (!printable (target))
    error = "bad target name";

  std::string password;
  if (error.empty ())
    (void) read_password (data->password_source.in (), username, password, error);

  TAO::Security::Audit_Record rec ("gssup_client", error.empty (),
                                   error.empty () ? TAO::Security::Audit_Reason::GSSUP_CREDENTIALS_ACQUIRED
                                                  : TAO::Security::Audit_Reason::SAS_CLIENT_NO_CREDENTIALS);
  rec.field ("user", username).field ("target", target).field ("password_source", data->password_source.in ());
  if (!error.empty ())
    {
      rec.text (error.c_str ());
      TAO::Security::Audit_Logger::instance ()->write (rec);
      if (TAO_debug_level > 0)
        ORBSVCS_ERROR ((LM_ERROR, ACE_TEXT ("(%P|%t) SL3GSSUP: %C\n"), error.c_str ()));
      this->destroy ();
      throw CORBA::BAD_PARAM ();
    }
  TAO::Security::Audit_Logger::instance ()->write (rec);

  GSSUP_OwnCredentials *creds = nullptr;
  ACE_NEW_THROW_EX (creds, GSSUP_OwnCredentials (username, password, target), CORBA::NO_MEMORY ());
  OPENSSL_cleanse (&password[0], password.size ());
  SecurityLevel3::OwnCredentials_var credentials = creds;

  if (on_list)
    this->curator_->_tao_add_own_credentials (creds);

  this->destroy ();
  return credentials._retn ();
}

void
TAO::SSLIOP::GSSUP_CredentialsAcquirer::destroy ()
{
  ACE_GUARD (TAO_SYNCH_MUTEX, guard, this->lock_);
  if (!this->destroyed_)
    {
      this->destroyed_ = true;
      (void) this->curator_.out ();
    }
}

// ------------------------------------------------------------------

SecurityLevel3::CredentialsAcquirer_ptr
TAO::SSLIOP::GSSUP_CredentialsAcquirerFactory::make (
  TAO::SL3::CredentialsCurator_ptr curator,
  CORBA::Any const & acquisition_arguments)
{
  SecurityLevel3::CredentialsAcquirer_ptr ca;
  ACE_NEW_THROW_EX (ca,
                    TAO::SSLIOP::GSSUP_CredentialsAcquirer (curator, acquisition_arguments),
                    CORBA::NO_MEMORY ());
  return ca;
}

TAO_END_VERSIONED_NAMESPACE_DECL
