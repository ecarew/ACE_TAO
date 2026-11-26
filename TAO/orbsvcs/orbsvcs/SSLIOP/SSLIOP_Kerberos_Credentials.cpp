#include "orbsvcs/Log_Macros.h"
#include "orbsvcs/SSLIOP/SSLIOP_Kerberos_Credentials.h"
#include "orbsvcs/Security/Audit_Logger.h"
#include "orbsvcs/SSLIOPC.h"

#include "tao/debug.h"

#include "ace/OS_NS_time.h"

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
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
// Kerberos_OwnCredentials

TAO::SSLIOP::Kerberos_OwnCredentials::Kerberos_OwnCredentials (Kerberos::Client_Source const &source,
                                                               std::string const &client,
                                                               std::string const &target,
                                                               long lifetime)
  : source_ (source),
    client_ (client),
    target_ (target),
    expiry_ (lifetime > 0 ? static_cast<long> (ACE_OS::time (nullptr)) + lifetime : 0L),
    state_ (SecurityLevel3::CS_Valid)
{
}

TAO::SSLIOP::Kerberos_OwnCredentials::~Kerberos_OwnCredentials () = default;

TAO::SSLIOP::Kerberos::Client_Source const &
TAO::SSLIOP::Kerberos_OwnCredentials::source () const
{
  return this->source_;
}

std::string const &
TAO::SSLIOP::Kerberos_OwnCredentials::client () const
{
  return this->client_;
}

std::string const &
TAO::SSLIOP::Kerberos_OwnCredentials::target () const
{
  return this->target_;
}

bool
TAO::SSLIOP::Kerberos_OwnCredentials::usable () const
{
  return this->state_ == SecurityLevel3::CS_Valid;
}

bool
TAO::SSLIOP::Kerberos_OwnCredentials::allows (std::string const &service) const
{
  if (service.empty () || this->target_.empty ())
    return false;
  if (this->target_[0] == '@')
    {
      std::string const realm = Kerberos::realm_of (service);
      return !realm.empty () && realm == this->target_.substr (1);
    }
  return service == this->target_;
}

TAO::SSLIOP::Kerberos_OwnCredentials *
TAO::SSLIOP::Kerberos_OwnCredentials::of (SecurityLevel3::Credentials_ptr creds)
{
  return dynamic_cast<Kerberos_OwnCredentials *> (creds);
}

char *
TAO::SSLIOP::Kerberos_OwnCredentials::creds_id ()
{
  return CORBA::string_dup (("Kerberos:" + this->client_ + " " + this->target_).c_str ());
}

SecurityLevel3::CredentialsType
TAO::SSLIOP::Kerberos_OwnCredentials::creds_type ()
{
  return SecurityLevel3::CT_OwnCredentials;
}

SecurityLevel3::CredentialsUsage
TAO::SSLIOP::Kerberos_OwnCredentials::creds_usage ()
{
  return SecurityLevel3::CU_InitiateOnly;
}

TimeBase::UtcT
TAO::SSLIOP::Kerberos_OwnCredentials::expiry_time ()
{
  // TimeBase::TimeT counts 100 ns units since 1582-10-15.
  TimeBase::UtcT t;
  t.time = 0;
  if (this->expiry_ > 0)
    t.time = (static_cast<TimeBase::TimeT> (this->expiry_) + ACE_UINT64_LITERAL (12219292800))
             * ACE_UINT64_LITERAL (10000000);
  t.inacclo = 0;
  t.inacchi = 0;
  t.tdf = 0;
  return t;
}

SecurityLevel3::CredentialsState
TAO::SSLIOP::Kerberos_OwnCredentials::creds_state ()
{
  return this->state_;
}

char *
TAO::SSLIOP::Kerberos_OwnCredentials::add_relinquished_listener (
    SecurityLevel3::RelinquishedCredentialsListener_ptr)
{
  throw CORBA::NO_IMPLEMENT ();
}

void
TAO::SSLIOP::Kerberos_OwnCredentials::remove_relinquished_listener (const char *)
{
  throw CORBA::NO_IMPLEMENT ();
}

SecurityLevel3::CredsInitiator_ptr
TAO::SSLIOP::Kerberos_OwnCredentials::creds_initiator ()
{
  throw CORBA::NO_IMPLEMENT ();
}

SecurityLevel3::CredsAcceptor_ptr
TAO::SSLIOP::Kerberos_OwnCredentials::creds_acceptor ()
{
  throw CORBA::NO_IMPLEMENT ();
}

void
TAO::SSLIOP::Kerberos_OwnCredentials::release_credentials ()
{
  // The tickets belong to the cache, not to TAO: only stop using them.
  this->state_ = SecurityLevel3::CS_Invalid;
}

// ------------------------------------------------------------------
// Kerberos_CredentialsAcquirer

TAO::SSLIOP::Kerberos_CredentialsAcquirer::Kerberos_CredentialsAcquirer (
    TAO::SL3::CredentialsCurator_ptr curator,
    CORBA::Any const &acquisition_arguments)
  : lock_ (),
    curator_ (TAO::SL3::CredentialsCurator::_duplicate (curator)),
    acquisition_arguments_ (acquisition_arguments),
    destroyed_ (false)
{
}

TAO::SSLIOP::Kerberos_CredentialsAcquirer::~Kerberos_CredentialsAcquirer () = default;

char *
TAO::SSLIOP::Kerberos_CredentialsAcquirer::acquisition_method ()
{
  return CORBA::string_dup ("SL3Kerberos");
}

SecurityLevel3::AcquisitionStatus
TAO::SSLIOP::Kerberos_CredentialsAcquirer::current_status ()
{
  if (this->destroyed_)
    throw CORBA::BAD_INV_ORDER ();
  return SecurityLevel3::AQST_Succeeded;
}

CORBA::ULong
TAO::SSLIOP::Kerberos_CredentialsAcquirer::nth_iteration ()
{
  if (this->destroyed_)
    throw CORBA::BAD_INV_ORDER ();
  return 1;
}

CORBA::Any *
TAO::SSLIOP::Kerberos_CredentialsAcquirer::get_continuation_data ()
{
  throw CORBA::BAD_INV_ORDER ();
}

SecurityLevel3::AcquisitionStatus
TAO::SSLIOP::Kerberos_CredentialsAcquirer::continue_acquisition (CORBA::Any const &)
{
  throw CORBA::BAD_INV_ORDER ();
}

SecurityLevel3::OwnCredentials_ptr
TAO::SSLIOP::Kerberos_CredentialsAcquirer::get_credentials (CORBA::Boolean on_list)
{
  if (this->destroyed_)
    throw CORBA::BAD_INV_ORDER ();

  ::SSLIOP::KerberosAuthData const *data {};
  if (!(this->acquisition_arguments_ >>= data))
    throw CORBA::BAD_PARAM ();

  Kerberos::Client_Source source;
  source.ccache = data->ccache.in ();
  source.keytab = data->keytab.in ();
  source.principal = data->principal.in ();
  std::string target = data->target_name.in ();

  std::string error;
  std::string client;
  long lifetime = 0;
  if (!printable (source.ccache) || !printable (source.keytab) || !printable (source.principal)
      || !printable (target))
    error = "control characters in the Kerberos acquisition arguments";
  else if (!target.empty () && (target.find ('@') == std::string::npos || target == "@"))
    error = "bad target name \"" + target + "\" (a service principal, or @REALM)";
  else if (Kerberos::check_client (source, client, lifetime, error))
    {
      if (!source.principal.empty () && client != source.principal)
        error = "the ticket cache holds " + client + ", not " + source.principal;
      else if (target.empty ())
        {
          std::string const realm = Kerberos::realm_of (client);
          if (realm.empty ())
            error = "no target name, and the client principal " + client + " names no realm";
          else
            target = "@" + realm;
        }
    }

  TAO::Security::Audit_Record rec ("krb_client", error.empty (),
                                   error.empty () ? TAO::Security::Audit_Reason::KRB_CREDENTIALS_ACQUIRED
                                                  : TAO::Security::Audit_Reason::SAS_CLIENT_NO_CREDENTIALS);
  rec.field ("principal", client.empty () ? source.principal : client)
    .field ("target", target)
    .field ("source", !source.keytab.empty () ? "keytab " + source.keytab
                      : !source.ccache.empty () ? "ccache " + source.ccache
                                                : std::string ("default ccache"));
  if (error.empty () && lifetime > 0)
    rec.field ("lifetime", std::to_string (lifetime));
  if (!error.empty ())
    {
      rec.text (error.c_str ());
      TAO::Security::Audit_Logger::instance ()->write (rec);
      if (TAO_debug_level > 0)
        ORBSVCS_ERROR ((LM_ERROR, ACE_TEXT ("(%P|%t) SL3Kerberos: %C\n"), error.c_str ()));
      this->destroy ();
      throw CORBA::BAD_PARAM ();
    }
  TAO::Security::Audit_Logger::instance ()->write (rec);

  Kerberos_OwnCredentials *creds = nullptr;
  ACE_NEW_THROW_EX (creds, Kerberos_OwnCredentials (source, client, target, lifetime), CORBA::NO_MEMORY ());
  SecurityLevel3::OwnCredentials_var credentials = creds;

  if (on_list)
    this->curator_->_tao_add_own_credentials (creds);

  this->destroy ();
  return credentials._retn ();
}

void
TAO::SSLIOP::Kerberos_CredentialsAcquirer::destroy ()
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
TAO::SSLIOP::Kerberos_CredentialsAcquirerFactory::make (
  TAO::SL3::CredentialsCurator_ptr curator,
  CORBA::Any const & acquisition_arguments)
{
  SecurityLevel3::CredentialsAcquirer_ptr ca;
  ACE_NEW_THROW_EX (ca,
                    TAO::SSLIOP::Kerberos_CredentialsAcquirer (curator, acquisition_arguments),
                    CORBA::NO_MEMORY ());
  return ca;
}

TAO_END_VERSIONED_NAMESPACE_DECL
