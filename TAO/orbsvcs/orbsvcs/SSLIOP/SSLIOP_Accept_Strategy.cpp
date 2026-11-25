#include "orbsvcs/SSLIOP/SSLIOP_Accept_Strategy.h"
#include "orbsvcs/SSLIOP/SSLIOP_Deny_List.h"
#include "orbsvcs/Security/Audit_Logger.h"
#include "orbsvcs/Security/Self_Check.h"
#include "orbsvcs/Log_Macros.h"
#include "tao/Security_Mode.h"
#include "tao/debug.h"

#include "ace/INET_Addr.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  using TAO::Security::Audit_Logger;
  using TAO::Security::Audit_Record;
  namespace Reason = TAO::Security::Audit_Reason;

  /// Connection decisions are audited where the host has a security
  /// mode that runs checks (test and prod).
  bool
  auditing ()
  {
    TAO_Security_Mode::Mode const m = TAO_Security_Mode::host ().mode;
    return m == TAO_Security_Mode::MODE_TEST || m == TAO_Security_Mode::MODE_PROD;
  }

  std::string
  address (ACE_INET_Addr const &a)
  {
    ACE_TCHAR buf[INET6_ADDRSTRLEN + 8] = ACE_TEXT ("");
    if (a.addr_to_string (buf, sizeof buf / sizeof buf[0], 1) != 0)
      return "?";
    return ACE_TEXT_ALWAYS_CHAR (buf);
  }

  std::string
  host_of (ACE_INET_Addr const &a)
  {
    char buf[INET6_ADDRSTRLEN] = "";
    return a.get_host_addr (buf, sizeof buf) != nullptr ? buf : "?";
  }

  /// Drops a connection accepted at the TLS level but refused by policy.
  /// The handler was never activated, so (as for a failed accept) close
  /// its stream and release the transport; close() would leave the
  /// socket open and the peer waiting.
  void
  refuse (TAO::SSLIOP::Connection_Handler *svc_handler)
  {
    svc_handler->peer ().close ();
    svc_handler->transport ()->remove_reference ();
  }

  char const *
  failure_reason (ACE_SSL_Handshake_Failure const &f)
  {
    switch (f.kind)
      {
      case ACE_SSL_Handshake_Failure::VERIFY:
        return f.verify_result == X509_V_ERR_CERT_HAS_EXPIRED ? Reason::CERT_EXPIRED : Reason::CERT_UNTRUSTED;
      case ACE_SSL_Handshake_Failure::NO_PEER_CERT:
        return Reason::NO_CLIENT_CERT;
      default:
        return Reason::TLS_HANDSHAKE_FAILED;
      }
  }
}

TAO::SSLIOP::Accept_Strategy::Accept_Strategy (TAO_ORB_Core * orb_core,
                                               const ACE_Time_Value & timeout,
                                               bool check_host)
  : TAO_Accept_Strategy<TAO::SSLIOP::Connection_Handler,
                        ACE_SSL_SOCK_Acceptor> (orb_core),
  timeout_ (timeout),
  check_host_ (check_host)
{
}

int
TAO::SSLIOP::Accept_Strategy::accept_svc_handler (handler_type * svc_handler)
{
  ACE_TRACE ("TAO::SSLIOP::Accept_Strategy::accept_svc_handler");

  // The following code is basically the same code found in
  // ACE_Accept_Strategy::accept_svc_handler().  The only difference
  // is that a timeout value is passed to the peer acceptor's accept()
  // method.  A timeout is necessary to prevent malicious or
  // misbehaved clients from only completing the TCP handshake and not
  // the SSL handshake.  Without the timeout, a denial-of-service
  // vulnerability would exist where multiple incomplete SSL passive
  // connections (i.e. where only the TCP handshake is completed)
  // could result in the server process running out of file
  // descriptors.  That would be due to the SSL handshaking process
  // blocking/waiting for the handshake to complete.

  // The timeout value will be modified.  Make a copy.
  ACE_Time_Value timeout (this->timeout_);

  // Try to find out if the implementation of the reactor that we are
  // using requires us to reset the event association for the newly
  // created handle. This is because the newly created handle will
  // inherit the properties of the listen handle, including its event
  // associations.
  int const reset_new_handle = this->reactor_->uses_event_associations ();

  ACE_INET_Addr peer_addr;
  ACE_SSL_Handshake_Failure failure;
  if (this->peer_acceptor_.accept (svc_handler->peer (), // stream
                                   &peer_addr,       // remote address
                                   &timeout,         // timeout
                                   1,                // restart
                                   reset_new_handle, // reset new handler
                                   failure) == -1)
    {
      // Ensure that errno is preserved in case the svc_handler
      // close() method resets it.
      ACE_Errno_Guard error (errno);

      // Every failed handshake is a security event: who, and why.
      if (failure.kind != ACE_SSL_Handshake_Failure::NONE && auditing ())
        {
          Audit_Record r ("authn", false, failure_reason (failure));
          r.field ("src", host_of (peer_addr)).field ("peer", address (peer_addr));
          if (failure.peer_subject.length () > 0)
            r.field ("subject", failure.peer_subject.c_str ());
          if (failure.peer_serial.length () > 0)
            r.field ("cert_serial", failure.peer_serial.c_str ());
          r.text (failure.detail.c_str ());
          Audit_Logger::instance ()->write (r);
        }

      // It doesn't make sense to close the handler since it didn't open.
      svc_handler->transport ()->remove_reference ();

      // #REFCOUNT# is zero at this point.
      return -1;
    }

  // While the security state is degraded (prod, audit sink down) no new
  // connection is accepted; requests on existing ones get TRANSIENT.
  if (TAO::Security::Self_Check::degraded ())
    {
      Audit_Logger::instance ()->write (
        Audit_Record ("authn", false, Reason::CONNECTION_REFUSED)
          .field ("src", host_of (peer_addr)).field ("peer", address (peer_addr))
          .text ("security state degraded"));
      refuse (svc_handler);
      return -1;
    }

  // A certificate on the deny-list is refused at the handshake.
  TAO::SSLIOP::Deny_List *const deny = TAO::SSLIOP::Deny_List::instance ();
  if (deny->configured ())
    {
      X509 *const peer = ::SSL_get_peer_certificate (svc_handler->peer ().ssl ());
      std::string const hit = deny->check (peer);
      if (!hit.empty ())
        {
          char subject[256] = "";
          ::X509_NAME_oneline (::X509_get_subject_name (peer), subject, sizeof subject);
          Audit_Logger::instance ()->write (
            Audit_Record ("authn", false, Reason::CERT_DENYLISTED)
              .field ("src", host_of (peer_addr)).field ("peer", address (peer_addr))
              .field ("subject", subject)
              .field ("cert_serial", TAO::SSLIOP::Deny_List::serial_of (peer))
              .field ("denylist_entry", hit)
              .field ("denylist_version", std::to_string (deny->version ())));
          ::X509_free (peer);
          refuse (svc_handler);
          return -1;
        }
      ::X509_free (peer);
    }

  // If required, verify the host in the endpoint match the cert
  if (this->check_host_ && !svc_handler->check_host ())
    {
      // Close the handler.
      svc_handler->close ();

      if (TAO_debug_level > 0)
        {
          ORBSVCS_ERROR ((LM_ERROR,
                          "TAO (%P|%t) - SLIIOP_Accept_Strategy::accept, "
                          "hostname verification failed\n"));
        }

      return -1;
    }

  return 0;
}

TAO_END_VERSIONED_NAMESPACE_DECL
