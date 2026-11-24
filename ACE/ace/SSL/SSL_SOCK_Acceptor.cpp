// -*- C++ -*-

#include "SSL_SOCK_Acceptor.h"

#include "ace/Handle_Set.h"
#include "ace/OS_Errno.h"
#include "ace/OS_NS_errno.h"
#include "ace/Log_Category.h"
#include "ace/Time_Value.h"
#include "ace/Countdown_Time.h"
#include "ace/Truncate.h"

#include <openssl/err.h>
#include <openssl/x509.h>

#if !defined (__ACE_INLINE__)
#include "SSL_SOCK_Acceptor.inl"
#endif /* __ACE_INLINE__ */

ACE_BEGIN_VERSIONED_NAMESPACE_DECL

ACE_ALLOC_HOOK_DEFINE(ACE_SSL_SOCK_Acceptor)

namespace
{
  /// Fills in @a f from the failed handshake on @a ssl, before the
  /// OpenSSL error queue is emptied.
  void
  describe_failure (SSL *ssl, ACE_SSL_Handshake_Failure &f)
  {
    long const v = ::SSL_get_verify_result (ssl);
    unsigned long const e = ::ERR_peek_last_error ();
    if (v != X509_V_OK)
      {
        f.kind = ACE_SSL_Handshake_Failure::VERIFY;
        f.verify_result = v;
        f.detail = ::X509_verify_cert_error_string (v);
      }
    else if (e != 0 && ERR_GET_LIB (e) == ERR_LIB_SSL
             && ERR_GET_REASON (e) == SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE)
      {
        f.kind = ACE_SSL_Handshake_Failure::NO_PEER_CERT;
        f.detail = "peer did not return a certificate";
      }
    else
      {
        f.kind = ACE_SSL_Handshake_Failure::TLS;
        char const *const r = e != 0 ? ::ERR_reason_error_string (e) : nullptr;
        f.detail = r != nullptr ? r : "TLS handshake failed";
      }

    X509 *const peer = ::SSL_get_peer_certificate (ssl);
    if (peer != nullptr)
      {
        char buf[256];
        ::X509_NAME_oneline (::X509_get_subject_name (peer), buf, sizeof buf);
        f.peer_subject = buf;
        BIGNUM *const bn = ::ASN1_INTEGER_to_BN (::X509_get0_serialNumber (peer), nullptr);
        char *const hex = bn != nullptr ? ::BN_bn2hex (bn) : nullptr;
        if (hex != nullptr)
          f.peer_serial = hex;
        ::OPENSSL_free (hex);
        ::BN_free (bn);
        ::X509_free (peer);
      }
  }
}

ACE_SSL_SOCK_Acceptor::~ACE_SSL_SOCK_Acceptor ()
{
  ACE_TRACE ("ACE_SSL_SOCK_Acceptor::~ACE_SSL_SOCK_Acceptor");
}

int
ACE_SSL_SOCK_Acceptor::ssl_accept (ACE_SSL_SOCK_Stream &new_stream,
                                   ACE_Time_Value *timeout,
                                   ACE_SSL_Handshake_Failure *failure) const
{
  SSL *ssl = new_stream.ssl ();

  if (SSL_is_init_finished (ssl))
    return 0;

  if (!SSL_in_accept_init (ssl))
    ::SSL_set_accept_state (ssl);

  ACE_HANDLE handle = new_stream.get_handle ();

  // We're going to call SSL_accept, optionally doing ACE::select and
  // retrying the SSL_accept, until the SSL handshake is done or
  // it fails.
  // To get the timeout affect, set the socket to nonblocking mode
  // before beginning if there is a timeout specified. If the timeout
  // is 0 (wait as long as it takes) then don't worry about the blocking
  // status; we'll block in SSL_accept if the socket is blocking, and
  // block in ACE::select if not.
  int reset_blocking_mode = 0;
  if (timeout != nullptr)
    {
      reset_blocking_mode = ACE_BIT_DISABLED (ACE::get_flags (handle),
                                              ACE_NONBLOCK);
          // Set the handle into non-blocking mode if it's not already
          // in it.
          if (reset_blocking_mode
              && ACE::set_flags (handle,
                                 ACE_NONBLOCK) == -1)
            return -1;
    }

  // Take into account the time between each select() call below.
  ACE_Countdown_Time countdown (timeout);

  int status;
  do
    {
      // These handle sets are used to set up for whatever SSL_accept
      // says it wants next. They're reset on each pass around the loop.
      ACE_Handle_Set rd_handle;
      ACE_Handle_Set wr_handle;

      status = ::SSL_accept (ssl);
      switch (::SSL_get_error (ssl, status))
        {
        case SSL_ERROR_NONE:
          status = 0;               // To tell caller about success
          break;                    // Done

        case SSL_ERROR_WANT_WRITE:
          wr_handle.set_bit (handle);
          status = 1;               // Wait for more activity
          break;

        case SSL_ERROR_WANT_READ:
          rd_handle.set_bit (handle);
          status = 1;               // Wait for more activity
          break;

        case SSL_ERROR_ZERO_RETURN:
          // The peer has notified us that it is shutting down via
          // the SSL "close_notify" message so we need to
          // shutdown, too.
          if (failure != nullptr)
            {
              failure->kind = ACE_SSL_Handshake_Failure::CLOSED;
              failure->detail = "peer closed the connection during the handshake";
            }
          status = -1;
          break;

        case SSL_ERROR_SYSCALL:
          // On some platforms (e.g. MS Windows) OpenSSL does not
          // store the last error in errno so explicitly do so.
          //
          // Explicitly check for EWOULDBLOCK since it doesn't get
          // converted to an SSL_ERROR_WANT_{READ,WRITE} on some
          // platforms. If SSL_accept failed outright, though, don't
          // bother checking more. This can happen if the socket gets
          // closed during the handshake.
          if (ACE_OS::set_errno_to_last_error () == EWOULDBLOCK &&
              status == -1)
            {
              // Although the SSL_ERROR_WANT_READ/WRITE isn't getting
              // set correctly, the read/write state should be valid.
              // Use that to decide what to do.
              status = 1;               // Wait for more activity
              if (SSL_want_write (ssl))
                wr_handle.set_bit (handle);
              else if (SSL_want_read (ssl))
                rd_handle.set_bit (handle);
              else
                status = -1;            // Doesn't want anything - bail out
            }
          else
            status = -1;
          if (status == -1 && failure != nullptr)
            {
              // A TLS failure can also surface this way (the peer sent
              // an alert and closed); otherwise the peer just went away.
              if (::ERR_peek_last_error () != 0
                  || ::SSL_get_verify_result (ssl) != X509_V_OK)
                describe_failure (ssl, *failure);
              else
                {
                  failure->kind = ACE_SSL_Handshake_Failure::CLOSED;
                  failure->detail = "peer closed the connection during the handshake";
                }
            }
          break;

        default:
          if (failure != nullptr)
            describe_failure (ssl, *failure);
          ACE_SSL_Context::report_error ();
          status = -1;
          break;
        }

      if (status == 1)
        {
          // Must have at least one handle to wait for at this point.
          ACE_ASSERT (rd_handle.num_set() == 1 || wr_handle.num_set () == 1);
          int select_width = 0;
#if !defined (ACE_WIN32)
          select_width = handle + 1;
#endif /* ACE_WIN32 */
          status = ACE::select (select_width,
                                &rd_handle,
                                &wr_handle,
                                nullptr,
                                timeout);

          (void) countdown.update ();

          // 0 is timeout, so we're done.
          // -1 is error, so we're done.
          // Could be both handles set (same handle in both masks) so
          // set to 1.
          if (status >= 1)
            status = 1;
          else                   // Timeout or failure
            {
              if (failure != nullptr)
                {
                  failure->kind = status == 0 ? ACE_SSL_Handshake_Failure::TIMEOUT
                                              : ACE_SSL_Handshake_Failure::CLOSED;
                  failure->detail = status == 0 ? "the handshake did not finish in time"
                                                : "waiting for the handshake failed";
                }
              status = -1;
            }
        }

    } while (status == 1 && !SSL_is_init_finished (ssl));

  if (reset_blocking_mode)
    {
      ACE_Errno_Guard eguard (errno);
      ACE::clr_flags (handle, ACE_NONBLOCK);
    }

  return (status == -1 ? -1 : 0);
}

// General purpose routine for accepting new connections.
// Since our underlying acceptor is of the plain old ACE_SOCK_Acceptor
// variety, get the basic socket setup done with it, then take care of
// the SSL handshake if the socket is accepted.
int
ACE_SSL_SOCK_Acceptor::accept (ACE_SSL_SOCK_Stream &new_stream,
                               ACE_Addr *remote_addr,
                               ACE_Time_Value *timeout,
                               bool restart,
                               bool reset_new_handle) const
{
  ACE_TRACE ("ACE_SSL_SOCK_Acceptor::accept");

  // Take into account the time to complete the basic TCP handshake
  // and the SSL handshake.
  ACE_Countdown_Time countdown (timeout);

  ACE_SOCK_Stream temp_stream;
  if (-1 == this->acceptor_.accept (temp_stream,
                                    remote_addr,
                                    timeout,
                                    restart,
                                    reset_new_handle))
    return -1;

  (void) countdown.update ();

  new_stream.set_handle (temp_stream.get_handle ());
  temp_stream.set_handle (ACE_INVALID_HANDLE);

  if (this->ssl_accept (new_stream, timeout) == -1)
    {
      new_stream.close ();
      new_stream.set_handle (ACE_INVALID_HANDLE);
      return -1;
    }

  return 0;
}

int
ACE_SSL_SOCK_Acceptor::accept (ACE_SSL_SOCK_Stream &new_stream,
                               ACE_Addr *remote_addr,
                               ACE_Time_Value *timeout,
                               bool restart,
                               bool reset_new_handle,
                               ACE_SSL_Handshake_Failure &failure) const
{
  ACE_TRACE ("ACE_SSL_SOCK_Acceptor::accept");

  failure = ACE_SSL_Handshake_Failure ();
  ACE_Countdown_Time countdown (timeout);

  ACE_SOCK_Stream temp_stream;
  if (-1 == this->acceptor_.accept (temp_stream,
                                    remote_addr,
                                    timeout,
                                    restart,
                                    reset_new_handle))
    return -1;

  (void) countdown.update ();

  new_stream.set_handle (temp_stream.get_handle ());
  temp_stream.set_handle (ACE_INVALID_HANDLE);

  if (this->ssl_accept (new_stream, timeout, &failure) == -1)
    {
      if (failure.kind == ACE_SSL_Handshake_Failure::NONE)
        {
          failure.kind = ACE_SSL_Handshake_Failure::TLS;
          failure.detail = "TLS handshake failed";
        }
      new_stream.close ();
      new_stream.set_handle (ACE_INVALID_HANDLE);
      return -1;
    }

  return 0;
}

int
ACE_SSL_SOCK_Acceptor::accept (ACE_SSL_SOCK_Stream &new_stream,
                               ACE_Accept_QoS_Params qos_params,
                               ACE_Addr *remote_addr,
                               ACE_Time_Value *timeout,
                               bool restart,
                               bool reset_new_handle) const
{
  ACE_TRACE ("ACE_SSL_SOCK_Acceptor::accept");

  // Take into account the time to complete the basic TCP handshake
  // and the SSL handshake.
  ACE_Countdown_Time countdown (timeout);

  ACE_SOCK_Stream temp_stream;
  if (-1 == this->acceptor_.accept (temp_stream,
                                    qos_params,
                                    remote_addr,
                                    timeout,
                                    restart,
                                    reset_new_handle))
    return -1;

  (void) countdown.update ();

  new_stream.set_handle (temp_stream.get_handle ());
  temp_stream.set_handle (ACE_INVALID_HANDLE);

  if (this->ssl_accept (new_stream, timeout) == -1)
    {
      new_stream.close ();
      new_stream.set_handle (ACE_INVALID_HANDLE);
      return -1;
    }

  return 0;
}

ACE_END_VERSIONED_NAMESPACE_DECL
