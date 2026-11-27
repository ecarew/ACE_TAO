
//=============================================================================
/**
 *  @file    SSL_Asynch_Stream_Test.cpp
 *
 *    This program is a functionality test of ACE_SSL_Asynch_Stream.
 *    It demonstrates one proper use case of ACE_SSL_Asynch_Stream in the
 *    Proactor framework and validates its basic functionality.
 *
 *    Usage: SSL_Asynch_Stream_Test [-r <hostname:port#>]
 *              [-t <num threads>] [-d <delay>]
 *              [-i <client conn attempt#>] [-n <client request# per conn>]
 *
 *    Default value:
 *        <hostname:port#>:       ACE_DEFAULT_SERVER_HOST:ACE_DEFAULT_PORT
 *        <num threads>:          ACE_MAX_THREADS
 *        <client conn attempt#>: ACE_MAX_ITERATIONS
 *        <client req# per conn>: 20
 *        <delay>:                0 usec
 *
 *  @author   Steve Huston <shuston@riverace.com>
 */
//=============================================================================


#include "../test_config.h"
#include "ace/Default_Constants.h"
#include "ace/OS_NS_signal.h"
#include "ace/OS_NS_string.h"
#include "ace/Event_Handler.h"
#include "ace/Get_Opt.h"
#include "ace/Proactor.h"
#include "ace/Reactor.h"
#include "ace/Thread_Manager.h"
#include "ace/INET_Addr.h"
#include "ace/SOCK_Acceptor.h"
#include "ace/SOCK_Connector.h"
#include "ace/SOCK_Stream.h"
#include "ace/Thread_Mutex.h"
#include "ace/Guard_T.h"
#include "ace/OS_NS_sys_socket.h"
#include "ace/OS_NS_sys_time.h"
#include "ace/SSL/SSL_Asynch_Stream.h"
#include <atomic>

#if defined (ACE_HAS_THREADS) && (defined (ACE_WIN32) || (defined (ACE_HAS_AIO_CALLS)))
  // This only works on Win32 platforms and on Unix platforms
  // supporting POSIX aio calls.

//FUZZ: disable check_for_ACE_Guard
// The handlers pass the guard ACE_GUARD made to their helpers.
using Lock_Guard = ACE_Guard<ACE_Thread_Mutex>;
//FUZZ: enable check_for_ACE_Guard

// Handlers still alive; run_main waits for this to drop to 0.
static std::atomic<long> live_handlers (0);

// A handler may delete itself only when its stream says so (close()
// returns 0, after the stream's handle_wakeup) AND the completion of its
// own last read or write has arrived: closing the stream cancels that
// operation by posting its completion, and with several proactor threads
// the close notification can run before it.  The completion still refers
// to the handler's message block, so deleting the handler on the wakeup
// alone is a use-after-free.
class Client_Handler : public ACE_Handler
{
public:
  Client_Handler ()
    : msgs_sent_ (0),
      stream_ (ACE_SSL_Asynch_Stream::ST_CLIENT),
      block_ (1024),
      io_pending_ (false),
      closing_ (false) { ++live_handlers; }
  ~Client_Handler ();

  //FUZZ: disable check_for_lack_ACE_OS
  int open (ACE_HANDLE);
  //FUZZ: enable check_for_lack_ACE_OS

private:
  virtual void handle_write_stream (const ACE_Asynch_Write_Stream::Result &result);
  virtual void handle_read_stream (const ACE_Asynch_Read_Stream::Result &result);
  virtual void handle_wakeup ();

  /// Starts closing the stream (call with lock_ held); may delete this.
  void finish (Lock_Guard &guard);
  /// Deletes this if it is closing, the stream is closed and no write is
  /// outstanding (call with lock_ held).
  void check_done (Lock_Guard &guard);

private:
  size_t                  msgs_sent_;
  ACE_SSL_Asynch_Stream   stream_;
  ACE_Message_Block       block_;
  ACE_Thread_Mutex        lock_;
  bool                    io_pending_;
  bool                    closing_;
};

class Server_Handler : public ACE_Handler
{
public:
  Server_Handler ()
    : msgs_rcvd_ (0),
      stream_ (ACE_SSL_Asynch_Stream::ST_SERVER),
      block_ (1024),
      io_pending_ (false),
      closing_ (false) { ++live_handlers; }
  ~Server_Handler ();

  //FUZZ: disable check_for_lack_ACE_OS
  int open (ACE_HANDLE);
  //FUZZ: enable check_for_lack_ACE_OS

private:
  virtual void handle_read_stream (const ACE_Asynch_Read_Stream::Result &result);
  virtual void handle_wakeup ();

  void finish (Lock_Guard &guard);
  void check_done (Lock_Guard &guard);

private:
  size_t                  msgs_rcvd_;
  ACE_SSL_Asynch_Stream   stream_;
  ACE_Message_Block       block_;
  ACE_Thread_Mutex        lock_;
  bool                    io_pending_;
  bool                    closing_;
};

class Server_Acceptor : public ACE_Event_Handler
{
public:
  //FUZZ: disable check_for_lack_ACE_OS
  int open (const ACE_INET_Addr &listen_addr);
  //FUZZ: enable check_for_lack_ACE_OS

  // Get the I/O handle.
  virtual ACE_HANDLE get_handle () const;

  // Called when a new connection is ready to accept.
  virtual int handle_input (ACE_HANDLE fd = ACE_INVALID_HANDLE);

  virtual int handle_close (ACE_HANDLE handle,
                            ACE_Reactor_Mask close_mask);

private:
  ACE_SOCK_Acceptor acceptor_;
};

// Accepting end point.  This is actually "localhost:10010", but some
// platform couldn't resolve the name so we use the IP address
// directly here.
static const ACE_TCHAR *rendezvous = \
  ACE_DEFAULT_SERVER_HOST ACE_TEXT (":") ACE_DEFAULT_SERVER_PORT_STR;

// Total number of proactor threads.
static size_t num_threads = ACE_MAX_THREADS;

// Number of client connections to attempt.
static size_t cli_conn_no = ACE_MAX_ITERATIONS;

// Number of requests each client connection sends.
static size_t cli_req_no = ACE_MAX_THREADS;

// Delay before a thread sending the next request (in msec.)
static int req_delay = 0;

// Set when the client thread has made all its connections.
static std::atomic<bool> clients_done (false);

// This is the string sent from client to server.
static const char *test_string = "SSL_Asynch_Stream_Test!";

// Function to remove signals from the signal mask.
static int
disable_signal (int sigmin, int sigmax)
{
#if !defined (ACE_LACKS_UNIX_SIGNALS)
  sigset_t signal_set;
  if (ACE_OS::sigemptyset (&signal_set) == - 1)
    ACE_ERROR ((LM_ERROR,
                ACE_TEXT ("Error: (%P|%t):%p\n"),
                ACE_TEXT ("sigemptyset failed")));

  for (int i = sigmin; i <= sigmax; i++)
    ACE_OS::sigaddset (&signal_set, i);

  // Put the <signal_set>.
# if defined (ACE_LACKS_PTHREAD_THR_SIGSETMASK)
  // In multi-threaded application this is not POSIX compliant
  // but let's leave it just in case.
  if (ACE_OS::sigprocmask (SIG_BLOCK, &signal_set, 0) != 0)
# else
  if (ACE_OS::thr_sigsetmask (SIG_BLOCK, &signal_set, 0) != 0)
# endif /* ACE_LACKS_PTHREAD_THR_SIGSETMASK */
    ACE_ERROR_RETURN ((LM_ERROR,
                       ACE_TEXT ("Error: (%P|%t): %p\n"),
                       ACE_TEXT ("SIG_BLOCK failed")),
                      -1);
#else
  ACE_UNUSED_ARG (sigmin);
  ACE_UNUSED_ARG (sigmax);
#endif /* ACE_LACKS_UNIX_SIGNALS */

  return 0;
}

static void
parse_args (int argc, ACE_TCHAR *argv[])
{
  //FUZZ: disable check_for_lack_ACE_OS
  ACE_Get_Opt getopt (argc, argv, ACE_TEXT ("r:t:d:i:n:"));

  int c;

  while ((c = getopt ()) != -1)
    {
  //FUZZ: enable check_for_lack_ACE_OS
      switch (c)
        {
        case 'r':                   // hostname:port
          rendezvous = getopt.opt_arg ();
          break;
        case 't':
          num_threads = ACE_OS::atoi (getopt.opt_arg ());
          break;
        case 'd':
          req_delay = ACE_OS::atoi (getopt.opt_arg ());
          break;
        case 'i':
          cli_conn_no = ACE_OS::atoi (getopt.opt_arg ());
          break;
        case 'n':
          cli_req_no = ACE_OS::atoi (getopt.opt_arg ());
          break;
        default:
          ACE_ERROR ((LM_ERROR,
                      ACE_TEXT ("Usage: %s [-r <hostname:port#>]")
                      ACE_TEXT ("\t[-t <nr threads>] [-d <delay>]")
                      ACE_TEXT ("\t[-i <client conn attempt#>]")
                      ACE_TEXT ("\t[-n <client request# per conn>]\n"),
                      argv[0]));
          break;
        }
    }
}

Client_Handler::~Client_Handler ()
{
  ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("(%t) Client %@ handle %d down\n"),
              this, this->stream_.handle ()));
  if (this->stream_.handle () != ACE_INVALID_HANDLE)
    {
      if (this->msgs_sent_ != cli_req_no)
        ACE_ERROR ((LM_ERROR,
                    ACE_TEXT ("(%t) Client handle %d sent %d messages; ")
                    ACE_TEXT ("expected %d\n"),
                    this->stream_.handle (),
                    this->msgs_sent_,
                    cli_req_no));
      else
        ACE_DEBUG ((LM_DEBUG,
                    ACE_TEXT ("(%t) Client handle %d sent %d messages; ")
                    ACE_TEXT ("closing connection\n"),
                    this->stream_.handle (),
                    cli_req_no));
    }
  if (this->handle () != ACE_INVALID_HANDLE)
    ACE_OS::closesocket (this->handle ());
  --live_handlers;
}

void
Client_Handler::finish (Lock_Guard &guard)
{
  this->closing_ = true;
  this->stream_.close ();   // starts the SSL shutdown; 0 once it is done
  this->check_done (guard);
}

void
Client_Handler::check_done (Lock_Guard &guard)
{
  if (this->closing_ && !this->io_pending_ && this->stream_.close () == 0)
    {
      guard.release ();
      delete this;
    }
}

void
Client_Handler::handle_wakeup ()
{
  // The stream has shut down (on our close, or on its own after an error).
  ACE_GUARD (ACE_Thread_Mutex, guard, this->lock_);
  this->closing_ = true;
  this->check_done (guard);
}

int
Client_Handler::open (ACE_HANDLE handle)
{
  ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("(%t) Client %@ handle %d up\n"),
              this, handle));
  this->handle (handle);   // ours to close from here on
  ACE_GUARD_RETURN (ACE_Thread_Mutex, guard, this->lock_, -1);
  if (this->stream_.open (*this, handle) == -1)
    ACE_ERROR_RETURN ((LM_ERROR,
                       ACE_TEXT ("(%t) Client_Handler: %p\n"),
                       ACE_TEXT ("open")),
                      -1);
  this->block_.copy (test_string);
  if (this->stream_.write (this->block_, this->block_.length ()) == -1)
    {
      ACE_ERROR ((LM_ERROR,
                  ACE_TEXT ("(%t) Client_Handler: %p\n"),
                  ACE_TEXT ("initiate write")));
      this->finish (guard);   // the stream is open: it must close first
      return 0;
    }
  this->io_pending_ = true;
  return 0;
}

void
Client_Handler::handle_write_stream
  (const ACE_Asynch_Write_Stream::Result &result)
{
  ACE_GUARD (ACE_Thread_Mutex, guard, this->lock_);
  this->io_pending_ = false;
  if (this->closing_)
    {
      // A write the close canceled, or one that finished as it closed.
      this->check_done (guard);
      return;
    }
  if (!result.success ())
    {
      errno = result.error ();
      ACE_ERROR ((LM_ERROR,
                  ACE_TEXT ("(%t) Client handle %d: %p\n"),
                  this->stream_.handle (),
                  ACE_TEXT ("write")));
      this->finish (guard);
      return;
    }
  ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("(%t) Client %@ handle %d sent %B of %B bytes\n"),
              this, this->stream_.handle (),
              result.bytes_transferred (), result.bytes_to_write ()));
  ACE_Message_Block &b = result.message_block ();
  bool send_again = true;
  if (b.length () == 0)
    {
      // All block's data sent; rewind the read pointer and send it again
      // until we've sent the configured number of times.
      ++this->msgs_sent_;
      if (this->msgs_sent_ == cli_req_no)
        send_again = false;   // All done
      else
        b.rd_ptr (b.base ());
    }

  if (send_again)
    {
      if (this->stream_.write (this->block_, this->block_.length ()) == -1)
        {
          ACE_ERROR ((LM_ERROR,
                      ACE_TEXT ("(%t) Client_Handler: %p\n"),
                      ACE_TEXT ("initiate write")));
          this->finish (guard);
        }
      else
        this->io_pending_ = true;
    }
  else
    {
      // Wait for the server to close the session.  Reading also takes in
      // what the server sent after the handshake (TLS 1.3 session
      // tickets); closing with that unread would reset the connection
      // under the server.
      ACE_DEBUG ((LM_DEBUG,
                  ACE_TEXT ("(%t) Client handle %d done sending\n"),
                  this->stream_.handle ()));
      this->block_.reset ();
      if (this->stream_.read (this->block_, this->block_.space ()) == -1)
        {
          ACE_ERROR ((LM_ERROR,
                      ACE_TEXT ("(%t) Client_Handler: %p\n"),
                      ACE_TEXT ("initiate read")));
          this->finish (guard);
        }
      else
        this->io_pending_ = true;
    }
  return;
}

void
Client_Handler::handle_read_stream
  (const ACE_Asynch_Read_Stream::Result &result)
{
  ACE_GUARD (ACE_Thread_Mutex, guard, this->lock_);
  this->io_pending_ = false;
  if (this->closing_)
    {
      this->check_done (guard);
      return;
    }
  if (!result.success ())
    {
      errno = result.error ();
      ACE_ERROR ((LM_ERROR,
                  ACE_TEXT ("(%t) Client handle %d: %p\n"),
                  this->stream_.handle (),
                  ACE_TEXT ("read")));
    }
  else if (result.bytes_transferred () != 0)
    ACE_ERROR ((LM_ERROR,
                ACE_TEXT ("(%t) Client handle %d: %B unexpected bytes\n"),
                this->stream_.handle (),
                result.bytes_transferred ()));
  else
    ACE_DEBUG ((LM_DEBUG,
                ACE_TEXT ("(%t) Client handle %d closed by server\n"),
                this->stream_.handle ()));
  this->finish (guard);
}

Server_Handler::~Server_Handler ()
{
  ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("(%t) Server %@ handle %d down\n"),
              this, this->stream_.handle ()));
  if (this->stream_.handle () != ACE_INVALID_HANDLE)
    {
      if (this->msgs_rcvd_ != cli_req_no)
        ACE_ERROR ((LM_ERROR,
                    ACE_TEXT ("(%t) Server handle %d received %d messages; ")
                    ACE_TEXT ("expected %d\n"),
                    this->stream_.handle (),
                    this->msgs_rcvd_,
                    cli_req_no));
      else
        ACE_DEBUG ((LM_DEBUG,
                    ACE_TEXT ("(%t) Server handle %d received %d messages; ")
                    ACE_TEXT ("closing connection\n"),
                    this->stream_.handle (),
                    cli_req_no));
    }
  if (this->handle () != ACE_INVALID_HANDLE)
    ACE_OS::closesocket (this->handle ());
  --live_handlers;
}

void
Server_Handler::finish (Lock_Guard &guard)
{
  this->closing_ = true;
  this->stream_.close ();
  this->check_done (guard);
}

void
Server_Handler::check_done (Lock_Guard &guard)
{
  if (this->closing_ && !this->io_pending_ && this->stream_.close () == 0)
    {
      guard.release ();
      delete this;
    }
}

void
Server_Handler::handle_wakeup ()
{
  ACE_GUARD (ACE_Thread_Mutex, guard, this->lock_);
  this->closing_ = true;
  this->check_done (guard);
}

int
Server_Handler::open (ACE_HANDLE handle)
{
  ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("(%t) Server %@ handle %d up\n"),
              this, handle));
  this->handle (handle);   // ours to close from here on
  ACE_GUARD_RETURN (ACE_Thread_Mutex, guard, this->lock_, -1);
  if (this->stream_.open (*this, handle) == -1)
    ACE_ERROR_RETURN ((LM_ERROR,
                       ACE_TEXT ("(%t) Server_Handler: %p\n"),
                       ACE_TEXT ("open")),
                      -1);
  if (this->stream_.read (this->block_, this->block_.space () - 1) == -1)
    {
      ACE_ERROR ((LM_ERROR,
                  ACE_TEXT ("(%t) Server_Handler: %p\n"),
                  ACE_TEXT ("read")));
      this->finish (guard);
      return 0;
    }
  this->io_pending_ = true;
  return 0;
}

void
Server_Handler::handle_read_stream
  (const ACE_Asynch_Read_Stream::Result &result)
{
  ACE_GUARD (ACE_Thread_Mutex, guard, this->lock_);
  this->io_pending_ = false;
  if (this->closing_)
    {
      this->check_done (guard);
      return;
    }
  if (!result.success ())
    {
      errno = result.error ();
      ACE_ERROR ((LM_ERROR,
                  ACE_TEXT ("(%t) Server handle %d: %p\n"),
                  this->stream_.handle (),
                  ACE_TEXT ("read")));
      this->finish (guard);
      return;
    }
  ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("(%t) Server %@ handle %d recv %B of %B bytes\n"),
              this, this->stream_.handle (),
              result.bytes_transferred (), result.bytes_to_read ()));
  if (result.bytes_transferred () == 0)
    {
      ACE_DEBUG ((LM_DEBUG,
                  ACE_TEXT ("(%t) Server handle %d closed by peer\n"),
                  this->stream_.handle ()));
      this->finish (guard);
      return;
    }

  // Scan through the received data for the expected string. There may be
  // multiples and/or partials. Count up how many arrive before the connection
  // is closed.
  // Remember that the client side sends the terminating nul; in case the
  // whole thing didn't arrive, we add a nul to the end of the receive
  // block so we don't run off the end. When the recv into this buffer was
  // initiated, we left the last byte empty to facilitate this.
  ACE_Message_Block &b = result.message_block ();
  *(b.wr_ptr ()) = '\0';
  size_t test_string_len = ACE_OS::strlen (test_string);
  while (b.length () >= test_string_len)
    {
      if (0 != ACE_OS::strncmp (b.rd_ptr (), test_string, test_string_len))
        ACE_ERROR_BREAK ((LM_ERROR,
                          ACE_TEXT ("(%t) Read string: %C; expected: %C\n"),
                          b.rd_ptr (),
                          test_string));
      b.rd_ptr (test_string_len);
      // That ran up over the string; can we also consume the nul?
      if (b.length () > 0)
        b.rd_ptr (1);
      ++this->msgs_rcvd_;
    }
  if (this->msgs_rcvd_ >= cli_req_no)
    {
      // All there: the server ends the session (the client waits for it).
      this->finish (guard);
      return;
    }
  b.crunch ();
  if (this->stream_.read (b, b.space () - 1) == -1)
    {
      ACE_ERROR ((LM_ERROR,
                  ACE_TEXT ("(%t) Server_Handler: %p\n"),
                  ACE_TEXT ("read")));
      this->finish (guard);
    }
  else
    this->io_pending_ = true;
  return;
}


int
Server_Acceptor::open (const ACE_INET_Addr &listen_addr)
{
  if (this->acceptor_.open (listen_addr) == -1)
    ACE_ERROR_RETURN ((LM_ERROR,
                       ACE_TEXT ("%p\n"),
                       ACE_TEXT ("listen")),
                      -1);
  return 0;
}

ACE_HANDLE
Server_Acceptor::get_handle () const
{
  return this->acceptor_.get_handle ();
}

int
Server_Acceptor::handle_input (ACE_HANDLE)
{
  ACE_SOCK_Stream new_stream;
  if (this->acceptor_.accept (new_stream) == -1)
    ACE_ERROR_RETURN ((LM_ERROR,
                       ACE_TEXT ("(%t) %p\n"),
                       ACE_TEXT ("accept")),
                      -1);
  Server_Handler *new_handler = 0;
  ACE_NEW_RETURN (new_handler, Server_Handler, -1);
  if (new_handler->open (new_stream.get_handle ()) != 0)
    delete new_handler;   // closes the socket

  return 0;
}

int
Server_Acceptor::handle_close (ACE_HANDLE, ACE_Reactor_Mask)
{
  this->acceptor_.close ();
  return 0;
}


static ACE_THR_FUNC_RETURN
proactor_loop (void *)
{
  ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("(%t) Start handling events.\n")));

  disable_signal (ACE_SIGRTMIN, ACE_SIGRTMAX);
  disable_signal (SIGPIPE, SIGPIPE);

  int result =
    ACE_Proactor::instance ()->proactor_run_event_loop ();
  if (result == -1)
    ACE_ERROR_RETURN ((LM_ERROR,
                       ACE_TEXT ("(%t) %p\n"),
                       ACE_TEXT ("Error handling events")),
                      0);

  ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("(%t) Done handling events.\n")));

  return ACE_THR_FUNC_RETURN_NULL;
}

static ACE_THR_FUNC_RETURN
start_clients (void *)
{
  // Client thread function.
  // Plain TCP connections: ACE_SSL_Asynch_Stream does the TLS handshake
  // itself.  (A connection that had already done a blocking handshake
  // would leave the server's TLS 1.3 session tickets unread, and the
  // stream's own handshake would then read them as its reply.)
  ACE_INET_Addr addr (rendezvous);
  ACE_SOCK_Connector connect;

  disable_signal (ACE_SIGRTMIN, ACE_SIGRTMAX);
  disable_signal (SIGPIPE, SIGPIPE);

  for (size_t i = 0 ; i < cli_conn_no; i++)
    {
      ACE_SOCK_Stream stream;
      if (connect.connect (stream, addr) < 0)
        {
          ACE_ERROR ((LM_ERROR,
                      ACE_TEXT ("(%t) %p\n"),
                      ACE_TEXT ("connect")));
          continue;
        }

      Client_Handler *new_handler = 0;
      ACE_NEW_RETURN (new_handler, Client_Handler, (ACE_THR_FUNC_RETURN)-1);
      if (new_handler->open (stream.get_handle ()) != 0)
        delete new_handler;   // closes the socket
    }
  clients_done = true;

  return ACE_THR_FUNC_RETURN_NULL;
}

int
run_main (int argc, ACE_TCHAR *argv[])
{
  ACE_START_TEST (ACE_TEXT ("SSL_Asynch_Stream_Test"));

  ACE_SSL_Context *context = ACE_SSL_Context::instance ();
  // Note - the next two strings are naked on purpose... the arguments to
  // the ACE_SSL_Context methods are const char *, not ACE_TCHAR *.
  if (context->certificate ("dummy.pem", SSL_FILETYPE_PEM) != 0)
    {
      ACE_ERROR ((LM_ERROR,
                  "ERROR: Setting certificate failed\n"));
      return 1;
    }
  if (context->private_key ("key.pem", SSL_FILETYPE_PEM) != 0)
    {
      ACE_ERROR ((LM_ERROR,
                  "ERROR: Setting key failed\n"));
      return 1;
    }

  parse_args (argc, argv);
  disable_signal (ACE_SIGRTMIN, ACE_SIGRTMAX);
  disable_signal (SIGPIPE, SIGPIPE);

  Server_Acceptor acceptor;
  ACE_INET_Addr accept_addr (rendezvous);

  if (acceptor.open (accept_addr) == -1)
    return 1;
  if (-1 == ACE_Reactor::instance ()->register_handler (&acceptor,
                                                        ACE_Event_Handler::ACCEPT_MASK))
    {
      ACE_ERROR ((LM_ERROR,
                  ACE_TEXT ("(%t) %p; aborting\n"),
                  ACE_TEXT ("register_handler")));
      return 1;
    }

  ACE_DEBUG ((LM_DEBUG, ACE_TEXT ("(%t) Listening at %s\n"), rendezvous));
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT ("(%t) Spawning %d proactor threads\n"),
              num_threads));
  int const proactor_grp =
    ACE_Thread_Manager::instance ()->spawn_n (num_threads, proactor_loop);
  int const client_grp =
    ACE_Thread_Manager::instance ()->spawn (start_clients);

  // Accept connections until every client and server handler is done
  // (at most 60 seconds), then stop the proactor threads.
  ACE_Time_Value const deadline =
    ACE_OS::gettimeofday () + ACE_Time_Value (60);
  while (!(clients_done && live_handlers == 0)
         && ACE_OS::gettimeofday () < deadline)
    {
      ACE_Time_Value slice (0, 100000);
      ACE_Reactor::instance ()->handle_events (slice);
    }
  if (live_handlers != 0)
    ACE_ERROR ((LM_ERROR,
                ACE_TEXT ("(%t) %d handlers still open after 60 seconds\n"),
                static_cast<int> (live_handlers.load ())));
  // Join only the test threads: the proactor keeps internal threads of
  // its own in the same thread manager, so wait () would never return.
  ACE_Reactor::instance ()->remove_handler (&acceptor,
                                           ACE_Event_Handler::ACCEPT_MASK
                                           | ACE_Event_Handler::DONT_CALL);
  ACE_Proactor::instance ()->proactor_end_event_loop ();
  ACE_Thread_Manager::instance ()->wait_grp (client_grp);
  ACE_Thread_Manager::instance ()->wait_grp (proactor_grp);

  ACE_END_TEST;
  return 0;
}

#else
int
run_main (int, ACE_TCHAR *[])
{
  ACE_START_TEST (ACE_TEXT ("SSL_Asynch_Stream_Test"));

  ACE_ERROR ((LM_INFO,
              ACE_TEXT ("This test requires threads and AIO which are not ")
              ACE_TEXT ("supported on this platform\n")));

  ACE_END_TEST;
  return 0;
}
#endif /* ACE_HAS_THREADS && (WIN32 || AIO) */
