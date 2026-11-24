#include "orbsvcs/SSLIOP/IIOP_SSL_Acceptor.h"
#include "orbsvcs/Log_Macros.h"
#include "tao/ORB_Core.h"
#include "tao/debug.h"

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

TAO::IIOP_SSL_Acceptor::IIOP_SSL_Acceptor ()
  : TAO_IIOP_Acceptor (),
    base_acceptor_ ()
{
}

TAO::IIOP_SSL_Acceptor::~IIOP_SSL_Acceptor ()
{
  // Make sure we are closed before we start destroying the
  // strategies.
  this->close ();

  delete this->creation_strategy_;
  delete this->concurrency_strategy_;
  delete this->accept_strategy_;
}

int
TAO::IIOP_SSL_Acceptor::close ()
{
  return this->base_acceptor_.close ();
}

int
TAO::IIOP_SSL_Acceptor::open_i (const ACE_INET_Addr &addr, ACE_Reactor *reactor)
{
  if (this->plain_listener_)
    return this->TAO_IIOP_Acceptor::open_i (addr, reactor);

  // No plain listener: port 0 in every IIOP address.  The hosts and
  // addresses were set up by open(); profiles still carry them, with the
  // SSL port in the SSLIOP component.
  for (CORBA::ULong j = 0; j < this->endpoint_count_; ++j)
    this->addrs_[j].set_port_number (0, 1);
  if (TAO_debug_level > 0)
    ORBSVCS_DEBUG ((LM_DEBUG,
                   ACE_TEXT ("TAO (%P|%t) - IIOP_SSL_Acceptor::open_i, ")
                   ACE_TEXT ("no plain IIOP listener (SSL only)\n")));
  return 0;
}

TAO_END_VERSIONED_NAMESPACE_DECL
