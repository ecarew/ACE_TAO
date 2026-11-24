// -*- C++ -*-

//=============================================================================
/**
 *  @file    IIOP_SSL_Acceptor.h
 *
 *  SSL-aware IIOP specific acceptor processing
 *
 *  @author Ossama Othman <ossama@dre.vanderbilt.edu>
 */
//=============================================================================


#ifndef TAO_IIOP_SSL_ACCEPTOR_H
#define TAO_IIOP_SSL_ACCEPTOR_H

#include /**/ "ace/pre.h"

#include "orbsvcs/SSLIOP/IIOP_SSL_Connection_Handler.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "tao/IIOP_Acceptor.h"

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  /**
   * @class IIOP_SSL_Acceptor
   *
   * @brief An SSL aware IIOP acceptor.
   *
   * The class differs from the non-SSL aware TAO_IIOP_Acceptor class
   * since it uses a different a set of Acceptor strategies.  In
   * particular, it overrides the open_i() method to use the Acceptor
   * strategies tailored to use the SSL aware server connection handler.
   * See the TAO_IIOP_SSL_Connection_Handler notes for details.
   */
  class IIOP_SSL_Acceptor : public TAO_IIOP_Acceptor
  {
  public:
    using TAO_IIOP_SSL_BASE_ACCEPTOR = ACE_Strategy_Acceptor<IIOP_SSL_Connection_Handler, ACE_SOCK_ACCEPTOR>;
    using TAO_IIOP_SSL_CREATION_STRATEGY = TAO_Creation_Strategy<IIOP_SSL_Connection_Handler>;
    using TAO_IIOP_SSL_CONCURRENCY_STRATEGY = TAO_Concurrency_Strategy<IIOP_SSL_Connection_Handler>;
    using TAO_IIOP_SSL_ACCEPT_STRATEGY = TAO_Accept_Strategy<IIOP_SSL_Connection_Handler, ACE_SOCK_ACCEPTOR>;

    /// Constructor.
    IIOP_SSL_Acceptor ();

    /// Destructor.
    ~IIOP_SSL_Acceptor () override;

    int close () override;

    /**
     * When false, open() listens on no plain IIOP port: the profile
     * advertises IIOP port 0 and only the SSL port (from the SSLIOP
     * tagged component) accepts connections.  SSLIOP clients that
     * require protection never use the IIOP port.  Prod sets this.
     */
    void plain_listener (bool enable) { this->plain_listener_ = enable; }
    bool plain_listener () const { return this->plain_listener_; }

  protected:
    int open_i (const ACE_INET_Addr &addr, ACE_Reactor *reactor) override;

  private:
    bool plain_listener_ {true};

    /// The concrete acceptor, as a pointer to it's base class.
    TAO_IIOP_SSL_BASE_ACCEPTOR base_acceptor_;

    /**
     * @name Acceptor Strategies
     *
     * Server side creation, concurrency and accept strategies.
     */
    //@{
    TAO_IIOP_SSL_CREATION_STRATEGY *creation_strategy_ {};
    TAO_IIOP_SSL_CONCURRENCY_STRATEGY *concurrency_strategy_ {};
    TAO_IIOP_SSL_ACCEPT_STRATEGY *accept_strategy_ {};
    //@}
  };
} // End TAO namespace.

TAO_END_VERSIONED_NAMESPACE_DECL

#include /**/ "ace/post.h"

#endif  /* TAO_IIOP_SSL_ACCEPTOR_H */
