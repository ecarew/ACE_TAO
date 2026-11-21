// -*- C++ -*-

/**
 *  @file Method_Request.h
 *
 *  @author Pradeep Gore <pradeep@oomworks.com>
 */

#ifndef TAO_Notify_METHOD_REQUEST_H
#define TAO_Notify_METHOD_REQUEST_H

#include /**/ "ace/pre.h"

#include "orbsvcs/Notify/notify_serv_export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "ace/Message_Block.h"
#include "ace/Bound_Ptr.h"
#include "ace/OS_NS_sys_time.h"

#include "orbsvcs/Notify/Event.h"

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

class TAO_Notify_Method_Request_Queueable;

/**
 * @class TAO_Notify_Method_Request
 *
 * @brief Base class for Method Requests
 */
class TAO_Notify_Serv_Export TAO_Notify_Method_Request
{
public:
  /// Destructor.
  virtual ~TAO_Notify_Method_Request ();

  /// Execute the Request
  virtual int execute () = 0;
  virtual TAO_Notify_Method_Request_Queueable* copy () = 0;
};

/***********************************************************************/

/**
 * @class TAO_Notify_Method_Request_Queueable
 *
 * @brief Interface for NS method Requests
 */
class TAO_Notify_Serv_Export TAO_Notify_Method_Request_Queueable
  : public ACE_Message_Block
  , public TAO_Notify_Method_Request
{
public:
  enum {PRIORITY_BASE = 32768};

  TAO_Notify_Method_Request_Queueable();
  TAO_Notify_Method_Request_Queueable(const TAO_Notify_Event * event);

  TAO_Notify_Method_Request_Queueable* copy () override;
  void init (const TAO_Notify_Event * event);

  /// The creation time of the event to which this request corresponds.
  const ACE_Time_Value& creation_time () const;

  /// Absolute time after which the event must not be delivered, or
  /// ACE_Time_Value::max_time if it does not expire.  init() sets it from
  /// the event's own Timeout; a queue applies its Timeout QoS to events
  /// that carry none.  Kept here because ACE_Message_Block only stores a
  /// deadline when ACE_HAS_TIMED_MESSAGE_BLOCKS is defined.
  const ACE_Time_Value& deadline () const;
  void deadline (const ACE_Time_Value& deadline);

private:
  ACE_Time_Value time_;
  ACE_Time_Value deadline_;
};

TAO_END_VERSIONED_NAMESPACE_DECL

#include /**/ "ace/post.h"

#endif /* TAO_Notify_METHOD_REQUEST_H */
