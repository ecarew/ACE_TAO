#include "orbsvcs/Notify/Method_Request.h"

#include "orbsvcs/Time_Utilities.h"
#include "ace/OS_NS_sys_time.h"

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

TAO_Notify_Method_Request::~TAO_Notify_Method_Request ()
{
}

TAO_Notify_Method_Request_Queueable *
TAO_Notify_Method_Request_Queueable::copy ()
{
  return this;
}

TAO_Notify_Method_Request_Queueable::TAO_Notify_Method_Request_Queueable()
  : deadline_ (ACE_Time_Value::max_time)
{
}

TAO_Notify_Method_Request_Queueable::TAO_Notify_Method_Request_Queueable(const TAO_Notify_Event * event)
  : deadline_ (ACE_Time_Value::max_time)
{
  this->init (event);
}

void
TAO_Notify_Method_Request_Queueable::init (const TAO_Notify_Event* event)
{
  ACE_ASSERT( event != nullptr );
  // Set the parameters that affect queuing in the message queue.
  // The ACE_Message_Block priorities go from 0 (lowest) to ULONG_MAX
  // (highest), while the Notification Events go from -32767 (lowest,
  // even though CORBA::Short goes to -32768) to 32767 (highest).

  // Convert to CORBA::Long to preserve the sign.  Conversion to
  // unsigned long will happen automatically and we do not have to worry
  // about losing the number in the addition since priority () returns a
  // CORBA::Short.
  this->msg_priority ((CORBA::Long)event->priority ().value () + PRIORITY_BASE);

  this->time_ = event->creation_time ();

  // The deadline is absolute, while the timeout for the event is relative
  // to the time it was received.  The message block's own deadline is kept
  // too, for DeadlineOrder queues on platforms with timed message blocks.
  const TAO_Notify_Property_Time& timeout = event->timeout ();

  if (timeout.is_valid () && timeout != 0)
  {
    ACE_Time_Value deadline;
    ORBSVCS_Time::TimeT_to_Time_Value(deadline, timeout.value());
    deadline += this->time_;
    this->deadline (deadline);
  }
}

const ACE_Time_Value&
TAO_Notify_Method_Request_Queueable::creation_time () const
{
  return this->time_;
}

const ACE_Time_Value&
TAO_Notify_Method_Request_Queueable::deadline () const
{
  return this->deadline_;
}

void
TAO_Notify_Method_Request_Queueable::deadline (const ACE_Time_Value& deadline)
{
  this->deadline_ = deadline;
  this->msg_deadline_time (deadline);
}

TAO_END_VERSIONED_NAMESPACE_DECL
