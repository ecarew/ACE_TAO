#include "orbsvcs/Log_Macros.h"
#include "orbsvcs/Notify/Buffering_Strategy.h"

#include "orbsvcs/Notify/Method_Request.h"
#include "orbsvcs/Notify/Notify_Extensions.h"
#include "orbsvcs/Notify/QoSProperties.h"
#include "orbsvcs/Notify/Notify_Extensions.h"

#include "orbsvcs/CosNotificationC.h"
#include "orbsvcs/Time_Utilities.h"

#include "tao/debug.h"

#include "ace/Message_Queue.h"

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  const ACE_Time_Value &
  request_deadline (const ACE_Message_Block *mb)
  {
    const TAO_Notify_Method_Request_Queueable *request =
      dynamic_cast<const TAO_Notify_Method_Request_Queueable *> (mb);
    return request == nullptr ? ACE_Time_Value::max_time : request->deadline ();
  }
}

int
TAO_Notify_Message_Queue::enqueue_deadline_i (ACE_Message_Block *new_item)
{
  if (new_item == nullptr)
    return -1;

  // This method does not support chains of blocks off the next pointer.
  new_item->next (nullptr);

  const ACE_Time_Value &deadline = request_deadline (new_item);

  ACE_Message_Block *later = this->head_;
  while (later != nullptr && !(deadline < request_deadline (later)))
    later = later->next ();

  if (later == nullptr)
    return this->enqueue_tail_i (new_item);

  if (later == this->head_)
    return this->enqueue_head_i (new_item);

  new_item->prev (later->prev ());
  new_item->next (later);
  later->prev ()->next (new_item);
  later->prev (new_item);

  new_item->total_size_and_length (this->cur_bytes_, this->cur_length_);
  ++this->cur_count_;

  if (this->signal_dequeue_waiters () == -1)
    return -1;

  return ACE_Utils::truncate_cast<int> (this->cur_count_);
}

int
TAO_Notify_Message_Queue::dequeue_deadline_i (ACE_Message_Block *&dequeued)
{
  if (this->head_ == nullptr)
    return -1;

  ACE_Message_Block *chosen = this->head_;
  for (ACE_Message_Block *mb = this->head_->next (); mb != nullptr; mb = mb->next ())
    if (request_deadline (mb) < request_deadline (chosen))
      chosen = mb;

  if (chosen == this->head_)
    return this->dequeue_head_i (dequeued);

  if (chosen == this->tail_)
    return this->dequeue_tail_i (dequeued);

  chosen->prev ()->next (chosen->next ());
  chosen->next ()->prev (chosen->prev ());
  chosen->prev (nullptr);
  chosen->next (nullptr);

  size_t mb_bytes = 0;
  size_t mb_length = 0;
  chosen->total_size_and_length (mb_bytes, mb_length);
  this->cur_bytes_ -= mb_bytes;
  this->cur_length_ -= mb_length;
  --this->cur_count_;

  dequeued = chosen;

  if (this->cur_bytes_ <= this->low_water_mark_
      && this->signal_enqueue_waiters () == -1)
    return -1;

  return ACE_Utils::truncate_cast<int> (this->cur_count_);
}

TAO_Notify_Buffering_Strategy::TAO_Notify_Buffering_Strategy (
  TAO_Notify_Message_Queue& msg_queue,
  const TAO_Notify_AdminProperties::Ptr& admin_properties)
: msg_queue_ (msg_queue)
, admin_properties_ (admin_properties)
, global_queue_lock_ (admin_properties->global_queue_lock ())
, global_queue_length_ (admin_properties->global_queue_length ())
, max_queue_length_ (admin_properties->max_global_queue_length ())
, order_policy_ (CosNotification::OrderPolicy, CosNotification::AnyOrder)
, discard_policy_ (CosNotification::DiscardPolicy, CosNotification::AnyOrder)
, max_events_per_consumer_ (CosNotification::MaxEventsPerConsumer)
, blocking_policy_ (TAO_Notify_Extensions::BlockingPolicy)
, timeout_ (CosNotification::Timeout)
, expired_count_ (0)
, global_not_full_ (admin_properties->global_queue_not_full())
, local_not_full_ (global_queue_lock_)
, local_not_empty_ (global_queue_lock_)
, shutdown_ (false)
, tracker_ (0)
{
}

TAO_Notify_Buffering_Strategy::~TAO_Notify_Buffering_Strategy ()
{
}

void
TAO_Notify_Buffering_Strategy::update_qos_properties
  (const TAO_Notify_QoSProperties& qos_properties)
{
  this->order_policy_.set (qos_properties);
  this->discard_policy_.set (qos_properties);
  this->max_events_per_consumer_.set(qos_properties);
  this->blocking_policy_.set (qos_properties);
  this->timeout_.set (qos_properties);
}

size_t
TAO_Notify_Buffering_Strategy::expired_count () const
{
  return this->expired_count_;
}

void
TAO_Notify_Buffering_Strategy::shutdown ()
{
  ACE_GUARD (TAO_SYNCH_MUTEX, ace_mon, this->global_queue_lock_);

  if (this->shutdown_)
  {
    return;
  }

  this->shutdown_ = true;

  // Events still queued (e.g. for a consumer that died or disconnected) will
  // never be delivered.  Release them and give their slots back to the
  // channel-wide count; otherwise each departing consumer with a backlog
  // leaks its share, and once the leaks reach MaxQueueLength a channel with
  // RejectNewEvents refuses every event from then on.
  this->global_queue_length_ -=
    static_cast<CORBA::Long> (this->msg_queue_.message_count ());
  this->msg_queue_.flush ();

  this->local_not_empty_.broadcast ();
  this->global_not_full_.broadcast();
  this->local_not_full_.broadcast();
}

ACE_Time_Value
TAO_Notify_Buffering_Strategy::oldest_event ()
{
  ACE_Time_Value tv (ACE_Time_Value::max_time);
  ACE_Message_Block* mb = nullptr;

  ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, ace_mon, this->global_queue_lock_, tv);
  TAO_Notify_Message_Queue::ITERATOR itr (this->msg_queue_);
  while(itr.next (mb))
    {
      TAO_Notify_Method_Request_Queueable* event =
        dynamic_cast<TAO_Notify_Method_Request_Queueable*> (mb);
      if (event != nullptr)
        {
          const ACE_Time_Value& etime = event->creation_time ();
          if (etime < tv)
            tv = etime;
        }
      itr.advance ();
    }

  return tv;
}


TAO_Notify_Buffering_Strategy::Tracker::Tracker ()
  : child_ (0)
{
}


TAO_Notify_Buffering_Strategy::Tracker::~Tracker ()
{
}


void
TAO_Notify_Buffering_Strategy::Tracker::register_child (TAO_Notify_Buffering_Strategy::Tracker * child)
{
  if (this->child_ == nullptr)
    {
      this->child_ = child;
    }
  else if (this->child_ != child)
    {
      this->child_->register_child (child);
    }
  // we simply ignore duplicate registrations.
}

void
TAO_Notify_Buffering_Strategy::Tracker::unregister_child (TAO_Notify_Buffering_Strategy::Tracker * child)
{
  if (this->child_ == child)
    {
      this->child_ = this->child_->child_;
    }
  else if (this->child_ != nullptr)
    {
      this->child_->unregister_child (child);
    }
}


int
TAO_Notify_Buffering_Strategy::enqueue (TAO_Notify_Method_Request_Queueable* method_request)
{
  ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, ace_mon, this->global_queue_lock_, -1);

  if (this->shutdown_)
    return -1;

  // An event that carries no Timeout of its own expires per this queue's
  // Timeout QoS, counted from when the channel received it.
  if (method_request->deadline () == ACE_Time_Value::max_time &&
      this->timeout_.is_valid () && this->timeout_ != 0)
    {
      ACE_Time_Value timeout;
      ORBSVCS_Time::TimeT_to_Time_Value (timeout, this->timeout_.value ());
      method_request->deadline (method_request->creation_time () + timeout);
    }

  bool discarded_existing = false;

  bool local_overflow = this->max_events_per_consumer_.is_valid() &&
    static_cast <CORBA::Long> (this->msg_queue_.message_count ()) >= this->max_events_per_consumer_.value();

  bool global_overflow = this->max_queue_length_.value () != 0 &&
    this->global_queue_length_ >= this->max_queue_length_.value ();

  // Expired events give up their place before the discard policy or the
  // RejectNewEvents limit applies to live ones.  This matters most for a
  // consumer that has stopped reading: nothing is dequeued for it, so its
  // queue would otherwise stay full of events nobody wants any more.
  if ((local_overflow || global_overflow) && this->purge_expired () > 0)
    {
      local_overflow = this->max_events_per_consumer_.is_valid() &&
        static_cast <CORBA::Long> (this->msg_queue_.message_count ()) >= this->max_events_per_consumer_.value();
      global_overflow = this->max_queue_length_.value () != 0 &&
        this->global_queue_length_ >= this->max_queue_length_.value ();
    }

  while (local_overflow || global_overflow)
    {
      if (blocking_policy_.is_valid())
        {
          ACE_Time_Value timeout;
          ORBSVCS_Time::TimeT_to_Time_Value(timeout, blocking_policy_.value());
          // Condition variables take an absolute time
          timeout += ACE_OS::gettimeofday();
          if (local_overflow)
            {
              local_not_full_.wait(&timeout);
            }
          else
            {
              global_not_full_.wait(&timeout);
            }
          if (errno != ETIME)
            {
              local_overflow =
                this->max_events_per_consumer_.is_valid() &&
                static_cast <CORBA::Long> (this->msg_queue_.message_count ()) >= this->max_events_per_consumer_.value();
              global_overflow =
                this->max_queue_length_.value () != 0 &&
                this->global_queue_length_ >= this->max_queue_length_.value ();
              continue;
            }
        }
      if (tracker_ != nullptr)
        {
          tracker_->count_queue_overflow (local_overflow, global_overflow);
        }

      discarded_existing = this->discard(method_request);
      if (discarded_existing)
        {
          --this->global_queue_length_;
          local_not_full_.signal();
          global_not_full_.signal();
        }
      break;
    }

  if (! (local_overflow || global_overflow) || discarded_existing)
    {
      if (this->queue (method_request) == -1)
        {
          ORBSVCS_DEBUG((LM_DEBUG,
                     "Notify (%P|%t) - Panic! failed to enqueue event\n"));
          return -1;
        }

      ++this->global_queue_length_;

      local_not_empty_.signal ();
    }
  else
    {
      ORBSVCS_DEBUG((LM_DEBUG,
                 "Notify (%P|%t) - Panic! did not attempt to enqueue event\n"));
      return -1;
    }

  size_t count = this->msg_queue_.message_count ();
  if (this->tracker_ != nullptr)
    {
      this->tracker_->update_queue_count (count);
    }

  return ACE_Utils::truncate_cast<int> (count);
}

int
TAO_Notify_Buffering_Strategy::dequeue (TAO_Notify_Method_Request_Queueable* &method_request, const ACE_Time_Value *abstime)
{
  ACE_Message_Block *mb = nullptr;

  ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, ace_mon, this->global_queue_lock_, -1);

  if ( this->shutdown_ )
    return -1;

  for (;;)
    {
      while (this->msg_queue_.message_count () == 0)
        {
          this->local_not_empty_.wait (abstime);

          if (this->shutdown_)
            return -1;

          if (errno == ETIME)
            return 0;
        }

      if (this->msg_queue_.dequeue (mb) == -1)
        return -1;

      method_request = dynamic_cast<TAO_Notify_Method_Request_Queueable*>(mb);

      // Never deliver an event after its deadline; take the next one.
      if (method_request == nullptr ||
          !expired (method_request, ACE_OS::gettimeofday ()))
        break;

      this->drop_expired (mb);
    }

  if (this->tracker_ != nullptr)
    {
      this->tracker_->update_queue_count (this->msg_queue_.message_count ());
    }

  if (method_request == nullptr)
    return -1;

  --this->global_queue_length_;
  local_not_full_.signal();
  global_not_full_.signal();

  return 1;
}

void
TAO_Notify_Buffering_Strategy::set_tracker (
                        TAO_Notify_Buffering_Strategy::Tracker* tracker)
{
  if (this->tracker_ == nullptr)
    {
      this->tracker_ = tracker;
    }
  else if (this->tracker_ != tracker)
    {
      this->tracker_->register_child (tracker);
    }
}

int
TAO_Notify_Buffering_Strategy::queue (TAO_Notify_Method_Request_Queueable* method_request)
{
  if ( this->shutdown_ )
    return -1;

  CORBA::Short order = this->order_policy_.value();

  if (! this->order_policy_.is_valid() ||
      order == CosNotification::AnyOrder ||
      order == CosNotification::FifoOrder)
    {
      if (TAO_debug_level > 0)
        ORBSVCS_DEBUG ((LM_DEBUG, "Notify (%P|%t) - enqueue in fifo order\n"));
      return this->msg_queue_.enqueue_tail (method_request);
    }

  if (order == CosNotification::PriorityOrder)
    {
      if (TAO_debug_level > 0)
        ORBSVCS_DEBUG ((LM_DEBUG, "Notify (%P|%t) - enqueue in priority order\n"));
      return this->msg_queue_.enqueue_prio (method_request);
    }

  if (order == CosNotification::DeadlineOrder)
    {
      if (TAO_debug_level > 0)
        ORBSVCS_DEBUG ((LM_DEBUG, "Notify (%P|%t) - enqueue in deadline order\n"));
      return this->msg_queue_.enqueue_deadline (method_request);
    }

  if (TAO_debug_level > 0)
    ORBSVCS_DEBUG ((LM_DEBUG, "Notify (%P|%t) - Invalid order policy\n"));
  return this->msg_queue_.enqueue_tail (method_request);
}

bool
TAO_Notify_Buffering_Strategy::discard (TAO_Notify_Method_Request_Queueable* method_request)
{
  if (this->shutdown_)
    {
      return false;
    }

  ACE_Message_Block* mb = nullptr;
  int result = -1;

  if (this->discard_policy_.is_valid() == 0 ||
      this->discard_policy_ == CosNotification::AnyOrder ||
      this->discard_policy_ == CosNotification::FifoOrder)
    {
      result = this->msg_queue_.dequeue_head (mb);
    }
  else if (this->discard_policy_ == CosNotification::LifoOrder)
    {
      // The most current message is NOT the newest one in the queue. It's
      // the one we're about to add to the queue.
      result = -1;
    }
  else if (this->discard_policy_ == CosNotification::DeadlineOrder)
    {
      result = this->msg_queue_.dequeue_deadline (mb);
    }
  else if (this->discard_policy_ == CosNotification::PriorityOrder)
    {
      result = this->msg_queue_.dequeue_prio (mb);
      if (mb->msg_priority() >= method_request->msg_priority())
        {
          this->msg_queue_.enqueue_prio (mb);
          result = -1;
        }
    }
  else
    {
      if (TAO_debug_level > 0)
        ORBSVCS_DEBUG ((LM_DEBUG, "Notify (%P|%t) - Invalid discard policy\n"));
      result = this->msg_queue_.dequeue_head (mb);
    }

  if (result != -1)
    {
      ACE_Message_Block::release (mb);
      return true;
    }

  return false;
}

bool
TAO_Notify_Buffering_Strategy::expired (
  const TAO_Notify_Method_Request_Queueable* method_request,
  const ACE_Time_Value& now)
{
  const ACE_Time_Value& deadline = method_request->deadline ();
  return deadline != ACE_Time_Value::max_time && deadline < now;
}

void
TAO_Notify_Buffering_Strategy::drop_expired (ACE_Message_Block* mb)
{
  ACE_Message_Block::release (mb);
  ++this->expired_count_;
  --this->global_queue_length_;
  local_not_full_.signal ();
  global_not_full_.signal ();

  if (this->tracker_ != nullptr)
    {
      this->tracker_->update_queue_count (this->msg_queue_.message_count ());
    }

  if (TAO_debug_level > 0)
    ORBSVCS_DEBUG ((LM_DEBUG,
                    "Notify (%P|%t) - dropped expired event, %lu so far\n",
                    static_cast<unsigned long> (this->expired_count_)));
}

size_t
TAO_Notify_Buffering_Strategy::purge_expired ()
{
  size_t dropped = 0;
  ACE_Time_Value const now = ACE_OS::gettimeofday ();
  ACE_Message_Block* mb = nullptr;

  while (this->msg_queue_.message_count () > 0 &&
         this->msg_queue_.peek_dequeue_head (mb) != -1)
    {
      TAO_Notify_Method_Request_Queueable* method_request =
        dynamic_cast<TAO_Notify_Method_Request_Queueable*> (mb);
      if (method_request == nullptr || !expired (method_request, now) ||
          this->msg_queue_.dequeue_head (mb) == -1)
        break;

      this->drop_expired (mb);
      ++dropped;
    }

  return dropped;
}


TAO_END_VERSIONED_NAMESPACE_DECL
