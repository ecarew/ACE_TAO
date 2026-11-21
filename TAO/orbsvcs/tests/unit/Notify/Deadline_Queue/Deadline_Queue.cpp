// Checks that TAO_Notify_Message_Queue orders and picks requests by their
// deadlines (DeadlineOrder order and discard policies), also on platforms
// without ACE_HAS_TIMED_MESSAGE_BLOCKS.

#include "orbsvcs/Notify/Buffering_Strategy.h"
#include "orbsvcs/Notify/Method_Request.h"
#include "ace/Log_Msg.h"
#include "ace/OS_main.h"

namespace
{
  class Request : public TAO_Notify_Method_Request_Queueable
  {
  public:
    Request (char id, long deadline_secs)
      : id_ (id)
    {
      if (deadline_secs >= 0)
        this->deadline (ACE_Time_Value (deadline_secs));
    }

    int execute () override { return 0; }

    char const id_;
  };

  // Deadlines in seconds; -1 = none.  Enqueued in this order.
  struct Item { char id; long deadline; };
  Item const items[] = {
    {'A', 30}, {'B', 10}, {'C', -1}, {'D', 20}, {'E', 10}, {'F', 5}
  };
  // Earliest deadline first; B before E (equal deadlines stay FIFO);
  // C, which has no deadline, last.
  char const expected[] = "FBEDAC";
  size_t const count = sizeof items / sizeof items[0];

  int status = 0;

  void check (char const *what, ACE_Message_Block *mb, size_t n, size_t left,
              TAO_Notify_Message_Queue &queue)
  {
    Request *request = dynamic_cast<Request *> (mb);
    if (request == nullptr || request->id_ != expected[n])
      {
        ACE_ERROR ((LM_ERROR, "ERROR: %C: position %B: expected %c, got %c\n",
                    what, n, expected[n], request ? request->id_ : '?'));
        status = 1;
      }
    if (queue.message_count () != left)
      {
        ACE_ERROR ((LM_ERROR, "ERROR: %C: %B left in the queue, expected %B\n",
                    what, queue.message_count (), left));
        status = 1;
      }
    if (mb != nullptr)
      mb->release ();
  }
}

int
ACE_TMAIN (int, ACE_TCHAR *[])
{
  {
    // DeadlineOrder order policy: enqueue_deadline() sorts, the head is
    // delivered first.
    TAO_Notify_Message_Queue queue;
    for (Item const &i : items)
      queue.enqueue_deadline (new Request (i.id, i.deadline));
    for (size_t n = 0; n < count; ++n)
      {
        ACE_Message_Block *mb = nullptr;
        queue.dequeue_head (mb);
        check ("enqueue_deadline + dequeue_head", mb, n, count - n - 1, queue);
      }
  }
  {
    // DeadlineOrder discard policy on a FIFO queue: dequeue_deadline()
    // takes the earliest deadline wherever it is.
    TAO_Notify_Message_Queue queue;
    for (Item const &i : items)
      queue.enqueue_tail (new Request (i.id, i.deadline));
    for (size_t n = 0; n < count; ++n)
      {
        ACE_Message_Block *mb = nullptr;
        queue.dequeue_deadline (mb);
        check ("enqueue_tail + dequeue_deadline", mb, n, count - n - 1, queue);
      }
    if (!queue.is_empty ())
      {
        ACE_ERROR ((LM_ERROR, "ERROR: queue not empty at the end\n"));
        status = 1;
      }
  }

  if (status == 0)
    ACE_DEBUG ((LM_DEBUG, "Deadline_Queue: passed\n"));
  return status;
}
