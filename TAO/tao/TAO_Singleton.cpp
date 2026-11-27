// -*- C++ -*-
#ifndef TAO_SINGLETON_CPP
#define TAO_SINGLETON_CPP

#include "tao/TAO_Singleton.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "tao/TAO_Singleton_Manager.h"

#include "ace/Guard_T.h"
#include "ace/Object_Manager.h"
#include "tao/debug.h"
#include "ace/os_include/os_typeinfo.h"

#if !defined (__ACE_INLINE__)
#include "tao/TAO_Singleton.inl"
#endif /* __ACE_INLINE__ */

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

template <class TYPE, class ACE_LOCK> void
TAO_Singleton<TYPE, ACE_LOCK>::dump ()
{
#if defined (ACE_HAS_DUMP)
  ACE_TRACE ("TAO_Singleton<TYPE, ACE_LOCK>::dump");

  TAOLIB_DEBUG ((LM_DEBUG,  ACE_TEXT ("instance_ = %@"),
              TAO_Singleton<TYPE, ACE_LOCK>::instance_i ().load ()));
  TAOLIB_DEBUG ((LM_DEBUG, ACE_END_DUMP));
#endif /* ACE_HAS_DUMP */
}

template <class TYPE, class ACE_LOCK> std::atomic<TAO_Singleton<TYPE, ACE_LOCK> *> &
TAO_Singleton<TYPE, ACE_LOCK>::instance_i ()
{
  return TAO_Singleton<TYPE, ACE_LOCK>::singleton_;
}

template <class TYPE, class ACE_LOCK> TYPE *
TAO_Singleton<TYPE, ACE_LOCK>::instance ()
{
  ACE_TRACE ("TAO_Singleton<TYPE, ACE_LOCK>::instance");

  std::atomic<TAO_Singleton<TYPE, ACE_LOCK> *> &singleton =
    TAO_Singleton<TYPE, ACE_LOCK>::instance_i ();

  // Perform the Double-Check pattern.  The first check is an acquire
  // load: a thread that sees the pointer also sees the constructed
  // object, which is published with a release store.
  TAO_Singleton<TYPE, ACE_LOCK> *s = singleton.load (std::memory_order_acquire);
  if (s == nullptr)
    {
      if (TAO_Singleton_Manager::starting_up () || TAO_Singleton_Manager::shutting_down ())
        {
          // The program is still starting up, and therefore assumed
          // to be single threaded.  There's no need to double-check.
          // Or, the TAO_Singleton_Manager instance has been destroyed,
          // so the preallocated lock is not available.  Either way,
          // don't register for destruction with the
          // TAO_Singleton_Manager:  we'll have to leak this instance.

          ACE_NEW_RETURN (s, (TAO_Singleton<TYPE, ACE_LOCK>), 0);
          singleton.store (s, std::memory_order_release);
        }
      else
        {
#if defined (ACE_MT_SAFE) && (ACE_MT_SAFE != 0)
          // Obtain a lock from the ACE_Object_Manager.  The pointer
          // is static, so we only obtain one per TAO_Singleton
          // instantiation.
          static ACE_LOCK *lock = nullptr;
          if (ACE_Object_Manager::get_singleton_lock (lock) != 0)
            // Failed to acquire the lock!
            return 0;

          ACE_GUARD_RETURN (ACE_LOCK, ace_mon, *lock, 0);

          s = singleton.load (std::memory_order_relaxed);
          if (s == nullptr)
            {
#endif /* ACE_MT_SAFE */
              ACE_NEW_RETURN (s, (TAO_Singleton<TYPE, ACE_LOCK>), 0);
              singleton.store (s, std::memory_order_release);

              // Register for destruction with TAO_Singleton_Manager.
#if !defined (ACE_MT_SAFE) || (ACE_MT_SAFE == 0)
              TAO_Singleton_Manager::at_exit (s, 0,
                                              typeid (TYPE).name ());
#else
              TAO_Singleton_Manager::at_exit (s, &lock,
                                              typeid (TYPE).name());
            }
#endif /* ACE_MT_SAFE */
        }
    }

  return &s->instance_;
}

template <class TYPE, class ACE_LOCK> void
TAO_Singleton<TYPE, ACE_LOCK>::cleanup (void *param)
{
  delete this;
  TAO_Singleton<TYPE, ACE_LOCK>::instance_i ().store (nullptr);

#if defined ACE_MT_SAFE && ACE_MT_SAFE != 0
  if (param)
    {
      ACE_LOCK **lock = static_cast<ACE_LOCK **> (param);
      *lock = 0;
    }
#endif
}

// Pointer to the Singleton instance.
template <class TYPE, class ACE_LOCK> std::atomic<TAO_Singleton<TYPE, ACE_LOCK> *>
TAO_Singleton<TYPE, ACE_LOCK>::singleton_ {nullptr};

template <class TYPE, class ACE_LOCK> std::atomic<TAO_TSS_Singleton<TYPE, ACE_LOCK> *>
TAO_TSS_Singleton<TYPE, ACE_LOCK>::singleton_ {nullptr};

template <class TYPE, class ACE_LOCK> void
TAO_TSS_Singleton<TYPE, ACE_LOCK>::dump ()
{
#if defined (ACE_HAS_DUMP)
  ACE_TRACE ("TAO_TSS_Singleton<TYPE, ACE_LOCK>::dump");

  TAOLIB_DEBUG ((LM_DEBUG,  ACE_TEXT ("instance_ = %@"),
              TAO_TSS_Singleton<TYPE, ACE_LOCK>::instance_i ().load ()));
  TAOLIB_DEBUG ((LM_DEBUG, ACE_END_DUMP));
#endif /* ACE_HAS_DUMP */
}

template <class TYPE, class ACE_LOCK> std::atomic<TAO_TSS_Singleton<TYPE, ACE_LOCK> *> &
TAO_TSS_Singleton<TYPE, ACE_LOCK>::instance_i ()
{
  return TAO_TSS_Singleton<TYPE, ACE_LOCK>::singleton_;
}

template <class TYPE, class ACE_LOCK> TYPE *
TAO_TSS_Singleton<TYPE, ACE_LOCK>::instance ()
{
  ACE_TRACE ("TAO_TSS_Singleton<TYPE, ACE_LOCK>::instance");

  std::atomic<TAO_TSS_Singleton<TYPE, ACE_LOCK> *> &singleton =
    TAO_TSS_Singleton<TYPE, ACE_LOCK>::instance_i ();

  // Perform the Double-Check pattern.  The first check is an acquire
  // load: a thread that sees the pointer also sees the constructed
  // object, which is published with a release store.
  TAO_TSS_Singleton<TYPE, ACE_LOCK> *s = singleton.load (std::memory_order_acquire);
  if (s == nullptr)
    {
      if (TAO_Singleton_Manager::starting_up () || TAO_Singleton_Manager::shutting_down ())
        {
          // The program is still starting up, and therefore assumed
          // to be single threaded.  There's no need to double-check.
          // Or, the TAO_Singleton_Manager instance has been destroyed,
          // so the preallocated lock is not available.  Either way,
          // don't register for destruction with the
          // TAO_Singleton_Manager:  we'll have to leak this instance.

          ACE_NEW_RETURN (s, (TAO_TSS_Singleton<TYPE, ACE_LOCK>), 0);
          singleton.store (s, std::memory_order_release);
        }
      else
        {
#if defined (ACE_MT_SAFE) && (ACE_MT_SAFE != 0)
          // Obtain a lock from the ACE_Object_Manager.  The pointer
          // is static, so we only obtain one per TAO_Singleton
          // instantiation.
          static ACE_LOCK *lock = nullptr;
          if (ACE_Object_Manager::get_singleton_lock (lock) != 0)
            // Failed to acquire the lock!
            return 0;

          ACE_GUARD_RETURN (ACE_LOCK, ace_mon, *lock, 0);

          s = singleton.load (std::memory_order_relaxed);
          if (s == nullptr)
            {
#endif /* ACE_MT_SAFE */
              ACE_NEW_RETURN (s, (TAO_TSS_Singleton<TYPE, ACE_LOCK>),
                              0);
              singleton.store (s, std::memory_order_release);

              // Register for destruction with TAO_Singleton_Manager.
              TAO_Singleton_Manager::at_exit (s, 0, typeid (TYPE).name ());
#if defined (ACE_MT_SAFE) && (ACE_MT_SAFE != 0)
            }
#endif /* ACE_MT_SAFE */
        }
    }

  return ACE_TSS_GET (&s->instance_, TYPE);
}

template <class TYPE, class ACE_LOCK> void
TAO_TSS_Singleton<TYPE, ACE_LOCK>::cleanup (void *)
{
  delete this;
  TAO_TSS_Singleton<TYPE, ACE_LOCK>::instance_i ().store (nullptr);
}

TAO_END_VERSIONED_NAMESPACE_DECL

#endif  /* TAO_SINGLETON_CPP */
