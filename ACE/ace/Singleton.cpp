#ifndef ACE_SINGLETON_CPP
#define ACE_SINGLETON_CPP

#include "ace/Singleton.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#if !defined (__ACE_INLINE__)
#include "ace/Singleton.inl"
#endif /* __ACE_INLINE__ */

#include "ace/Object_Manager.h"
#include "ace/Log_Category.h"
#include "ace/Framework_Component.h"
#include "ace/Guard_T.h"
#include "ace/os_include/os_typeinfo.h"
#include <memory>

ACE_BEGIN_VERSIONED_NAMESPACE_DECL

ACE_ALLOC_HOOK_DEFINE_Tcc(ACE_Singleton)
ACE_ALLOC_HOOK_DEFINE_Tcc(ACE_Unmanaged_Singleton)
ACE_ALLOC_HOOK_DEFINE_Tcc(ACE_TSS_Singleton)
ACE_ALLOC_HOOK_DEFINE_Tcc(ACE_Unmanaged_TSS_Singleton)
ACE_ALLOC_HOOK_DEFINE_Tcc(ACE_DLL_Singleton_T)
ACE_ALLOC_HOOK_DEFINE_Tc(ACE_DLL_Singleton_Adapter_T)

template <class TYPE, class ACE_LOCK> void
ACE_Singleton<TYPE, ACE_LOCK>::dump ()
{
#if defined (ACE_HAS_DUMP)
  ACE_TRACE ("ACE_Singleton<TYPE, ACE_LOCK>::dump");

  ACELIB_DEBUG ((LM_DEBUG,  ACE_TEXT ("instance_ = %x"),
              ACE_Singleton<TYPE, ACE_LOCK>::instance_i ().load ()));
  ACELIB_DEBUG ((LM_DEBUG, ACE_END_DUMP));
#endif /* ACE_HAS_DUMP */
}

template <class TYPE, class ACE_LOCK>
std::atomic<ACE_Singleton<TYPE, ACE_LOCK> *> &
ACE_Singleton<TYPE, ACE_LOCK>::instance_i ()
{
  return ACE_Singleton<TYPE, ACE_LOCK>::singleton_;
}

template <class TYPE, class ACE_LOCK> TYPE *
ACE_Singleton<TYPE, ACE_LOCK>::instance ()
{
  ACE_TRACE ("ACE_Singleton<TYPE, ACE_LOCK>::instance");

  std::atomic<ACE_Singleton<TYPE, ACE_LOCK> *> &singleton =
    ACE_Singleton<TYPE, ACE_LOCK>::instance_i ();

  // Perform the Double-Check pattern.  The first check is an acquire
  // load: a thread that sees the pointer also sees the constructed
  // object, which is published with a release store.
  ACE_Singleton<TYPE, ACE_LOCK> *s = singleton.load (std::memory_order_acquire);
  if (s == nullptr)
    {
      if (ACE_Object_Manager::starting_up () || ACE_Object_Manager::shutting_down ())
        {
          // The program is still starting up, and therefore assumed
          // to be single threaded.  There's no need to double-check.
          // Or, the ACE_Object_Manager instance has been destroyed,
          // so the preallocated lock is not available.  Either way,
          // don't register for destruction with the
          // ACE_Object_Manager:  we'll have to leak this instance.

          ACE_NEW_RETURN (s, (ACE_Singleton<TYPE, ACE_LOCK>), nullptr);
          singleton.store (s, std::memory_order_release);
        }
      else
        {
#if defined (ACE_MT_SAFE) && (ACE_MT_SAFE != 0)
          // Obtain a lock from the ACE_Object_Manager.  The pointer
          // is static, so we only obtain one per instantiation.
#if defined(ACE_FACE_SAFETY_BASE)
          static ACE_LOCK the_lock;
          static ACE_LOCK *lock = std::addressof(the_lock);
#else /* ACE_FACE_SAFETY_BASE */
          static ACE_LOCK *lock = nullptr;
#endif /* ACE_FACE_SAFETY_BASE */
          if (ACE_Object_Manager::get_singleton_lock (lock) != 0)
            // Failed to acquire the lock!
            return 0;

          ACE_GUARD_RETURN (ACE_LOCK, ace_mon, *lock, 0);
          s = singleton.load (std::memory_order_relaxed);
          if (s == nullptr)
            {
#endif /* ACE_MT_SAFE */
              ACE_NEW_RETURN (s, (ACE_Singleton<TYPE, ACE_LOCK>), 0);
              // Register for destruction with ACE_Object_Manager.
#if !defined (ACE_MT_SAFE) || (ACE_MT_SAFE == 0)
              ACE_Object_Manager::at_exit (s, 0, typeid (TYPE).name ());
#else
              ACE_Object_Manager::at_exit (s, &lock, typeid (TYPE).name ());
#endif /* ACE_MT_SAFE */
              singleton.store (s, std::memory_order_release);
#if defined (ACE_MT_SAFE) && (ACE_MT_SAFE != 0)
            }
#endif /* ACE_MT_SAFE */
        }
    }

  return &s->instance_;
}

template <class TYPE, class ACE_LOCK> void
ACE_Singleton<TYPE, ACE_LOCK>::cleanup (void *param)
{
  ACE_Object_Manager::remove_at_exit (this);
  delete this;
  ACE_Singleton<TYPE, ACE_LOCK>::instance_i ().store (nullptr);

#if !defined ACE_MT_SAFE || ACE_MT_SAFE == 0 || defined ACE_FACE_SAFETY_BASE
  ACE_UNUSED_ARG (param);
#else
  if (param)
    {
      ACE_LOCK **lock = static_cast<ACE_LOCK **> (param);
      *lock = nullptr;
    }
#endif
}

template <class TYPE, class ACE_LOCK> void
ACE_Singleton<TYPE, ACE_LOCK>::close ()
{
  ACE_Singleton<TYPE, ACE_LOCK> *const singleton =
    ACE_Singleton<TYPE, ACE_LOCK>::instance_i ().load ();

  if (singleton)
    {
      singleton->cleanup ();
      ACE_Singleton<TYPE, ACE_LOCK>::instance_i ().store (nullptr);
    }
}

// Pointer to the Singleton instance.
template <class TYPE, class ACE_LOCK>
std::atomic<ACE_Singleton<TYPE, ACE_LOCK> *>
ACE_Singleton<TYPE, ACE_LOCK>::singleton_ {nullptr};

template <class TYPE, class ACE_LOCK>
std::atomic<ACE_Unmanaged_Singleton<TYPE, ACE_LOCK> *>
ACE_Unmanaged_Singleton<TYPE, ACE_LOCK>::singleton_ {nullptr};

template <class TYPE, class ACE_LOCK> void
ACE_Unmanaged_Singleton<TYPE, ACE_LOCK>::dump ()
{
#if defined (ACE_HAS_DUMP)
  ACE_TRACE ("ACE_Unmanaged_Singleton<TYPE, ACE_LOCK>::dump");

  ACELIB_DEBUG ((LM_DEBUG,  ACE_TEXT ("instance_ = %x"),
              ACE_Unmanaged_Singleton<TYPE, ACE_LOCK>::instance_i ().load ()));
  ACELIB_DEBUG ((LM_DEBUG, ACE_END_DUMP));
#endif /* ACE_HAS_DUMP */
}

template <class TYPE, class ACE_LOCK>
std::atomic<ACE_Unmanaged_Singleton<TYPE, ACE_LOCK> *> &
ACE_Unmanaged_Singleton<TYPE, ACE_LOCK>::instance_i ()
{
  return ACE_Unmanaged_Singleton<TYPE, ACE_LOCK>::singleton_;
}

template <class TYPE, class ACE_LOCK> TYPE *
ACE_Unmanaged_Singleton<TYPE, ACE_LOCK>::instance ()
{
  ACE_TRACE ("ACE_Unmanaged_Singleton<TYPE, ACE_LOCK>::instance");

  std::atomic<ACE_Unmanaged_Singleton<TYPE, ACE_LOCK> *> &singleton =
    ACE_Unmanaged_Singleton<TYPE, ACE_LOCK>::instance_i ();

  // Perform the Double-Check pattern.  The first check is an acquire
  // load: a thread that sees the pointer also sees the constructed
  // object, which is published with a release store.
  ACE_Unmanaged_Singleton<TYPE, ACE_LOCK> *s = singleton.load (std::memory_order_acquire);
  if (s == nullptr)
    {
      if (ACE_Object_Manager::starting_up () || ACE_Object_Manager::shutting_down ())
        {
          // The program is still starting up, and therefore assumed
          // to be single threaded.  There's no need to double-check.
          // Or, the ACE_Object_Manager instance has been destroyed,
          // so the preallocated lock is not available.  Either way,
          // don't register for destruction with the
          // ACE_Object_Manager:  we'll have to leak this instance.

          ACE_NEW_RETURN (s, (ACE_Unmanaged_Singleton<TYPE, ACE_LOCK>), nullptr);
          singleton.store (s, std::memory_order_release);
        }
      else
        {
#if defined (ACE_MT_SAFE) && (ACE_MT_SAFE != 0)
          // Obtain a lock from the ACE_Object_Manager.  The pointer
          // is static, so we only obtain one per instantiation.
#if defined(ACE_FACE_SAFETY_BASE)
          static ACE_LOCK the_lock;
          static ACE_LOCK *lock = &the_lock;
#else /* ACE_FACE_SAFETY_BASE */
          static ACE_LOCK *lock = nullptr;
#endif /* ACE_FACE_SAFETY_BASE */
          if (ACE_Object_Manager::get_singleton_lock (lock) != 0)
            // Failed to acquire the lock!
            return 0;

          ACE_GUARD_RETURN (ACE_LOCK, ace_mon, *lock, 0);
          s = singleton.load (std::memory_order_relaxed);
          if (s == nullptr)
            {
#endif /* ACE_MT_SAFE */
              ACE_NEW_RETURN (s, (ACE_Unmanaged_Singleton<TYPE, ACE_LOCK>), 0);
              singleton.store (s, std::memory_order_release);
#if defined (ACE_MT_SAFE) && (ACE_MT_SAFE != 0)
            }
#endif /* ACE_MT_SAFE */
        }
    }

  return &s->instance_;
}

template <class TYPE, class ACE_LOCK> void
ACE_Unmanaged_Singleton<TYPE, ACE_LOCK>::close ()
{
  ACE_Unmanaged_Singleton<TYPE, ACE_LOCK> *const singleton =
    ACE_Unmanaged_Singleton<TYPE, ACE_LOCK>::instance_i ().load ();

  if (singleton)
    {
      singleton->cleanup ();
      ACE_Unmanaged_Singleton<TYPE, ACE_LOCK>::instance_i ().store (nullptr);
    }
}

template <class TYPE, class ACE_LOCK> void
ACE_TSS_Singleton<TYPE, ACE_LOCK>::dump ()
{
#if defined (ACE_HAS_DUMP)
  ACE_TRACE ("ACE_TSS_Singleton<TYPE, ACE_LOCK>::dump");

  ACELIB_DEBUG ((LM_DEBUG,  ACE_TEXT ("instance_ = %x"),
              ACE_TSS_Singleton<TYPE, ACE_LOCK>::instance_i ().load ()));
  ACELIB_DEBUG ((LM_DEBUG, ACE_END_DUMP));
#endif /* ACE_HAS_DUMP */
}

template <class TYPE, class ACE_LOCK>
std::atomic<ACE_TSS_Singleton<TYPE, ACE_LOCK> *> &
ACE_TSS_Singleton<TYPE, ACE_LOCK>::instance_i ()
{
  return ACE_TSS_Singleton<TYPE, ACE_LOCK>::singleton_;
}

template <class TYPE, class ACE_LOCK> TYPE *
ACE_TSS_Singleton<TYPE, ACE_LOCK>::instance ()
{
  ACE_TRACE ("ACE_TSS_Singleton<TYPE, ACE_LOCK>::instance");

  std::atomic<ACE_TSS_Singleton<TYPE, ACE_LOCK> *> &singleton =
    ACE_TSS_Singleton<TYPE, ACE_LOCK>::instance_i ();

  // Perform the Double-Check pattern.  The first check is an acquire
  // load: a thread that sees the pointer also sees the constructed
  // object, which is published with a release store.
  ACE_TSS_Singleton<TYPE, ACE_LOCK> *s = singleton.load (std::memory_order_acquire);
  if (s == nullptr)
    {
      if (ACE_Object_Manager::starting_up () || ACE_Object_Manager::shutting_down ())
        {
          // The program is still starting up, and therefore assumed
          // to be single threaded.  There's no need to double-check.
          // Or, the ACE_Object_Manager instance has been destroyed,
          // so the preallocated lock is not available.  Either way,
          // don't register for destruction with the
          // ACE_Object_Manager:  we'll have to leak this instance.

          ACE_NEW_RETURN (s, (ACE_TSS_Singleton<TYPE, ACE_LOCK>), nullptr);
          singleton.store (s, std::memory_order_release);
        }
      else
        {
#if defined (ACE_MT_SAFE) && (ACE_MT_SAFE != 0)
          // Obtain a lock from the ACE_Object_Manager.  The pointer
          // is static, so we only obtain one per instantiation.
#if defined(ACE_FACE_SAFETY_BASE)
          static ACE_LOCK the_lock;
          static ACE_LOCK *lock = &the_lock;
#else /* ACE_FACE_SAFETY_BASE */
          static ACE_LOCK *lock = nullptr;
#endif /* ACE_FACE_SAFETY_BASE */
          if (ACE_Object_Manager::get_singleton_lock (lock) != 0)
            // Failed to acquire the lock!
            return 0;

          ACE_GUARD_RETURN (ACE_LOCK, ace_mon, *lock, 0);
          s = singleton.load (std::memory_order_relaxed);
          if (s == nullptr)
            {
#endif /* ACE_MT_SAFE */
              ACE_NEW_RETURN (s, (ACE_TSS_Singleton<TYPE, ACE_LOCK>), 0);
              // Register for destruction with ACE_Object_Manager.
              ACE_Object_Manager::at_exit (s, 0, typeid (TYPE).name ());
              singleton.store (s, std::memory_order_release);
#if defined (ACE_MT_SAFE) && (ACE_MT_SAFE != 0)
            }
#endif /* ACE_MT_SAFE */
        }
    }

  return ACE_TSS_GET (&s->instance_, TYPE);
}

template <class TYPE, class ACE_LOCK> void
ACE_TSS_Singleton<TYPE, ACE_LOCK>::cleanup (void *)
{
  delete this;
  ACE_TSS_Singleton<TYPE, ACE_LOCK>::instance_i ().store (nullptr);
}

template <class TYPE, class ACE_LOCK> void
ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK>::dump ()
{
#if defined (ACE_HAS_DUMP)
  ACE_TRACE ("ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK>::dump");

  ACELIB_DEBUG ((LM_DEBUG,  ACE_TEXT ("instance_ = %x"),
              ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK>::instance_i ().load ()));
  ACELIB_DEBUG ((LM_DEBUG, ACE_END_DUMP));
#endif /* ACE_HAS_DUMP */
}

template <class TYPE, class ACE_LOCK>
std::atomic<ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK> *> &
ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK>::instance_i ()
{
  return ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK>::singleton_;
}

template <class TYPE, class ACE_LOCK> TYPE *
ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK>::instance ()
{
  ACE_TRACE ("ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK>::instance");

  std::atomic<ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK> *> &singleton =
    ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK>::instance_i ();

  // Perform the Double-Check pattern.  The first check is an acquire
  // load: a thread that sees the pointer also sees the constructed
  // object, which is published with a release store.
  ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK> *s = singleton.load (std::memory_order_acquire);
  if (s == nullptr)
    {
      if (ACE_Object_Manager::starting_up () || ACE_Object_Manager::shutting_down ())
        {
          // The program is still starting up, and therefore assumed
          // to be single threaded.  There's no need to double-check.
          // Or, the ACE_Object_Manager instance has been destroyed,
          // so the preallocated lock is not available.  Either way,
          // don't register for destruction with the
          // ACE_Object_Manager:  we'll have to leak this instance.

          ACE_NEW_RETURN (s, (ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK>), nullptr);
          singleton.store (s, std::memory_order_release);
        }
      else
        {
#if defined (ACE_MT_SAFE) && (ACE_MT_SAFE != 0)
          // Obtain a lock from the ACE_Object_Manager.  The pointer
          // is static, so we only obtain one per instantiation.
#if defined(ACE_FACE_SAFETY_BASE)
          static ACE_LOCK the_lock;
          static ACE_LOCK *lock = &the_lock;
#else /* ACE_FACE_SAFETY_BASE */
          static ACE_LOCK *lock = nullptr;
#endif /* ACE_FACE_SAFETY_BASE */
          if (ACE_Object_Manager::get_singleton_lock (lock) != 0)
            // Failed to acquire the lock!
            return 0;

          ACE_GUARD_RETURN (ACE_LOCK, ace_mon, *lock, 0);
          s = singleton.load (std::memory_order_relaxed);
          if (s == nullptr)
            {
#endif /* ACE_MT_SAFE */
              ACE_NEW_RETURN (s, (ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK>), 0);
              singleton.store (s, std::memory_order_release);
#if defined (ACE_MT_SAFE) && (ACE_MT_SAFE != 0)
            }
#endif /* ACE_MT_SAFE */
        }
    }

  return ACE_TSS_GET (&s->instance_, TYPE);
}

template <class TYPE, class ACE_LOCK> void
ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK>::close ()
{
  ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK> *const singleton =
    ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK>::instance_i ().load ();

  if (singleton)
    singleton->cleanup ();
}

// Pointer to the Singleton instance.
template <class TYPE, class ACE_LOCK>
std::atomic<ACE_TSS_Singleton<TYPE, ACE_LOCK> *>
ACE_TSS_Singleton<TYPE, ACE_LOCK>::singleton_ {nullptr};

template <class TYPE, class ACE_LOCK>
std::atomic<ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK> *>
ACE_Unmanaged_TSS_Singleton<TYPE, ACE_LOCK>::singleton_ {nullptr};

/*************************************************************************/

// Pointer to the Singleton instance.
template <class TYPE, class ACE_LOCK>
std::atomic<ACE_DLL_Singleton_T<TYPE, ACE_LOCK> *>
ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::singleton_ {nullptr};

template <class TYPE, class ACE_LOCK> void
ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::dump ()
{
#if defined (ACE_HAS_DUMP)
  ACE_TRACE ("ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::dump");

  ACELIB_DEBUG ((LM_DEBUG,  ACE_TEXT ("instance_ = %x"),
              ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::instance_i ().load ()));
  ACELIB_DEBUG ((LM_DEBUG, ACE_END_DUMP));
#endif /* ACE_HAS_DUMP */
}

template <class TYPE, class ACE_LOCK>
std::atomic<ACE_DLL_Singleton_T<TYPE, ACE_LOCK> *> &
ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::instance_i ()
{
  ACE_TRACE ("ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::instance_i");

  return ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::singleton_;
}

template <class TYPE, class ACE_LOCK> TYPE *
ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::instance ()
{
  ACE_TRACE ("ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::instance");

  std::atomic<ACE_DLL_Singleton_T<TYPE, ACE_LOCK> *> &singleton =
    ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::instance_i ();

  // Perform the Double-Check pattern.  The first check is an acquire
  // load: a thread that sees the pointer also sees the constructed
  // object, which is published with a release store.
  ACE_DLL_Singleton_T<TYPE, ACE_LOCK> *s = singleton.load (std::memory_order_acquire);
  if (s == nullptr)
    {
      if (ACE_Object_Manager::starting_up () || ACE_Object_Manager::shutting_down ())
        {
          // The program is still starting up, and therefore assumed
          // to be single threaded.  There's no need to double-check.
          // Or, the ACE_Object_Manager instance has been destroyed,
          // so the preallocated lock is not available.  Either way,
          // don't register for destruction with the
          // ACE_Object_Manager:  we'll have to leak this instance.

          ACE_NEW_RETURN (s, (ACE_DLL_Singleton_T<TYPE, ACE_LOCK>), nullptr);
          //ACE_REGISTER_FRAMEWORK_COMPONENT(ACE_DLL_Singleton<TYPE,ACE_LOCK>, singleton);
          ACE_Framework_Repository::instance ()->register_component
            (new ACE_Framework_Component_T<ACE_DLL_Singleton_T<TYPE, ACE_LOCK> > (s));
          singleton.store (s, std::memory_order_release);
        }
      else
        {
#if defined (ACE_MT_SAFE) && (ACE_MT_SAFE != 0)
          // Obtain a lock from the ACE_Object_Manager.  The pointer
          // is static, so we only obtain one per instantiation.
#if defined(ACE_FACE_SAFETY_BASE)
          static ACE_LOCK the_lock;
          static ACE_LOCK *lock = &the_lock;
#else /* ACE_FACE_SAFETY_BASE */
          static ACE_LOCK *lock = nullptr;
#endif /* ACE_FACE_SAFETY_BASE */
          if (ACE_Object_Manager::get_singleton_lock (lock) != 0)
            // Failed to acquire the lock!
            return 0;

          ACE_GUARD_RETURN (ACE_LOCK, ace_mon, *lock, 0);
          s = singleton.load (std::memory_order_relaxed);
          if (s == nullptr)
            {
#endif /* ACE_MT_SAFE */
              ACE_NEW_RETURN (s, (ACE_DLL_Singleton_T<TYPE, ACE_LOCK>), 0);
              //ACE_REGISTER_FRAMEWORK_COMPONENT(ACE_DLL_Singleton<TYPE,ACE_LOCK>, singleton);
              ACE_Framework_Repository::instance ()->register_component
                (new ACE_Framework_Component_T<ACE_DLL_Singleton_T<TYPE, ACE_LOCK> > (s));
              singleton.store (s, std::memory_order_release);
#if defined (ACE_MT_SAFE) && (ACE_MT_SAFE != 0)
            }
#endif /* ACE_MT_SAFE */
        }
    }

  return &s->instance_;
}

template <class TYPE, class ACE_LOCK> void
ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::close ()
{
  ACE_TRACE ("ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::close");

  delete ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::instance_i ().exchange (nullptr);
}

template <class TYPE, class ACE_LOCK> void
ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::close_singleton ()
{
  ACE_TRACE ("ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::close_singleton");
  ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::close ();
}

template <class TYPE, class ACE_LOCK> const ACE_TCHAR *
ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::dll_name ()
{
  return this->instance ()->dll_name ();
}

template <class TYPE, class ACE_LOCK> const ACE_TCHAR *
ACE_DLL_Singleton_T<TYPE, ACE_LOCK>::name ()
{
  return this->instance ()->name ();
}


/**********************************************************************/

template <class TYPE> const ACE_TCHAR*
ACE_DLL_Singleton_Adapter_T<TYPE>::dll_name ()
{
  // @todo make this a constant somewhere (or it there already is one
  // then use it.
  return ACE_TEXT("ACE");
}

ACE_END_VERSIONED_NAMESPACE_DECL

#endif /* ACE_SINGLETON_CPP */
