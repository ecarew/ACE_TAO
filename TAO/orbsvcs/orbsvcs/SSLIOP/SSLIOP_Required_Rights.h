// -*- C++ -*-

//=============================================================================
/**
 *  @file SSLIOP_Required_Rights.h
 *
 *  SecurityLevel2::RequiredRights answered from the role model's signed
 *  required-rights table (Phase 3 T2, R41).  Rights are the Security
 *  Service's standard family (definer 0, family 1): "g" get, "s" set,
 *  "m" manage, "u" use.  In prod set_required_rights is refused (tables
 *  change only through signed files); in test mode it changes the
 *  in-memory requirement.  Both are audited.
 */
//=============================================================================

#ifndef TAO_SSLIOP_REQUIRED_RIGHTS_H
#define TAO_SSLIOP_REQUIRED_RIGHTS_H

#include /**/ "ace/pre.h"

#include "orbsvcs/SSLIOP/SSLIOP_Export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "orbsvcs/SecurityLevel2C.h"
#include "tao/LocalObject.h"

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4250)
#endif /* _MSC_VER */

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace SSLIOP
  {
    class TAO_SSLIOP_Export Required_Rights
      : public virtual SecurityLevel2::RequiredRights,
        public virtual ::CORBA::LocalObject
    {
    public:
      Required_Rights () = default;

      void get_required_rights (CORBA::Object_ptr obj,
                                const char *operation_name,
                                const char *interface_name,
                                ::Security::RightsList_out rights,
                                ::Security::RightsCombinator_out rights_combinator) override;

      void set_required_rights (const char *operation_name,
                                const char *interface_name,
                                const ::Security::RightsList &rights,
                                ::Security::RightsCombinator rights_combinator) override;

    protected:
      ~Required_Rights () override = default;
    };
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#if defined(_MSC_VER)
#pragma warning(pop)
#endif /* _MSC_VER */

#include /**/ "ace/post.h"

#endif /* TAO_SSLIOP_REQUIRED_RIGHTS_H */
