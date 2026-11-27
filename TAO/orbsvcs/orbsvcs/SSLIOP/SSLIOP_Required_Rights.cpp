#include "orbsvcs/SSLIOP/SSLIOP_Required_Rights.h"
#include "orbsvcs/SSLIOP/SSLIOP_Role_Model.h"
#include "orbsvcs/Security/Audit_Logger.h"

#include "tao/Security_Mode.h"

#include <string>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  namespace RM = TAO::SSLIOP::Role_Model;
  namespace Reason = TAO::Security::Audit_Reason;

  /// The Security Service's standard rights family (definer 0, family 1).
  bool
  standard_family (::Security::ExtensibleFamily const &f)
  {
    return f.family_definer == 0 && f.family == 1;
  }

  char const *const letters[] = { "g", "s", "m", "u" };
}

void
TAO::SSLIOP::Required_Rights::get_required_rights (CORBA::Object_ptr,
                                                   const char *operation_name,
                                                   const char *interface_name,
                                                   ::Security::RightsList_out rights,
                                                   ::Security::RightsCombinator_out rights_combinator)
{
  ::Security::RightsList_var out;
  ACE_NEW_THROW_EX (out, ::Security::RightsList, CORBA::NO_MEMORY ());
  rights_combinator = ::Security::SecAllRights;
  RM::Requirement r;
  if (operation_name != nullptr && interface_name != nullptr
      && RM::Engine::instance ()->required (interface_name, operation_name, r))
    {
      for (unsigned i = 0; i < 4; ++i)
        if ((r.rights & (1u << i)) != 0)
          {
            CORBA::ULong const n = out->length ();
            out->length (n + 1);
            out[n].rights_family.family_definer = 0;
            out[n].rights_family.family = 1;
            out[n].the_right = CORBA::string_dup (letters[i]);
          }
      rights_combinator = r.any ? ::Security::SecAnyRight : ::Security::SecAllRights;
    }
  rights = out._retn ();
}

void
TAO::SSLIOP::Required_Rights::set_required_rights (const char *operation_name,
                                                   const char *interface_name,
                                                   const ::Security::RightsList &rights,
                                                   ::Security::RightsCombinator rights_combinator)
{
  std::string const op = operation_name != nullptr ? operation_name : "";
  std::string const iface = interface_name != nullptr ? interface_name : "";
  if (TAO_Security_Mode::host ().mode == TAO_Security_Mode::MODE_PROD)
    {
      TAO::Security::Audit_Logger::instance ()->write (
        TAO::Security::Audit_Record ("roles", false, Reason::REQUIRED_RIGHTS_REFUSED)
          .field ("interface", iface)
          .field ("op", op)
          .text ("set_required_rights refused in prod: required rights change only through signed tables"));
      throw CORBA::NO_PERMISSION ();
    }

  RM::Requirement r;
  for (CORBA::ULong i = 0; i < rights.length (); ++i)
    {
      std::string const right = rights[i].the_right.in ();
      unsigned bit = 0;
      for (unsigned k = 0; k < 4; ++k)
        if (right == letters[k])
          bit = 1u << k;
      if (!standard_family (rights[i].rights_family) || bit == 0)
        throw CORBA::BAD_PARAM ();
      r.rights |= bit;
    }
  if (iface.compare (0, 4, "IDL:") != 0 || op.empty () || r.rights == 0)
    throw CORBA::BAD_PARAM ();
  r.any = rights_combinator == ::Security::SecAnyRight;
  RM::Engine::instance ()->override_required (iface, op, r);
  TAO::Security::Audit_Logger::instance ()->write (
    TAO::Security::Audit_Record ("roles", true, Reason::REQUIRED_RIGHTS_SET)
      .field ("interface", iface)
      .field ("op", op)
      .field ("rights_required", (r.any ? "any:" : "") + RM::rights_text (r.rights))
      .text ("test mode: in memory only, until the process ends"));
}

TAO_END_VERSIONED_NAMESPACE_DECL
