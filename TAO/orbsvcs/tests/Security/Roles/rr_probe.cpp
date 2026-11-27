// RequiredRights probe (Phase 3 T2, R41): SecurityLevel2 RequiredRights
// answered from the role model's signed required-rights table.
//
//   rr_probe -ORBSvcConf SVC IFACE OP [set RIGHTS any|all]
//
// Prints "RIGHTS <letters> all|any" for (IFACE, OP), or "RIGHTS none";
// with "set" first calls set_required_rights (RIGHTS: letters g s m u,
// e.g. "gs") and prints "SET OK" or "SET <exception>", then the rights
// again.  "NO_IMPLEMENT" when the role model is not configured.
// ACE_TAO_SECURITY_CONF names the security configuration.

#include "orbsvcs/SecurityLevel2C.h"

#include "ace/OS_main.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_string.h"

#include <string>

namespace
{
  void
  show (SecurityLevel2::RequiredRights_ptr rr, char const *iface, char const *op)
  {
    ::Security::RightsList_var rights;
    ::Security::RightsCombinator comb;
    rr->get_required_rights (CORBA::Object::_nil (), op, iface, rights.out (), comb);
    std::string letters;
    for (CORBA::ULong i = 0; i < rights->length (); ++i)
      letters += rights[i].the_right.in ();
    if (letters.empty ())
      ACE_OS::printf ("RIGHTS none\n");
    else
      ACE_OS::printf ("RIGHTS %s %s\n", letters.c_str (), comb == ::Security::SecAnyRight ? "any" : "all");
  }
}

int
ACE_TMAIN (int argc, ACE_TCHAR *argv[])
{
  try
    {
      CORBA::ORB_var orb = CORBA::ORB_init (argc, argv);
      if (argc < 3)
        {
          ACE_OS::fprintf (stderr, "usage: rr_probe IFACE OP [set RIGHTS any|all]\n");
          return 64;
        }
      std::string const iface = ACE_TEXT_ALWAYS_CHAR (argv[1]);
      std::string const op = ACE_TEXT_ALWAYS_CHAR (argv[2]);
      CORBA::Object_var obj = orb->resolve_initial_references ("SecurityLevel2:SecurityManager");
      SecurityLevel2::SecurityManager_var sm = SecurityLevel2::SecurityManager::_narrow (obj.in ());
      SecurityLevel2::RequiredRights_var rr;
      try
        {
          rr = sm->required_rights_object ();
        }
      catch (CORBA::NO_IMPLEMENT const &)
        {
          ACE_OS::printf ("NO_IMPLEMENT\n");
          orb->destroy ();
          return 0;
        }
      show (rr.in (), iface.c_str (), op.c_str ());
      if (argc >= 6 && ACE_OS::strcmp (argv[3], ACE_TEXT ("set")) == 0)
        {
          std::string const letters = ACE_TEXT_ALWAYS_CHAR (argv[4]);
          ::Security::RightsList rights (static_cast<CORBA::ULong> (letters.size ()));
          rights.length (static_cast<CORBA::ULong> (letters.size ()));
          for (CORBA::ULong i = 0; i < rights.length (); ++i)
            {
              rights[i].rights_family.family_definer = 0;
              rights[i].rights_family.family = 1;
              rights[i].the_right = CORBA::string_dup (std::string (1, letters[i]).c_str ());
            }
          try
            {
              rr->set_required_rights (op.c_str (), iface.c_str (), rights,
                                       ACE_OS::strcmp (argv[5], ACE_TEXT ("any")) == 0 ? ::Security::SecAnyRight
                                                                                         : ::Security::SecAllRights);
              ACE_OS::printf ("SET OK\n");
            }
          catch (CORBA::Exception const &ex)
            {
              ACE_OS::printf ("SET %s\n", ex._name ());
            }
          show (rr.in (), iface.c_str (), op.c_str ());
        }
      orb->destroy ();
    }
  catch (CORBA::INITIALIZE const &ex)
    {
      ACE_OS::printf ("ORB_INIT REFUSED: %s\n", ex._name ());
      return 2;
    }
  catch (CORBA::Exception const &ex)
    {
      ex._tao_print_exception ("rr_probe");
      return 1;
    }
  return 0;
}
