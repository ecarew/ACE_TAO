// SAS test server: the Caller test server (Who objects "alpha" and
// "beta" in POA "Who", whoami() reporting the caller from
// SecurityLevel3::SecurityCurrent) with a test GSSUP verifier installed
// before ORB_init: user "alice", password "wonderland" (test data only).
// With SAS_TEST_NO_VERIFIER set it installs none, so a gssup_store in
// security.conf supplies the verifier (the GSSUP_Store test).
// Writes alpha.ior and beta.ior into the directory given with -d.

#include "TestS.h"

#include "orbsvcs/SecurityLevel3C.h"
#include "orbsvcs/Security/GSSUP_Verifier.h"

#include "ace/Get_Opt.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"

#include <string>

namespace
{
  /// Test verifier: fixed users and passwords.
  class Test_Verifier : public TAO::Security::GSSUP_Verifier
  {
  public:
    Result
    verify (std::string const &user, std::string const &password, std::string const &target,
            std::string const &, std::string &detail) override
    {
      if (user == "alice" && password == "wonderland" && target == "@lab.test")
        return ACCEPTED;
      // A name with an '@' in it, sent quoted as "bob\@corp" (10.2.5.2).
      if (user == "bob@corp" && password == "builder" && target == "@lab.test")
        return ACCEPTED;
      detail = user == "alice" ? "wrong password" : "unknown user";
      return REJECTED;
    }
  };
  std::string
  narrow (CORBA::WChar const *w)
  {
    std::string out;
    for (; w != nullptr && *w != 0; ++w)
      out += *w < 0x80 ? static_cast<char> (*w) : '?';
    return out;
  }

  std::string
  describe (SecurityLevel3::PrincipalName const &n)
  {
    std::string s = n.the_type.in ();
    s += ":";
    for (CORBA::ULong i = 0; i < n.the_name.length (); ++i)
      s += narrow (n.the_name[i].in ());
    return s;
  }

  class Who_i : public virtual POA_Who
  {
  public:
    Who_i (CORBA::ORB_ptr orb, SecurityLevel3::SecurityCurrent_ptr current)
      : orb_ (CORBA::ORB::_duplicate (orb)),
        current_ (SecurityLevel3::SecurityCurrent::_duplicate (current))
    {
    }

    char *
    whoami () override
    {
      SecurityLevel3::ClientCredentials_var creds = this->current_->client_credentials ();
      SecurityLevel3::Principal_var p = creds->client_principal ();
      std::string s = "name=" + describe (p->the_name ());
      SecurityLevel3::SimplePrincipal *const simple = SecurityLevel3::SimplePrincipal::_downcast (p.in ());
      if (simple != nullptr)
        {
          s += std::string (" authenticated=") + (simple->authenticated () ? "yes" : "no");
          for (CORBA::ULong i = 0; i < simple->alternate_names ().length (); ++i)
            s += " alt=" + describe (simple->alternate_names ()[i]);
        }
      return CORBA::string_dup (s.c_str ());
    }

    void poke () override {}

    char *
    relay (char const *ior) override
    {
      CORBA::Object_var obj = this->orb_->string_to_object (ior);
      Who_var next = Who::_unchecked_narrow (obj.in ());
      CORBA::String_var s = next->whoami ();
      return CORBA::string_dup ((std::string ("RELAY ") + s.in ()).c_str ());
    }

    void shutdown () override { this->orb_->shutdown (false); }

  private:
    CORBA::ORB_var orb_;
    SecurityLevel3::SecurityCurrent_var current_;
  };

  bool
  write_ior (CORBA::ORB_ptr orb, CORBA::Object_ptr obj, std::string const &path)
  {
    CORBA::String_var ior = orb->object_to_string (obj);
    FILE *const fp = ACE_OS::fopen (path.c_str (), ACE_TEXT ("w"));
    if (fp == nullptr)
      return false;
    ACE_OS::fprintf (fp, "%s", ior.in ());
    ACE_OS::fclose (fp);
    return true;
  }
}

int
ACE_TMAIN (int argc, ACE_TCHAR *argv[])
{
  try
    {
      static Test_Verifier verifier;
      if (ACE_OS::getenv ("SAS_TEST_NO_VERIFIER") == nullptr)
        TAO::Security::GSSUP_Verifier::install (&verifier);
      CORBA::ORB_var orb = CORBA::ORB_init (argc, argv);
      std::string dir = ".";
      ACE_Get_Opt opts (argc, argv, ACE_TEXT ("d:"));
      for (int c; (c = opts ()) != -1; )
        if (c == 'd')
          dir = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ());

      CORBA::Object_var obj = orb->resolve_initial_references ("SecurityLevel3:SecurityCurrent");
      SecurityLevel3::SecurityCurrent_var current = SecurityLevel3::SecurityCurrent::_narrow (obj.in ());

      obj = orb->resolve_initial_references ("RootPOA");
      PortableServer::POA_var root = PortableServer::POA::_narrow (obj.in ());
      PortableServer::POAManager_var mgr = root->the_POAManager ();

      CORBA::PolicyList policies (2);
      policies.length (2);
      policies[0] = root->create_id_assignment_policy (PortableServer::USER_ID);
      policies[1] = root->create_id_uniqueness_policy (PortableServer::MULTIPLE_ID);
      PortableServer::POA_var poa = root->create_POA ("Who", mgr.in (), policies);
      for (CORBA::ULong i = 0; i < policies.length (); ++i)
        policies[i]->destroy ();

      PortableServer::Servant_var<Who_i> servant = new Who_i (orb.in (), current.in ());
      for (char const *name : {"alpha", "beta"})
        {
          PortableServer::ObjectId_var id = PortableServer::string_to_ObjectId (name);
          poa->activate_object_with_id (id.in (), servant.in ());
          obj = poa->id_to_reference (id.in ());
          if (!write_ior (orb.in (), obj.in (), dir + "/" + name + ".ior"))
            return 1;
        }
      ACE_OS::printf ("SERVER READY\n");
      ACE_OS::fflush (stdout);

      mgr->activate ();
      orb->run ();
      orb->destroy ();
    }
  catch (CORBA::INITIALIZE const &ex)
    {
      ACE_OS::printf ("ORB_INIT REFUSED: %s\n", ex._name ());
      return 2;
    }
  catch (CORBA::Exception const &ex)
    {
      ex._tao_print_exception ("server");
      return 1;
    }
  return 0;
}
