// SAS test client: calls Who over SSLIOP with a hand-made CSIv2 SAS
// service context (a client request interceptor adds it) and prints the
// SAS context of the reply.
//
//   client -k IOR [-c whoami|poke|relay] [-m MODE] [-a ASSERTION] [-i CONTEXT_ID]
//          [-g USER:SOURCE[:TARGET] [-G]] [-b] [-r IOR]
//
// -c relay asks the server to call whoami() on the -r reference and
// prints "RELAY <its answer>".
//
// -g acquires SecurityLevel3 "SL3GSSUP" credentials (SOURCE: prompt,
// fd:N or file:PATH; TARGET: the GSSUP target name, default the user's
// realm) and lets TAO's own SAS client send them ("ACQUIRE OK" or
// "ACQUIRE FAILED <exception>").  They go on the ORB's default list, or
// with -G into a ContextEstablishmentPolicy on the reference.  -b sets a
// ContextEstablishmentPolicy that turns TAO's client authentication off,
// so a target that requires GSSUP is called without it.
//
// -K KEY=VALUE[,KEY=VALUE...] acquires SecurityLevel3 "SL3Kerberos"
// credentials (keys ccache, keytab, principal, target; see
// SSLIOP::KerberosAuthData) the same way ("ACQUIRE OK" or "ACQUIRE
// FAILED <exception>").  With both -g and -K, TAO prefers Kerberos.
//
// MODE:
//   none                    no SAS context (with -a: EstablishContext with
//                           only the identity token)
//   gssup:USER:PASS[:TARGET] EstablishContext with a GSSUP token
//                           (TARGET default @lab.test, as an exported name)
//   authz:USER:PASS         the same plus a one-element authorization token
//   ident                   EstablishContext with an ITTPrincipalName identity token
//   notgssup                a client authentication token for another mechanism
//   krb5:PRINCIPAL:BIND[:SAVE] a Kerberos token for service PRINCIPAL from the
//                           ticket cache (KRB5CCNAME); BIND is "none" or the
//                           target's certificate (PEM) for channel binding;
//                           SAVE writes the token to a file
//   krb5save:PRINCIPAL:BIND:FILE  make that token and write it to FILE, but
//                           send an EstablishContext without it
//   rawtoken:FILE           a client authentication token read from FILE
//   mic                     MessageInContext
//   garbage                 an undecodable SAS context
//
// ASSERTION (an identity token added to the EstablishContext):
//   name:NAME               ITTPrincipalName (GSSUP exported name)
//   krbname:NAME            ITTPrincipalName: a Kerberos exported name (K5)
//   badoid:NAME             ITTPrincipalName under an unknown mechanism OID
//   dn:CERT.pem             ITTDistinguishedName: the certificate's subject
//   x509:CERT.pem[,CA.pem]  ITTX509CertChain (DER SEQUENCE OF Certificate)
//   anonymous               ITTAnonymous
//   type:N                  an identity token of unsupported type N
//
// Prints "SAS REPLY complete ctx=N stateful=B", "SAS REPLY error ctx=N
// major=M minor=N gssup_error=E" or "SAS REPLY none", then "WHOAMI ...",
// "POKE OK" or "<op> EXCEPTION <name>".

#include "TestC.h"

#include "orbsvcs/CSIC.h"
#include "orbsvcs/GSSUPC.h"
#include "orbsvcs/Security/CSI_Utils.h"
#include "orbsvcs/SSLIOP/SSLIOP_SAS.h"
#include "orbsvcs/SSLIOP/SSLIOP_Kerberos.h"
#include "orbsvcs/SecurityLevel3C.h"
#include "orbsvcs/SSLIOPC.h"

#include "tao/PI/PI.h"
#include "tao/LocalObject.h"
#include "tao/ORBInitializer_Registry.h"
#include "tao/CDR.h"

#include "ace/Get_Opt.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_string.h"

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <string>
#include <vector>

namespace
{
  std::string mode = "none";
  std::string assertion;
  CSI::ContextId context_id = 0;

  std::vector<std::string>
  split_on (std::string const &s, char sep)
  {
    std::vector<std::string> out;
    size_t p = 0;
    for (;;)
      {
        size_t const c = s.find (sep, p);
        out.push_back (s.substr (p, c == std::string::npos ? std::string::npos : c - p));
        if (c == std::string::npos)
          break;
        p = c + 1;
      }
    return out;
  }

  std::vector<std::string>
  split (std::string const &s)
  {
    std::vector<std::string> out;
    size_t p = 0;
    for (;;)
      {
        size_t const c = s.find (':', p);
        out.push_back (s.substr (p, c == std::string::npos ? std::string::npos : c - p));
        if (c == std::string::npos)
          break;
        p = c + 1;
      }
    return out;
  }

  template <typename SEQ>
  void
  set_octets (SEQ &seq, std::string const &v)
  {
    seq.length (static_cast<CORBA::ULong> (v.size ()));
    if (!v.empty ())
      ACE_OS::memcpy (seq.get_buffer (), v.data (), v.size ());
  }

  /// DER of the certificate in @a pem (empty on failure).
  std::string
  cert_der (std::string const &pem, bool subject_only)
  {
    std::string out;
    FILE *const fp = ACE_OS::fopen (pem.c_str (), "r");
    if (fp == nullptr)
      return out;
    X509 *const x = ::PEM_read_X509 (fp, nullptr, nullptr, nullptr);
    ACE_OS::fclose (fp);
    if (x == nullptr)
      return out;
    unsigned char *buf = nullptr;
    int const n = subject_only ? ::i2d_X509_NAME (::X509_get_subject_name (x), &buf) : ::i2d_X509 (x, &buf);
    if (n > 0)
      out.assign (reinterpret_cast<char const *> (buf), static_cast<size_t> (n));
    ::OPENSSL_free (buf);
    ::X509_free (x);
    return out;
  }

  /// Channel-binding data for the certificate in @a pem, or empty.
  std::string
  binding_of (std::string const &pem)
  {
    if (pem == "none")
      return std::string ();
    FILE *const fp = ACE_OS::fopen (pem.c_str (), "r");
    if (fp == nullptr)
      return std::string ();
    X509 *const x = ::PEM_read_X509 (fp, nullptr, nullptr, nullptr);
    ACE_OS::fclose (fp);
    std::string const out = TAO::SSLIOP::Kerberos::tls_server_end_point (x);
    ::X509_free (x);
    return out;
  }

  /// DER length octets.
  std::string
  der_length (size_t n)
  {
    if (n < 128)
      return std::string (1, static_cast<char> (n));
    std::string b;
    for (; n > 0; n >>= 8)
      b.insert (b.begin (), static_cast<char> (n & 0xFF));
    return std::string (1, static_cast<char> (0x80 | b.size ())) + b;
  }

  bool
  make_identity (CSI::IdentityToken &tok)
  {
    std::string const kind = assertion.substr (0, assertion.find (':'));
    std::string const arg = assertion.find (':') == std::string::npos ? "" : assertion.substr (assertion.find (':') + 1);
    if (kind == "name")
      {
        CSI::GSS_NT_ExportedName name;
        set_octets (name, TAO::SSLIOP::SAS_Target::exported_name (arg));
        tok.principal_name (name);
      }
    else if (kind == "krbname")
      {
        CSI::GSS_NT_ExportedName name;
        set_octets (name, TAO::SSLIOP::Kerberos::exported_name (arg));
        tok.principal_name (name);
      }
    else if (kind == "badoid")
      {
        // 04 01, an OID no mechanism here uses (1.3.6.1.4.1.32473.1, from
        // the documentation range), the name.
        std::string const oid ("\x06\x09\x2b\x06\x01\x04\x01\x81\xfd\x59\x01", 11);
        std::string o ("\x04\x01", 2);
        o += static_cast<char> (0);
        o += static_cast<char> (oid.size ());
        o += oid;
        for (int shift = 24; shift >= 0; shift -= 8)
          o += static_cast<char> ((arg.size () >> shift) & 0xFF);
        o += arg;
        CSI::GSS_NT_ExportedName name;
        set_octets (name, o);
        tok.principal_name (name);
      }
    else if (kind == "dn")
      {
        std::string const der = cert_der (arg, true);
        if (der.empty ())
          return false;
        CSI::X501DistinguishedName dn;
        set_octets (dn, der);
        tok.dn (dn);
      }
    else if (kind == "x509")
      {
        std::string certs;
        for (std::string const &f : split_on (arg, ','))
          {
            std::string const der = cert_der (f, false);
            if (der.empty ())
              return false;
            certs += der;
          }
        CSI::X509CertificateChain chain;
        set_octets (chain, std::string ("\x30", 1) + der_length (certs.size ()) + certs);
        tok.certificate_chain (chain);
      }
    else if (kind == "anonymous")
      {
        tok.anonymous (true);
      }
    else if (kind == "type")
      {
        CSI::IdentityExtension ext;
        set_octets (ext, std::string ("x", 1));
        tok.id (ext);
        tok._d (static_cast<CSI::IdentityTokenType> (ACE_OS::atoi (arg.c_str ())));
      }
    else
      {
        return false;
      }
    return true;
  }

  bool
  make_context (IOP::ServiceContext &sc)
  {
    std::vector<std::string> const a = split (mode);
    CSI::SASContextBody body;
    if (a[0] == "garbage")
      {
        sc.context_id = IOP::SecurityAttributeService;
        set_octets (sc.context_data, std::string ("\x01", 1));   // byte order only
        return true;
      }
    if (a[0] == "mic")
      {
        CSI::MessageInContext m;
        m.client_context_id = context_id == 0 ? 42 : context_id;
        m.discard_context = false;
        body.in_context_msg (m);
      }
    else
      {
        CSI::EstablishContext ec;
        ec.client_context_id = context_id;
        ec.authorization_token.length (0);
        ec.identity_token.absent (true);
        ec.client_authentication_token.length (0);
        if ((a[0] == "gssup" || a[0] == "authz") && a.size () >= 3)
          {
            std::string const target = a.size () >= 4 ? a[3] : "@lab.test";
            if (!TAO::SSLIOP::SAS_Target::encode_gssup_token (
                  a[1], a[2], TAO::SSLIOP::SAS_Target::exported_name (target), ec.client_authentication_token))
              return false;
            if (a[0] == "authz")
              {
                ec.authorization_token.length (1);
                ec.authorization_token[0].the_type = CSI::X509AttributeCertChain;
                set_octets (ec.authorization_token[0].the_element, std::string ("cert-chain", 10));
              }
          }
        else if (a[0] == "ident")
          {
            CSI::GSS_NT_ExportedName name;
            set_octets (name, TAO::SSLIOP::SAS_Target::exported_name ("mallory@lab.test"));
            ec.identity_token.principal_name (name);
          }
        else if (a[0] == "none")
          {
            // Only the identity token (-a).
          }
        else if ((a[0] == "krb5" && a.size () >= 3) || (a[0] == "krb5save" && a.size () >= 4))
          {
            std::string token;
            std::string why;
            if (!TAO::SSLIOP::Kerberos::initiate (a[1], binding_of (a[2]), token, why))
              {
                ACE_OS::printf ("KRB5 INIT FAILED %s\n", why.c_str ());
                return false;
              }
            if (a.size () >= 4)
              {
                FILE *const fp = ACE_OS::fopen (a[3].c_str (), "wb");
                if (fp == nullptr || ACE_OS::fwrite (token.data (), 1, token.size (), fp) != token.size ())
                  return false;
                ACE_OS::fclose (fp);
              }
            if (a[0] == "krb5")
              set_octets (ec.client_authentication_token, token);
          }
        else if (a[0] == "rawtoken" && a.size () >= 2)
          {
            FILE *const fp = ACE_OS::fopen (a[1].c_str (), "rb");
            if (fp == nullptr)
              return false;
            std::string token;
            char buf[4096];
            size_t n;
            while ((n = ACE_OS::fread (buf, 1, sizeof buf, fp)) > 0)
              token.append (buf, n);
            ACE_OS::fclose (fp);
            set_octets (ec.client_authentication_token, token);
          }
        else if (a[0] == "notgssup")
          {
            // A Kerberos-mechanism token: 0x60 len, OID 1.2.840.113554.1.2.2, junk.
            set_octets (ec.client_authentication_token,
                        std::string ("\x60\x0f\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01\x00\x00\x00", 17));
          }
        else
          {
            return false;
          }
        if (!assertion.empty () && !make_identity (ec.identity_token))
          return false;
        body.establish_msg (ec);
      }
    TAO::CSI_Utils::create_sas_service_context (body, sc);
    return true;
  }

  void
  print_reply (PortableInterceptor::ClientRequestInfo_ptr ri)
  {
    IOP::ServiceContext_var sc;
    try
      {
        sc = ri->get_reply_service_context (IOP::SecurityAttributeService);
      }
    catch (CORBA::BAD_PARAM const &)
      {
        ACE_OS::printf ("SAS REPLY none\n");
        return;
      }
    CSI::SASContextBody body;
    if (!TAO::CSI_Utils::extract_sas_service_context (sc.in (), body))
      {
        ACE_OS::printf ("SAS REPLY undecodable\n");
        return;
      }
    if (body._d () == CSI::MTCompleteEstablishContext)
      {
        ACE_OS::printf ("SAS REPLY complete ctx=%llu stateful=%d\n",
                        static_cast<unsigned long long> (body.complete_msg ().client_context_id),
                        body.complete_msg ().context_stateful ? 1 : 0);
        if (body.complete_msg ().final_context_token.length () > 0)
          ACE_OS::printf ("SAS FINAL TOKEN %u octets\n",
                          static_cast<unsigned> (body.complete_msg ().final_context_token.length ()));
      }
    else if (body._d () == CSI::MTContextError)
      {
        CSI::ContextError const &e = body.error_msg ();
        long gssup_error = 0;
        if (e.error_token.length () > 0)
          {
            TAO_InputCDR cdr (reinterpret_cast<char const *> (e.error_token.get_buffer ()), e.error_token.length ());
            CORBA::Boolean bo;
            GSSUP::ErrorToken t;
            if ((cdr >> ACE_InputCDR::to_boolean (bo)))
              {
                cdr.reset_byte_order (static_cast<int> (bo));
                if (cdr >> t)
                  gssup_error = static_cast<long> (t.error_code);
              }
          }
        ACE_OS::printf ("SAS REPLY error ctx=%llu major=%d minor=%d gssup_error=%ld\n",
                        static_cast<unsigned long long> (e.client_context_id), static_cast<int> (e.major_status),
                        static_cast<int> (e.minor_status), gssup_error);
      }
    else
      ACE_OS::printf ("SAS REPLY type=%d\n", static_cast<int> (body._d ()));
  }

  class SAS_Client_Interceptor
    : public virtual PortableInterceptor::ClientRequestInterceptor,
      public virtual ::CORBA::LocalObject
  {
  public:
    char *name () override { return CORBA::string_dup ("SAS_Test_Client"); }
    void destroy () override {}
    void
    send_request (PortableInterceptor::ClientRequestInfo_ptr ri) override
    {
      if (mode == "none" && assertion.empty ())
        return;
      IOP::ServiceContext sc;
      if (!make_context (sc))
        {
          ACE_OS::printf ("BAD MODE %s / ASSERTION %s\n", mode.c_str (), assertion.c_str ());
          return;
        }
      ri->add_request_service_context (sc, true);
    }
    void send_poll (PortableInterceptor::ClientRequestInfo_ptr) override {}
    void receive_reply (PortableInterceptor::ClientRequestInfo_ptr ri) override { print_reply (ri); }
    void receive_exception (PortableInterceptor::ClientRequestInfo_ptr ri) override { print_reply (ri); }
    void receive_other (PortableInterceptor::ClientRequestInfo_ptr) override {}
  };

  class Initializer
    : public virtual PortableInterceptor::ORBInitializer,
      public virtual ::CORBA::LocalObject
  {
  public:
    void pre_init (PortableInterceptor::ORBInitInfo_ptr) override {}
    void
    post_init (PortableInterceptor::ORBInitInfo_ptr info) override
    {
      PortableInterceptor::ClientRequestInterceptor_var i = new SAS_Client_Interceptor;
      info->add_client_request_interceptor (i.in ());
    }
  };
}

int
ACE_TMAIN (int argc, ACE_TCHAR *argv[])
{
  char const *what = "whoami";
  try
    {
      PortableInterceptor::ORBInitializer_var init = new Initializer;
      PortableInterceptor::register_orb_initializer (init.in ());

      CORBA::ORB_var orb = CORBA::ORB_init (argc, argv);
      char const *ior = nullptr;
      std::string gssup;
      std::string kerberos;
      bool in_policy = false;
      bool bypass = false;
      char const *relay_ior = "";
      ACE_Get_Opt opts (argc, argv, ACE_TEXT ("k:c:m:a:i:g:K:Gbr:"));
      for (int c; (c = opts ()) != -1; )
        switch (c)
          {
          case 'k': ior = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          case 'c': what = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          case 'm': mode = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          case 'a': assertion = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          case 'i': context_id = ACE_OS::strtoull (ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()), nullptr, 10); break;
          case 'g': gssup = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          case 'K': kerberos = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          case 'G': in_policy = true; break;
          case 'b': bypass = true; break;
          case 'r': relay_ior = ACE_TEXT_ALWAYS_CHAR (opts.opt_arg ()); break;
          default: break;
          }
      if (ior == nullptr)
        {
          ACE_OS::fprintf (stderr, "usage: client -k IOR [-c whoami|poke] [-m MODE] [-a ASSERTION] [-i CONTEXT_ID]\n");
          return 64;
        }

      CORBA::Object_var obj = orb->string_to_object (ior);
      if (CORBA::is_nil (obj.in ()))
        {
          ACE_OS::printf ("NIL REFERENCE\n");
          orb->destroy ();
          return 1;
        }
      SecurityLevel3::OwnCredentials_var creds;
      if (!gssup.empty ())
        {
          std::vector<std::string> const g = split_on (gssup, ':');
          try
            {
              CORBA::Object_var cobj = orb->resolve_initial_references ("SecurityLevel3:CredentialsCurator");
              SecurityLevel3::CredentialsCurator_var curator = SecurityLevel3::CredentialsCurator::_narrow (cobj.in ());
              SSLIOP::GSSUPAuthData data;
              data.username = g.size () > 0 ? g[0].c_str () : "";
              // A SOURCE of file:PATH or fd:N holds a colon: rejoin it.
              std::string source = g.size () > 1 ? g[1] : "";
              size_t next = 2;
              if ((source == "file" || source == "fd") && g.size () > 2)
                source += ":" + g[next++];
              data.password_source = source.c_str ();
              data.target_name = g.size () > next ? g[next].c_str () : "";
              CORBA::Any args;
              args <<= data;
              SecurityLevel3::CredentialsAcquirer_var acquirer = curator->acquire_credentials ("SL3GSSUP", args);
              creds = acquirer->get_credentials (!in_policy);
              ACE_OS::printf ("ACQUIRE OK\n");
            }
          catch (CORBA::Exception const &ex)
            {
              ACE_OS::printf ("ACQUIRE FAILED %s\n", ex._name ());
              orb->destroy ();
              return 0;
            }
        }
      SecurityLevel3::OwnCredentials_var krb_creds;
      if (!kerberos.empty ())
        {
          try
            {
              CORBA::Object_var cobj = orb->resolve_initial_references ("SecurityLevel3:CredentialsCurator");
              SecurityLevel3::CredentialsCurator_var curator = SecurityLevel3::CredentialsCurator::_narrow (cobj.in ());
              SSLIOP::KerberosAuthData data;
              for (std::string const &kv : split_on (kerberos, ','))
                {
                  size_t const eq = kv.find ('=');
                  std::string const key = kv.substr (0, eq);
                  std::string const value = eq == std::string::npos ? std::string () : kv.substr (eq + 1);
                  if (key == "ccache")
                    data.ccache = value.c_str ();
                  else if (key == "keytab")
                    data.keytab = value.c_str ();
                  else if (key == "principal")
                    data.principal = value.c_str ();
                  else if (key == "target")
                    data.target_name = value.c_str ();
                }
              CORBA::Any args;
              args <<= data;
              SecurityLevel3::CredentialsAcquirer_var acquirer = curator->acquire_credentials ("SL3Kerberos", args);
              krb_creds = acquirer->get_credentials (!in_policy);
              ACE_OS::printf ("ACQUIRE OK\n");
            }
          catch (CORBA::Exception const &ex)
            {
              ACE_OS::printf ("ACQUIRE FAILED %s\n", ex._name ());
              orb->destroy ();
              return 0;
            }
        }
      if (bypass || in_policy)
        {
          SecurityLevel3::ContextEstablishmentPolicyArgument arg;
          arg.creds_directive = SecurityLevel3::CD_Default;
          arg.creds_list.length (0);
          if (in_policy)
            for (SecurityLevel3::OwnCredentials_ptr c : {creds.in (), krb_creds.in ()})
              if (!CORBA::is_nil (c))
                {
                  CORBA::ULong const n = arg.creds_list.length ();
                  arg.creds_list.length (n + 1);
                  arg.creds_list[n] = SecurityLevel3::OwnCredentials::_duplicate (c);
                }
          arg.use_client_auth = bypass ? SecurityLevel3::FD_DoNotUse : SecurityLevel3::FD_Use;
          arg.use_target_auth = SecurityLevel3::FD_Use;
          arg.use_confidentiality = SecurityLevel3::FD_Use;
          arg.use_integrity = SecurityLevel3::FD_Use;
          CORBA::Any any;
          any <<= arg;
          CORBA::PolicyList policies (1);
          policies.length (1);
          policies[0] = orb->create_policy (SecurityLevel3::ContextEstablishmentPolicyType, any);
          obj = obj->_set_policy_overrides (policies, CORBA::ADD_OVERRIDE);
          policies[0]->destroy ();
        }
      Who_var who = Who::_unchecked_narrow (obj.in ());
      try
        {
          if (ACE_OS::strcmp (what, "poke") == 0)
            {
              who->poke ();
              ACE_OS::printf ("POKE OK\n");
            }
          else if (ACE_OS::strcmp (what, "relay") == 0)
            {
              CORBA::String_var s = who->relay (relay_ior);
              ACE_OS::printf ("%s\n", s.in ());
            }
          else if (ACE_OS::strcmp (what, "shutdown") == 0)
            {
              who->shutdown ();
              ACE_OS::printf ("SHUTDOWN SENT\n");
            }
          else
            {
              CORBA::String_var s = who->whoami ();
              ACE_OS::printf ("WHOAMI %s\n", s.in ());
            }
        }
      catch (CORBA::Exception const &ex)
        {
          ACE_OS::printf ("%s EXCEPTION %s\n", what, ex._name ());
        }
      orb->destroy ();
    }
  catch (CORBA::Exception const &ex)
    {
      ex._tao_print_exception ("client");
      return 1;
    }
  return 0;
}
