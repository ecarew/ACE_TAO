#include "orbsvcs/SSLIOP/SSLIOP_SAS.h"
#include "orbsvcs/SSLIOP/SSLIOP_Asserter_List.h"
#include "orbsvcs/SSLIOP/SSLIOP_Deny_List.h"
#include "orbsvcs/SSLIOP/SSLIOP_Kerberos.h"

#include "orbsvcs/Security/Audit_Logger.h"
#include "orbsvcs/Security/CSI_Utils.h"
#include "orbsvcs/Security/GSSUP_Verifier.h"
#include "tao/CDR.h"
#include "ace/Message_Block.h"
#include "tao/Security_Mode.h"

#include "ace/OS_NS_string.h"
#include "ace/OS_NS_time.h"

#include "ace/SSL/SSL_Context.h"

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <memory>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  namespace Reason = TAO::Security::Audit_Reason;
  using TAO::SSLIOP::SAS_Target;

  int
  level_of (std::string const &v)
  {
    return v == "required" ? 2 : v == "supported" ? 1 : 0;
  }

  template <typename SEQ>
  std::string
  octets (SEQ const &s)
  {
    return std::string (reinterpret_cast<char const *> (s.get_buffer ()), s.length ());
  }

  template <typename SEQ>
  void
  set_octets (SEQ &seq, std::string const &v)
  {
    seq.length (static_cast<CORBA::ULong> (v.size ()));
    if (!v.empty ())
      ACE_OS::memcpy (seq.get_buffer (), v.data (), v.size ());
  }

  /// A CDR encapsulation of @a value.
  template <typename T>
  bool
  encapsulate (T const &value, std::string &out)
  {
    TAO_OutputCDR cdr;
    if (!(cdr << TAO_OutputCDR::from_boolean (TAO_ENCAP_BYTE_ORDER)) || !(cdr << value))
      return false;
    out.clear ();
    for (ACE_Message_Block const *mb = cdr.begin (); mb != nullptr; mb = mb->cont ())
      out.append (mb->rd_ptr (), mb->length ());
    return true;
  }

  /**
   * Reads the length after the 0x60 tag at @a p: DER (short form, or
   * 0x8N and N octets) when that accounts for exactly the rest of the
   * token, else JacORB's base-128 form (7 bits an octet, high bit = more).
   */
  bool
  read_length (unsigned char const *data, size_t size, size_t &p, size_t &length)
  {
    if (p >= size)
      return false;
    if (data[p] < 0x80)
      {
        length = data[p++];
        return p + length == size;
      }
    // DER long form.
    size_t const n = data[p] & 0x7F;
    if (n >= 1 && n <= 4 && p + 1 + n <= size)
      {
        size_t l = 0;
        for (size_t i = 0; i < n; ++i)
          l = (l << 8) | data[p + 1 + i];
        if (p + 1 + n + l == size)
          {
            p += 1 + n;
            length = l;
            return true;
          }
      }
    // JacORB's base-128 form.
    size_t l = 0;
    size_t q = p;
    for (int i = 0; i < 5 && q < size; ++i)
      {
        unsigned char const b = data[q++];
        l = (l << 7) | (b & 0x7F);
        if ((b & 0x80) == 0)
          {
            if (q + l != size)
              return false;
            p = q;
            length = l;
            return true;
          }
      }
    return false;
  }

  void
  wipe (std::string &s)
  {
    if (!s.empty ())
      ::OPENSSL_cleanse (&s[0], s.size ());
    s.clear ();
  }

  template <typename SEQ>
  void
  wipe_seq (SEQ &seq)
  {
    if (seq.length () > 0)
      ::OPENSSL_cleanse (seq.get_buffer (), seq.length ());
  }

  void
  add_reply (PortableInterceptor::ServerRequestInfo_ptr ri, CSI::SASContextBody const &body)
  {
    IOP::ServiceContext sc;
    TAO::CSI_Utils::create_sas_service_context (body, sc);
    ri->add_reply_service_context (sc, true);
  }

  /// Answers ContextError, audits and throws NO_PERMISSION.
  [[noreturn]] void
  refuse (PortableInterceptor::ServerRequestInfo_ptr ri,
          TAO::Security::Caller const &caller,
          char const *operation,
          CSI::ContextId id,
          CORBA::Long major,
          char const *reason,
          char const *why,
          std::string const &user = std::string (),
          bool gssup_error = false)
  {
    if (major != 0)
      {
        CSI::ContextError err;
        err.client_context_id = id;
        err.major_status = major;
        err.minor_status = 1;
        if (gssup_error)
          {
            // Never say which part was wrong (R20): always UNSPECIFIED.
            GSSUP::ErrorToken token;
            token.error_code = GSSUP::GSS_UP_S_G_UNSPECIFIED;
            std::string enc;
            if (encapsulate (token, enc))
              set_octets (err.error_token, enc);
          }
        CSI::SASContextBody body;
        body.error_msg (err);
        try
          {
            add_reply (ri, body);
          }
        catch (CORBA::Exception const &)
          {
          }
      }

    TAO::Security::Audit_Record rec ("authn", false, reason);
    rec.field ("principal", caller.transport ())
      .field ("src", caller.source)
      .field ("op", operation == nullptr ? "" : operation);
    if (!user.empty ())
      rec.field ("user", user);
    if (!caller.asserter.empty ())
      rec.field ("asserter", caller.asserter);
    if (!caller.asserted.empty ())
      rec.field ("asserted", caller.asserted);
    if (major != 0)
      rec.field ("context_error", std::to_string (major));
    rec.text (why);
    TAO::Security::Audit_Logger::instance ()->write (rec);

    throw CORBA::NO_PERMISSION (CORBA::OMGVMCID | 1, CORBA::COMPLETED_NO);
  }

  std::string
  rfc2253 (X509_NAME *name)
  {
    std::string out;
    BIO *const b = ::BIO_new (::BIO_s_mem ());
    if (b == nullptr)
      return out;
    if (::X509_NAME_print_ex (b, name, 0, XN_FLAG_RFC2253) >= 0)
      {
        char *data = nullptr;
        long const n = ::BIO_get_mem_data (b, &data);
        if (n > 0 && data != nullptr)
          out.assign (data, static_cast<size_t> (n));
      }
    ::BIO_free (b);
    return out;
  }

  /// A printable name (no blanks or control characters), 1 to 256 bytes.
  bool
  printable (std::string const &s)
  {
    if (s.empty () || s.size () > 256)
      return false;
    for (char const ch : s)
      {
        unsigned char const u = static_cast<unsigned char> (ch);
        if (u < 0x21 || u > 0x7e)
          return false;
      }
    return true;
  }

  struct Free_X509 { void operator() (X509 *x) const { ::X509_free (x); } };
  struct Free_Stack { void operator() (STACK_OF (X509) *s) const { sk_X509_pop_free (s, ::X509_free); } };
  struct Free_Store_Ctx { void operator() (X509_STORE_CTX *c) const { ::X509_STORE_CTX_free (c); } };

  /**
   * Decodes an asserted certificate chain (DER SEQUENCE OF Certificate,
   * the subject's certificate first), verifies it as a client chain
   * against the service's trust store and the deny-list, and names it.
   */
  bool
  asserted_chain (std::string const &der, std::string &name, std::string &why)
  {
    unsigned char const *p = reinterpret_cast<unsigned char const *> (der.data ());
    long len = 0;
    int tag = 0, xclass = 0;
    int const r = ::ASN1_get_object (&p, &len, &tag, &xclass, static_cast<long> (der.size ()));
    if ((r & 0x80) != 0 || tag != V_ASN1_SEQUENCE
        || p + len != reinterpret_cast<unsigned char const *> (der.data ()) + der.size ())
      {
        why = "the certificate chain is not a DER SEQUENCE";
        return false;
      }
    unsigned char const *const end = p + len;
    std::unique_ptr<X509, Free_X509> leaf;
    std::unique_ptr<STACK_OF (X509), Free_Stack> rest (sk_X509_new_null ());
    while (p < end)
      {
        X509 *const x = ::d2i_X509 (nullptr, &p, static_cast<long> (end - p));
        if (x == nullptr)
          {
            why = "undecodable certificate in the chain";
            return false;
          }
        if (!leaf)
          leaf.reset (x);
        else
          sk_X509_push (rest.get (), x);
      }
    if (!leaf)
      {
        why = "empty certificate chain";
        return false;
      }
    X509_STORE *const store = ::SSL_CTX_get_cert_store (ACE_SSL_Context::instance ()->context ());
    std::unique_ptr<X509_STORE_CTX, Free_Store_Ctx> ctx (::X509_STORE_CTX_new ());
    if (store == nullptr || !ctx || ::X509_STORE_CTX_init (ctx.get (), store, leaf.get (), rest.get ()) != 1)
      {
        why = "no trust store to verify the chain";
        return false;
      }
    ::X509_STORE_CTX_set_purpose (ctx.get (), X509_PURPOSE_SSL_CLIENT);
    if (::X509_verify_cert (ctx.get ()) != 1)
      {
        why = std::string ("the certificate chain does not verify: ")
              + ::X509_verify_cert_error_string (::X509_STORE_CTX_get_error (ctx.get ()));
        return false;
      }
    std::string const denied = TAO::SSLIOP::Deny_List::instance ()->check (leaf.get ());
    if (!denied.empty ())
      {
        why = "the asserted certificate is on the deny-list (" + denied + ")";
        return false;
      }
    std::set<std::string> const ids = TAO::SSLIOP::Deny_List::spiffe_ids_of (leaf.get ());
    name = !ids.empty () ? *ids.begin () : rfc2253 (::X509_get_subject_name (leaf.get ()));
    if (name.empty ())
      {
        why = "the asserted certificate has no SPIFFE ID or subject";
        return false;
      }
    return true;
  }

  /// Accepts the identity token from a listed asserter (R22-R24), or
  /// refuses the request.
  void
  assert_identity (PortableInterceptor::ServerRequestInfo_ptr ri,
                   TAO::Security::Caller &caller,
                   char const *operation,
                   CSI::ContextId id,
                   CSI::IdentityToken const &token,
                   SAS_Target::Config const &c)
  {
    // CSIv2 rule 4 (CORBA 3.3 Part 2, Table 10.4): with
    // allow_anonymous_assertion = on an anonymous assertion is accepted
    // whoever makes it, authenticated or not.
    if (token._d () == CSI::ITTAnonymous && c.anonymous == 2)
      {
        caller.asserter = !caller.authenticated.empty () ? caller.authenticated : caller.transport ();
        caller.asserted = "anonymous";
        return;
      }

    if (!c.assertion)
      refuse (ri, caller, operation, id, 2, Reason::SAS_INVALID_MECH,
              "identity assertion is not supported here (no csiv2_asserters)");

    // Who is asserting: its GSSUP login, else its certificate's SPIFFE
    // IDs and subject (CSIv2 backward trust, rule 2).
    std::vector<std::string> candidates;
    candidates.push_back (caller.authenticated);
    for (std::string const &sid : caller.spiffe_ids)
      candidates.push_back (sid);
    candidates.push_back (caller.subject);
    TAO::SSLIOP::Asserter_List::Entry entry;
    if (!TAO::SSLIOP::Asserter_List::instance ()->find (candidates, entry))
      {
        std::string const who = caller.authenticated.empty () ? caller.transport () : caller.authenticated;
        refuse (ri, caller, operation, id, 1, Reason::ASSERTION_REJECTED,
                ("asserter " + who + " is not on the asserter list").c_str ());
      }
    caller.asserter = entry.principal;

    unsigned long const type = static_cast<unsigned long> (token._d ());
    std::string const type_name = TAO::SSLIOP::Asserter_List::type_names (type);
    if (type != CSI::ITTAnonymous && type != CSI::ITTPrincipalName && type != CSI::ITTDistinguishedName
        && type != CSI::ITTX509CertChain)
      refuse (ri, caller, operation, id, 2, Reason::SAS_INVALID_MECH,
              ("identity token type " + std::to_string (type) + " is not supported").c_str ());
    if ((entry.types & type) == 0)
      refuse (ri, caller, operation, id, 1, Reason::ASSERTION_REJECTED,
              ("the asserter may not assert identity type " + type_name).c_str ());

    std::string asserted;
    std::string why;
    switch (type)
      {
      case CSI::ITTAnonymous:
        if (c.anonymous == 0)
          refuse (ri, caller, operation, id, 1, Reason::ASSERTION_REJECTED,
                  "anonymous assertion is off (allow_anonymous_assertion)");
        asserted = "anonymous";
        break;

      case CSI::ITTPrincipalName:
        {
          std::string const o = octets (token.principal_name ());
          // R32 (Phase 3 K5): an exported name of the Kerberos mechanism,
          // where Kerberos is on, under the same limits as a GSSUP name:
          // a well-formed principal in a realm the asserter may assert
          // ("@REALM" in its realms=, or "*"; by default the service
          // principal's own realm).
          std::string krb_name;
          if (TAO::SSLIOP::Kerberos::parse_exported_name (o, krb_name))
            {
              if (c.kerberos == 0)
                refuse (ri, caller, operation, id, 1, Reason::ASSERTION_REJECTED,
                        "Kerberos names are not accepted here (csiv2_kerberos = off)");
              std::string const realm = TAO::SSLIOP::Kerberos::realm_of (krb_name);
              if (!printable (krb_name) || realm.empty () || krb_name.size () <= realm.size () + 1)
                refuse (ri, caller, operation, id, 1, Reason::ASSERTION_REJECTED,
                        "the asserted name is not a well-formed Kerberos principal (name@REALM)");
              std::string const scope = "@" + realm;
              std::string const own = "@" + TAO::SSLIOP::Kerberos::realm_of (c.krb_principal);
              bool const realm_ok = entry.realms.count ("*") != 0 || entry.realms.count (scope) != 0
                                    || (entry.realms.empty () && scope == own);
              if (!realm_ok)
                {
                  caller.asserted = krb_name;
                  refuse (ri, caller, operation, id, 1, Reason::ASSERTION_REJECTED,
                          ("the asserter may not assert names in realm " + realm).c_str ());
                }
              caller.asserted = krb_name;
              caller.asserted_mech = "krb5";
              return;
            }

          // An exported name of the GSSUP mechanism: 04 01, the OID, the name.
          std::string const oid = SAS_Target::gssup_mech_der ();
          std::string name;
          bool ok = o.size () >= 8 + oid.size () && o[0] == '\x04' && o[1] == '\x01'
                    && static_cast<size_t> ((static_cast<unsigned char> (o[2]) << 8) | static_cast<unsigned char> (o[3])) == oid.size ()
                    && o.compare (4, oid.size (), oid) == 0;
          if (ok)
            ok = SAS_Target::parse_exported_name (o, name) && printable (name);
          if (!ok)
            refuse (ri, caller, operation, id, 1, Reason::ASSERTION_REJECTED,
                    "the asserted name is not a well-formed GSSUP or Kerberos exported name");
          std::string value;
          std::string realm;
          if (!SAS_Target::split_scoped (name, value, realm))
            refuse (ri, caller, operation, id, 1, Reason::ASSERTION_REJECTED,
                    "the asserted name is not a well-formed scoped-username");
          if (value.empty ())
            refuse (ri, caller, operation, id, 1, Reason::ASSERTION_REJECTED, "the asserted name has no user");
          if (realm.empty ())
            {
              if (c.target.empty ())
                refuse (ri, caller, operation, id, 1, Reason::ASSERTION_REJECTED,
                        "an unscoped name needs gssup_target");
              realm = c.target;
            }
          name = SAS_Target::quote_scoped (value) + realm;
          bool const realm_ok = entry.realms.count ("*") != 0 || entry.realms.count (realm) != 0
                                || (entry.realms.empty () && realm == c.target);
          if (!realm_ok)
            {
              caller.asserted = name;
              refuse (ri, caller, operation, id, 1, Reason::ASSERTION_REJECTED,
                      ("the asserter may not assert names in realm " + realm).c_str ());
            }
          asserted = name;
          caller.asserted_mech = "gssup";
        }
        break;

      case CSI::ITTDistinguishedName:
        {
          std::string const der = octets (token.dn ());
          unsigned char const *p = reinterpret_cast<unsigned char const *> (der.data ());
          X509_NAME *const n = ::d2i_X509_NAME (nullptr, &p, static_cast<long> (der.size ()));
          if (n != nullptr && p == reinterpret_cast<unsigned char const *> (der.data ()) + der.size ())
            asserted = rfc2253 (n);
          if (n != nullptr)
            ::X509_NAME_free (n);
          if (asserted.empty ())
            refuse (ri, caller, operation, id, 1, Reason::ASSERTION_REJECTED,
                    "the asserted distinguished name is not a DER Name");
        }
        break;

      default:   // CSI::ITTX509CertChain
        if (!asserted_chain (octets (token.certificate_chain ()), asserted, why))
          refuse (ri, caller, operation, id, 1, Reason::ASSERTION_REJECTED, why.c_str ());
        break;
      }
    caller.asserted = asserted;
  }
}

SAS_Target::Config const &
SAS_Target::config ()
{
  static Config const c = [] {
    Config r;
    TAO_Security_Mode::Host_Config const &h = TAO_Security_Mode::host ();
    bool const prod = h.mode == TAO_Security_Mode::MODE_PROD;
    r.csiv2 = level_of (h.get ("csiv2", prod ? "supported" : "off"));
    r.gssup = level_of (h.get ("csiv2_gssup", "off"));
    if (r.csiv2 == 0)
      r.gssup = 0;
    r.target = h.get ("gssup_target");
    if (!r.target.empty () && r.target[0] != '@')
      r.target = "@" + r.target;
    r.audit_grants = h.get ("audit_grants") == "on";
    r.assertion = r.csiv2 != 0 && !h.get ("csiv2_asserters").empty ();
    std::string const anon = h.get ("allow_anonymous_assertion");
    r.anonymous = r.csiv2 == 0 ? 0 : anon == "on" ? 2 : anon == "listed" ? 1 : 0;
    r.assert_caller = h.get ("csiv2_assert_caller") == "on";
    r.kerberos = r.csiv2 == 0 ? 0 : level_of (h.get ("csiv2_kerberos", "off"));
    r.krb_principal = h.get ("krb_principal");
    r.krb_keytab = h.get ("krb_keytab");
    r.krb_rcache = h.get ("krb_rcache");
    r.krb_binding = level_of (h.get ("krb_channel_binding", "required"));
    // A value the self-check refuses gives no limit here; prod does not
    // start with it.
    long const age = TAO::SSLIOP::Kerberos::parse_duration (h.get ("krb_max_ticket_age"), 30L * 86400);
    r.krb_max_age = age > 0 ? age : 0;
    return r;
  } ();
  return c;
}

bool
SAS_Target::split_scoped (std::string const &name, std::string &value, std::string &scope)
{
  value.clear ();
  scope.clear ();
  bool in_scope = false;
  for (size_t i = 0; i < name.size (); ++i)
    {
      char ch = name[i];
      if (ch == '\\')
        {
          if (i + 1 >= name.size () || (name[i + 1] != '@' && name[i + 1] != '\\'))
            return false;
          ch = name[++i];
        }
      else if (ch == '@')
        {
          if (in_scope)
            return false;
          in_scope = true;
          scope = "@";
          continue;
        }
      (in_scope ? scope : value) += ch;
    }
  // "name", "name@scope" or "@scope": no empty scope after an '@', and
  // not an empty name on its own.
  if (in_scope ? scope.size () < 2 : value.empty ())
    return false;
  return true;
}

std::string
SAS_Target::quote_scoped (std::string const &part)
{
  std::string out;
  for (char const ch : part)
    {
      if (ch == '@' || ch == '\\')
        out += '\\';
      out += ch;
    }
  return out;
}

std::string
SAS_Target::gssup_mech_der ()
{
  // 2.23.130.1.1.1: 2*40+23 = 0x67, 130 = 0x81 0x02, 1, 1, 1.
  static unsigned char const der[] = {0x06, 0x06, 0x67, 0x81, 0x02, 0x01, 0x01, 0x01};
  return std::string (reinterpret_cast<char const *> (der), sizeof der);
}

std::string
SAS_Target::exported_name (std::string const &name)
{
  std::string const oid = gssup_mech_der ();
  std::string out ("\x04\x01", 2);
  out += static_cast<char> ((oid.size () >> 8) & 0xFF);
  out += static_cast<char> (oid.size () & 0xFF);
  out += oid;
  for (int shift = 24; shift >= 0; shift -= 8)
    out += static_cast<char> ((name.size () >> shift) & 0xFF);
  out += name;
  return out;
}

bool
SAS_Target::parse_exported_name (std::string const &o, std::string &name)
{
  if (o.size () < 8 || o[0] != '\x04' || o[1] != '\x01')
    return false;
  size_t const oid_len = (static_cast<unsigned char> (o[2]) << 8) | static_cast<unsigned char> (o[3]);
  size_t p = 4 + oid_len;
  if (p + 4 > o.size ())
    return false;
  size_t len = 0;
  for (int i = 0; i < 4; ++i)
    len = (len << 8) | static_cast<unsigned char> (o[p + i]);
  p += 4;
  if (p + len != o.size ())
    return false;
  name = o.substr (p, len);
  return true;
}

bool
SAS_Target::encode_gssup_token (std::string const &user,
                                std::string const &password,
                                std::string const &target_name_octets,
                                CSI::GSSToken &out)
{
  GSSUP::InitialContextToken ict;
  set_octets (ict.username, user);
  set_octets (ict.password, password);
  set_octets (ict.target_name, target_name_octets);
  std::string body;
  bool const ok = encapsulate (ict, body);
  wipe_seq (ict.password);
  if (!ok)
    return false;
  std::string const inner = gssup_mech_der () + body;
  wipe (body);

  // DER length.
  std::string token (1, '\x60');
  size_t const n = inner.size ();
  if (n < 0x80)
    token += static_cast<char> (n);
  else if (n <= 0xFF)
    {
      token += '\x81';
      token += static_cast<char> (n);
    }
  else
    {
      token += '\x82';
      token += static_cast<char> ((n >> 8) & 0xFF);
      token += static_cast<char> (n & 0xFF);
    }
  token += inner;
  set_octets (out, token);
  wipe (token);
  return true;
}

SAS_Target::Decode
SAS_Target::decode_gssup_token (CSI::GSSToken const &token, GSSUP::InitialContextToken &out)
{
  unsigned char const *const d = token.get_buffer ();
  size_t const size = token.length ();
  size_t p = 0;
  if (size < 2 || d[p++] != 0x60)
    return MALFORMED;
  size_t length = 0;
  if (!read_length (d, size, p, length))
    return MALFORMED;
  std::string const oid = gssup_mech_der ();
  if (size - p < 2 || d[p] != 0x06)
    return MALFORMED;
  size_t const oid_size = 2u + d[p + 1];
  if (p + oid_size > size)
    return MALFORMED;
  if (oid_size != oid.size () || ACE_OS::memcmp (d + p, oid.data (), oid.size ()) != 0)
    return NOT_GSSUP;
  p += oid_size;

  // The encapsulation starts at an odd offset inside the token; CDR
  // alignment is reckoned from the buffer's address, so decode it from an
  // aligned copy (wiped afterwards: it holds the password).
  size_t const body = size - p;
  ACE_Message_Block mb (body + ACE_CDR::MAX_ALIGNMENT);
  ACE_CDR::mb_align (&mb);
  ACE_OS::memcpy (mb.wr_ptr (), d + p, body);
  mb.wr_ptr (body);
  Decode result = MALFORMED;
  {
    TAO_InputCDR cdr (&mb);
    CORBA::Boolean byte_order;
    if (cdr >> ACE_InputCDR::to_boolean (byte_order))
      {
        cdr.reset_byte_order (static_cast<int> (byte_order));
        if (cdr >> out)
          result = DECODED;
      }
  }
  ::OPENSSL_cleanse (mb.base (), mb.size ());
  return result;
}

std::string
SAS_Target::token_mech (std::string const &token)
{
  unsigned char const *const d = reinterpret_cast<unsigned char const *> (token.data ());
  size_t const size = token.size ();
  size_t p = 0;
  size_t length = 0;
  if (size < 2 || d[p++] != 0x60 || !read_length (d, size, p, length))
    return std::string ();
  if (size - p < 2 || d[p] != 0x06 || p + 2u + d[p + 1] > size)
    return std::string ();
  return token.substr (p, 2u + d[p + 1]);
}

SAS_Target::Result
SAS_Target::process (PortableInterceptor::ServerRequestInfo_ptr ri,
                     TAO::Security::Caller &caller,
                     bool tls,
                     char const *operation,
                     ssl_st *ssl)
{
  Config const &c = config ();
  if (c.csiv2 == 0)
    return NONE;

  IOP::ServiceContext_var sc;
  try
    {
      sc = ri->get_request_service_context (IOP::SecurityAttributeService);
    }
  catch (CORBA::BAD_PARAM const &)
    {
    }

  if (sc.ptr () == nullptr)
    {
      // accept_transport_context: no SAS message.
      if (c.csiv2 == 2 || c.gssup == 2 || c.kerberos == 2)
        refuse (ri, caller, operation, 0, 0, Reason::SAS_MISSING,
                c.gssup == 2      ? "no SAS context; GSSUP client authentication is required"
                : c.kerberos == 2 ? "no SAS context; Kerberos client authentication is required"
                                  : "no SAS context; csiv2 = required");
      return NONE;
    }

  if (!tls)
    refuse (ri, caller, operation, 0, 1, Reason::SAS_NO_TLS, "SAS context on a connection without TLS");

  CSI::SASContextBody body;
  if (!TAO::CSI_Utils::extract_sas_service_context (sc.in (), body))
    refuse (ri, caller, operation, 0, 1, Reason::SAS_INVALID_EVIDENCE, "undecodable SAS context");

  switch (body._d ())
    {
    case CSI::MTEstablishContext:
      break;
    case CSI::MTMessageInContext:
      // A stateless target keeps no contexts (R12).
      refuse (ri, caller, operation, body.in_context_msg ().client_context_id, 4, Reason::SAS_NO_CONTEXT,
              "MessageInContext: no context is kept (stateless)");
    default:
      refuse (ri, caller, operation, 0, 1, Reason::SAS_INVALID_EVIDENCE, "unexpected SAS message type");
    }

  CSI::EstablishContext &ec = body.establish_msg ();
  CSI::ContextId const id = ec.client_context_id;

  if (ec.authorization_token.length () > 0)
    {
      TAO::Security::Audit_Logger::instance ()->write (
        TAO::Security::Audit_Record ("authn", true, Reason::SAS_AUTHZ_TOKEN_IGNORED)
          .field ("principal", caller.transport ())
          .field ("src", caller.source)
          .field ("elements", std::to_string (ec.authorization_token.length ()))
          .text ("authorization token ignored (no Level 1 support)"));
    }

  std::string final_token;
  char const *mech_name = "";
  TAO::SSLIOP::Kerberos::Pac_Info pac;
  std::string const auth_mech =
    ec.client_authentication_token.length () > 0 ? token_mech (octets (ec.client_authentication_token)) : std::string ();

  if (ec.client_authentication_token.length () > 0 && auth_mech == TAO::SSLIOP::Kerberos::mech_der ())
    {
      // Kerberos V5 (R27, R28).
      if (c.kerberos == 0)
        refuse (ri, caller, operation, id, 2, Reason::SAS_INVALID_MECH, "Kerberos client authentication is not offered");
      if (c.gssup == 2)
        refuse (ri, caller, operation, id, 2, Reason::SAS_INVALID_MECH, "GSSUP client authentication is required");
      std::string const token = octets (ec.client_authentication_token);
      std::string const binding =
        ssl != nullptr ? TAO::SSLIOP::Kerberos::tls_server_end_point (::SSL_get_certificate (ssl)) : std::string ();
      std::string client;
      std::string reply;
      std::string why;
      long long auth_time = 0;
      TAO::SSLIOP::Kerberos::Accept_Status const st = TAO::SSLIOP::Kerberos::accept (
        token, binding, c.krb_principal, c.krb_keytab, c.krb_rcache, c.krb_binding == 2, client, reply, why, &pac,
        &auth_time);
      if (st != TAO::SSLIOP::Kerberos::ACCEPTED)
        refuse (ri, caller, operation, id, 1, Reason::KRB_FAILED, why.c_str ());
      // krb_max_ticket_age: the user's KDC login (the ticket's authtime,
      // kept through renewals) must be recent, so a fresh login brings
      // the account's current groups from AD in a new PAC.
      if (c.krb_max_age > 0)
        {
          long long const age = static_cast<long long> (ACE_OS::time (nullptr)) - auth_time;
          if (auth_time <= 0 || age > c.krb_max_age)
            {
              refuse (ri, caller, operation, id, 1, Reason::KRB_LOGIN_TOO_OLD,
                      (auth_time <= 0 ? std::string ("the ticket's login time is unknown")
                                      : "the ticket's login is " + std::to_string (age) + " s old")
                        .append (", over krb_max_ticket_age (" + std::to_string (c.krb_max_age)
                                 + " s): log in to the KDC again").c_str (),
                      client);
            }
        }
      caller.authenticated = client;
      caller.authenticated_mech = "krb5";
      caller.auth_time = auth_time;
      // R30: AD groups from the ticket's PAC, trusted only once it
      // verified with the ticket; no directory is asked.
      if (pac.verified)
        {
          caller.user_sid = pac.user_sid;
          if (!pac.groups.empty ())
            {
              caller.groups = pac.groups;
              caller.groups_authority = TAO::SSLIOP::Kerberos::realm_of (client);
            }
        }
      final_token = reply;
      mech_name = "krb5";
    }
  else if (ec.client_authentication_token.length () > 0)
    {
      if (c.kerberos == 2)
        refuse (ri, caller, operation, id, 2, Reason::SAS_INVALID_MECH, "Kerberos client authentication is required");
      if (c.gssup == 0)
        refuse (ri, caller, operation, id, 2, Reason::SAS_INVALID_MECH, "client authentication is not offered");

      GSSUP::InitialContextToken ict;
      Decode const d = decode_gssup_token (ec.client_authentication_token, ict);
      if (d != DECODED)
        wipe_seq (ec.client_authentication_token);
      if (d == NOT_GSSUP)
        refuse (ri, caller, operation, id, 2, Reason::SAS_INVALID_MECH, "client authentication token is not GSSUP");
      if (d == MALFORMED)
        refuse (ri, caller, operation, id, 1, Reason::SAS_INVALID_EVIDENCE, "malformed GSSUP token",
                std::string (), true);

      // Copy the fields out first: the decoded sequences may share the
      // token's buffer, so the token is wiped only afterwards.
      std::string const user = octets (ict.username);
      std::string password = octets (ict.password);
      std::string const raw_target = octets (ict.target_name);
      wipe_seq (ict.password);
      wipe_seq (ec.client_authentication_token);
      std::string target;
      if (!parse_exported_name (raw_target, target))
        target = raw_target;

      if (c.target.empty () || target != c.target)
        {
          wipe (password);
          refuse (ri, caller, operation, id, 1, Reason::GSSUP_FAILED,
                  c.target.empty () ? "gssup_target is not configured" : "GSSUP target name does not match",
                  user, true);
        }

      // The username is a scoped-username (10.2.4.1.1): "alice", or
      // "alice@lab.test" scoped by this service's own target name.
      std::string name;
      std::string scope;
      bool const well_formed = split_scoped (user, name, scope) && !name.empty ();
      if (!well_formed || (!scope.empty () && scope != c.target))
        {
          wipe (password);
          refuse (ri, caller, operation, id, 1, Reason::GSSUP_FAILED,
                  well_formed ? "the username's scope is not this service's GSSUP target name"
                              : "the username is not a well-formed scoped-username",
                  user, true);
        }

      using Verifier = TAO::Security::GSSUP_Verifier;
      Verifier *const v = Verifier::installed ();
      std::string detail;
      Verifier::Result const r =
        v == nullptr ? Verifier::UNAVAILABLE : v->verify (name, password, c.target, caller.source, detail);
      wipe (password);
      if (r != Verifier::ACCEPTED)
        {
          // One answer on the wire whatever the reason (R13, R19).
          char const *const reason = r == Verifier::LOCKED         ? Reason::GSSUP_LOCKED
                                     : r == Verifier::RATE_LIMITED ? Reason::GSSUP_RATE_LIMITED
                                                                   : Reason::GSSUP_FAILED;
          if (v == nullptr)
            detail = "no GSSUP verifier is installed";
          refuse (ri, caller, operation, id, 1, reason, detail.empty () ? "rejected" : detail.c_str (), user, true);
        }
      caller.authenticated = quote_scoped (name) + c.target;
      caller.authenticated_mech = "gssup";
      caller.auth_time = static_cast<long long> (ACE_OS::time (nullptr));
      // Store groups for the role map's group:NAME lines (Phase 3 T3).
      caller.login_groups = v->groups (name);
      mech_name = "gssup";
    }
  else if (c.gssup == 2)
    {
      refuse (ri, caller, operation, id, 2, Reason::SAS_INVALID_MECH, "GSSUP client authentication is required");
    }
  else if (c.kerberos == 2)
    {
      refuse (ri, caller, operation, id, 2, Reason::SAS_INVALID_MECH, "Kerberos client authentication is required");
    }

  // Identity assertion, once the asserter's own identity is known (its
  // certificate, and its GSSUP login if it sent one).
  if (ec.identity_token._d () != CSI::ITTAbsent)
    assert_identity (ri, caller, operation, id, ec.identity_token, c);

  CSI::CompleteEstablishContext done;
  done.client_context_id = id;
  done.context_stateful = false;   // R12: stateless
  set_octets (done.final_context_token, final_token);
  CSI::SASContextBody reply;
  reply.complete_msg (done);
  add_reply (ri, reply);

  if (c.audit_grants)
    {
      TAO::Security::Audit_Record rec ("authn", true, Reason::SAS_ACCEPTED);
      rec.field ("principal", caller.effective ())
        .field ("transport_principal", caller.transport ())
        .field ("asserter", caller.asserter)
        .field ("src", caller.source)
        .field ("op", operation == nullptr ? "" : operation)
        .field ("mech", mech_name);
      if (!caller.login_groups.empty ())
        {
          std::string list;
          for (std::string const &g : caller.login_groups)
            list += (list.empty () ? "" : ",") + g;
          rec.field ("login_groups", list);
        }
      if (pac.present)
        {
          // Ticket groups (K4): the first 64, then how many more.
          std::string list;
          size_t const shown = pac.groups.size () < 64 ? pac.groups.size () : 64;
          for (size_t i = 0; i < shown; ++i)
            list += (i == 0 ? "" : ",") + pac.groups[i];
          if (pac.groups.size () > shown)
            list += ",+" + std::to_string (pac.groups.size () - shown) + " more";
          rec.field ("user_sid", pac.user_sid).field ("groups", list);
          if (!pac.note.empty ())
            rec.text (pac.note.c_str ());
        }
      TAO::Security::Audit_Logger::instance ()->write (rec);
    }
  return ACCEPTED;
}

TAO_END_VERSIONED_NAMESPACE_DECL
