#include "orbsvcs/SSLIOP/SSLIOP_SAS.h"

#include "orbsvcs/Security/Audit_Logger.h"
#include "orbsvcs/Security/CSI_Utils.h"
#include "orbsvcs/Security/GSSUP_Verifier.h"
#include "tao/CDR.h"
#include "ace/Message_Block.h"
#include "tao/Security_Mode.h"

#include "ace/OS_NS_string.h"

#include <openssl/crypto.h>

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

  /// The username scoped to the target: "alice" -> "alice@lab.example".
  std::string
  scoped (std::string const &user, std::string const &target)
  {
    if (user.find ('@') != std::string::npos || target.empty ())
      return user;
    return user + (target[0] == '@' ? target : "@" + target);
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
    if (major != 0)
      rec.field ("context_error", std::to_string (major));
    rec.text (why);
    TAO::Security::Audit_Logger::instance ()->write (rec);

    throw CORBA::NO_PERMISSION (CORBA::OMGVMCID | 1, CORBA::COMPLETED_NO);
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
    return r;
  } ();
  return c;
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

SAS_Target::Result
SAS_Target::process (PortableInterceptor::ServerRequestInfo_ptr ri,
                     TAO::Security::Caller &caller,
                     bool tls,
                     char const *operation)
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
      if (c.csiv2 == 2 || c.gssup == 2)
        refuse (ri, caller, operation, 0, 0, Reason::SAS_MISSING,
                c.gssup == 2 ? "no SAS context; GSSUP client authentication is required"
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

  if (ec.identity_token._d () != CSI::ITTAbsent)
    refuse (ri, caller, operation, id, 2, Reason::SAS_INVALID_MECH, "identity assertion is not supported");

  if (ec.client_authentication_token.length () > 0)
    {
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

      TAO::Security::GSSUP_Verifier *const v = TAO::Security::GSSUP_Verifier::installed ();
      std::string detail;
      bool const ok = v != nullptr && v->verify (user, password, c.target, detail);
      wipe (password);
      if (!ok)
        refuse (ri, caller, operation, id, 1, Reason::GSSUP_FAILED,
                v == nullptr ? "no GSSUP verifier is installed" : (detail.empty () ? "rejected" : detail.c_str ()),
                user, true);
      caller.authenticated = scoped (user, c.target);
    }
  else if (c.gssup == 2)
    {
      refuse (ri, caller, operation, id, 2, Reason::SAS_INVALID_MECH, "GSSUP client authentication is required");
    }

  CSI::CompleteEstablishContext done;
  done.client_context_id = id;
  done.context_stateful = false;   // R12: stateless
  done.final_context_token.length (0);
  CSI::SASContextBody reply;
  reply.complete_msg (done);
  add_reply (ri, reply);

  if (c.audit_grants)
    TAO::Security::Audit_Logger::instance ()->write (
      TAO::Security::Audit_Record ("authn", true, Reason::SAS_ACCEPTED)
        .field ("principal", caller.effective ())
        .field ("transport_principal", caller.transport ())
        .field ("src", caller.source)
        .field ("op", operation == nullptr ? "" : operation));
  return ACCEPTED;
}

TAO_END_VERSIONED_NAMESPACE_DECL
