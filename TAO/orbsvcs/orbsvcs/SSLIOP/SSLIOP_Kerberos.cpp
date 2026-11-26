#include "orbsvcs/SSLIOP/SSLIOP_Kerberos.h"

#include "ace/Guard_T.h"
#include "ace/Thread_Mutex.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_sys_stat.h"
#include "ace/OS_NS_unistd.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include <set>

#if defined (TAO_HAS_GSSAPI)
# include <gssapi/gssapi.h>
# include <gssapi/gssapi_ext.h>
# include <gssapi/gssapi_krb5.h>
# include <krb5.h>
#endif /* TAO_HAS_GSSAPI */

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  // 1.2.840.113554.1.2.2, without the DER tag and length.
  char const krb5_oid_body[] = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
  size_t const krb5_oid_length = sizeof krb5_oid_body - 1;

#if defined (TAO_HAS_GSSAPI)
  /// Appends gss_display_status text for one status code of @a type.
  void
  append_status (std::string &out, OM_uint32 code, int type)
  {
    OM_uint32 context = 0;
    do
      {
        OM_uint32 minor = 0;
        gss_buffer_desc text = GSS_C_EMPTY_BUFFER;
        OM_uint32 const major =
          ::gss_display_status (&minor, code, type, GSS_C_NO_OID, &context, &text);
        if (GSS_ERROR (major))
          break;
        if (!out.empty ())
          out += "; ";
        out.append (static_cast<char const *> (text.value), text.length);
        ::gss_release_buffer (&minor, &text);
      }
    while (context != 0);
  }

  gss_OID_desc krb5_oid_desc = { static_cast<OM_uint32> (krb5_oid_length),
                                 const_cast<char *> (krb5_oid_body) };

  /// A Kerberos principal name, imported.
  gss_name_t
  import_principal (std::string const &principal, std::string &why)
  {
    OM_uint32 minor = 0;
    gss_buffer_desc b = { principal.size (), const_cast<char *> (principal.data ()) };
    gss_name_t name = GSS_C_NO_NAME;
    OM_uint32 const major = ::gss_import_name (&minor, &b, GSS_KRB5_NT_PRINCIPAL_NAME, &name);
    if (GSS_ERROR (major))
      {
        why = "bad Kerberos principal " + principal + ": " + TAO::SSLIOP::Kerberos::status_text (major, minor);
        return GSS_C_NO_NAME;
      }
    return name;
  }

  /// Channel bindings carrying only application data (no addresses).
  struct Bindings
  {
    explicit Bindings (std::string const &data)
    {
      cb.initiator_addrtype = GSS_C_AF_NULLADDR;
      cb.initiator_address.length = 0;
      cb.initiator_address.value = nullptr;
      cb.acceptor_addrtype = GSS_C_AF_NULLADDR;
      cb.acceptor_address.length = 0;
      cb.acceptor_address.value = nullptr;
      cb.application_data.length = data.size ();
      cb.application_data.value = const_cast<char *> (data.data ());
      use = !data.empty ();
    }
    gss_channel_bindings_t get () { return use ? &cb : GSS_C_NO_CHANNEL_BINDINGS; }
    gss_channel_bindings_struct cb;
    bool use;
  };

  /// The acceptor credential, acquired once from the keytab.  The MIT
  /// library reads the keytab at each accept, so a rotated key is seen.
  ACE_Thread_Mutex cred_lock;
  gss_cred_id_t acceptor_cred = GSS_C_NO_CREDENTIAL;
  std::string acceptor_key;

  gss_cred_id_t
  acceptor (std::string const &principal, std::string const &keytab, std::string const &rcache, std::string &why)
  {
    ACE_GUARD_RETURN (ACE_Thread_Mutex, guard, cred_lock, GSS_C_NO_CREDENTIAL);
    std::string const key = principal + '\n' + keytab + '\n' + rcache;
    if (acceptor_cred != GSS_C_NO_CREDENTIAL && key == acceptor_key)
      return acceptor_cred;

    gss_name_t name = import_principal (principal, why);
    if (name == GSS_C_NO_NAME)
      return GSS_C_NO_CREDENTIAL;
    gss_key_value_element_desc elements[2];
    elements[0].key = "keytab";
    elements[0].value = keytab.c_str ();
    OM_uint32 count = 1;
    if (!rcache.empty ())
      {
        elements[1].key = "rcache";
        elements[1].value = rcache.c_str ();
        count = 2;
      }
    gss_key_value_set_desc store = { count, elements };
    gss_OID_set_desc mechs = { 1, &krb5_oid_desc };
    OM_uint32 minor = 0;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    OM_uint32 const major =
      ::gss_acquire_cred_from (&minor, name, GSS_C_INDEFINITE, &mechs, GSS_C_ACCEPT, &store, &cred, nullptr, nullptr);
    ::gss_release_name (&minor, &name);
    if (GSS_ERROR (major))
      {
        why = "no Kerberos acceptor credential for " + principal + " in " + keytab + ": "
              + TAO::SSLIOP::Kerberos::status_text (major, minor);
        return GSS_C_NO_CREDENTIAL;
      }
    if (acceptor_cred != GSS_C_NO_CREDENTIAL)
      ::gss_release_cred (&minor, &acceptor_cred);
    acceptor_cred = cred;
    acceptor_key = key;
    return cred;
  }
#endif /* TAO_HAS_GSSAPI */
}

bool
TAO::SSLIOP::Kerberos::built ()
{
#if defined (TAO_HAS_GSSAPI)
  return true;
#else
  return false;
#endif /* TAO_HAS_GSSAPI */
}

std::string
TAO::SSLIOP::Kerberos::mech_der ()
{
  std::string der ("\x06", 1);
  der += static_cast<char> (krb5_oid_length);
  der.append (krb5_oid_body, krb5_oid_length);
  return der;
}

bool
TAO::SSLIOP::Kerberos::mechanism_offered (std::string &detail)
{
#if defined (TAO_HAS_GSSAPI)
  OM_uint32 minor = 0;
  gss_OID_set mechs = GSS_C_NO_OID_SET;
  OM_uint32 const major = ::gss_indicate_mechs (&minor, &mechs);
  if (GSS_ERROR (major))
    {
      detail = "gss_indicate_mechs failed: " + status_text (major, minor);
      return false;
    }
  bool found = false;
  for (size_t i = 0; mechs != GSS_C_NO_OID_SET && i < mechs->count && !found; ++i)
    {
      gss_OID const m = &mechs->elements[i];
      found = m->length == krb5_oid_length && std::string (static_cast<char const *> (m->elements), m->length)
                                                == std::string (krb5_oid_body, krb5_oid_length);
    }
  ::gss_release_oid_set (&minor, &mechs);
  detail = found ? "Kerberos V5 mechanism offered" : "the GSS-API library does not offer Kerberos V5";
  return found;
#else
  detail = "SSLIOP was built without GSS-API (MPC feature gssapi)";
  return false;
#endif /* TAO_HAS_GSSAPI */
}

std::string
TAO::SSLIOP::Kerberos::status_text (unsigned long major, unsigned long minor)
{
#if defined (TAO_HAS_GSSAPI)
  std::string out;
  append_status (out, static_cast<OM_uint32> (major), GSS_C_GSS_CODE);
  if (minor != 0)
    append_status (out, static_cast<OM_uint32> (minor), GSS_C_MECH_CODE);
  return out.empty () ? "GSS status " + std::to_string (major) : out;
#else
  ACE_UNUSED_ARG (major);
  ACE_UNUSED_ARG (minor);
  return "GSS-API not built";
#endif /* TAO_HAS_GSSAPI */
}

std::string
TAO::SSLIOP::Kerberos::exported_name (std::string const &principal)
{
  std::string const oid = mech_der ();
  std::string out ("\x04\x01", 2);
  out += static_cast<char> ((oid.size () >> 8) & 0xFF);
  out += static_cast<char> (oid.size () & 0xFF);
  out += oid;
  for (int shift = 24; shift >= 0; shift -= 8)
    out += static_cast<char> ((principal.size () >> shift) & 0xFF);
  out += principal;
  return out;
}

std::string
TAO::SSLIOP::Kerberos::tls_server_end_point (x509_st *cert)
{
  if (cert == nullptr)
    return std::string ();
  // RFC 5929 4.1: SHA-256 when the certificate is signed with MD5 or
  // SHA-1 (or SHA-256), else the hash of its own signature algorithm.
  EVP_MD const *md = ::EVP_sha256 ();
  int mdnid = NID_undef;
  if (::X509_get_signature_info (cert, &mdnid, nullptr, nullptr, nullptr) == 1)
    {
      if (mdnid == NID_sha384)
        md = ::EVP_sha384 ();
      else if (mdnid == NID_sha512)
        md = ::EVP_sha512 ();
    }
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int length = 0;
  if (::X509_digest (cert, md, digest, &length) != 1)
    return std::string ();
  std::string out ("tls-server-end-point:");
  out.append (reinterpret_cast<char const *> (digest), length);
  return out;
}

bool
TAO::SSLIOP::Kerberos::check_keytab (std::string const &path,
                                     std::string const &principal,
                                     bool prod,
                                     std::string &summary,
                                     std::string &error)
{
  ACE_stat st;
  if (path.empty () || ACE_OS::stat (path.c_str (), &st) != 0)
    {
      error = "cannot read keytab " + path;
      return false;
    }
  if ((st.st_mode & S_IFMT) != S_IFREG)
    {
      error = path + " is not a regular file";
      return false;
    }
#if !defined (ACE_WIN32)
  if (prod)
    {
      unsigned const mode = static_cast<unsigned> (st.st_mode & 0777);
      if (mode != 0600 && mode != 0400)
        {
          char m[8];
          ACE_OS::snprintf (m, sizeof m, "%04o", mode);
          error = path + " is mode " + m + " (want 0600 or 0400)";
          return false;
        }
      if (st.st_uid != ACE_OS::geteuid ())
        {
          error = path + " is not owned by the service account";
          return false;
        }
    }
#else
  ACE_UNUSED_ARG (prod);
#endif

#if defined (TAO_HAS_GSSAPI)
  krb5_context ctx = nullptr;
  if (::krb5_init_context (&ctx) != 0)
    {
      error = "cannot initialise the Kerberos library";
      return false;
    }
  krb5_keytab kt = nullptr;
  std::string const name = "FILE:" + path;
  krb5_error_code rc = ::krb5_kt_resolve (ctx, name.c_str (), &kt);
  krb5_kt_cursor cursor;
  if (rc == 0)
    rc = ::krb5_kt_start_seq_get (ctx, kt, &cursor);
  if (rc != 0)
    {
      char const *msg = ::krb5_get_error_message (ctx, rc);
      error = "cannot read keytab " + path + ": " + msg;
      ::krb5_free_error_message (ctx, msg);
      if (kt != nullptr)
        ::krb5_kt_close (ctx, kt);
      ::krb5_free_context (ctx);
      return false;
    }
  std::set<unsigned> kvnos;
  std::set<std::string> types;
  std::set<std::string> weak;
  krb5_keytab_entry entry;
  while (::krb5_kt_next_entry (ctx, kt, &entry, &cursor) == 0)
    {
      char *p = nullptr;
      if (::krb5_unparse_name (ctx, entry.principal, &p) == 0)
        {
          if (principal == p)
            {
              char type[64] = "";
              ::krb5_enctype_to_name (entry.key.enctype, TRUE, type, sizeof type);
              kvnos.insert (static_cast<unsigned> (entry.vno));
              switch (entry.key.enctype)
                {
                case ENCTYPE_DES_CBC_CRC:
                case ENCTYPE_DES_CBC_MD4:
                case ENCTYPE_DES_CBC_MD5:
                case ENCTYPE_DES3_CBC_SHA1:
                case ENCTYPE_ARCFOUR_HMAC:
                case ENCTYPE_ARCFOUR_HMAC_EXP:
                  weak.insert (type);
                  break;
                default:
                  types.insert (type);
                }
            }
          ::krb5_free_unparsed_name (ctx, p);
        }
      ::krb5_free_keytab_entry_contents (ctx, &entry);
    }
  ::krb5_kt_end_seq_get (ctx, kt, &cursor);
  ::krb5_kt_close (ctx, kt);
  ::krb5_free_context (ctx);

  auto join = [] (std::set<std::string> const &s) {
    std::string out;
    for (std::string const &x : s)
      out += (out.empty () ? "" : ",") + x;
    return out;
  };
  if (!weak.empty ())
    {
      error = path + " holds weak keys (" + join (weak) + ") for " + principal;
      return false;
    }
  if (kvnos.empty ())
    {
      error = path + " holds no keys for " + principal;
      return false;
    }
  std::string vs;
  for (unsigned v : kvnos)
    vs += (vs.empty () ? "" : ",") + std::to_string (v);
  summary = principal + " key version(s) " + vs + " (" + join (types) + ")";
  return true;
#else
  ACE_UNUSED_ARG (principal);
  ACE_UNUSED_ARG (summary);
  error = "SSLIOP was built without GSS-API (MPC feature gssapi)";
  return false;
#endif /* TAO_HAS_GSSAPI */
}

TAO::SSLIOP::Kerberos::Accept_Status
TAO::SSLIOP::Kerberos::accept (std::string const &token,
                               std::string const &binding,
                               std::string const &principal,
                               std::string const &keytab,
                               std::string const &rcache,
                               bool require_binding,
                               std::string &client,
                               std::string &reply,
                               std::string &why)
{
#if defined (TAO_HAS_GSSAPI)
  gss_cred_id_t const cred = acceptor (principal, keytab, rcache, why);
  if (cred == GSS_C_NO_CREDENTIAL)
    return UNAVAILABLE;

  OM_uint32 minor = 0;
  gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
  gss_buffer_desc in = { token.size (), const_cast<char *> (token.data ()) };
  gss_name_t src = GSS_C_NO_NAME;
  gss_OID mech = GSS_C_NO_OID;
  gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
  OM_uint32 flags = 0;
  Bindings cb (binding);
  OM_uint32 const major =
    ::gss_accept_sec_context (&minor, &ctx, cred, &in, cb.get (), &src, &mech, &out, &flags, nullptr, nullptr);

  Accept_Status result = REFUSED;
  if (major == GSS_S_COMPLETE)
    {
      gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
      OM_uint32 m2 = 0;
      if (mech == GSS_C_NO_OID || mech->length != krb5_oid_length
          || std::string (static_cast<char const *> (mech->elements), mech->length)
               != std::string (krb5_oid_body, krb5_oid_length))
        why = "the token is not Kerberos V5";
      else if (require_binding && (flags & GSS_C_CHANNEL_BOUND_FLAG) == 0)
        why = "the token is not bound to this TLS session (krb_channel_binding = required)";
      else if (GSS_ERROR (::gss_display_name (&m2, src, &name, nullptr)))
        why = "cannot read the client principal";
      else
        {
          client.assign (static_cast<char const *> (name.value), name.length);
          reply.assign (static_cast<char const *> (out.value), out.length);
          why = (flags & GSS_C_CHANNEL_BOUND_FLAG) != 0 ? "bound to the TLS session" : "not channel bound";
          result = ACCEPTED;
          ::gss_release_buffer (&m2, &name);
        }
    }
  else if (major == GSS_S_CONTINUE_NEEDED)
    why = "the token needs more than one step; a stateless target accepts single-step Kerberos only";
  else if (GSS_ROUTINE_ERROR (major) == GSS_S_BAD_BINDINGS)
    why = "the token is bound to another TLS session (channel bindings differ)";
  else
    {
      // MIT reports a replay as a failure whose Kerberos text names it.
      why = status_text (major, minor);
      if ((GSS_SUPPLEMENTARY_INFO (major) & GSS_S_DUPLICATE_TOKEN) != 0 || why.find ("replay") != std::string::npos)
        why = "replayed token: " + why;
    }

  OM_uint32 m3 = 0;
  if (src != GSS_C_NO_NAME)
    ::gss_release_name (&m3, &src);
  if (out.length > 0)
    {
      ::OPENSSL_cleanse (out.value, out.length);
      ::gss_release_buffer (&m3, &out);
    }
  if (ctx != GSS_C_NO_CONTEXT)
    ::gss_delete_sec_context (&m3, &ctx, GSS_C_NO_BUFFER);
  return result;
#else
  ACE_UNUSED_ARG (token);
  ACE_UNUSED_ARG (binding);
  ACE_UNUSED_ARG (principal);
  ACE_UNUSED_ARG (keytab);
  ACE_UNUSED_ARG (rcache);
  ACE_UNUSED_ARG (require_binding);
  ACE_UNUSED_ARG (client);
  ACE_UNUSED_ARG (reply);
  why = "SSLIOP was built without GSS-API (MPC feature gssapi)";
  return UNAVAILABLE;
#endif /* TAO_HAS_GSSAPI */
}

bool
TAO::SSLIOP::Kerberos::initiate (std::string const &principal,
                                 std::string const &binding,
                                 std::string &token,
                                 std::string &why)
{
#if defined (TAO_HAS_GSSAPI)
  gss_name_t target = import_principal (principal, why);
  if (target == GSS_C_NO_NAME)
    return false;
  OM_uint32 minor = 0;
  gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
  gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
  Bindings cb (binding);
  OM_uint32 const major = ::gss_init_sec_context (&minor, GSS_C_NO_CREDENTIAL, &ctx, target, &krb5_oid_desc,
                                                  GSS_C_MUTUAL_FLAG, 0, cb.get (), GSS_C_NO_BUFFER, nullptr,
                                                  &out, nullptr, nullptr);
  bool const ok = !GSS_ERROR (major) && out.length > 0;
  if (ok)
    token.assign (static_cast<char const *> (out.value), out.length);
  else
    why = "cannot make a Kerberos token for " + principal + ": " + status_text (major, minor);
  OM_uint32 m2 = 0;
  ::gss_release_name (&m2, &target);
  if (out.length > 0)
    ::gss_release_buffer (&m2, &out);
  if (ctx != GSS_C_NO_CONTEXT)
    ::gss_delete_sec_context (&m2, &ctx, GSS_C_NO_BUFFER);
  return ok;
#else
  ACE_UNUSED_ARG (principal);
  ACE_UNUSED_ARG (binding);
  ACE_UNUSED_ARG (token);
  why = "SSLIOP was built without GSS-API (MPC feature gssapi)";
  return false;
#endif /* TAO_HAS_GSSAPI */
}

std::string
TAO::SSLIOP::Kerberos::realm_of (std::string const &principal)
{
  // The realm follows the last '@' that is not quoted by '\'.
  size_t at = std::string::npos;
  for (size_t i = 0; i < principal.size (); ++i)
    {
      if (principal[i] == '\\')
        ++i;
      else if (principal[i] == '@')
        at = i;
    }
  return at == std::string::npos ? std::string () : principal.substr (at + 1);
}

bool
TAO::SSLIOP::Kerberos::parse_exported_name (std::string const &o, std::string &principal)
{
  std::string const oid = mech_der ();
  if (o.size () < 4 + oid.size () + 4 || o[0] != '\x04' || o[1] != '\x01')
    return false;
  size_t const oid_len = (static_cast<unsigned char> (o[2]) << 8) | static_cast<unsigned char> (o[3]);
  if (oid_len != oid.size () || o.compare (4, oid_len, oid) != 0)
    return false;
  size_t p = 4 + oid_len;
  size_t len = 0;
  for (int i = 0; i < 4; ++i)
    len = (len << 8) | static_cast<unsigned char> (o[p + i]);
  p += 4;
  if (len == 0 || p + len != o.size ())
    return false;
  principal = o.substr (p, len);
  return true;
}

#if defined (TAO_HAS_GSSAPI)
namespace
{
  /// Initiator credentials from @a source.  A keytab without a named
  /// cache gets a private in-memory one, one per client principal and
  /// keytab in this process, so the TGT obtained with the keytab is
  /// reused but never lands in the user's own cache.
  gss_cred_id_t
  initiator_cred (TAO::SSLIOP::Kerberos::Client_Source const &source, OM_uint32 *lifetime, std::string &why)
  {
    if (!source.keytab.empty () && source.principal.empty ())
      {
        why = "a client keytab needs the client principal";
        return GSS_C_NO_CREDENTIAL;
      }
    gss_name_t name = GSS_C_NO_NAME;
    if (!source.principal.empty ())
      {
        name = import_principal (source.principal, why);
        if (name == GSS_C_NO_NAME)
          return GSS_C_NO_CREDENTIAL;
      }
    std::string ccache = source.ccache;
    if (ccache.empty () && !source.keytab.empty ())
      {
        unsigned long h = 5381;
        for (char ch : source.principal + '\n' + source.keytab)
          h = h * 33 + static_cast<unsigned char> (ch);
        ccache = "MEMORY:ace_tao_" + std::to_string (static_cast<unsigned long> (ACE_OS::getpid ())) + "_"
                 + std::to_string (h);
      }
    gss_key_value_element_desc elements[2];
    OM_uint32 count = 0;
    if (!ccache.empty ())
      {
        elements[count].key = "ccache";
        elements[count].value = ccache.c_str ();
        ++count;
      }
    if (!source.keytab.empty ())
      {
        elements[count].key = "client_keytab";
        elements[count].value = source.keytab.c_str ();
        ++count;
      }
    gss_key_value_set_desc store = { count, elements };
    gss_OID_set_desc mechs = { 1, &krb5_oid_desc };
    OM_uint32 minor = 0;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    OM_uint32 const major = ::gss_acquire_cred_from (&minor, name, GSS_C_INDEFINITE, &mechs, GSS_C_INITIATE,
                                                     count > 0 ? &store : GSS_C_NO_CRED_STORE, &cred, nullptr,
                                                     lifetime);
    OM_uint32 m2 = 0;
    if (name != GSS_C_NO_NAME)
      ::gss_release_name (&m2, &name);
    if (GSS_ERROR (major))
      {
        std::string const from = !source.keytab.empty () ? "client keytab " + source.keytab
                                 : !ccache.empty ()       ? "ticket cache " + ccache
                                                          : std::string ("the default ticket cache");
        why = "no Kerberos credentials in " + from + ": " + TAO::SSLIOP::Kerberos::status_text (major, minor);
        return GSS_C_NO_CREDENTIAL;
      }
    return cred;
  }
}
#endif /* TAO_HAS_GSSAPI */

bool
TAO::SSLIOP::Kerberos::check_client (Client_Source const &source,
                                     std::string &client,
                                     long &lifetime,
                                     std::string &why)
{
#if defined (TAO_HAS_GSSAPI)
  gss_cred_id_t cred = initiator_cred (source, nullptr, why);
  if (cred == GSS_C_NO_CREDENTIAL)
    return false;
  OM_uint32 minor = 0;
  gss_name_t name = GSS_C_NO_NAME;
  OM_uint32 left = 0;
  OM_uint32 major = ::gss_inquire_cred (&minor, cred, &name, &left, nullptr, nullptr);
  bool ok = false;
  if (GSS_ERROR (major))
    why = "cannot read the Kerberos credentials: " + status_text (major, minor);
  else if (left == 0 && source.keytab.empty ())
    why = "the Kerberos ticket has expired (kinit)";
  else
    {
      gss_buffer_desc text = GSS_C_EMPTY_BUFFER;
      major = ::gss_display_name (&minor, name, &text, nullptr);
      if (GSS_ERROR (major))
        why = "cannot read the client principal: " + status_text (major, minor);
      else
        {
          client.assign (static_cast<char const *> (text.value), text.length);
          ::gss_release_buffer (&minor, &text);
          lifetime = left == GSS_C_INDEFINITE ? -1L : static_cast<long> (left);
          ok = true;
        }
    }
  if (name != GSS_C_NO_NAME)
    ::gss_release_name (&minor, &name);
  ::gss_release_cred (&minor, &cred);
  return ok;
#else
  ACE_UNUSED_ARG (source);
  ACE_UNUSED_ARG (client);
  ACE_UNUSED_ARG (lifetime);
  why = "SSLIOP was built without GSS-API (MPC feature gssapi)";
  return false;
#endif /* TAO_HAS_GSSAPI */
}

struct TAO::SSLIOP::Kerberos::Initiator::Impl
{
#if defined (TAO_HAS_GSSAPI)
  gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
  gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
  gss_name_t target = GSS_C_NO_NAME;
#endif /* TAO_HAS_GSSAPI */
  std::string binding;
  std::string target_text;
  bool waiting = false;

  ~Impl ()
  {
#if defined (TAO_HAS_GSSAPI)
    OM_uint32 minor = 0;
    if (ctx != GSS_C_NO_CONTEXT)
      ::gss_delete_sec_context (&minor, &ctx, GSS_C_NO_BUFFER);
    if (target != GSS_C_NO_NAME)
      ::gss_release_name (&minor, &target);
    if (cred != GSS_C_NO_CREDENTIAL)
      ::gss_release_cred (&minor, &cred);
#endif /* TAO_HAS_GSSAPI */
  }
};

TAO::SSLIOP::Kerberos::Initiator::Initiator ()
  : impl_ (new Impl)
{
}

TAO::SSLIOP::Kerberos::Initiator::~Initiator ()
{
  delete this->impl_;
}

bool
TAO::SSLIOP::Kerberos::Initiator::start (Client_Source const &source,
                                         std::string const &target,
                                         std::string const &binding,
                                         std::string &token,
                                         std::string &why)
{
#if defined (TAO_HAS_GSSAPI)
  Impl &i = *this->impl_;
  if (i.waiting || i.ctx != GSS_C_NO_CONTEXT)
    {
      why = "this login has already started";
      return false;
    }
  i.cred = initiator_cred (source, nullptr, why);
  if (i.cred == GSS_C_NO_CREDENTIAL)
    return false;
  i.target = import_principal (target, why);
  if (i.target == GSS_C_NO_NAME)
    return false;
  i.binding = binding;
  i.target_text = target;

  OM_uint32 minor = 0;
  gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
  Bindings cb (i.binding);
  OM_uint32 const major = ::gss_init_sec_context (&minor, i.cred, &i.ctx, i.target, &krb5_oid_desc,
                                                  GSS_C_MUTUAL_FLAG, 0, cb.get (), GSS_C_NO_BUFFER, nullptr,
                                                  &out, nullptr, nullptr);
  bool ok = false;
  if (major == GSS_S_CONTINUE_NEEDED && out.length > 0)
    {
      token.assign (static_cast<char const *> (out.value), out.length);
      i.waiting = true;
      ok = true;
    }
  else if (GSS_ERROR (major))
    why = "cannot make a Kerberos token for " + target + ": " + status_text (major, minor);
  else
    why = "the Kerberos library did not ask for mutual authentication";
  OM_uint32 m2 = 0;
  if (out.length > 0)
    ::gss_release_buffer (&m2, &out);
  return ok;
#else
  ACE_UNUSED_ARG (source);
  ACE_UNUSED_ARG (target);
  ACE_UNUSED_ARG (binding);
  ACE_UNUSED_ARG (token);
  why = "SSLIOP was built without GSS-API (MPC feature gssapi)";
  return false;
#endif /* TAO_HAS_GSSAPI */
}

bool
TAO::SSLIOP::Kerberos::Initiator::finish (std::string const &reply, std::string &why)
{
#if defined (TAO_HAS_GSSAPI)
  Impl &i = *this->impl_;
  if (!i.waiting)
    {
      why = "no Kerberos login is waiting for a reply";
      return false;
    }
  i.waiting = false;
  if (reply.empty ())
    {
      why = "the target returned no Kerberos reply token, so it did not prove it is " + i.target_text;
      return false;
    }
  OM_uint32 minor = 0;
  gss_buffer_desc in = { reply.size (), const_cast<char *> (reply.data ()) };
  gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
  OM_uint32 flags = 0;
  Bindings cb (i.binding);
  OM_uint32 const major = ::gss_init_sec_context (&minor, i.cred, &i.ctx, i.target, &krb5_oid_desc,
                                                  GSS_C_MUTUAL_FLAG, 0, cb.get (), &in, nullptr, &out, &flags,
                                                  nullptr);
  bool ok = false;
  if (major == GSS_S_COMPLETE && (flags & GSS_C_MUTUAL_FLAG) != 0)
    ok = true;
  else if (major == GSS_S_COMPLETE)
    why = "the Kerberos reply did not complete mutual authentication";
  else if (major == GSS_S_CONTINUE_NEEDED)
    why = "the Kerberos reply asks for another step; a stateless target sends one reply only";
  else
    why = "the Kerberos reply does not verify as " + i.target_text + ": " + status_text (major, minor);
  OM_uint32 m2 = 0;
  if (out.length > 0)
    ::gss_release_buffer (&m2, &out);
  return ok;
#else
  ACE_UNUSED_ARG (reply);
  why = "SSLIOP was built without GSS-API (MPC feature gssapi)";
  return false;
#endif /* TAO_HAS_GSSAPI */
}

TAO_END_VERSIONED_NAMESPACE_DECL
