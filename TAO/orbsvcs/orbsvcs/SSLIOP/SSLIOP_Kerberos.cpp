#include "orbsvcs/SSLIOP/SSLIOP_Kerberos.h"

#include "orbsvcs/Security/Audit_Logger.h"

#include "ace/Guard_T.h"
#include "tao/orbconf.h"
#include "tao/Security_Mode.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_stat.h"
#include "ace/OS_NS_unistd.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include <cstdint>
#include <memory>
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

  /// The keytab file checks of R31 that need no Kerberos library: a
  /// regular file and, in @a prod, mode 0600 or 0400 owned by the
  /// effective user.  @a st gets its status.
  bool
  keytab_file_ok (std::string const &path, bool prod, ACE_stat &st, std::string &error)
  {
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
    // Whole, not cut short (a keytab written in place while it is read):
    // the MIT format is 0x05 0x01|0x02, then records each led by a 4-byte
    // length (negative for a deleted record's hole) that must end exactly
    // at the end of the file.  The library stops quietly at a truncated
    // record, so a half-written file would otherwise pass with fewer keys.
    FILE *const fp = ACE_OS::fopen (path.c_str (), ACE_TEXT ("rb"));
    if (fp == nullptr)
      {
        error = "cannot read keytab " + path;
        return false;
      }
    std::string bytes;
    char buf[4096];
    size_t n = 0;
    while ((n = ACE_OS::fread (buf, 1, sizeof buf, fp)) > 0)
      bytes.append (buf, n);
    ACE_OS::fclose (fp);
    if (bytes.size () < 2 || bytes[0] != '\x05' || (bytes[1] != '\x01' && bytes[1] != '\x02'))
      {
        error = path + " is not a keytab (no MIT keytab header)";
        return false;
      }
    // Version 2 is big-endian; version 1 is in the writer's byte order.
    std::uint16_t const probe = 1;
    bool const big_endian = bytes[1] == '\x02' || *reinterpret_cast<unsigned char const *> (&probe) == 0;
    for (size_t at = 2; at < bytes.size (); )
      {
        if (bytes.size () - at < 4)
          {
            error = path + " is cut short (a record length runs past its end)";
            return false;
          }
        unsigned char const *b = reinterpret_cast<unsigned char const *> (bytes.data () + at);
        std::uint32_t const raw = big_endian
          ? (std::uint32_t (b[0]) << 24) | (std::uint32_t (b[1]) << 16) | (std::uint32_t (b[2]) << 8) | b[3]
          : (std::uint32_t (b[3]) << 24) | (std::uint32_t (b[2]) << 16) | (std::uint32_t (b[1]) << 8) | b[0];
        std::int64_t const length = static_cast<std::int32_t> (raw);
        std::uint64_t const span = length < 0 ? static_cast<std::uint64_t> (-length) : static_cast<std::uint64_t> (length);
        at += 4;
        if (span > bytes.size () - at)
          {
            error = path + " is cut short (its last record runs past the end of the file)";
            return false;
          }
        at += static_cast<size_t> (span);
      }
    ACE_OS::memset (&bytes[0], 0, bytes.size ());
    return true;
  }

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

  /**
   * Reads the keys of @a principal from the keytab file @a path, refusing
   * DES and RC4 (R31) and a keytab without keys for it.  With @a dest the
   * keys are also added to that keytab.  @a summary lists the key
   * versions and encryption types, @a versions counts the versions.
   */
  bool
  read_keytab_keys (krb5_context ctx, std::string const &path, std::string const &principal, krb5_keytab dest,
                    std::string &summary, std::string &error, size_t *versions)
  {
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
        return false;
      }
    std::set<unsigned> kvnos;
    std::set<std::string> types;
    std::set<std::string> weak;
    std::string add_error;
    krb5_keytab_entry entry;
    krb5_error_code next = 0;
    while ((next = ::krb5_kt_next_entry (ctx, kt, &entry, &cursor)) == 0)
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
                    if (dest != nullptr && add_error.empty ())
                      {
                        krb5_error_code const arc = ::krb5_kt_add_entry (ctx, dest, &entry);
                        if (arc != 0)
                          {
                            char const *msg = ::krb5_get_error_message (ctx, arc);
                            add_error = std::string ("cannot hold the keys in memory: ") + msg;
                            ::krb5_free_error_message (ctx, msg);
                          }
                      }
                  }
              }
            ::krb5_free_unparsed_name (ctx, p);
          }
        ::krb5_free_keytab_entry_contents (ctx, &entry);
      }
    ::krb5_kt_end_seq_get (ctx, kt, &cursor);
    ::krb5_kt_close (ctx, kt);

    auto join = [] (std::set<std::string> const &set) {
      std::string out;
      for (std::string const &x : set)
        out += (out.empty () ? "" : ",") + x;
      return out;
    };
    // A file cut short (written in place while it was read) ends in a
    // read error rather than at its end.
    if (next != KRB5_KT_END)
      {
        char const *msg = ::krb5_get_error_message (ctx, next);
        error = "cannot read keytab " + path + " to its end: " + msg;
        ::krb5_free_error_message (ctx, msg);
        return false;
      }
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
    if (!add_error.empty ())
      {
        error = add_error;
        return false;
      }
    std::string vs;
    for (unsigned v : kvnos)
      vs += (vs.empty () ? "" : ",") + std::to_string (v);
    summary = principal + " key version(s) " + vs + " (" + join (types) + ")";
    if (versions != nullptr)
      *versions = kvnos.size ();
    return true;
  }

  /// What identifies one state of the keytab file.  A file renamed over
  /// it, rewritten or re-permissioned changes it.
  struct File_State
  {
    unsigned long long dev = 0, ino = 0, size = 0, mode = 0, uid = 0;
    long long mtime = 0;
    bool present = false;

    explicit File_State (ACE_stat const *st = nullptr)
    {
      if (st == nullptr)
        return;
      present = true;
      dev = static_cast<unsigned long long> (st->st_dev);
      ino = static_cast<unsigned long long> (st->st_ino);
      size = static_cast<unsigned long long> (st->st_size);
      mode = static_cast<unsigned long long> (st->st_mode);
      uid = static_cast<unsigned long long> (st->st_uid);
      mtime = static_cast<long long> (st->st_mtime);
    }
    bool operator== (File_State const &o) const
    {
      return present == o.present && dev == o.dev && ino == o.ino && size == o.size && mode == o.mode
             && uid == o.uid && mtime == o.mtime;
    }
    bool operator!= (File_State const &o) const { return !(*this == o); }
  };

  File_State
  file_state (std::string const &path)
  {
    ACE_stat st;
    return ACE_OS::stat (path.c_str (), &st) == 0 ? File_State (&st) : File_State ();
  }

  /// The service's keys, held in a MEMORY keytab of their own, and the
  /// acceptor credential made on them (the credential holds the keytab
  /// open; the keytab goes when the credential is released).
  struct Acceptor_Keys
  {
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    std::string summary;
    ~Acceptor_Keys ()
    {
      OM_uint32 minor = 0;
      if (cred != GSS_C_NO_CREDENTIAL)
        ::gss_release_cred (&minor, &cred);
    }
  };

  /// Checks the keytab file and loads the keys of @a principal into
  /// memory, with an acceptor credential on them; null with @a why.
  std::shared_ptr<Acceptor_Keys>
  load_keys (std::string const &principal, std::string const &path, std::string const &rcache, bool prod,
             std::string &why)
  {
    static unsigned long generation = 0;
    ACE_stat st;
    if (!keytab_file_ok (path, prod, st, why))
      return nullptr;
    krb5_context ctx = nullptr;
    if (::krb5_init_context (&ctx) != 0)
      {
        why = "cannot initialise the Kerberos library";
        return nullptr;
      }
    std::string const mem = "MEMORY:tao-acceptor-" + std::to_string (static_cast<long> (ACE_OS::getpid ())) + "-"
                            + std::to_string (++generation);
    krb5_keytab dest = nullptr;
    std::shared_ptr<Acceptor_Keys> keys;
    if (::krb5_kt_resolve (ctx, mem.c_str (), &dest) != 0)
      why = "cannot make an in-memory keytab";
    else
      {
        std::string summary;
        if (read_keytab_keys (ctx, path, principal, dest, summary, why, nullptr))
          {
            gss_name_t name = import_principal (principal, why);
            if (name != GSS_C_NO_NAME)
              {
                gss_key_value_element_desc elements[2];
                elements[0].key = "keytab";
                elements[0].value = mem.c_str ();
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
                OM_uint32 const major = ::gss_acquire_cred_from (&minor, name, GSS_C_INDEFINITE, &mechs,
                                                                 GSS_C_ACCEPT, &store, &cred, nullptr, nullptr);
                ::gss_release_name (&minor, &name);
                if (GSS_ERROR (major))
                  why = "no Kerberos acceptor credential for " + principal + " in " + path + ": "
                        + TAO::SSLIOP::Kerberos::status_text (major, minor);
                else
                  {
                    keys = std::make_shared<Acceptor_Keys> ();
                    keys->cred = cred;
                    keys->summary = summary;
                  }
              }
          }
        ::krb5_kt_close (ctx, dest);
      }
    ::krb5_free_context (ctx);
    return keys;
  }

  /**
   * The keys in force (R31).  The keytab file is read again only when it
   * changes, and its keys replace the current ones only if they pass the
   * keytab checks: a file that is bad, missing or half written is
   * refused, audited once, and the last good keys stay in force.  A
   * request in flight keeps the keys it started with.
   */
  TAO_SYNCH_MUTEX cred_lock;
  std::shared_ptr<Acceptor_Keys> acceptor_keys;
  std::string acceptor_config;
  File_State acceptor_file;
  File_State rejected_file;

  std::shared_ptr<Acceptor_Keys>
  acceptor (std::string const &principal, std::string const &keytab, std::string const &rcache, std::string &why)
  {
    File_State const now = file_state (keytab);
    std::string const config = principal + '\n' + keytab + '\n' + rcache;
    std::shared_ptr<Acceptor_Keys> keys;
    std::string event;          // audited after the lock is released
    std::string event_text;
    {
      ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, cred_lock, nullptr);
      bool const same_config = acceptor_keys && config == acceptor_config;
      if (same_config && (now == acceptor_file || now == rejected_file))
        return acceptor_keys;

      bool const prod = TAO_Security_Mode::host ().mode == TAO_Security_Mode::MODE_PROD;
      std::string error;
      keys = load_keys (principal, keytab, rcache, prod, error);
      if (keys && file_state (keytab) != now)
        {
          // Changed while it was read: try again at the next login.
          keys.reset ();
          if (same_config)
            return acceptor_keys;
          error = keytab + " changed while it was read";
        }
      if (keys)
        {
          if (same_config)
            {
              event = TAO::Security::Audit_Reason::KRB_KEYTAB_LOADED;
              event_text = "the keytab changed; now in force: " + keys->summary;
            }
          acceptor_keys = keys;
          acceptor_config = config;
          acceptor_file = now;
          rejected_file = File_State ();
        }
      else if (same_config)
        {
          rejected_file = now;
          keys = acceptor_keys;
          event = TAO::Security::Audit_Reason::KRB_KEYTAB_REJECTED;
          event_text = error + "; the last good keys stay in force (" + acceptor_keys->summary + ")";
        }
      else
        why = error;
    }
    if (!event.empty ())
      TAO::Security::Audit_Logger::instance ()->write (
        TAO::Security::Audit_Record ("config", event == TAO::Security::Audit_Reason::KRB_KEYTAB_LOADED, event.c_str ())
          .field ("file", keytab)
          .text (event_text.c_str ()));
    return keys;
  }

  /// A verified PAC's logon information into @a info; a PAC that does
  /// not parse leaves the groups empty, with a note (no group is
  /// granted from a buffer TAO cannot read).
  void
  parse_pac (std::string const &ndr, TAO::SSLIOP::Kerberos::Pac_Info &info)
  {
    std::string why;
    if (!TAO::SSLIOP::Kerberos::parse_logon_info (ndr, info, why))
      {
        info.groups.clear ();
        info.note = "unreadable PAC logon information (" + why + "); its groups are ignored";
      }
  }

  /// The PAC logon information of the accepted client @a src (MIT
  /// exposes PAC buffers as "urn:mspac:" name attributes).  Its groups
  /// are used only when the library verified the PAC with the ticket.
  void
  read_pac (gss_name_t src, TAO::SSLIOP::Kerberos::Pac_Info &info)
  {
    static char const attr[] = "urn:mspac:logon-info";
    gss_buffer_desc a = { sizeof attr - 1, const_cast<char *> (attr) };
    int authenticated = 0;
    int complete = 0;
    int more = -1;
    gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc display = GSS_C_EMPTY_BUFFER;
    OM_uint32 minor = 0;
    OM_uint32 const major =
      ::gss_get_name_attribute (&minor, src, &a, &authenticated, &complete, &value, &display, &more);
    if (GSS_ERROR (major) || value.length == 0)
      {
        info.note = "the ticket carries no PAC logon information";
      }
    else
      {
        info.present = true;
        info.verified = authenticated != 0;
        if (!info.verified)
          info.note = "the PAC did not verify with the ticket; its groups are ignored";
        else
          parse_pac (std::string (static_cast<char const *> (value.value), value.length), info);
      }
    OM_uint32 m2 = 0;
    if (value.length > 0)
      ::gss_release_buffer (&m2, &value);
    if (display.length > 0)
      ::gss_release_buffer (&m2, &display);
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
                                     std::string &error,
                                     size_t *versions)
{
  ACE_stat st;
  if (!keytab_file_ok (path, prod, st, error))
    return false;
#if defined (TAO_HAS_GSSAPI)
  krb5_context ctx = nullptr;
  if (::krb5_init_context (&ctx) != 0)
    {
      error = "cannot initialise the Kerberos library";
      return false;
    }
  bool const ok = read_keytab_keys (ctx, path, principal, nullptr, summary, error, versions);
  ::krb5_free_context (ctx);
  return ok;
#else
  ACE_UNUSED_ARG (principal);
  ACE_UNUSED_ARG (summary);
  ACE_UNUSED_ARG (versions);
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
                               std::string &why,
                               Pac_Info *pac)
{
#if defined (TAO_HAS_GSSAPI)
  std::shared_ptr<Acceptor_Keys> const keys = acceptor (principal, keytab, rcache, why);
  if (!keys)
    return UNAVAILABLE;
  gss_cred_id_t const cred = keys->cred;

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
          if (pac != nullptr)
            read_pac (src, *pac);
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
  ACE_UNUSED_ARG (pac);
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

namespace
{
  /// A bounds-checked little-endian NDR (MS-RPCE 2.2.5) reader.
  class Ndr_Reader
  {
  public:
    explicit Ndr_Reader (std::string const &b) : b_ (b) {}
    bool ok () const { return ok_; }
    size_t pos () const { return pos_; }
    void
    align (size_t n)
    {
      size_t const p = (pos_ + n - 1) / n * n;
      if (p > b_.size ())
        ok_ = false;
      else
        pos_ = p;
    }
    void
    skip (size_t n)
    {
      if (!ok_ || n > b_.size () - pos_)
        ok_ = false;
      else
        pos_ += n;
    }
    unsigned
    u8 ()
    {
      if (!ok_ || pos_ >= b_.size ())
        {
          ok_ = false;
          return 0;
        }
      return static_cast<unsigned char> (b_[pos_++]);
    }
    unsigned long
    u16 ()
    {
      unsigned long const lo = u8 ();
      return lo | (static_cast<unsigned long> (u8 ()) << 8);
    }
    unsigned long
    u32 ()
    {
      unsigned long const lo = u16 ();
      return lo | (u16 () << 16);
    }
    void fail () { ok_ = false; }

  private:
    std::string const &b_;
    size_t pos_ = 0;
    bool ok_ = true;
  };

  constexpr unsigned long MAX_PAC_GROUPS = 4096;
  /// MS-PAC SE_GROUP_USE_FOR_DENY_ONLY (0x10): a SID that may only deny,
  /// never grant.  Named apart from the Windows SDK macro of that name.
  constexpr unsigned long PAC_GROUP_DENY_ONLY = 0x10;

  /// A deferred RPC_UNICODE_STRING body (conformant varying array of
  /// UTF-16), returned as ASCII with '?' for anything else.
  std::string
  ndr_string (Ndr_Reader &r)
  {
    r.align (4);
    unsigned long const max = r.u32 ();
    unsigned long const offset = r.u32 ();
    unsigned long const actual = r.u32 ();
    if (!r.ok () || offset != 0 || actual > max || actual > 1024)
      {
        r.fail ();
        return std::string ();
      }
    std::string out;
    for (unsigned long i = 0; i < actual && r.ok (); ++i)
      {
        unsigned long const c = r.u16 ();
        out += (c >= 0x20 && c < 0x7F) ? static_cast<char> (c) : '?';
      }
    return out;
  }

  /// A deferred RPC_SID (conformant on its sub-authorities), as text.
  std::string
  ndr_sid (Ndr_Reader &r)
  {
    r.align (4);
    unsigned long const max = r.u32 ();
    unsigned const revision = r.u8 ();
    unsigned const count = r.u8 ();
    if (!r.ok () || revision != 1 || count != max || count > 15)
      {
        r.fail ();
        return std::string ();
      }
    unsigned long long authority = 0;
    for (int i = 0; i < 6; ++i)
      authority = (authority << 8) | r.u8 ();
    std::string out = "S-1-";
    if (authority < (1ULL << 32))
      out += std::to_string (authority);
    else
      {
        char hex[20];
        ACE_OS::snprintf (hex, sizeof hex, "0x%012llX", authority);
        out += hex;
      }
    for (unsigned i = 0; i < count && r.ok (); ++i)
      out += "-" + std::to_string (r.u32 ());
    return r.ok () ? out : std::string ();
  }

  /// A deferred array of GROUP_MEMBERSHIP (RelativeId, Attributes).
  void
  ndr_groups (Ndr_Reader &r, unsigned long count, std::vector<std::pair<unsigned long, unsigned long>> &out)
  {
    r.align (4);
    if (r.u32 () != count || count > MAX_PAC_GROUPS)
      {
        r.fail ();
        return;
      }
    for (unsigned long i = 0; i < count && r.ok (); ++i)
      {
        unsigned long const rid = r.u32 ();
        unsigned long const attributes = r.u32 ();
        out.emplace_back (rid, attributes);
      }
  }
}

bool
TAO::SSLIOP::Kerberos::parse_logon_info (std::string const &ndr, Pac_Info &info, std::string &why)
{
  Ndr_Reader r (ndr);
  // MS-RPCE 2.2.6 type serialisation version 1: common header (version
  // 1, little-endian, length 8, filler), private header (object length,
  // filler), then the top-level pointer to KERB_VALIDATION_INFO.
  if (ndr.size () < 20 || r.u8 () != 1 || r.u8 () != 0x10 || r.u16 () != 8)
    {
      why = "not a little-endian NDR type serialisation (version 1)";
      return false;
    }
  r.skip (4);
  unsigned long const length = r.u32 ();
  r.skip (4);
  if (!r.ok () || length > ndr.size () - 16 || r.u32 () == 0)
    {
      why = "bad NDR serialisation header";
      return false;
    }

  // KERB_VALIDATION_INFO, fixed part.
  r.skip (6 * 8);                       // six FILETIMEs
  bool strings[6];
  for (bool &s : strings)               // EffectiveName .. HomeDirectoryDrive
    {
      r.skip (4);
      s = r.u32 () != 0;
    }
  r.skip (4);                           // LogonCount, BadPasswordCount
  unsigned long const user_id = r.u32 ();
  r.skip (4);                           // PrimaryGroupId (also in GroupIds)
  unsigned long const group_count = r.u32 ();
  bool const group_ids = r.u32 () != 0;
  r.skip (4 + 16);                      // UserFlags, UserSessionKey
  r.skip (4);
  bool const logon_server = r.u32 () != 0;
  r.skip (4);
  bool const logon_domain = r.u32 () != 0;
  bool const domain_id = r.u32 () != 0;
  r.skip (8 + 4 + 4 + 8 + 8 + 4 + 4);   // Reserved1 .. Reserved3
  unsigned long const sid_count = r.u32 ();
  bool const extra_sids = r.u32 () != 0;
  bool const resource_domain = r.u32 () != 0;
  unsigned long const resource_count = r.u32 ();
  bool const resource_ids = r.u32 () != 0;
  if (!r.ok () || group_count > MAX_PAC_GROUPS || sid_count > MAX_PAC_GROUPS || resource_count > MAX_PAC_GROUPS)
    {
      why = !r.ok () ? "the PAC logon information is truncated" : "the PAC names more than 4096 groups";
      return false;
    }

  // Deferred pointees, in field order.
  for (bool s : strings)
    if (s)
      (void) ndr_string (r);
  std::vector<std::pair<unsigned long, unsigned long>> groups;
  if (group_ids)
    ndr_groups (r, group_count, groups);
  if (logon_server)
    (void) ndr_string (r);
  std::string domain;
  if (logon_domain)
    domain = ndr_string (r);
  std::string domain_sid;
  if (domain_id)
    domain_sid = ndr_sid (r);
  std::vector<std::pair<std::string, unsigned long>> extras;
  if (extra_sids)
    {
      r.align (4);
      if (r.u32 () != sid_count)
        r.fail ();
      std::vector<std::pair<bool, unsigned long>> slots;
      for (unsigned long i = 0; i < sid_count && r.ok (); ++i)
        {
          bool const p = r.u32 () != 0;
          slots.emplace_back (p, r.u32 ());
        }
      for (auto const &s : slots)
        if (s.first && r.ok ())
          extras.emplace_back (ndr_sid (r), s.second);
    }
  std::string resource_sid;
  if (resource_domain)
    resource_sid = ndr_sid (r);
  std::vector<std::pair<unsigned long, unsigned long>> resources;
  if (resource_ids)
    ndr_groups (r, resource_count, resources);
  if (!r.ok ())
    {
      why = "the PAC logon information is malformed";
      return false;
    }
  if (domain_sid.empty ())
    {
      why = "the PAC logon information has no domain SID";
      return false;
    }

  info.domain = domain;
  info.domain_sid = domain_sid;
  info.user_sid = domain_sid + "-" + std::to_string (user_id);
  info.groups.clear ();
  std::set<std::string> seen;
  auto add = [&info, &seen] (std::string const &sid, unsigned long attributes) {
    if (!sid.empty () && (attributes & PAC_GROUP_DENY_ONLY) == 0 && seen.insert (sid).second)
      info.groups.push_back (sid);
  };
  for (auto const &g : groups)
    add (domain_sid + "-" + std::to_string (g.first), g.second);
  for (auto const &e : extras)
    add (e.first, e.second);
  if (!resource_sid.empty ())
    for (auto const &g : resources)
      add (resource_sid + "-" + std::to_string (g.first), g.second);
  return true;
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
