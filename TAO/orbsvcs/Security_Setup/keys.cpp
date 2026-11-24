// ace-tao-setup key / cert.
//
//   key create --type file   --out PATH --password-file F [--algorithm ec|rsa] [--force]
//   key create --type file   --out PATH --unprotected      (dev and test only)
//   key create --type pkcs11 --uri 'pkcs11:token=T;object=O' [--password-file PIN] [--algorithm rsa|ec]
//   key create --type tpm2   --out PATH [--algorithm ec|rsa]
//   key create --type sep    --out PATH [--sep-keygen PATH]
//   key check  --key SPEC [--password-file F] [--cert PEM]
//
//   cert request --key SPEC --token-file F --out PEM [--password-file F]
//                [--ca-url URL] [--root PEM] [--force]
//   cert renew   --key SPEC --cert PEM [--password-file F]
//                [--ca-url URL] [--root PEM] [--force]
//
// Keys are made and used through OpenSSL 3 providers, so a key in a token
// (pkcs11-provider), a TPM (tpm2-openssl) or the Secure Enclave (sep) is
// never exported: the signature for a certificate request or a TLS
// handshake is computed where the key lives.  SPEC is what SSLIOP takes for
// -SSLPrivateKey: PEM:path, STORE:uri or pkcs11:...; the password file is
// what -SSLPassword file: names (a token PIN for pkcs11), read the same way.
//
// A certificate is requested with a one-time token from step-ca ("step ca
// token NAME --san ..."), made by whoever holds the provisioner password.
// The token decides the identity: the request asks for exactly the token's
// subject and SANs, and the root certificate must match the fingerprint the
// token carries.  Renewal is mutual TLS to the CA with the current
// certificate and the same key, so it needs no token; it runs when less than
// a third of the certificate's lifetime is left (--force: now).

#include "keys.h"

#include "orbsvcs/Security/Audit_Logger.h"

#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_stat.h"
#include "ace/OS_NS_time.h"
#include "ace/OS_NS_unistd.h"

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <memory>
#include <vector>

namespace Reason = TAO::Security::Audit_Reason;

namespace
{
  constexpr int EXIT_OK = 0;
  constexpr int EXIT_WARN = 1;
  constexpr int EXIT_FAIL = 2;
  constexpr int EXIT_USAGE = 64;

  char const key_usage[] =
    "usage: ace-tao-setup key create --type file --out PATH (--password-file F | --unprotected)\n"
    "                                [--algorithm ec|rsa] [--force]\n"
    "       ace-tao-setup key create --type pkcs11 --uri 'pkcs11:token=T;object=O'\n"
    "                                [--password-file PIN-FILE] [--algorithm rsa|ec]\n"
    "       ace-tao-setup key create --type tpm2 --out PATH [--algorithm ec|rsa]\n"
    "       ace-tao-setup key create --type sep --out PATH [--sep-keygen PATH]\n"
    "       ace-tao-setup key check --key SPEC [--password-file F] [--cert PEM]\n"
    "  SPEC is what SSLIOP -SSLPrivateKey takes: PEM:path, STORE:uri or pkcs11:...\n";

  char const cert_usage[] =
    "usage: ace-tao-setup cert request --key SPEC --token-file F --out PEM [--password-file F]\n"
    "                                  [--ca-url URL] [--root PEM] [--force]\n"
    "       ace-tao-setup cert renew --key SPEC --cert PEM [--password-file F]\n"
    "                                [--ca-url URL] [--root PEM] [--force]\n"
    "  --ca-url and --root default to ca_url and ca_root in the security configuration.\n";

  int
  usage (char const *text, std::string const &problem)
  {
    if (!problem.empty ())
      ACE_OS::fprintf (stderr, "ace-tao-setup: %s\n", problem.c_str ());
    ACE_OS::fputs (text, stderr);
    return EXIT_USAGE;
  }

  int
  refuse (std::string const &why)
  {
    ACE_OS::fprintf (stderr, "ace-tao-setup: %s\n", why.c_str ());
    return EXIT_FAIL;
  }

  /// The OpenSSL error queue as one line (and empties it).
  std::string
  ssl_errors ()
  {
    std::string out;
    unsigned long e;
    while ((e = ::ERR_get_error ()) != 0)
      {
        char buf[256];
        ::ERR_error_string_n (e, buf, sizeof buf);
        if (!out.empty ())
          out += "; ";
        out += buf;
      }
    return out.empty () ? "no detail" : out;
  }

  struct Free_PKEY { void operator() (EVP_PKEY *p) const { ::EVP_PKEY_free (p); } };
  struct Free_X509 { void operator() (X509 *p) const { ::X509_free (p); } };
  struct Free_BIO { void operator() (BIO *p) const { ::BIO_free_all (p); } };
  struct Free_CTX { void operator() (SSL_CTX *p) const { ::SSL_CTX_free (p); } };
  using PKEY = std::unique_ptr<EVP_PKEY, Free_PKEY>;
  using Cert = std::unique_ptr<X509, Free_X509>;

  bool
  exists (std::string const &path)
  {
    ACE_stat st;
    return ACE_OS::stat (path.c_str (), &st) == 0;
  }

  bool
  read_file (std::string const &path, std::string &out, size_t limit = 1 << 20)
  {
    FILE *const fp = ACE_OS::fopen (path.c_str (), ACE_TEXT ("rb"));
    if (fp == nullptr)
      return false;
    out.clear ();
    char buf[4096];
    size_t n;
    while ((n = ACE_OS::fread (buf, 1, sizeof buf, fp)) > 0 && out.size () < limit)
      out.append (buf, n);
    ACE_OS::fclose (fp);
    return true;
  }

  /// Writes through a temporary file and rename, created with @a mode.
  bool
  write_atomic (std::string const &path, std::string const &text, mode_t mode, std::string &error)
  {
    std::string const tmp = path + ".tmp." + std::to_string (static_cast<long> (ACE_OS::getpid ()));
    ACE_HANDLE const fd = ACE_OS::open (tmp.c_str (), O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd == ACE_INVALID_HANDLE)
      {
        error = "cannot write " + tmp + ": " + ACE_OS::strerror (errno);
        return false;
      }
    bool ok = ACE_OS::write (fd, text.data (), text.size ()) == static_cast<ssize_t> (text.size ());
    ok = ::fsync (fd) == 0 && ok;
    ok = ACE_OS::close (fd) == 0 && ok;
    ok = ok && ::chmod (tmp.c_str (), mode) == 0;
    ok = ok && ACE_OS::rename (tmp.c_str (), path.c_str ()) == 0;
    if (!ok)
      {
        error = "cannot write " + path + ": " + ACE_OS::strerror (errno);
        ACE_OS::unlink (tmp.c_str ());
      }
    return ok;
  }

  // ------------------------------------------------------------------
  // Passwords and key loading

  /// The password (or PIN) in @a path, read as SSLIOP's -SSLPassword file:
  /// reads it: everything up to the first newline.
  bool
  read_password (std::string const &path, std::string &out, std::string &error)
  {
    if (!read_file (path, out, 4096))
      {
        error = "cannot read " + path + ": " + ACE_OS::strerror (errno);
        return false;
      }
    size_t const nl = out.find ('\n');
    if (nl != std::string::npos)
      out.resize (nl);
    if (out.empty ())
      {
        error = path + " is empty";
        return false;
      }
    return true;
  }

  int
  password_cb (char *buf, int size, int, void *u)
  {
    std::string const *const pw = static_cast<std::string const *> (u);
    if (pw == nullptr || pw->empty () || static_cast<int> (pw->size ()) >= size)
      return -1;
    ACE_OS::memcpy (buf, pw->data (), pw->size ());
    return static_cast<int> (pw->size ());
  }

  /// SSLIOP's -SSLPrivateKey forms to an OSSL_STORE URI (a plain path is a
  /// URI for the file loader).
  std::string
  store_uri (std::string const &spec)
  {
    if (spec.compare (0, 4, "PEM:") == 0)
      return spec.substr (4);
    if (spec.compare (0, 6, "STORE:") == 0)
      return spec.substr (6);
    return spec;
  }

  /// Loads the private key named by @a spec.  With an empty password the
  /// load never prompts.
  PKEY
  load_key (std::string const &spec, std::string const &password, std::string &error)
  {
    std::string const uri = store_uri (spec);
    UI_METHOD *const ui = password.empty () ? nullptr : ::UI_UTIL_wrap_read_pem_callback (password_cb, 0);
    OSSL_STORE_CTX *const store =
      ::OSSL_STORE_open_ex (uri.c_str (), nullptr, nullptr, ui != nullptr ? ui : ::UI_null (),
                            const_cast<std::string *> (&password), nullptr, nullptr, nullptr);
    EVP_PKEY *pkey = nullptr;
    if (store != nullptr)
      {
        (void) ::OSSL_STORE_expect (store, OSSL_STORE_INFO_PKEY);
        while (pkey == nullptr && !::OSSL_STORE_eof (store))
          {
            OSSL_STORE_INFO *const info = ::OSSL_STORE_load (store);
            if (info == nullptr)
              {
                if (::OSSL_STORE_error (store))
                  break;
                continue;
              }
            if (::OSSL_STORE_INFO_get_type (info) == OSSL_STORE_INFO_PKEY)
              pkey = ::OSSL_STORE_INFO_get1_PKEY (info);
            ::OSSL_STORE_INFO_free (info);
          }
        ::OSSL_STORE_close (store);
      }
    if (ui != nullptr)
      ::UI_destroy_method (ui);
    if (pkey == nullptr)
      error = "cannot load the private key " + spec + " (" + ssl_errors () + ")";
    ::ERR_clear_error ();
    return PKEY (pkey);
  }

  std::string
  provider_of (EVP_PKEY *pkey)
  {
    OSSL_PROVIDER const *const p = ::EVP_PKEY_get0_provider (pkey);
    return p ? ::OSSL_PROVIDER_get0_name (p) : "legacy";
  }

  /// True when the private key can be read out of its provider.
  bool
  exportable (EVP_PKEY *pkey)
  {
    OSSL_PARAM *params = nullptr;
    if (::EVP_PKEY_todata (pkey, EVP_PKEY_KEYPAIR, &params) != 1)
      {
        ::ERR_clear_error ();
        return false;
      }
    bool const priv = ::OSSL_PARAM_locate (params, OSSL_PKEY_PARAM_PRIV_KEY) != nullptr
                      || ::OSSL_PARAM_locate (params, OSSL_PKEY_PARAM_RSA_D) != nullptr;
    ::OSSL_PARAM_free (params);
    return priv;
  }

  std::string
  describe (EVP_PKEY *pkey)
  {
    char group[64] = "";
    size_t len = 0;
    std::string d = ::EVP_PKEY_get0_type_name (pkey) ? ::EVP_PKEY_get0_type_name (pkey) : "key";
    if (::EVP_PKEY_get_utf8_string_param (pkey, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group, &len) == 1)
      d += std::string (" ") + group;
    else if (::EVP_PKEY_get_bits (pkey) > 0)
      d += " " + std::to_string (::EVP_PKEY_get_bits (pkey));
    ::ERR_clear_error ();
    return d;
  }

  /// The public half of @a pkey as a software key (default provider).
  PKEY
  public_copy (EVP_PKEY *pkey)
  {
    unsigned char *der = nullptr;
    int const len = ::i2d_PUBKEY (pkey, &der);
    if (len <= 0)
      return PKEY ();
    unsigned char const *p = der;
    PKEY pub (::d2i_PUBKEY (nullptr, &p, len));
    ::OPENSSL_free (der);
    return pub;
  }

  /// Signs random data with the key (where it lives) and verifies the
  /// signature in software with the public key.
  bool
  test_signature (EVP_PKEY *pkey, std::string &error)
  {
    unsigned char data[64];
    ::RAND_bytes (data, sizeof data);
    std::vector<unsigned char> sig (1024);
    size_t siglen = sig.size ();
    EVP_MD_CTX *ctx = ::EVP_MD_CTX_new ();
    bool ok = ::EVP_DigestSignInit_ex (ctx, nullptr, "SHA256", nullptr, nullptr, pkey, nullptr) == 1
              && ::EVP_DigestSign (ctx, sig.data (), &siglen, data, sizeof data) == 1;
    ::EVP_MD_CTX_free (ctx);
    if (!ok)
      {
        error = "signing failed: " + ssl_errors ();
        return false;
      }
    PKEY pub = public_copy (pkey);
    ctx = ::EVP_MD_CTX_new ();
    ok = pub && ::EVP_DigestVerifyInit_ex (ctx, nullptr, "SHA256", nullptr, nullptr, pub.get (), nullptr) == 1
         && ::EVP_DigestVerify (ctx, sig.data (), siglen, data, sizeof data) == 1;
    ::EVP_MD_CTX_free (ctx);
    if (!ok)
      error = "the signature does not verify with the public key: " + ssl_errors ();
    ::ERR_clear_error ();
    return ok;
  }

  Cert
  read_cert (std::string const &path, std::vector<Cert> *rest = nullptr)
  {
    BIO *const b = ::BIO_new_file (path.c_str (), "r");
    if (b == nullptr)
      return Cert ();
    Cert leaf (::PEM_read_bio_X509 (b, nullptr, nullptr, nullptr));
    if (rest != nullptr)
      while (X509 *const x = ::PEM_read_bio_X509 (b, nullptr, nullptr, nullptr))
        rest->emplace_back (x);
    ::BIO_free (b);
    ::ERR_clear_error ();
    return leaf;
  }

  std::string
  subject_of (X509 *x)
  {
    char buf[256];
    ::X509_NAME_oneline (::X509_get_subject_name (x), buf, sizeof buf);
    return buf;
  }

  std::string
  serial_of (X509 *x)
  {
    BIGNUM *const bn = ::ASN1_INTEGER_to_BN (::X509_get0_serialNumber (x), nullptr);
    char *const hex = bn ? ::BN_bn2hex (bn) : nullptr;
    std::string const s = hex ? hex : "";
    ::OPENSSL_free (hex);
    ::BN_free (bn);
    return s;
  }

  std::string
  asn1_time (ASN1_TIME const *t)
  {
    struct tm tm_buf;
    char buf[32] = "";
    if (::ASN1_TIME_to_tm (t, &tm_buf) == 1)
      ACE_OS::strftime (buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return buf;
  }

  /// Seconds from now to @a t (negative when past).
  long long
  seconds_until (ASN1_TIME const *t)
  {
    int days = 0, secs = 0;
    if (::ASN1_TIME_diff (&days, &secs, nullptr, t) != 1)
      return 0;
    return static_cast<long long> (days) * 86400 + secs;
  }

  // ------------------------------------------------------------------
  // key create / key check

  struct Finding
  {
    char const *status;
    std::string name;
    std::string detail;
  };

  int
  print_findings (std::vector<Finding> const &f)
  {
    int worst = EXIT_OK;
    for (auto const &x : f)
      {
        ACE_OS::printf ("%-5s %-14s %s\n", x.status, x.name.c_str (), x.detail.c_str ());
        if (ACE_OS::strcmp (x.status, "FAIL") == 0)
          worst = EXIT_FAIL;
        else if (ACE_OS::strcmp (x.status, "WARN") == 0 && worst == EXIT_OK)
          worst = EXIT_WARN;
      }
    return worst;
  }

  int
  key_check (std::string const &spec, std::string const &password, std::string const &cert_path)
  {
    std::vector<Finding> f;
    std::string error;
    PKEY pkey = load_key (spec, password, error);
    if (!pkey)
      {
        f.push_back ({"FAIL", "load", error});
        return print_findings (f);
      }
    std::string const prov = provider_of (pkey.get ());
    f.push_back ({"OK", "load", describe (pkey.get ()) + " from provider " + prov});

    std::string const uri = store_uri (spec);
    bool const is_file = uri.find (':') == std::string::npos || uri.compare (0, 5, "file:") == 0;
    if (!exportable (pkey.get ()))
      f.push_back ({"OK", "protection", "held by provider " + prov + "; the private key cannot be exported"});
    else if (is_file)
      {
        std::string text;
        std::string const path = uri.compare (0, 5, "file:") == 0 ? uri.substr (5) : uri;
        read_file (path, text);
        bool const encrypted = text.find ("ENCRYPTED PRIVATE KEY") != std::string::npos
                               || text.find ("Proc-Type: 4,ENCRYPTED") != std::string::npos;
        if (encrypted)
          f.push_back ({"OK", "protection", "software key in a passphrase-encrypted file"});
        else
          f.push_back ({"FAIL", "protection", "software key stored UNENCRYPTED in " + path});
        ACE_stat st;
        if (ACE_OS::stat (path.c_str (), &st) == 0 && (st.st_mode & 077) != 0)
          {
            char mode[8];
            ACE_OS::snprintf (mode, sizeof mode, "%04o", static_cast<unsigned> (st.st_mode & 07777));
            f.push_back ({"FAIL", "permissions", path + " is mode " + mode + " (want 0600 or 0400)"});
          }
      }
    else
      f.push_back ({"WARN", "protection", "provider " + prov + " lets the private key be exported"});

    if (test_signature (pkey.get (), error))
      f.push_back ({"OK", "signature", "test signature made and verified"});
    else
      f.push_back ({"FAIL", "signature", "cannot sign with the key: " + error});

    if (!cert_path.empty ())
      {
        Cert cert = read_cert (cert_path);
        if (!cert)
          f.push_back ({"FAIL", "certificate", "cannot read " + cert_path});
        else
          {
            if (::EVP_PKEY_eq (::X509_get0_pubkey (cert.get ()), pkey.get ()) == 1)
              f.push_back ({"OK", "certificate", "matches " + subject_of (cert.get ())});
            else
              f.push_back ({"FAIL", "certificate", cert_path + " is for a different key"});
            long long const left = seconds_until (::X509_get0_notAfter (cert.get ()));
            if (left <= 0)
              f.push_back ({"FAIL", "expiry", "expired " + asn1_time (::X509_get0_notAfter (cert.get ()))});
            else
              f.push_back ({"OK", "expiry", "valid until " + asn1_time (::X509_get0_notAfter (cert.get ()))
                                            + " (" + std::to_string (left / 86400) + " day(s))"});
            ::ERR_clear_error ();
          }
      }
    return print_findings (f);
  }

  /// Runs @a args; returns the exit status (or -1).
  int
  run (std::vector<std::string> const &args)
  {
    pid_t const pid = ::fork ();
    if (pid < 0)
      return -1;
    if (pid == 0)
      {
        std::vector<char *> v;
        for (auto const &a : args)
          v.push_back (const_cast<char *> (a.c_str ()));
        v.push_back (nullptr);
        ::execv (v[0], v.data ());
        ::_exit (127);
      }
    int status = 0;
    while (::waitpid (pid, &status, 0) < 0)
      if (errno != EINTR)
        return -1;
    return WIFEXITED (status) ? WEXITSTATUS (status) : -1;
  }

  std::string
  find_program (std::string const &name, std::vector<std::string> const &extra)
  {
    std::vector<std::string> dirs = extra;
    char const *const path = ACE_OS::getenv ("PATH");
    std::string const p = path ? path : "";
    for (size_t s = 0, e; s <= p.size (); s = e + 1)
      {
        e = p.find (':', s);
        if (e == std::string::npos)
          e = p.size ();
        if (e > s)
          dirs.push_back (p.substr (s, e - s));
      }
    for (auto const &d : dirs)
      if (ACE_OS::access ((d + "/" + name).c_str (), X_OK) == 0)
        return d + "/" + name;
    return "";
  }

  /// Generates a key through the provider selected by @a propq; for pkcs11
  /// the key is made in the token named by @a pkcs11_uri.
  PKEY
  generate (std::string const &algorithm, char const *propq, std::string const &pkcs11_uri, std::string &error)
  {
    EVP_PKEY_CTX *const ctx =
      ::EVP_PKEY_CTX_new_from_name (nullptr, algorithm == "rsa" ? "RSA" : "EC", propq);
    EVP_PKEY *pkey = nullptr;
    bool ok = ctx != nullptr && ::EVP_PKEY_keygen_init (ctx) == 1;
    if (ok)
      {
        OSSL_PARAM params[3];
        size_t n = 0;
        size_t bits = 3072;
        if (algorithm == "rsa")
          params[n++] = ::OSSL_PARAM_construct_size_t (OSSL_PKEY_PARAM_RSA_BITS, &bits);
        else
          params[n++] = ::OSSL_PARAM_construct_utf8_string (OSSL_PKEY_PARAM_GROUP_NAME,
                                                            const_cast<char *> ("P-256"), 0);
        if (!pkcs11_uri.empty ())
          params[n++] = ::OSSL_PARAM_construct_utf8_string ("pkcs11_uri", const_cast<char *> (pkcs11_uri.c_str ()), 0);
        params[n] = ::OSSL_PARAM_construct_end ();
        ok = ::EVP_PKEY_CTX_set_params (ctx, params) == 1 && ::EVP_PKEY_generate (ctx, &pkey) == 1;
      }
    ::EVP_PKEY_CTX_free (ctx);
    if (!ok)
      error = ssl_errors ();
    ::ERR_clear_error ();
    return PKEY (pkey);
  }

  /// The PEM encoding of a key, as its provider writes it (a TPM key is a
  /// TSS2 blob only that TPM can load; a software key is encrypted with
  /// @a password unless it is empty).
  bool
  encode_key (EVP_PKEY *pkey, std::string const &password, std::string &pem, std::string &error)
  {
    BIO *const mem = ::BIO_new (::BIO_s_mem ());
    bool ok;
    if (password.empty ())
      {
        OSSL_ENCODER_CTX *const ectx =
          ::OSSL_ENCODER_CTX_new_for_pkey (pkey, EVP_PKEY_KEYPAIR, "PEM", nullptr, nullptr);
        ok = ectx != nullptr && ::OSSL_ENCODER_CTX_get_num_encoders (ectx) > 0
             && ::OSSL_ENCODER_to_bio (ectx, mem) == 1;
        ::OSSL_ENCODER_CTX_free (ectx);
      }
    else
      ok = ::PEM_write_bio_PKCS8PrivateKey (mem, pkey, ::EVP_aes_256_cbc (), password.data (),
                                            static_cast<int> (password.size ()), nullptr, nullptr) == 1;
    if (ok)
      {
        char *data = nullptr;
        long const len = BIO_get_mem_data (mem, &data);
        pem.assign (data, static_cast<size_t> (len));
      }
    else
      error = ssl_errors ();
    ::BIO_free (mem);
    ::ERR_clear_error ();
    return ok;
  }

  int
  key_create (int argc, ACE_TCHAR *argv[])
  {
    std::string type, out, uri, password_file, algorithm, sep_keygen;
    bool unprotected = false, force = false;
    for (int i = 0; i < argc; ++i)
      {
        std::string const a = ACE_TEXT_ALWAYS_CHAR (argv[i]);
        bool const more = i + 1 < argc;
        if (a == "--type" && more) type = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--out" && more) out = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--uri" && more) uri = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--password-file" && more) password_file = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--algorithm" && more) algorithm = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--sep-keygen" && more) sep_keygen = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--unprotected") unprotected = true;
        else if (a == "--force") force = true;
        else
          return usage (key_usage, "key create: unknown option " + a);
      }
    if (type != "file" && type != "pkcs11" && type != "tpm2" && type != "sep")
      return usage (key_usage, "key create: --type must be file, pkcs11, tpm2 or sep");
    if (algorithm.empty ())
      algorithm = type == "pkcs11" ? "rsa" : "ec";
    if (algorithm != "ec" && algorithm != "rsa")
      return usage (key_usage, "key create: --algorithm must be ec (P-256) or rsa (3072 bits)");
    if (type == "pkcs11" ? uri.compare (0, 7, "pkcs11:") != 0 : out.empty ())
      return usage (key_usage, type == "pkcs11" ? "key create: --uri pkcs11:... is required"
                                                : "key create: --out PATH is required");
    if (type == "sep" && algorithm != "ec")
      return usage (key_usage, "key create: the Secure Enclave makes only P-256 keys");

    std::string password, error;
    if (!password_file.empty () && !read_password (password_file, password, error))
      return refuse (error);
    if (type == "file")
      {
        if (password.empty () && !unprotected)
          return usage (key_usage, "key create: a file key needs --password-file "
                                   "(or --unprotected, which prod refuses)");
        if (!password.empty () && unprotected)
          return usage (key_usage, "key create: --password-file and --unprotected conflict");
        std::string const mode = setup_conf_get ("mode");
        if (unprotected && mode == "prod")
          return refuse ("key create: prod refuses unprotected keys; give --password-file or use a keystore");
      }
    if (!out.empty () && exists (out) && !force)
      return refuse (out + " exists; not replacing a key (--force replaces it, and the old key is lost)");
    if (type == "sep" && force && exists (out))
      return refuse ("key create: remove " + out + " first (sep-keygen never replaces a key)");

    std::string spec;
    if (type == "sep")
      {
        if (sep_keygen.empty ())
          sep_keygen = find_program ("sep-keygen", {"/opt/homebrew/var/ace-tao/bin", "/usr/local/libexec/ace-tao"});
        if (sep_keygen.empty ())
          return refuse ("key create: sep-keygen not found (give --sep-keygen PATH)");
        if (run ({sep_keygen, out}) != 0)
          return refuse ("key create: " + sep_keygen + " failed");
        spec = "STORE:se:" + out;
      }
    else
      {
        std::string full_uri;
        if (type == "pkcs11")
          {
            // pkcs11-provider takes the PIN from the URI's pin-source.
            full_uri = uri;
            if (!password_file.empty () && uri.find ("pin-source=") == std::string::npos)
              full_uri += (uri.find ('?') == std::string::npos ? "?" : "&") + std::string ("pin-source=file:")
                          + password_file;
          }
        char const *const propq = type == "file" ? "provider=default"
                                  : type == "pkcs11" ? "provider=pkcs11" : "provider=tpm2";
        PKEY pkey = generate (algorithm, propq, full_uri, error);
        if (!pkey)
          return refuse ("key create: cannot generate the key with provider "
                         + std::string (propq + 9) + ": " + error);
        if (type == "pkcs11")
          {
            if (exportable (pkey.get ()))
              return refuse ("key create: the token made an EXTRACTABLE key; delete it from the token");
            std::string base = uri.substr (0, uri.find ('?'));
            if (base.find ("type=") == std::string::npos)
              base += ";type=private";
            spec = "STORE:" + base;
          }
        else
          {
            if (type == "tpm2" && exportable (pkey.get ()))
              return refuse ("key create: the key was made in software, not in the TPM");
            std::string pem;
            if (!encode_key (pkey.get (), type == "file" ? password : std::string (), pem, error))
              return refuse ("key create: cannot encode the key: " + error);
            if (!write_atomic (out, pem, 0600, error))
              return refuse (error);
            spec = type == "tpm2" ? "STORE:" + out : "PEM:" + out;
          }
      }

    setup_audit (Reason::KEY_CREATED, {{"key_type", type}, {"algorithm", algorithm}, {"key", spec}});
    ACE_OS::printf ("Created a %s key (%s).\n", type.c_str (), algorithm == "ec" ? "P-256" : "RSA 3072");
    int const rc = key_check (spec, password, "");
    ACE_OS::printf ("SSLIOP: -SSLPrivateKey %s%s\n", spec.c_str (),
                    password_file.empty () ? "" : (" -SSLPassword file:" + password_file).c_str ());
    return rc;
  }

  // ------------------------------------------------------------------
  // step-ca client

  /// The string value of "key" in a JSON object (first match; enough for
  /// step-ca's flat responses and JWT claims).  Handles the usual escapes.
  bool
  json_string (std::string const &json, char const *key, std::string &out, size_t from = 0)
  {
    std::string const k = std::string ("\"") + key + "\"";
    size_t p = json.find (k, from);
    while (p != std::string::npos)
      {
        size_t q = p + k.size ();
        while (q < json.size () && (json[q] == ' ' || json[q] == '\t' || json[q] == '\n' || json[q] == '\r'))
          ++q;
        if (q < json.size () && json[q] == ':')
          {
            ++q;
            while (q < json.size () && (json[q] == ' ' || json[q] == '\t' || json[q] == '\n' || json[q] == '\r'))
              ++q;
            if (q >= json.size () || json[q] != '"')
              return false;
            out.clear ();
            for (++q; q < json.size () && json[q] != '"'; ++q)
              {
                char c = json[q];
                if (c == '\\' && q + 1 < json.size ())
                  {
                    c = json[++q];
                    if (c == 'n') c = '\n';
                    else if (c == 't') c = '\t';
                    else if (c == 'r') c = '\r';
                    else if (c == 'u' && q + 4 < json.size ())
                      {
                        unsigned long const cp = ACE_OS::strtoul (json.substr (q + 1, 4).c_str (), nullptr, 16);
                        q += 4;
                        c = cp < 0x80 ? static_cast<char> (cp) : '?';
                      }
                  }
                out += c;
              }
            return q < json.size ();
          }
        p = json.find (k, p + 1);
      }
    return false;
  }

  /// The strings of the array value of "key" (JWT "sans", "aud").
  std::vector<std::string>
  json_strings (std::string const &json, char const *key)
  {
    std::vector<std::string> out;
    std::string const k = std::string ("\"") + key + "\"";
    size_t p = json.find (k);
    if (p == std::string::npos)
      return out;
    p = json.find_first_not_of (" \t\r\n", p + k.size ());
    if (p == std::string::npos || json[p] != ':')
      return out;
    p = json.find_first_not_of (" \t\r\n", p + 1);
    if (p == std::string::npos)
      return out;
    if (json[p] == '"')
      {
        std::string s;
        if (json_string (json, key, s))
          out.push_back (s);
        return out;
      }
    if (json[p] != '[')
      return out;
    size_t const end = json.find (']', p);
    std::string const body = json.substr (p, end == std::string::npos ? std::string::npos : end - p);
    for (size_t q = body.find ('"'); q != std::string::npos; )
      {
        size_t const e = body.find ('"', q + 1);
        if (e == std::string::npos)
          break;
        out.push_back (body.substr (q + 1, e - q - 1));
        q = body.find ('"', e + 1);
      }
    return out;
  }

  long long
  json_number (std::string const &json, char const *key)
  {
    std::string const k = std::string ("\"") + key + "\"";
    size_t p = json.find (k);
    if (p == std::string::npos)
      return 0;
    p = json.find (':', p + k.size ());
    return p == std::string::npos ? 0 : ACE_OS::strtoll (json.c_str () + p + 1, nullptr, 10);
  }

  bool
  base64url_decode (std::string in, std::string &out)
  {
    for (char &c : in)
      c = c == '-' ? '+' : c == '_' ? '/' : c;
    while (in.size () % 4)
      in += '=';
    std::vector<unsigned char> buf (in.size ());
    int const n = ::EVP_DecodeBlock (buf.data (), reinterpret_cast<unsigned char const *> (in.data ()),
                                     static_cast<int> (in.size ()));
    if (n < 0)
      return false;
    size_t pad = 0;
    for (size_t i = in.size (); i > 0 && in[i - 1] == '='; --i)
      ++pad;
    out.assign (reinterpret_cast<char *> (buf.data ()), static_cast<size_t> (n) - pad);
    return true;
  }

  struct Url
  {
    std::string host;
    std::string port;
    std::string prefix;   // path before /1.0/..., without a trailing slash
  };

  bool
  parse_url (std::string u, Url &out)
  {
    if (u.compare (0, 8, "https://") != 0)
      return false;
    u = u.substr (8);
    size_t const slash = u.find ('/');
    std::string hostport = u.substr (0, slash);
    out.prefix = slash == std::string::npos ? "" : u.substr (slash);
    while (!out.prefix.empty () && out.prefix.back () == '/')
      out.prefix.pop_back ();
    if (!hostport.empty () && hostport[0] == '[')
      {
        size_t const close = hostport.find (']');
        if (close == std::string::npos)
          return false;
        out.host = hostport.substr (1, close - 1);
        out.port = close + 2 <= hostport.size () && hostport[close + 1] == ':' ? hostport.substr (close + 2) : "443";
      }
    else
      {
        size_t const colon = hostport.rfind (':');
        out.host = hostport.substr (0, colon);
        out.port = colon == std::string::npos ? "443" : hostport.substr (colon + 1);
      }
    return !out.host.empty () && !out.port.empty ();
  }

  struct Response
  {
    int status = 0;
    std::string body;
  };

  /// One HTTPS request to the CA.  The server must present a certificate
  /// that chains to @a root and names the URL's host.  With @a cert_chain
  /// and @a key, the client authenticates with them (mutual TLS).
  bool
  https_post (Url const &url, std::string const &path, std::string const &body, std::string const &root,
              std::string const &cert_chain, EVP_PKEY *key, Response &resp, std::string &error)
  {
    std::unique_ptr<SSL_CTX, Free_CTX> ctx (::SSL_CTX_new (::TLS_client_method ()));
    if (!ctx)
      {
        error = ssl_errors ();
        return false;
      }
    SSL_CTX_set_min_proto_version (ctx.get (), TLS1_2_VERSION);
    ::SSL_CTX_set_verify (ctx.get (), SSL_VERIFY_PEER, nullptr);
    if (::SSL_CTX_load_verify_locations (ctx.get (), root.c_str (), nullptr) != 1)
      {
        error = "cannot load the root certificate " + root + " (" + ssl_errors () + ")";
        return false;
      }
    if (key != nullptr)
      if (::SSL_CTX_use_certificate_chain_file (ctx.get (), cert_chain.c_str ()) != 1
          || ::SSL_CTX_use_PrivateKey (ctx.get (), key) != 1)
        {
          error = "cannot use " + cert_chain + " with the key (" + ssl_errors () + ")";
          return false;
        }

    std::unique_ptr<BIO, Free_BIO> bio (::BIO_new_ssl_connect (ctx.get ()));
    SSL *ssl = nullptr;
    BIO_get_ssl (bio.get (), &ssl);
    std::string const target = (url.host.find (':') != std::string::npos ? "[" + url.host + "]" : url.host)
                               + ":" + url.port;
    BIO_set_conn_hostname (bio.get (), target.c_str ());
    unsigned char ip[16];
    bool const is_ip = ::inet_pton (AF_INET, url.host.c_str (), ip) == 1
                       || ::inet_pton (AF_INET6, url.host.c_str (), ip) == 1;
    if (is_ip)
      ::X509_VERIFY_PARAM_set1_ip_asc (::SSL_get0_param (ssl), url.host.c_str ());
    else
      {
        SSL_set_tlsext_host_name (ssl, url.host.c_str ());
        ::SSL_set1_host (ssl, url.host.c_str ());
      }
    if (BIO_do_connect (bio.get ()) != 1 || BIO_do_handshake (bio.get ()) != 1)
      {
        long const v = ::SSL_get_verify_result (ssl);
        error = "cannot connect to https://" + target + ": "
                + (v != X509_V_OK ? std::string ("server certificate: ") + ::X509_verify_cert_error_string (v)
                                  : ssl_errors ());
        return false;
      }
    int const fd = static_cast<int> (BIO_get_fd (bio.get (), nullptr));
    if (fd >= 0)
      {
        struct timeval tv {30, 0};
        ::setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
      }

    std::string req = "POST " + url.prefix + path + " HTTP/1.1\r\nHost: " + url.host
                      + "\r\nUser-Agent: ace-tao-setup\r\nAccept: application/json\r\n"
                        "Content-Type: application/json\r\nConnection: close\r\nContent-Length: "
                      + std::to_string (body.size ()) + "\r\n\r\n" + body;
    if (::BIO_write (bio.get (), req.data (), static_cast<int> (req.size ())) != static_cast<int> (req.size ())
        || BIO_flush (bio.get ()) != 1)
      {
        error = "cannot send the request (" + ssl_errors () + ")";
        return false;
      }
    std::string raw;
    char buf[4096];
    int n;
    while ((n = ::BIO_read (bio.get (), buf, sizeof buf)) > 0 && raw.size () < (1 << 20))
      raw.append (buf, static_cast<size_t> (n));
    ::ERR_clear_error ();

    size_t const hdr_end = raw.find ("\r\n\r\n");
    if (raw.compare (0, 5, "HTTP/") != 0 || hdr_end == std::string::npos)
      {
        error = "no HTTP response from the CA";
        return false;
      }
    size_t const sp = raw.find (' ');
    resp.status = ACE_OS::atoi (raw.c_str () + sp + 1);
    std::string headers = raw.substr (0, hdr_end);
    for (char &c : headers)
      c = static_cast<char> (::tolower (static_cast<unsigned char> (c)));
    resp.body = raw.substr (hdr_end + 4);
    if (headers.find ("transfer-encoding: chunked") != std::string::npos)
      {
        std::string decoded;
        size_t p = 0;
        while (p < resp.body.size ())
          {
            size_t const eol = resp.body.find ("\r\n", p);
            if (eol == std::string::npos)
              break;
            unsigned long const len = ACE_OS::strtoul (resp.body.substr (p, eol - p).c_str (), nullptr, 16);
            if (len == 0)
              break;
            decoded += resp.body.substr (eol + 2, len);
            p = eol + 2 + len + 2;
          }
        resp.body = decoded;
      }
    return true;
  }

  std::string
  ca_error (Response const &r)
  {
    std::string msg;
    if (!json_string (r.body, "message", msg))
      msg = r.body.substr (0, 200);
    return "the CA answered " + std::to_string (r.status) + ": " + msg;
  }

  std::string
  sha256_hex (X509 *x)
  {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    ::X509_digest (x, ::EVP_sha256 (), md, &len);
    std::string out;
    char hex[3];
    for (unsigned int i = 0; i < len; ++i)
      {
        ACE_OS::snprintf (hex, sizeof hex, "%02x", md[i]);
        out += hex;
      }
    return out;
  }

  std::string
  pem_of (X509 *x)
  {
    BIO *const mem = ::BIO_new (::BIO_s_mem ());
    ::PEM_write_bio_X509 (mem, x);
    char *data = nullptr;
    long const len = BIO_get_mem_data (mem, &data);
    std::string const s (data, static_cast<size_t> (len));
    ::BIO_free (mem);
    return s;
  }

  /// Checks a CA response (leaf "crt", intermediate "ca") against the key
  /// and the root, then writes leaf + intermediate to @a out.
  bool
  accept_certificate (Response const &r, EVP_PKEY *key, std::string const &root, std::string const &out,
                      Cert &leaf_out, std::string &error)
  {
    std::string crt, ca;
    if (!json_string (r.body, "crt", crt) || !json_string (r.body, "ca", ca))
      {
        error = "the CA's response has no certificate";
        return false;
      }
    BIO *b = ::BIO_new_mem_buf (crt.data (), static_cast<int> (crt.size ()));
    Cert leaf (::PEM_read_bio_X509 (b, nullptr, nullptr, nullptr));
    ::BIO_free (b);
    b = ::BIO_new_mem_buf (ca.data (), static_cast<int> (ca.size ()));
    Cert inter (::PEM_read_bio_X509 (b, nullptr, nullptr, nullptr));
    ::BIO_free (b);
    if (!leaf || !inter)
      {
        error = "the CA's certificates cannot be parsed";
        return false;
      }
    if (::EVP_PKEY_eq (::X509_get0_pubkey (leaf.get ()), key) != 1)
      {
        error = "the CA returned a certificate for a different key";
        return false;
      }
    X509_STORE *const store = ::X509_STORE_new ();
    STACK_OF (X509) *const chain = sk_X509_new_null ();
    sk_X509_push (chain, inter.get ());
    X509_STORE_CTX *const sctx = ::X509_STORE_CTX_new ();
    bool const verified = ::X509_STORE_load_file (store, root.c_str ()) == 1
                          && ::X509_STORE_CTX_init (sctx, store, leaf.get (), chain) == 1
                          && ::X509_verify_cert (sctx) == 1;
    if (!verified)
      error = std::string ("the CA's certificate does not chain to ") + root + ": "
              + ::X509_verify_cert_error_string (::X509_STORE_CTX_get_error (sctx));
    ::X509_STORE_CTX_free (sctx);
    sk_X509_free (chain);
    ::X509_STORE_free (store);
    ::ERR_clear_error ();
    if (!verified)
      return false;
    if (!write_atomic (out, pem_of (leaf.get ()) + pem_of (inter.get ()), 0644, error))
      return false;
    leaf_out = std::move (leaf);
    return true;
  }

  struct Cert_Options
  {
    std::string key, out, cert, token_file, password_file, ca_url, root;
    bool force = false;
  };

  int
  parse_cert_options (int argc, ACE_TCHAR *argv[], Cert_Options &o, char const *cmd)
  {
    for (int i = 0; i < argc; ++i)
      {
        std::string const a = ACE_TEXT_ALWAYS_CHAR (argv[i]);
        bool const more = i + 1 < argc;
        if (a == "--key" && more) o.key = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--out" && more) o.out = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--cert" && more) o.cert = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--token-file" && more) o.token_file = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--password-file" && more) o.password_file = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--ca-url" && more) o.ca_url = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--root" && more) o.root = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--force") o.force = true;
        else
          return usage (cert_usage, std::string (cmd) + ": unknown option " + a);
      }
    if (o.root.empty ())
      o.root = setup_conf_get ("ca_root");
    if (o.ca_url.empty ())
      o.ca_url = setup_conf_get ("ca_url");
    if (o.key.empty ())
      return usage (cert_usage, std::string (cmd) + ": --key SPEC is required");
    return EXIT_OK;
  }

  void
  print_certificate (X509 *leaf, std::string const &out)
  {
    ACE_OS::printf ("Certificate %s\n  subject %s\n  serial  %s\n  valid   %s .. %s\n", out.c_str (),
                    subject_of (leaf).c_str (), serial_of (leaf).c_str (),
                    asn1_time (::X509_get0_notBefore (leaf)).c_str (),
                    asn1_time (::X509_get0_notAfter (leaf)).c_str ());
  }

  int
  cert_request (int argc, ACE_TCHAR *argv[])
  {
    Cert_Options o;
    if (int const rc = parse_cert_options (argc, argv, o, "cert request"))
      return rc;
    if (o.token_file.empty () || o.out.empty ())
      return usage (cert_usage, "cert request: --token-file and --out are required");
    if (o.root.empty ())
      return usage (cert_usage, "cert request: --root PEM is required (or ca_root in the configuration)");
    if (exists (o.out) && !o.force)
      return refuse (o.out + " exists (--force replaces it)");

    // The token: header.payload.signature; the CA checks the signature.
    std::string token, payload;
    if (!read_file (o.token_file, token, 16384))
      return refuse ("cannot read " + o.token_file + ": " + ACE_OS::strerror (errno));
    while (!token.empty () && (token.back () == '\n' || token.back () == '\r' || token.back () == ' '))
      token.pop_back ();
    size_t const d1 = token.find ('.');
    size_t const d2 = d1 == std::string::npos ? d1 : token.find ('.', d1 + 1);
    if (d2 == std::string::npos || !base64url_decode (token.substr (d1 + 1, d2 - d1 - 1), payload))
      return refuse (o.token_file + " does not hold a step-ca token (step ca token NAME --san ...)");
    std::string sub, sha;
    json_string (payload, "sub", sub);
    json_string (payload, "sha", sha);
    std::vector<std::string> sans = json_strings (payload, "sans");
    std::vector<std::string> const aud = json_strings (payload, "aud");
    long long const exp = json_number (payload, "exp");
    if (sub.empty ())
      return refuse ("the token has no subject");
    if (sans.empty ())
      sans.push_back (sub);
    if (exp != 0 && exp < static_cast<long long> (ACE_OS::time (nullptr)))
      return refuse ("the token expired; ask for a new one");
    if (o.ca_url.empty () && !aud.empty ())
      {
        size_t const p = aud[0].find ("/1.0/sign");
        if (p != std::string::npos)
          o.ca_url = aud[0].substr (0, p);
      }
    Url url;
    if (!parse_url (o.ca_url, url))
      return usage (cert_usage, "cert request: --ca-url https://HOST[:PORT] is required");

    Cert root = read_cert (o.root);
    if (!root)
      return refuse ("cannot read the root certificate " + o.root);
    if (!sha.empty () && sha256_hex (root.get ()) != sha)
      return refuse ("the root certificate " + o.root + " is not the one the token names (sha256 " + sha + ")");

    std::string password, error;
    if (!o.password_file.empty () && !read_password (o.password_file, password, error))
      return refuse (error);
    PKEY key = load_key (o.key, password, error);
    if (!key)
      return refuse (error);

    // The request: CN = subject, SANs = the token's, signed with the key.
    X509_REQ *const req = ::X509_REQ_new ();
    ::X509_REQ_set_version (req, 0);
    X509_NAME *const name = ::X509_REQ_get_subject_name (req);
    ::X509_NAME_add_entry_by_txt (name, "CN", MBSTRING_UTF8, reinterpret_cast<unsigned char const *> (sub.c_str ()),
                                  -1, -1, 0);
    ::X509_REQ_set_pubkey (req, key.get ());
    GENERAL_NAMES *const gens = sk_GENERAL_NAME_new_null ();
    for (auto const &s : sans)
      {
        unsigned char ip[16];
        char const *kind = ::inet_pton (AF_INET, s.c_str (), ip) == 1 || ::inet_pton (AF_INET6, s.c_str (), ip) == 1
                             ? "IP" : s.find ("://") != std::string::npos ? "URI"
                             : s.find ('@') != std::string::npos ? "email" : "DNS";
        GENERAL_NAME *const g = ::a2i_GENERAL_NAME (nullptr, nullptr, nullptr,
                                                    ACE_OS::strcmp (kind, "IP") == 0 ? GEN_IPADD
                                                    : ACE_OS::strcmp (kind, "URI") == 0 ? GEN_URI
                                                    : ACE_OS::strcmp (kind, "email") == 0 ? GEN_EMAIL : GEN_DNS,
                                                    s.c_str (), 0);
        if (g != nullptr)
          sk_GENERAL_NAME_push (gens, g);
      }
    STACK_OF (X509_EXTENSION) *const exts = sk_X509_EXTENSION_new_null ();
    sk_X509_EXTENSION_push (exts, ::X509V3_EXT_i2d (NID_subject_alt_name, 0, gens));
    ::X509_REQ_add_extensions (req, exts);
    sk_X509_EXTENSION_pop_free (exts, ::X509_EXTENSION_free);
    sk_GENERAL_NAME_pop_free (gens, ::GENERAL_NAME_free);
    EVP_MD_CTX *const mctx = ::EVP_MD_CTX_new ();
    bool const signed_ok =
      ::EVP_DigestSignInit_ex (mctx, nullptr, "SHA256", nullptr, nullptr, key.get (), nullptr) == 1
      && ::X509_REQ_sign_ctx (req, mctx) > 0;
    ::EVP_MD_CTX_free (mctx);
    std::string csr;
    if (signed_ok)
      {
        BIO *const mem = ::BIO_new (::BIO_s_mem ());
        ::PEM_write_bio_X509_REQ (mem, req);
        char *data = nullptr;
        long const len = BIO_get_mem_data (mem, &data);
        csr.assign (data, static_cast<size_t> (len));
        ::BIO_free (mem);
      }
    ::X509_REQ_free (req);
    if (!signed_ok)
      return refuse ("cannot sign the certificate request with the key: " + ssl_errors ());

    std::string escaped;
    for (char const c : csr)
      escaped += c == '\n' ? std::string ("\\n") : std::string (1, c);
    Response r;
    if (!https_post (url, "/1.0/sign", "{\"csr\":\"" + escaped + "\",\"ott\":\"" + token + "\"}", o.root, "",
                     nullptr, r, error))
      return refuse (error);
    if (r.status != 200 && r.status != 201)
      return refuse (ca_error (r));
    Cert leaf;
    if (!accept_certificate (r, key.get (), o.root, o.out, leaf, error))
      return refuse (error);

    setup_audit (Reason::CERT_ISSUED, {{"subject", subject_of (leaf.get ())}, {"cert_serial", serial_of (leaf.get ())},
                                       {"not_after", asn1_time (::X509_get0_notAfter (leaf.get ()))},
                                       {"ca", o.ca_url}});
    print_certificate (leaf.get (), o.out);
    ACE_OS::printf ("  (leaf, then the intermediate CA)\nSSLIOP: -SSLCertificate PEM:%s -SSLPrivateKey %s\n",
                    o.out.c_str (), o.key.c_str ());
    if (setup_conf_get ("ca_url").empty ())
      ACE_OS::printf ("For renewal, add to the security configuration:\n  ca_url = %s\n  ca_root = %s\n",
                      o.ca_url.c_str (), o.root.c_str ());
    return EXIT_OK;
  }

  int
  cert_renew (int argc, ACE_TCHAR *argv[])
  {
    Cert_Options o;
    if (int const rc = parse_cert_options (argc, argv, o, "cert renew"))
      return rc;
    if (o.cert.empty ())
      return usage (cert_usage, "cert renew: --cert PEM is required");
    if (o.root.empty ())
      return usage (cert_usage, "cert renew: --root PEM is required (or ca_root in the configuration)");
    Url url;
    if (!parse_url (o.ca_url, url))
      return usage (cert_usage, "cert renew: --ca-url https://HOST[:PORT] is required (or ca_url in the configuration)");

    Cert cert = read_cert (o.cert);
    if (!cert)
      return refuse ("cannot read " + o.cert);
    long long const left = seconds_until (::X509_get0_notAfter (cert.get ()));
    long long const life = left - seconds_until (::X509_get0_notBefore (cert.get ()));
    if (left <= 0)
      return refuse (o.cert + " expired " + asn1_time (::X509_get0_notAfter (cert.get ()))
                     + "; renewal needs a valid certificate: get a new token and run cert request");
    if (!o.force && left > life / 3)
      {
        time_t const due = ACE_OS::time (nullptr) + static_cast<time_t> (left - life / 3);
        struct tm tm_buf;
        char buf[32];
        ACE_OS::gmtime_r (&due, &tm_buf);
        ACE_OS::strftime (buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
        ACE_OS::printf ("Not due: %s is valid for %lld more day(s); renewal starts %s (--force renews now).\n",
                        o.cert.c_str (), left / 86400, buf);
        return EXIT_OK;
      }

    std::string password, error;
    if (!o.password_file.empty () && !read_password (o.password_file, password, error))
      return refuse (error);
    PKEY key = load_key (o.key, password, error);
    if (!key)
      return refuse (error);
    if (::EVP_PKEY_eq (::X509_get0_pubkey (cert.get ()), key.get ()) != 1)
      return refuse (o.cert + " is not the certificate for " + o.key);

    Response r;
    if (!https_post (url, "/1.0/renew", "", o.root, o.cert, key.get (), r, error))
      return refuse (error);
    if (r.status != 200 && r.status != 201)
      return refuse (ca_error (r));

    std::string old;
    read_file (o.cert, old);
    std::string const prev = o.cert + ".prev";
    if (!write_atomic (prev, old, 0644, error))
      return refuse (error);
    Cert leaf;
    if (!accept_certificate (r, key.get (), o.root, o.cert, leaf, error))
      return refuse (error);
    setup_audit (Reason::CERT_RENEWED, {{"subject", subject_of (leaf.get ())}, {"cert_serial", serial_of (leaf.get ())},
                                        {"previous_serial", serial_of (cert.get ())},
                                        {"not_after", asn1_time (::X509_get0_notAfter (leaf.get ()))}});
    print_certificate (leaf.get (), o.cert);
    ACE_OS::printf ("  (previous certificate kept as %s; restart the service to use the new one)\n", prev.c_str ());
    return EXIT_OK;
  }
}

bool
setup_read_password (std::string const &path, std::string &out, std::string &error)
{
  return read_password (path, out, error);
}

EVP_PKEY *
setup_load_key (std::string const &spec, std::string const &password, std::string &error)
{
  return load_key (spec, password, error).release ();
}

bool
setup_write_atomic (std::string const &path, std::string const &text, unsigned mode, std::string &error)
{
  return write_atomic (path, text, static_cast<mode_t> (mode), error);
}

int
setup_key (int argc, ACE_TCHAR *argv[])
{
  if (argc < 1)
    return usage (key_usage, "key: give create or check");
  std::string const sub = ACE_TEXT_ALWAYS_CHAR (argv[0]);
  if (sub == "create")
    return key_create (argc - 1, argv + 1);
  if (sub != "check")
    return usage (key_usage, "key: unknown subcommand " + sub);
  std::string spec, password_file, cert;
  for (int i = 1; i < argc; ++i)
    {
      std::string const a = ACE_TEXT_ALWAYS_CHAR (argv[i]);
      bool const more = i + 1 < argc;
      if (a == "--key" && more) spec = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
      else if (a == "--password-file" && more) password_file = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
      else if (a == "--cert" && more) cert = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
      else
        return usage (key_usage, "key check: unknown option " + a);
    }
  if (spec.empty ())
    return usage (key_usage, "key check: --key SPEC is required");
  std::string password, error;
  if (!password_file.empty () && !read_password (password_file, password, error))
    return refuse (error);
  return key_check (spec, password, cert);
}

int
setup_cert (int argc, ACE_TCHAR *argv[])
{
  if (argc < 1)
    return usage (cert_usage, "cert: give request or renew");
  std::string const sub = ACE_TEXT_ALWAYS_CHAR (argv[0]);
  if (sub == "request")
    return cert_request (argc - 1, argv + 1);
  if (sub == "renew")
    return cert_renew (argc - 1, argv + 1);
  return usage (cert_usage, "cert: unknown subcommand " + sub);
}
