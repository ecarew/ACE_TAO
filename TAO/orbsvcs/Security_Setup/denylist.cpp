// ace-tao-setup denylist: maintain and sign the deny-list that SSLIOP
// services check at each handshake and request (see
// orbsvcs/SSLIOP/SSLIOP_Deny_List.h for the format and the
// security.conf keys).
//
//   denylist add    --key SPEC [--password-file F] [--file LIST] (--serial HEX | --spiffe ID | --cert PEM)...
//   denylist remove --key SPEC [--password-file F] [--file LIST] (--serial HEX | --spiffe ID | --cert PEM)...
//   denylist sign   --key SPEC [--password-file F] [--file LIST]
//   denylist check  [--file LIST] [--signer PEM]
//   denylist pin    (--signer PEM | --key SPEC [--password-file F])
//
// add and remove rewrite the list with the next version and the current
// time, then sign it (LIST.sig) with the signing key, which may live in a
// keystore.  They refuse to extend a list whose current signature is not
// from the same key (--force overrides).  sign signs a list edited by
// hand.  check verifies a list as a service would.  pin prints the
// SHA-256 to put in denylist_signer_sha256.  LIST defaults to denylist in
// the security configuration, the signer to denylist_signer.

#include "keys.h"

#include "orbsvcs/SSLIOP/SSLIOP_Deny_List.h"
#include "orbsvcs/Security/Audit_Logger.h"

#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_string.h"
#include "ace/OS_NS_sys_stat.h"
#include "ace/OS_NS_time.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <set>
#include <vector>

using TAO::SSLIOP::Deny_List;
namespace Reason = TAO::Security::Audit_Reason;

namespace
{
  constexpr int EXIT_OK = 0;
  constexpr int EXIT_FAIL = 2;
  constexpr int EXIT_USAGE = 64;

  char const usage_text[] =
    "usage: ace-tao-setup denylist add    --key SPEC [--password-file F] [--file LIST]\n"
    "                                     (--serial HEX | --spiffe ID | --cert PEM)... [--force]\n"
    "       ace-tao-setup denylist remove --key SPEC [--password-file F] [--file LIST]\n"
    "                                     (--serial HEX | --spiffe ID | --cert PEM)... [--force]\n"
    "       ace-tao-setup denylist sign   --key SPEC [--password-file F] [--file LIST]\n"
    "       ace-tao-setup denylist check  [--file LIST] [--signer PEM]\n"
    "       ace-tao-setup denylist pin    (--signer PEM | --key SPEC [--password-file F])\n"
    "  LIST defaults to denylist in the security configuration, PEM to denylist_signer.\n"
    "  The list is signed into LIST.sig; SPEC is a key as SSLIOP -SSLPrivateKey takes it.\n";

  int
  usage (std::string const &problem)
  {
    if (!problem.empty ())
      ACE_OS::fprintf (stderr, "ace-tao-setup: %s\n", problem.c_str ());
    ACE_OS::fputs (usage_text, stderr);
    return EXIT_USAGE;
  }

  int
  refuse (std::string const &why)
  {
    ACE_OS::fprintf (stderr, "ace-tao-setup: %s\n", why.c_str ());
    return EXIT_FAIL;
  }

  struct Free_PKEY { void operator() (EVP_PKEY *p) const { ::EVP_PKEY_free (p); } };
  using PKEY = std::unique_ptr<EVP_PKEY, Free_PKEY>;

  bool
  slurp (std::string const &path, std::string &out)
  {
    FILE *const fp = ACE_OS::fopen (path.c_str (), ACE_TEXT ("rb"));
    if (fp == nullptr)
      return false;
    out.clear ();
    char buf[4096];
    size_t n;
    while ((n = ACE_OS::fread (buf, 1, sizeof buf, fp)) > 0)
      out.append (buf, n);
    ACE_OS::fclose (fp);
    return true;
  }

  bool
  exists (std::string const &path)
  {
    ACE_stat st;
    return ACE_OS::stat (path.c_str (), &st) == 0;
  }

  std::string
  now_iso ()
  {
    time_t const t = ACE_OS::time (nullptr);
    struct tm tm_buf;
    char buf[32];
    ACE_OS::gmtime_r (&t, &tm_buf);
    ACE_OS::strftime (buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return buf;
  }

  /// Base64 signature (SHA-256) of @a text with @a key, where the key lives.
  bool
  sign (EVP_PKEY *key, std::string const &text, std::string &b64, std::string &error)
  {
    std::vector<unsigned char> sig (1024);
    size_t len = sig.size ();
    EVP_MD_CTX *const ctx = ::EVP_MD_CTX_new ();
    bool const ok = ::EVP_DigestSignInit_ex (ctx, nullptr, "SHA256", nullptr, nullptr, key, nullptr) == 1
                    && ::EVP_DigestSign (ctx, sig.data (), &len,
                                         reinterpret_cast<unsigned char const *> (text.data ()), text.size ()) == 1;
    ::EVP_MD_CTX_free (ctx);
    if (!ok)
      {
        char buf[256];
        ::ERR_error_string_n (::ERR_get_error (), buf, sizeof buf);
        error = std::string ("cannot sign with the key: ") + buf;
        ::ERR_clear_error ();
        return false;
      }
    std::vector<unsigned char> out (4 * ((len + 2) / 3) + 1);
    int const n = ::EVP_EncodeBlock (out.data (), sig.data (), static_cast<int> (len));
    b64.assign (reinterpret_cast<char *> (out.data ()), static_cast<size_t> (n));
    b64 += '\n';
    return true;
  }

  /// The public half of @a key as a software key, for verifying.
  PKEY
  public_copy (EVP_PKEY *key)
  {
    unsigned char *der = nullptr;
    int const len = ::i2d_PUBKEY (key, &der);
    if (len <= 0)
      return PKEY ();
    unsigned char const *p = der;
    PKEY pub (::d2i_PUBKEY (nullptr, &p, len));
    ::OPENSSL_free (der);
    return pub;
  }

  std::string
  serialize (Deny_List::Content const &c)
  {
    std::string s = "# ace-tao deny-list, written by ace-tao-setup denylist\n";
    s += "version " + std::to_string (c.version) + "\n";
    s += "issued " + c.issued + "\n";
    for (auto const &x : c.serials)
      s += "serial " + x + "\n";
    for (auto const &x : c.spiffe)
      s += "spiffe " + x + "\n";
    return s;
  }

  struct Options
  {
    std::string file, key, password_file, signer;
    std::vector<std::string> serials, spiffe, certs;
    bool force = false;
  };

  int
  parse (int argc, ACE_TCHAR *argv[], Options &o, std::string const &cmd)
  {
    for (int i = 0; i < argc; ++i)
      {
        std::string const a = ACE_TEXT_ALWAYS_CHAR (argv[i]);
        bool const more = i + 1 < argc;
        if (a == "--file" && more) o.file = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--key" && more) o.key = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--password-file" && more) o.password_file = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--signer" && more) o.signer = ACE_TEXT_ALWAYS_CHAR (argv[++i]);
        else if (a == "--serial" && more) o.serials.push_back (ACE_TEXT_ALWAYS_CHAR (argv[++i]));
        else if (a == "--spiffe" && more) o.spiffe.push_back (ACE_TEXT_ALWAYS_CHAR (argv[++i]));
        else if (a == "--cert" && more) o.certs.push_back (ACE_TEXT_ALWAYS_CHAR (argv[++i]));
        else if (a == "--force") o.force = true;
        else
          return usage ("denylist " + cmd + ": unknown option " + a);
      }
    if (o.file.empty ())
      o.file = setup_conf_get ("denylist");
    if (o.signer.empty ())
      o.signer = setup_conf_get ("denylist_signer");
    return EXIT_OK;
  }

  PKEY
  signing_key (Options const &o, std::string &error)
  {
    std::string password;
    if (!o.password_file.empty () && !setup_read_password (o.password_file, password, error))
      return PKEY ();
    return PKEY (setup_load_key (o.key, password, error));
  }

  /// Signs @a text with @a key and writes LIST.sig, then LIST.
  int
  publish (Options const &o, EVP_PKEY *key, std::string const &text, Deny_List::Content const &c, char const *what)
  {
    std::string sig, error;
    if (!sign (key, text, sig, error))
      return refuse (error);
    PKEY pub = public_copy (key);
    if (!pub || !Deny_List::verify (text, sig, pub.get (), error))
      return refuse ("the new signature does not verify: " + error);
    if (!setup_write_atomic (o.file + ".sig", sig, 0644, error) || !setup_write_atomic (o.file, text, 0644, error))
      return refuse (error);
    setup_audit (Reason::DENYLIST_SIGNED, {{"file", o.file}, {"version", std::to_string (c.version)},
                                           {"serials", std::to_string (c.serials.size ())},
                                           {"spiffe_ids", std::to_string (c.spiffe.size ())},
                                           {"change", what}});
    ACE_OS::printf ("%s: version %ld issued %s, %zu serial(s), %zu SPIFFE ID(s); signed into %s.sig\n",
                    o.file.c_str (), c.version, c.issued.c_str (), c.serials.size (), c.spiffe.size (), o.file.c_str ());
    ACE_OS::printf ("Signer pin (denylist_signer_sha256): %s\n", Deny_List::spki_sha256 (key).c_str ());
    return EXIT_OK;
  }

  int
  cmd_change (int argc, ACE_TCHAR *argv[], bool add)
  {
    char const *const cmd = add ? "add" : "remove";
    Options o;
    if (int const rc = parse (argc, argv, o, cmd))
      return rc;
    if (o.file.empty () || o.key.empty ())
      return usage (std::string ("denylist ") + cmd + ": --file (or denylist in the configuration) and --key are required");
    if (o.serials.empty () && o.spiffe.empty () && o.certs.empty ())
      return usage (std::string ("denylist ") + cmd + ": give --serial, --spiffe or --cert");

    std::set<std::string> serials, spiffe;
    for (auto const &s : o.serials)
      {
        std::string const n = Deny_List::normalize_serial (s);
        if (n.empty () || n.find_first_not_of ("0123456789ABCDEF") != std::string::npos)
          return refuse ("not a hexadecimal serial: " + s);
        serials.insert (n);
      }
    for (auto const &s : o.spiffe)
      {
        if (s.compare (0, 9, "spiffe://") != 0)
          return refuse ("not a spiffe:// URI: " + s);
        spiffe.insert (s);
      }
    for (auto const &path : o.certs)
      {
        BIO *const b = ::BIO_new_file (path.c_str (), "r");
        X509 *const x = b ? ::PEM_read_bio_X509 (b, nullptr, nullptr, nullptr) : nullptr;
        ::BIO_free (b);
        ::ERR_clear_error ();
        if (x == nullptr)
          return refuse ("cannot read the certificate " + path);
        // A certificate is listed by serial: renewing gives a new serial,
        // so list its SPIFFE ID (--spiffe) to refuse the identity itself.
        serials.insert (Deny_List::serial_of (x));
        ::X509_free (x);
      }

    std::string error;
    PKEY key = signing_key (o, error);
    if (!key)
      return refuse (error);

    Deny_List::Content c;
    if (exists (o.file))
      {
        std::string text, sig;
        if (!slurp (o.file, text))
          return refuse ("cannot read " + o.file);
        if (!Deny_List::parse (text, c, error))
          return refuse (o.file + ": " + error);
        PKEY pub = public_copy (key.get ());
        bool const signed_by_us = slurp (o.file + ".sig", sig) && pub && Deny_List::verify (text, sig, pub.get (), error);
        if (!signed_by_us && !o.force)
          return refuse (o.file + " is not signed by this key or was changed since it was signed "
                         "(check it, then --force)");
      }
    else if (!add)
      return refuse (o.file + " does not exist");

    size_t changed = 0;
    for (auto const &s : serials)
      changed += add ? c.serials.insert (s).second : c.serials.erase (s);
    for (auto const &s : spiffe)
      changed += add ? c.spiffe.insert (s).second : c.spiffe.erase (s);
    if (changed == 0)
      {
        ACE_OS::printf ("No change: %s already %s.\n", o.file.c_str (),
                        add ? "lists every entry given" : "lists none of the entries given");
        return EXIT_OK;
      }
    c.version += 1;
    c.issued = now_iso ();
    return publish (o, key.get (), serialize (c), c, cmd);
  }

  int
  cmd_sign (int argc, ACE_TCHAR *argv[])
  {
    Options o;
    if (int const rc = parse (argc, argv, o, "sign"))
      return rc;
    if (o.file.empty () || o.key.empty ())
      return usage ("denylist sign: --file (or denylist in the configuration) and --key are required");
    std::string text, error;
    if (!slurp (o.file, text))
      return refuse ("cannot read " + o.file);
    Deny_List::Content c;
    if (!Deny_List::parse (text, c, error))
      return refuse (o.file + ": " + error);
    PKEY key = signing_key (o, error);
    if (!key)
      return refuse (error);
    return publish (o, key.get (), text, c, "sign");
  }

  int
  cmd_check (int argc, ACE_TCHAR *argv[])
  {
    Options o;
    if (int const rc = parse (argc, argv, o, "check"))
      return rc;
    if (o.file.empty () || o.signer.empty ())
      return usage ("denylist check: --file and --signer are required (or denylist and denylist_signer)");
    std::string text, sig, error;
    if (!slurp (o.file, text))
      return refuse ("cannot read " + o.file);
    if (!slurp (o.file + ".sig", sig))
      return refuse ("cannot read " + o.file + ".sig");
    PKEY signer (Deny_List::load_signer (o.signer.c_str (), error));
    if (!signer)
      return refuse (error);
    std::string const pin = Deny_List::spki_sha256 (signer.get ());
    std::string want = setup_conf_get ("denylist_signer_sha256");
    for (char &ch : want)
      ch = static_cast<char> (::tolower (static_cast<unsigned char> (ch)));
    if (!want.empty () && want != pin)
      return refuse (o.signer + " is not the pinned signer (denylist_signer_sha256 " + want + ")");
    if (!Deny_List::verify (text, sig, signer.get (), error))
      return refuse (o.file + ": " + error);
    Deny_List::Content c;
    if (!Deny_List::parse (text, c, error))
      return refuse (o.file + ": " + error);
    long const age = static_cast<long> ((ACE_OS::time (nullptr) - c.issued_time) / 86400);
    ACE_OS::printf ("OK: %s version %ld issued %s (%ld day(s) ago), %zu serial(s), %zu SPIFFE ID(s)\n",
                    o.file.c_str (), c.version, c.issued.c_str (), age, c.serials.size (), c.spiffe.size ());
    ACE_OS::printf ("Signer %s, sha256 %s%s\n", o.signer.c_str (), pin.c_str (),
                    want.empty () ? " (not pinned: set denylist_signer_sha256)" : " (pinned)");
    for (auto const &x : c.serials)
      ACE_OS::printf ("  serial %s\n", x.c_str ());
    for (auto const &x : c.spiffe)
      ACE_OS::printf ("  spiffe %s\n", x.c_str ());
    return EXIT_OK;
  }

  int
  cmd_pin (int argc, ACE_TCHAR *argv[])
  {
    Options o;
    if (int const rc = parse (argc, argv, o, "pin"))
      return rc;
    std::string error;
    PKEY key;
    std::string signer_arg;
    for (int i = 0; i < argc; ++i)
      if (ACE_OS::strcmp (ACE_TEXT_ALWAYS_CHAR (argv[i]), "--signer") == 0)
        signer_arg = o.signer;
    if (!o.key.empty ())
      key = signing_key (o, error);
    else if (!signer_arg.empty ())
      key.reset (Deny_List::load_signer (signer_arg.c_str (), error));
    else
      return usage ("denylist pin: give --signer PEM or --key SPEC");
    if (!key)
      return refuse (error);
    ACE_OS::printf ("denylist_signer_sha256 = %s\n", Deny_List::spki_sha256 (key.get ()).c_str ());
    if (!o.key.empty ())
      {
        // The public key, for denylist_signer on the services.
        BIO *const mem = ::BIO_new (::BIO_s_mem ());
        ::PEM_write_bio_PUBKEY (mem, key.get ());
        char *data = nullptr;
        long const len = BIO_get_mem_data (mem, &data);
        ACE_OS::printf ("%.*s", static_cast<int> (len), data);
        ::BIO_free (mem);
      }
    return EXIT_OK;
  }
}

int
setup_denylist (int argc, ACE_TCHAR *argv[])
{
  if (argc < 1)
    return usage ("denylist: give add, remove, sign, check or pin");
  std::string const sub = ACE_TEXT_ALWAYS_CHAR (argv[0]);
  if (sub == "add")
    return cmd_change (argc - 1, argv + 1, true);
  if (sub == "remove")
    return cmd_change (argc - 1, argv + 1, false);
  if (sub == "sign")
    return cmd_sign (argc - 1, argv + 1);
  if (sub == "check")
    return cmd_check (argc - 1, argv + 1);
  if (sub == "pin")
    return cmd_pin (argc - 1, argv + 1);
  return usage ("denylist: unknown subcommand " + sub);
}
