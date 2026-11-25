#include "orbsvcs/SSLIOP/SSLIOP_GSSUP_Store.h"
#include "orbsvcs/SSLIOP/SSLIOP_Signed_File.h"

#include "orbsvcs/Security/Audit_Logger.h"
#include "tao/Security_Mode.h"

#include "ace/Guard_T.h"
#include "ace/OS_NS_stdio.h"
#include "ace/OS_NS_stdlib.h"
#include "ace/OS_NS_sys_stat.h"
#include "ace/OS_NS_unistd.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <cstdint>
#include <sstream>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  namespace Reason = TAO::Security::Audit_Reason;
  namespace Signed_File = TAO::SSLIOP::Signed_File;
  using Store = TAO::SSLIOP::GSSUP_Store;

  constexpr size_t SALT_BYTES = 16;
  constexpr size_t HASH_BYTES = 32;

  /// Above this many tracked users or hosts, entries with nothing
  /// recent are dropped; at the hard cap new ones are not tracked (the
  /// per-host limit still applies to the hosts already tracked).
  constexpr size_t TRACK_PRUNE = 4096;
  constexpr size_t TRACK_CAP = 65536;

  std::string
  b64 (std::string const &raw)
  {
    std::string out (4 * ((raw.size () + 2) / 3) + 1, '\0');
    int const n = ::EVP_EncodeBlock (reinterpret_cast<unsigned char *> (&out[0]),
                                     reinterpret_cast<unsigned char const *> (raw.data ()),
                                     static_cast<int> (raw.size ()));
    out.resize (n > 0 ? static_cast<size_t> (n) : 0);
    return out;
  }

  bool
  unb64 (std::string const &text, std::string &out)
  {
    if (text.empty () || text.size () % 4 != 0)
      return false;
    out.assign (3 * text.size () / 4, '\0');
    int const n = ::EVP_DecodeBlock (reinterpret_cast<unsigned char *> (&out[0]),
                                     reinterpret_cast<unsigned char const *> (text.data ()),
                                     static_cast<int> (text.size ()));
    if (n < 0)
      return false;
    size_t pad = 0;
    for (size_t i = text.size (); i > 0 && text[i - 1] == '='; --i)
      ++pad;
    out.resize (static_cast<size_t> (n) - pad);
    return true;
  }

  bool
  params_ok (Store::Params const &p)
  {
    if (p.log2n < 10 || p.log2n > 22 || p.r < 1 || p.r > 32 || p.p < 1 || p.p > 16)
      return false;
    // At most 1 GiB of scrypt memory.
    return 128ULL * p.r * ((1ULL << p.log2n) + 2) * p.p <= (1ULL << 30);
  }

  bool
  scrypt (std::string const &password, std::string const &salt, Store::Params const &p, std::string &out)
  {
    if (!params_ok (p))
      return false;
    EVP_KDF *const kdf = ::EVP_KDF_fetch (nullptr, "SCRYPT", nullptr);
    if (kdf == nullptr)
      return false;
    EVP_KDF_CTX *const ctx = ::EVP_KDF_CTX_new (kdf);
    ::EVP_KDF_free (kdf);
    if (ctx == nullptr)
      return false;
    uint64_t n = 1ULL << p.log2n;
    uint32_t r = p.r;
    uint32_t pp = p.p;
    uint64_t maxmem = 128ULL * p.r * (n + 2) + 128ULL * p.r * p.p + (1ULL << 20);
    OSSL_PARAM params[] = {
      ::OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_PASSWORD, const_cast<char *> (password.data ()),
                                           password.size ()),
      ::OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_SALT, const_cast<char *> (salt.data ()), salt.size ()),
      ::OSSL_PARAM_construct_uint64 (OSSL_KDF_PARAM_SCRYPT_N, &n),
      ::OSSL_PARAM_construct_uint32 (OSSL_KDF_PARAM_SCRYPT_R, &r),
      ::OSSL_PARAM_construct_uint32 (OSSL_KDF_PARAM_SCRYPT_P, &pp),
      ::OSSL_PARAM_construct_uint64 (OSSL_KDF_PARAM_SCRYPT_MAXMEM, &maxmem),
      ::OSSL_PARAM_construct_end ()};
    out.assign (HASH_BYTES, '\0');
    bool const ok = ::EVP_KDF_derive (ctx, reinterpret_cast<unsigned char *> (&out[0]), out.size (), params) == 1;
    ::EVP_KDF_CTX_free (ctx);
    if (!ok)
      out.clear ();
    return ok;
  }

  bool
  number (std::string const &s, unsigned &out)
  {
    if (s.empty () || s.size () > 4 || s.find_first_not_of ("0123456789") != std::string::npos)
      return false;
    out = static_cast<unsigned> (ACE_OS::atoi (s.c_str ()));
    return true;
  }

  std::vector<std::string>
  split (std::string const &s, char sep)
  {
    std::vector<std::string> out;
    size_t p = 0;
    for (;;)
      {
        size_t const c = s.find (sep, p);
        out.push_back (s.substr (p, c == std::string::npos ? std::string::npos : c - p));
        if (c == std::string::npos)
          return out;
        p = c + 1;
      }
  }

  /// The host part of "host:port" or "[v6]:port".
  std::string
  host_of (std::string const &source)
  {
    if (!source.empty () && source[0] == '[')
      {
        size_t const close = source.find (']');
        return close == std::string::npos ? source : source.substr (0, close + 1);
      }
    size_t const colon = source.rfind (':');
    return colon == std::string::npos ? source : source.substr (0, colon);
  }

  /// Device, inode, modification time, size, mode and owner: a store
  /// replaced by rename always gets a new inode, so a change is seen even
  /// within the same second and at the same size; a chmod or chown is
  /// seen too, so loosened permissions are refused in prod at once.
  std::string
  file_stamp (std::string const &path)
  {
    ACE_stat st;
    if (ACE_OS::stat (path.c_str (), &st) != 0)
      return "-";
    return std::to_string (static_cast<long long> (st.st_dev)) + ":"
           + std::to_string (static_cast<long long> (st.st_ino)) + ":"
           + std::to_string (static_cast<long long> (st.st_mtime)) + ":"
           + std::to_string (static_cast<long long> (st.st_size)) + ":"
           + std::to_string (static_cast<long long> (st.st_mode)) + ":"
           + std::to_string (static_cast<long long> (st.st_uid));
  }

  /// An entry no password matches, for unknown users: same cost.
  Store::Entry const &
  decoy ()
  {
    static Store::Entry const e = [] {
      Store::Entry d;
      d.user = "-";
      unsigned char random[32];
      ::RAND_bytes (random, sizeof random);
      std::string const pw (reinterpret_cast<char const *> (random), sizeof random);
      std::string error;
      Store::make_entry ("decoy", pw, Store::Params (), d, error);
      d.user = "-";
      return d;
    } ();
    return e;
  }

  void
  audit_store (bool ok, char const *reason, std::string const &path, std::string const &text)
  {
    TAO::Security::Audit_Logger::instance ()->write (
      TAO::Security::Audit_Record ("config", ok, reason).field ("file", path).text (text.c_str ()));
  }
}

bool
Store::valid_user (std::string const &user)
{
  if (user.empty () || user.size () > 64)
    return false;
  for (char const c : user)
    {
      bool const ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.'
                      || c == '_' || c == '-';
      if (!ok)
        return false;
    }
  return true;
}

bool
Store::parse (std::string const &text, std::vector<Entry> &out, std::string &error)
{
  out.clear ();
  std::istringstream in (text);
  std::string raw;
  int line_no = 0;
  while (std::getline (in, raw))
    {
      ++line_no;
      std::string const line = Signed_File::trim (raw);
      if (line.empty () || line[0] == '#')
        continue;
      std::istringstream fields (line);
      std::string user, cred, state, extra;
      fields >> user >> cred >> state;
      std::string const where = "line " + std::to_string (line_no) + ": ";
      if (state.empty () || (fields >> extra))
        {
          error = where + "want USER scrypt:LOG2N:R:P:SALT:HASH active|locked";
          return false;
        }
      if (!valid_user (user))
        {
          error = where + "bad user name (1 to 64 of A-Z a-z 0-9 . _ -)";
          return false;
        }
      Entry e;
      e.user = user;
      std::vector<std::string> const c = split (cred, ':');
      if (c.size () != 6 || c[0] != "scrypt" || !number (c[1], e.params.log2n) || !number (c[2], e.params.r)
          || !number (c[3], e.params.p) || !params_ok (e.params) || !unb64 (c[4], e.salt) || !unb64 (c[5], e.hash)
          || e.salt.size () < 8 || e.hash.size () != HASH_BYTES)
        {
          error = where + "bad credential for " + user;
          return false;
        }
      if (state == "locked")
        e.locked = true;
      else if (state != "active")
        {
          error = where + "state must be active or locked";
          return false;
        }
      for (Entry const &o : out)
        if (o.user == user)
          {
            error = where + "user " + user + " appears twice";
            return false;
          }
      out.push_back (e);
    }
  return true;
}

std::string
Store::format (std::vector<Entry> const &entries)
{
  std::string s = "# ace-tao GSSUP password store; maintained by \"ace-tao-setup user\".\n"
                  "# USER scrypt:LOG2N:R:P:SALT:HASH active|locked\n";
  for (Entry const &e : entries)
    s += e.user + " scrypt:" + std::to_string (e.params.log2n) + ":" + std::to_string (e.params.r) + ":"
         + std::to_string (e.params.p) + ":" + b64 (e.salt) + ":" + b64 (e.hash) + (e.locked ? " locked\n" : " active\n");
  return s;
}

bool
Store::make_entry (std::string const &user, std::string const &password, Params const &params, Entry &out,
                   std::string &error)
{
  if (!params_ok (params))
    {
      error = "scrypt parameters out of range";
      return false;
    }
  out = Entry ();
  out.user = user;
  out.params = params;
  out.salt.assign (SALT_BYTES, '\0');
  if (::RAND_bytes (reinterpret_cast<unsigned char *> (&out.salt[0]), static_cast<int> (SALT_BYTES)) != 1)
    {
      error = "no random bytes for the salt";
      return false;
    }
  if (!scrypt (password, out.salt, params, out.hash))
    {
      error = "scrypt failed: " + Signed_File::ssl_error ();
      return false;
    }
  return true;
}

bool
Store::matches (Entry const &entry, std::string const &password)
{
  std::string h;
  if (!scrypt (password, entry.salt, entry.params, h) || h.size () != entry.hash.size ())
    return false;
  bool const same = ::CRYPTO_memcmp (h.data (), entry.hash.data (), h.size ()) == 0;
  ::OPENSSL_cleanse (&h[0], h.size ());
  return same;
}

bool
Store::check_file (std::string const &path, bool prod, std::string &error)
{
  ACE_stat st;
  if (ACE_OS::stat (path.c_str (), &st) != 0)
    {
      error = "cannot read " + path;
      return false;
    }
#if !defined (ACE_WIN32)
  if (prod && (st.st_mode & 077) != 0)
    {
      char mode[8];
      ACE_OS::snprintf (mode, sizeof mode, "%04o", static_cast<unsigned> (st.st_mode & 07777));
      error = path + " is mode " + mode + " (want 0600 or 0400)";
      return false;
    }
  if (prod && st.st_uid != ACE_OS::geteuid ())
    {
      error = path + " is owned by uid " + std::to_string (static_cast<long> (st.st_uid)) + ", not this service (uid "
              + std::to_string (static_cast<long> (ACE_OS::geteuid ())) + ")";
      return false;
    }
#else
  ACE_UNUSED_ARG (prod);
#endif
  return true;
}

Store *
Store::instance ()
{
  static Store store;
  return &store;
}

Store::GSSUP_Store ()
{
  TAO_Security_Mode::Host_Config const &h = TAO_Security_Mode::host ();
  this->path_ = h.get ("gssup_store");
  this->prod_ = h.mode == TAO_Security_Mode::MODE_PROD;
  auto positive = [&h] (char const *key, long fallback) {
    long const v = ACE_OS::atoi (h.get (key, std::to_string (fallback).c_str ()).c_str ());
    return v > 0 ? v : fallback;
  };
  this->max_failures_ = static_cast<unsigned> (positive ("gssup_max_failures", 10));
  this->source_max_failures_ = static_cast<unsigned> (positive ("gssup_source_max_failures", 50));
  this->window_ = std::chrono::seconds (positive ("gssup_failure_window", 900));
  this->lockout_ = std::chrono::seconds (positive ("gssup_lockout", 1800));
}

bool
Store::read (std::map<std::string, Entry> &out, std::string &error) const
{
  if (!check_file (this->path_, this->prod_, error))
    return false;
  std::string text;
  if (!Signed_File::slurp (this->path_, text))
    {
      error = "cannot read " + this->path_;
      return false;
    }
  std::vector<Entry> entries;
  bool const ok = parse (text, entries, error);
  if (!text.empty ())
    ::OPENSSL_cleanse (&text[0], text.size ());
  if (!ok)
    {
      error = this->path_ + ": " + error;
      return false;
    }
  out.clear ();
  for (Entry &e : entries)
    out[e.user] = e;
  return true;
}

void
Store::refresh_i (Clock::time_point now)
{
  if (this->users_ && now - this->last_check_ < std::chrono::seconds (1))
    return;
  this->last_check_ = now;
  std::string const stamp = file_stamp (this->path_);
  if (stamp == this->stamp_ && (this->users_ || !this->load_error_.empty ()))
    return;
  this->stamp_ = stamp;
  auto fresh = std::make_shared<std::map<std::string, Entry>> ();
  std::string error;
  if (this->read (*fresh, error))
    {
      this->users_ = fresh;
      this->load_error_.clear ();
      audit_store (true, Reason::GSSUP_STORE_LOADED, this->path_, std::to_string (fresh->size ()) + " user(s)");
    }
  else
    {
      // Fail closed: no store, no logins.
      this->users_.reset ();
      this->load_error_ = error;
      audit_store (false, Reason::GSSUP_STORE_REJECTED, this->path_, error + "; every GSSUP login is refused");
    }
}

bool
Store::load (std::string &summary)
{
  ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, false);
  this->stamp_.clear ();
  this->users_.reset ();
  this->load_error_.clear ();
  this->refresh_i (Clock::now ());
  if (!this->users_)
    {
      summary = this->load_error_;
      return false;
    }
  size_t locked = 0;
  for (auto const &u : *this->users_)
    if (u.second.locked)
      ++locked;
  summary = std::to_string (this->users_->size ()) + " user(s), " + std::to_string (locked) + " locked; lockout after "
            + std::to_string (this->max_failures_) + " failure(s) in " + std::to_string (this->window_.count ())
            + " s for " + std::to_string (this->lockout_.count ()) + " s";
  return true;
}

bool
Store::locked_i (Track &t, Clock::time_point now) const
{
  while (!t.failures.empty () && now - t.failures.front () > this->window_)
    t.failures.pop_front ();
  return now < t.locked_until;
}

bool
Store::fail_i (Track &t, Clock::time_point now, unsigned max) const
{
  t.failures.push_back (now);
  if (t.failures.size () >= max && now >= t.locked_until)
    {
      t.locked_until = now + this->lockout_;
      t.failures.clear ();
      return true;
    }
  return false;
}

void
Store::prune_i (Clock::time_point now)
{
  for (auto *m : {&this->by_user_, &this->by_source_})
    {
      if (m->size () < TRACK_PRUNE)
        continue;
      for (auto i = m->begin (); i != m->end ();)
        {
          bool const locked = this->locked_i (i->second, now);
          if (!locked && i->second.failures.empty ())
            i = m->erase (i);
          else
            ++i;
        }
    }
}

void
Store::reset_limits ()
{
  ACE_GUARD (TAO_SYNCH_MUTEX, guard, this->lock_);
  this->by_user_.clear ();
  this->by_source_.clear ();
}

TAO::Security::GSSUP_Verifier::Result
Store::verify (std::string const &user, std::string const &password, std::string const &, std::string const &source,
               std::string &detail)
{
  Clock::time_point const now = Clock::now ();
  std::string const host = host_of (source);
  Entry entry;
  bool known = false;
  {
    ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, UNAVAILABLE);
    this->refresh_i (now);
    if (!this->users_)
      {
        detail = "GSSUP store unusable: " + this->load_error_;
        return UNAVAILABLE;
      }
    this->prune_i (now);
    auto const s = this->by_source_.find (host);
    if (s != this->by_source_.end () && this->locked_i (s->second, now))
      {
        detail = "too many failed logins from " + host;
        return RATE_LIMITED;
      }
    auto const u = this->by_user_.find (user);
    if (u != this->by_user_.end () && this->locked_i (u->second, now))
      {
        detail = "user locked after repeated failures";
        return LOCKED;
      }
    auto const e = this->users_->find (user);
    known = e != this->users_->end ();
    entry = known ? e->second : decoy ();
  }

  // The expensive part, outside the lock.  Unknown and locked users pay
  // the same scrypt as a wrong password.
  bool const right = this->matches (entry, password) && known && !entry.locked;

  ACE_GUARD_RETURN (TAO_SYNCH_MUTEX, guard, this->lock_, UNAVAILABLE);
  if (right)
    {
      this->by_user_.erase (user);
      return ACCEPTED;
    }
  bool user_locked = false, source_limited = false;
  if (this->by_user_.size () < TRACK_CAP || this->by_user_.count (user) != 0)
    user_locked = this->fail_i (this->by_user_[user], now, this->max_failures_);
  if (this->by_source_.size () < TRACK_CAP || this->by_source_.count (host) != 0)
    source_limited = this->fail_i (this->by_source_[host], now, this->source_max_failures_);
  if (user_locked)
    {
      detail = "lockout began: " + std::to_string (this->max_failures_) + " failure(s) within "
               + std::to_string (this->window_.count ()) + " s; locked for " + std::to_string (this->lockout_.count ())
               + " s";
      return LOCKED;
    }
  if (source_limited)
    {
      detail = "rate limit began for " + host + ": " + std::to_string (this->source_max_failures_)
               + " failure(s) within " + std::to_string (this->window_.count ()) + " s";
      return RATE_LIMITED;
    }
  detail = !known ? "unknown user" : entry.locked ? "user locked by an administrator" : "wrong password";
  return REJECTED;
}

TAO_END_VERSIONED_NAMESPACE_DECL
