// -*- C++ -*-
//
// ace-tao-setup key / cert: service keys in protected storage and
// certificates from a step-ca certificate authority.

#ifndef ACE_TAO_SETUP_KEYS_H
#define ACE_TAO_SETUP_KEYS_H

#include "ace/config-lite.h"
#include "ace/os_include/os_time.h"

#include <map>
#include <string>

/// key create --type file|pkcs11|tpm2|sep ... ; key check --key SPEC ...
int setup_key (int argc, ACE_TCHAR *argv[]);

/// cert request ... ; cert renew ...
int setup_cert (int argc, ACE_TCHAR *argv[]);

/// denylist add|remove|sign|check|pin ... (denylist.cpp)
int setup_denylist (int argc, ACE_TCHAR *argv[]);

/// access sign|check|test ... (access.cpp)
int setup_access (int argc, ACE_TCHAR *argv[]);
/// asserters sign|check ... (access.cpp)
int setup_asserters (int argc, ACE_TCHAR *argv[]);
/// user add|passwd|lock|unlock|remove|list ... (user.cpp)
int setup_user (int argc, ACE_TCHAR *argv[]);

// Shared by keys.cpp, denylist.cpp and access.cpp.
typedef struct evp_pkey_st EVP_PKEY;

/// Reads a password or PIN file as SSLIOP's -SSLPassword file: does.
bool setup_read_password (std::string const &path, std::string &out, std::string &error);

/// Loads the private key named by an SSLIOP -SSLPrivateKey SPEC.
EVP_PKEY *setup_load_key (std::string const &spec, std::string const &password, std::string &error);

/// Writes through a temporary file and rename.
bool setup_write_atomic (std::string const &path, std::string const &text, unsigned mode, std::string &error);

/// Base64 SHA-256 signature of @a text with @a key, newline-terminated (denylist.cpp).
bool setup_sign_text (EVP_PKEY *key, std::string const &text, std::string &b64, std::string &error);

/// A software copy of the public half of @a key (caller frees), or null.
EVP_PKEY *setup_public_key (EVP_PKEY *key);

// Provided by ace_tao_setup.cpp.

/// Writes an audit record for a change (as the other commands do).
void setup_audit (char const *reason, std::map<std::string, std::string> const &fields);

/// A value from the security configuration, or @a fallback.
std::string setup_conf_get (char const *key, char const *fallback = "");
/// @a t (0: now) as UTC YYYY-MM-DDTHH:MM:SSZ.
std::string setup_iso_time (time_t t = 0);

#endif /* ACE_TAO_SETUP_KEYS_H */
