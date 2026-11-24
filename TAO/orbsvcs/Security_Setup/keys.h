// -*- C++ -*-
//
// ace-tao-setup key / cert: service keys in protected storage and
// certificates from a step-ca certificate authority.

#ifndef ACE_TAO_SETUP_KEYS_H
#define ACE_TAO_SETUP_KEYS_H

#include "ace/config-lite.h"

#include <map>
#include <string>

/// key create --type file|pkcs11|tpm2|sep ... ; key check --key SPEC ...
int setup_key (int argc, ACE_TCHAR *argv[]);

/// cert request ... ; cert renew ...
int setup_cert (int argc, ACE_TCHAR *argv[]);

/// denylist add|remove|sign|check|pin ... (denylist.cpp)
int setup_denylist (int argc, ACE_TCHAR *argv[]);

// Shared by keys.cpp and denylist.cpp.
typedef struct evp_pkey_st EVP_PKEY;

/// Reads a password or PIN file as SSLIOP's -SSLPassword file: does.
bool setup_read_password (std::string const &path, std::string &out, std::string &error);

/// Loads the private key named by an SSLIOP -SSLPrivateKey SPEC.
EVP_PKEY *setup_load_key (std::string const &spec, std::string const &password, std::string &error);

/// Writes through a temporary file and rename.
bool setup_write_atomic (std::string const &path, std::string const &text, unsigned mode, std::string &error);

// Provided by ace_tao_setup.cpp.

/// Writes an audit record for a change (as the other commands do).
void setup_audit (char const *reason, std::map<std::string, std::string> const &fields);

/// A value from the security configuration, or @a fallback.
std::string setup_conf_get (char const *key, char const *fallback = "");

#endif /* ACE_TAO_SETUP_KEYS_H */
