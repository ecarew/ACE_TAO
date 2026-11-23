// -*- C++ -*-
//
// ace-tao-setup install / uninstall / run: service installation with a
// manifest, so that uninstall removes exactly what install created.

#ifndef ACE_TAO_SETUP_INSTALL_H
#define ACE_TAO_SETUP_INSTALL_H

#include "ace/config-lite.h"

/// install [--service naming] [--label-prefix P] [--port N] [--user NAME]
///         [--root DIR] [--bin-dir DIR] [--no-start] [--dry-run]
int setup_install (int argc, ACE_TCHAR *argv[], char const *self);

/// uninstall [--root DIR] [--purge] [--force] [--dry-run]
int setup_uninstall (int argc, ACE_TCHAR *argv[]);

/// run --svc-conf FILE [--conf PATH] -- COMMAND [ARGS...]
/// Gate check for the service, then exec COMMAND (for launchd, which has
/// no ExecStartPre).
int setup_run (int argc, ACE_TCHAR *argv[], char const *self, char const *conf_path);

/// Exit status of "check --gate" for a findings worst-case status.
int setup_gate_status (int worst);

#endif /* ACE_TAO_SETUP_INSTALL_H */
