[![Lastest release](https://img.shields.io/github/release/docgroup/ace_tao.svg)](https://github.com/DOCGroup/ACE_TAO/releases/latest)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/4089b696ab6c47ed933ca8d6a6cc6d9b)](https://www.codacy.com/gh/DOCGroup/ACE_TAO/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=DOCGroup/ACE_TAO&amp;utm_campaign=Badge_Grade)
[![Linux CI](https://github.com/DOCGroup/ACE_TAO/actions/workflows/linux.yml/badge.svg)](https://github.com/DOCGroup/ACE_TAO/actions?query=workflow%3Alinux)
[![Windows CI](https://github.com/DOCGroup/ACE_TAO/actions/workflows/windows.yml/badge.svg)](https://github.com/DOCGroup/ACE_TAO/actions?query=workflow%3Awindows)
[![Fuzz CI](https://github.com/DOCGroup/ACE_TAO/actions/workflows/fuzz.yml/badge.svg)](https://github.com/DOCGroup/ACE_TAO/actions?query=workflow%3Afuzz)
[![MacOSX CI](https://github.com/DOCGroup/ACE_TAO/actions/workflows/macosx.yml/badge.svg)](https://github.com/DOCGroup/ACE_TAO/actions?query=workflow%3Amacosx)
[![Face CI](https://github.com/DOCGroup/ACE_TAO/actions/workflows/face.yml/badge.svg)](https://github.com/DOCGroup/ACE_TAO/actions?query=workflow%3Aface)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/1/badge.svg)](https://scan.coverity.com/projects/1)
[![CodeFactor](https://www.codefactor.io/repository/github/docgroup/ace_tao/badge)](https://www.codefactor.io/repository/github/docgroup/ace_tao)

# ACE/TAO #

See [Douglas C. Schmidt website](https://www.cs.wm.edu/~dcschmidt/)  for more information about ACE/TAO. The quality of ACE/TAO is monitored through our distributed [scoreboard](https://www.dre.vanderbilt.edu/scoreboard/)

[ACE](https://www.cs.wm.edu/~dcschmidt/ACE.html) is a C++ framework for implementing distributed and
networked applications, [TAO](https://www.cs.wm.edu/~dcschmidt/TAO.html) is a C++
implementation of the OMG's [CORBA](https://www.omg.org/spec/CORBA/) standard.

All support on github is **best effort**, when you require a guaranteed response consider hiring one of the [commercial companies](https://github.com/DOCGroup/ACE_TAO/wiki/ACE-and-TAO-Commercial-support) who provide support and services for ACE/TAO.

## Changes on this branch (ACE_TAO_Claude)

- **macOS optimized builds:** `optimize=1` now applies `-O2` to C++ code; it was only reaching C.
- **macOS install rpaths:** unquoted absolute library paths stay absolute, so apps built against an installed ACE/TAO find their libraries.
- **macOS listen backlog:** the default is now `SOMAXCONN` instead of 5. macOS resets connections beyond the backlog rather than letting clients retry.
- **OpenSSL 3:** fixed `ACE_SSL_SOCK_Stream` shutdown handling, and `Thread_Pool_Reactor_SSL_Test` now closes TLS sessions cleanly.
- **SSLIOP concurrency:** fixed hangs and crashes when several threads invoke over the same TLS connection.
- **SSLIOP certificate chains:** a PEM `-SSLCertificate` file now sends its intermediate CA certificates too, so peers need only the root CA.
- **ORB invocation retries:** clients no longer retry the next IOR profile after unrelated system exceptions. This removes multi-minute hangs on hosts with several network interfaces (e.g. a VPN).
- **Notification Service:** per-consumer queue limits now work when each consumer has its own delivery thread, and a consumer that leaves no longer leaks its queued events from the channel-wide count. Before, one stalled consumer could make the channel refuse all events permanently.
- **Notification Service event expiry:** queued events past their Timeout (the event's own, or the proxy, admin or channel Timeout QoS) are dropped instead of delivered late. Before, Timeout was ignored on every platform but INTEGRITY. Suppliers that used tiny header Timeouts only as sort keys will now lose those events.
- **CLAUDE.md:** build, test and architecture notes for working on the code base.
