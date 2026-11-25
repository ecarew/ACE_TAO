#include "orbsvcs/Security/GSSUP_Verifier.h"

#include <atomic>

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  std::atomic<TAO::Security::GSSUP_Verifier *> the_verifier {nullptr};
}

TAO::Security::GSSUP_Verifier::~GSSUP_Verifier () = default;

void
TAO::Security::GSSUP_Verifier::install (GSSUP_Verifier *verifier)
{
  the_verifier.store (verifier);
}

TAO::Security::GSSUP_Verifier *
TAO::Security::GSSUP_Verifier::installed ()
{
  return the_verifier.load ();
}

TAO_END_VERSIONED_NAMESPACE_DECL
