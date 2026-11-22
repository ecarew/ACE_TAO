eval '(exit $?0)' && eval 'exec perl -S $0 ${1+"$@"}'
     & eval 'exec perl -S $0 $argv:q'
     if 0;

# -*- perl -*-

use lib "$ENV{ACE_ROOT}/bin";
use PerlACE::TestTarget;

my $test = PerlACE::TestTarget::create_target (1) || die "Create target 1 failed\n";

$TEST = $test->CreateProcess ("audit_test");

my $status = $TEST->SpawnWaitKill ($test->ProcessStartWaitInterval () + 45);

if ($status != 0) {
    print STDERR "ERROR: audit_test returned $status\n";
    exit 1;
}

exit 0;
