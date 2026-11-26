eval '(exit $?0)' && eval 'exec perl -S $0 ${1+"$@"}'
     & eval 'exec perl -S $0 $argv:q'
     if 0;

# -*- perl -*-
#
# Kerberos in SSLIOP (Phase 3 K1): SSLIOP built with the MPC feature
# gssapi links MIT krb5's GSS-API, offers the Kerberos V5 mechanism and
# turns GSS status codes into the library's text; built without it, it
# says so.  Both builds pass.  No KDC is needed (that is K2, with the L1
# lab).

use lib "$ENV{ACE_ROOT}/bin";
use PerlACE::TestTarget;
use Cwd;

my $test = PerlACE::TestTarget::create_target (1) || die "Create target 1 failed\n";
my $dir = getcwd ();
my $status = 0;

sub expect {
    my ($name, $text, $want) = @_;
    my @miss = grep { $text !~ /$_/m } @$want;
    if (@miss) {
        print STDERR "ERROR: $name\n  missing: " . join ("\n  missing: ", @miss) . "\n  output:\n$text\n";
        $status = 1;
    } else {
        print "ok: $name\n";
    }
}

my $out = `$dir/krb_probe 2>&1`;
my $rc = $? >> 8;
expect ('krb_probe reports a consistent build', "$out\nrc=$rc", ['^rc=0$']);
expect ('the Kerberos V5 mechanism OID is 1.2.840.113554.1.2.2', $out, ['^mech_der=06092a864886f712010202$']);
if ($out =~ /^built=1$/m) {
    expect ('built with GSS-API: the library offers Kerberos V5', $out, ['^offered=1 Kerberos V5 mechanism offered$']);
    expect ('  ... and gives GSS status text', $out, ['^status_text=\S']);
} else {
    expect ('built without GSS-API: it says so', $out,
            ['^offered=0 SSLIOP was built without GSS-API', '^status_text=GSS-API not built$']);
}

exit $status;
