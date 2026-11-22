eval '(exit $?0)' && eval 'exec perl -S $0 ${1+"$@"}'
     & eval 'exec perl -S $0 $argv:q'
     if 0;

# -*- perl -*-
#
# ace-tao-setup (orbsvcs/Security_Setup): init, check, enroll, set-mode,
# unenroll, against a configuration and enrollment marker in a scratch
# directory.  Certificates come from ../Mode.

use lib "$ENV{ACE_ROOT}/bin";
use PerlACE::TestTarget;
use Cwd;
use File::Path qw(rmtree);

my $test = PerlACE::TestTarget::create_target (1) || die "Create target 1 failed\n";
my $dir = getcwd ();
my $tool = "$ENV{TAO_ROOT}/orbsvcs/Security_Setup/ace-tao-setup";
my $certs = "$dir/../Mode";
my $work = "$dir/setup_work";
my $conf = "$work/etc/security.conf";
my $marker = "$work/var/enrolled-prod";
my $svc = "$work/svc.conf";
my $common = "--conf $conf --marker $marker";
my $anchor = 'D4:A1:A8:18:BB:BA:70:7B:33:27:37:AA:46:8B:5E:F3:FD:12:15:47:BA:59:84:1E:B3:FE:A7:2D:25:4A:7A:97';

rmtree ($work);
mkdir $work;
delete $ENV{'ACE_TAO_SECURITY_CONF'};

my $status = 0;

sub run {
    my ($args, $stdin) = @_;
    my $redir = defined $stdin ? "< $stdin" : '';
    my $out = `$tool $common $args $redir 2>&1`;
    return ($? >> 8, $out);
}

sub check_case {
    my ($name, $args, $want, $must, $mustnot, $stdin) = @_;
    my ($exit, $out) = run ($args, $stdin);
    my @problems;
    my @ok = ref ($want) ? @$want : ($want);
    push @problems, "exit $exit, want @ok" unless grep { $_ == $exit } @ok;
    foreach my $re (@$must) { push @problems, "missing /$re/" unless $out =~ /$re/m; }
    foreach my $re (@{$mustnot || []}) { push @problems, "unexpected /$re/" if $out =~ /$re/; }
    if (@problems) {
        print STDERR "ERROR: $name: " . join ('; ', @problems) . "\n$out\n";
        $status = 1;
    }
    else {
        print "ok: $name\n";
    }
    return $out;
}

sub slurp {
    my $f = shift;
    open (my $fh, '<', $f) || return '';
    local $/;
    my $s = <$fh>;
    close ($fh);
    return $s;
}

# Where the kernel clock is not synchronized (containers), the time check
# fails in prod and test; checks then exit 2 instead of 1.
my (undef, $st) = run ('status');
my $synced = $st =~ /clock\s+synchronized/;
my $warn_exit = $synced ? 1 : 2;
print "clock: " . ($synced ? "synchronized" : "not synchronized") . "\n";

check_case ('status without a configuration', 'status', 0,
            ['configuration .*\(absent\)', 'mode\s+none', 'enrolled\s+no']);

check_case ('init prod with a trust anchor file', "init --mode prod --trust-anchor-file $certs/ca.pem --audit-sink stderr --yes", 0,
            ['/CN=TAO Mode Test Root', "sha256 $anchor", 'Wrote .*mode prod', 'reason="MODE_SET".*new_mode="prod".*old_mode="none"']);
my $c = slurp ($conf);
if ($c =~ /^mode = prod$/m && $c =~ /^trust_anchor_sha256 = \Q$anchor\E$/m && $c =~ /^audit_sink = stderr$/m) {
    print "ok: configuration written\n";
}
else {
    print STDERR "ERROR: configuration not as expected:\n$c\n"; $status = 1;
}
open (my $fh, '>>', $conf); print $fh "time_sync_wait = 0\n"; close ($fh);

check_case ('init refuses to overwrite', "init --mode test --yes", 2, ['exists']);
check_case ('init with unconfirmed anchors and no terminal is refused',
            "init --mode prod --trust-anchor-file $certs/ca.pem --force", 2, ['not confirmed'], [], '/dev/null');

check_case ('host check: warnings only', 'check', $warn_exit,
            ['OK\s+config\s+mode=prod', 'WARN\s+enrollment', 'OK\s+audit', 'OK\s+trust_anchors']);

open ($fh, '>', $svc);
print $fh "dynamic SSLIOP_Factory Service_Object * TAO_SSLIOP:_make_TAO_SSLIOP_Protocol_Factory() "
        . "\"-SSLAuthenticate SERVER_AND_CLIENT -SSLCAfile PEM:$certs/ca.pem -SSLCertificate PEM:$certs/server_cert.pem "
        . "-SSLPrivateKey PEM:$certs/server_key_enc.pem -SSLPassword file:$certs/password.txt\"\n"
        . "static Resource_Factory \"-ORBProtocolFactory SSLIOP_Factory\"\n";
close ($fh);
if ($synced) {
    check_case ('service check passes', "check --svc-conf $svc", 1,
                ['OK\s+service\s+startup checks passed', 'OK\s+service.ssliop_key', 'OK\s+service.ssliop_trust']);
}
else {
    check_case ('service check is refused by the time check alone', "check --svc-conf $svc", 2,
                ['FAIL\s+service.time', 'OK\s+service.ssliop_key'], ['FAIL\s+service\.(?!time)']);
}

my $bad = "$work/bad_svc.conf";
open ($fh, '>', $bad);
print $fh "dynamic SSLIOP_Factory Service_Object * TAO_SSLIOP:_make_TAO_SSLIOP_Protocol_Factory() "
        . "\"-SSLAuthenticate SERVER_AND_CLIENT -SSLCAfile PEM:$certs/ca.pem -SSLCertificate PEM:$certs/server_cert.pem "
        . "-SSLPrivateKey PEM:$certs/server_key.pem\"\n"
        . "static Resource_Factory \"-ORBProtocolFactory SSLIOP_Factory\"\n";
close ($fh);
check_case ('service check finds an unprotected key', "check --svc-conf $bad", 2,
            ['FAIL\s+service.ssliop_key\s+unprotected private key file', 'FAIL\s+service\s+the service would refuse to start']);

check_case ('check --json', 'check --json', $warn_exit,
            ['^\{"mode":"prod","conf":".*","result":"(warn|fail)","checks":\[\{"name":"config","status":"OK"']);

if ($synced) {
    check_case ('enroll needs confirmation', 'enroll', 2, ['not confirmed'], [], '/dev/null');
    check_case ('enroll', 'enroll --yes', 0, ['Enrolled:', 'reason="HOST_ENROLLED"']);
    check_case ('status shows enrollment', 'status', 0, ['enrolled\s+yes']);
    check_case ('set-mode test refused while enrolled', 'set-mode test --yes', 2, ['enrolled in prod.*unenroll first']);
    check_case ('init --force --mode dev refused while enrolled', 'init --mode dev --force --yes', 2, ['mode dev is refused']);
    check_case ('unenroll needs a reason', 'unenroll', 64, ['--reason TEXT is required']);
    check_case ('unenroll', "unenroll --reason 'move to QA (change 1234)'", 0,
                ['Unenrolled:', 'reason="HOST_UNENROLLED".*justification="move to QA \(change 1234\)"'],
                ['reason="move']);
}
else {
    check_case ('enroll is refused while the clock is not synchronized', 'enroll --yes', 2, ['host check failed: time']);
}

check_case ('leaving prod needs confirmation', 'set-mode test', 2, ['leaving prod not confirmed'], [], '/dev/null');
check_case ('set-mode test', 'set-mode test --yes', 0, ['Mode changed from prod to test', 'reason="MODE_SET"']);
$c = slurp ($conf);
if ($c =~ /^mode = test$/m && $c =~ /^trust_anchor_sha256 = /m && $c =~ /^time_sync_wait = 0$/m) {
    print "ok: set-mode keeps the other settings\n";
}
else {
    print STDERR "ERROR: set-mode lost settings:\n$c\n"; $status = 1;
}
check_case ('enroll refused outside prod', 'enroll --yes', 2, ['only a host in mode prod']);
check_case ('unknown mode is a usage error', 'init --mode production', 64, ['must be dev, test, prod or embedded']);
check_case ('dev mode check runs no security checks', 'set-mode dev', 0, ['to dev']);
check_case ('dev host check', 'check', [0, 1], ['OK\s+config\s+mode=dev'], ['audit', 'time', 'FAIL']);

rmtree ($work);
exit $status;
