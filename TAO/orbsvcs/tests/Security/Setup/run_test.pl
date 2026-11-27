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
use File::Copy;
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

# Authenticated time through stand-ins for chronyc.
my %chrony = (
  'nts' => "time.cloudflare.com,NTS,1,15,256,33,0,0,8,64\npool.ntp.org,-,0,0,0,0,0,0,0,0\n",
  'plain' => "pool.ntp.org,-,0,0,0,0,0,0,0,0\n",
);
foreach my $k (keys %chrony) {
    open (my $c, '>', "$work/chronyc-$k");
    print $c "#!/bin/sh\ncat <<'EOF'\n$chrony{$k}EOF\n";
    close ($c);
    chmod (0755, "$work/chronyc-$k");
}
check_case ('NTS sources found', "check --chronyc $work/chronyc-nts", [1, 2],
            ['OK\s+nts\s+chrony: 1 of 2 source\(s\) use NTS']);
{
    # chronyc runs without a shell, so its path may hold blanks and quotes.
    my $odd = "$work/odd dir's";
    mkdir $odd;
    copy ("$work/chronyc-nts", "$odd/chronyc") || die "copy: $!";
    chmod (0755, "$odd/chronyc");
    check_case ('chronyc runs without a shell (a path with a blank and a quote)', "check --chronyc \"$odd/chronyc\"", [1, 2],
                ['OK\s+nts\s+chrony: 1 of 2 source\(s\) use NTS']);
}
check_case ('no NTS sources warns', "check --chronyc $work/chronyc-plain", [1, 2],
            ['WARN\s+nts\s+chrony has no NTS sources']);
check_case ('chrony not found warns', "check --chronyc $work/no-such-chronyc", [1, 2],
            ['WARN\s+nts\s+cannot verify authenticated time: chrony not found']);
open ($fh, '>>', $conf); print $fh "require_nts = yes\n"; close ($fh);
check_case ('require_nts makes missing NTS fail prod', "check --chronyc $work/chronyc-plain", 2,
            ['FAIL\s+nts\s+chrony has no NTS sources']);
check_case ('require_nts is satisfied by NTS', "check --chronyc $work/chronyc-nts", [1, 2],
            ['OK\s+nts'], ['FAIL\s+nts']);
my $without = join ('', grep { !/^require_nts/ } split (/^/m, slurp ($conf)));
open ($fh, '>', $conf); print $fh $without; close ($fh);

open ($fh, '>', $svc);
print $fh "dynamic SSLIOP_Factory Service_Object * TAO_SSLIOP:_make_TAO_SSLIOP_Protocol_Factory() "
        . "\"-SSLAuthenticate SERVER_AND_CLIENT -SSLCAfile PEM:$certs/ca.pem -SSLCertificate PEM:$certs/server_cert.pem "
        . "-SSLPrivateKey PEM:$certs/server_key_enc.pem -SSLPassword file:$certs/password.txt\"\n"
        . "static Resource_Factory \"-ORBProtocolFactory SSLIOP_Factory\"\n";
close ($fh);
# Prod needs a signed access list before an SSLIOP service starts.
{
    my $signer = "$dir/../Transport";
    my $acl = "$work/access.list";
    open (my $a, '>', $acl); print $a "version 0\nissued 2026-01-01T00:00:00Z\nallow * *\n"; close ($a);
    my $o = `$tool --conf /dev/null access sign --key PEM:$signer/signer_key_enc.pem --password-file $signer/password.txt --file $acl --bump 2>&1`;
    die "access sign failed:\n$o" unless $o =~ /signed into/;
    my ($pin) = `$tool --conf /dev/null denylist pin --signer $signer/signer_pub.pem` =~ /= (\w+)/;
    open ($fh, '>>', $conf);
    print $fh "access_list = $acl\naccess_list_signer = $signer/signer_pub.pem\naccess_list_signer_sha256 = $pin\n";
    close ($fh);
}
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

# key create / key check (software keys; keystore keys and step-ca are
# exercised in the lab: CORBA lab/setup/keys_lab_test.sh).
open (my $pw, '>', "$work/key-pass"); print $pw "key-pass\n"; close ($pw);
check_case ('key create file', "key create --type file --out $work/svc.key --password-file $work/key-pass", 0,
            ['Created a file key \(P-256\)', 'OK\s+protection\s+software key in a passphrase-encrypted file',
             'OK\s+signature', 'reason="KEY_CREATED".*key_type="file"',
             "SSLIOP: -SSLPrivateKey PEM:$work/svc.key -SSLPassword file:$work/key-pass"]);
my $k = slurp ("$work/svc.key");
my $kmode = (stat ("$work/svc.key"))[2] & 07777;
if ($k =~ /^-----BEGIN ENCRYPTED PRIVATE KEY-----/ && $kmode == 0600) {
    print "ok: the key file is encrypted and mode 0600\n";
}
else {
    printf STDERR "ERROR: key file mode %04o:\n%s\n", $kmode, $k; $status = 1;
}
check_case ('key create does not replace a key', "key create --type file --out $work/svc.key --password-file $work/key-pass", 2,
            ['exists; not replacing a key']);
check_case ('a file key needs a password', "key create --type file --out $work/other.key", 64,
            ['needs --password-file']);
check_case ('unknown key type', "key create --type hsm --out $work/other.key", 64, ['must be file, pkcs11, tpm2 or sep']);
open ($pw, '>', "$work/wrong-pass"); print $pw "wrong"; close ($pw);
check_case ('key check with the wrong password', "key check --key PEM:$work/svc.key --password-file $work/wrong-pass", 2,
            ['FAIL\s+load\s+cannot load the private key']);
system ("cp $certs/server_key_enc.pem $certs/server_key.pem $work/ && chmod 600 $work/server_key_enc.pem $work/server_key.pem");
check_case ('key check with its certificate', "key check --key $work/server_key_enc.pem --password-file $certs/password.txt --cert $certs/server_cert.pem", 0,
            ['OK\s+certificate\s+matches /CN=mode-test', 'OK\s+expiry\s+valid until 2046']);
check_case ('key check finds an expired certificate', "key check --key $work/server_key_enc.pem --password-file $certs/password.txt --cert $certs/server_cert_expired.pem", 2,
            ['OK\s+certificate', 'FAIL\s+expiry\s+expired 2020-02-01']);
check_case ('key check finds a certificate for another key', "key check --key PEM:$work/svc.key --password-file $work/key-pass --cert $certs/server_cert.pem", 2,
            ['FAIL\s+certificate\s+.* is for a different key']);
check_case ('key check finds an unencrypted key', "key check --key $work/server_key.pem", 2,
            ['FAIL\s+protection\s+software key stored UNENCRYPTED'], ['FAIL\s+permissions']);
chmod (0644, "$work/server_key.pem");
check_case ('key check finds a readable key file', "key check --key $work/server_key.pem", 2,
            ['FAIL\s+permissions\s+.* is mode 0644']);
check_case ('set-mode prod for the key policy', 'set-mode prod', 0, ['to prod']);
check_case ('prod refuses an unprotected key', "key create --type file --out $work/other.key --unprotected", 2,
            ['prod refuses unprotected keys']);
check_case ('back to dev', 'set-mode dev --yes', 0, ['to dev']);

# cert request / cert renew: the checks made before the CA is contacted.
use MIME::Base64 qw(encode_base64url);
sub token {
    my $claims = shift;
    return encode_base64url ('{"alg":"ES256","typ":"JWT"}') . '.' . encode_base64url ($claims) . '.c2ln';
}
sub write_file { my ($f, $t) = @_; open (my $fh, '>', $f); print $fh $t; close ($fh); }
my $later = time () + 300;
write_file ("$work/bad.tok", "not a token\n");
check_case ('cert request needs a step-ca token', "cert request --key PEM:$work/svc.key --password-file $work/key-pass --token-file $work/bad.tok --out $work/svc.pem --root $certs/ca.pem", 2,
            ['does not hold a step-ca token']);
write_file ("$work/expired.tok", token ('{"sub":"svc.ace-tao.test","aud":"https://localhost:1/1.0/sign","exp":1600000000}'));
check_case ('cert request refuses an expired token', "cert request --key PEM:$work/svc.key --password-file $work/key-pass --token-file $work/expired.tok --out $work/svc.pem --root $certs/ca.pem", 2,
            ['the token expired']);
write_file ("$work/sha.tok", token ('{"sub":"svc.ace-tao.test","sans":["svc.ace-tao.test"],"aud":["https://localhost:1/1.0/sign"],"exp":' . $later . ',"sha":"' . ('ab' x 32) . '"}'));
check_case ('cert request checks the root against the token', "cert request --key PEM:$work/svc.key --password-file $work/key-pass --token-file $work/sha.tok --out $work/svc.pem --root $certs/ca.pem", 2,
            ['is not the one the token names']);
check_case ('cert request needs a root', "cert request --key PEM:$work/svc.key --token-file $work/sha.tok --out $work/svc.pem", 64,
            ['--root PEM is required']);
check_case ('cert renew: a long-lived certificate is not due', "cert renew --key $work/server_key_enc.pem --password-file $certs/password.txt --cert $certs/server_cert.pem --root $certs/ca.pem --ca-url https://localhost:1", 0,
            ['Not due: .* more day\(s\); renewal starts 2040']);
check_case ('cert renew refuses an expired certificate', "cert renew --key $work/server_key_enc.pem --password-file $certs/password.txt --cert $certs/server_cert_expired.pem --root $certs/ca.pem --ca-url https://localhost:1", 2,
            ['expired 2020-02-01.*run cert request']);
check_case ('cert renew needs a CA URL', "cert renew --key $work/server_key_enc.pem --cert $certs/server_cert.pem --root $certs/ca.pem", 64,
            ['--ca-url https://HOST\[:PORT\] is required']);
check_case ('cert renew --force reports an unreachable CA', "cert renew --key $work/server_key_enc.pem --password-file $certs/password.txt --cert $certs/server_cert.pem --root $certs/ca.pem --ca-url https://127.0.0.1:1 --force", 2,
            ['cannot connect to https://127.0.0.1:1']);

# install / uninstall into a scratch tree (no root, nothing loaded).
my $tree = "$work/tree";
my $bin = "$ENV{TAO_ROOT}/orbsvcs/Naming_Service";
check_case ('install dry run changes nothing', "install --root $tree --bin-dir $bin --port 2899 --dry-run", 0,
            ['Would install', 'Dry run complete']);
if (-e $tree) { print STDERR "ERROR: dry run created $tree\n"; $status = 1; }
check_case ('install into a scratch tree', "install --root $tree --bin-dir $bin --port 2899 --label-prefix test.ace-tao --no-start", 0,
            ['Installed. Manifest:']);
my $man = slurp ("$tree/var/lib/ace-tao/install-manifest");
if ($man =~ /^dir \Q$tree\E\/var\/lib\/ace-tao$/m && $man =~ /^file \S+naming\.svc\.conf [0-9a-f]{64}$/m) {
    print "ok: manifest records directories and files with checksums\n";
}
else {
    print STDERR "ERROR: manifest not as expected:\n$man\n"; $status = 1;
}
check_case ('second install is refused', "install --root $tree --bin-dir $bin --no-start", 2, ['already installed']);
open ($fh, '>', "$tree/var/lib/ace-tao/naming/NameService"); print $fh "data\n"; close ($fh);
check_case ('uninstall keeps service data and its record', "uninstall --root $tree", 2,
            ['keep \S+/naming: not empty', 'records them']);
check_case ('uninstall --purge finishes', "uninstall --root $tree --purge", 0,
            ['purge \S+NameService', 'everything install created is gone']);
opendir (my $dh, $tree);
my @left = grep { !/^\.\.?$/ } readdir ($dh);
closedir ($dh);
if (@left) { print STDERR "ERROR: left in the scratch tree: @left\n"; $status = 1; }
else { print "ok: scratch tree is empty again\n"; }
check_case ('uninstall with nothing installed', "uninstall --root $tree", 2, ['nothing to uninstall']);

rmtree ($work);
exit $status;
