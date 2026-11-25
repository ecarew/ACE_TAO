eval '(exit $?0)' && eval 'exec perl -S $0 ${1+"$@"}'
     & eval 'exec perl -S $0 $argv:q'
     if 0;

# -*- perl -*-
#
# The CSIv2 GSSUP password store (Phase 2 W4): "ace-tao-setup user"
# maintains a file of scrypt hashes (passwords never from the command
# line, at least 12 characters, file mode 0600); a service with
# gssup_store set checks logins against it, picks up changes without a
# restart, locks a user after gssup_max_failures failures and a host
# after gssup_source_max_failures, answers a locked user exactly like a
# wrong password, refuses every login while the store is unusable (and,
# in prod, while it is readable by others), and audits it all without a
# password.  Uses the SAS test's server (with SAS_TEST_NO_VERIFIER, so
# the store is the verifier) and client; certificates and the signer
# from ../Transport.

use lib "$ENV{ACE_ROOT}/bin";
use PerlACE::TestTarget;
use Cwd;
use File::Path qw(rmtree);
use POSIX qw(:sys_wait_h);

my $test = PerlACE::TestTarget::create_target (1) || die "Create target 1 failed\n";
my $dir = getcwd ();
my $sas = "$dir/../SAS";
my $certs = "$dir/../Transport";
my $work = "$dir/store_work";
my $tool = "$ENV{TAO_ROOT}/orbsvcs/Security_Setup/ace-tao-setup";
my $status = 0;

rmtree ($work);
mkdir $work;
delete $ENV{'ACE_TAO_SECURITY_CONF'};
$ENV{'SAS_TEST_NO_VERIFIER'} = '1';

sub slurp { my $f = shift; open (my $fh, '<', $f) || return ''; local $/; my $s = <$fh>; close ($fh); return $s; }
sub spit { my ($f, $t) = @_; open (my $fh, '>', $f) || die "$f: $!"; print $fh $t; close ($fh); }

sub expect {
    my ($name, $out, $must, $mustnot) = @_;
    my @p;
    foreach my $re (@$must) { push @p, "missing /$re/" unless $out =~ /$re/m; }
    foreach my $re (@{$mustnot || []}) { push @p, "unexpected /$re/" if $out =~ /$re/m; }
    if (@p) { print STDERR "ERROR: $name: " . join ('; ', @p) . "\n$out\n"; $status = 1; }
    else { print "ok: $name\n"; }
}

my $clock = -x "$dir/../Mode/mode_test" ? `$dir/../Mode/mode_test -clock` : 'synced';
my $prod = $clock =~ /^synced/;
print "mode: " . ($prod ? "prod" : "test (clock not synchronized)") . "\n";

# Test passwords (test data only).
my $pw_alice = 'correct-horse-alice';
my $pw_alice2 = 'second-horse-alice';
my $pw_bob = 'correct-horse-bobby';
my $pw_wrong = 'wrong-password-xyz';

my $store = "$work/gssup.store";
my $tconf = "$work/tool.conf";
spit ($tconf, "mode = test\naudit_sink = stderr\ngssup_store = $store\n");
sub tool {
    my ($args, $stdin) = @_;
    my $in = defined $stdin ? "printf '%s\\n' '$stdin' |" : '</dev/null';
    my $out = `$in $tool --conf $tconf user $args 2>&1`;
    return ($out, $? >> 8);
}

# --- ace-tao-setup user ---------------------------------------------------------------
my ($out, $rc);
($out, $rc) = tool ("add alice --password=$pw_alice");
expect ('user add refuses a password on the command line', "$rc\n$out", ['^64$', 'never taken from the command line']);
($out, $rc) = tool ("add alice --password-stdin", 'short-pw');
expect ('user add refuses a password under 12 characters', "$rc\n$out", ['^2$', '12 to 256 characters']);
($out, $rc) = tool ("add alice");
expect ('user add without a terminal needs --password-stdin', "$rc\n$out", ['^2$', 'not a terminal']);
($out, $rc) = tool ("add al:ice --password-stdin", $pw_alice);
expect ('user add refuses a bad user name', "$rc\n$out", ['^64$', 'bad user name']);
($out, $rc) = tool ("add alice --password-stdin --cost 14", $pw_alice);
expect ('user add creates the store', "$rc\n$out", ['^0$', 'Added alice']);
expect ('  (the change is audited, without the password)', $out,
        ['reason="GSSUP_USER_CHANGED" uid="\d+" action="add" file="[^"]+" user="alice"'], [quotemeta ($pw_alice)]);
expect ('  (mode 0600)', sprintf ("%04o", (stat ($store))[2] & 07777), ['^0600$']);
($out, $rc) = tool ("add bob --password-stdin --cost 14", $pw_bob);
expect ('user add appends a second user', "$rc\n$out", ['^0$', 'Added bob']);
($out, $rc) = tool ("add bob --password-stdin", $pw_bob);
expect ('user add refuses an existing user', "$rc\n$out", ['^2$', 'exists']);
my $text = slurp ($store);
my ($salt) = $text =~ /^alice scrypt:14:8:1:([^:]+):/m;
($out, $rc) = tool ("list");
expect ('user list shows names, states and costs, never hashes', "$rc\n$out",
        ['^0$', '^alice\s+active\s+scrypt N=2\^14 r=8 p=1$', '^bob\s+active\s', '^2 user\(s\)'],
        [defined $salt ? quotemeta ($salt) : 'no-salt-found', 'scrypt:']);
expect ('the store holds no password', $text, ['^alice scrypt:14:8:1:\S+:\S+ active$', '^bob scrypt:'],
        [$pw_alice, $pw_bob]);

# --- a service checks logins against the store ----------------------------------------
my $fp = `openssl x509 -in $certs/ca.pem -noout -fingerprint -sha256`;
$fp =~ s/.*=//; chomp $fp;
my ($pin) = `$tool --conf /dev/null denylist pin --signer $certs/signer_pub.pem` =~ /= (\w+)/;
my $sign = "--key PEM:$certs/signer_key_enc.pem --password-file $certs/password.txt";
my $acl = "$work/access.list";
spit ($acl, "version 0\nissued 2026-01-01T00:00:00Z\nallow * /RootPOA/Who/beta\nallow * /RootPOA/Who/alpha\n");
$out = `$tool --conf /dev/null access sign $sign --file $acl --bump 2>&1`;
die "access sign failed:\n$out" unless $out =~ /signed into/;

my $base = "mode = " . ($prod ? "prod" : "test") . "\naudit_sink = stderr\ntime_sync_wait = 0\n"
         . "trust_anchor_sha256 = $fp\naccess_list = $acl\naccess_list_signer = $certs/signer_pub.pem\n"
         . "access_list_signer_sha256 = $pin\naccess_default = deny\n"
         . "csiv2 = supported\ncsiv2_gssup = supported\ngssup_target = \@lab.test\ngssup_store = $store\n"
         . "gssup_failure_window = 60\ngssup_lockout = 3\n";
spit ("$work/user.conf", $base . "gssup_max_failures = 3\ngssup_source_max_failures = 100\n");
spit ("$work/source.conf", $base . "gssup_max_failures = 100\ngssup_source_max_failures = 4\n");
chmod (0600, "$work/user.conf", "$work/source.conf");

sub svc {
    my ($name, $cert, $key) = @_;
    my $opts = "-SSLAuthenticate SERVER_AND_CLIENT -SSLCAfile PEM:$certs/ca.pem"
             . " -SSLCertificate PEM:$certs/$cert -SSLPrivateKey PEM:$certs/$key -SSLPassword file:$certs/password.txt";
    spit ("$work/$name.svc",
          "dynamic SSLIOP_Factory Service_Object * TAO_SSLIOP:_make_TAO_SSLIOP_Protocol_Factory() \"$opts\"\n"
        . "static Resource_Factory \"-ORBProtocolFactory SSLIOP_Factory\"\n");
}
svc ('server', 'server_cert.pem', 'server_key_enc.pem');
svc ('client', 'client_cert.pem', 'client_key_enc.pem');

my ($pid, $d, $log);
sub start_server {
    my ($which) = @_;
    $d = "$work/$which";
    mkdir $d;
    $log = "$d/server.log";
    $pid = fork ();
    if ($pid == 0) {
        $ENV{'ACE_TAO_SECURITY_CONF'} = "$work/$which.conf";
        open (STDOUT, '>', $log); open (STDERR, '>&STDOUT');
        exec ("$sas/server", '-ORBSvcConf', "$work/server.svc", '-ORBListenEndpoints', 'iiop://127.0.0.1:', '-d', $d);
        exit 127;
    }
    for (my $i = 0; $i < 100 && !-s "$d/beta.ior"; ++$i) { select (undef, undef, undef, 0.1); }
}
sub stop_server {
    `$sas/client -ORBSvcConf $work/client.svc -k file://$d/beta.ior -c shutdown -m none 2>&1`;
    my $gone = 0;
    for (my $i = 0; $i < 50 && !$gone; ++$i) { $gone = waitpid ($pid, WNOHANG) == $pid; select (undef, undef, undef, 0.1) unless $gone; }
    if (!$gone) { kill ('KILL', $pid); waitpid ($pid, 0); print STDERR "ERROR: server did not shut down\n"; $status = 1; }
}
sub login {
    my ($user, $pw) = @_;
    return scalar (`$sas/client -ORBSvcConf $work/client.svc -k file://$d/alpha.ior -c whoami -m gssup:$user:$pw 2>&1`);
}
my @ok = ('^SAS REPLY complete ctx=0 stateful=0$');
my @refused = ('^SAS REPLY error ctx=0 major=1 minor=1 gssup_error=1$', '^whoami EXCEPTION NO_PERMISSION$');

# --- per-user lockout, changes picked up ------------------------------------------------
start_server ('user');
expect ('the service starts with the store as its verifier', slurp ($log),
        ['SERVER READY', 'checks: \d+ ok, \d+ warn, 0 fail', 'reason="GSSUP_STORE_LOADED" file="[^"]+"\] 2 user\(s\)']);
expect ('right password: logged in', login ('alice', $pw_alice), [@ok, '^WHOAMI name=oid:2\.23\.130\.1\.2\.1:alice\@lab\.test ']);
my $wrong = login ('alice', $pw_wrong);
my $nouser = login ('carol', $pw_wrong);
expect ('wrong password: refused', $wrong, [@refused], ['^WHOAMI']);
expect ('unknown user: refused', $nouser, [@refused], ['^WHOAMI']);
login ('alice', $pw_wrong);
my $third = login ('alice', $pw_wrong);
my $locked = login ('alice', $pw_alice);
expect ('the 3rd failure locks alice; the answer is still a plain refusal', $third, [@refused]);
expect ('locked: even the right password is refused, with the same answer', $locked, [@refused], ['^WHOAMI']);
(my $a1 = $wrong) =~ s/\n.*//s; (my $a2 = $locked) =~ s/\n.*//s; (my $a3 = $nouser) =~ s/\n.*//s;
expect ('  (wrong password, unknown user and locked user: identical replies)',
        ($a1 eq $a2 && $a2 eq $a3) ? "same" : "differ: $a1 / $a2 / $a3", ['^same$']);
expect ('bob is not affected by alice\'s lock', login ('bob', $pw_bob), [@ok]);
sleep (4);
expect ('after gssup_lockout the right password works again', login ('alice', $pw_alice), [@ok]);

($out, $rc) = tool ("lock bob");
expect ('user lock', "$rc\n$out", ['^0$', 'Locked bob']);
sleep (1);
expect ('a user locked by the administrator is refused (no restart needed)', login ('bob', $pw_bob), [@refused]);
($out, $rc) = tool ("unlock bob");
sleep (1);
expect ('user unlock: bob logs in again', login ('bob', $pw_bob), [@ok]);
($out, $rc) = tool ("passwd alice --password-stdin", $pw_alice2);
expect ('user passwd', "$rc\n$out", ['^0$', 'Changed the password of alice']);
sleep (1);
expect ('after passwd the old password is refused', login ('alice', $pw_alice), [@refused]);
expect ('  and the new one works', login ('alice', $pw_alice2), [@ok]);
($out, $rc) = tool ("remove bob");
sleep (1);
expect ('user remove: bob is refused', login ('bob', $pw_bob), [@refused]);

# An unusable store refuses every login (fail closed), and recovers.
my $good = slurp ($store);
spit ($store, "alice scrypt:broken active\n");
chmod (0600, $store);
sleep (1);
expect ('a broken store refuses every login', login ('alice', $pw_alice2), [@refused]);
spit ($store, $good);
chmod (0600, $store);
sleep (1);
expect ('  and a repaired one works again', login ('alice', $pw_alice2), [@ok]);
if ($prod) {
    chmod (0644, $store);
    sleep (1);
    expect ('prod: a store readable by others refuses every login', login ('alice', $pw_alice2), [@refused]);
    chmod (0600, $store);
    sleep (1);
    expect ('  and works again at 0600', login ('alice', $pw_alice2), [@ok]);
}

my $l = slurp ($log);
expect ('everything is audited, the user named, no password', $l,
        ['reason="GSSUP_FAILED" .*user="alice" context_error="1"\] wrong password',
         'reason="GSSUP_FAILED" .*user="carol" context_error="1"\] unknown user',
         'reason="GSSUP_LOCKED" .*user="alice" context_error="1"\] lockout began: 3 failure\(s\) within 60 s; locked for 3 s',
         'reason="GSSUP_LOCKED" .*user="alice" context_error="1"\] user locked after repeated failures',
         'reason="GSSUP_FAILED" .*user="bob" context_error="1"\] user locked by an administrator',
         'reason="GSSUP_STORE_REJECTED" file="[^"]+"\] [^ ]+: line 1: bad credential for alice; every GSSUP login is refused',
         'reason="GSSUP_FAILED" .*user="alice" context_error="1"\] GSSUP store unusable'],
        [quotemeta ($pw_alice), quotemeta ($pw_alice2), quotemeta ($pw_bob), quotemeta ($pw_wrong)]);
stop_server ();

# --- per-host limit -------------------------------------------------------------------
start_server ('source');
foreach my $u ('u1', 'u2', 'u3') { login ($u, $pw_wrong); }
my $fourth = login ('u4', $pw_wrong);
expect ('failures spread over users from one host hit the host limit', $fourth, [@refused]);
expect ('  then that host is refused even with a right password', login ('alice', $pw_alice2), [@refused], ['^WHOAMI']);
expect ('  (audited as GSSUP_RATE_LIMITED, not as a wrong password)', slurp ($log),
        ['reason="GSSUP_RATE_LIMITED" .*user="u4" context_error="1"\] rate limit began for 127\.0\.0\.1: 4 failure',
         'reason="GSSUP_RATE_LIMITED" .*user="alice" context_error="1"\] too many failed logins from 127\.0\.0\.1']);
sleep (4);
expect ('after gssup_lockout the host may log in again', login ('alice', $pw_alice2), [@ok]);
stop_server ();

# --- prod refuses to start on a store readable by others -------------------------------
if ($prod) {
    chmod (0640, $store);
    expect ('prod: the self-check fails on a store readable by others',
            scalar (`ACE_TAO_SECURITY_CONF=$work/user.conf $sas/server -ORBSvcConf $work/server.svc -ORBListenEndpoints iiop://127.0.0.1: -d $work 2>&1`),
            ['FAIL gssup_store: GSSUP store unusable, every login refused: \S+ is mode 0640 \(want 0600 or 0400\)', 'ORB_INIT REFUSED']);
    chmod (0600, $store);
}

if ($status == 0) { rmtree ($work); }
exit $status;
