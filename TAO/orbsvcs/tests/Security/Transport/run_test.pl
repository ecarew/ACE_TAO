eval '(exit $?0)' && eval 'exec perl -S $0 ${1+"$@"}'
     & eval 'exec perl -S $0 $argv:q'
     if 0;

# -*- perl -*-
#
# SSLIOP transport hardening on a host in prod (test where the clock is
# not synchronized): no plain IIOP listener; every failed handshake
# audited with the peer's address and why; the signed deny-list checked
# at the handshake and on each request, reloaded when it changes, and a
# bad or older list refused; SecurityLevel3 acquirers (SL3TLS, and
# SL3TLSKeystore refusing a software key).  The deny-list is maintained
# with ace-tao-setup denylist.  Certificates: make_certs.sh.

use lib "$ENV{ACE_ROOT}/bin";
use PerlACE::TestTarget;
use Cwd;
use File::Path qw(rmtree);

my $test = PerlACE::TestTarget::create_target (1) || die "Create target 1 failed\n";
my $dir = getcwd ();
my $work = "$dir/transport_work";
my $tool = "$ENV{TAO_ROOT}/orbsvcs/Security_Setup/ace-tao-setup";
my $status = 0;

rmtree ($work);
mkdir $work;
delete $ENV{'ACE_TAO_SECURITY_CONF'};

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

# prod needs a synchronized clock; elsewhere (containers) run in test mode.
my $clock = -x "$dir/../Mode/mode_test" ? `$dir/../Mode/mode_test -clock` : 'synced';
my $prod = $clock =~ /^synced/;
print "mode: " . ($prod ? "prod" : "test (clock not synchronized)") . "\n";

my $fp = `openssl x509 -in $dir/ca.pem -noout -fingerprint -sha256`;
$fp =~ s/.*=//; chomp $fp;
my ($pin) = `$tool --conf /dev/null denylist pin --signer $dir/signer_pub.pem` =~ /= (\w+)/;
my $deny = "$work/deny.list";
my $conf_base = "mode = " . ($prod ? "prod" : "test") . "\naudit_sink = stderr\ntime_sync_wait = 0\n"
              . "trust_anchor_sha256 = $fp\ndenylist = $deny\ndenylist_signer = $dir/signer_pub.pem\n"
              . "denylist_reload = 1\n";
my $conf = "$work/security.conf";
spit ($conf, $conf_base . "denylist_signer_sha256 = $pin\n");
chmod (0600, $conf);
my $sign = "--key PEM:$dir/signer_key_enc.pem --password-file $dir/password.txt";

sub svc {
    my ($name, $cert, $key) = @_;
    my $opts = "-SSLAuthenticate SERVER_AND_CLIENT -SSLCAfile PEM:$dir/ca.pem";
    $opts .= " -SSLCertificate PEM:$dir/$cert -SSLPrivateKey PEM:$dir/$key -SSLPassword file:$dir/password.txt" if $cert;
    spit ("$work/$name.conf",
          "dynamic SSLIOP_Factory Service_Object * TAO_SSLIOP:_make_TAO_SSLIOP_Protocol_Factory() \"$opts\"\n"
        . "static Resource_Factory \"-ORBProtocolFactory SSLIOP_Factory\"\n");
}
svc ('server', 'server_cert.pem', 'server_key_enc.pem');
svc ('good', 'client_cert.pem', 'client_key_enc.pem');
svc ('client2', 'client2_cert.pem', 'client2_key_enc.pem');
svc ('stranger', 'stranger_cert.pem', 'stranger_key_enc.pem');
svc ('expired', 'expired_cert.pem', 'expired_key_enc.pem');
svc ('nocert');

my $out = `$tool --conf $conf denylist add $sign --cert $dir/client2_cert.pem 2>&1`;
expect ('denylist add writes and signs version 1', $out,
        ['reason="DENYLIST_SIGNED"', 'version 1 issued .* 1 serial\(s\), 0 SPIFFE ID\(s\)']);
expect ('denylist check verifies it with the pinned signer', `$tool --conf $conf denylist check 2>&1`,
        ['^OK: .* version 1', '\(pinned\)', 'serial 42CCF2AAFAF0B7F8BE815FF423B8AF8C74AF60DD']);
expect ('denylist add refuses a list signed by another key',
        `$tool --conf $conf denylist add --key PEM:$dir/impostor_key_enc.pem --password-file $dir/password.txt --spiffe spiffe://ace-tao.test/x 2>&1`,
        ['is not signed by this key']);

# prod refuses a deny-list whose signer is not pinned, or not the pinned one.
if ($prod) {
    my $bad = "$work/nopin.conf";
    spit ($bad, $conf_base); chmod (0600, $bad);
    expect ('prod refuses an unpinned deny-list signer',
            `ACE_TAO_SECURITY_CONF=$bad $dir/server -ORBSvcConf $work/server.conf -ORBListenEndpoints iiop://127.0.0.1: -o $work/x.ior 2>&1`,
            ['FAIL denylist: denylist_signer_sha256 is not set', 'ORB_INIT REFUSED']);
    spit ($bad, $conf_base . "denylist_signer_sha256 = " . ('ab' x 32) . "\n");
    expect ('prod refuses a deny-list signer that is not the pinned one',
            `ACE_TAO_SECURITY_CONF=$bad $dir/server -ORBSvcConf $work/server.conf -ORBListenEndpoints iiop://127.0.0.1: -o $work/x.ior 2>&1`,
            ['FAIL denylist: deny-list unusable: .* is not the pinned signer', 'ORB_INIT REFUSED']);
}

# The server, in the background, with its output in a log.
my $log = "$work/server.log";
my $ior = "$work/server.ior";
my $pid = fork ();
if ($pid == 0) {
    $ENV{'ACE_TAO_SECURITY_CONF'} = $conf;
    open (STDOUT, '>', $log); open (STDERR, '>&STDOUT');
    exec ("$dir/server", '-ORBSvcConf', "$work/server.conf", '-ORBListenEndpoints', 'iiop://127.0.0.1:', '-o', $ior);
    exit 127;
}
for (my $i = 0; $i < 100 && !-s $ior; ++$i) { select (undef, undef, undef, 0.1); }
expect ('server starts with the deny-list loaded', slurp ($log),
        ['SERVER READY', 'deny=v1', 'checks: \d+ ok, \d+ warn, 0 fail']);
expect ('prod opens no plain IIOP listener (IIOP port 0)', slurp ($log), ['PORTS iiop=0 ssl=[1-9]']) if $prod;

sub client { my ($conf, $args) = @_; my $o = `$dir/client -ORBSvcConf $work/$conf.conf -k file://$ior $args 2>&1`; return $o; }

expect ('a trusted client is served', client ('good'), ['CALL 1 OK']);
expect ('SL3TLS acquires file credentials and they are used', client ('nocert',
          "-m SL3TLS -c $dir/client_cert.pem -K $dir/client_key_enc.pem -p transport-test-pass"),
        ['ACQUIRE OK', 'CALL 1 OK']);
expect ('SL3TLSKeystore refuses a software key', client ('nocert',
          "-m SL3TLSKeystore -c $dir/client_cert.pem -K STORE:$dir/client_key_enc.pem -p transport-test-pass"),
        ['is a software key that can be exported', 'ACQUIRE FAILED BAD_PARAM']);

expect ('a client without a certificate is refused', client ('nocert'), ['CALL 1 EXCEPTION']);
expect ('an untrusted client is refused', client ('stranger'), ['CALL 1 EXCEPTION']);
expect ('an expired client certificate is refused', client ('expired'), ['CALL 1 EXCEPTION']);
expect ('a deny-listed serial is refused at the handshake', client ('client2'), ['CALL 1 EXCEPTION']);
expect ('failed handshakes are audited with the peer and why', slurp ($log),
        ['event="authn" result="fail" reason="NO_CLIENT_CERT" src="127.0.0.1" peer="127.0.0.1:\d+"\] peer did not return a certificate',
         'reason="CERT_UNTRUSTED" src="127.0.0.1" peer="127.0.0.1:\d+"\] self-signed certificate',
         'reason="CERT_EXPIRED" src="127.0.0.1" peer="127.0.0.1:\d+"\] certificate has expired',
         'reason="CERT_DENYLISTED" src="127.0.0.1" peer="127.0.0.1:\d+" subject="/CN=transport-client2" cert_serial="42CCF2AAFAF0B7F8BE815FF423B8AF8C74AF60DD" denylist_entry="serial 42CCF2AAFAF0B7F8BE815FF423B8AF8C74AF60DD"']);

# A changed list that does not verify, then one that is not newer, are
# both refused; the service keeps version 1.
my $good_list = slurp ($deny);
spit ($deny, $good_list . "spiffe spiffe://ace-tao.test/client\n");
sleep (2);
expect ('a tampered client still calls (call made so the list is re-read)', client ('good'), ['CALL 1 OK']);
spit ($deny, $good_list);
sleep (2);
expect ('the old list again (call made so it is re-read)', client ('good'), ['CALL 1 OK']);
expect ('a list that does not verify, or is not newer, is refused and the last one kept', slurp ($log),
        ['reason="DENYLIST_REJECTED" .*current_version="1".*\] the signature does not verify',
         'reason="DENYLIST_REJECTED" .*\] version 1 is not newer than the current version 1']);

# Listed while connected: the next request on the same connection is refused.
my $cpid = open (my $cfh, '-|', "$dir/client -ORBSvcConf $work/good.conf -k file://$ior -n 2 -s 3 2>&1");
sleep (1);
$out = `$tool --conf $conf denylist add $sign --spiffe spiffe://ace-tao.test/client 2>&1`;
expect ('denylist add publishes version 2', $out, ['version 2 issued .* 1 SPIFFE ID\(s\)']);
my $calls = do { local $/; <$cfh> };
close ($cfh);
expect ('a request after the identity was listed is refused (NO_PERMISSION)', $calls,
        ['CALL 1 OK', 'CALL 2 EXCEPTION NO_PERMISSION']);
expect ('the new list is loaded and the refusal audited', slurp ($log),
        ['reason="DENYLIST_LOADED" .*version="2".*previous_version="1"',
         'event="authz" result="deny" reason="CERT_DENYLISTED" subject="/CN=transport-client" .*denylist_entry="spiffe://ace-tao.test/client" op="hello"']);

$out = `$tool --conf $conf denylist remove $sign --spiffe spiffe://ace-tao.test/client 2>&1`;
expect ('denylist remove publishes version 3', $out, ['version 3 issued .* 0 SPIFFE ID\(s\)']);
sleep (2);
$out = client ('good', '-x');
expect ('removed from the list, the client is served again', $out, ['CALL 1 OK']);

# (kill 0 succeeds on an exited child until it is reaped, so poll waitpid.)
use POSIX ':sys_wait_h';
my $gone = 0;
for (my $i = 0; $i < 50 && !$gone; ++$i) {
    $gone = waitpid ($pid, WNOHANG) == $pid;
    select (undef, undef, undef, 0.1) unless $gone;
}
if (!$gone) { kill ('KILL', $pid); waitpid ($pid, 0); print STDERR "ERROR: server did not shut down\n"; $status = 1; }

if ($status == 0) { rmtree ($work); }
else { print STDERR "server log:\n" . slurp ($log); }
exit $status;
