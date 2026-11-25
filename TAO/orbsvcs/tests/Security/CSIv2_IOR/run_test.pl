eval '(exit $?0)' && eval 'exec perl -S $0 ${1+"$@"}'
     & eval 'exec perl -S $0 $argv:q'
     if 0;

# -*- perl -*-
#
# CSIv2 in SSLIOP references (Phase 2 W2): with csiv2 on (the prod
# default) every SSLIOP profile carries TAG_CSI_SEC_MECH_LIST, one
# compound mechanism whose transport is TAG_TLS_SEC_TRANS with the TLS
# port, beside TAO's TAG_SSL_SEC_TRANS; csiv2 = off leaves it out.  A
# client reaches a server whose reference has only the CSIv2 component
# (as a JacORB server's has), and refuses a reference whose two
# components name different TLS ports (IOR_TLS_MISMATCH).  TLS 1.2 is the
# minimum: a TLS 1.1 handshake is refused.  Server and client come from
# ../Caller, certificates and the signer from ../Transport.

use lib "$ENV{ACE_ROOT}/bin";
use PerlACE::TestTarget;
use Cwd;
use File::Path qw(rmtree);
use POSIX qw(:sys_wait_h);

my $test = PerlACE::TestTarget::create_target (1) || die "Create target 1 failed\n";
my $dir = getcwd ();
my $certs = "$dir/../Transport";
my $caller = "$dir/../Caller";
my $work = "$dir/csiv2_work";
my $tool = "$ENV{TAO_ROOT}/orbsvcs/Security_Setup/ace-tao-setup";
my $openssl = $ENV{'OPENSSL'} || (-x '/opt/homebrew/opt/openssl@3/bin/openssl' ? '/opt/homebrew/opt/openssl@3/bin/openssl' : 'openssl');
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

# prod needs a synchronized clock; elsewhere run in test mode with csiv2
# set explicitly (its default there is off).
my $clock = -x "$dir/../Mode/mode_test" ? `$dir/../Mode/mode_test -clock` : 'synced';
my $prod = $clock =~ /^synced/;
print "mode: " . ($prod ? "prod" : "test (clock not synchronized)") . "\n";

my $fp = `$openssl x509 -in $certs/ca.pem -noout -fingerprint -sha256`;
$fp =~ s/.*=//; chomp $fp;
my ($pin) = `$tool --conf /dev/null denylist pin --signer $certs/signer_pub.pem` =~ /= (\w+)/;
my $acl = "$work/access.list";
spit ($acl, "version 0\nissued 2026-01-01T00:00:00Z\nallow * *\n");
my $o = `$tool --conf /dev/null access sign --key PEM:$certs/signer_key_enc.pem --password-file $certs/password.txt --file $acl --bump 2>&1`;
die "access sign failed:\n$o" unless $o =~ /signed into/;
my $base = "mode = " . ($prod ? "prod" : "test") . "\naudit_sink = stderr\ntime_sync_wait = 0\n"
         . "trust_anchor_sha256 = $fp\naccess_list = $acl\naccess_list_signer = $certs/signer_pub.pem\n"
         . "access_list_signer_sha256 = $pin\n";
my $conf = "$work/security.conf";
spit ($conf, $base . ($prod ? "" : "csiv2 = supported\n"));
my $conf_off = "$work/off.conf";
spit ($conf_off, $base . "csiv2 = off\n");
my $conf_bad = "$work/bad.conf";
spit ($conf_bad, $base . "csiv2 = maybe\n");
chmod (0600, $conf, $conf_off, $conf_bad);

sub svc {
    my ($name, $cert, $key) = @_;
    my $opts = "-SSLAuthenticate SERVER_AND_CLIENT -SSLCAfile PEM:$certs/ca.pem"
             . " -SSLCertificate PEM:$certs/$cert -SSLPrivateKey PEM:$certs/$key -SSLPassword file:$certs/password.txt";
    spit ("$work/$name.conf",
          "dynamic SSLIOP_Factory Service_Object * TAO_SSLIOP:_make_TAO_SSLIOP_Protocol_Factory() \"$opts\"\n"
        . "static Resource_Factory \"-ORBProtocolFactory SSLIOP_Factory\"\n");
}
svc ('server', 'server_cert.pem', 'server_key_enc.pem');
svc ('client', 'client_cert.pem', 'client_key_enc.pem');

sub start_server {
    my ($cfg, $sub) = @_;
    my $d = "$work/$sub";
    mkdir $d;
    my $log = "$d/server.log";
    my $pid = fork ();
    if ($pid == 0) {
        $ENV{'ACE_TAO_SECURITY_CONF'} = $cfg;
        open (STDOUT, '>', $log); open (STDERR, '>&STDOUT');
        exec ("$caller/server", '-ORBSvcConf', "$work/server.conf", '-ORBListenEndpoints', 'iiop://127.0.0.1:', '-d', $d);
        exit 127;
    }
    for (my $i = 0; $i < 100 && !-s "$d/beta.ior"; ++$i) { select (undef, undef, undef, 0.1); }
    return ($pid, $d, $log);
}
sub stop_server {
    my ($pid) = @_;
    kill ('TERM', $pid);
    for (my $i = 0; $i < 30 && waitpid ($pid, WNOHANG) != $pid; ++$i) { select (undef, undef, undef, 0.1); }
    kill ('KILL', $pid); waitpid ($pid, 0);
}

# --- csiv2 = off: no CSIv2 component; a bad value is refused in prod ---------
my ($pid, $d, $log) = start_server ($conf_off, 'off');
expect ('csiv2 = off: TAO component only', scalar (`$dir/ior_tool -k file://$d/alpha.ior 2>&1`),
        ['^PROFILE 0 host=127.0.0.1', '^  TAG_SSL_SEC_TRANS port=[1-9]'], ['TAG_CSI_SEC_MECH_LIST']);
expect ('csiv2 = off is reported by the self-check', scalar (`$tool --conf $conf_off check --svc-conf $work/server.conf 2>&1`),
        ['OK\s+service.csiv2\s+off: no CSIv2 component']);
stop_server ($pid);
if ($prod) {
    expect ('prod refuses an unknown csiv2 value',
            scalar (`ACE_TAO_SECURITY_CONF=$conf_bad $caller/server -ORBSvcConf $work/server.conf -ORBListenEndpoints iiop://127.0.0.1: -d $work 2>&1`),
            ['FAIL csiv2: csiv2 must be off, supported or required, not maybe', 'ORB_INIT REFUSED']);
}

# --- csiv2 on (prod default) ----------------------------------------------------
($pid, $d, $log) = start_server ($conf, 'on');
expect ('server starts with 0 failures', slurp ($log), ['SERVER READY', 'checks: \d+ ok, \d+ warn, 0 fail']);
expect ('its self-check reports TLS 1.2 minimum and the CSIv2 component',
        scalar (`$tool --conf $conf check --svc-conf $work/server.conf 2>&1`),
        ['OK\s+service.tls_versions\s+TLS 1.2 minimum', 'OK\s+service.csiv2\s+CSIv2 TLS transport advertised']);
my $show = `$dir/ior_tool -k file://$d/alpha.ior 2>&1`;
my ($ssl_port) = $show =~ /TAG_SSL_SEC_TRANS port=(\d+)/;
# Association options (CSIv2): Integrity 0x2, Confidentiality 0x4,
# EstablishTrustInTarget 0x20, EstablishTrustInClient 0x40, NoDelegation 0x80.
expect ('the reference carries TAG_CSI_SEC_MECH_LIST beside TAG_SSL_SEC_TRANS', $show,
        ['^  TAG_SSL_SEC_TRANS port=[1-9]\d*',
         '^  TAG_CSI_SEC_MECH_LIST stateful=0 mechanisms=1$',
         '^    MECH 0 requires=0xc6 transport=36$',
         "^      TLS supports=0xe6 requires=0xc6 addresses=127.0.0.1:$ssl_port\$",
         '^      AS supports=0x0 requires=0x0 mech_octets=0$',
         '^      SAS supports=0x0 requires=0x0 identity_types=0x0$']);
expect ('prod keeps plain IIOP closed (port 0, no TAG_NULL_TAG)', $show, ['^PROFILE 0 host=127.0.0.1 iiop_port=0$'],
        ['transport=34']) if $prod;

# A CSIv2-only reference (no TAG_SSL_SEC_TRANS) is reached over TLS.
expect ('ior_tool -s strips TAG_SSL_SEC_TRANS', scalar (`$dir/ior_tool -k file://$d/alpha.ior -s -o $work/csiv2_only.ior 2>&1`),
        ['WROTE']);
expect ('  (the stripped reference has the CSIv2 component only)', scalar (`$dir/ior_tool -k file://$work/csiv2_only.ior 2>&1`),
        ['TAG_CSI_SEC_MECH_LIST', "addresses=127.0.0.1:$ssl_port"], ['TAG_SSL_SEC_TRANS']);
expect ('a client reaches a CSIv2-only reference over TLS with its certificate',
        scalar (`$caller/client -ORBSvcConf $work/client.conf -k file://$work/csiv2_only.ior -c whoami 2>&1`),
        ['^WHOAMI name=TAO:SPIFFEID:spiffe://ace-tao.test/client ']);

# Components that disagree are refused.
expect ('ior_tool -p moves the CSIv2 port', scalar (`$dir/ior_tool -k file://$d/alpha.ior -p -o $work/mismatch.ior 2>&1`),
        ['WROTE']);
my $mm = `ACE_TAO_SECURITY_CONF=$conf $caller/client -ORBSvcConf $work/client.conf -k file://$work/mismatch.ior -c whoami 2>&1`;
expect ('a reference whose TLS ports disagree is refused and audited', $mm,
        ['reason="IOR_TLS_MISMATCH" host="127.0.0.1" ssl_port="' . $ssl_port . '" tls_sec_trans_ports="' . ($ssl_port + 1) . '"', '^NIL REFERENCE'],
        ['^WHOAMI']);

# TLS 1.2 minimum, on the server's TLS port.
my $s12 = `echo | $openssl s_client -connect 127.0.0.1:$ssl_port -tls1_2 -CAfile $certs/ca.pem -cert $certs/client_cert.pem -key $certs/client_key_enc.pem -pass file:$certs/password.txt 2>&1`;
expect ('a TLS 1.2 handshake succeeds', $s12, ['Protocol *: TLSv1\.2']);
my $s11 = `echo | $openssl s_client -connect 127.0.0.1:$ssl_port -tls1_1 -cipher DEFAULT\@SECLEVEL=0 -CAfile $certs/ca.pem 2>&1`;
# (s_client prints the version it tried even when refused; no cipher
# means no session.)
expect ('a TLS 1.1 handshake is refused', $s11, ['alert protocol version|unsupported protocol|no protocols available|wrong version number'],
        ['Cipher is (?!\(NONE\))']);
sleep (1);
expect ('  (and audited by the server)', slurp ($log), ['reason="TLS_HANDSHAKE_FAILED" src="127.0.0.1" peer="127.0.0.1:\d+"\] .*(unsupported protocol|version)']);

`$caller/client -ORBSvcConf $work/client.conf -k file://$d/beta.ior -c shutdown 2>&1`;
my $gone = 0;
for (my $i = 0; $i < 50 && !$gone; ++$i) { $gone = waitpid ($pid, WNOHANG) == $pid; select (undef, undef, undef, 0.1) unless $gone; }
if (!$gone) { kill ('KILL', $pid); waitpid ($pid, 0); print STDERR "ERROR: server did not shut down\n"; $status = 1; }

if ($status == 0 && !$ENV{KEEP_WORK}) { rmtree ($work); }
else { print STDERR "server log:\n" . slurp ($log); }
exit $status;
