eval '(exit $?0)' && eval 'exec perl -S $0 ${1+"$@"}'
     & eval 'exec perl -S $0 $argv:q'
     if 0;

# -*- perl -*-
#
# The CSIv2 Security Attribute Service on a TAO server, stateless, over
# TLS (Phase 2 W3): a GSSUP login is checked by the installed verifier and
# answered with CompleteEstablishContext (context_stateful false), and the
# servant and the access decision see the authenticated user; a wrong
# password, an unknown user or a wrong target name get the same
# ContextError (major 1, GSSUP error UNSPECIFIED); MessageInContext gets
# major 4, an undecodable context major 1, identity assertion and other
# mechanisms major 2; csiv2_gssup = required refuses a request without a
# login; GSSUP is advertised in the reference's authentication layer; no
# password reaches the log.  Certificates and the signer from ../Transport,
# ior_tool from ../CSIv2_IOR.

use lib "$ENV{ACE_ROOT}/bin";
use PerlACE::TestTarget;
use Cwd;
use File::Path qw(rmtree);
use POSIX qw(:sys_wait_h);

my $test = PerlACE::TestTarget::create_target (1) || die "Create target 1 failed\n";
my $dir = getcwd ();
my $certs = "$dir/../Transport";
my $iortool = "$dir/../CSIv2_IOR/ior_tool";
my $work = "$dir/sas_work";
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

my $clock = -x "$dir/../Mode/mode_test" ? `$dir/../Mode/mode_test -clock` : 'synced';
my $prod = $clock =~ /^synced/;
print "mode: " . ($prod ? "prod" : "test (clock not synchronized)") . "\n";

my $fp = `openssl x509 -in $certs/ca.pem -noout -fingerprint -sha256`;
$fp =~ s/.*=//; chomp $fp;
my ($pin) = `$tool --conf /dev/null denylist pin --signer $certs/signer_pub.pem` =~ /= (\w+)/;
my $sign = "--key PEM:$certs/signer_key_enc.pem --password-file $certs/password.txt";

# The access list grants whoami on alpha to the GSSUP user only, poke on
# alpha to the certificate, and everything on beta to everyone.
my $acl = "$work/access.list";
spit ($acl, "version 0\nissued 2026-01-01T00:00:00Z\n"
          . "allow alice\@lab.test /RootPOA/Who/alpha whoami\n"
          . "allow spiffe://ace-tao.test/client /RootPOA/Who/alpha poke\n"
          . "allow * /RootPOA/Who/beta\n");
my $o = `$tool --conf /dev/null access sign $sign --file $acl --bump 2>&1`;
die "access sign failed:\n$o" unless $o =~ /signed into/;

my $base = "mode = " . ($prod ? "prod" : "test") . "\naudit_sink = stderr\ntime_sync_wait = 0\n"
         . "trust_anchor_sha256 = $fp\naccess_list = $acl\naccess_list_signer = $certs/signer_pub.pem\n"
         . "access_list_signer_sha256 = $pin\naccess_default = deny\naudit_grants = on\n"
         . "csiv2 = supported\ngssup_target = \@lab.test\n";
my %conf = (supported => $base . "csiv2_gssup = supported\n",
            required  => $base . "csiv2_gssup = required\n",
            off       => $base . "csiv2_gssup = off\n");
foreach my $k (keys %conf) { spit ("$work/$k.conf", $conf{$k}); chmod (0600, "$work/$k.conf"); }

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
        exec ("$dir/server", '-ORBSvcConf', "$work/server.svc", '-ORBListenEndpoints', 'iiop://127.0.0.1:', '-d', $d);
        exit 127;
    }
    for (my $i = 0; $i < 100 && !-s "$d/beta.ior"; ++$i) { select (undef, undef, undef, 0.1); }
}
sub stop_server {
    my ($mode) = @_;
    $mode = 'none' unless defined $mode;
    `$dir/client -ORBSvcConf $work/client.svc -k file://$d/beta.ior -c shutdown -m $mode 2>&1`;
    my $gone = 0;
    for (my $i = 0; $i < 50 && !$gone; ++$i) { $gone = waitpid ($pid, WNOHANG) == $pid; select (undef, undef, undef, 0.1) unless $gone; }
    if (!$gone) { kill ('KILL', $pid); waitpid ($pid, 0); print STDERR "ERROR: server did not shut down\n"; $status = 1; }
}
sub call {
    my ($obj, $what, $mode, $extra) = @_;
    return scalar (`$dir/client -ORBSvcConf $work/client.svc -k file://$d/$obj.ior -c $what -m $mode $extra 2>&1`);
}

# --- csiv2_gssup = supported ----------------------------------------------------
start_server ('supported');
expect ('server starts with GSSUP and its verifier', slurp ($log), ['SERVER READY', 'checks: \d+ ok, \d+ warn, 0 fail']);
expect ('the reference advertises GSSUP (supported) in its authentication layer',
        scalar (`$iortool -k file://$d/alpha.ior 2>&1`),
        ['^    MECH 0 requires=0xc6 transport=36$', '^      AS supports=0x40 requires=0x0 mech_octets=8$']);

expect ('no SAS context: served on the certificate (poke granted to it)', call ('alpha', 'poke', 'none'),
        ['^SAS REPLY none$', '^POKE OK$']);
expect ('no SAS context: whoami on alpha is the GSSUP user\'s, refused', call ('alpha', 'whoami', 'none'),
        ['^whoami EXCEPTION NO_PERMISSION$']);
expect ('GSSUP login: CompleteEstablishContext, stateless; the servant sees the user, the certificate as an alternate',
        call ('alpha', 'whoami', 'gssup:alice:wonderland'),
        ['^SAS REPLY complete ctx=0 stateful=0$',
         '^WHOAMI name=oid:2\.23\.130\.1\.2\.1:alice\@lab\.test authenticated=yes alt=TAO:SPIFFEID:spiffe://ace-tao\.test/client alt=SL3:X509DirectoryPathName:CN=transport-client$']);
expect ('a non-zero client_context_id is answered statelessly (R12)', call ('alpha', 'whoami', 'gssup:alice:wonderland', '-i 77'),
        ['^SAS REPLY complete ctx=77 stateful=0$', '^WHOAMI name=']);

my $wrong = call ('alpha', 'whoami', 'gssup:alice:wrong-password');
my $nouser = call ('alpha', 'whoami', 'gssup:bob:wonderland');
my $target = call ('alpha', 'whoami', 'gssup:alice:wonderland:@other.test');
foreach my $case (['wrong password', $wrong], ['unknown user', $nouser], ['wrong target name', $target]) {
    expect ("$case->[0]: ContextError major 1, GSSUP error UNSPECIFIED, NO_PERMISSION", $case->[1],
            ['^SAS REPLY error ctx=0 major=1 minor=1 gssup_error=1$', '^whoami EXCEPTION NO_PERMISSION$'], ['^WHOAMI']);
}
# The first line of the reply, ignoring the client's own audit records.
sub first_reply { my $s = shift; $s =~ s/^.*ace-tao-audit.*\n//mg; $s =~ s/\n.*//s; return $s; }
my $w = first_reply ($wrong); my $n = first_reply ($nouser);
expect ('  (a wrong password and an unknown user get identical replies)', ($w eq $n ? "same" : "differ: $w / $n"), ['^same$']);

expect ('MessageInContext: ContextError major 4 (no context is kept)', call ('alpha', 'whoami', 'mic', '-i 42'),
        ['^SAS REPLY error ctx=42 major=4 minor=1 gssup_error=0$', '^whoami EXCEPTION NO_PERMISSION$']);
expect ('an undecodable SAS context: major 1', call ('alpha', 'whoami', 'garbage'),
        ['^SAS REPLY error ctx=0 major=1 minor=1 ', '^whoami EXCEPTION NO_PERMISSION$']);
expect ('identity assertion (not supported yet): major 2', call ('alpha', 'whoami', 'ident'),
        ['^SAS REPLY error ctx=0 major=2 minor=1 ', '^whoami EXCEPTION NO_PERMISSION$']);
expect ('a non-GSSUP client authentication token: major 2', call ('alpha', 'whoami', 'notgssup'),
        ['^SAS REPLY error ctx=0 major=2 minor=1 ', '^whoami EXCEPTION NO_PERMISSION$']);
expect ('an authorization token is ignored (and audited); the login still works', call ('alpha', 'whoami', 'authz:alice:wonderland'),
        ['^SAS REPLY complete ctx=0 stateful=0$', '^WHOAMI name=oid:2\.23\.130\.1\.2\.1:alice\@lab\.test ']);

my $l = slurp ($log);
expect ('refusals and logins are audited (user named, password never)', $l,
        ['event="authn" result="fail" reason="GSSUP_FAILED" principal="spiffe://ace-tao.test/client" src="127.0.0.1:\d+" op="whoami" user="alice" context_error="1"\] wrong password',
         'reason="GSSUP_FAILED" .*user="bob" context_error="1"\] unknown user',
         'reason="GSSUP_FAILED" .*user="alice" context_error="1"\] GSSUP target name does not match',
         'reason="SAS_NO_CONTEXT" .*context_error="4"\]',
         'reason="SAS_INVALID_EVIDENCE" .*\] undecodable SAS context',
         'reason="SAS_INVALID_MECH" .*\] identity assertion is not supported',
         'reason="SAS_INVALID_MECH" .*\] client authentication token is not GSSUP',
         'event="authn" result="ok" reason="SAS_AUTHZ_TOKEN_IGNORED"',
         'event="authn" result="ok" reason="SAS_ACCEPTED" principal="alice\@lab\.test" transport_principal="spiffe://ace-tao.test/client"',
         'reason="ACCESS_DENIED" principal="spiffe://ace-tao.test/client" .*object="/RootPOA/Who/alpha" op="whoami"',
         'reason="ACCESS_GRANTED" principal="alice\@lab\.test" .*object="/RootPOA/Who/alpha" op="whoami"'],
        ['wonderland', 'wrong-password']);
stop_server ();

# --- csiv2_gssup = required ---------------------------------------------------------
start_server ('required');
expect ('required: the reference requires GSSUP (compound and authentication layer)', scalar (`$iortool -k file://$d/alpha.ior 2>&1`),
        ['^    MECH 0 requires=0xc6 transport=36$', '^      AS supports=0x40 requires=0x40 mech_octets=8$']);
expect ('required: a request without a login is refused (SAS_MISSING, no SAS reply)', call ('beta', 'poke', 'none', '-b'),
        ['^SAS REPLY none$', '^poke EXCEPTION NO_PERMISSION$']);
# A client configuration that only sends its audit records to stderr.
spit ("$work/client.conf", "mode = test\naudit_sink = stderr\ntime_sync_wait = 0\n");
chmod (0600, "$work/client.conf");
expect ('required: a TAO client without GSSUP credentials refuses locally',
        do { local $ENV{'ACE_TAO_SECURITY_CONF'} = "$work/client.conf"; call ('beta', 'poke', 'none') },
        ['^SAS REPLY none$', '^poke EXCEPTION NO_PERMISSION$', 'reason="SAS_CLIENT_NO_CREDENTIALS" .*target="\@lab\.test"']);
expect ('required: with a login it is served', call ('beta', 'poke', 'gssup:alice:wonderland'),
        ['^SAS REPLY complete ctx=0 stateful=0$', '^POKE OK$']);
expect ('  (SAS_MISSING audited)', slurp ($log), ['reason="SAS_MISSING" .*\] no SAS context; GSSUP client authentication is required']);
stop_server ('gssup:alice:wonderland');

# --- csiv2_gssup = off --------------------------------------------------------------
start_server ('off');
expect ('off: no authentication layer in the reference', scalar (`$iortool -k file://$d/alpha.ior 2>&1`),
        ['^      AS supports=0x0 requires=0x0 mech_octets=0$']);
expect ('off: a GSSUP token is the wrong mechanism (major 2)', call ('beta', 'poke', 'gssup:alice:wonderland'),
        ['^SAS REPLY error ctx=0 major=2 minor=1 ', '^poke EXCEPTION NO_PERMISSION$']);
stop_server ();

# --- prod refuses GSSUP without a verifier ------------------------------------------
if ($prod) {
    expect ('prod refuses csiv2_gssup without a GSSUP verifier',
            scalar (`SAS_TEST_NO_VERIFIER=1 ACE_TAO_SECURITY_CONF=$work/supported.conf $dir/server -ORBSvcConf $work/server.svc -ORBListenEndpoints iiop://127.0.0.1: -d $work 2>&1`),
            ['FAIL csiv2_gssup: csiv2_gssup is on but no GSSUP verifier is installed', 'ORB_INIT REFUSED']);
}

if ($status == 0) { rmtree ($work); }
exit $status;
