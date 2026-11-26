eval '(exit $?0)' && eval 'exec perl -S $0 ${1+"$@"}'
     & eval 'exec perl -S $0 $argv:q'
     if 0;

# -*- perl -*-
#
# CSIv2 identity assertion on a TAO server (Phase 2 W5): an identity
# token is accepted only from an asserter on the signed asserter list
# (csiv2_asserters), matched on its certificate or on its own GSSUP login
# (backward trust), and only for the types and realms its entry allows.
# Asserted names, distinguished names and certificate chains (verified
# against the trust store and the deny-list) become the caller's
# effective principal; the asserter is kept beside it, in the servant's
# view, in access-list rules (via=) and in the audit records.  The
# reference advertises identity assertion in its SAS layer.  Uses the SAS
# test's server and client; certificates and the signer from ../Transport,
# ior_tool from ../CSIv2_IOR.

use lib "$ENV{ACE_ROOT}/bin";
use PerlACE::TestTarget;
use Cwd;
use File::Path qw(rmtree);
use POSIX qw(:sys_wait_h);

my $test = PerlACE::TestTarget::create_target (1) || die "Create target 1 failed\n";
my $dir = getcwd ();
my $sas = "$dir/../SAS";
my $certs = "$dir/../Transport";
my $iortool = "$dir/../CSIv2_IOR/ior_tool";
my $work = "$dir/assert_work";
my $tool = "$ENV{TAO_ROOT}/orbsvcs/Security_Setup/ace-tao-setup";
my $status = 0;

rmtree ($work);
mkdir $work;
delete $ENV{'ACE_TAO_SECURITY_CONF'};
delete $ENV{'SAS_TEST_NO_VERIFIER'};

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
my $tconf = "$work/tool.conf";
spit ($tconf, "mode = test\naudit_sink = stderr\ndenylist_signer = $certs/signer_pub.pem\ndenylist_signer_sha256 = $pin\n");

# --- the asserter list and ace-tao-setup asserters ----------------------------------
my $asserters = "$work/asserters.list";
spit ($asserters, "version 0\nissued 2026-01-01T00:00:00Z\nasserter *\n");
my $o = `$tool --conf $tconf asserters sign $sign --file $asserters --bump 2>&1`;
expect ('asserters sign refuses "asserter *" (presumed trust)', $o, ['presumed trust is not allowed'], ['signed into']);
spit ($asserters, "version 0\nissued 2026-01-01T00:00:00Z\n"
                . "asserter spiffe://ace-tao.test/client  types=name,dn,x509 realms=\@lab.test\n"
                . "asserter alice\@lab.test\n");
$o = `$tool --conf $tconf asserters sign $sign --file $asserters --bump 2>&1`;
expect ('asserters sign signs the list (audited)', $o,
        ['version 1 issued \S+, 2 asserter\(s\); signed into', 'reason="ASSERTER_LIST_SIGNED"']);
$o = `$tool --conf $tconf asserters check --file $asserters 2>&1`;
expect ('asserters check verifies it and shows each asserter\'s limits', $o,
        ['^OK: .* version 1 ', '\(pinned\)', '^  spiffe://ace-tao.test/client types=name,dn,x509 realms=\@lab.test$',
         '^  alice\@lab.test types=name realms=\(the service\'s gssup_target\)$']);

# The access list: alice only when the client certificate vouches for her,
# carol only when alice (logged in with GSSUP) does.
my $acl = "$work/access.list";
spit ($acl, "version 0\nissued 2026-01-01T00:00:00Z\n"
          . "allow alice\@lab.test /RootPOA/Who/alpha whoami via=spiffe://ace-tao.test/client\n"
          . "allow bob\@lab.test /RootPOA/Who/alpha whoami\n"
          . "allow carol\@lab.test /RootPOA/Who/alpha whoami via=alice\@lab.test\n"
          . "allow CN=transport-client2 /RootPOA/Who/alpha whoami\n"
          . "allow spiffe://ace-tao.test/client2 /RootPOA/Who/alpha whoami\n"
          . "allow * /RootPOA/Who/beta\n");
$o = `$tool --conf /dev/null access sign $sign --file $acl --bump 2>&1`;
die "access sign failed:\n$o" unless $? == 0 && -s "$acl.sig";
$o = `$tool --conf /dev/null access check --file $acl --signer $certs/signer_pub.pem 2>&1`;
expect ('access check shows via=', $o, ['^  allow alice\@lab.test /RootPOA/Who/alpha whoami via=spiffe://ace-tao.test/client$']);

my $base = "mode = " . ($prod ? "prod" : "test") . "\naudit_sink = stderr\ntime_sync_wait = 0\n"
         . "trust_anchor_sha256 = $fp\naccess_list = $acl\naccess_list_signer = $certs/signer_pub.pem\n"
         . "access_list_signer_sha256 = $pin\naccess_default = deny\naudit_grants = on\n"
         . "csiv2 = supported\ncsiv2_gssup = supported\ngssup_target = \@lab.test\n"
         . "denylist_signer = $certs/signer_pub.pem\ndenylist_signer_sha256 = $pin\n"
         . "csiv2_asserters = $asserters\n";
spit ("$work/main.conf", $base);

# A deny-list naming client2, for the asserted-chain check.
my $deny = "$work/deny.list";
my $serial2 = `openssl x509 -in $certs/client2_cert.pem -noout -serial`;
$serial2 =~ s/.*=//; chomp $serial2;
spit ($deny, "version 1\nissued 2026-01-01T00:00:00Z\nserial $serial2\n");
$o = `$tool --conf $tconf denylist sign $sign --file $deny 2>&1`;
die "denylist sign failed:\n$o" unless $? == 0 && -s "$deny.sig";
spit ("$work/deny.conf", $base . "denylist = $deny\n");

# Anonymous assertion on.
my $asserters_anon = "$work/asserters_anon.list";
spit ($asserters_anon, "version 0\nissued 2026-01-01T00:00:00Z\nasserter spiffe://ace-tao.test/client types=name,anonymous\n");
$o = `$tool --conf $tconf asserters sign $sign --file $asserters_anon --bump 2>&1`;
die "asserters sign failed:\n$o" unless $? == 0 && -s "$asserters_anon.sig";
(my $anon = $base) =~ s/^csiv2_asserters = .*$/csiv2_asserters = $asserters_anon/m;
spit ("$work/anon.conf", $anon . "allow_anonymous_assertion = listed\n");
# Rule 4 (CORBA 3.3 Part 2, Table 10.4): any caller may assert anonymous,
# with the usual asserter list (client2 is not on it) and with none at all.
spit ("$work/anyanon.conf", $base . "allow_anonymous_assertion = on\n");
(my $noasserters = $base) =~ s/^csiv2_asserters = .*\n//m;
spit ("$work/anyanon_nolist.conf", $noasserters . "allow_anonymous_assertion = on\n");
spit ("$work/badanon.conf", $base . "allow_anonymous_assertion = yes\n");
chmod (0600, "$work/main.conf", "$work/deny.conf", "$work/anon.conf", "$work/anyanon.conf",
       "$work/anyanon_nolist.conf", "$work/badanon.conf");

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
svc ('client2', 'client2_cert.pem', 'client2_key_enc.pem');

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
sub call {
    my ($as, $assertion, $mode) = @_;
    $mode = 'none' unless defined $mode;
    return scalar (`$sas/client -ORBSvcConf $work/$as.svc -k file://$d/alpha.ior -c whoami -m $mode -a $assertion 2>&1`);
}
my @ok = ('^SAS REPLY complete ctx=0 stateful=0$');
my @refused1 = ('^SAS REPLY error ctx=0 major=1 minor=1 ', '^whoami EXCEPTION NO_PERMISSION$');
my @refused2 = ('^SAS REPLY error ctx=0 major=2 minor=1 ', '^whoami EXCEPTION NO_PERMISSION$');

# --- a listed asserter ---------------------------------------------------------------
start_server ('main');
expect ('the server starts with the asserter list', slurp ($log), ['SERVER READY', 'checks: \d+ ok, \d+ warn, 0 fail']);
expect ('the reference advertises identity assertion (name, X.509 chain, DN; GSSUP names)',
        scalar (`$iortool -k file://$d/alpha.ior 2>&1`), ['^      SAS supports=0x400 requires=0x0 identity_types=0xe$']);

expect ('the client certificate asserts alice@lab.test: served as alice, the asserter beside her',
        call ('client', 'name:alice@lab.test'),
        [@ok, '^WHOAMI name=oid:2\.23\.130\.1\.2\.1:alice\@lab\.test authenticated=yes.* alt=TAO:SPIFFEID:spiffe://ace-tao\.test/client']);
expect ('an unscoped name is in the service\'s realm (bob -> bob@lab.test)', call ('client', 'name:bob'),
        [@ok, '^WHOAMI name=oid:2\.23\.130\.1\.2\.1:bob\@lab\.test ']);
expect ('a name in a realm the asserter may not assert: ContextError 1', call ('client', 'name:eve@other.test'), [@refused1]);
expect ('a name under a non-GSSUP mechanism OID: ContextError 1', call ('client', 'badoid:alice@lab.test'), [@refused1]);
expect ('an asserted distinguished name becomes the principal',
        call ('client', "dn:$certs/client2_cert.pem"), [@ok, '^WHOAMI name=\S+:CN=transport-client2 ']);
expect ('an asserted certificate chain that verifies becomes its SPIFFE ID',
        call ('client', "x509:$certs/client2_cert.pem"), [@ok, '^WHOAMI name=TAO:SPIFFEID:spiffe://ace-tao\.test/client2 ']);
expect ('an asserted chain from another CA: ContextError 1', call ('client', "x509:$certs/stranger_cert.pem"), [@refused1]);
expect ('an expired asserted certificate: ContextError 1', call ('client', "x509:$certs/expired_cert.pem"), [@refused1]);
expect ('anonymous, not in the asserter\'s types: ContextError 1', call ('client', 'anonymous'), [@refused1]);
expect ('an unsupported identity token type: ContextError 2', call ('client', 'type:16'), [@refused2]);

expect ('an unlisted asserter (client2): ContextError 1', call ('client2', 'name:alice@lab.test'), [@refused1], ['^WHOAMI']);
expect ('backward trust: client2 logged in as alice (listed) asserts carol: served as carol',
        call ('client2', 'name:carol@lab.test', 'gssup:alice:wonderland'),
        [@ok, '^WHOAMI name=oid:2\.23\.130\.1\.2\.1:carol\@lab\.test ']);
expect ('via=: alice logging in herself does not satisfy "via the client certificate"',
        scalar (`$sas/client -ORBSvcConf $work/client.svc -k file://$d/alpha.ior -c whoami -m gssup:alice:wonderland 2>&1`),
        ['^SAS REPLY complete ', '^whoami EXCEPTION NO_PERMISSION$'], ['^WHOAMI']);

my $l = slurp ($log);
expect ('both identities in the audit records; rejections say why', $l,
        ['reason="SAS_ACCEPTED" principal="alice\@lab\.test" transport_principal="spiffe://ace-tao\.test/client" asserter="spiffe://ace-tao\.test/client"',
         'reason="ACCESS_GRANTED" principal="alice\@lab\.test" asserter="spiffe://ace-tao\.test/client"',
         'reason="ACCESS_GRANTED" principal="carol\@lab\.test" asserter="alice\@lab\.test"',
         'reason="ASSERTION_REJECTED" .*asserter="spiffe://ace-tao\.test/client" asserted="eve\@other\.test" context_error="1"\] the asserter may not assert names in realm \@other\.test',
         'reason="ASSERTION_REJECTED" .*context_error="1"\] the asserted name is not a well-formed GSSUP or Kerberos exported name',
         'reason="ASSERTION_REJECTED" .*context_error="1"\] the certificate chain does not verify',
         'reason="ASSERTION_REJECTED" .*context_error="1"\] the asserter may not assert identity type anonymous',
         'reason="SAS_INVALID_MECH" .*context_error="2"\] identity token type 16 is not supported',
         'reason="ASSERTION_REJECTED" principal="spiffe://ace-tao\.test/client2" .*context_error="1"\] asserter spiffe://ace-tao\.test/client2 is not on the asserter list',
         'reason="ACCESS_DENIED" principal="alice\@lab\.test" subject='],
        ['wonderland']);
stop_server ();

# --- an asserted chain on the deny-list -------------------------------------------------
start_server ('deny');
expect ('an asserted certificate on the deny-list: ContextError 1', call ('client', "x509:$certs/client2_cert.pem"), [@refused1]);
expect ('  (audited)', slurp ($log), ['reason="ASSERTION_REJECTED" .*\] the asserted certificate is on the deny-list \(serial ']);
stop_server ();

# --- anonymous assertion allowed ------------------------------------------------------
start_server ('anon');
expect ('allow_anonymous_assertion = listed warns in the self-check', slurp ($log), ['WARN csiv2_asserters: allow_anonymous_assertion = listed']);
expect ('the reference then advertises ITTAnonymous too', scalar (`$iortool -k file://$d/alpha.ior 2>&1`),
        ['^      SAS supports=0x400 requires=0x0 identity_types=0xf$']);
expect ('an asserted anonymous caller is accepted by SAS but is not an identified caller (access list refuses)',
        call ('client', 'anonymous'), [@ok, '^whoami EXCEPTION NO_PERMISSION$']);
expect ('  (audited as anonymous, with its asserter)', slurp ($log),
        ['reason="ACCESS_DENIED" principal="anonymous" asserter="spiffe://ace-tao\.test/client"']);
expect ('listed: an unlisted asserter (client2) may not assert anonymous', call ('client2', 'anonymous'), [@refused1]);
stop_server ();

# --- anonymous assertion from any caller (rule 4) -------------------------------------
start_server ('anyanon');
expect ('allow_anonymous_assertion = on warns in the self-check', slurp ($log),
        ['WARN csiv2_asserters: allow_anonymous_assertion = on: any caller may assert an anonymous caller']);
expect ('on: an unlisted asserter (client2) asserting anonymous is accepted by SAS (access list refuses)',
        call ('client2', 'anonymous'), [@ok, '^whoami EXCEPTION NO_PERMISSION$']);
expect ('  (audited as anonymous, with the real asserter)', slurp ($log),
        ['reason="ACCESS_DENIED" principal="anonymous" asserter="spiffe://ace-tao\.test/client2"']);
expect ('on: a name assertion from client2 is still refused (only anonymous is open)',
        call ('client2', 'name:alice@lab.test'), [@refused1], ['^WHOAMI']);
stop_server ();

start_server ('anyanon_nolist');
expect ('on without an asserter list: the reference advertises ITTAnonymous only', scalar (`$iortool -k file://$d/alpha.ior 2>&1`),
        ['^      SAS supports=0x400 requires=0x0 identity_types=0x1$']);
expect ('on without an asserter list: anonymous is accepted by SAS (access list refuses)',
        call ('client2', 'anonymous'), [@ok, '^whoami EXCEPTION NO_PERMISSION$']);
expect ('on without an asserter list: a name assertion is ContextError 2', call ('client', 'name:alice@lab.test'), [@refused2]);
stop_server ();

if ($prod) {
    expect ('prod: allow_anonymous_assertion with an unknown value fails the self-check',
            scalar (`ACE_TAO_SECURITY_CONF=$work/badanon.conf $sas/server -ORBSvcConf $work/server.svc -ORBListenEndpoints iiop://127.0.0.1: -d $work 2>&1`),
            ['FAIL csiv2_asserters: allow_anonymous_assertion = yes: not off, listed or on', 'ORB_INIT REFUSED']);
} else {
    start_server ('badanon');
    expect ('allow_anonymous_assertion with an unknown value is flagged by the self-check', slurp ($log),
            ['WARN csiv2_asserters: allow_anonymous_assertion = yes: not off, listed or on']);
    expect ('  (and anonymous assertion stays off)', call ('client', 'anonymous'), [@refused1]);
    stop_server ();
}

# --- prod: a tampered asserter list stops the service -----------------------------------
if ($prod) {
    my $good = slurp ($asserters);
    spit ($asserters, $good . "asserter spiffe://ace-tao.test/client2\n");
    expect ('prod: an asserter list whose signature does not verify fails the self-check',
            scalar (`ACE_TAO_SECURITY_CONF=$work/main.conf $sas/server -ORBSvcConf $work/server.svc -ORBListenEndpoints iiop://127.0.0.1: -d $work 2>&1`),
            ['FAIL csiv2_asserters: asserter list unusable, every assertion refused: ', 'ORB_INIT REFUSED']);
    spit ($asserters, $good);
}

if ($status == 0) { rmtree ($work); }
exit $status;
