eval '(exit $?0)' && eval 'exec perl -S $0 ${1+"$@"}'
     & eval 'exec perl -S $0 $argv:q'
     if 0;

# -*- perl -*-
#
# The TAO client side of CSIv2 SAS (Phase 2 W6), TAO to TAO:
#  - GSSUP credentials acquired through SecurityLevel3 ("SL3GSSUP") with
#    the password read from a file (owner-only), a file descriptor or a
#    terminal, never from the command line;
#  - sent only over TLS and only to targets whose GSSUP target name
#    matches the credentials (a password is never offered to another
#    realm's server); a target that requires GSSUP without matching
#    credentials is refused locally;
#  - ContextError replies become NO_PERMISSION and are audited;
#  - a middle tier with csiv2_assert_caller = on asserts its caller (the
#    GSSUP user, or the caller's certificate chain) to a back end that
#    lists it as an asserter.
# Uses the SAS test's server and client; certificates and the signer
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
my $work = "$dir/client_work";
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

# whoami on alpha: alice only; everything on beta: everyone.
my $acl = "$work/access.list";
spit ($acl, "version 0\nissued 2026-01-01T00:00:00Z\n"
          . "allow alice\@lab.test /RootPOA/Who/alpha whoami\n"
          . "allow * /RootPOA/Who/beta\n");
my $o = `$tool --conf /dev/null access sign $sign --file $acl --bump 2>&1`;
die "access sign failed:\n$o" unless $? == 0 && -s "$acl.sig";

# The back end trusts the middle tier (the server certificate) to assert.
my $asserters = "$work/asserters.list";
spit ($asserters, "version 0\nissued 2026-01-01T00:00:00Z\n"
                . "asserter spiffe://ace-tao.test/server types=name,x509 realms=\@lab.test\n");
$o = `$tool --conf $tconf asserters sign $sign --file $asserters --bump 2>&1`;
die "asserters sign failed:\n$o" unless $? == 0 && -s "$asserters.sig";
my $nobody = "$work/asserters_nobody.list";
spit ($nobody, "version 0\nissued 2026-01-01T00:00:00Z\n"
             . "asserter spiffe://ace-tao.test/client2 types=name,x509 realms=\@lab.test\n");
$o = `$tool --conf $tconf asserters sign $sign --file $nobody --bump 2>&1`;
die "asserters sign failed:\n$o" unless $? == 0 && -s "$nobody.sig";

my $base = "mode = " . ($prod ? "prod" : "test") . "\naudit_sink = stderr\ntime_sync_wait = 0\n"
         . "trust_anchor_sha256 = $fp\naccess_list = $acl\naccess_list_signer = $certs/signer_pub.pem\n"
         . "access_list_signer_sha256 = $pin\naccess_default = deny\naudit_grants = on\n"
         . "csiv2 = supported\ngssup_target = \@lab.test\n"
         . "denylist_signer = $certs/signer_pub.pem\ndenylist_signer_sha256 = $pin\n";
my %conf = (supported => $base . "csiv2_gssup = supported\n",
            required  => $base . "csiv2_gssup = required\n",
            middle    => $base . "csiv2_gssup = supported\ncsiv2_assert_caller = on\n",
            plain     => $base . "csiv2_gssup = supported\n",
            backend   => $base . "csiv2_gssup = supported\ncsiv2_asserters = $asserters\n",
            stranger  => $base . "csiv2_gssup = supported\ncsiv2_asserters = $nobody\n");
foreach my $k (keys %conf) { spit ("$work/$k.conf", $conf{$k}); chmod (0600, "$work/$k.conf"); }
# The client's own configuration: audit records to its stderr.
spit ("$work/client.conf", "mode = test\naudit_sink = stderr\ntime_sync_wait = 0\naudit_grants = on\n");
chmod (0600, "$work/client.conf");

# Password sources (test data only).
spit ("$work/pw_good", "wonderland\n");
spit ("$work/pw_bad", "not-the-password\n");
spit ("$work/pw_open", "wonderland\n");
chmod (0600, "$work/pw_good", "$work/pw_bad");
chmod (0644, "$work/pw_open");

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

my %srv;
sub start_server {
    my ($name, $which) = @_;
    my $d = "$work/$name";
    mkdir $d;
    # A server started again in the same directory: wait for its new references.
    unlink ("$d/alpha.ior", "$d/beta.ior");
    my $pid = fork ();
    if ($pid == 0) {
        $ENV{'ACE_TAO_SECURITY_CONF'} = "$work/$which.conf";
        open (STDOUT, '>', "$d/server.log"); open (STDERR, '>&STDOUT');
        exec ("$sas/server", '-ORBSvcConf', "$work/server.svc", '-ORBListenEndpoints', 'iiop://127.0.0.1:', '-d', $d);
        exit 127;
    }
    for (my $i = 0; $i < 100 && !-s "$d/beta.ior"; ++$i) { select (undef, undef, undef, 0.1); }
    $srv{$name} = { pid => $pid, dir => $d, log => "$d/server.log" };
}
sub stop_server {
    my ($name) = @_;
    my $s = $srv{$name};
    `$sas/client -ORBSvcConf $work/client.svc -k file://$s->{dir}/beta.ior -c shutdown -m none -g alice\@lab.test:file:$work/pw_good 2>&1`;
    my $gone = 0;
    for (my $i = 0; $i < 50 && !$gone; ++$i) { $gone = waitpid ($s->{pid}, WNOHANG) == $s->{pid}; select (undef, undef, undef, 0.1) unless $gone; }
    if (!$gone) { kill ('KILL', $s->{pid}); waitpid ($s->{pid}, 0); print STDERR "ERROR: server $name did not shut down\n"; $status = 1; }
}
sub ior { my ($name, $obj) = @_; return "file://$srv{$name}->{dir}/$obj.ior"; }
sub call {
    my ($name, $obj, $what, $extra) = @_;
    my $k = ior ($name, $obj);
    return scalar (`ACE_TAO_SECURITY_CONF=$work/client.conf $sas/client -ORBSvcConf $work/client.svc -k $k -c $what -m none $extra 2>&1`);
}
sub log_of { my $name = shift; select (undef, undef, undef, 0.3); return slurp ($srv{$name}->{log}); }

my $alice = 'name=oid:2\.23\.130\.1\.2\.1:alice\@lab\.test';

# --- GSSUP from a TAO client -------------------------------------------------------
start_server ('main', 'supported');
$o = call ('main', 'alpha', 'whoami', "-g alice\@lab.test:file:$work/pw_good");
expect ('SL3GSSUP (password file): TAO sends the login; the servant sees alice', $o,
        ['^ACQUIRE OK$', '^SAS REPLY complete ctx=0 stateful=0$', "^WHOAMI $alice "]);
expect ('  ... acquisition audited without the password; the login is sent', $o,
        ['reason="GSSUP_CREDENTIALS_ACQUIRED" user="alice\@lab\.test" target="\@lab\.test" password_source="file:',
         'reason="SAS_CLIENT_SENT" user="alice\@lab\.test"'], ['wonderland']);
$o = call ('main', 'alpha', 'whoami', "-g alice\@lab.test:file:$work/pw_good -G");
expect ('SL3GSSUP credentials in a ContextEstablishmentPolicy', $o,
        ['^ACQUIRE OK$', '^SAS REPLY complete ', "^WHOAMI $alice "]);
$o = scalar (`ACE_TAO_SECURITY_CONF=$work/client.conf $sas/client -ORBSvcConf $work/client.svc -k ${\ior('main','alpha')} -c whoami -m none -g alice\@lab.test:fd:3 3<$work/pw_good 2>&1`);
expect ('SL3GSSUP from a file descriptor', $o, ['^ACQUIRE OK$', "^WHOAMI $alice "]);
$o = call ('main', 'alpha', 'whoami', "-g alice\@lab.test:file:$work/pw_bad");
expect ('wrong password: ContextError 1 becomes NO_PERMISSION; the client audits the refusal', $o,
        ['^ACQUIRE OK$', '^SAS REPLY error ctx=0 major=1 ', '^whoami EXCEPTION NO_PERMISSION$',
         'reason="SAS_CLIENT_REFUSED" op="whoami" context_error="1"'], ['not-the-password']);
$o = call ('main', 'beta', 'poke', "-g alice\@other.test:file:$work/pw_good");
expect ('credentials for another realm are not offered to this target (no SAS context)', $o,
        ['^ACQUIRE OK$', '^SAS REPLY none$', '^POKE OK$'], ['SAS_CLIENT_SENT']);
$o = call ('main', 'beta', 'poke', "-g alice\@lab.test:file:$work/pw_good:\@elsewhere.test");
expect ('  ... nor are credentials bound to another target name', $o, ['^SAS REPLY none$', '^POKE OK$'], ['SAS_CLIENT_SENT']);
$o = call ('main', 'beta', 'poke', "-g alice\@lab.test:file:$work/pw_good -b");
expect ('  ... nor when the policy turns client authentication off', $o, ['^SAS REPLY none$', '^POKE OK$']);
expect ('  (the server saw no login for those calls)', log_of ('main'), [], ['principal="alice\@other\.test"']);
$o = call ('main', 'beta', 'poke', "-g alice\@lab.test:file:$work/pw_open");
expect ('a password file readable by others is refused', $o,
        ['^ACQUIRE FAILED BAD_PARAM$', 'reason="SAS_CLIENT_NO_CREDENTIALS" .*readable or writable by others']);
$o = call ('main', 'beta', 'poke', "-g alice\@lab.test:wonderland");
expect ('a password given in place of a source is refused (never from arguments)', $o,
        ['^ACQUIRE FAILED BAD_PARAM$', 'unknown password_source'], ['SAS_CLIENT_SENT']);
$o = call ('main', 'beta', 'poke', "-g alice:file:$work/pw_good");
expect ('a username without a realm needs an explicit target name', $o, ['^ACQUIRE FAILED BAD_PARAM$', 'no target name']);
stop_server ('main');

start_server ('req', 'required');
$o = call ('req', 'beta', 'poke', "-g alice\@lab.test:file:$work/pw_good");
expect ('required: served with matching credentials', $o, ['^SAS REPLY complete ', '^POKE OK$']);
$o = call ('req', 'beta', 'poke', "-g alice\@other.test:file:$work/pw_good");
expect ('required: no matching credentials, refused locally (the target is not asked)', $o,
        ['^SAS REPLY none$', '^poke EXCEPTION NO_PERMISSION$', 'reason="SAS_CLIENT_NO_CREDENTIALS" target="\@lab\.test" op="poke"']);
expect ('  (and the server never saw it)', log_of ('req'), [], ['reason="SAS_MISSING"']);
stop_server ('req');

# --- a middle tier asserting its caller -------------------------------------------
start_server ('backend', 'backend');
start_server ('middle', 'middle');
my $back = ior ('backend', 'beta');
$o = call ('middle', 'beta', 'relay', "-g alice\@lab.test:file:$work/pw_good -r $back");
expect ('middle tier asserts its GSSUP caller: the back end serves alice, the middle tier as asserter', $o,
        ["^RELAY $alice .*alt=TAO:SPIFFEID:spiffe://ace-tao\\.test/server"]);
expect ('  ... the back end audits both', log_of ('backend'),
        ['reason="SAS_ACCEPTED" principal="alice\@lab\.test" transport_principal="spiffe://ace-tao\.test/server" asserter="spiffe://ace-tao\.test/server"']);
expect ('  ... the middle tier audits what it asserted', log_of ('middle'),
        ['reason="SAS_CLIENT_SENT" asserted="alice\@lab\.test" op="whoami"']);
$o = call ('middle', 'beta', 'relay', "-r $back");
expect ('middle tier asserts a certificate caller as its certificate chain', $o,
        ['^RELAY name=TAO:SPIFFEID:spiffe://ace-tao\.test/client .*alt=TAO:SPIFFEID:spiffe://ace-tao\.test/server']);
stop_server ('middle');

start_server ('plain', 'plain');
$o = call ('plain', 'beta', 'relay', "-g alice\@lab.test:file:$work/pw_good -r $back");
expect ('without csiv2_assert_caller the back end sees the middle tier itself', $o,
        ['^RELAY name=TAO:SPIFFEID:spiffe://ace-tao\.test/server'], ['^RELAY .*alice']);
stop_server ('plain');
stop_server ('backend');

start_server ('stranger', 'stranger');
start_server ('middle', 'middle');
$o = call ('middle', 'beta', 'relay', "-g alice\@lab.test:file:$work/pw_good -r ${\ior('stranger','beta')}");
expect ('a back end that does not list the middle tier refuses the assertion (NO_PERMISSION)', $o,
        ['^relay EXCEPTION NO_PERMISSION$']);
expect ('  ... ASSERTION_REJECTED there, SAS_CLIENT_REFUSED in the middle tier', log_of ('stranger') . log_of ('middle'),
        ['reason="ASSERTION_REJECTED" .*asserter spiffe://ace-tao\.test/server is not on the asserter list',
         'reason="SAS_CLIENT_REFUSED" op="whoami" context_error="1"']);
stop_server ('middle');
stop_server ('stranger');

rmtree ($work) if $status == 0;
exit $status;
