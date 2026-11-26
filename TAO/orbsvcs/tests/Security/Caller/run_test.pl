eval '(exit $?0)' && eval 'exec perl -S $0 ${1+"$@"}'
     & eval 'exec perl -S $0 $argv:q'
     if 0;

# -*- perl -*-
#
# Caller identity and the access decision on TLS calls: every request on
# a TLS connection gets a caller record from the peer certificate (SPIFFE
# ID, subject, serial, peer address); the servant reads it through
# SecurityLevel3::SecurityCurrent; TAO's AccessDecision decides the
# request on it with the signed access list (allow/deny rules per
# principal, object and operation; deny wins; no rule is refused in prod
# and with access_default = deny); refusals are audited.  The list is
# signed and tried out with ace-tao-setup access, reloaded when it
# changes, and a bad or older list is refused.  Certificates and the
# signer come from ../Transport (make_certs.sh there).

use lib "$ENV{ACE_ROOT}/bin";
use PerlACE::TestTarget;
use Cwd;
use File::Path qw(rmtree);
use POSIX qw(strftime :sys_wait_h);

my $test = PerlACE::TestTarget::create_target (1) || die "Create target 1 failed\n";
my $dir = getcwd ();
my $certs = "$dir/../Transport";
my $work = "$dir/caller_work";
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

# prod needs a synchronized clock; elsewhere (containers) run in test
# mode with access_default = deny, which decides the same way.
my $clock = -x "$dir/../Mode/mode_test" ? `$dir/../Mode/mode_test -clock` : 'synced';
my $prod = $clock =~ /^synced/;
print "mode: " . ($prod ? "prod" : "test (clock not synchronized)") . "\n";

my $fp = `openssl x509 -in $certs/ca.pem -noout -fingerprint -sha256`;
$fp =~ s/.*=//; chomp $fp;
my ($pin) = `$tool --conf /dev/null denylist pin --signer $certs/signer_pub.pem` =~ /= (\w+)/;
my $acl = "$work/access.list";
my $conf_base = "mode = " . ($prod ? "prod" : "test") . "\naudit_sink = stderr\ntime_sync_wait = 0\n"
              . "trust_anchor_sha256 = $fp\naccess_list_signer = $certs/signer_pub.pem\n"
              . "access_list_reload = 1\n" . ($prod ? "" : "access_default = deny\n");
my $conf = "$work/security.conf";
spit ($conf, $conf_base . "access_list = $acl\naccess_list_signer_sha256 = $pin\n");
chmod (0600, $conf);
my $sign = "--key PEM:$certs/signer_key_enc.pem --password-file $certs/password.txt";

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
svc ('client2', 'client2_cert.pem', 'client2_key_enc.pem');

my $now = strftime ("%Y-%m-%dT%H:%M:%SZ", gmtime ());
my $rules_v1 = "# Caller test access list\nversion 0\nissued $now\n"
             . "allow spiffe://ace-tao.test/client   /RootPOA/Who/alpha\n"
             . "allow spiffe://ace-tao.test/client   /RootPOA/Who/beta  whoami\n"
             . "deny  spiffe://ace-tao.test/client2  *\n"
             . "allow *                              /RootPOA/Who/alpha whoami\n";
spit ($acl, $rules_v1);

# --- ace-tao-setup access -------------------------------------------------
my $out = `$tool --conf $conf access sign $sign --bump 2>&1`;
expect ('access sign --bump writes version 1 and signs it', $out,
        ['reason="ACCESS_LIST_SIGNED"', 'version 1 issued .* 4 rule\(s\); signed into']);
expect ('access check verifies it with the pinned signer and lists the rules', `$tool --conf $conf access check 2>&1`,
        ['^OK: .* version 1 .* 4 rule\(s\)', '\(pinned\)',
         'allow spiffe://ace-tao.test/client /RootPOA/Who/beta whoami',
         'deny  spiffe://ace-tao.test/client2 \* \(all operations\)']);
expect ('access sign refuses a key that is not the pinned signer',
        `$tool --conf $conf access sign --key PEM:$certs/impostor_key_enc.pem --password-file $certs/password.txt 2>&1`,
        ['is not the pinned access-list signer']);
spit ("$work/bad.list", "version 1\nissued $now\nallow spiffe://x /a*b\n");
expect ('access sign refuses a malformed list',
        `$tool --conf $conf access sign $sign --file $work/bad.list 2>&1`, ['line 3: \* may only end the object']);
spit ("$work/star.list", "version 1\nissued $now\nallow spiffe://x /a *\n");
expect ('a lone * in the operations means every operation',
        `$tool --conf $conf access sign $sign --file $work/star.list 2>&1 && $tool --conf $conf access check --file $work/star.list 2>&1`,
        ['allow spiffe://x /a \(all operations\)']);
spit ("$work/star2.list", "version 1\nissued $now\nallow spiffe://x /a * whoami\n");
expect ('* listed with named operations is refused',
        `$tool --conf $conf access sign $sign --file $work/star2.list 2>&1`,
        ['line 3: \* stands for every operation and cannot be listed with others']);

sub try { my ($args) = @_; my $o = `$tool --conf $conf access test $args 2>&1`; return ($o, $? >> 8); }
my ($t, $rc) = try ('--principal spiffe://ace-tao.test/client --object /RootPOA/Who/beta --op poke');
expect ('access test: no rule is refused', "$t rc=$rc", ['^REFUSED: .*\(no rule; (prod refuses|access_default deny)\)', 'rc=2']);
($t, $rc) = try ('--principal spiffe://ace-tao.test/client2 --object /RootPOA/Who/alpha --op whoami');
expect ('access test: a deny wins over a matching allow', "$t rc=$rc", ['^REFUSED: .*\(a deny rule\)', 'rc=2']);
($t, $rc) = try ('--principal spiffe://ace-tao.test/other --object /RootPOA/Who/alpha --op whoami');
expect ('access test: * allows any identified caller', "$t rc=$rc", ['^ALLOWED: .*\(an allow rule\)', 'rc=0']);

# --- prod start-up checks ---------------------------------------------------
if ($prod) {
    my $bad = "$work/bad.conf";
    spit ($bad, $conf_base); chmod (0600, $bad);
    expect ('prod refuses to run without an access list',
            `ACE_TAO_SECURITY_CONF=$bad $dir/server -ORBSvcConf $work/server.conf -ORBListenEndpoints iiop://127.0.0.1: -d $work 2>&1`,
            ['FAIL access_list: no access list \(access_list\): every TLS request would be refused', 'ORB_INIT REFUSED']);
    spit ($bad, $conf_base . "access_list = $acl\naccess_list_signer_sha256 = $pin\naccess_default = allow\n");
    expect ('prod refuses access_default = allow',
            `ACE_TAO_SECURITY_CONF=$bad $dir/server -ORBSvcConf $work/server.conf -ORBListenEndpoints iiop://127.0.0.1: -d $work 2>&1`,
            ['FAIL access_list: access_default = allow', 'ORB_INIT REFUSED']);
    spit ($bad, $conf_base . "access_list = $acl\n");
    expect ('prod refuses an unpinned access-list signer',
            `ACE_TAO_SECURITY_CONF=$bad $dir/server -ORBSvcConf $work/server.conf -ORBListenEndpoints iiop://127.0.0.1: -d $work 2>&1`,
            ['FAIL access_list: access_list_signer_sha256 \(or denylist_signer_sha256\) is not set', 'ORB_INIT REFUSED']);
}

# --- the server ----------------------------------------------------------------
my $log = "$work/server.log";
my $pid = fork ();
if ($pid == 0) {
    $ENV{'ACE_TAO_SECURITY_CONF'} = $conf;
    open (STDOUT, '>', $log); open (STDERR, '>&STDOUT');
    exec ("$dir/server", '-ORBSvcConf', "$work/server.conf", '-ORBListenEndpoints', 'iiop://127.0.0.1:', '-d', $work);
    exit 127;
}
for (my $i = 0; $i < 100 && !-s "$work/beta.ior"; ++$i) { select (undef, undef, undef, 0.1); }
expect ('server starts with the access list loaded', slurp ($log),
        ['SERVER READY', 'acl=v1', 'checks: \d+ ok, \d+ warn, 0 fail']);

sub call { my ($who, $obj, $what) = @_; return `$dir/client -ORBSvcConf $work/$who.conf -k file://$work/$obj.ior -c $what 2>&1`; }

expect ('the servant sees the caller: SPIFFE ID, then the subject as an alternate name', call ('client', 'alpha', 'whoami'),
        ['^WHOAMI name=TAO:SPIFFEID:spiffe://ace-tao.test/client authenticated=yes alt=SL3:X509DirectoryPathName:CN=transport-client$']);
expect ('an allow rule for the object covers every operation', call ('client', 'alpha', 'poke'), ['^POKE OK']);
expect ('an allow rule for one operation covers only that one', call ('client', 'beta', 'whoami'), ['^WHOAMI name=']);
expect ('another operation on that object has no rule and is refused', call ('client', 'beta', 'poke'),
        ['^poke EXCEPTION NO_PERMISSION']);
expect ('a deny rule wins over a matching allow', call ('client2', 'alpha', 'whoami'),
        ['^whoami EXCEPTION NO_PERMISSION']);
expect ('refusals are audited with the caller, the object and the operation', slurp ($log),
        ['event="authz" result="deny" reason="ACCESS_DENIED" principal="spiffe://ace-tao.test/client" subject="CN=transport-client" cert_serial="[0-9A-F]+" src="127.0.0.1:\d+" object="/RootPOA/Who/beta" op="poke" access_list_version="1"',
         'reason="ACCESS_DENIED" principal="spiffe://ace-tao.test/client2" .*object="/RootPOA/Who/alpha" op="whoami"'],
        ['ACCESS_GRANTED']);

# A changed list that does not verify, then one that is not newer, are
# refused and version 1 kept; a newer signed list is used.
my $v1 = slurp ($acl);
spit ($acl, $v1 . "allow spiffe://ace-tao.test/client /RootPOA/Who/beta poke\n");
sleep (2);
expect ('a tampered list is not used', call ('client', 'beta', 'poke'), ['^poke EXCEPTION NO_PERMISSION']);
spit ($acl, $v1);
sleep (2);
expect ('the old list again (call made so it is re-read)', call ('client', 'beta', 'whoami'), ['^WHOAMI']);
expect ('a list that does not verify, or is not newer, is refused and the last one kept', slurp ($log),
        ['reason="ACCESS_LIST_REJECTED" .*current_version="1".*\] the signature does not verify',
         'reason="ACCESS_LIST_REJECTED" .*\] version 1 is not newer than the current version 1']);

(my $v2 = $v1) =~ s/^deny  spiffe:\/\/ace-tao.test\/client2  \*\n//m;
$v2 .= "allow spiffe://ace-tao.test/client2  /RootPOA/Who/beta  poke shutdown\n";
spit ($acl, $v2);
$out = `$tool --conf $conf access sign $sign --bump 2>&1`;
expect ('access sign --bump publishes version 2', $out, ['version 2 issued .* 4 rule\(s\)']);
sleep (2);
expect ('the new list is used: client2 may now poke beta', call ('client2', 'beta', 'poke'), ['^POKE OK']);
expect ('and whoami on alpha through the * rule', call ('client2', 'alpha', 'whoami'),
        ['^WHOAMI name=TAO:SPIFFEID:spiffe://ace-tao.test/client2 ']);
expect ('the reload is audited', slurp ($log),
        ['reason="ACCESS_LIST_LOADED" .*version="2".*rules="4".*previous_version="1"']);

call ('client2', 'beta', 'shutdown');
my $gone = 0;
for (my $i = 0; $i < 50 && !$gone; ++$i) {
    $gone = waitpid ($pid, WNOHANG) == $pid;
    select (undef, undef, undef, 0.1) unless $gone;
}
if (!$gone) { kill ('KILL', $pid); waitpid ($pid, 0); print STDERR "ERROR: server did not shut down\n"; $status = 1; }

if ($status == 0) { rmtree ($work); }
else { print STDERR "server log:\n" . slurp ($log); }
exit $status;
