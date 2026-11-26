eval '(exit $?0)' && eval 'exec perl -S $0 ${1+"$@"}'
     & eval 'exec perl -S $0 $argv:q'
     if 0;

# -*- perl -*-
#
# The role model's signed policy tables (Phase 3 T1, R39 and R40): dated
# files with detached signatures in roles_dir, one loader for the rights,
# grants and roles tables.
#  - ace-tao-setup KIND sign gives each table the next version and a dated
#    name (KIND-YYYY-MM-DD.txt, then .2.txt the same day), signed by the
#    roles signer, never by the deny-list signer (D3.7);
#  - the highest version among files that verify wins; a file whose signed
#    issued date differs from its name (an older file renamed), whose
#    header names another table, or whose signature fails is refused;
#  - a service loads all three at startup (prod refuses to start without
#    them), picks up a newly signed table within roles_reload, keeps the
#    last good table when a new file fails, and with roles_state refuses
#    after a restart a version lower than one it accepted before.
# Uses the SAS test's server and client; certificates and the deny-list
# signer from ../Transport.

use lib "$ENV{ACE_ROOT}/bin";
use PerlACE::TestTarget;
use Cwd;
use File::Copy;
use File::Path qw(rmtree);
use POSIX qw(:sys_wait_h strftime);

my $test = PerlACE::TestTarget::create_target (1) || die "Create target 1 failed\n";
my $dir = getcwd ();
my $sas = "$dir/../SAS";
my $certs = "$dir/../Transport";
my $work = "$dir/roles_work";
my $tables = "$work/tables";
my $tool = "$ENV{TAO_ROOT}/orbsvcs/Security_Setup/ace-tao-setup";
my $openssl = $ENV{'OPENSSL'} || (-x '/opt/homebrew/opt/openssl@3/bin/openssl' ? '/opt/homebrew/opt/openssl@3/bin/openssl' : 'openssl');
my $status = 0;

rmtree ($work);
mkdir $work;
mkdir $tables;
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
my $deny_sign = "--key PEM:$certs/signer_key_enc.pem --password-file $certs/password.txt";

# The roles signer: a key of its own (D3.7), made for this run.
`$openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $work/roles_key.pem 2>&1`;
`$openssl pkey -in $work/roles_key.pem -pubout -out $work/roles_pub.pem 2>&1`;
chmod (0600, "$work/roles_key.pem");
my ($rpin) = `$tool --conf /dev/null denylist pin --signer $work/roles_pub.pem` =~ /= (\w+)/;
die "no roles signer pin\n" unless $rpin;
`$openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $work/other_key.pem 2>&1`;
chmod (0600, "$work/other_key.pem");
my $sign = "--key PEM:$work/roles_key.pem";

my $state = "$work/roles.state";
my $tconf = "$work/tool.conf";
spit ($tconf, "mode = test\naudit_sink = stderr\nroles_dir = $tables\nroles_signer = $work/roles_pub.pem\n"
            . "roles_signer_sha256 = $rpin\nroles_state = $state\ndenylist_signer_sha256 = $pin\n");
sub tool { return scalar (`$tool --conf $tconf @_ 2>&1`); }

my $qt = quotemeta ($tables);
my $today = strftime ('%Y-%m-%d', gmtime (time ()));
my $tomorrow = strftime ('%Y-%m-%d', gmtime (time () + 86400));
spit ("$work/rights.draft", "# draft: required rights (contents come with T2)\nop Naming get\n");
spit ("$work/grants.draft", "grant reader get\n");
spit ("$work/roles.draft", "role alice\@lab.test reader\n");
sub plant { my ($from, $to) = @_; copy ($from, $to) || die "$from: $!"; copy ("$from.sig", "$to.sig") || die "$from.sig: $!"; }

# --- signing ---------------------------------------------------------------------------
my $o = tool ("rights sign $sign --file $work/rights.draft");
expect ('rights sign writes a dated, signed table at version 1 (audited)', $o,
        ["^$qt/rights-$today\\.txt: table rights version 1 issued ${today}T\\S+Z, 1 line\\(s\\); signed into",
         'reason="ROLES_TABLE_SIGNED" .*table="rights"']);
expect ('  ... its header is signed with it', slurp ("$tables/rights-$today.txt"),
        ["^table rights\nversion 1\nissued ${today}T", '^op Naming get$']);
$o = tool ("rights sign $sign --file $work/rights.draft");
expect ('a second rights table the same day is revision .2 at version 2', $o,
        ["rights-$today\\.2\\.txt: table rights version 2 "]);
tool ("grants sign $sign --file $work/grants.draft");
tool ("roles sign $sign --file $work/roles.draft");
expect ('grants and roles tables are signed the same way', join ('', map { -s "$tables/$_-$today.txt.sig" ? "$_ " : '' } qw(grants roles)),
        ['^grants roles $']);
expect ('the deny-list signer may not sign policy tables (D3.7)', tool ("rights sign $deny_sign --file $work/rights.draft"),
        ['the key is not the pinned roles signer']);
{
    # Even unpinned, the deny-list key is refused.
    (my $c = slurp ($tconf)) =~ s/^roles_signer_sha256 = .*\n//m;
    spit ("$work/tool_nopin.conf", $c);
    expect ('  ... even when the roles signer is not pinned',
            scalar (`$tool --conf $work/tool_nopin.conf rights sign $deny_sign --file $work/rights.draft 2>&1`),
            ['the key is the deny-list signer: policy tables need their own key \(D3\.7\)']);
}
expect ('another key is not the pinned roles signer', tool ("rights sign --key PEM:$work/other_key.pem --file $work/rights.draft"),
        ['the key is not the pinned roles signer']);

# --- which file wins -----------------------------------------------------------------------
$o = tool ('rights check');
expect ('rights check: the highest version wins; the older one is passed over', $o,
        ["^OK: rights version 2 issued \\S+ from $qt/rights-$today\\.2\\.txt",
         "rights-$today\\.txt  refused: version 1 is not the highest \\(2 is\\)"]);
plant ("$tables/rights-$today.txt", "$tables/rights-$tomorrow.txt");
plant ("$tables/grants-$today.txt", "$tables/rights-$today.5.txt");
$o = tool ('rights check');
expect ('an older table renamed to a later date is refused (its signed issued date gives it away)', $o,
        ["rights-$tomorrow\\.txt  refused: its signed issued date $today does not match the date in its name",
         '^OK: rights version 2 ']);
expect ('a table named for another kind is refused (its signed header names grants)', $o,
        ["rights-$today\\.5\\.txt  refused: its header names table \"grants\""]);

# --- a service -----------------------------------------------------------------------------
my $acl = "$work/access.list";
spit ($acl, "version 0\nissued 2026-01-01T00:00:00Z\nallow * /RootPOA/Who/beta\n");
$o = `$tool --conf /dev/null access sign $deny_sign --file $acl --bump 2>&1`;
die "access sign failed:\n$o" unless $o =~ /signed into/;
my $base = "mode = " . ($prod ? "prod" : "test") . "\naudit_sink = stderr\ntime_sync_wait = 0\n"
         . "trust_anchor_sha256 = $fp\naccess_list = $acl\naccess_list_signer = $certs/signer_pub.pem\n"
         . "access_list_signer_sha256 = $pin\naccess_default = deny\n"
         . "denylist_signer = $certs/signer_pub.pem\ndenylist_signer_sha256 = $pin\n";
my $roles = "roles_dir = $tables\nroles_signer = $work/roles_pub.pem\nroles_signer_sha256 = $rpin\n"
          . "roles_reload = 1\nroles_state = $state\n";
spit ("$work/roles.conf", $base . $roles);
spit ("$work/samekey.conf", $base . "roles_dir = $tables\nroles_signer = $certs/signer_pub.pem\nroles_signer_sha256 = $pin\n");
mkdir "$work/partial";
copy ("$tables/rights-$today.2.txt", "$work/partial/rights-$today.2.txt"); copy ("$tables/rights-$today.2.txt.sig", "$work/partial/rights-$today.2.txt.sig");
copy ("$tables/roles-$today.txt", "$work/partial/roles-$today.txt"); copy ("$tables/roles-$today.txt.sig", "$work/partial/roles-$today.txt.sig");
spit ("$work/partial.conf", $base . "roles_dir = $work/partial\nroles_signer = $work/roles_pub.pem\nroles_signer_sha256 = $rpin\n");
chmod (0600, map { "$work/$_.conf" } qw(roles samekey partial));

my $svc = "-SSLAuthenticate SERVER_AND_CLIENT -SSLCAfile PEM:$certs/ca.pem -SSLPassword file:$certs/password.txt";
spit ("$work/server.svc", "dynamic SSLIOP_Factory Service_Object * TAO_SSLIOP:_make_TAO_SSLIOP_Protocol_Factory() "
                        . "\"$svc -SSLCertificate PEM:$certs/server_cert.pem -SSLPrivateKey PEM:$certs/server_key_enc.pem\"\n"
                        . "static Resource_Factory \"-ORBProtocolFactory SSLIOP_Factory\"\n");
spit ("$work/client.svc", "dynamic SSLIOP_Factory Service_Object * TAO_SSLIOP:_make_TAO_SSLIOP_Protocol_Factory() "
                        . "\"$svc -SSLCertificate PEM:$certs/client_cert.pem -SSLPrivateKey PEM:$certs/client_key_enc.pem\"\n"
                        . "static Resource_Factory \"-ORBProtocolFactory SSLIOP_Factory\"\n");

my ($pid, $d, $log);
sub start_server {
    my ($which, $tag) = @_;
    $d = "$work/$which" . (defined $tag ? "_$tag" : '');
    mkdir $d;
    unlink ("$d/alpha.ior", "$d/beta.ior");
    $log = "$d/server.log";
    $pid = fork ();
    if ($pid == 0) {
        $ENV{'ACE_TAO_SECURITY_CONF'} = "$work/$which.conf";
        open (STDOUT, '>', $log); open (STDERR, '>&STDOUT');
        exec ("$sas/server", '-ORBSvcConf', "$work/server.svc", '-ORBListenEndpoints', 'iiop://127.0.0.1:', '-d', $d);
        exit 127;
    }
    for (my $i = 0; $i < 100 && !-s "$d/beta.ior" && waitpid ($pid, WNOHANG) == 0; ++$i) { select (undef, undef, undef, 0.1); }
}
sub poke { return scalar (`$sas/client -ORBSvcConf $work/client.svc -k file://$d/beta.ior -c poke -m none 2>&1`); }
sub stop_server {
    `$sas/client -ORBSvcConf $work/client.svc -k file://$d/beta.ior -c shutdown -m none 2>&1`;
    my $gone = 0;
    for (my $i = 0; $i < 50 && !$gone; ++$i) { $gone = waitpid ($pid, WNOHANG) == $pid; select (undef, undef, undef, 0.1) unless $gone; }
    if (!$gone) { kill ('KILL', $pid); waitpid ($pid, 0); print STDERR "ERROR: server did not shut down\n"; $status = 1; }
}
sub run_once {   # a server that should refuse to start: its output
    my ($which) = @_;
    return scalar (`ACE_TAO_SECURITY_CONF=$work/$which.conf $sas/server -ORBSvcConf $work/server.svc -ORBListenEndpoints iiop://127.0.0.1: -d $work 2>&1 & p=\$!; sleep 3; kill \$p 2>/dev/null; wait \$p 2>/dev/null`);
}
sub log_now { select (undef, undef, undef, 0.3); return slurp ($log); }

start_server ('roles');
$o = slurp ($log);
expect ('the service loads all three tables at startup (self-check and banner)', $o,
        ['SERVER READY', 'checks: \d+ ok, \d+ warn, 0 fail', 'roles=v2/v1/v1']);
expect ('  (audited: each table loaded, the planted files refused with their reasons)', $o,
        ["reason=\"ROLES_TABLE_LOADED\" table=\"rights\" version=\"2\" .*file=\"\\S+rights-$today\\.2\\.txt\" lines=\"1\"",
         'reason="ROLES_TABLE_LOADED" table="grants" version="1"', 'reason="ROLES_TABLE_LOADED" table="roles" version="1"',
         "reason=\"ROLES_TABLE_REJECTED\" table=\"rights\" file=\"\\S+rights-$tomorrow\\.txt\"\\] its signed issued date",
         "reason=\"ROLES_TABLE_REJECTED\" table=\"rights\" file=\"\\S+rights-$today\\.5\\.txt\"\\] its header names table"]);
expect ('  ... and records the versions it accepted (roles_state)', slurp ($state), ['^rights 2$', '^grants 1$', '^roles 1$']);

tool ("rights sign $sign --file $work/rights.draft");
sleep (2);
poke ();
expect ('a newly signed table is picked up within roles_reload', log_now (),
        ['reason="ROLES_TABLE_LOADED" table="rights" version="3" .* replaces="2"']);
tool ("rights sign $sign --file $work/rights.draft");
my ($v4) = grep { slurp ($_) =~ /^version 4$/m } glob ("$tables/rights-*.txt");
my $qv4 = quotemeta ($v4);
open (my $fh, '>>', $v4) || die "$v4: $!"; print $fh "op Naming destroy\n"; close ($fh);
sleep (2);
poke ();
$o = log_now ();
expect ('a table altered after signing is refused, and the last good table stays', $o,
        ["reason=\"ROLES_TABLE_REJECTED\" table=\"rights\" file=\"$qv4\"\\] .*(signature|verif)"],
        ['reason="ROLES_TABLE_LOADED" table="rights" version="4"']);
sleep (2);
poke ();
my $count = () = log_now () =~ /ROLES_TABLE_REJECTED" table="rights" file="\Q$v4\E"/g;
expect ('  ... audited once, not at every reload', "$count", ['^1$']);
stop_server ();
expect ('the state file holds the highest accepted version', slurp ($state), ['^rights 3$']);

# Rollback across a restart: the newest tables are deleted while the
# service is down; roles_state still remembers version 3.
foreach my $f (glob ("$tables/rights-*.txt")) {
    my $t = slurp ($f);
    if ($t =~ /^version [34]$/m) { unlink ($f, "$f.sig"); }
}
$o = run_once ('roles');
if ($prod) {
    expect ('after a rollback (newest tables deleted) prod refuses to start', $o,
            ['FAIL roles: policy tables incomplete \(rights missing, grants v1, roles v1\): rights: no file verifies and qualifies',
             'ORB_INIT REFUSED']);
} else {
    expect ('after a rollback (newest tables deleted) the self-check reports it', $o,
            ['WARN roles: policy tables incomplete \(rights missing, grants v1, roles v1\)']);
}
expect ('  (audited: the remaining table is below the recorded version)', $o,
        ['reason="ROLES_TABLE_REJECTED" table="rights" .*version 2 is below 3, the lowest acceptable']);

if ($prod) {
    expect ('prod refuses to start with a table missing', run_once ('partial'),
            ['FAIL roles: policy tables incomplete \(rights v2, grants missing, roles v1\): grants: no grants-YYYY-MM-DD\.txt file',
             'ORB_INIT REFUSED']);
    expect ('prod refuses the deny-list signer as the roles signer (D3.7)', run_once ('samekey'),
            ['FAIL roles: the roles signer is the deny-list signer: policy tables need their own key \(D3\.7\)']);
} else {
    expect ('a missing table is reported by the self-check', run_once ('partial'),
            ['WARN roles: policy tables incomplete \(rights v2, grants missing, roles v1\)']);
}

rmtree ($work) if $status == 0;
exit $status;
