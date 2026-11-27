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
# T2 adds the decision (rights, grants, roles; R33, R34, R38, R41) and T3
# the full role map: role-map, store and AD SID groups, via= and
# factors=tls+gssup conditions, asserter roles= caps, anonymous, and
# ace-tao-setup roles import (R35 to R37, R40).
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
spit ("$work/rights.draft", "# required rights of the test's Who interface\nrequire IDL:Who:1.0 whoami get\n");
spit ("$work/grants.draft", "grant reader get\n");
spit ("$work/roles.draft", "role alice\@lab.test reader\n");
sub plant { my ($from, $to) = @_; copy ($from, $to) || die "$from: $!"; copy ("$from.sig", "$to.sig") || die "$from.sig: $!"; }

# --- signing ---------------------------------------------------------------------------
my $o = tool ("rights sign $sign --file $work/rights.draft");
expect ('rights sign writes a dated, signed table at version 1 (audited)', $o,
        ["^$qt/rights-$today\\.txt: table rights version 1 issued ${today}T\\S+Z, 1 line\\(s\\); signed into",
         'reason="ROLES_TABLE_SIGNED" .*table="rights"']);
expect ('  ... its header is signed with it', slurp ("$tables/rights-$today.txt"),
        ["^table rights\nversion 1\nissued ${today}T", '^require IDL:Who:1.0 whoami get$']);
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
spit ("$work/bad.draft", "require IDL:Who:1.0 whoami fetch\n");
expect ('a draft whose body does not parse is not signed', tool ("rights sign $sign --file $work/bad.draft"),
        ['line \d+: unknown right in "fetch"'], ['signed into']);
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
    kill ('TERM', $pid);
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


# --- T2: the decision (R33, R34, R38, R41) ------------------------------------------------
my $t2 = "$work/t2tables";
mkdir $t2;
spit ("$work/t2_rights.draft", "require IDL:Who:1.0 whoami get\nrequire IDL:Who:1.0 poke set\n"
                             . "require IDL:Who:1.0 shutdown manage\n");
spit ("$work/t2_grants.draft", "grant reader get\ngrant writer get,set\ngrant admin get,set,manage,use\n"
                             . "domain /RootPOA/Admin\ngrant admin get,set,manage,use\n");
spit ("$work/t2_roles.draft", "role spiffe://ace-tao.test/client reader\nrole alice\@lab.test writer\n");
tool ("$_ sign $sign --file $work/t2_$_.draft --dir $t2") foreach qw(rights grants roles);
sub decide {
    my ($who, $op, $object) = @_;
    $object = '/RootPOA/Who/alpha' unless defined $object;
    return tool ("roles test --dir $t2 --principal $who --interface IDL:Who:1.0 --op $op --object $object");
}
expect ('roles test: a role holding the required right is allowed', decide ('spiffe://ace-tao.test/client', 'whoami'),
        ['^ALLOWED: ', '^  roles reader; requires get; service domain']);
expect ('roles test: ... and refused when it lacks it', decide ('spiffe://ace-tao.test/client', 'poke'),
        ['^REFUSED: ', 'roles reader; requires set; service domain; roles hold get in the service domain, set required']);
expect ('roles test: another role grants it', decide ('alice@lab.test', 'poke'), ['^ALLOWED: ', 'roles writer; requires set']);
expect ('roles test: an operation not in the rights table is refused', decide ('alice@lab.test', 'relay'),
        ['^REFUSED: ', 'requires \(not listed\); .*not in the required-rights table']);
expect ('roles test: a built-in operation needs get by default', decide ('spiffe://ace-tao.test/client', '_is_a'),
        ['^ALLOWED: ', 'requires get']);
expect ('roles test: a POA domain has only its own grants', decide ('alice@lab.test', 'whoami', '/RootPOA/Admin/console'),
        ['^REFUSED: ', '/RootPOA/Admin domain']);
expect ('roles test: a caller with no role is refused', decide ('carol@lab.test', '_non_existent'),
        ['^REFUSED: ', 'the caller has no role']);

my $t2acl = "$work/t2_access.list";
spit ($t2acl, "version 0\nissued 2026-01-01T00:00:00Z\ndeny alice\@lab.test /RootPOA/Who/beta whoami\n");
$o = `$tool --conf /dev/null access sign $deny_sign --file $t2acl --bump 2>&1`;
die "access sign failed:\n$o" unless $o =~ /signed into/;
(my $t2base = $base) =~ s/^access_list = .*$/access_list = $t2acl/m;
spit ("$work/t2.conf", $t2base . "audit_grants = on\ncsiv2 = supported\ncsiv2_gssup = supported\ngssup_target = \@lab.test\n"
                      . "roles_dir = $t2\nroles_signer = $work/roles_pub.pem\nroles_signer_sha256 = $rpin\n");
spit ("$work/t2rr.conf", $t2base . "roles_dir = $t2\nroles_signer = $work/roles_pub.pem\nroles_signer_sha256 = $rpin\n");
spit ("$work/t2test.conf", "mode = test\naudit_sink = stderr\ntime_sync_wait = 0\n"
                         . "roles_dir = $t2\nroles_signer = $work/roles_pub.pem\nroles_signer_sha256 = $rpin\n");
spit ("$work/client.conf", "mode = test\naudit_sink = stderr\ntime_sync_wait = 0\n");
spit ("$work/pw", "wonderland\n");
chmod (0600, "$work/t2.conf", "$work/t2rr.conf", "$work/t2test.conf", "$work/client.conf", "$work/pw");
sub call {
    my ($obj, $what, $extra) = @_;
    $extra = '' unless defined $extra;
    return scalar (`ACE_TAO_SECURITY_CONF=$work/client.conf $sas/client -ORBSvcConf $work/client.svc -k file://$d/$obj.ior -c $what -m none $extra 2>&1`);
}
my $alice = "-g alice\@lab.test:file:$work/pw";

start_server ('t2');
expect ('the service starts with the role model and no access-list allow rules', slurp ($log),
        ['SERVER READY', 'checks: \d+ ok, \d+ warn, 0 fail', 'roles=v\d+/v\d+/v\d+']);
expect ('a certificate caller with role reader may call whoami', call ('alpha', 'whoami'), ['^WHOAMI ']);
expect ('  ... but not poke, which needs set', call ('alpha', 'poke'), ['^poke EXCEPTION NO_PERMISSION$']);
expect ('alice (GSSUP, role writer) may poke', call ('alpha', 'poke', $alice), ['^POKE OK$']);
call ('alpha', 'shutdown', $alice);   # oneway: a refusal shows only in the audit record
expect ('  ... nor relay, which no rights line covers', call ('alpha', 'relay', "$alice -r file://$d/beta.ior"),
        ['^relay EXCEPTION NO_PERMISSION$']);
expect ('an explicit deny in the access list wins over her roles', call ('beta', 'whoami', $alice),
        ['^whoami EXCEPTION NO_PERMISSION$']);
$o = log_now ();
expect ('  (audited: roles held, rights required, domain and table versions)', $o,
        ['reason="ACCESS_DENIED" principal="spiffe://ace-tao\.test/client" .*op="poke" interface="IDL:Who:1\.0" roles="reader" rights_required="set" domain="service" tables="rights v\d+, grants v\d+, roles v\d+" roles_from="spiffe://ace-tao\.test/client"\] roles hold get in the service domain, set required',
         'reason="ACCESS_DENIED" principal="alice\@lab\.test" .*op="shutdown" .*rights_required="manage" domain="service"',
         'reason="ACCESS_GRANTED" principal="alice\@lab\.test" .*op="poke" interface="IDL:Who:1\.0" roles="reader,writer" rights_required="set"',
         'reason="ACCESS_DENIED" principal="alice\@lab\.test" .*op="relay" .*rights_required="\(unlisted\)".*\] the operation is not in the required-rights table',
         'reason="ACCESS_DENIED" principal="alice\@lab\.test" .*object="/RootPOA/Who/beta" op="whoami" interface="IDL:Who:1\.0" access_list_version="1"\] an explicit deny rule in the access list']);
stop_server ();

# The Naming Service's recommended tables, as shipped (R33): gate G6
# offline, through NamingContextExt, which inherits NamingContext's lines.
my $shipped = "$ENV{TAO_ROOT}/orbsvcs/Security_Setup/tables";
my $nt = "$work/naming";
mkdir $nt;
spit ("$work/naming_roles.draft", "role spiffe://ace-tao.test/reader reader\nrole spiffe://ace-tao.test/publisher publisher\n"
                                . "role spiffe://ace-tao.test/admin ns-admin\n");
expect ('the shipped Naming rights and grants drafts sign cleanly',
        tool ("rights sign $sign --file $shipped/rights-naming.txt --dir $nt")
        . tool ("grants sign $sign --file $shipped/grants-naming.txt --dir $nt")
        . tool ("roles sign $sign --file $work/naming_roles.draft --dir $nt"),
        ['table rights version \d+ .*signed into', 'table grants version \d+ .*signed into', 'table roles version \d+ .*signed into']);
sub ns {
    my ($who, $op) = @_;
    return tool ("roles test --dir $nt --principal spiffe://ace-tao.test/$who --interface IDL:omg.org/CosNaming/NamingContextExt:1.0 --op $op --object /RootPOA/NameService/root");
}
expect ('Naming: a reader can resolve (inherited) and resolve_str', ns ('reader', 'resolve') . ns ('reader', 'resolve_str'),
        ['^ALLOWED: \S+ resolve ', '^ALLOWED: \S+ resolve_str ']);
expect ('Naming: ... but not bind', ns ('reader', 'bind'), ['^REFUSED: ', 'requires set']);
expect ('Naming: a publisher can bind but not destroy', ns ('publisher', 'bind') . ns ('publisher', 'destroy'),
        ['^ALLOWED: \S+ bind ', '^REFUSED: \S+ destroy ', 'requires manage']);
expect ('Naming: an ns-admin can destroy', ns ('admin', 'destroy'), ['^ALLOWED: \S+ destroy ']);
# The Notification Service's recommended tables, as shipped (R33).
my $nn = "$work/notify";
mkdir $nn;
spit ("$work/notify_roles.draft", "role spiffe://ace-tao.test/reader observer\nrole spiffe://ace-tao.test/publisher participant\n"
                                . "role spiffe://ace-tao.test/admin channel-admin\n");
expect ('the shipped Notify rights and grants drafts sign cleanly',
        tool ("rights sign $sign --file $shipped/rights-notify.txt --dir $nn")
        . tool ("grants sign $sign --file $shipped/grants-notify.txt --dir $nn")
        . tool ("roles sign $sign --file $work/notify_roles.draft --dir $nn"),
        ['table rights version \d+ .*signed into', 'table grants version \d+ .*signed into', 'table roles version \d+ .*signed into']);
sub nf {
    my ($who, $iface, $op) = @_;
    return tool ("roles test --dir $nn --principal spiffe://ace-tao.test/$who --interface IDL:$iface:1.0 --op $op --object /RootPOA/NotifyService");
}
expect ('Notify: an observer can read QoS (inherited by ConsumerAdmin) but not obtain a proxy',
        nf ('reader', 'omg.org/CosNotifyChannelAdmin/ConsumerAdmin', 'get_qos')
        . nf ('reader', 'omg.org/CosNotifyChannelAdmin/ConsumerAdmin', 'obtain_notification_push_supplier'),
        ['^ALLOWED: \S+ get_qos ', '^REFUSED: \S+ obtain_notification_push_supplier ', 'requires use']);
expect ('Notify: a participant can connect and push (inherited) but not destroy an admin',
        nf ('publisher', 'omg.org/CosNotifyChannelAdmin/ProxyPushSupplier', 'connect_any_push_consumer')
        . nf ('publisher', 'omg.org/CosNotifyComm/PushConsumer', 'push')
        . nf ('publisher', 'omg.org/CosNotifyChannelAdmin/ConsumerAdmin', 'destroy'),
        ['^ALLOWED: \S+ connect_any_push_consumer ', '^ALLOWED: \S+ push ', '^REFUSED: \S+ destroy ', 'requires manage']);
expect ('Notify: a channel-admin can create channels through NotifyExt::EventChannelFactory',
        nf ('admin', 'NotifyExt/EventChannelFactory', 'create_channel'),
        ['^ALLOWED: \S+ create_channel ']);
spit ("$work/cycle_rights.draft", "inherit IDL:A:1.0 IDL:B:1.0\ninherit IDL:B:1.0 IDL:A:1.0\nrequire IDL:B:1.0 ping get\n");
mkdir "$work/cycle";
tool ("$_ sign $sign --file $work/" . ($_ eq 'rights' ? 'cycle_rights' : "t2_$_") . ".draft --dir $work/cycle") foreach qw(rights grants roles);
expect ('an inheritance cycle in the rights table cannot loop',
        tool ("roles test --dir $work/cycle --principal alice\@lab.test --interface IDL:A:1.0 --op pong") . tool ("roles test --dir $work/cycle --principal alice\@lab.test --interface IDL:A:1.0 --op ping"),
        ['^REFUSED: alice\@lab\.test pong ', 'not in the required-rights table', '^ALLOWED: alice\@lab\.test ping ']);

# SecurityLevel2 RequiredRights (R41).
sub rr { my ($conf, @args) = @_; return scalar (`ACE_TAO_SECURITY_CONF=$work/$conf $dir/rr_probe -ORBSvcConf $work/server.svc @args 2>&1`); }
expect ('RequiredRights answers from the rights table', rr ('t2rr.conf', 'IDL:Who:1.0', 'poke'), ['^RIGHTS s all$']);
expect ('  ... a built-in operation needs get', rr ('t2rr.conf', 'IDL:Who:1.0', '_is_a'), ['^RIGHTS g all$']);
expect ('  ... an unlisted operation has no rights', rr ('t2rr.conf', 'IDL:Who:1.0', 'relay'), ['^RIGHTS none$']);
expect ('set_required_rights is refused in prod (audited)', rr ('t2rr.conf', 'IDL:Who:1.0', 'poke', 'set', 'gu', 'any'),
        ['^SET NO_PERMISSION$', '^RIGHTS s all$', 'reason="REQUIRED_RIGHTS_REFUSED"']) if $prod;
expect ('  ... and changes the in-memory requirement in test mode (audited)',
        rr ('t2test.conf', 'IDL:Who:1.0', 'poke', 'set', 'gu', 'any'),
        ['^SET OK$', '^RIGHTS gu any$', 'reason="REQUIRED_RIGHTS_SET" .*rights_required="any:get,use"']);
expect ('without roles_dir there is no RequiredRights object (NO_IMPLEMENT)', rr ('client.conf', 'IDL:Who:1.0', 'poke'),
        ['^NO_IMPLEMENT$']);


# --- T3: groups, conditions, asserter caps, anonymous (R35 to R37) ---------------------------
my $t3 = "$work/t3tables";
mkdir $t3;
spit ("$work/t3_roles.draft", <<'EOT');
# T3 role map
role alice@lab.test writer
group operators bob@lab.test
role group:operators admin factors=tls+gssup
role group:auditors reader
role sid:S-1-5-21-1-2-3-1105 admin
sid  S-1-5-21-1-2-3-1105 AD.LAB.TEST\ns-admins
role carol@lab.test writer via=spiffe://ace-tao.test/portal
role dave@lab.test admin,writer
role anonymous reader
role CN=legacy gateway,O=Example reader
EOT
$o = tool ("roles sign $sign --file $work/t3_roles.draft --dir $t3");
expect ('a role map with groups, SIDs, conditions and anonymous signs cleanly', $o, ['table roles version \d+ .*signed into']);
tool ("$_ sign $sign --file $work/t2_$_.draft --dir $t3") foreach qw(rights grants);
sub t3 {
    my ($args, $op) = @_;
    return tool ("roles test --dir $t3 --interface IDL:Who:1.0 --op $op --object /RootPOA/Who/alpha $args");
}
expect ('factors=tls+gssup: a role-map group member is refused with a login alone',
        t3 ('--principal bob@lab.test', 'shutdown'), ['^REFUSED: bob\@lab\.test shutdown ', 'the caller has no role']);
expect ('  ... and holds the role with a login over a certificate',
        t3 ('--principal bob@lab.test --cert spiffe://ace-tao.test/client', 'shutdown'),
        ['^ALLOWED: bob\@lab\.test shutdown ', '^  roles from: group:operators$', 'roles admin;']);
expect ('  ... never on a certificate alone', t3 ('--principal spiffe://ace-tao.test/client', 'whoami'),
        ['^REFUSED: ', 'the caller has no role']);
expect ('a store group (groups= on the login\'s store line) gives group:NAME roles',
        t3 ('--principal erin@lab.test --groups auditors', 'whoami'), ['^ALLOWED: erin\@lab\.test whoami ', '^  roles from: group:auditors$']);
expect ('an AD group SID from the ticket gives sid: roles, shown with its readable name (Q4)',
        t3 ('--principal frank@AD.LAB.TEST --sids S-1-5-21-1-2-3-513,S-1-5-21-1-2-3-1105', 'shutdown'),
        ['^ALLOWED: frank\@AD\.LAB\.TEST shutdown ', '^  roles from: sid:S-1-5-21-1-2-3-1105\(AD\.LAB\.TEST\\\\ns-admins\)$']);
expect ('via=: carol\'s role holds only when the named asserter asserts her',
        t3 ('--principal carol@lab.test', 'poke')
        . t3 ('--principal spiffe://ace-tao.test/portal --asserted carol@lab.test --via spiffe://ace-tao.test/portal', 'poke')
        . t3 ('--principal spiffe://ace-tao.test/kiosk --asserted carol@lab.test --via spiffe://ace-tao.test/kiosk', 'poke'),
        ['^REFUSED: carol\@lab\.test poke .*\n.*the caller has no role', '^ALLOWED: carol\@lab\.test poke ',
         '^REFUSED: carol\@lab\.test poke .*\n.*the caller has no role\n.*\n(?!ALLOWED)']);
expect ('an asserter cap (roles=) removes what it does not list (R36)',
        t3 ('--principal spiffe://ace-tao.test/portal --asserted dave@lab.test --via spiffe://ace-tao.test/portal --cap reader,writer', 'shutdown')
        . t3 ('--principal spiffe://ace-tao.test/portal --asserted dave@lab.test --via spiffe://ace-tao.test/portal --cap reader,writer', 'poke'),
        ['^REFUSED: dave\@lab\.test shutdown ', '^  removed by the asserter\'s cap: admin$', 'roles writer; requires manage',
         '^ALLOWED: dave\@lab\.test poke ']);
expect ('  ... and a cap that leaves nothing says so',
        t3 ('--principal spiffe://ace-tao.test/portal --asserted dave@lab.test --via spiffe://ace-tao.test/portal --cap reader', 'poke'),
        ['^REFUSED: ', 'the caller\'s roles are outside its asserter\'s roles= cap']);
expect ('an asserted caller gets neither the ticket SIDs nor the store groups on the request',
        t3 ('--principal frank@AD.LAB.TEST --sids S-1-5-21-1-2-3-1105 --groups auditors --asserted erin@lab.test --via frank@AD.LAB.TEST', 'whoami'),
        ['^REFUSED: erin\@lab\.test whoami ', 'the caller has no role']);
expect ('  ... nor factors=tls+gssup, even asserted by a login over a certificate',
        t3 ('--principal alice@lab.test --cert spiffe://ace-tao.test/client --asserted bob@lab.test --via alice@lab.test', 'shutdown'),
        ['^REFUSED: bob\@lab\.test shutdown ', 'the caller has no role']);
expect ('anonymous: only the explicit anonymous line gives roles (R37)',
        t3 ('--anonymous', 'whoami') . t3 ('--anonymous', 'poke'),
        ['^ALLOWED: anonymous whoami ', '^  roles from: anonymous$', '^REFUSED: anonymous poke ']);
expect ('a subject DN with blanks is a principal', t3 ("--principal 'CN=legacy gateway,O=Example'", 'whoami'),
        ['^ALLOWED: CN=legacy gateway,O=Example whoami ']);
foreach my $bad (["role anonymous reader factors=tls+gssup\n", 'an anonymous caller proves no factors'],
                 ["role alice\@lab.test reader factors=tls+krb5\n", 'factors= takes tls\+gssup'],
                 ["role sid:S-1-x reader\n", 'bad SID'],
                 ["group 9ops bob\@lab.test\n", 'expected "group NAME PRINCIPAL"'],
                 ["group ops group:other\n", 'a group member is a principal'],
                 ["role group:bad! reader\n", 'bad group name'],
                 ["role alice\@lab.test reader via=\n", 'no principal|via= needs one asserter']) {
    spit ("$work/t3_bad.draft", $bad->[0]);
    expect ("the role map refuses: $bad->[0]" =~ s/\n$//r, tool ("roles sign $sign --file $work/t3_bad.draft --dir $t3"),
            [$bad->[1]], ['signed into']);
}

# ace-tao-setup roles import: a role map drafted from the interim access list.
spit ("$work/import.list", "version 4\nissued 2026-01-01T00:00:00Z\n"
                         . "allow spiffe://ace-tao.test/admin *\n"
                         . "allow spiffe://ace-tao.test/sweeper /RootPOA/NameService* resolve list\n"
                         . "allow spiffe://ace-tao.test/sweeper2 /RootPOA/NameService* resolve list\n"
                         . "deny spiffe://ace-tao.test/sweeper /RootPOA/NameService* destroy\n"
                         . "allow carol\@lab.test /RootPOA/Ledger/accounts read via=spiffe://ace-tao.test/portal\n"
                         . "allow * /RootPOA/Status/info\n");
$o = tool ("roles import --access $work/import.list");
expect ('roles import drafts one role for each distinct set of allow rules', $o,
        ['^# Role map drafted by "ace-tao-setup roles import" from \S+import\.list \(version 4, 6 rule\(s\)\)',
         '^role spiffe://ace-tao\.test/sweeper (imported-\d+)\nrole spiffe://ace-tao\.test/sweeper2 \1$',
         '^role carol\@lab\.test imported-\d+ via=spiffe://ace-tao\.test/portal$',
         '^#   allow /RootPOA/NameService\* list resolve$',
         '^#   deny spiffe://ace-tao\.test/sweeper /RootPOA/NameService\* destroy  \(deny: stays in the access list',
         '^#   allow \* /RootPOA/Status/info \(all operations\)  \(any identified caller']);
$o = tool ("roles import --access $work/import.list --out $work/imported.draft");
expect ('  ... into a file, which signs as a role map', $o . tool ("roles sign $sign --file $work/imported.draft --dir $work/cycle"),
        ['drafted 4 role line\(s\) and 3 role\(s\) into ', '; 2 rule\(s\) not imported', 'table roles version \d+ .*signed into']);

# ace-tao-setup user groups, and the asserter list's roles=.
my $store = "$work/t3.store";
my $pw_erin = 'erin-has-a-long-password';
my $pw_bob = 'bob-has-a-long-password';
spit ("$work/pw_erin", "$pw_erin\n");
spit ("$work/pw_bob", "$pw_bob\n");
chmod (0600, "$work/pw_erin", "$work/pw_bob");
sub user_tool { my ($args, $in) = @_; return scalar (`echo '$in' | $tool --conf $tconf user $args --store $store 2>&1`); }
user_tool ("add erin --password-stdin --cost 12", $pw_erin);
user_tool ("add bob --password-stdin --cost 12", $pw_bob);
expect ('user groups sets a user\'s store groups (audited)', user_tool ('groups erin --set auditors,ops'),
        ['^Set the groups of erin in \S+: auditors,ops$', 'reason="GSSUP_USER_CHANGED" .*action="groups"']);
expect ('  ... refuses a bad group name', user_tool ('groups erin --set "bad group"'), ['bad group name']);
user_tool ("passwd erin --password-stdin", $pw_erin);
expect ('  ... which passwd keeps, and list shows', user_tool ('list') . slurp ($store),
        ['^erin\s+active\s+scrypt N=2\^12 r=8 p=1 groups=auditors,ops$', '^erin scrypt:\S+ active groups=auditors,ops$']);
user_tool ('groups erin --set auditors');
chmod (0600, $store);

my $t3ast = "$work/t3_asserters.list";
spit ($t3ast, "version 0\nissued 2026-01-01T00:00:00Z\nasserter spiffe://ace-tao.test/client types=name realms=\@lab.test roles=reader,writer\n");
$o = `$tool --conf /dev/null asserters sign $deny_sign --file $t3ast --bump 2>&1`;
die "asserters sign failed:\n$o" unless $o =~ /signed into/;
expect ('asserters check shows an asserter\'s roles= cap',
        scalar (`$tool --conf /dev/null asserters check --file $t3ast --signer $certs/signer_pub.pem 2>&1`),
        ['^  spiffe://ace-tao\.test/client types=name realms=\@lab\.test roles=reader,writer$']);
spit ("$work/t3_bad_asserters.list", "version 0\nissued 2026-01-01T00:00:00Z\nasserter spiffe://ace-tao.test/client roles=ok,bad!\n");
expect ('  ... and refuses a bad role name in it',
        scalar (`$tool --conf /dev/null asserters sign $deny_sign --file $work/t3_bad_asserters.list --bump 2>&1`),
        ['bad role name "bad!" in roles='], ['signed into']);

# Live: store groups, two factors and an asserter cap on a running service.
spit ("$work/t3.conf", $base . "audit_grants = on\ncsiv2 = supported\ncsiv2_gssup = supported\ngssup_target = \@lab.test\n"
                      . "gssup_store = $store\ncsiv2_asserters = $t3ast\ncsiv2_asserters_signer = $certs/signer_pub.pem\n"
                      . "roles_dir = $t3\nroles_signer = $work/roles_pub.pem\nroles_signer_sha256 = $rpin\n");
chmod (0600, "$work/t3.conf");
$ENV{'SAS_TEST_NO_VERIFIER'} = '1';
start_server ('t3');
delete $ENV{'SAS_TEST_NO_VERIFIER'};
expect ('the service starts with the T3 role map, store and asserter list', slurp ($log),
        ['SERVER READY', 'checks: \d+ ok, \d+ warn, 0 fail']);
expect ('the client certificate alone has no role here', call ('alpha', 'whoami'), ['^whoami EXCEPTION NO_PERMISSION$']);
expect ('erin\'s store group auditors gives her reader', call ('alpha', 'whoami', "-g erin\@lab.test:file:$work/pw_erin"),
        ['^WHOAMI ']);
expect ('  ... but not poke', call ('alpha', 'poke', "-g erin\@lab.test:file:$work/pw_erin"), ['^poke EXCEPTION NO_PERMISSION$']);
expect ('bob (group operators, login over a certificate: two factors) may poke',
        call ('alpha', 'poke', "-g bob\@lab.test:file:$work/pw_bob"), ['^POKE OK$']);
expect ('dave asserted by the client certificate, capped to reader,writer, may poke',
        call ('alpha', 'poke', '-a name:dave@lab.test'), ['^POKE OK$']);
call ('alpha', 'shutdown', '-a name:dave@lab.test');   # oneway: the refusal is in the audit record
$o = log_now ();
expect ('  (audited: login groups, where the roles came from, what the cap removed)', $o,
        ['reason="SAS_ACCEPTED" principal="erin\@lab\.test" .*login_groups="auditors"',
         'reason="ACCESS_GRANTED" principal="erin\@lab\.test" .*roles="reader" .*roles_from="group:auditors"',
         'reason="ACCESS_GRANTED" principal="bob\@lab\.test" .*op="poke" .*roles="admin" .*roles_from="group:operators"',
         'reason="ACCESS_DENIED" principal="dave\@lab\.test" asserter="spiffe://ace-tao\.test/client" .*op="shutdown" .*roles="writer" rights_required="manage" .*roles_from="dave\@lab\.test" roles_capped="admin"']);
stop_server ();

rmtree ($work) if $status == 0;
exit $status;
