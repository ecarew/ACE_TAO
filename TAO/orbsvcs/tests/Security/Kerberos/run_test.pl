eval '(exit $?0)' && eval 'exec perl -S $0 ${1+"$@"}'
     & eval 'exec perl -S $0 $argv:q'
     if 0;

# -*- perl -*-
#
# Kerberos in SSLIOP (Phase 3).
#
# K1 (every build): SSLIOP built with the MPC feature gssapi links MIT
# krb5's GSS-API, offers the Kerberos V5 mechanism and turns GSS status
# codes into the library's text; built without it, it says so.
#
# K2 (needs the lab KDC, CORBA lab/kdc.sh up, and a gssapi build; skipped
# otherwise): a TAO target with csiv2_kerberos accepts a Kerberos token
# with its keytab and serves the caller as user@LAB.TEST; the reference
# lists Kerberos first, then GSSUP; the token must be bound to the TLS
# session (krb_channel_binding = required); a token without the binding,
# with another session's binding, for another service, replayed or
# carrying an expired ticket is refused with ContextError 1 and audited
# (KRB_FAILED) with the real reason; GSSUP logins and TAO's GSSUP client
# still work beside Kerberos; csiv2_kerberos = required offers only
# Kerberos and refuses everything else; the keytab self-check refuses a
# world-readable keytab in prod and RC4 keys anywhere.  In prod the
# reference's IIOP port is 0; a Kerberos token over plain IIOP (a test-mode
# instance) is refused as SAS_NO_TLS; a client clock skewed past the
# service's krb5.conf clockskew is refused (needs faketime; skipped
# without it); at ORB debug level 10 no log line holds the password or a
# keytab key (TAO's hex dumps of whole GIOP messages at that level are
# not checked: a debugging aid, out of scope).  The SAS test's
# server and client (../SAS) and certificates (../Transport) are used.
#
# The lab is found at $ACE_TAO_KRB_LAB (default
# ~/Projects/claude/CORBA/lab/state/kdc), its tools at $KRB5_BIN.

use lib "$ENV{ACE_ROOT}/bin";
use PerlACE::TestTarget;
use Cwd;
use File::Copy;
use File::Path qw(rmtree);
use POSIX qw(:sys_wait_h);

my $test = PerlACE::TestTarget::create_target (1) || die "Create target 1 failed\n";
my $dir = getcwd ();
my $sas = "$dir/../SAS";
my $certs = "$dir/../Transport";
my $iortool = "$dir/../CSIv2_IOR/ior_tool";
my $work = "$dir/krb_work";
my $tool = "$ENV{TAO_ROOT}/orbsvcs/Security_Setup/ace-tao-setup";
my $status = 0;

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

# --- K1: the build ------------------------------------------------------------------
my $out = `$dir/krb_probe 2>&1`;
my $rc = $? >> 8;
expect ('krb_probe reports a consistent build', "$out\nrc=$rc", ['^rc=0$']);
expect ('the Kerberos V5 mechanism OID is 1.2.840.113554.1.2.2', $out, ['^mech_der=06092a864886f712010202$']);
my $built = $out =~ /^built=1$/m;
if ($built) {
    expect ('built with GSS-API: the library offers Kerberos V5', $out, ['^offered=1 Kerberos V5 mechanism offered$']);
    expect ('  ... and gives GSS status text', $out, ['^status_text=\S']);
} else {
    expect ('built without GSS-API: it says so', $out,
            ['^offered=0 SSLIOP was built without GSS-API', '^status_text=GSS-API not built$']);
}

# --- K4: PAC logon information, canned (no KDC needed) -----------------------------
# pac_samba_logon_info.hex is the logon-info buffer of a real AD ticket
# from the lab's Samba domain: user dana (RID 1102) in Domain Users (513)
# and ns-admins (1103), plus two extra SIDs.  Variants patch it.
{
    my $pacdir = "$dir/pac_work";
    rmtree ($pacdir);
    mkdir $pacdir;
    my $raw = pack ('H*', join ('', slurp ("$dir/pac_samba_logon_info.hex") =~ /([0-9a-f]+)/g));
    my $dom = 'S-1-5-21-1705173496-149076901-855181407';
    sub pac_probe {
        my ($pacdir, $name, $bytes) = @_;
        spit ("$pacdir/$name.hex", unpack ('H*', $bytes));
        return scalar (`$dir/krb_probe -pac $pacdir/$name.hex 2>&1`);
    }
    sub patched { my ($b, $off, $v) = @_; substr ($b, $off, 4) = pack ('V', $v); return $b; }
    $out = pac_probe ($pacdir, 'real', $raw);
    expect ('K4: a real AD PAC (Samba) parses: user SID, domain and every group', $out,
            ["^PAC OK user_sid=$dom-1102 domain=ADLAB\$", "^GROUP $dom-513\$", "^GROUP $dom-1103\$", '^GROUP S-1-18-1$']);
    $out = pac_probe ($pacdir, 'denyonly', patched ($raw, 0x14c, 0x17));
    expect ('K4: a deny-only group (SE_GROUP_USE_FOR_DENY_ONLY) grants nothing and is left out', $out,
            ["^PAC OK ", "^GROUP $dom-513\$"], ["^GROUP $dom-1103\$"]);
    expect ('K4: a PAC naming more than 4096 groups is refused', pac_probe ($pacdir, 'huge', patched ($raw, 0x80, 0x10000)),
            ['^PAC REFUSED the PAC names more than 4096 groups$']);
    expect ('K4: a group count that disagrees with its array is refused', pac_probe ($pacdir, 'count', patched ($raw, 0x80, 3)),
            ['^PAC REFUSED the PAC logon information is malformed$']);
    expect ('K4: a PAC shorter than its header says is refused', pac_probe ($pacdir, 'short', substr ($raw, 0, 300)),
            ['^PAC REFUSED bad NDR serialisation header$']);
    expect ('K4: a truncated PAC whose header agrees is refused', pac_probe ($pacdir, 'cut', patched (substr ($raw, 0, 300), 8, 284)),
            ['^PAC REFUSED the PAC logon information is (malformed|truncated)$']);
    expect ('K4: a buffer that is not NDR is refused', pac_probe ($pacdir, 'notndr', "\x02" . substr ($raw, 1)),
            ['^PAC REFUSED not a little-endian NDR type serialisation']);
    rmtree ($pacdir) if $status == 0;
}

# --- K2: needs the lab KDC ----------------------------------------------------------
my $lab = $ENV{'ACE_TAO_KRB_LAB'} || "$ENV{HOME}/Projects/claude/CORBA/lab/state/kdc";
my $krb = $ENV{'KRB5_BIN'} || (-x '/opt/homebrew/opt/krb5/bin/kinit' ? '/opt/homebrew/opt/krb5/bin' : '/usr/bin');
my $skip = !$built ? 'SSLIOP built without GSS-API'
         : !-f "$lab/krb5.conf" || !-f "$lab/keytabs/who.keytab" || !-f "$lab/passwords/alice" ? "no Kerberos lab at $lab"
         : !-x "$krb/kinit" ? "no kinit in $krb" : '';
rmtree ($work);
mkdir $work;
$ENV{'KRB5_CONFIG'} = "$lab/krb5.conf";
$ENV{'KRB5CCNAME'} = "FILE:$work/ccache";
if ($skip eq '') {
    my $k = `$krb/kinit alice\@LAB.TEST < $lab/passwords/alice 2>&1`;
    $skip = "kinit failed (is the KDC up? CORBA lab/kdc.sh up): $k" if $? != 0;
}
if ($skip ne '') {
    print "SKIPPED: Kerberos lab checks ($skip)\n";
    rmtree ($work) if $status == 0;
    exit $status;
}
delete $ENV{'ACE_TAO_SECURITY_CONF'};

my $clock = -x "$dir/../Mode/mode_test" ? `$dir/../Mode/mode_test -clock` : 'synced';
my $prod = $clock =~ /^synced/;
print "mode: " . ($prod ? "prod" : "test (clock not synchronized)") . "\n";

my $principal = 'ace-tao/who.lab.test@LAB.TEST';
# The servers' krb5.conf: the lab's, with a 10-second clock-skew window
# (Kerberos accepts a ticket for that long past its end time; the
# default is 300 s), so the expired-ticket check need not wait minutes.
(my $srvconf = slurp ("$lab/krb5.conf")) =~ s/^\[libdefaults\]\n/[libdefaults]\n    clockskew = 10\n/m;
spit ("$work/krb5.conf", $srvconf);
copy ("$lab/keytabs/who.keytab", "$work/who.keytab") || die "copy keytab: $!";
chmod (0600, "$work/who.keytab");
copy ("$lab/keytabs/who.keytab", "$work/open.keytab") || die "copy keytab: $!";
chmod (0644, "$work/open.keytab");
spit ("$work/pw", "wonderland\n"); chmod (0600, "$work/pw");
spit ("$work/client.conf", "mode = test\naudit_sink = stderr\ntime_sync_wait = 0\n"); chmod (0600, "$work/client.conf");

my $fp = `openssl x509 -in $certs/ca.pem -noout -fingerprint -sha256`;
$fp =~ s/.*=//; chomp $fp;
my ($pin) = `$tool --conf /dev/null denylist pin --signer $certs/signer_pub.pem` =~ /= (\w+)/;
my $sign = "--key PEM:$certs/signer_key_enc.pem --password-file $certs/password.txt";
my $acl = "$work/access.list";
spit ($acl, "version 0\nissued 2026-01-01T00:00:00Z\n"
          . "allow alice\@LAB.TEST /RootPOA/Who/alpha whoami\n"
          . "allow alice\@lab.test /RootPOA/Who/alpha whoami\n"
          . "allow * /RootPOA/Who/beta\n");
my $o = `$tool --conf /dev/null access sign $sign --file $acl --bump 2>&1`;
die "access sign failed:\n$o" unless $o =~ /signed into/;

my $base = "mode = " . ($prod ? "prod" : "test") . "\naudit_sink = stderr\ntime_sync_wait = 0\n"
         . "trust_anchor_sha256 = $fp\naccess_list = $acl\naccess_list_signer = $certs/signer_pub.pem\n"
         . "access_list_signer_sha256 = $pin\naccess_default = deny\naudit_grants = on\n"
         . "csiv2 = supported\ngssup_target = \@lab.test\ncsiv2_gssup = supported\n"
         . "krb_principal = $principal\nkrb_rcache = file2:$work/rcache\n";
my %conf = (krb      => $base . "csiv2_kerberos = supported\nkrb_keytab = $work/who.keytab\n",
            loose    => $base . "csiv2_kerberos = supported\nkrb_keytab = $work/who.keytab\nkrb_channel_binding = supported\n",
            required => $base . "csiv2_kerberos = required\nkrb_keytab = $work/who.keytab\n",
            open     => $base . "csiv2_kerberos = supported\nkrb_keytab = $work/open.keytab\n");
# A test-mode instance, which keeps a plain IIOP listener (prod has none).
($conf{plain} = $conf{krb}) =~ s/^mode = \w+$/mode = test/m;
foreach my $c (keys %conf) { spit ("$work/$c.conf", $conf{$c}); chmod (0600, "$work/$c.conf"); }

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
my $bind = "$certs/server_cert.pem";

my ($pid, $d, $log);
sub start_server {
    my ($which, $tamper, $tag, @orb) = @_;
    $d = "$work/$which" . (defined $tag ? "_$tag" : '');
    mkdir $d;
    # A reference left by an earlier server in this directory must not
    # pass for the new one before it has written its own.
    unlink ("$d/alpha.ior", "$d/beta.ior");
    $log = "$d/server.log";
    $pid = fork ();
    if ($pid == 0) {
        $ENV{'ACE_TAO_SECURITY_CONF'} = "$work/$which.conf";
        $ENV{'KRB5_CONFIG'} = "$work/krb5.conf";
        $ENV{'SAS_TEST_TAMPER_REPLY'} = $tamper if defined $tamper;
        open (STDOUT, '>', $log); open (STDERR, '>&STDOUT');
        exec ("$sas/server", '-ORBSvcConf', "$work/server.svc", '-ORBListenEndpoints', 'iiop://127.0.0.1:', @orb, '-d', $d);
        exit 127;
    }
    for (my $i = 0; $i < 100 && !-s "$d/beta.ior"; ++$i) { select (undef, undef, undef, 0.1); }
}
sub stop_server {
    my ($mode) = @_;
    $mode = "krb5:$principal:$bind" unless defined $mode;
    `$sas/client -ORBSvcConf $work/client.svc -k file://$d/beta.ior -c shutdown -m $mode 2>&1`;
    my $gone = 0;
    for (my $i = 0; $i < 50 && !$gone; ++$i) { $gone = waitpid ($pid, WNOHANG) == $pid; select (undef, undef, undef, 0.1) unless $gone; }
    if (!$gone) { kill ('KILL', $pid); waitpid ($pid, 0); print STDERR "ERROR: server did not shut down\n"; $status = 1; }
}
sub call {
    my ($what, $mode, $extra) = @_;
    $extra = '' unless defined $extra;
    return scalar (`$sas/client -ORBSvcConf $work/client.svc -k file://$d/alpha.ior -c $what -m $mode $extra 2>&1`);
}
sub log_now { select (undef, undef, undef, 0.3); return slurp ($log); }
my @refused1 = ('^SAS REPLY error ctx=0 major=1 minor=1 ', '^whoami EXCEPTION NO_PERMISSION$');
my @refused2 = ('^SAS REPLY error ctx=0 major=2 minor=1 ', '^whoami EXCEPTION NO_PERMISSION$');

# --- csiv2_kerberos = supported, beside GSSUP ---------------------------------------------
start_server ('krb');
expect ('server starts with Kerberos and its keytab', slurp ($log),
        ['SERVER READY', 'checks: \d+ ok, \d+ warn, 0 fail'],
        ['csiv2_kerberos: (?!\S+ holds \d+ key versions)']);   # the lab keytab gathers versions
my $ior = scalar (`$iortool -k file://$d/alpha.ior 2>&1`);
expect ('the reference lists Kerberos first (mechanism OID, service principal), then GSSUP', $ior,
        ['^    MECH 0 requires=0x[0-9a-f]+ transport=36$', '^      AS supports=0x40 requires=0x0 mech_octets=11$',
         'target_name=.*ace-tao/who\.lab\.test\@LAB\.TEST',
         '^    MECH 1 requires=0x[0-9a-f]+ transport=36$', '^      AS supports=0x40 requires=0x0 mech_octets=8$']);
expect ('  ... and its IIOP port is 0 (prod has no plain listener)', $ior, ['^PROFILE 0 .*iiop_port=0$']) if $prod;

$out = call ('whoami', "krb5:$principal:$bind");
expect ('a Kerberos login bound to the TLS session is served as alice@LAB.TEST', $out,
        ['^SAS REPLY complete ctx=0 stateful=0$', '^SAS FINAL TOKEN \d+ octets$',
         '^WHOAMI name=\S+alice\@LAB\.TEST authenticated=yes ']);
expect ('  (audited: accepted by Kerberos, and the access decision sees alice@LAB.TEST)', log_now (),
        ['reason="SAS_ACCEPTED" principal="alice\@LAB\.TEST" transport_principal="spiffe://ace-tao\.test/client".* mech="krb5"',
         'reason="ACCESS_GRANTED" principal="alice\@LAB\.TEST"']);

$out = call ('whoami', "krb5:$principal:none");
expect ('a token without channel binding is refused (krb_channel_binding = required)', $out, [@refused1], ['^WHOAMI']);
$out = call ('whoami', "krb5:$principal:$certs/client_cert.pem");
expect ('a token bound to another TLS session is refused', $out, [@refused1], ['^WHOAMI']);
$out = call ('whoami', "krb5:ace-tao/naming.lab.test\@LAB.TEST:$bind");
expect ('a ticket for another service is refused', $out, [@refused1], ['^WHOAMI']);
$out = call ('whoami', "krb5:$principal:$bind:$work/token");
my $again = call ('whoami', "rawtoken:$work/token");
expect ('a replayed token is refused', "$out\n$again", ['^WHOAMI name=\S+alice\@LAB\.TEST', @refused1]);
$out = call ('whoami', 'notgssup');
expect ('a malformed Kerberos token is refused', $out, [@refused1], ['^WHOAMI']);
expect ('  (each audited as KRB_FAILED with its reason)', log_now (),
        ['reason="KRB_FAILED" .*context_error="1"\] the token is not bound to this TLS session',
         'reason="KRB_FAILED" .*context_error="1"\] the token is bound to another TLS session',
         'reason="KRB_FAILED" .*context_error="1"\] .*Cannot decrypt ticket for ace-tao/naming\.lab\.test',
         'reason="KRB_FAILED" .*context_error="1"\] replayed token']);

# An expired ticket: a token made with a 5-second ticket, sent once the
# ticket and the server's 10-second skew window have both passed.
{
    local $ENV{'KRB5CCNAME'} = "FILE:$work/ccache_short";
    `$krb/kinit -l 5s alice\@LAB.TEST < $lab/passwords/alice 2>&1`;
    call ('poke', "krb5save:$principal:$bind:$work/short_token");
}
sleep (17);
$out = call ('whoami', "rawtoken:$work/short_token");
expect ('a token whose ticket has expired is refused', $out, [@refused1], ['^WHOAMI']);
expect ('  (audited: the ticket expired)', log_now (), ['reason="KRB_FAILED" .*context_error="1"\] .*[Ee]xpired']);

$out = call ('whoami', 'gssup:alice:wonderland');
expect ('a GSSUP login still works beside Kerberos', $out,
        ['^SAS REPLY complete ctx=0 stateful=0$', '^WHOAMI name=\S+alice\@lab\.test authenticated=yes ']);
$out = scalar (`ACE_TAO_SECURITY_CONF=$work/client.conf $sas/client -ORBSvcConf $work/client.svc -k file://$d/alpha.ior -c whoami -m none -g alice\@lab.test:file:$work/pw 2>&1`);
expect ('TAO\'s own GSSUP client skips the Kerberos mechanism and logs in with GSSUP', $out,
        ['^ACQUIRE OK$', '^SAS REPLY complete ctx=0 stateful=0$', '^WHOAMI name=\S+alice\@lab\.test authenticated=yes ']);
stop_server ();
expect ('no password or Kerberos secret in the log', slurp ($log), ['SAS_ACCEPTED'], ['wonderland']);

# --- a Kerberos token over plain IIOP (test mode: prod has no plain listener) ------------
start_server ('plain');
$out = scalar (`$sas/client -ORBSvcConf /dev/null -k file://$d/alpha.ior -c whoami -m krb5:$principal:none 2>&1`);
expect ('a Kerberos token over plain IIOP is refused', $out, [@refused1], ['^WHOAMI']);
expect ('  (audited as SAS_NO_TLS)', log_now (), ['reason="SAS_NO_TLS"']);
stop_server ();

# --- a skewed client clock -----------------------------------------------------------------
# The client runs 60 s ahead: inside the KDC's 300 s window, so it still
# gets its service ticket, but past the service's 10 s clockskew, so the
# authenticator is refused.
my ($faketime) = grep { -x $_ } map { "$_/faketime" } split (/:/, $ENV{'PATH'});
if (!defined $faketime) {
    print "skipped: skewed-clock check (no faketime here; the Linux lab runs it)\n";
}
else {
    start_server ('krb', undef, 'skew');
    $out = scalar (`$faketime -f +60s $sas/client -ORBSvcConf $work/client.svc -k file://$d/alpha.ior -c whoami -m krb5:$principal:$bind 2>&1`);
    expect ('a client clock 60 s ahead (service clockskew 10 s) is refused', $out, [@refused1], ['^WHOAMI']);
    expect ('  (audited: the clock skew)', log_now (), ['reason="KRB_FAILED" .*context_error="1"\] .*[Ss]kew']);
    $out = call ('whoami', "krb5:$principal:$bind");
    expect ('  ... while the same client with a true clock is served', $out, ['^WHOAMI name=\S+alice\@LAB\.TEST']);
    stop_server ();
}

# --- no secret in the log text at ORB debug level 10 ----------------------------------------
# Only the text TAO and the security code write: the hex dumps of whole
# GIOP messages at this level (service contexts included) are a
# debugging aid and are not checked.
sub without_dumps {
    return join ("\n", grep { !/^(?:[0-9a-f]{2}  ?){1,16}/ } split (/\n/, shift));
}
start_server ('krb', undef, 'debug10', '-ORBDebugLevel', '10');
call ('whoami', "krb5:$principal:$bind");
call ('whoami', 'gssup:alice:wonderland');
stop_server ();
{
    my $text = without_dumps (slurp ($log));
    my @leaks;
    push @leaks, 'level 10 not in effect' unless $text =~ /GIOP_Message_Base/;
    push @leaks, 'the GSSUP password' if index ($text, 'wonderland') >= 0;
    my @keys = `$krb/klist -K -k $work/who.keytab 2>&1` =~ /\(0x([0-9a-f]{32,})\)/g;
    push @leaks, 'no keytab keys were read' unless @keys;
    foreach my $k (@keys) { push @leaks, 'a keytab key' if $text =~ /$k/i; }
    expect ('at ORB debug level 10 no log line holds the password or a keytab key',
            @leaks ? join (', ', @leaks) : 'clean', ['^clean$']);
}

# --- the deny-list names principals ---------------------------------------------------------
# A user cut off by name while the ticket is still valid (an AD account
# disabled keeps the tickets it was issued); case does not matter.  The
# same entry stops the user's GSSUP login.
my $deny = "$work/deny.list";
sub denyconf {
    my ($name, $from) = @_;
    spit ("$work/$name.conf", $from . "denylist = $deny\ndenylist_signer = $certs/signer_pub.pem\n"
                                   . "denylist_signer_sha256 = $pin\ndenylist_reload = 1\n");
    chmod (0600, "$work/$name.conf");
}
sub denylist { return scalar (`$tool --conf $work/deny.conf denylist @_ $sign 2>&1`); }
denyconf ('deny', $conf{krb});
denylist ('add', '--principal', 'nobody@LAB.TEST');
start_server ('deny');
$out = call ('whoami', "krb5:$principal:$bind");
expect ('deny-list: an unlisted Kerberos user is served', $out, ['^WHOAMI name=\S+alice\@LAB\.TEST']);
$out = denylist ('add', '--principal', 'ALICE@lab.test');
expect ('  ... denylist add --principal publishes the name', $out, ['version 2 issued .* 2 principal\(s\), 0 SID\(s\)']);
sleep (2);
$out = call ('whoami', "krb5:$principal:$bind");
expect ('deny-list: a listed Kerberos user is refused at the next request, the ticket still valid', $out,
        ['^whoami EXCEPTION NO_PERMISSION$'], ['^WHOAMI']);
expect ('  (audited: PRINCIPAL_DENYLISTED, the entry named)', log_now (),
        ['reason="PRINCIPAL_DENYLISTED" principal="alice\@LAB\.TEST" .*denylist_entry="principal alice\@lab\.test" op="whoami"']);
$out = call ('whoami', 'gssup:alice:wonderland');
expect ('  ... and so is the same user\'s GSSUP login', $out, ['^whoami EXCEPTION NO_PERMISSION$'], ['^WHOAMI']);
denylist ('remove', '--principal', 'alice@LAB.TEST');
sleep (2);
$out = call ('whoami', "krb5:$principal:$bind");
expect ('  ... removed from the list, the user is served again', $out, ['^WHOAMI name=\S+alice\@LAB\.TEST']);
stop_server ();

# --- krb_channel_binding = supported ---------------------------------------------------
start_server ('loose');
expect ('krb_channel_binding = supported warns in the self-check', slurp ($log),
        ['WARN csiv2_kerberos: krb_channel_binding = supported: Kerberos tokens not bound to the TLS session are accepted']);
$out = call ('whoami', "krb5:$principal:none");
expect ('  ... and serves an unbound token', $out, ['^SAS REPLY complete ', '^WHOAMI name=\S+alice\@LAB\.TEST ']);
expect ('  ... but still refuses one bound to another session', call ('whoami', "krb5:$principal:$certs/client_cert.pem"),
        [@refused1], ['^WHOAMI']);
stop_server ();

# --- csiv2_kerberos = required ------------------------------------------------------------
start_server ('required');
$ior = scalar (`$iortool -k file://$d/alpha.ior 2>&1`);
expect ('required: the reference offers only Kerberos, as required', $ior,
        ['^    MECH 0 requires=0x[0-9a-f]+ transport=36$', '^      AS supports=0x40 requires=0x40 mech_octets=11$'],
        ['^    MECH 1 ']);
# -b turns TAO's own client authentication off: without it TAO refuses the
# call locally (K3), and the server would never see it.
expect ('required: a call with no SAS context is refused (SAS_MISSING)', call ('whoami', 'none', '-b'),
        ['^whoami EXCEPTION NO_PERMISSION$'], ['^WHOAMI']);
expect ('required: a GSSUP login is refused (ContextError 2)', call ('whoami', 'gssup:alice:wonderland'), [@refused2], ['^WHOAMI']);
expect ('required: a Kerberos login is served', call ('whoami', "krb5:$principal:$bind"), ['^WHOAMI name=\S+alice\@LAB\.TEST ']);
expect ('  (audited)', log_now (),
        ['reason="SAS_MISSING" .*\] no SAS context; Kerberos client authentication is required',
         'reason="SAS_INVALID_MECH" .*context_error="2"\] Kerberos client authentication is required']);
stop_server ();

# --- K3: TAO's own Kerberos client (SL3Kerberos) ----------------------------------------
# TAO's SAS client, not the test's hand-made contexts (-m none): the
# credentials come from "SL3Kerberos" (-K), the token is bound to the
# connection, and the target's reply token is checked.
spit ("$work/krbclient.conf", "mode = test\naudit_sink = stderr\ntime_sync_wait = 0\naudit_grants = on\n");
chmod (0600, "$work/krbclient.conf");
copy ("$lab/keytabs/naming.keytab", "$work/naming.keytab") || die "copy keytab: $!";
chmod (0600, "$work/naming.keytab");
sub tao {
    my ($obj, $args, $env) = @_;
    $env = '' unless defined $env;
    return scalar (`$env ACE_TAO_SECURITY_CONF=$work/krbclient.conf $sas/client -ORBSvcConf $work/client.svc -k file://$d/$obj.ior -c whoami -m none $args 2>&1`);
}
my $served = '^WHOAMI name=\S+alice\@LAB\.TEST authenticated=yes ';

start_server ('krb', undef, 'k3');
$out = tao ('alpha', '-K target=');
expect ('K3: after kinit, TAO logs in with Kerberos and is served as alice@LAB.TEST', $out,
        ['^ACQUIRE OK$', '^SAS REPLY complete ctx=0 stateful=0$', $served]);
expect ('  (client audit: credentials acquired, Kerberos login sent to the service)', $out,
        ['reason="KRB_CREDENTIALS_ACQUIRED" principal="alice\@LAB\.TEST" target="\@LAB\.TEST" source="default ccache" lifetime="\d+"',
         'reason="SAS_CLIENT_SENT" user="alice\@LAB\.TEST" mech="kerberos" target="ace-tao/who\.lab\.test\@LAB\.TEST"'],
        ['KRB_SERVER_UNVERIFIED']);
expect ('  (server audit: accepted by Kerberos, bound to the TLS session)', log_now (),
        ['reason="SAS_ACCEPTED" principal="alice\@LAB\.TEST" .* mech="krb5"']);

$out = tao ('alpha', "-K target= -g alice\@lab.test:file:$work/pw");
expect ('K3: with both Kerberos and GSSUP credentials, TAO prefers Kerberos', $out,
        ['^ACQUIRE OK$', $served], ['alice\@lab\.test authenticated']);
$out = tao ('alpha', "-K target=ace-tao/naming.lab.test\@LAB.TEST -g alice\@lab.test:file:$work/pw");
expect ('K3: Kerberos credentials for another service are not used; GSSUP is', $out,
        ['^WHOAMI name=\S+alice\@lab\.test authenticated=yes '], ['mech="kerberos"']);
$out = tao ('alpha', "-K target=\@OTHER.TEST");
expect ('K3: ... nor for another realm (the call goes without a login and is denied)', $out,
        ['^whoami EXCEPTION NO_PERMISSION$'], ['mech="kerberos"', '^WHOAMI']);

$out = tao ('alpha', "-K ccache=FILE:$work/ccache", "KRB5CCNAME=FILE:$work/no_such_ccache");
expect ('K3: a named ticket cache is used', $out, ['^ACQUIRE OK$', $served]);
$out = tao ('alpha', '-K target=', "KRB5CCNAME=FILE:$work/no_such_ccache");
expect ('K3: no ticket: acquisition fails (BAD_PARAM) and is audited', $out,
        ['^ACQUIRE FAILED BAD_PARAM$', 'reason="SAS_CLIENT_NO_CREDENTIALS" .*\] no Kerberos credentials in the default ticket cache']);
$out = tao ('alpha', '-K principal=bob@LAB.TEST');
expect ('K3: a cache without the named principal fails acquisition', $out, ['^ACQUIRE FAILED BAD_PARAM$']);

# A service logging in as itself with a client keytab: its TGT goes to a
# private in-memory cache, never to the user's cache (KRB5CCNAME).
$out = tao ('beta', "-K keytab=$work/naming.keytab,principal=ace-tao/naming.lab.test\@LAB.TEST",
            "KRB5CCNAME=FILE:$work/keytab_must_not_write");
expect ('K3: a client keytab logs a service in as itself', $out,
        ['^ACQUIRE OK$', '^WHOAMI name=\S+ace-tao/naming\.lab\.test\@LAB\.TEST authenticated=yes ',
         'source="keytab \S+naming\.keytab"']);
expect ('  ... without writing the user\'s ticket cache', -e "$work/keytab_must_not_write" ? 'written' : 'untouched',
        ['^untouched$']);
expect ('K3: a keytab without its principal is refused', tao ('beta', "-K keytab=$work/naming.keytab"),
        ['^ACQUIRE FAILED BAD_PARAM$', 'a client keytab needs the client principal']);
stop_server ();

# Mutual authentication: a server that drops or corrupts its Kerberos
# reply token is not trusted, although it served the call.
foreach my $how ('drop', 'flip') {
    start_server ('krb', $how, $how);
    $out = tao ('alpha', '-K target=');
    expect ("K3: a reply whose Kerberos token was ${how}ped is rejected (NO_PERMISSION)", $out,
            ['^SAS REPLY complete ', '^whoami EXCEPTION NO_PERMISSION$', 'reason="KRB_SERVER_UNVERIFIED"'],
            ['^WHOAMI']);
    expect ('  (audited with the reason)', $out,
            [$how eq 'drop' ? 'KRB_SERVER_UNVERIFIED.*\] the target returned no Kerberos reply token'
                            : 'KRB_SERVER_UNVERIFIED.*\] the Kerberos reply does not verify as ace-tao/who\.lab\.test\@LAB\.TEST']);
    expect ('  (TAO\'s GSSUP client is not affected)', tao ('alpha', "-g alice\@lab.test:file:$work/pw"),
            ['^WHOAMI name=\S+alice\@lab\.test authenticated=yes ']);
    stop_server ();
}

start_server ('required', undef, 'k3');
expect ('K3: required: TAO\'s Kerberos client is served', tao ('alpha', '-K target='), [$served]);
$out = tao ('alpha', "-g alice\@lab.test:file:$work/pw");
expect ('K3: required, no Kerberos credentials: refused locally, without a login', $out,
        ['^whoami EXCEPTION NO_PERMISSION$',
         'reason="SAS_CLIENT_NO_CREDENTIALS" .*mech="kerberos"\] the target requires Kerberos and there are no Kerberos credentials'],
        ['^SAS REPLY (complete|error)', '^WHOAMI']);
stop_server ();

# --- K4: AD group SIDs from real tickets (the lab AD domain, Samba) -------------------
my $adlab = $ENV{'ACE_TAO_AD_LAB'} || "$ENV{HOME}/Projects/claude/CORBA/lab/state/addc";
my $addc = "$adlab/../../addc.sh";
my $adskip = !-f "$adlab/keytabs/who.keytab" || !-f "$adlab/passwords/dana" || !-f "$adlab/ns-admins.sid"
           ? "no lab AD domain at $adlab (CORBA lab/addc.sh up)" : '';
my $adenv = "KRB5_CONFIG=$adlab/krb5.conf";
sub kinit_ad { my ($user) = @_; return scalar (`$adenv KRB5CCNAME=FILE:$work/ad_$user $krb/kinit $user\@AD.LAB.TEST < $adlab/passwords/$user 2>&1`); }
if ($adskip eq '') {
    my $k = kinit_ad ('dana');
    $adskip = "kinit at the lab AD domain failed (is it up? CORBA lab/addc.sh up): $k" if $? != 0;
}
if ($adskip ne '') {
    print "SKIPPED: AD lab checks ($adskip)\n";
} else {
    (my $nsadmins = slurp ("$adlab/ns-admins.sid")) =~ s/\s+//g;
    (my $danasid = slurp ("$adlab/dana.sid")) =~ s/\s+//g;
    copy ("$adlab/keytabs/who.keytab", "$work/ad.keytab") || die "copy keytab: $!";
    chmod (0600, "$work/ad.keytab");
    (my $adconf = $base) =~ s/^krb_principal = .*$/krb_principal = ace-tao\/who.ad.lab.test\@AD.LAB.TEST/m;
    spit ("$work/ad.conf", $adconf . "csiv2_kerberos = supported\nkrb_keytab = $work/ad.keytab\n");
    chmod (0600, "$work/ad.conf");
    my $ns = "priv=TAO:KerberosRealm:AD\\.LAB\\.TEST/TAO:ADGroupSID=\Q$nsadmins\E( |\$)";
    my $users = 'priv=TAO:KerberosRealm:AD\.LAB\.TEST/TAO:ADGroupSID=S-1-5-21-[0-9-]+-513( |$)';

    start_server ('ad');
    $out = tao ('beta', '-K target=', "$adenv KRB5CCNAME=FILE:$work/ad_dana");
    expect ('K4: an AD ticket is served, with the user\'s groups from its PAC as privileges', $out,
            ['^ACQUIRE OK$', '^WHOAMI name=\S+dana\@AD\.LAB\.TEST authenticated=yes', $ns, $users]);
    expect ('  (server audit: the user SID and the ticket groups)', log_now (),
            ["reason=\"SAS_ACCEPTED\" principal=\"dana\\\@AD\\.LAB\\.TEST\".* mech=\"krb5\" user_sid=\"\Q$danasid\E\" groups=\"[^\"]*\Q$nsadmins\E"]);
    kinit_ad ('erin');
    $out = tao ('beta', '-K target=', "$adenv KRB5CCNAME=FILE:$work/ad_erin");
    expect ('K4: a user outside ns-admins gets only her own groups', $out,
            ['^WHOAMI name=\S+erin\@AD\.LAB\.TEST authenticated=yes', $users], [$ns]);

    # Revocation at the next ticket (D3.10): out of the group, a new ticket
    # no longer carries it.  The lab is put back as it was afterwards.
    # Needs the lab script and Docker (not inside the Linux lab container).
    if (-f $addc && `command -v docker 2>/dev/null` ne '') {
        `bash $addc member remove ns-admins dana 2>&1`;
        kinit_ad ('dana');
        $out = tao ('beta', '-K target=', "$adenv KRB5CCNAME=FILE:$work/ad_dana");
        expect ('K4: removed from ns-admins, the user\'s next ticket no longer carries it', $out,
                ['^WHOAMI name=\S+dana\@AD\.LAB\.TEST authenticated=yes', $users], [$ns]);
        `bash $addc member add ns-admins dana 2>&1`;
    } else {
        print "SKIPPED: group removal check (needs CORBA lab/addc.sh and docker)\n";
    }
    stop_server ('none');
    expect ('K4: an MIT ticket (no PAC logon information) carries no groups', slurp ("$work/krb_k3/server.log"),
            ['reason="SAS_ACCEPTED" principal="alice\@LAB\.TEST"'], ['principal="alice\@LAB\.TEST"[^\n]*groups=']);

    # The deny-list names SIDs: an AD account, or a group cutting off every
    # member, from the verified ticket's PAC.
    denyconf ('addeny', $adconf . "csiv2_kerberos = supported\nkrb_keytab = $work/ad.keytab\n");
    start_server ('addeny');
    kinit_ad ('dana');
    $out = denylist ('add', '--sid', $danasid);
    expect ('deny-list: denylist add --sid publishes the SID', $out, ['issued .* 1 SID\(s\)']);
    sleep (2);
    $out = tao ('beta', '-K target=', "$adenv KRB5CCNAME=FILE:$work/ad_dana");
    expect ('deny-list: an AD account listed by SID is refused, its ticket still valid', $out,
            ['^ACQUIRE OK$', '^whoami EXCEPTION NO_PERMISSION$'], ['^WHOAMI']);
    expect ('  (audited: the account SID)', log_now (),
            ["reason=\"PRINCIPAL_DENYLISTED\" principal=\"dana\\\@AD\\.LAB\\.TEST\" .*denylist_entry=\"sid \Q$danasid\E\""]);
    $out = tao ('beta', '-K target=', "$adenv KRB5CCNAME=FILE:$work/ad_erin");
    expect ('  ... while another account is served', $out, ['^WHOAMI name=\S+erin\@AD\.LAB\.TEST']);
    denylist ('remove', '--sid', $danasid);
    denylist ('add', '--sid', $nsadmins);
    sleep (2);
    $out = tao ('beta', '-K target=', "$adenv KRB5CCNAME=FILE:$work/ad_dana");
    expect ('deny-list: a group SID cuts off its members', $out, ['^whoami EXCEPTION NO_PERMISSION$'], ['^WHOAMI']);
    expect ('  (audited: the group SID)', log_now (), ["denylist_entry=\"sid \Q$nsadmins\E\""]);
    $out = tao ('beta', '-K target=', "$adenv KRB5CCNAME=FILE:$work/ad_erin");
    expect ('  ... but not users outside the group', $out, ['^WHOAMI name=\S+erin\@AD\.LAB\.TEST']);
    stop_server ('none');
}

# --- K5: Kerberos names in identity assertions (R32) -------------------------------
# A listed asserter may assert a Kerberos principal, within the realms it
# is allowed (by default the service principal's own); TAO's middle tier
# asserts a Kerberos caller as a Kerberos name, never as a GSSUP one.
my $krbtype = 'oid:1\.2\.840\.113554\.1\.2\.2\.1';
spit ("$work/tool.conf", "mode = test\naudit_sink = stderr\ndenylist_signer = $certs/signer_pub.pem\ndenylist_signer_sha256 = $pin\n");
my $asserters = "$work/asserters.list";
spit ($asserters, "version 0\nissued 2026-01-01T00:00:00Z\n"
                . "asserter spiffe://ace-tao.test/client types=name realms=\@LAB.TEST\n"
                . "asserter spiffe://ace-tao.test/server types=name realms=\@LAB.TEST\n"
                . "asserter alice\@LAB.TEST types=name\n");
$o = `$tool --conf $work/tool.conf asserters sign $sign --file $asserters --bump 2>&1`;
die "asserters sign failed:\n$o" unless $o =~ /signed into/;
my $k5base = $base . "krb_keytab = $work/who.keytab\ndenylist_signer = $certs/signer_pub.pem\n"
           . "denylist_signer_sha256 = $pin\ncsiv2_asserters = $asserters\n";
spit ("$work/k5.conf", $k5base . "csiv2_kerberos = supported\n");
spit ("$work/k5off.conf", $k5base);
spit ("$work/k5mid.conf", $base . "csiv2_kerberos = supported\nkrb_keytab = $work/who.keytab\ncsiv2_assert_caller = on\n");
chmod (0600, "$work/k5.conf", "$work/k5off.conf", "$work/k5mid.conf");

start_server ('k5');
$out = call ('whoami', 'none', '-k file://' . "$d/beta.ior" . ' -a krbname:bob@LAB.TEST');
expect ('K5: a listed asserter may assert a Kerberos principal (served with the Kerberos name type)', $out,
        ['^SAS REPLY complete ', "^WHOAMI name=$krbtype:bob\\\@LAB\\.TEST "]);
expect ('K5: ... not one in a realm it may not assert', call ('whoami', 'none', "-k file://$d/beta.ior -a krbname:bob\@OTHER.TEST"),
        [@refused1], ['^WHOAMI']);
expect ('K5: ... nor a name without a realm', call ('whoami', 'none', "-k file://$d/beta.ior -a krbname:bob"),
        [@refused1], ['^WHOAMI']);
expect ('K5: a name under an unknown mechanism OID is refused', call ('whoami', 'none', "-k file://$d/beta.ior -a badoid:bob\@LAB.TEST"),
        [@refused1], ['^WHOAMI']);
$out = call ('whoami', "krb5:$principal:$bind", "-k file://$d/beta.ior -a krbname:carol\@LAB.TEST");
expect ('K5: a Kerberos-authenticated asserter asserts a name of its service\'s realm', $out,
        ["^WHOAMI name=$krbtype:carol\\\@LAB\\.TEST "]);
expect ('  (audited: who asserted, the realm limits)', log_now (),
        ['reason="SAS_ACCEPTED" principal="bob\@LAB\.TEST" .*asserter="spiffe://ace-tao\.test/client"',
         'reason="SAS_ACCEPTED" principal="carol\@LAB\.TEST" .*asserter="alice\@LAB\.TEST"',
         'reason="ASSERTION_REJECTED" .*the asserter may not assert names in realm OTHER\.TEST',
         'reason="ASSERTION_REJECTED" .*not a well-formed Kerberos principal',
         'reason="ASSERTION_REJECTED" .*not a well-formed GSSUP or Kerberos exported name']);
stop_server ('none');

start_server ('k5off');
expect ('K5: with csiv2_kerberos = off a Kerberos name is refused',
        call ('whoami', 'none', "-k file://$d/beta.ior -a krbname:bob\@LAB.TEST"), [@refused1], ['^WHOAMI']);
expect ('  (audited)', log_now (), ['reason="ASSERTION_REJECTED" .*Kerberos names are not accepted here']);
stop_server ('none');

# TAO end to end: alice logs in to a middle tier with Kerberos; the middle
# tier (csiv2_assert_caller = on, certificate spiffe://ace-tao.test/server)
# asserts her to a back end.
foreach my $back ('k5', 'k5off') {
    start_server ($back, undef, 'back');
    my ($bpid, $bd, $blog) = ($pid, $d, $log);
    start_server ('k5mid');
    $out = tao ('beta', "-K target= -c relay -r file://$bd/beta.ior");
    if ($back eq 'k5') {
        expect ('K5: TAO\'s middle tier asserts a Kerberos caller to a Kerberos back end as a Kerberos name', $out,
                ['^ACQUIRE OK$', "^RELAY name=$krbtype:alice\\\@LAB\\.TEST "]);
        expect ('  (back end audit: alice, asserted by the middle tier)', slurp ($blog),
                ['reason="SAS_ACCEPTED" principal="alice\@LAB\.TEST" .*asserter="spiffe://ace-tao\.test/server"']);
    } else {
        expect ('K5: ... and to a back end without Kerberos names asserts nothing (never re-labelled as GSSUP)', $out,
                ['^ACQUIRE OK$', '^RELAY name=\S+spiffe://ace-tao\.test/server '], ['^RELAY .*alice']);
    }
    stop_server ('none');
    ($pid, $d, $log) = ($bpid, $bd, $blog);
    stop_server ('none');
}

# --- the keytab self-check -----------------------------------------------------------------
my $sc = scalar (`ACE_TAO_SECURITY_CONF=$work/open.conf $sas/server -ORBSvcConf $work/server.svc -ORBListenEndpoints iiop://127.0.0.1: -d $work 2>&1 & sleep 3; kill \$! 2>/dev/null`);
if ($prod) {
    expect ('prod: a world-readable keytab fails the self-check', $sc,
            ['FAIL csiv2_kerberos: Kerberos keytab unusable, every login refused: \S+open\.keytab is mode 0644', 'ORB_INIT REFUSED']);
}
# An RC4 key, written with ktutil (skipped where the library no longer
# writes RC4 keys).
`printf 'addent -password -p $principal -k 9 -e rc4-hmac\\nweak-password\\nwkt $work/rc4.keytab\\nquit\\n' | $krb/ktutil 2>&1`;
if (-s "$work/rc4.keytab") {
    chmod (0600, "$work/rc4.keytab");
    spit ("$work/rc4.conf", $base . "csiv2_kerberos = supported\nkrb_keytab = $work/rc4.keytab\n");
    chmod (0600, "$work/rc4.conf");
    $sc = scalar (`ACE_TAO_SECURITY_CONF=$work/rc4.conf $sas/server -ORBSvcConf $work/server.svc -ORBListenEndpoints iiop://127.0.0.1: -d $work 2>&1 & sleep 3; kill \$! 2>/dev/null`);
    expect ('a keytab with an RC4 key fails the self-check', $sc,
            ['csiv2_kerberos: Kerberos keytab unusable, every login refused: \S+rc4\.keytab holds weak keys \(rc4-hmac']);
} else {
    print "SKIPPED: RC4 keytab check (ktutil wrote no RC4 key)\n";
}

# --- key rotation ---------------------------------------------------------------------------
# Needs ACE_TAO_KRB_REKEY: a command that gives a lab service (its name is
# appended) a new key version, kept in its keytab beside the old one
# (CORBA lab/kdc.sh rekey).  The service keeps running: the new keytab
# replaces its file the way a deployment tool would (written beside it,
# then renamed over it), and tickets issued under the old and the new key
# must both be served without a restart.
if (my $rekey = $ENV{'ACE_TAO_KRB_REKEY'}) {
    start_server ('krb', undef, 'rot');
    $out = call ('whoami', "krb5:$principal:$bind");
    expect ('key rotation: before it, the service is served a ticket under the current key', $out,
            ['^WHOAMI name=\S+alice\@LAB\.TEST']);
    call ('poke', "krb5save:$principal:$bind:$work/old_key_token");
    my $r = `$rekey who 2>&1`;
    copy ("$lab/keytabs/who.keytab", "$work/who.keytab.new") || die "copy keytab: $!";
    chmod (0600, "$work/who.keytab.new");
    rename ("$work/who.keytab.new", "$work/who.keytab") || die "rename keytab: $!";
    my %kvno = map { $_ => 1 } (`$krb/klist -k $work/who.keytab 2>&1` =~ /^\s*(\d+) ace-tao\/who\./mg);
    expect ('  ... the new keytab holds the old and the new key version', scalar (keys %kvno) . " versions\n$r",
            ['^([2-9]|\d\d+) versions']);
    $out = call ('whoami', "rawtoken:$work/old_key_token");
    expect ('  ... without a restart, a ticket issued under the old key is still served', $out,
            ['^WHOAMI name=\S+alice\@LAB\.TEST']);
    {
        local $ENV{'KRB5CCNAME'} = "FILE:$work/ccache_rot";
        `$krb/kinit alice\@LAB.TEST < $lab/passwords/alice 2>&1`;
        $out = call ('whoami', "krb5:$principal:$bind");
    }
    expect ('  ... and so is one issued under the new key', $out, ['^WHOAMI name=\S+alice\@LAB\.TEST']);
    expect ('  (audited: the changed keytab was checked and loaded)', log_now (),
            ['reason="KRB_KEYTAB_LOADED" file="\S+who\.keytab"\] the keytab changed; now in force: ace-tao/who\.lab\.test\@LAB\.TEST key version']);

    # The service holds its keys in memory: a replacement that fails the
    # keytab checks is refused, audited once, and the last good keys stay.
    my $good = slurp ("$work/who.keytab");
    my $replace = sub {
        my ($bytes, $mode) = @_;
        spit ("$work/who.keytab.new", $bytes);
        chmod ($mode, "$work/who.keytab.new");
        rename ("$work/who.keytab.new", "$work/who.keytab") || die "rename keytab: $!";
    };
    $replace->(substr ($good, 0, int (length ($good) / 2)), 0600);
    $out = call ('whoami', "krb5:$principal:$bind");
    expect ('a half-written replacement keytab is refused, and logins go on with the last good keys', $out,
            ['^WHOAMI name=\S+alice\@LAB\.TEST']);
    expect ('  (audited once: KRB_KEYTAB_REJECTED, the last good keys stay in force)', log_now (),
            ['reason="KRB_KEYTAB_REJECTED" file="\S+who\.keytab"\] .*the last good keys stay in force']);
    call ('whoami', "krb5:$principal:$bind");
    my $rejections = () = log_now () =~ /reason="KRB_KEYTAB_REJECTED"/g;
    expect ('  ... and not again at the next login', "$rejections rejection(s)", ['^1 rejection']);
    if ($prod) {
        $replace->($good, 0644);
        $out = call ('whoami', "krb5:$principal:$bind");
        expect ('prod: a world-readable replacement keytab is refused, the last good keys serve', $out,
                ['^WHOAMI name=\S+alice\@LAB\.TEST']);
        expect ('  (audited: its mode)', log_now (), ['reason="KRB_KEYTAB_REJECTED" .*is mode 0644']);
    }
    $replace->($good, 0600);
    $out = call ('whoami', "krb5:$principal:$bind");
    my $loads = () = log_now () =~ /reason="KRB_KEYTAB_LOADED"/g;
    expect ('a good keytab put back is loaded again', "$loads load(s)\n$out", ['^2 load', '^WHOAMI name=\S+alice\@LAB\.TEST']);
    stop_server ();
    if (scalar (keys %kvno) - 1 > 4) {   # versions at startup, before this rotation
        expect ('the self-check warns about a keytab with more than 4 key versions', slurp ($log),
                ['WARN csiv2_kerberos: \S+who\.keytab holds \d+ key versions']);
    }
    print "--- rotation server log (KRB lines)\n" . join ("\n", grep { /KRB|keytab/i } split (/\n/, slurp ($log))) . "\n"
        if $ENV{'KRB_ROTATION_DEBUG'};
}
else {
    print "skipped: key rotation check (set ACE_TAO_KRB_REKEY, e.g. to CORBA lab/kdc.sh rekey)\n";
}

rmtree ($work) if $status == 0;
exit $status;
