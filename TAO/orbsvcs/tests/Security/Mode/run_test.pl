eval '(exit $?0)' && eval 'exec perl -S $0 ${1+"$@"}'
     & eval 'exec perl -S $0 $argv:q'
     if 0;

# -*- perl -*-
#
# Host security mode: each case writes a security configuration and a
# service configuration, points ACE_TAO_SECURITY_CONF at the first, runs
# mode_test, and checks its exit status and output.

use lib "$ENV{ACE_ROOT}/bin";
use PerlACE::TestTarget;
use Cwd;

my $test = PerlACE::TestTarget::create_target (1) || die "Create target 1 failed\n";
my $dir = getcwd ();
my $exe = "$dir/mode_test";

my $anchor = 'D4:A1:A8:18:BB:BA:70:7B:33:27:37:AA:46:8B:5E:F3:FD:12:15:47:BA:59:84:1E:B3:FE:A7:2D:25:4A:7A:97';
my $conf = "$dir/mode_test_security.conf";
my $svc = "$dir/mode_test_svc.conf";
my $sock = "$dir/mode_test_audit.sock";

sub ssliop {
    my ($opts, $factories) = @_;
    $factories = "-ORBProtocolFactory SSLIOP_Factory" unless defined $factories;
    return "dynamic SSLIOP_Factory Service_Object * TAO_SSLIOP:_make_TAO_SSLIOP_Protocol_Factory() \"$opts\"\n"
         . "static Resource_Factory \"$factories\"\n";
}

my $good_ssl = "-SSLAuthenticate SERVER_AND_CLIENT -SSLCAfile PEM:$dir/ca.pem "
             . "-SSLCertificate PEM:$dir/server_cert.pem -SSLPrivateKey PEM:$dir/server_key_enc.pem "
             . "-SSLPassword file:$dir/password.txt";
my $prod = "mode = prod\naudit_sink = stderr\ntime_sync_wait = 0\ntrust_anchor_sha256 = $anchor\n";
my $test_mode = "mode = test\naudit_sink = stderr\n";

# name, security.conf (undef: none), conf file mode, svc.conf (undef: none),
# expected exit, regexes the output must match, regexes it must not.
my @cases = (
  ['no configuration: stock TAO', undef, 0600, undef, 0, ['ORB_INIT OK'], ['SECURITY', 'MODE=']],
  ['test mode without a plugin', $test_mode, 0600, undef, 0, ['ORB_INIT OK'], []],
  ['dev without a plugin runs and says so', "mode = dev\naudit_sink = stderr\n", 0600, undef, 0,
     ['MODE=DEV .*security checks are not run', 'ORB_INIT OK'], ['check ', 'WARN', 'FAIL']],
  ['embedded without a plugin runs with a loud banner', "mode = embedded\naudit_sink = stderr\n", 0600, undef, 0,
     ['MODE=EMBEDDED .*running without the security plugin', 'ORB_INIT OK'], ['check ', 'FAIL']],
  ['dev with weak SSLIOP settings runs no self-check', "mode = dev\naudit_sink = stderr\n", 0600,
     ssliop ("-SSLAuthenticate SERVER_AND_CLIENT -SSLCAfile PEM:$dir/ca_plus_other.pem "
           . "-SSLCertificate PEM:$dir/server_cert.pem -SSLPrivateKey PEM:$dir/server_key.pem -SSLPassword env:"), 0,
     ['MODE=DEV', 'ORB_INIT OK'], ['check ', 'WARN', 'FAIL', 'MODE=TEST']],
  ['prod without a plugin is refused', $prod, 0600, undef, 2,
     ['no security plugin is loaded', 'ORB_INIT REFUSED'], []],
  ['configuration without a mode is refused', "audit_sink = stderr\n", 0600, undef, 2,
     ['has no mode', 'ORB_INIT REFUSED'], []],
  ['unknown mode is refused', "mode = production\n", 0600, undef, 2,
     ['unknown mode "production" \(want dev, test, prod or embedded\)', 'ORB_INIT REFUSED'], []],
  ['group-writable configuration is refused', $prod, 0620, undef, 2,
     ['writable by group or others', 'ORB_INIT REFUSED'], []],
  ['prod with SSLIOP, protected key and trust anchor', $prod, 0600, ssliop ($good_ssl), 0,
     ['MODE=PROD .*key=encrypted-file .*ca=sha256:d4a1a818bbba .*0 fail', 'ORB_INIT OK',
      'check protocols OK', 'check ssliop_key OK', 'check ssliop_trust OK', 'check core_dumps OK',
      'event="secenv" result="ok" reason="OK" phase="startup"'], ['FAIL']],
  ['prod with plain IIOP also loaded is refused', $prod, 0600,
     ssliop ($good_ssl, "-ORBProtocolFactory IIOP_Factory -ORBProtocolFactory SSLIOP_Factory"), 2,
     ['FAIL protocols: protocol factory IIOP_Factory is not in allowed_protocols', 'ORB_INIT REFUSED'], []],
  ['prod with an unprotected key file is refused', $prod, 0600,
     ssliop ("-SSLAuthenticate SERVER_AND_CLIENT -SSLCAfile PEM:$dir/ca.pem -SSLCertificate PEM:$dir/server_cert.pem "
           . "-SSLPrivateKey PEM:$dir/server_key.pem"), 2,
     ['FAIL ssliop_key: unprotected private key file', 'ORB_INIT REFUSED'], []],
  ['prod with a literal passphrase is refused', $prod, 0600,
     ssliop ("-SSLAuthenticate SERVER_AND_CLIENT -SSLCAfile PEM:$dir/ca.pem -SSLCertificate PEM:$dir/server_cert.pem "
           . "-SSLPrivateKey PEM:$dir/server_key_enc.pem -SSLPassword mode-test-pass"), 2,
     ['FAIL ssliop_password: -SSLPassword from a literal value', 'ORB_INIT REFUSED'], []],
  ['prod with an extra CA in the trust store is refused', $prod, 0600,
     ssliop ("-SSLAuthenticate SERVER_AND_CLIENT -SSLCAfile PEM:$dir/ca_plus_other.pem "
           . "-SSLCertificate PEM:$dir/server_cert.pem -SSLPrivateKey PEM:$dir/server_key_enc.pem "
           . "-SSLPassword file:$dir/password.txt"), 2,
     ['FAIL ssliop_trust: .* holds certificates that are not trust anchors', 'ORB_INIT REFUSED'], []],
  ['prod without trust_anchor_sha256 is refused', "mode = prod\naudit_sink = stderr\ntime_sync_wait = 0\n", 0600,
     ssliop ($good_ssl), 2, ['FAIL ssliop_trust: trust_anchor_sha256 is not set', 'ORB_INIT REFUSED'], []],
  ['prod with a dead audit sink is refused',
     "mode = prod\naudit_sink = unix:$dir/no-such-socket\ntime_sync_wait = 0\ntrust_anchor_sha256 = $anchor\n", 0600,
     ssliop ($good_ssl), 2, ['FAIL audit: audit sink unix:.* does not accept records', 'ORB_INIT REFUSED'], []],
  ['test mode warns about the same weaknesses but runs', $test_mode, 0600,
     ssliop ("-SSLAuthenticate SERVER_AND_CLIENT -SSLCAfile PEM:$dir/ca_plus_other.pem "
           . "-SSLCertificate PEM:$dir/server_cert.pem -SSLPrivateKey PEM:$dir/server_key.pem -SSLPassword env:"), 0,
     ['WARN ssliop_key', 'WARN ssliop_password', 'WARN ssliop_trust', 'MODE=TEST', 'ORB_INIT OK'], ['FAIL']],
  ['prod refuses Notify event persistence', $prod, 0600,
     ssliop ($good_ssl)
     . "dynamic Event_Persistence Service_Object* TAO_CosNotification_Serv:_make_TAO_Notify_Standard_Event_Persistence() "
     . "\"-file_path $dir/mode_test_events.db\"\n", 2,
     ['Notification Service event persistence is refused in prod mode'], ['ORB_INIT OK']],
);

sub write_file {
    my ($path, $text, $mode) = @_;
    open (my $fh, '>', $path) || die "cannot write $path: $!\n";
    print $fh $text;
    close ($fh);
    chmod ($mode, $path) if defined $mode;
}

my $status = 0;

my $unit = `$exe -unit 2>&1`;
print $unit;
if ($? != 0) {
    print STDERR "ERROR: mode_test -unit failed\n";
    $status = 1;
}

foreach my $c (@cases) {
    my ($name, $sec, $mode, $svcconf, $want_exit, $must, $mustnot) = @$c;
    unlink $conf, $svc;
    if (defined $sec) {
        write_file ($conf, $sec, $mode);
    }
    $ENV{'ACE_TAO_SECURITY_CONF'} = $conf;
    my $args = '';
    if (defined $svcconf) {
        write_file ($svc, $svcconf, 0600);
        $args = "-ORBSvcConf $svc";
    }
    my $out = `$exe $args 2>&1`;
    my $exit = $? >> 8;
    my @problems;
    push @problems, "exit $exit, want $want_exit" if $exit != $want_exit;
    foreach my $re (@$must) {
        push @problems, "missing /$re/" unless $out =~ /$re/;
    }
    foreach my $re (@$mustnot) {
        push @problems, "unexpected /$re/" if $out =~ /$re/;
    }
    if (@problems) {
        print STDERR "ERROR: $name: " . join ('; ', @problems) . "\n$out\n";
        $status = 1;
    }
    else {
        print "ok: $name\n";
    }
}

# Running monitor: requests are refused while the audit sink is down.
write_file ($conf, "mode = prod\naudit_sink = unix:$sock\ntime_sync_wait = 0\ntrust_anchor_sha256 = $anchor\n", 0600);
write_file ($svc, ssliop ($good_ssl), 0600);
$ENV{'ACE_TAO_SECURITY_CONF'} = $conf;
my $out = `$exe -degrade $sock -ORBSvcConf $svc -ORBCollocation no -ORBListenEndpoints iiop://127.0.0.1: 2>&1`;
my @lines = grep { /^(ok|FAIL):/ } split (/\n/, $out);
print join ("\n", @lines) . "\n";
if ($? != 0 || scalar (grep { /^ok:/ } @lines) != 5) {
    print STDERR "ERROR: degraded-mode case failed\n$out\n";
    $status = 1;
}

unlink $conf, $svc, $sock, "$dir/mode_test_events.db";
exit $status;
