# Deploying with Active Directory

How a hardened ACE/TAO service gets its identity from an Active Directory
estate, and keeps it current: the TLS certificate from AD Certificate
Services (AD CS), the Kerberos keytab from an AD account, and the AD
operations that go with them.

Status: the Kerberos and keytab parts are exercised by the test suite
against a lab KDC and a lab Samba AD domain. The AD CS parts are guidance
only: they have not been run against an AD CS installation here. Check each
step against your own AD CS and Group Policy before relying on it.

Nothing here makes a deployment compliant with any standard. It describes
how this software expects to be deployed.

## What the service needs

| Item | Used for | Comes from |
| --- | --- | --- |
| Private key | TLS (SSLIOP) | Made on the host (`ace-tao-setup key create`), never exported |
| Certificate for that key | TLS identity: its SPIFFE ID (URI SAN), else its subject DN | AD CS, issued from a request made with the key |
| CA certificate chain | `-SSLCAfile`, `trust_anchor_sha256` | The AD CS root (and issuing CA) |
| Keytab | Kerberos logins to the service (`krb_principal`, `krb_keytab`) | An AD account holding the service's SPN |

The key stays where it was made (a file, a PKCS#11 token, a TPM, the Secure
Enclave). Only a certificate request leaves the host.

## The certificate from AD CS

### Choose the identity first

SSLIOP names a caller by the first `spiffe://` URI in its certificate's
subject alternative names, else by its subject DN, and access rules, role
lines and deny-list entries use that name. Decide it before requesting the
certificate, for example `spiffe://corp.example/naming/host01`, and use the
same name in the service's access list or role map.

### Request it

1. Make the key on the service host, as the service account:

   ```
   ace-tao-setup key create --type tpm2 --out /etc/ace-tao/naming.key
   ```

   (or `--type pkcs11 --uri ...`, or `--type file --password-file ...`).

2. Make a certificate signing request (CSR) with that key, asking for the
   chosen identity: the subject, the URI SAN, and the DNS name the service
   is reached at. `ace-tao-setup` makes requests only for step-ca today
   (`cert request`, with a one-time token), so for AD CS make the CSR with
   OpenSSL 3, using the same provider that holds the key, for example:

   ```
   openssl req -new -provider tpm2 -provider default \
     -key /etc/ace-tao/naming.key -subj "/CN=naming.host01.corp.example" \
     -addext "subjectAltName=URI:spiffe://corp.example/naming/host01,DNS:host01.corp.example" \
     -out naming.csr
   ```

3. Submit it to AD CS with a template made for these services:
   - Windows: `certreq -submit -attrib "CertificateTemplate:AceTaoService" naming.csr naming.cer`
   - Linux: certmonger with an AD CS enrollment helper (MS-XCEP/MS-WSTEP,
     for example cepces), or AD CS web enrollment from an admin's browser.

4. Approval. With **CA certificate manager approval** set on the template
   (Issuance Requirements), the request waits as pending until a
   certificate manager reviews it. They check that the identity in the
   request is the one this host should hold, then issue it
   (`certutil -resubmit <RequestId>` or the Certification Authority
   console). The requester then collects it:
   `certreq -retrieve <RequestId> naming.cer`.

5. Install and check. Convert to PEM if needed
   (`openssl x509 -inform der -in naming.cer -out naming.pem`), install
   it beside the key, then check that the certificate matches the key and
   has not expired (the service's self-check judges the rest at startup):

   ```
   ace-tao-setup key check --key STORE:... --cert naming.pem
   ```

   Point SSLIOP at it (`-SSLCertificate PEM:...`), put the AD CS chain in
   `-SSLCAfile`, and pin the AD CS root with `trust_anchor_sha256`
   (`openssl x509 -in root.pem -noout -fingerprint -sha256`).

### The template, and the risks it carries

A template that lets the requester put its own identity in the request
(Subject Name: **Supply in the request**) and issues client-authentication
certificates can let anyone allowed to enroll obtain a certificate for any
name. That includes names used elsewhere in the domain (the "ESC1" class of
AD CS misconfiguration). Our services need both of those properties,
because the SPIFFE URI must come from the request. So:

- Require **CA certificate manager approval** on the template, or
  restrict **Enroll** to the specific service hosts' computer accounts or
  a group holding only them. Prefer both.
- Do not enable `EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA to get the SAN
  in. It lets requests add SANs under every template.
- EKUs: Server Authentication and Client Authentication (SSLIOP is
  mutual TLS). Nothing broader.
- Key: ECDSA P-256 or RSA 3072 or more; mark the key non-exportable where
  the template offers it (it is made on the host anyway).
- Validity: short enough that renewal is routine (for example 90 days),
  long enough that an approval queue does not cause outages.

### Renewal

- **Automated.** certmonger (Linux) or autoenrollment (Windows) renews
  ahead of expiry. A template with manager approval sends each renewal to
  the queue too, unless it allows renewal requests signed with the current
  certificate to be issued without approval. Decide which your process
  needs.
- **Manual.** Repeat the request and approval. The service's self-check
  warns `cert_warn_days` days (default 14) before expiry, in every mode.
- **Restart after renewal.** SSLIOP loads its certificate when the
  service starts. A renewed certificate takes effect at the next restart,
  so have the renewal tool's post-save step restart the service
  (`systemctl restart ...`).

## The keytab from AD

The service's Kerberos identity is an SPN on an AD account, for example
`ace-tao/host01.corp.example@CORP.EXAMPLE` on a dedicated service account.

- **Windows tools:** register the SPN on the account
  (`setspn -S ace-tao/host01.corp.example CORP\svc-acetao-host01`), then
  export its keys:

  ```
  ktpass /princ ace-tao/host01.corp.example@CORP.EXAMPLE /mapuser CORP\svc-acetao-host01 ^
         /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL /pass * /out acetao.keytab
  ```

  (`/pass *` sets a new password; it changes the account's keys).
- **Linux tools:** `msktutil` can create the account, set the SPN and write
  the keytab from the host, and update the password and keytab later.

Then:

- Install the keytab as the service account, mode 0600 or 0400 (prod
  refuses anything else), and set `krb_principal` and `krb_keytab`.
- AES keys only. The self-check refuses a keytab holding DES or RC4 keys,
  so set the account to AES (msDS-SupportedEncryptionTypes) before
  exporting.
- **Rotation without a restart.** The service holds its keys in memory
  and reads the keytab again when the file changes. Replace it by writing
  the new keytab beside the old one and renaming it over (msktutil and
  most tools do). A replacement that fails the checks is refused
  (`KRB_KEYTAB_REJECTED`) and the last good keys stay in force.
- **Keep old key versions for a while.** Tickets issued before a password
  change still use the old key until they expire, renewals included, so
  keep the old version in the keytab that long. The self-check warns
  above four versions.
- A group managed service account (gMSA) rotates its own password. A
  Linux host needs extra tooling to read it and write the keytab, which
  is not covered here.

## Operating with AD

- **Cutting someone off now.** Disabling an AD account does not end the
  tickets it already holds (10 hours by default, renewals longer). Add the
  user or service to the signed deny-list:
  `ace-tao-setup denylist add --principal alice@CORP.EXAMPLE` or
  `--sid S-1-5-21-...`. A group SID cuts off every member. Services
  refuse it within `denylist_reload` seconds (default 30).
- **Group changes.** A user's groups are fixed in the ticket at their KDC
  login. Set `krb_max_ticket_age` (for example `1h`) so tickets from older
  logins are refused and users come back with current groups. Use
  `maxage=` on sensitive role lines (for example `maxage=15m` on an admin
  role) for a tighter limit there only.
- **No LDAP.** Services never query AD. Groups come only from the ticket's
  PAC, names for them from the signed SID-name table in the role map.
