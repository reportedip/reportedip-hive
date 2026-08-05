# WebAuthn hardware test matrix

Release gate for the "official YubiKey support" claim. Every cell must pass
on a staging site served over HTTPS with a real YubiKey 5C NFC before the
release that advertises hardware-key support is tagged. Automated coverage
(Playwright + Chromium virtual authenticator) exercises the same flows but
cannot reach real USB/NFC hardware paths.

Fill each cell with the date + initials on pass, or a ticket reference on
fail.

| Platform | Transport | Enrol | wp-login 2FA | WC frontend 2FA | Reset gate | 2nd key | Foreign key rejected | Cancel, then retry |
|---|---|---|---|---|---|---|---|---|
| Windows 11, Chrome | USB-C | | | | | | | |
| Windows 11, Edge | USB-C | | | | | | | |
| Android, Chrome | NFC tap | | | | | | | |
| iPhone, Safari | NFC tap | | | | | | | |
| macOS, Safari | USB-C | | | | | | | |

Column notes:

- **Enrol** — profile key manager, "Security key (USB / NFC)" flow with a
  custom name; expect no FIDO2-PIN prompt on a fresh key
  (`residentKey: discouraged` working).
- **wp-login 2FA** — challenge interstitial, "Use passkey or security key".
- **WC frontend 2FA** — storefront challenge (requires a PRO-tier staging
  site with WooCommerce).
- **Reset gate** — lost-password flow, WebAuthn tab of the reset challenge.
- **2nd key** — enrol a second YubiKey as backup; excludeCredentials must
  refuse re-registering the first key on itself.
- **Foreign key rejected** — assert with a YubiKey never enrolled for the
  account; expect "Unknown security key".
- **Cancel, then retry** — cancel the browser dialog, confirm the guidance
  message mentions the NFC tap, retry succeeds without a reload.

Additional checks (once per release):

- Model label "YubiKey 5 Series with NFC" appears under the key name in the
  key manager (direct-attestation AAGUID path).
- On firmware 5.2.3+ the stored credential negotiates Ed25519
  (`public_key` COSE alg -8) when libsodium is active server-side.
- The stored `sign_count` increments after every hardware login
  (clone detection armed).
- A "new security key was added" notification mail arrives on enrolment.
