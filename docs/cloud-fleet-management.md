# Cloud Fleet Management

Manage the security settings of every ReportedIP Hive installation you own
from one place — either a self-hosted [MainWP](https://mainwp.com/) dashboard
or the reportedip.com fleet dashboard (Business plan). Both speak the same
[remote settings protocol](remote-settings-protocol.md), so a policy behaves
identically no matter which dashboard applied it.

This document describes the feature end to end: what it does, how it is
secured, how to enable it, and how to operate it. For the exact wire format
see the protocol document; for what to change when settings change see its
*Change checklist* section.

---

## What it does

- **One policy, many sites.** Define a security policy once — failed-login
  thresholds, auto-blocking, WAF level, 2FA enforcement, logging, and every
  other remote-managed option — and push it to any connected site.
- **Per-site overrides.** Any single field can be overridden for one site;
  everything else inherits the global policy.
- **Drift detection.** Every site reports a settings fingerprint on each API
  call. If someone changes a setting directly on a site, the dashboard shows
  that site as *drifted* until you push again.
- **Live compare.** See the dashboard's target value next to the site's
  actual value, per field, fetched live from the site.
- **Schema-driven.** The form is rendered from a schema the site itself
  exports, so new Hive options appear in the dashboard automatically after a
  schema reload — no dashboard update required.

The feature manages **63 settings** across seven groups: detection, blocking,
WAF, hide-login, account security, privacy/logging, and notifications. A small
set of options is deliberately excluded (see *Scope* below).

---

## Two transports, one contract

| Transport | Who runs it | How it reaches the site |
|---|---|---|
| MainWP extension | your own MainWP dashboard | the MainWP Child channel (`mainwp_child_extra_execution`) |
| reportedip.com fleet | the reportedip.com dashboard (Business) | signed REST call to the site |

Both end in the same three operations against the same core classes on the
site: read the schema, read current values, apply a validated batch. The
result envelope is byte-identical between the two transports.

---

## Enabling it on a site

1. The site must be in **Community Network mode** with a configured
   Community Access Key.
2. Update the site to **Hive 2.1.48 or newer**.
3. **MainWP:** connect the site to your MainWP dashboard as usual — no extra
   step, the child bridge ships inside Hive.
4. **reportedip.com fleet:** switch on **"Cloud fleet management via
   reportedip.com"** on the Hive *General* settings tab. It is **off by
   default**. While it is on, each API request the site makes announces its
   settings schema version and fingerprint, which is how the fleet dashboard
   discovers the site and detects drift. Switch it off and the site rejects
   every management request again.

The MainWP transport does not require the toggle; it is authenticated by the
MainWP Child connection instead.

---

## Drift states

A site is always in exactly one of five states:

| State | Meaning |
|---|---|
| **No schema / not enabled** | The site does not (yet) support the protocol or has cloud management switched off. No push possible. |
| **Never pushed** | Supported and connected, but no policy has been applied yet. |
| **Pending** | You changed the policy or an override in the dashboard; the site has not received it yet. |
| **Drifted** | Someone changed a managed setting directly on the site, so it no longer matches the last push. |
| **In sync** | The site matches the applied policy. |

"Push all" targets every capable site. "Push drifted only" targets exactly
the *drifted* and *pending* sites — never *never pushed* ones, so healing
drift can never accidentally configure a site you had not set up yet.

The fingerprint is always computed **on the site**. Dashboards store the hash
returned by the last successful apply and compare it against the hash the site
reports later — they never recompute it. This keeps the two sides honest
across PHP/JSON representation differences.

---

## Security model

The reportedip.com fleet transport calls into each site, so it is
authenticated end to end. Every request carries an Ed25519-signed envelope
that the site verifies before doing anything:

1. **Opt-in.** The site-side toggle must be on, the site in Community mode,
   and an access key present. A request that fails this and a request that
   fails the signature check return the **same** generic authentication error,
   so an unauthenticated caller cannot tell from the response whether a site
   has opted in.
2. **Rate limit.** Per-IP throttling on the site.
3. **Signature.** Detached Ed25519 signature over the exact payload string,
   verified against a public key bundled in the plugin. The private key never
   leaves the service; a rotation slot is reserved so a new key can ship
   before the service switches to it.
4. **Freshness.** The request timestamp must be within a five-minute window.
5. **Replay protection.** Each request id is single-use for ten minutes.
6. **Audience binding.** The signed payload names the target site; an envelope
   for one site cannot be replayed against another.
7. **Account proof.** The payload carries a proof derived from the site's own
   access key, binding the request to the account that owns the site.

On the service side the outbound call is additionally guarded against
server-side request forgery: only `http`/`https` targets are allowed, the host
is resolved and rejected if it points at a private or reserved address, and
redirects are disabled so the check cannot be bypassed. The signing key is
stored encrypted at rest and never returned in any response.

The whole transport is **fail-closed**: with no valid signature, an expired
timestamp, a replayed id, a wrong audience, or a bad account proof, the
request is refused and logged as a security event — while the caller only
ever sees the generic denial.

---

## Scope — what is and isn't managed

**Managed (63 keys, both transports):** the detection thresholds and monitor
toggles, auto-blocking and escalation, report-only mode, the WAF engine
level and rule-sync options, hide-login, 2FA enablement/enforcement/policy,
password policy, logging and retention, audit options, and notification
settings.

**Deliberately excluded (both transports):**

- `operation_mode` and `api_key` — these define the connection itself and are
  handled through provisioning, not policy.
- The frontend-2FA rewrite slugs, hardening mode, and the advanced security
  headers (CSP/HSTS) — these carry site-specific side effects or are a remote
  footgun, and are managed locally.
- On Multisite, the two per-site override options are network-scoped locally
  and never remote-managed.

Because both dashboards render from the same exported schema, this scope is
identical on MainWP and on reportedip.com. Adding a new managed option is a
Hive-only change; it then appears in both dashboards after a schema reload.

---

## Multisite

All remote-managed options are network options. Applying a policy to any
connected sub-site therefore configures the **whole network**. The dashboard
surfaces this with a network-wide notice in the compare view so it is never a
surprise.

---

## Troubleshooting

- **A site shows "No schema / not enabled".** It is on a Hive version older
  than 2.1.48, not in Community mode, or the cloud-management toggle is off.
- **A push reports "plan-locked" keys.** Those settings require a higher plan
  on that site; they are skipped, never forced, and do not count as failures.
- **A push fails with an unreachable/blocked error.** The site could not be
  reached, or its address resolved to a non-routable host and was blocked by
  the SSRF guard. Verify the site's public address and that it is online.
- **A site keeps showing "Drifted".** Something on the site changes a managed
  setting after each push (another plugin, a deploy script, a person). Use the
  compare view to see which field differs.
- **Schema looks outdated in the dashboard.** Reload the schema
  ("Schema neu laden" in MainWP, "Reload schema" on the fleet dashboard);
  this also re-validates the stored policy and overrides against the new
  schema.

---

## Related documents

- [Remote settings protocol](remote-settings-protocol.md) — the wire format,
  envelopes, kinds, fingerprint algorithm, and the change checklist for when
  options change.
