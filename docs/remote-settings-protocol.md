# Remote Settings Protocol

Fixed contract for managing ReportedIP Hive settings from a central dashboard.
Every management transport speaks this protocol against the same three core
classes, so behaviour is identical no matter who is asking:

| Transport | Status | Entry point |
|---|---|---|
| MainWP (`mainwp_child_extra_execution` / `mainwp_site_sync_others_data`) | live | `includes/class-mainwp-integration.php` |
| reportedip.com management API (`reportedip-hive/v1/remote/settings/*`) | live | `includes/class-cloud-management-rest.php` |

Core classes (all loaded unconditionally, in every request context):

- `ReportedIP_Hive_Settings_Registry` — the declarative option registry:
  kinds, ranges, allowed values, tier gates, side effects, schema export,
  the settings fingerprint.
- `ReportedIP_Hive_Settings_Apply` — validates and writes a batch, returns a
  per-key result map. Call `ReportedIP_Hive_Settings_Apply::apply( $values, $origin )`.
  Four origins exist: `mainwp`, `cloud`, `import` and `admin` (the plugin's own
  settings pages and their AJAX cards). Only `admin` logs
  `settings_admin_apply`; the three remote origins log
  `settings_remote_apply`.
- `ReportedIP_Hive_Settings_Effects` — executes declared side effects
  (rewrite flushes, cache resets) once per request for any writer.

## Versioning

`ReportedIP_Hive_Settings_Registry::SCHEMA_VERSION` (integer, currently `1`).

- **Bump required**: removing a key, changing a key's kind, changing enum
  semantics of an existing value.
- **No bump**: adding keys or sections. Consumers MUST tolerate unknown keys
  (they receive `unknown_key` results) and unknown fields in envelopes.

## Operations

Requests arrive form-encoded through MainWP, so every value must survive
string transport. `values_json` is therefore a single JSON string; the
registry coerces types by kind on the child.

### `reportedip_hive_settings_schema`

Request: `{ "reportedip_hive_settings_schema": { "want": 1 } }`

Response (`$information['reportedip_hive']['settings_schema']`):

```jsonc
{
  "schema_version": 1,
  "plugin_version": "2.1.47",
  "sections": [
    { "id": "detection", "label": "…", "description": "…", "keys": [ "reportedip_hive_monitor_failed_logins", "…" ] }
  ],
  "fields": {
    "reportedip_hive_failed_login_threshold": {
      "kind": "int", "min": 1, "max": 100, "default": 5,
      "label": "…", "tier": null
    }
  }
}
```

Labels are translated into the site locale at export time.

Sections, in export order: `detection`, `blocking`, `waf`, `hide_login`,
`lockdown` (attack-surface switches: REST API access, XML-RPC, feeds,
wp-admin for visitors, PHP execution in uploads, software fingerprints),
`account_security`, `privacy_logs`, `notifications`. A section is pure
presentation: dashboards group fields by it and ignore ids they do not know.

### `reportedip_hive_settings_get`

Request: `{ "reportedip_hive_settings_get": { "want": 1 } }`

Form-encoded transports drop `null` values (`http_build_query`), so the job
object must always carry at least one non-null member — `want: 1` by
convention. The same applies to every job in this protocol.

Response (`settings_values`):

```jsonc
{
  "schema_version": 1,
  "values": { "reportedip_hive_auto_block": true, "…": "…" },
  "hash": "sha256:…",
  "is_main_site": true,
  "network_wide": false
}
```

### `reportedip_hive_settings_apply`

Request:

```jsonc
{ "reportedip_hive_settings_apply": {
    "schema_version": 1,
    "values_json": "{\"reportedip_hive_failed_login_threshold\":5,\"reportedip_hive_auto_block\":true}" } }
```

Response (`settings_apply`):

```jsonc
{
  "schema_version": 1,
  "results": {
    "reportedip_hive_failed_login_threshold": { "status": "applied" },
    "reportedip_hive_auto_block":             { "status": "unchanged" },
    "reportedip_hive_block_tor":              { "status": "skipped_tier", "message": "…" }
  },
  "applied": 1, "unchanged": 1, "failed": 0,
  "hash": "sha256:…"
}
```

Per-key status codes:

| Status | Meaning | Counts as |
|---|---|---|
| `applied` | value written | success |
| `unchanged` | sanitized value equals stored value | success |
| `skipped_tier` | value requires a higher plan on this site | soft skip |
| `invalid` | rejected by kind/range/cross-field validation | failure |
| `unknown_key` | key not in the remote registry (older child, typo) | failure |

A malformed `values_json` yields `"error": "invalid_payload"` with empty
results. `unknown_key` and `skipped_tier` are per-key and never abort the
batch.

### Sync piggyback (capability + drift channel)

Every `reportedip_hive_sync` response additionally carries:

- `settings_schema_version` — presence signals protocol support.
- `settings_hash` — current fingerprint (see below).

The cloud transport has the equivalent passive channel: when cloud
management is enabled, every outbound request to the reportedip.com API
carries the request headers `X-Rip-Settings-Schema` (schema version) and
`X-Rip-Settings-Hash` (current fingerprint). Header presence signals both
protocol support **and** the owner's opt-in; their absence must be treated
as "do not push".

## Cloud transport authentication

The MainWP transport inherits its authentication from the MainWP Child
layer. The cloud transport authenticates every request itself. Routes
(registered by `ReportedIP_Hive_Cloud_Management_REST`):

```
POST /wp-json/reportedip-hive/v1/remote/settings/schema
POST /wp-json/reportedip-hive/v1/remote/settings/get
POST /wp-json/reportedip-hive/v1/remote/settings/apply
```

Request body:

```jsonc
{ "payload": "<exact JSON string, signed as-is>", "signature": "<base64 Ed25519 detached signature>" }
```

Signed payload fields:

```jsonc
{
  "action": "apply",                     // must match the endpoint: schema | get | apply
  "site": "example.com",                 // audience: lowercased host, leading www. stripped
  "issued_at": 1756200000,               // unix time, accepted within +/- 300 s
  "request_id": "5f0f…",                 // unique per request, single-use for 600 s
  "key_proof": "<sha256(api_key + request_id)>",
  "schema_version": 1,                   // apply only, informational
  "values_json": "{…}"                   // apply only, same string contract as MainWP
}
```

Verification chain on the site, in order — every step failing rejects the
request and logs a `cloud_management_auth_fail` security event:

1. Opt-in: option `reportedip_hive_cloud_management` (default off) plus
   Community mode plus a configured Community Access Key. A request that
   fails this step and a request that fails the signature check both return
   the identical generic `reportedip_cloud_denied` (HTTP 401), so an
   unauthenticated caller cannot fingerprint from the response whether a
   site has opted in; the real reason is recorded server-side only.
2. Per-IP throttle (30 requests / 5 min).
3. Ed25519 signature over the **literal** `payload` string against the
   bundled fleet public keys (`PUBLIC_KEYS`, rotation slot `next`, filter
   `reportedip_hive_cloud_public_keys`). Decoding happens only after
   verification. The fleet keypair is separate from the ruleset signing key.
4. `action` matches the endpoint.
5. `issued_at` within the freshness window.
6. `request_id` unused (replay cache, site-transient, 600 s).
7. `site` equals this installation's announced host
   (`ReportedIP_Hive_API::api_site_url()`, normalized).
8. `key_proof` equals `sha256(own_api_key + request_id)` — binds the request
   to the account that owns this site's key.

Responses are the same envelopes as the MainWP jobs, keyed identically:
`{"settings_schema": …}`, `{"settings_values": …}`, `{"settings_apply": …}`.
Both transports build them through the same helpers
(`ReportedIP_Hive_Settings_Registry::values_envelope()`,
`ReportedIP_Hive_Settings_Apply::invalid_payload_envelope()`), so the shapes
cannot drift.

## Kind vocabulary

| Kind | Wire value | Sanitization |
|---|---|---|
| `bool` | bool / `"1"` / `"0"` / `"true"` … | `rest_sanitize_boolean()`, stored as `1`/`0` |
| `int` | number or numeric string | `absint()`, clamped to `min`..`max` |
| `enum` | string | must be in `allowed`, else `invalid` |
| `text` | string | `sanitize_text_field()` |
| `textarea` | string | `sanitize_textarea_field()` |
| `email` | string | `sanitize_email()`; invalid becomes `""` |
| `email_list` | string | split on whitespace/`,`/`;`, each validated, joined `a@x, b@y` |
| `url` | string | `esc_url_raw()`; empty allowed |
| `csv_int_list` | `"5,15,30"` | each item clamped to `min`..`max`; empty falls back to the canonical default |
| `slug` | string | via the key's `sanitize` override (Hide-Login slug rules: 3–50 chars, reserved list, permalink-collision check); violations are `invalid` |
| `json_list` | JSON array string or array | items `sanitize_key`ed, filtered through the key's validity filter, canonically re-encoded `wp_json_encode` |

`export_schema()` does not export a `json_list`'s allowed vocabulary (role
slugs, method names), so both dashboards render these keys as a raw JSON
textarea and the child filters unknown items away on apply. `textarea` keys
carry newline-separated lists and must not be flattened by a dashboard's
sanitizer.

## Cross-field rules

Evaluated over the merged view (incoming values over current values):

1. `reportedip_hive_hide_login_enabled` cannot be enabled while the effective
   `reportedip_hive_hide_login_slug` is empty → `invalid` on the enable key.

## Tier gating

Keys may declare a feature slug (`Mode_Manager::feature_status()`), applied
only when the target value activates the feature:

- `reportedip_hive_block_tor` → `tor_blocking` (gate when enabling).
- `reportedip_hive_waf_paranoia` → `rule_sync_priority` (gate for level ≥ 2;
  level 1 is always allowed).
- `reportedip_hive_prohibited_usernames`, `reportedip_hive_email_rules` →
  `registration_rules_unlimited` via `Registration_Guard::list_needs_tier()`
  (gate above ten entries or on any `/regex/` entry; ten plain entries stay
  free).
- `reportedip_hive_registration_allowlist` → `registration_rules_unlimited`
  (gate on any non-empty list).
- the seven `reportedip_hive_2fa_policy_*` role lists (`new_country`,
  `new_ip`, `new_subnet`, `new_device`, `every_n_days`, `every_n_logins`,
  `sessions_above_n`) → `2fa_policies` via
  `Settings_Registry::policy_list_needs_tier()` (gate on any non-empty list).
  Their three companion integers (`reportedip_hive_2fa_policy_days`,
  `_logins`, `_sessions`) are ungated: without an armed role list they do
  nothing.

A gated write returns `skipped_tier` and does not touch the stored value.
Disabling a gated feature is always allowed.

## Side effects

Declared per key as tokens, executed once per request on `shutdown` by
`ReportedIP_Hive_Settings_Effects` regardless of the writer:

| Token | Effect |
|---|---|
| `flush_rewrite` | `flush_rewrite_rules( false )` |
| `flush_2fa_frontend_memo` | reset the frontend-2FA availability/slug memo |

The WAF drop-in rebake, decoy `.htaccess`, verdict caches, API-key tier
refresh and mode-change event are wired on option-update hooks elsewhere in
the plugin and fire for registry writes automatically.

## Settings fingerprint (drift hash)

```
hash = "sha256:" + sha256( json_encode( { "s": SCHEMA_VERSION, "v": normalized } ) )
```

`normalized` = all remote keys sorted with `ksort`, each value normalized by
kind (`bool` → true/false, `int` → integer, everything else the stored
string). The hash is computed **only on the child**. Dashboards store the
`hash` returned by their last successful apply and compare it against the
`settings_hash` reported in subsequent syncs — they never recompute it.

`json_list` values are canonically re-encoded on every registry write, so a
value stored pre-2.1.47 in an equivalent-but-different encoding shows as
drift exactly once; the first push resolves it.

## Multisite semantics

All remote-managed keys are network options. An apply arriving at any
connected sub-site therefore changes the **whole network**; the
`settings_get` response carries `is_main_site` and `network_wide` so a
dashboard can warn accordingly. The three per-site override keys
(`ReportedIP_Hive_Option_Routing::SITE_OPTION_LOOKUP`) are deliberately
excluded from the remote registry.

## Compatibility rules

- Older child + newer dashboard: unsupported job keys are silently ignored
  (no `settings_schema_version` in the sync blob → dashboard must not push).
- Newer child + older dashboard: the two extra sync fields are ignored.
- Unknown keys in an apply: per-key `unknown_key`, batch continues.

## Extending the registry

Adding a managed option is a two-place change, enforced by unit test:

1. Default in `ReportedIP_Hive_Defaults::SAFE_OPTIONS`.
2. Spec entry in `ReportedIP_Hive_Settings_Registry::spec()` (section, kind,
   ranges, label, optional tier/side effects/`remote` flag).

The remote key list and kinds are snapshot-locked by
`tests/Unit/SettingsRegistryTest.php`; changing them forces a conscious
fixture update and a `SCHEMA_VERSION` decision.

Runtime state is not a setting. Options the plugin writes by itself
(`reportedip_hive_readiness_state`, `reportedip_hive_2fa_policy_admin_verified`,
`reportedip_hive_api_stats`, …) stay out of `SAFE_OPTIONS`, out of the
registry and out of the JSON export; a dashboard must never push them. Adding
a section is a one-place change: `Settings_Registry::sections()`.

## Change checklist — what to touch when options change

Both dashboards (MainWP extension, reportedip.com fleet) render their forms
from the exported schema, so most changes are Hive-only:

| Change | Hive (this repo) | MainWP extension | reportedip.com fleet | SCHEMA_VERSION |
|---|---|---|---|---|
| Add an option (existing kind) | `Defaults::SAFE_OPTIONS` + `Registry::spec()` (+ i18n); update the snapshot fixture consciously | nothing — reload the schema | nothing — refresh the schema | no |
| Remove an option / change a kind / change enum semantics | Registry + fixture | reload schema (stored policy/overrides must be re-validated) | schema refresh re-validates stored policy/overrides | **yes** |
| Introduce a new kind | `Registry::sanitize_kind()` + kind table above | PHP `render_value_input()`, JS `buildValueInput()`/`readFieldValue()`, `sanitize_against_schema()` | fleet JS renderer + server-side `sanitize_against_schema()` | yes |
| Add a tier gate to an option | `tier` slug in `spec()` (the Mode-Manager feature must exist) | nothing (generic badge) | nothing (generic badge) | no |
| Add a side-effect token | `spec()` + `Settings_Effects` token handler | nothing | nothing | no |
| Rotate the cloud signing key | ship the new public key in `PUBLIC_KEYS['next']`, switch the service after fleet adoption, then promote to `current` | — | swap the fleet signer keypair | no |
| Add a transport | a thin adapter around `export_schema()` / `values_envelope()` / `Settings_Apply::apply()` — never its own validation | — | — | no |

Ground rule: **one new option = exactly two code places in Hive** (default +
spec). Dashboards pick it up from the schema without a code change.

### Known settings-page exceptions

Two registry keys keep a bespoke sanitizer on the wp-admin settings page —
and only there: `reportedip_hive_2fa_allowed_methods` and
`reportedip_hive_2fa_enforce_roles`. Their form posts checkboxes instead of
the option value, so the page callback must detect the form shape from
`$_POST` (the 2.0.28 "only TOTP saved / roles wiped" fix), which a generic
registry callback cannot do. Every remote writer (MainWP, cloud, import)
sanitizes both keys through the registry's `json_list` kind; the bespoke
callbacks' direct-write branch is semantically identical. This list may only
shrink; the consistency check enforces it.

`slug` is an override-only kind: `sanitize_kind()` deliberately has no
generic slug branch, because the only slug key delegates to
`ReportedIP_Hive_Hide_Login::validate_slug_value()` (reserved-list and
permalink-collision checks live there). A second slug option must bring its
own `sanitize` override.

## Development workflow — changing settings, and how to test it

The end-to-end routine for any settings change, in order:

1. **Edit exactly two places in Hive** (for a new option):
   `ReportedIP_Hive_Defaults::SAFE_OPTIONS` (default) and
   `ReportedIP_Hive_Settings_Registry::spec()` (section, kind, ranges,
   label, optional `tier` / `sanitize` / `side_effects` / `remote`).
   Consult the change checklist above for every other change type; bump
   `SCHEMA_VERSION` only when the checklist says so.
2. **Update the locked snapshots consciously.** `SettingsRegistryTest`
   (remote key list + kinds) and `SettingsKeysAreStableTest` (registered
   option keys) fail on any drift; updating their fixtures is the explicit
   sign-off that the change is intended.
3. **Translate.** `composer i18n`, translate the new entries in
   `languages/reportedip-hive-de_DE.po`, `composer i18n:build` — the
   freshness gate blocks CI otherwise.
4. **Run the consistency layers:**
   - `vendor/bin/phpunit --testsuite unit` — includes
     `SettingsConsistencyTest` (identical apply results and stored state
     across the `mainwp` / `cloud` / `import` origins, schema
     renderability, wizard/registry kind agreement, defaults round-trip)
     and `CloudManagementRestTest` (transport auth chain + envelope parity).
   - The private workspace additionally runs a static cross-repo check
     (settings page callbacks, wizard delegation, import routing, shared
     envelope helpers, service/extension kind and drift-state coverage)
     before any release.
5. **Release gates.** The full pre-tag pipeline (lint, static analysis,
   unit + multisite suites, plugin check, E2E on single-site and multisite)
   must pass; dashboards need no code change for added options — after the
   Hive release, reload the schema in the MainWP extension ("Schema neu
   laden") and in the fleet dashboard ("Reload schema"), which also
   re-validates stored policies and overrides.
6. **Verify in production the safe way:** push a no-op policy (the exact
   current values) to one owned site first — every key must come back
   `unchanged` before the change is trusted fleet-wide.
