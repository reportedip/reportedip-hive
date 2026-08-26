# Remote Settings Protocol

Fixed contract for managing ReportedIP Hive settings from a central dashboard.
Every management transport speaks this protocol against the same three core
classes, so behaviour is identical no matter who is asking:

| Transport | Status | Entry point |
|---|---|---|
| MainWP (`mainwp_child_extra_execution` / `mainwp_site_sync_others_data`) | live | `includes/class-mainwp-integration.php` |
| reportedip.com management API (`reportedip-hive/v1/remote/settings/*`) | planned | same core classes, REST wrapper |

Core classes (all loaded unconditionally, in every request context):

- `ReportedIP_Hive_Settings_Registry` — the declarative option registry:
  kinds, ranges, allowed values, tier gates, side effects, schema export,
  the settings fingerprint.
- `ReportedIP_Hive_Settings_Apply` — validates and writes a batch, returns a
  per-key result map. Call `ReportedIP_Hive_Settings_Apply::apply( $values, $origin )`.
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
