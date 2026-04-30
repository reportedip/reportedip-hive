# Changelog

All changes to ReportedIP Hive are documented here.

## [1.6.1] — 2026-04-30

### New

- **Post-upgrade 2FA setup banner.** When a customer's plan crosses
  from Free / Contributor into Professional / Business / Enterprise,
  a dismissable welcome banner with a three-step checklist now
  appears on every Hive admin page until the customer either
  finishes 2FA setup or dismisses it. The plugin auto-prefills the
  Managed SMS Relay as the SMS provider (only when no provider is
  configured yet) and adds the email method to the site-wide allow
  list — the SMS method toggle and the AVV confirmation remain
  untouched so the consent gesture stays explicit.
- **Login-time 2FA reminder for end users.** New
  `ReportedIP_Hive_Two_Factor_Recommend` listener counts how often
  each user signs in without a configured 2FA method and renders a
  soft reminder banner across the WordPress admin. After the
  configurable threshold (default 5) administrators, editors and
  shop managers are forced into the existing onboarding wizard
  before they can continue; customers, subscribers and other
  non-privileged roles only ever see the soft banner so a missing
  phone never locks anyone out of WooCommerce. A new
  `reportedip_hive_2fa_method_enabled` action fires whenever any
  method goes live and resets the counter; full unit coverage in
  `tests/Unit/TwoFactorRecommendTest.php`.
- New `ReportedIP_Hive_Tier_Upgrade` listener wires the existing
  `reportedip_hive_tier_changed` action to the soft-activation /
  notice lifecycle, with full unit-test coverage.

### Changed

- **AVV / DPA checkbox on the 2FA tab adapts to the active SMS
  provider.** When `reportedip_relay` is selected, the label reads
  *"I have accepted the ReportedIP AVV (signed with my plan
  subscription)"* and is auto-checked because the AVV is part of
  the plan subscription. For self-hosted providers (Sipgate,
  MessageBird, sevenio) the original *"I confirm that a DPA …"*
  wording is preserved. The privacy hard gate behaviour is
  unchanged: no SMS is dispatched until the flag is true.
- The "Managed SMS relay active" info box on the 2FA tab gains a
  final-step hint when the SMS method is not yet in the site's
  allow list, pointing the operator to the methods list above.
- Saving `reportedip_relay` as the active SMS provider now
  automatically sets `OPT_AVV_CONFIRMED` (when the relay is
  available for the current tier), so the click-through path
  works without the banner.
- 2FA settings tab gains a "Login reminder" section to toggle the
  end-user reminder, set the hard-block threshold (1–10) and pick
  which roles get hard-blocked at the threshold.
- Setup wizard's 2FA step now mentions the login-reminder
  behaviour so the site operator knows what end users will see
  after activation.

## [1.6.0] — 2026-04-30

### New

- **Tier-aware UI foundation across admin pages.** Every plugin page
  now renders a tier badge next to the existing operation-mode badge
  in the branded header (Free / Contributor / Professional / Business /
  Enterprise), and PRO+ tiers gain a managed-relay quota panel on the
  Security Dashboard with mail and SMS counters, progress bars and
  reset hints. The setup wizard's first step now reuses the same
  Local-vs-Community comparison cards as the Settings page, so the
  value proposition is consistent end-to-end. The SMS-provider
  selector marks the "ReportedIP SMS Relay" entry as PRO+ when the
  current tier is too low, with a deep link to the pricing page.
  Marketing copy that mentioned third-party SMS providers by name has
  been replaced with neutral "managed via reportedip.de" wording.

### Changed

- New `Mode_Manager::feature_status( string $feature ): array` helper
  returns a structured `{available, reason, min_tier, mode_required,
  label, description}` payload — the canonical way to check whether a
  feature is gated by mode or tier and the only contract any future
  tier-gated control needs to hook into.
- New `Mode_Manager::get_tier_info()` and `get_relay_quota_snapshot()`
  expose tier display tokens (label, badge class, icon, color) and a
  normalized monthly relay quota snapshot (mail/sms used/limit, SMS
  bundle balance, period bounds, stale flag) for dashboard rendering.
- API key validation now fires the new
  `do_action( 'reportedip_hive_tier_changed', $old, $new )` hook when
  the upstream `userRole` flips between tiers, and clears the cached
  relay quota so consumers (mailer, SMS, dashboard) re-fetch.
- New reusable static helpers on `Admin_Settings`:
  `render_header_actions()`, `render_mode_badge()`,
  `render_tier_badge()`, `render_tier_lock()`,
  `render_mode_comparison()`. The Settings General tab and the wizard
  both render the mode comparison through the same helper, so layout
  drift between the two surfaces can no longer happen.
- New CSS components in the design system: `.rip-tier-badge` with five
  tier variants plus `--honeypot`, `.rip-tier-lock` chip for upgrade
  affordances and `.rip-stat-card--quota` with progress-bar and stale
  hint slots. All new visuals respect the existing `--rip-*` tokens —
  no hardcoded colors.

### Fixes

- **API queue rows no longer get stuck "pending" for 24+ hours.** A worker
  that crashed during the HTTP call (PHP fatal, OOM, request timeout) used
  to leave its row in `processing` forever — invisible to every later cron
  run, never cleaned up, and counted by the cooldown check, which silently
  suppressed every further report for that IP for 24 h. The queue cron
  now runs a recovery sweep on every invocation that resets stuck rows
  back to `pending` (or graduates them to `failed` once retries are
  exhausted), and the cooldown check no longer treats `pending` or
  `processing` rows as "recently reported".
- **In-flight rows are protected from the recovery sweep** by a new
  `submitted_at` timestamp set immediately before the HTTP call. Only
  rows whose `submitted_at` is older than the configured timeout
  (`reportedip_hive_processing_timeout_minutes`, default 10 minutes) are
  considered crashed and reset.
- **A failure on one queue row no longer aborts the entire batch.** Every
  per-row send is now wrapped in `try { … } catch ( \Throwable )`; on
  exception the offending row is marked `failed` and processing
  continues with the next row.
- **Concurrent queue runs are serialised.** A 5-minute transient lock
  (`reportedip_hive_queue_lock`) prevents WP-Cron, an external cron and
  manual admin triggers from racing the recovery sweep against each
  other on the same row.
- **Failed rows are deduplicated for 15 minutes** at insert time, so a
  transient API failure no longer immediately re-queues a duplicate
  report when the IP triggers again seconds later.

### Changed

- New `submitted_at datetime` column on `wp_reportedip_hive_api_queue`
  (schema v4, migrated automatically via `dbDelta`).
- Queue cron now logs structured "skipped: api not usable" when
  `process_report_queue()` exits because Community mode is off or the
  API key is unset, instead of returning silently.
- New option `reportedip_hive_processing_timeout_minutes` (default 10)
  controls the recovery-sweep window.

## [1.5.2] — 2026-04-28

### Fixes

- **Cache plugins no longer cache the "Access Denied" 403 page.** The
  blocked-page response now defines `DONOTCACHEPAGE`, `DONOTCACHEDB`
  and `DONOTCACHEOBJECT` (respected by WP Rocket, W3 Total Cache,
  WP Super Cache and LiteSpeed Cache) and emits explicit
  `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`,
  `Pragma: no-cache` plus the WordPress core `nocache_headers()`
  set. Previously a single blocked attacker could pollute the page
  cache with a 403 that legitimate visitors then received until the
  cache expired.
- **Front-end IP-block runs at `init` priority 1** instead of the
  default priority 10. Earlier hook position so plugins that
  themselves hook `init` at default priority do not run for blocked
  IPs.
- **2FA per-IP throttle graduates to a real escalation block.** The
  in-class `LOCKOUT_THRESHOLDS` ladder (3 → 30 s, 5 → 300 s,
  10 → 1800 s, 15 → 3600 s) was capping at one hour and the
  `HOUR_IN_SECONDS` transient simply forgot, so a brute-forcer who
  paced themselves around the hour was never promoted to the
  `wp_reportedip_hive_blocked` table. When the count reaches the
  top step, the IP is now graduated via the central
  `auto_block_ip()` path with event type `2fa_brute_force` — that
  trips progressive escalation (5 m → 15 m → 30 m → 24 h → 48 h →
  7 d) and community-mode reporting just like every other sensor.

### Changed

- New static helper `ReportedIP_Hive::emit_block_response_headers()`
  centralises the cache-prevention contract so it can be exercised
  by tests without invoking the page-rendering path that ends in
  `exit`.

## [1.5.1] — 2026-04-28

### Changed

- **Blocking-tab clarity.** The Blocking settings page and the
  wizard's Protection step now spell out the three-level chain:
  Report-only mode wins over everything; Auto-blocking is the
  master switch that decides *whether* a block happens; the
  duration strategy (fixed length vs. progressive ladder) is the
  follow-up choice that decides *how long*. The duration strategy
  is now a labelled subsection with a required marker and is
  visually disabled while Auto-blocking is off, so users cannot
  configure a duration that will never apply. The fixed-length and
  ladder editors swap inline depending on the toggle, removing the
  earlier ambiguity of seeing both sets of inputs at once.

## [1.5.0] — 2026-04-28

### Fixes

- **Cookie-banner endpoints no longer get visitors blocked.** The
  REST monitor counted every anonymous request to consent endpoints
  toward the global rate-limit; high-traffic sites tripped the
  threshold and started returning the "Access Denied" page for the
  consent POST itself, locking visitors into a banner loop. The
  default bypass list now ships with the four common consent
  namespaces — `/real-cookie-banner/v1`, `/complianz/v1`,
  `/borlabs-cookie/v1`, `/cookie-law-info/v1`. Custom consent stacks
  can extend the list via the existing
  `reportedip_hive_rest_bypass_routes` filter.
- **404 + comment-spam defaults relaxed.** `scan_404_threshold` was
  8 in 1 minute — too tight for sites with broken theme links or
  chatty bots. Bumped to 12 in 2 minutes. `comment_spam_threshold`
  was 3 in 60 minutes — bumped to 5. Existing installs are not
  touched (`add_option` only seeds when missing); new sites get the
  saner defaults out of the box.

### New

- **Progressive block escalation.** A new
  `ReportedIP_Hive_Block_Escalation` class derives the next block
  duration from how many times the IP has been blocked inside the
  configurable reset window. Default ladder: **5 min → 15 min →
  30 min → 24 h → 48 h → 7 d** (cap). After 30 days clean the IP
  starts at step 1 again. First-time tripping legitimate visitors
  (CGNAT, fat-fingered admins, HSDPA carriers) recover in minutes;
  repeat offenders pay the full 7-day price. The fixed
  `block_duration` setting still applies when the ladder is toggled
  off.
- **Settings UI** for the new ladder under **Settings → Blocking →
  Progressive blocking**: enable toggle, comma-separated minute
  ladder editor, reset-window in days. The wizard's Protection step
  also exposes the master toggle so fresh installs are escalation-
  aware from the first save.
- **`block_ip_for_minutes()`** on the database class — sub-hour
  block granularity required by the new ladder. The original
  `block_ip( …, $duration_hours )` API is unchanged.

### Changed

- **`is_route_bypassed()`** on the REST monitor now ships four
  additional consent-banner namespaces in its default bypass set
  (see Fixes above).

## [1.4.0] — 2026-04-28

### Fixes

- **Setup wizard now saves every protection toggle.** Step 3 silently
  dropped five advanced sensors (`monitor_app_passwords`,
  `monitor_rest_api`, `block_user_enumeration`, `monitor_404_scans`,
  `monitor_geo_anomaly`) — they appeared on by default but persisted
  as `0` on every wizard run because the JS step persistence only
  covered five of nine keys. All nine toggles now round-trip correctly
  through sessionStorage and the final AJAX save.

### New

- **Calmer protection step.** Step 3 of the setup wizard splits its
  monitoring toggles into three themed cards — **Authentication**,
  **Content & API abuse**, **Behaviour & scanning** — each with a
  one-line intro. Same options, much lighter cognitive load.
- **Pre-filled 2FA step.** The wizard now reads existing
  `reportedip_hive_2fa_allowed_methods`, `reportedip_hive_2fa_enforce_roles`
  and the convenience toggles, so returning users see their previous
  picks instead of the hard-coded defaults. Picking at least one role
  is required — Administrator stays the safe default and the AJAX
  handler refuses to persist an empty enforce-roles list when 2FA is
  on.
- **Provider-setup-required tag** on the SMS 2FA card. As soon as a
  user picks SMS, an amber tag inside the card spells out that the
  provider still has to be configured in **Settings → Two-Factor**
  after the wizard finishes.
- **"Below content" auto-footer placement.** The Promote tab and the
  wizard's Promote step now offer a fourth alignment option that
  renders the badge as a full-width row directly below the theme
  footer. Implementation hooks `wp_footer` priority 99999 with
  `visibility:hidden`, then relocates the wrapper to `document.body`
  via a tiny inline script — deterministic across classic and block
  themes, escapes any `overflow:hidden` or flex parent.
- **Featured shortcode discoverability.** The Promote tab gains a
  highlighted callout for `[reportedip_stat type="api_reports_30d"
  tone="contributor"]` and a fifth showcase entry for the new
  `[reportedip_stat type="logins_30d" tone="trust"]` login-activity
  counter. The wizard's Promote step links back to the same gallery.
- **Tasteful Setup-complete celebration.** The final wizard step now
  pulses a soft halo behind the success check, scale-bounces the
  checkmark once and fades the summary cards in with a stagger. All
  animations are gated behind a JS-applied `.rip-wizard__complete--play`
  class and wrapped in `prefers-reduced-motion`.
- **Centralised wizard defaults.** New `ReportedIP_Hive_Defaults` class
  exposes `wizard()` (form fallbacks) and `safe_options()` (post-
  wizard option seed). The wizard JS reads its defaults via
  `wp_localize_script`; `apply_safe_defaults()` consumes the same
  values. Single source of truth, no behavioural change.

### Changed

- **Hide-Login step layout.** Replaced inline `display:flex`/`<pre>`
  styles with a new `.rip-input-group` (label → URL prefix → slug
  field) and `.rip-codeblock` BEM classes. Toggling Hide-Login off
  now visibly disables the slug field (opacity + pointer-events)
  instead of vanishing it.
- **Promote step alignment radios** match the settings-page parity:
  Left, Center, Right and "Below content" with a live preview.
- **Step indicator labels shortened** to `Connect` (was "Mode & API")
  and `Login` (was "Login URL") so they stay on a single line at every
  breakpoint, with `white-space: nowrap` as a safety net.
- **Wizard navigation buttons clarified.** Step 6 ("Login") now reads
  *Save & continue* and routes to the Promote step; step 7 ("Promote")
  reads *Save & finish* and lands on the Done celebration.

## [1.3.0] — 2026-04-28

### New

- **Frontend banner shortcodes** — four new public shortcodes
  (`[reportedip_badge]`, `[reportedip_stat]`, `[reportedip_banner]`,
  `[reportedip_shield]`) render community-trust banners on any post,
  page, widget or theme template, each linking back to reportedip.de
  with UTM tracking. The banners ship as a `<rip-hive-banner>` Web
  Component with a Shadow Root, so themes cannot override their styling
  — but the underlying `<a href>` stays in the light DOM, keeping the
  link crawlable for search engines and visible without JavaScript.
- **Lifetime stat types** — `attacks_total` and `reports_total` source
  their numbers from the daily `stats` table (which is never pruned),
  giving sites a stable, ever-growing community-impact number to show.
  Other supported types: `attacks_30d`, `api_reports_30d`,
  `blocked_active`, `whitelist_active`, `logins_30d`, `spam_30d`.
- **Marketing-tone presets** — `tone="protect|trust|community|contributor"`
  swap the banner headline between "Protected by ReportedIP Hive",
  "Secured by ReportedIP Hive", "Part of the ReportedIP Hive" and
  "ReportedIP Contributor". All wording is fully translatable through
  the standard WordPress text domain pipeline.
- **Custom-theme attributes** — `bg=`, `color=`, `border=`, `intro=`,
  `label=` and `live=` let site owners match the banner to their brand
  without breaking the Shadow-DOM isolation. Hex colours and gradients
  are strictly regex-validated; free-text overrides are tag-stripped
  and length-clamped to prevent injection.
- **Count-up animation + live indicator** — when a banner enters the
  viewport the headline number animates up from zero with an ease-out
  cubic curve, and a subtle pulsing dot signals "live protection".
  Both effects honour the user's `prefers-reduced-motion` preference.
- **"Promote" sub-tab** in **Community & Quota** — new tab with an
  opt-in **auto-footer badge** (variant and position picker — left,
  center, right), showcase cards for every variant, an attribute
  reference, and a full **interactive banner builder** that updates
  the preview and generated shortcode live as you change controls.
- **Setup-wizard step** — new penultimate step that explains the
  auto-footer badge, shows a live preview and lets the admin enable
  it with a single click during onboarding.

### Changed

- Default plugin options gained `reportedip_hive_auto_footer_enabled`,
  `reportedip_hive_auto_footer_variant` and
  `reportedip_hive_auto_footer_align`. All ship `false` / `badge` /
  `center` — existing installs see no behavioural change until an
  admin opts in via the new Promote tab.

### Notes

- All public-facing strings are in English and translatable; banner
  copy is privacy-safe (only aggregated counts — no IPs, usernames or
  timestamps).
- The frontend script is only enqueued when a shortcode is detected in
  the current post or the auto-footer is enabled, keeping pages that
  don't use the feature free of any extra JS.

## [1.2.4] — 2026-04-27

### Fixes

- **"Retry" button on the API queue admin appeared to do nothing for
  pending items** — the AJAX handler called `reset_report_for_retry()`
  (sets `status=pending, attempts=0`) and reported success without
  actually sending anything. For items that were already pending this
  was a no-op; the page reloaded, the row stayed pending, and the
  admin had to wait up to 15 minutes for the cron tick. The handler
  now performs the API call synchronously after the reset and reports
  the actual outcome — `Report sent.` on success, or
  `Send failed: <api message>` on a real error.

- **"Retry All Failed" likewise didn't drain inline** — same shape:
  reset the rows, return success, wait for cron. Now the handler
  calls `process_report_queue( 50 )` synchronously and the success
  toast carries the real numbers (`X failed reset · Y sent · Z errors`).

## [1.2.3] — 2026-04-27

### Fixes

- **Cron still couldn't drain the queue on unlimited tiers** — 1.2.1
  fixed `has_report_quota()` for the `-1`-means-unlimited case but
  missed a second copy of the same logic inside
  `process_report_queue()`. The pre-loop cap `min( $limit, $remaining )`
  collapsed to `-1` for unlimited accounts and tripped the
  `<= 0 → 'no_quota'` short-circuit before the loop could even start.
  Cron returned skipped, items stayed pending, customer queue grew.
  The cap now only applies when `$remaining >= 0`, matching the fix
  shape in `has_report_quota()`. Verified live: a direct `report_ip()`
  call already worked on the affected install — only the queue
  processor was blocked.

## [1.2.2] — 2026-04-27

### Fixes

- **REST monitor locked admins out of their own backend** — the global
  `rest_pre_dispatch` rate-limit fired against authenticated traffic too,
  and the WordPress Block Editor alone makes 50+ REST calls when an
  admin opens a single page (autosave, media library, taxonomy / user
  lookups, block patterns, theme.json). With the default 60-in-5-min
  threshold this tripped near-instantly. The gate now skips the count
  entirely when `is_user_logged_in()` — authenticated REST traffic is
  not the threat model this sensor exists for. Default global threshold
  also bumped from 60 to 240 to give anonymous block-theme frontends and
  WooCommerce storefronts more headroom; the lower per-route threshold
  for sensitive endpoints (`/wp/v2/users`, `/wp/v2/comments`) is
  unchanged at 20 / 5 min.

- **404 / scanner detector burst-trigger covered legit admin 404s** —
  missing CSS source maps, deprecated plugin asset URLs after an update
  and admin-side searches that hit `template_redirect` could rack up
  enough 404s in the 60-second burst window to fire the threshold.
  The burst trigger is now skipped for logged-in users; **pattern
  hits** on known-bad paths (`/.env`, `/wp-config.php.bak`,
  `/.git/config`, `/phpmyadmin/`, `/.aws/credentials`, …) stay armed
  for everyone, including admins — those paths have no legitimate use
  in any browser.

- A separate-process unit test (`RestMonitorExemptionTest`) locks down
  the logged-in exemption so future changes can't silently regress it.

## [1.2.1] — 2026-04-27

### Fixes

- **API queue stuck for unlimited-tier accounts** — `has_report_quota()`
  rejected accounts whose service-side response carries
  `daily_report_limit = -1` and `remaining_reports = -1` (Enterprise /
  Honeypot tiers, no daily cap). The `<= 0` short-circuit fired before
  the "is there even a limit" check, so the gate never opened and pending
  reports piled up until 24 h cleanup. The check now mirrors the logic
  in `get_quota_status()`: only treat the count as exhausted when the
  account has a *positive* daily limit and zero remaining; `-1` means
  unlimited. Locked down with a new `QuotaGateTest` suite covering all
  four tier shapes (unlimited / exhausted-finite / remaining-finite /
  zero-permission) plus the cold-start "no cached quota yet" case.

## [1.2.0] — 2026-04-27

### New

- **Seven new attack sensors** that extend the threat coverage from the
  existing failed-login / comment-spam / XMLRPC trio to the WordPress
  surface that iThemes Security Pro covers via its modular architecture:
  - **Application Password Abuse** — rate-limits failed application-password
    Basic-Auth attempts on REST and XMLRPC, blocks app-password creation
    for users in 2FA-enforced roles until they have completed enrolment,
    and audit-logs every successful app-password authentication.
    Hooks: `application_password_failed_authentication`,
    `application_password_did_authenticate`,
    `wp_is_application_passwords_available_for_user`.
  - **REST API Abuse** — global rate-limit on `rest_pre_dispatch` with a
    separate, lower threshold for sensitive routes (`/wp/v2/users`,
    `/wp/v2/comments`). Whitelist for the plugin's own 2FA endpoints and
    the oEmbed discovery endpoint; remaining bypasses configurable via the
    `reportedip_hive_rest_bypass_routes` filter.
  - **User Enumeration Defence** — closes the four classic username-leak
    vectors: `?author=<n>` redirects (now answered with 404), the
    `/wp-json/wp/v2/users` endpoint family for unauthenticated callers,
    `author_name` / `author_url` in oEmbed responses, and the verbose
    `invalid_username` / `incorrect_password` login error codes (unified
    to a single generic `invalid_credentials`). Repeated probes accumulate
    in a counter and trip the standard auto-block.
  - **404 Scanner Detection** — pattern-based instant trigger for known
    vulnerability paths (`/.env`, `/wp-config.php.bak`,
    `/wp-content/debug.log`, `/.git/config`, `phpmyadmin`, …) plus a rate
    threshold for high 404 burst rates. Path lists are filterable via
    `reportedip_hive_scan_paths` / `reportedip_hive_scan_prefixes` so
    operators can add their own honeypot URLs.
  - **Password Spray Detection** — distinct-username variant of the
    failed-login counter. Fires when a single IP probes ≥ N different
    usernames within a short window, which is a stronger
    credential-stuffing signal than the classic per-IP attempt count.
    Usernames are stored hashed (SHA-256 + `wp_salt()`) in a transient,
    never in plaintext.
  - **WooCommerce Login Hook** — feeds WC's dedicated
    `woocommerce_login_failed` and `woocommerce_checkout_login_form_failed_login`
    hooks into the same lockout / threshold pipeline, covering checkout
    AJAX login attempts that bypass the standard `wp_login_failed` hook.
  - **Geographic Anomaly Detection** — passive observation: when a
    successful login arrives from a country / ASN never seen before for
    that user (90-day rolling window, 12-entry per-user history capped),
    the event is logged and the user's trusted-device cookies are revoked
    so the next login forces a fresh 2FA challenge. Country/ASN come from
    the cached reputation lookup the plugin already does — no extra
    external call.
- **Centralised category mapping** — the legacy ad-hoc category IDs
  scattered across the codebase are now consolidated in
  `ReportedIP_Hive_Security_Monitor::get_category_ids_for_event()`,
  publicly accessible and overridable via the
  `reportedip_hive_event_category_map` filter. The new sensors map onto
  the WordPress-specific service taxonomy (`WP User Enumeration`,
  `WP REST API Abuse`, `WP Login Brute Force`, `WP Plugin Scanning`,
  `WP Version Scanning`, `WP Config Exposure`); legacy events keep their
  original IDs so existing 1.x deployments see no behavioural change.
- **Password Strength enforcement** — minimum length / character-class
  diversity check plus an optional HaveIBeenPwned k-anonymity range
  lookup (only the first 5 SHA-1 hex characters leave the server). Runs
  on `user_profile_update_errors` and `validate_password_reset` for users
  in the `reportedip_hive_2fa_enforce_roles` list.

- **Hide Login** — optional feature that moves `wp-login.php` behind a
  custom slug (e.g. `/welcome`) so automated scanners can no longer find a
  login form to brute-force. Direct hits on the original URL are answered
  with the existing Hive block page (HTTP 403, same look as the IP-block
  page) or, optionally, with the theme's 404 template for deeper recon
  hardening. The feature is available as:
  - a new **Settings → Hide Login** tab, with live slug validation,
    reserved-slug rejection (`wp-admin`, `login`, `wp-json`, etc.) and
    permalink-collision detection against existing pages, posts, terms and
    author archives;
  - a new optional step in the setup wizard ("Login URL"), which only
    enables the feature if the user explicitly opts in;
  - a `wp-config.php` recovery constant
    `define( 'REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN', true );` that disables
    the feature in case the slug is ever lost.

  REST, cron, AJAX (logged-in), CLI, XMLRPC, password-reset links and the
  re-auth interim-login dialog are bypassed automatically so existing
  workflows (Block Editor, Application Passwords, Jetpack SSO, password
  recovery emails) keep working. All login-URL generators (`login_url`,
  `site_url`, `network_site_url`, `admin_url`, `lostpassword_url`,
  `register_url`, `logout_url`, `wp_redirect`) are filtered to point at
  the new slug. The bundled block page is now context-aware so the same
  template renders both IP-block and login-block screens.

  This is security through obscurity, not a substitute for strong
  passwords or 2FA — the UI surfaces that explicitly.

### Changed

- **Database schema v3** — `reportedip_hive_attempts.attempt_type` widened
  from a fixed `ENUM('login','comment','xmlrpc','admin')` to
  `VARCHAR(32)` so new sensor-types (`app_password`, `rest_abuse`,
  `user_enumeration`, `scan_404`, `wc_login`) share the same counter
  table. Migration is automatic and idempotent — runs once on the next
  admin page load via `maybe_update_schema()`.

## [1.1.4] — 2026-04-27

### Fixes

- **Dashboard "Events (24h)" stuck at 0 / charts empty** — the count and
  chart aggregation queries used `DATE_SUB(NOW(), INTERVAL …)` against
  `created_at` values stored via `CURRENT_TIMESTAMP`. On hosts where the
  MySQL session timezone drifted from the storage timezone (commonly
  `time_zone = SYSTEM` with a shifted OS clock) the comparison produced
  zero rows even though logs were freshly written. The 24h count and the
  chart fallback now use a PHP-computed UTC cutoff `OR`'d with the
  MySQL relative cutoff, so the window stays correct regardless of
  session-timezone drift.
- **"Recent Activity" widget only showed `Blocked By Reputation`** — the
  widget called `get_recent_critical_events()` which filters
  `severity IN ('high', 'critical')`. Failed logins (medium), successful
  logins (medium) and info events were silently excluded despite the UI
  label saying "Recent Activity". A new `get_recent_events()` query
  returns the full event stream; the dashboard now uses it.
- **Threat Distribution donut "XMLRPC Abuse" and "Admin Scanning" always
  zero** — these two slices were hardcoded to `0` in `get_chart_data()`.
  Both are now aggregated from `event_type LIKE '%xmlrpc%'`,
  `'%admin_scan%'` and `'%wp_admin%'` so the donut reflects reality.
- **Charts read from a sparse rollup table** — `reportedip_hive_stats`
  is only incremented on threshold breaches and auto-blocks (see
  `class-security-monitor.php::handle_threshold_exceeded()`), which left
  it empty or all-zero for most installs and made the Security Events
  line chart appear flat. `get_chart_data()` now queries
  `reportedip_hive_logs` directly with `event_type LIKE` aggregation so
  every logged event contributes to the chart.

### Hardened

- **2FA onboarding wizard CSS** (`assets/css/wizard.css`,
  `assets/css/two-factor.css`) — the standalone wizard at
  `?page=reportedip-hive-2fa-onboarding` rendered all five steps at once
  whenever a theme or admin-skin plugin overrode the browser default
  `[hidden] { display: none }`. Locked the body chrome
  (`body.rip-wizard-page`) — font, size, line-height, margin, background
  — with `!important`, forced font inheritance on headings, paragraphs,
  links, lists and form elements, locked `code/pre/kbd/samp` to a
  monospace fallback, and pinned `[hidden]` to `display: none !important`
  for the wizard, the step content panels and the wp-login 2FA challenge
  panels. The same lock-down covers the setup wizard.

## [1.1.3] — 2026-04-27

**Real fix for the settings-page persistence bug**

`update_option()` in WordPress 5.5+ has a long-known footgun: when the
stored option value happens to equal the value registered as the
`'default'` in `register_setting()`, the function reroutes to
`add_option()`, which returns `false` and silently does nothing because
the row already exists. The previous "1.1.2" hidden-input fallback fix
was on the right track but did not address this deeper layer — saves
still failed for `2fa_enforce_roles` (default `'[]'`), every boolean
toggle (default `false`/`true`), and several other fields whose stored
value happened to match their registered default.

Reproduced end-to-end inside the dev container:

    $value = sanitize_option('reportedip_hive_2fa_enforce_roles', ['administrator']);
    // = '["administrator"]', correct
    update_option('reportedip_hive_2fa_enforce_roles', ['administrator']);
    // = false (silently fails)

### Fixes

- **Removed every `'default' => …'` argument from `register_setting()`** in
  both `class-admin-settings.php` (≈30 settings across all six tabs) and
  `class-two-factor-admin.php` (15 settings on the 2FA tab). Defaults are
  supplied at every read site via `get_option( $key, $fallback )` —
  identical effective behaviour, but `update_option()` no longer trips
  the default-equals-old short-circuit.
- All affected toggles now persist on un-check, including the originally
  reported "Enforcement → 2FA required for roles" with only Administrator
  selected. Verified via a scripted full WP bootstrap inside the dev
  container that exercises the real `wp-admin/options.php` save path.

---

## [1.1.2] — 2026-04-27

**Settings persistence fixes after the topic-based settings refactor**

Several toggles on the new settings tabs silently kept their old value when
the user un-checked them, because WordPress' `options.php` only invokes a
sanitize callback for fields actually present in `$_POST`. Same root cause
on the 2FA tab made it impossible to save an empty "required for roles" set,
or to switch off any of the verification methods.

### Fixes

- **Hidden-input fallbacks** added to every checkbox / multi-select on the 2FA tab
  (`enabled_global`, `allowed_methods`, `enforce_roles[]`, `frontend_onboarding`,
  `notify_new_device`, `xmlrpc_app_password_only`, `trusted_devices`,
  `extended_remember`, `branded_login`, `sms_avv_confirmed`) and on the
  Detection / Blocking / Notifications / Privacy & Logs / Performance tabs.
  Unchecking now persists. Verified: clearing all enforced roles writes `[]`,
  clearing all 2FA methods falls back to TOTP-only (deliberate — never leave
  users without a working method).
- **2FA "required for roles" actually saves now** — the previous build silently
  reverted to the old value when at least one role was un-ticked.
- **Wizard ↔ Settings parity audit** — confirmed all 26 option keys the setup
  wizard writes are also registered on a settings tab. No drift.

### New

- **"Add my IP" button** under the 2FA → IP allowlist textarea. One click
  appends the admin's current detected IP (`REPORTEDIP_HIVE::get_client_ip()`)
  to the allowlist, with duplicate-line guard.

### Docs

- **CLAUDE.md** got a dedicated "CI / GIT test workflow" section documenting
  every job in `ci.yml` / `release.yml`, the pre-push checklist, and the
  post-push verification commands.

---

## [1.1.1] — 2026-04-27

**Security hardening + first public release**

This is the first public GitHub release. All changes accumulated since 1.0.1
ship as 1.1.1, plus a focused security pass on the 2FA REST surface and the
admin JavaScript layer.

### Security

- **2FA REST `/2fa/verify` brute-force protection** — added a per-token failed-attempt counter (max 5 fails → token invalidated) and a per-IP rate limit (30 requests / 5 min). Without this, the 5-minute token TTL allowed unbounded TOTP guessing against the 6-digit code space.
- **2FA REST `/2fa/challenge` defense-in-depth throttle** — per-IP rate limit (20 requests / 5 min) before `wp_authenticate()`, in addition to the existing IP-block hooks.
- **Admin JS XSS hardening** — added a shared `escapeHtml()` helper in `admin.js` and `two-factor-admin.js`; all dynamic strings (AJAX response data proxied from the remote community API, recovery codes, IP-lookup result fields, TOTP manual key) are now HTML-escaped before insertion via `.html()` / template literals. The local helper in `settings-import-export.js` now also escapes single quotes.
- **2FA onboarding error path** — replaced `innerHTML` interpolation with safe DOM API (`textContent` + `appendChild`) for the recovery-codes failure message.

### Fixes

- **`SHOW TABLES` query in `ajax_test_database`** — switched to `$wpdb->prepare()` for WordPress coding standards compliance.
- **Localised previously German strings** in the 2FA admin script (`Kopieren` / `Herunterladen` / "Diese Codes …") via `wp_localize_script` so they participate in the `reportedip-hive` text domain.

### Changed

- Author/contact email rotated from `1@reportedip.de` to `ps@cms-admins.de` across all file headers, `composer.json`, `REPORTEDIP_HIVE_CONTACT_MAIL`, and the readme contact links.
- `release.yml` now copies `composer.lock` unconditionally — a missing lock file fails the build hard instead of silently shipping an unlocked vendor tree.

---

## [1.1.0] — bundled into 1.1.1 (never tagged separately)

**Settings area refactor + JSON import/export**

The settings page is now organised by **topic** instead of by registration group. Seven tabs (General · Detection · Blocking · Notifications · Privacy & Logs · Performance & Tools · Two-Factor) replace the previous three-tab layout, each with plain-language labels and inline guidance written for non-developers. Every option key, default value and sanitiser is byte-identical to 1.0.1 — a new snapshot test (`SettingsKeysAreStableTest`) guards against silent renames.

A new **Settings Import / Export** panel inside the Performance & Tools tab lets administrators download a JSON snapshot and reapply it on another site. The setup wizard's welcome step has a matching shortcut so agencies onboarding a fresh install can skip directly to Step 6 with their preferred configuration already in place.

### New

- **`ReportedIP_Hive_Settings_Import_Export` (singleton, `admin/class-settings-import-export.php`)** — central export/preview/apply pipeline. Eight named sections (General, Detection, Blocking, Notifications, Privacy & Logs, Performance, Two-Factor global, IP lists) plus an opt-in `include_secrets` toggle for the API key and encrypted SMS-provider config. Per-user 2FA secrets (TOTP, WebAuthn, SMS number) are excluded by design.
- **JSON envelope schema v1** — `_meta.plugin`, `_meta.schema_version`, `_meta.includes_secrets` plus `options` and `ip_lists`. Preview shows a per-section diff before anything is written; apply rejects keys not on the allowlist (defence in depth).
- **Wizard import shortcut** — Welcome step has an `Already have an export file?` link that uploads JSON, runs the same `apply_payload()` pipeline, marks the wizard complete and jumps to Step 6.
- **Snapshot test `tests/Unit/SettingsKeysAreStableTest.php`** — parses every `register_setting()` call across `class-admin-settings.php` and `class-two-factor-admin.php` and compares against a frozen list. A removed/renamed key fails the build.
- **Import/export tests `tests/Unit/SettingsImportExportTest.php`** — section catalogue, allowlist, secret opt-in, foreign-key rejection, section-scoped apply.
- **Logging profile radio (Privacy & Logs tab)** — single Minimal · Standard · Detailed control writes the underlying `minimal_logging` + `detailed_logging` toggles. Easier to reason about than two interacting checkboxes.
- **Plain-language labels** — e.g. "Watch failed logins" instead of "Enable Failed Login Monitoring", "How long an IP stays blocked" instead of "Block Duration (Hours)". XML-RPC, reputation score, negative cache and trusted-IP-header all carry an inline explanation.
- **`REPORTEDIP_MAX_SETTINGS_UPLOAD_SIZE` (512 KiB)** — upload-size cap for the JSON import.

### Changed

- **`reportedip_hive_protection`** settings group split into three sub-groups so each tab can submit atomically without WordPress wiping the others: `reportedip_hive_protection_detection`, `reportedip_hive_protection_blocking`, `reportedip_hive_protection_notifications`.
- **`reportedip_hive_advanced`** settings group split into `reportedip_hive_advanced_privacy` (Privacy & Logs tab) and `reportedip_hive_advanced_performance` (Performance tab) for the same reason.
- **`blocked_page_contact_url` and `report_cooldown_hours`** now have UI fields. They were registered in 1.0.1 but had no rendered control — defaults applied silently.
- **Old tab slugs (`api`, `security`, `actions`, `protection`, `logging`, `caching`, `advanced`)** are aliased to their new home so external links keep working.
- **Settings page header subtitle** now says "Configure how ReportedIP Hive protects your site — grouped by topic so you can find what you need quickly."

### Removed

- **`render_security_tab()`, `render_actions_tab()`, `render_logging_tab()`, `render_caching_tab()`** in `class-admin-settings.php` — ~580 lines of legacy private helpers replaced by the five new topic-driven render methods.

### Migration notes

- No data migration required. All option keys, defaults and sanitisers stay byte-identical.
- Sites that POST directly to the legacy `reportedip_hive_protection` or `reportedip_hive_advanced` settings groups (programmatic integrations, REST `/wp/v2/settings`) need to use the new sub-group names.

## [1.1.0] — 2026-04-26

**Mail unification: single template + central mailer class**

All four emails the plugin can send (2FA code, new-device login, admin security alert, 2FA reset) now flow through a central dispatcher and share the same brand layout (Indigo gradient header, logo, footer "Protected by ReportedIP Hive"). Before: two were plain text, one in the brand look (E2E verification template), one in a third layout — three versions of one brand. After: one look, one place in code, one provider hook.

### New

- **`ReportedIP_Hive_Mailer` (singleton, `includes/class-mailer.php`)** — single public API for outgoing mail. Takes structured slots (greeting / intro / main_block / cta / security_notice / disclaimer), renders the template, and automatically builds a plain-text alternative from the same source strings.
- **`ReportedIP_Hive_Mail_Provider_Interface` (`includes/interface-mail-provider.php`)** — provider contract with `send()` + `get_name()`. Allows drop-in replacement of `wp_mail()` (Postmark, SES, SMTP relay, …) without touching mail call sites.
- **`ReportedIP_Hive_Mail_Provider_WordPress` (`includes/mail-providers/`)** — default provider that wraps `wp_mail()` with a `phpmailer_init` hook for `multipart/alternative` (HTML + plain text). The hook is removed after each send — no side effects.
- **`templates/emails/base.php`** — unified HTML layout with slots. Brand colors from the ReportedIP Design System (`--rip-primary` / `--rip-gradient-primary`), inline SVG logo, system font stack, optional CTA button.
- **Filters / actions for extensibility:**
  - `reportedip_hive_mail_args` (filter) — last-mile modification before send
  - `reportedip_hive_mail_provider` (filter) — inject custom transport
  - `reportedip_hive_mail_template_path` (filter) — alternative template (e.g. white-label)
  - `reportedip_hive_mail_before_send` / `_after_send` (actions) — telemetry / throttling
- **Unit test** `tests/Unit/MailerTemplateTest.php` — mock provider, slot render, filter effect, default headers.

### Changed

- **2FA OTP mail** (`includes/class-two-factor-email.php`) — `send_code()` now calls the mailer; the previous 460-line `build_email_html()` shrinks to a small `render_code_box()` helper (~30 lines, just the code-box content).
- **New-device login** (`includes/class-two-factor-notifications.php`) — was plain text, now HTML in the brand look with a details table (time / IP / device) and CTA "Review your security settings". Plain-text multipart alternative remains.
- **Admin security alert** (`includes/class-security-monitor.php`) — was a foreign layout ("🚨 Security Alert", `Arial, sans-serif`, red headline), now in the brand look. Details remain (event label, IP, timestamp, attempts/timeframe/username, action-taken box, recommended steps). Cooldown and report-only logic unchanged.
- **2FA reset mail** (`admin/class-two-factor-admin.php`) — was plain text, now HTML with greeting, clear instruction, CTA "Set up 2FA again", security notice (IP + timestamp), and a hint to contact the admin if the reset wasn't initiated.
- **Bootstrap** (`reportedip-hive.php`) — three `require_once` calls for interface, default provider, and mailer added (before 2FA classes). `Requires PHP` and all other main entries unchanged.
- **Version**: 1.0.1 → 1.1.0 (minor bump because of new public API + filter hooks).

### Migration / compatibility

- Existing custom subjects (`reportedip_hive_2fa_email_subject` option) keep working — the `{site_name}` placeholder is still replaced.
- Cooldown and rate-limit logic of all mails unchanged (transient keys identical).
- Anyone who wanted to modify mail content before now has official hooks instead of nothing.

### Bonus: SMS + test button

- **SMS 2FA wording aligned** (`includes/class-two-factor-sms.php`) — same calm tone as the mail (`Your verification code: %d (valid for %d minutes). Never share this code.`). GDPR constraint preserved: no site name, no user data, no URLs in the SMS body. **Bug fix on the side**: the hardcoded "Valid for 5 minutes" did not match the actual `CODE_TTL` of 600 s (= 10 minutes) — now derived from the constant.
- **"Send test email" button** (`admin/class-admin-settings.php`, *Notifications* tab) — new AJAX handler `ajax_send_test_mail` (`includes/class-ajax-handler.php`) sends a sample mail through the brand template to the logged-in admin. Useful for verifying the provider configuration (`wp_mail` / custom provider) and the template before any real mails go out.

## [1.0.1] — 2026-04-26

**Maintenance release: dead code removed, PHP 8.5-compatible, UI fixes from E2E**

Pure cleanup release before the next feature cycle — functionally the plugin behaves exactly like 1.0.0, just leaner, easier to maintain, and free of deprecation warnings under PHP 8.4/8.5.

### UI fixes (E2E verification)

- **Logs / Blocked IPs / Whitelist / Queue tables**: the `Details` column collapsed under `table-layout: fixed` to ~33 px because all sibling columns reserved fixed pixel widths. Result: long values and even the column header broke letter-by-letter vertically. Tables now use `auto` layout, `Details` has a 220 px minimum, and the timestamp stays single-line.
- **Setup wizard redirect** after activation: the transient window was 60 s, which is too short if the admin visits other pages first. Now five minutes — the transient is still consumed on the first matching `admin_init`.

### Breaking changes

- **`Requires PHP` raised from 7.4 to 8.1.** PHP 7.4 has been end-of-life since November 2022; relevant hosts and WordPress recommendations have long since moved to 8.1+. WordPress no longer installs the plugin on older PHP versions.

### Cleaner code (~1,500 lines less)

- **PHP**: 25 unused methods removed — including `Database::migrate_to_v2`, `cleanup_old_queue_items`, `get_top_attacking_ips`, `Logger::write_to_file`/`format_log_entry`/`get_dashboard_summary`/`get_severity_class`, `Cache::get_cache_recommendations`, `API::bulk_check`/`reset_api_statistics`, five unused `Mode_Manager` methods, three `IP_Manager` methods, `Security_Monitor::refresh_categories`/`get_cached_categories`, `Admin_Settings::sanitize_cleanup_interval`.
- **Options**: `reportedip_hive_file_logging` and `reportedip_hive_auto_whitelist_admins` removed from defaults — their consumers were already gone; UI toggles and wizard inputs follow.
- **Wrappers**: `ReportedIP_Hive::activate()`/`deactivate()` (instance forwards), `mode_manager()` (static alias), `IP_Manager::sanitize_for_api_report()` wrapper removed.
- **Duplicates**: `get_log_statistics`, `get_recent_critical_events`, `export_logs_csv`/`json`, and `cleanup_expired_entries` were redundantly defined across multiple classes — now one canonical source per helper.
- **JS**: `refreshTable`/`refreshDashboardStats`/`animateNumber`/`autoRefresh` removed from `admin.js` (referenced selectors that no longer exist), `initApiUsageChart`/`updateChart` removed from `charts.js` (canvas does not exist), three raw `alert()` calls in `two-factor-admin.js` replaced with non-blocking notice + `wp.a11y.speak`.
- **CSS**: ~40 unused selectors removed (legacy dashboard cards, `.status-indicator`, `.connection-status`, `.add-ip-form`, `.progress-bar`, `.rip-stat-card__trend`, `.rip-lookup-item/-label/-value`, the `.rip-notification` family from design-system.css, and more). Duplicated blocks consolidated: `.rip-badge`, `.rip-empty-state`, `:root` tokens in `wizard.css`, `@keyframes spin` (3 → 1, now uniformly `rip-spin`).

### PHP 8.5 compatibility

- **WebAuthn**: `openssl_random_pseudo_bytes()` fallback removed (deprecated in PHP 8.4). `random_bytes()` is guaranteed to be available since PHP 7.0; the surrounding `try/catch` was dead code that produced a notice.
- **WebAuthn**: `rsa_der()` now validates `n`/`e` as non-empty strings before indexing — prevents `ValueError` on malicious or broken CBOR input under PHP 8.4+.
- **Consistency**: 7× `json_encode()` replaced with `wp_json_encode()` (Database, Logger, Cache, Ajax handler).
- **Hygiene**: `current_time('timestamp')` → `time()`, `explode('/', $cidr)` with limit, `?:` → `??` for timeout default, `@inet_pton()` suppression removed (function returns `false` on error anyway).

### Build / CI

- `composer.json`: `php >= 7.4` → `>= 8.1`.
- `phpcs.xml`: `testVersion` raised to `8.1-` — PHPCompatibility now checks against PHP 8.1+.

## [1.0.0] — 2026-04-24

**Initial Public Release — ReportedIP Hive**

First public release of the plugin under its final product name **ReportedIP Hive**. All earlier internal working versions (1.0.0 – 1.6.0 under the working name "ReportedIP Client") were discarded — version 1.0.0 marks the actual market launch.

### Security suite (5 layers)

1. **IP threat intelligence** — community-backed reputation system with ETag caching (~80% fewer API calls) and quota transparency.
2. **Event-based threat detection** — five independent threshold channels: failed logins, comment spam, XMLRPC abuse, admin scanning, reputation checks.
3. **Coordinated-attack detection** — multi-IP time-window analysis (3+ IPs, 20+ attempts in 2 h) catches attack campaigns that single-IP rules would miss.
4. **Two-factor-authentication suite** — four methods in the core (TOTP · email · SMS · WebAuthn/Passkeys), trusted devices (30 days), recovery codes, rate-limited attempts, role-based enforcement.
5. **Dual-mode autonomy** — Local Hive runs 100% offline; Networked Hive enables community sharing.

### Core features

- **6-step setup wizard** with privacy-first defaults (Welcome → Mode+API → Protection → 2FA → Privacy → Done).
- **Modern admin dashboard** with real-time charts, health score (30% config + 30% success + 25% cache hit + 15% response time), queue monitor, and mode badge.
- **2FA suite with 4 methods**: TOTP (RFC 6238), email OTP, SMS via EU providers (Sipgate / MessageBird / seven.io, numbers encrypted at rest), WebAuthn/FIDO2 (Face ID, Touch ID, Windows Hello, YubiKey) — including a 5-step onboarding wizard.
- **CSV import/export** for whitelist, blocked IPs, logs.
- **Report-only mode** for safe threshold tuning.
- **4 cron jobs**: cleanup (daily), reputation sync (hourly), queue processing (15 min), quota refresh (6 h) — triggerable manually from the dashboard.
- **XMLRPC hardening** including optional `system.multicall` disabling.

### Database (7 tables)

- `wp_reportedip_hive_logs`, `wp_reportedip_hive_attempts`, `wp_reportedip_hive_blocked`, `wp_reportedip_hive_whitelist`, `wp_reportedip_hive_api_queue`, `wp_reportedip_hive_stats`, `wp_reportedip_hive_trusted_devices`
- Composite indexes (e.g. `ip_address + attempt_type`) for O(1) threshold checks.

### Privacy & GDPR

- Minimal data collection (no usernames, no comment content, truncated user agents).
- Automatic anonymization (default: 7 days) + configurable retention (default: 30 days).
- All API reports sanitized — no personal data leaves the site.
- Optional full data wipe on uninstall.

### Developer experience

- Full hook catalog under the prefix `reportedip_hive_*`.
- REST API endpoints for headless integrations.
- SMS provider registry is pluggable.
- Internationalization complete (text domain `reportedip-hive`, `.pot` + DE translation included).
- WordPress Coding Standards compliant, PHPStan level 5, 170+ PHPUnit tests.
