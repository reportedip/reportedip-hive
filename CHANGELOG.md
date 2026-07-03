# Changelog

All changes to ReportedIP Hive are documented here.

## [2.1.21] — 2026-07-03

### Fixed

- **Setup-wizard step indicator no longer overflows.** With ten steps the
  indicator ran off the page and stacked labels character by character; it now
  stays on one row with readable single-line labels and scrolls gracefully on
  narrow screens.
- **Account-tier badge showed the wrong word in German.** "Free" (the plan) and
  "Free" (queue-lock available) shared one translation, so the tier rendered as
  "Frei". The tier noun now carries a translation context and reads correctly,
  consistent with the other English tier names.
- **Tier badge updates immediately after validating a Community key in the
  wizard.** Key validation now persists the resolved tier at once, so the header
  badge and PRO-gated defaults (e.g. SMS pre-selected as a 2FA method) reflect
  the new plan without waiting for the next background sync.
- **Wizard privacy selects were unreadable under some themes.** The standalone
  wizard renders inside the active front-end theme, whose CSS could collapse or
  hide the `<select>` controls; their width and colours are now pinned.
- **Settings tab bar wrapped mid-word in German.** Longer translated labels stay
  on one line and the bar wraps cleanly; the page header keeps its badges
  aligned to the right.
- **Removed spurious admin notices on the standalone wizard and 2FA onboarding
  pages.** Rendering a front-end-style page inside wp-admin let third-party
  enqueue callbacks trip WordPress' jQuery-deregister and admin-bar-bump
  warnings. Both pages now isolate the front-end enqueue phase through a shared
  `ReportedIP_Hive::isolate_standalone_frontend_page()` helper.

### Changed

- **2FA method descriptions state the plan requirement clearly.** SMS carries a
  PRO badge and explains it is a Professional-plan feature delivered through the
  managed relay (no Twilio account required); Email advertises the managed
  relay's SPF/DKIM/DMARC deliverability and links to upgrade whenever the
  free-plan `wp_mail()` path is in use.
- **Setup wizard introduces Extended Protection (pre-WordPress).** The firewall
  step now describes the optional pre-WordPress guard and notes that enabling it
  brings additional server-setup settings; the Firewall page's description says
  the same.

## [2.1.20] — 2026-06-25

### Fixed

- **WAF Extended Protection now shows nginx setup instructions.** An nginx +
  PHP-FPM stack is reported by PHP as the `fpm` SAPI, so Hive treated it as
  fully auto-managed (via `.user.ini`) and hid the manual snippets — leaving
  nginx operators without instructions when the auto-written `.user.ini` did
  not take effect (the common case when `user_ini.filename` is disabled or the
  document root is not the scan path). When the auto-written directive is not
  yet running, the Server Setup tab now surfaces the manual options — the
  php.ini / PHP-FPM-pool line (`php_admin_value[auto_prepend_file]`) and the
  nginx `fastcgi_param PHP_VALUE "auto_prepend_file=…"` server block — and the
  WAF tab links to them.

## [2.1.19] — 2026-06-25

### Fixed

- **Hidden login no longer breaks on trailing-slash sites.** The login form
  action was generated as `…/<slug>` without a trailing slash. On a site whose
  permalinks use trailing slashes — and whose web server enforces them (common
  on nginx) — a POST to `/<slug>` is answered with a 301 redirect to `/<slug>/`,
  which the browser replays as a GET and silently drops the credentials. Sign-in
  then appeared to do nothing. The login URL now follows the site's permalink
  convention (`user_trailingslashit()`), so the form posts straight to `/<slug>/`
  and no redirect happens. Sites without trailing-slash permalinks are unchanged.
- **Hidden login no longer breaks behind a page cache (WP Rocket & co.).**
  When "Hide login" was active, the custom login slug is an ordinary URL, so
  page-cache plugins happily cached it. A cached login page is served as static
  HTML without PHP running, so `wp-login.php` never set the `wordpress_test_cookie`
  — the next sign-in then failed the cookie handshake ("Cookies are blocked…")
  and the login appeared to do nothing. The served login page now opts out of
  every known page cache: it defines the `DONOTCACHE*` constants and sends
  no-store / LiteSpeed bypass headers before rendering (covers WP Rocket, W3 Total
  Cache, WP Super Cache, WP Fastest Cache, Comet Cache, Cache Enabler, Hummingbird
  and LiteSpeed Cache), and the slug is also added to WP Rocket's never-cache URL
  list so a copy cannot be served from `advanced-cache.php` before init.

## [2.1.18] — 2026-06-22

### Fixed

- **"API health degraded" no longer sticks forever after a one-off outage.**
  The API success rate was a lifetime cumulative counter with no reset, so a
  single bad spell (e.g. a burst of failed calls) pinned the rate low for good
  and the dashboard kept reporting "degraded" long after the API had recovered.
  Health is now measured over a rolling window of the most recent calls (last 50
  within 7 days), so the metric reflects current behaviour and recovers on its
  own within a window's worth of successful calls. Lifetime usage counters are
  kept for the "Total API calls" figure and the monthly estimate.
- **A runaway loop can no longer flood the security log.** Repeated
  `api_call_failed` entries are now throttled per error type (at most one per
  minute), so a failure burst is summarised instead of writing tens of thousands
  of rows.
- **API statistics are written in UTC** (`last_reset`), matching the plugin-wide
  datetime convention.

### Changed

- **Added a "Reset API statistics" action** to the API call usage card and a
  one-time upgrade step that clears a previously poisoned counter (only on
  installs that look stuck — healthy usage history is left untouched).

## [2.1.17] — 2026-06-19

### Fixed

- **Extended Protection now covers every PHP endpoint on nginx, automatically.**
  On nginx the guard was wired only through a hand-pasted `location` snippet,
  which protects just the one `location` block it lands in — so requests handled
  by their own blocks (wp-login.php, the cached front controller) slipped past
  the firewall while admin-ajax was covered. Hive now detects the PHP-FPM SAPI
  ahead of the nginx server string and writes a document-root `.user.ini`
  instead; PHP-FPM honours `auto_prepend_file` there for every request
  regardless of nginx `location` blocks, with no manual step. The nginx/php.ini
  snippet remains the fallback only for stacks without a FastCGI PHP SAPI.
- **The pre-WordPress WAF guard (Extended Protection) no longer blocks signed-in
  editors saving content.** The guard runs before WordPress via
  `auto_prepend_file` and previously inspected the request body unconditionally,
  so a logged-in user saving a post through `admin-ajax.php` or the REST API
  could trip the XSS/SQLi signature (HTTP 403, `X-Rip-Waf`). The guard now
  detects the `wordpress_logged_in` cookie and skips body inspection for
  authenticated requests (default on, option
  `reportedip_hive_waf_dropin_skip_authenticated`); URL and user-agent rules
  still run, and the in-WordPress engine remains the capability-aware backstop.
- **Disabling the WAF engine (or switching to report-only) now also neutralises
  the pre-WordPress guard.** The guard bakes the engine-enabled and report-only
  state in and self-heals on toggle, so the firewall can no longer keep
  enforcing after it was switched off in the admin.

### Changed

- **Softened the SMS 2FA backoff ladder so legitimate resends are no longer
  punished.** The per-recipient ladder now climbs `0s → 30s → 1m → 2m → 5m →
  15m` (was `0s → 2m → 5m → 15m → 30m → 60m`) — the gentle early rungs cover a
  slow or missed SMS, while escalation still throttles a genuine burst. Mirrors
  the matching change in the reportedip.de relay rate-limiter; the daily
  per-recipient hard cap and the monthly relay quota remain the cost ceiling.

## [2.1.16] — 2026-06-17

### Fixed

- **Stopped the runaway `/relay-quota` polling that could fire on every
  front-end request.** A tier lookup on a cold or error-returning cache fell
  through to a live `/relay-quota` call, and that lookup runs on hot paths
  (firewall, security headers, bot verification), so a site under load polled
  the service thousands of times a minute. Tier reads are now served purely
  from cache — the status transient, the relay-quota transient, then the
  durable known-tier baseline — and never trigger a live call.

### Changed

- A failed `/relay-quota` response now arms a short cooldown so it is not
  retried on the next request, the meta-bucket hourly rate limit also guards
  the call, and saving an API key refreshes the tier once in the background
  instead of letting a live front-end lookup discover it. Live refresh is owned
  solely by the six-hour cron and the key-save hook.

## [2.1.15] — 2026-06-17

### Fixed

- **Every timestamp in the admin now renders in the site timezone.** The
  "Timestamp" line inside a log row's details — and the coordinated-attack time
  window — were printed in raw UTC, off by the site offset from the localized
  row time and the rest of the WordPress admin. Both are now converted to the
  configured site timezone.

## [2.1.14] — 2026-06-17

### Fixed

- **Auto-blocking no longer silently fails on servers whose database timezone
  is not UTC.** Expiry and attempt timestamps are written in UTC but were
  compared against the MySQL session clock (`NOW()` / `CURDATE()`). On a
  non-UTC server this made the per-IP attempt counter never accumulate inside
  its window — so the failed-login and XML-RPC thresholds were never reached
  and no offender was ever blocked — and treated every freshly written block as
  already expired, leaving the block list empty during an active attack. Every
  datetime column and every comparison is now UTC-consistent.

### Changed

- All stored datetimes are normalised to UTC across the database layer, the
  coordinated-attack detector, the queue recovery sweep, trusted-device expiry
  and the daily statistics. Admin tables (logs, blocked IPs, whitelist, audit
  trail, WAF exceptions) now render timestamps in the site timezone instead of
  raw UTC.

## [2.1.13] — 2026-06-16

### Changed

- **Security dashboard reworked into a full analytics view.** The Security
  Events, Threat Distribution and Recent Activity sections now draw on every
  sensor instead of five legacy categories. New: a headline strip (attacks
  blocked over 30 days / today, IPs currently blocked, active protection
  layers), a stacked timeline grouped into seven threat families with a
  7/30/90-day selector, a doughnut by attack vector, a WAF rule-group bar
  chart, a severity breakdown, and a Top Attackers table. Recent Activity
  entries now carry a severity badge and threat-family label. A single,
  frequency-capped card promotes the deeper analytics on higher plans.

### Fixed

- **Hardening Mode no longer triggers on routine background brute-force.** The
  coordinated-attack detectors now count individual `failed_login` events over
  a real time window from the logs table instead of summing the cumulative
  per-IP counter from the attempts table, which over-counted any IP merely
  active in the window with its full lifetime total. Detection defaults were
  raised to realistic values (distributed: 10 distinct IPs and 50 attempts in
  10 minutes; burst: 8 IPs and 30 attempts in one minute) so a normal botnet
  baseline no longer tightens login thresholds network-wide. New installs pick
  up the new defaults; sites that previously saved the Hardening tab keep their
  stored values.

## [2.1.12] — 2026-06-16

### Added

- **MainWP provisioning can switch a managed site into Community Network mode.**
  A `community` flag on the `reportedip_hive_provision` job sets the operation
  mode alongside the API key, and the sync job now reports the current
  `operation_mode` so the dashboard reflects each child site's mode.

## [2.1.11] — 2026-06-16

### Changed

- **WAF exception form is now self-explanatory.** Each field carries an inline
  hint, the scope selector progressively reveals only the relevant field, and
  the ambiguous "Rule ID or group" field is split into a Rule ID input (single
  rule) and a Rule group dropdown populated from the engine's known categories —
  so it is clear what to enter and where the value comes from (the WAF block
  log, or the one-click "Allow" button). The exceptions FAQ was rewritten to
  explain what to configure, where to find a rule ID or group, how to pick a
  scope, and how the path/IP filters work.

### Fixed

- **API queue bulk actions work again.** The queue tab wrapped its list table in
  a `method="get"` form while `process_bulk_action()` read `$_POST`, so selecting
  rows and applying Retry / Delete silently reloaded the page with no effect. The
  form is now `method="post"`, matching the logs / blocked / whitelist tabs.
- **"Retry all failed" now revives permanently-failed reports.** The bulk reset
  excluded rows that had already reached `max_attempts`, so a manual retry of an
  all-exhausted queue reset nothing. A manual, admin-initiated retry now resets
  every failed row (overriding the automatic cron ceiling), consistent with the
  per-row retry; the tab's "Retry All Failed" button counts and enables on all
  failed rows.
- **Coordinated-attack detections are logged once per sweep.** The minute-bucket
  query and the rolling-window detector each logged a `coordinated_attack_detected`
  event for the same incident; only the strongest reason is logged now.

### Added

- **Block decisions are self-explanatory in the log.** WAF blocks now record the
  matched value, the inspected target, the request method, URI and User-Agent,
  and the active paranoia level; the bot verifier records the verification reason
  (e.g. `ptr_foreign_domain`, `ip_not_in_official_range`) plus the real
  User-Agent; the 404 scan detector records method and User-Agent. A block
  decision is now diagnosable without reproducing the request.
- **Failed relay-mail and API calls record a reason.** Non-retryable relay-mail
  failures are logged (`mail_relay_error`) instead of being dropped, and
  `api_call_failed` carries a preview of the rejecting response body.

## [2.1.10] — 2026-06-16

### Fixed

- **Extended Protection (pre-WordPress guard) now honours WAF exceptions — and
  inspects request bodies at all.** The generated guard declared its helper
  functions *after* the immediately-invoked guard closure; because those
  declarations are conditional (`function_exists`) they are not hoisted, so the
  closure fatally errored and failed open on every request that carried a POST
  body. Body inspection in the pre-WordPress layer was therefore a no-op (the
  in-WordPress engine still caught those requests). Helpers are now declared
  before the closure, so the guard inspects bodies as intended. The guard also
  bakes in the active WAF exceptions (rule / group / whole-path, with optional
  path-prefix and IP/CIDR scope) and rebakes when the allowlist changes, so the
  pre-WordPress layer and the in-WordPress engine honour the same exceptions.

### Added

- **WAF tab orientation: a sticky "jump to" bar** (Engine & rules · Extended
  protection · Exceptions) and a **WAF-exceptions FAQ** explaining why a
  first-party request can trip the firewall, what an exception does, how tightly
  to scope it, and that exceptions also apply to Extended Protection.

## [2.1.9] — 2026-06-15

### Added

- **Backend-managed WAF exceptions (allowlist).** A false positive can now be
  relieved from the admin without touching code — the way ModSecurity exclusions
  and the Wordfence allowlist work. Firewall → WAF gains a "WAF Exceptions"
  section, and every WAF log row carries an "Allow" action that creates a narrow
  exception for exactly that rule on that path. An exception is scoped to a
  single rule, a rule group, or — for a first-party endpoint that legitimately
  receives attack-like payloads (a security API ingesting reported attack data)
  — the whole engine on a path, optionally narrowed to an IP/CIDR. A
  whole-engine exception must always carry a path or IP, so the engine can never
  be globally disabled by accident. Exceptions are network-wide data
  (`reportedip_hive_waf_exceptions`, `db_version` 10), available on every plan —
  the protection engine itself stays free. Nothing site-specific ships in the
  code.
- **Developer hook `reportedip_hive_waf_bypass_routes`** complements the backend
  list as a code-level escape hatch (empty by default). Matching is an anchored
  `str_starts_with` test against the resolved WP REST route — never an
  unanchored substring of the raw URI — so a decoy bypass token in an unrelated
  query parameter (`?x=/my-api/v1`) cannot disable the WAF.

## [2.1.8] — 2026-06-15

### Security

- **Extended Protection (WAF drop-in) can no longer take a site offline when
  it is removed.** When the `auto_prepend_file` directive lived in a file Hive
  cannot edit — an nginx `fastcgi_param` or a hand-edited `php.ini` line —
  deactivating or deleting the plugin used to delete the guard file while that
  directive stayed behind, leaving PHP pointing at a missing file and crashing
  every request (including wp-admin) with a 500. Removal now strips the
  directives Hive does control (`.htaccess`, `.user.ini`) and *neutralises* the
  guard to an inert placeholder instead of deleting it, so a leftover directive
  can never reference a missing file. This mirrors how Wordfence keeps its
  `wordfence-waf.php` fail-safe.

### Changed

- **Server Setup now shows a prominent warning and recovery steps** next to the
  nginx / php.ini snippet: how to remove the directive before uninstalling and,
  if a 500 ever appears, how to recover by commenting out the line and reloading
  PHP-FPM / nginx — no FTP file restore needed.

## [2.1.7] — 2026-06-12

### Changed

- **Unified tier markers across the admin UI.** Every tier-gated control now
  renders the same compact tier badge through a single helper: locked
  features show the badge with a lock glyph linking to the plan comparison,
  available features keep the badge as an "included in your plan" marker —
  so paying customers keep seeing what their plan covers. This replaces four
  ad-hoc inline-styled "PRO" mini badges, the mixed lock-chip/badge
  constructs and a generic info badge on the Rule Sync comparison card.
- **Bot Verification and Disposable Email now carry a visible tier marker**
  in their card headers instead of burying the plan boundary in help text.
- **The Free/Contributor tier badge in the page header now links to the plan
  comparison** (shown to admins only); paid tiers stay non-interactive.
- **The Logs event-type filter is grouped** (Login & Spam / Firewall /
  Hardening Mode) and now covers the firewall events: WAF blocks and
  report-only matches, spoofed crawlers, decoy-path hits, scan detection,
  disposable-email matches and ruleset signature failures.

### Fixes

- **Every tier-lock chip linked against a constant that never existed**
  (`REPORTEDIP_UPGRADE_URL`), so the upgrade link silently fell back to a
  hard-coded URL. All upgrade affordances now share one canonical pricing
  URL.
- **Firewall tabs rendered their stacked cards and grids without vertical
  spacing** under the content panel; the design system now applies a
  consistent rhythm between top-level blocks.
- **The log export delivered CSV regardless of which export button was
  clicked, and the CSV Details column only contained the word "Array".** The
  AJAX handler read `format`/`days` from `$_POST` while the export buttons are
  GET links, so the JSON export silently fell back to CSV; and the decoded
  details array was handed straight to `fputcsv()`, which casts it to the
  literal string "Array". The parameters are now read from `$_REQUEST`, the
  details cell carries the full payload as JSON, and the CSV gains a Severity
  column.
- **The WAF `.user.ini` directive never took effect on PHP-FPM/CGI hosts.** The
  drop-in manager wrote the `auto_prepend_file` block via WordPress'
  `insert_with_markers()`, which uses `#` comment markers and injects a
  translatable instruction comment. The PHP INI parser only accepts `;`
  comments (`#` was removed in PHP 7), and the instruction comment contains
  parentheses — a hard INI syntax error that aborts `.user.ini` parsing before
  the directive line is reached, so the guard silently never ran. The
  `.user.ini` block now uses `;` markers with nothing but the bare directive,
  and the hourly self-heal replaces the broken legacy `#` block on existing
  installs automatically.

## [2.1.6] — 2026-06-12

### Fixes

- **Genuine search crawlers are no longer mislabelled "fake bot".** The
  verified-bot classifier treated an out-of-range IP as a decisive spoofer and a
  failed reverse-DNS lookup as proof of forgery — so a real Bing crawler from a
  /24 missing from the seed (e.g. `52.167.144.0/24`), or any crawler on a host
  with a flaky resolver, was flagged. Classification is now three-state: an
  IP-range match verifies, a PTR on a foreign domain is fake, and a missing range
  or unresolved DNS stays `unknown` (never flagged). Out-of-range IPs fall back
  to forward-confirmed reverse DNS instead of an automatic fake verdict.

### Added

- **MainWP sync now reports the WAF pre-WordPress drop-in status.** The MainWP
  integration module ships `waf_enabled`, `waf_report_only`, `waf_dropin_enabled`,
  `waf_dropin_running`, `waf_server` and the derived `waf_needs_setup` flag with
  every sync, so a MainWP dashboard can flag sites whose extended protection is
  enabled but not yet running — typically an nginx host still waiting for the
  manual server snippet. Counts only; no new data leaves the site.

## [2.1.5] — 2026-06-11

### Fixes

- **Fatal `ArithmeticError: Bit shift by negative number` in the CIDR matcher.**
  `ip_in_cidr()` branched on the IP family but never checked the CIDR family, so
  testing a v4 address against a v6 range (e.g. a `::1/128` whitelist entry or a
  bot IP-range feed) fed a `/33..128` mask into the 32-bit shift and crashed the
  request. It now rejects mismatched families and out-of-range/malformed masks
  cleanly, and handles `/0` and `/128` host routes correctly.
- **Genuine search crawlers are no longer blocked as user-enumeration.**
  Googlebot (and other verified crawlers) routinely index author archives
  (`/author/<slug>/`), which the user-enumeration sensor counted as probes and
  escalated to an IP block — locking the crawler out of the site for up to two
  days, an SEO regression. The sensor now exempts verified-crawler User-Agents
  from the probe ladder (the same allowlist the 404- and REST-burst sensors
  use); the 404 that hides the username is still served, so a spoofed crawler
  UA gains nothing.
- **Loopback and private addresses are never reported as attackers.**
  `get_client_ip()` accepted any syntactically valid address from the trusted
  proxy header, so an internal hop (`127.0.0.1`, `::1`, `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, link-local) could become the "client" IP
  and get flagged. It now requires a publicly-routable address on that path.
- **The API report queue drops non-public IPs.** A new `is_public_ip()` gate in
  `queue_api_report()` rejects the `unknown` sentinel and every private/reserved
  range before queueing, so a mis-detected internal request no longer produces a
  report that the remote API rejects after three wasted retries.

## [2.1.4] — 2026-06-11

### Changed

- **Firewall admin UX overhaul.** The Overview tab is now a real mini-dashboard:
  per-module status table, 7-day activity counters and the recent firewall
  event stream (new type-filtered log queries). Every tab opens with a short
  plain-language intro explaining what the module does.
- **One place for all server rules.** A new Server Setup tab bundles every
  web-server-level snippet — the WAF `auto_prepend_file` directive, the decoy
  rewrite rules and an optional server-level export of the configured security
  headers (nginx `add_header` / Apache `Header` lines generated from the live
  Hardening configuration). The WAF and Scan & Decoy tabs link there instead of
  scattering snippets across tabs.
- **Extended Protection setup is verifiable.** The drop-in status now reports
  the definitive signal — whether the guard executed for the current request —
  and shows "Setup complete" the moment it works. On nginx and managed hosts
  the manual step is an explicit either/or choice: a php.ini /
  hosting-panel `auto_prepend_file` line (new, usually the easiest route) or
  the nginx snippet.
- **Bot Verification tab** now shows the verified crawler list as badges
  (range-verified vs rDNS-verified), 7-day spoofer counts and how verification
  works; the Rule Sync tab brands synced rulesets as delivered by the
  reportedip.de Rule API, adds rule counts and per-ruleset consumer links, and
  hides the Free-vs-Professional comparison once Priority Sync is active.
- The Hardening tab's save button now also renders for plans without advanced
  headers, so the free basic headers can be saved again.

### New

- WAF block reason codes for the newer attack classes delivered through the
  rule sync — SSRF, Log4Shell/JNDI, PHP object injection, NoSQL injection, XXE,
  web-shell uploads, CRLF and template injection now surface a specific
  `X-RIP-Ref` reason instead of the generic scan code. The detection rules
  themselves ship through the server-delivered ruleset, not the bundled
  baseline.

## [2.1.3] — 2026-06-11

### Fixes

- Verified-bot detection no longer flags genuine crawlers that connect over
  IPv6 as fake. The FCrDNS forward-confirmation used `gethostbyname()` (IPv4
  only), so every IPv6 crawler without a published IP range failed
  verification; it now resolves A and AAAA records and compares addresses by
  their packed binary form.
- `facebookexternalhit` (Meta) is verified against Meta's published IP ranges
  (AS32934) instead of reverse DNS, which Meta does not provide reliably — real
  Facebook link-preview crawlers from `2a03:2880::/29` are no longer flagged.

## [2.1.2] — 2026-06-11

### New

- **Rule delivery framework.** Server-delivered, versioned, Ed25519-signed,
  tier-staggered rulesets (`waf`, `bot_signatures`, `disposable_domains`,
  `scan_paths`). The plugin verifies every ruleset against a
  bundled public key before applying it and always falls back to the bundled
  baseline — a tampered, oversized or unreachable feed can never poison the
  rules. Synced every six hours (Community mode + API key + toggle); the
  bundled baselines work fully offline. Network-wide on multisite (sitemeta).
- **Web Application Firewall.** Request-inspecting engine on `init` that matches
  the active `waf` ruleset against the URI, query, body and user-agent and
  blocks via the shared cache-safe, reference-coded 403 path. The engine and
  the Paranoia-Level-1 baseline are free on every plan; Professional unlocks
  Level 2/3. ReDoS-hardened (bounded PCRE backtracking, fail-open on a malformed
  rule), whitelist- and content-author-aware to avoid false positives, with a
  repeat-offender escalation into the existing block ladder.
- **Extended Protection drop-in (optional).** A pre-WordPress `auto_prepend_file`
  guard that runs the WAF before WordPress loads — Apache (`.htaccess`),
  PHP-FPM (`.user.ini`) auto-config and an nginx snippet generator. Off by
  default; removal always strips the directive before deleting the guard so a
  stale prepend can never fatal the site.
- **Verified bot detection.** Confirms that a request claiming to be Googlebot,
  Bingbot or another crawler genuinely originates from it — a DNS-free match
  against the crawler's official IP ranges first (Priority Sync), then a
  forward-confirmed reverse-DNS fallback. A spoofer is flagged (default) or
  blocked; a genuine crawler is never blocked. Free on every plan.
- **Disposable-email blocking.** Inspects the address on registration (WordPress
  and WooCommerce) against the `disposable_domains` list. Three modes
  (off/monitor/block); privacy relays (Apple Hide My Email, Firefox Relay, …)
  are a distinct category that passes through by default. Free on every plan;
  the live list rides Priority Sync.
- **Comment honeypot.** An invisible, screen-reader-excluded decoy field on the
  comment form; spam bots that fill every field are rejected with no CAPTCHA
  friction for real visitors.
- **Firewall admin area** with a Rule Sync status view (per-ruleset version and
  source, Free-vs-Professional comparison), a WAF status + controls tab
  (engine/mode/active rules, Paranoia-Level selector), a Bot Verification tab,
  a Spam Defence tab (disposable-email + honeypot) and the Extended Protection
  box. Hardening folds into the Firewall tab strip and the Audit Trail into
  Security › Activity, keeping the menu lean.
- **Protection & hardening score.** Two dashboard gauges (0–100 plus an
  A+–F grade, Mozilla-Observatory style) that rate the detection coverage and
  the hardening posture, with per-item deep links to switch a sensor on.
  Locked features count toward the visible potential, not the score.
- **Security headers.** Hardening response headers on every front-end request:
  the basic trio (X-Content-Type-Options, X-Frame-Options, Referrer-Policy) is
  free; HSTS, Permissions-Policy, a Content-Security-Policy (report-only by
  default) and the cross-origin trio (COOP/CORP/COEP) come with Professional.
  Headers already sent by the server or another plugin are detected and left
  untouched.
- **Audit event trail (Business).** Append-only user-lifecycle trail — logins,
  failed logins, password resets, profile updates, role changes including the
  acting user, registrations and new-IP detection — with filters, CSV/JSON
  export, GDPR export/erasure integration and retention cleanup. Standard
  security logs stay available on every plan.
- **Firewall step in the setup wizard.** The wizard now covers the WAF
  (enable/report-only), verified-bot action, disposable-email mode and the
  comment honeypot with their safe defaults.
- **Settings export/import covers the firewall.** New `firewall`, `headers` and
  `audit` sections carry the new configuration between sites; the host-specific
  drop-in toggle and runtime ruleset state intentionally stay local.

### Fixes

- The pre-WordPress WAF drop-in is rebaked immediately after a rule sync and
  after every whitelist change (queued once per request), so a freshly
  whitelisted client or an updated ruleset no longer waits for the hourly
  self-heal.
- The drop-in guard now honours the configured trusted proxy header when
  resolving the client IP, matching the in-WordPress engine — behind a proxy
  the baked-in whitelist previously never matched.
- Settings export/import reads and writes through the network-aware option
  layer, so exports taken in the multisite network admin carry the real values.
- The System Status page reports the WAF drop-in state (active, detected
  server, config-target writability).

### Performance

- WAF adds ~4 µs CPU per request and zero extra database queries when a
  persistent object cache is present; the whitelist lookup is de-duplicated on
  the request hot path so it is no longer queried twice per visitor.

### Changed

- The Firewall admin page renders from its own class and drives every toggle,
  select and copy button through a single delegated script
  (`assets/js/firewall.js`) instead of per-tab inline scripts; AJAX errors now
  surface a message instead of silently reloading.

## [2.1.0] — 2026-06-10

### New

- **MainWP integration.** The plugin is now remote-manageable from a MainWP
  dashboard without an extra child plugin. It hooks the MainWP Child
  `mainwp_child_extra_execution` filter (authenticated by the MainWP Child
  channel) and answers two jobs: a security-metrics sync (aggregate counts only
  — active blocks, whitelist size, failed logins, comment spam, reputation
  blocks, queue size, recent critical events, 2FA-enabled users — no IPs,
  usernames, secrets or the API key leave the site) and API-key provisioning
  (sets `reportedip_hive_api_key` from the trusted dashboard).
- **Block-page reference codes.** Every blocked response now carries a
  correlatable reference code (e.g. `WAF_SQLI-3F9A2B71`), shown on the page and
  emitted as the `X-RIP-Ref` header. A wrongly blocked visitor can quote one
  short string an admin matches in the logs; the incident token is a one-way
  hash of the IP, reason and hour, so no personal data is exposed.

### Changed

- **Blocked page rebuilt on the design system.** Sharp-edged card, inline SVG
  shield icon (no emoji), design-system palette, and every string is now
  translatable (German included).

### Fixed

- **2FA option sanitisers clobbered direct writes.** The allowed-methods and
  enforced-roles sanitisers fire for *every* write to their options via the
  `sanitize_option_*` filter, not only the settings form. A direct write (setup
  wizard, settings import, WP-CLI) was discarded — collapsing the allowed
  methods to TOTP only and wiping the enforced roles. Both sanitisers now detect
  the settings-form shape and pass direct writes through `filter_valid_methods()`
  / `filter_valid_roles()` (the new single source of truth on
  `ReportedIP_Hive_Two_Factor`).

## [2.0.29] — 2026-06-09

### Security

- **Hardening Mode now catches distributed botnets, not just same-minute
  bursts.** The coordinated-attack detector previously fired only when ≥ 3 IPs
  and ≥ 20 failed logins landed in the *same calendar minute*. A botnet that
  rotates IPs every couple of minutes — each IP auto-blocked at the per-IP
  threshold before the next starts — never satisfied that rule, so hardening
  stayed dormant through exactly the attack it exists to stop. A second,
  complementary detector now aggregates distinct IPs and failed logins across a
  configurable rolling window (default 10 minutes) and tightens thresholds when
  the distributed pattern crosses ≥ 5 IPs / ≥ 20 attempts. The original
  same-minute burst rule is retained, so both simultaneous floods and slow
  rotating attacks are covered.

### Fixed

- **Multisite: coordinated-attack detection queried the wrong table.**
  `Security_Monitor::check_coordinated_attacks()` and the plugin-reset handler
  read `$wpdb->prefix . 'reportedip_hive_attempts'` instead of the canonical
  `base_prefix`. On a sub-site that points at a non-existent per-site table, so
  detection was effectively dead and the data reset silently skipped the real
  network-wide tables. Both now use `base_prefix`, making detection correctly
  network-wide.

### New

- **Configurable distributed-detection thresholds** on the Hardening Mode
  settings tab: detection window (minutes), minimum distinct IPs and minimum
  total attempts, with conservative defaults (10 / 5 / 20).

## [2.0.28] — 2026-06-09

### Fixed

- **Setup wizard now persists every selected 2FA method and enforced role.**
  The 2FA step saved only TOTP and silently dropped the enforced-roles list no
  matter what was chosen. The `register_setting` sanitisers for
  `2fa_allowed_methods` and `2fa_enforce_roles` run via the global
  `sanitize_option_<key>` filter on every write — not just the settings form —
  yet they only understood the form's shape: the methods sanitiser rebuilt the
  list from the per-method `$_POST` checkboxes (absent on a wizard save, so it
  collapsed to TOTP) and the roles sanitiser required an array and rejected the
  JSON string the wizard writes (wiping the list to empty). Both now sanitise
  the value they are handed while keeping the settings-form checkbox path
  authoritative, so the wizard, tier-upgrade and settings-import write paths
  round-trip correctly.

### Changed

- **Business tier copy now states the multi-bookable model.** The Settings
  upgrade card, the setup-wizard tier card and `Mode_Manager`'s Business
  descriptor now spell out "15 domains per licence" and "bookable x2–x20 —
  domains, API quota and 2FA mail/SMS scale with the licence count (volume
  discount)", matching the live Stripe volume pricing.
- **Bot allowlist expanded** so legitimate crawlers no longer trip the 404 /
  REST burst triggers: WordPress core (pingbacks/loopback), uptime monitors
  (UptimeRobot, Pingdom, Site24x7, StatusCake, BetterStack), more search and
  social bots (PetalBot, SeznamBot, Qwantify, CocCocBot, MojeekBot, Yeti,
  NaverBot, Mastodon, Tumblr, HubSpot, Screaming Frog, Lighthouse, …). The
  `Pinterestbot` / `Slackbot-LinkExpanding` tokens were broadened to
  `Pinterest` / `Slackbot` to match the real user-agent strings. Honeypot-path
  detection stays active for every user-agent regardless of allowlist.
- **Scan detector ignores static-asset 404s.** `css`, `js`, `map` and
  `webmanifest` join the passive-asset extension list, so a missing stylesheet
  or source map never counts toward the scanner threshold.

### Documentation

- **Free-vs-paid positioning corrected across README and readme.txt.** The
  former "no upsell tiers / no Pro gate / no feature held behind a paywall"
  claims were inaccurate: `hardening_mode` and `frontend_2fa` run locally but
  require a Professional plan. The docs now state honestly that the detection
  and identity core (all 12 sensors, TOTP / Passkey / Email / Recovery 2FA,
  progressive blocking, the password-reset gate, dashboards and exports) is
  free and GPL-2.0, while paid plans add the managed relays, multi-site
  management, WooCommerce frontend 2FA, Hardening Mode, white-label and higher
  quotas.
- **Stale facts fixed:** the multisite FAQ ("single-site for now") now
  describes the network-only Multisite support shipped in 2.0.0; schema version
  corrected v4 → v8; the removed `reportedip_2fa_sms_providers` filter and the
  removed "SMS provider credentials" reference were dropped; the database-table
  count corrected 6 → 7; the setup wizard is consistently described as 9 steps;
  the Enterprise price floor updated to "from ~663 €/month"; volatile test
  counts replaced with durable wording; the 2.0.27 changelog entry was added to
  readme.txt.

## [2.0.27] — 2026-06-05

### Added
- **WPMU network admin compatibility.** Replaced hardcoded `admin_url` references with dynamic `ReportedIP_Hive_Admin_Settings::get_admin_page_url` context resolution, keeping administrators in the Network Admin context when managing network-activated settings, onboarding, 2FA settings, or resets.
- **Text-independent login error masking.** Refactored error masking in `normalize_login_errors` to check error codes within the global `$errors` object rather than string matching. This ensures 2FA onboarding, password resets, and IP/reputation blocks pass through unmasked across all languages (including German) while keeping credential errors securely masked.

### Changed
- **Styled missing API key warning.** Restyled and rebuilt the missing API key notice on the community page to use the premium design system's BEM classes and SVG layouts.

## [2.0.25] — 2026-06-04

### Added

- **GDPR / privacy integration (`includes/class-privacy.php`).** Registers a
  suggested privacy-policy passage in the WordPress Privacy Policy Guide
  (Tools -> Privacy) and a personal-data exporter/eraser for a user's own login
  attempts (matched by username) and trusted devices (matched by user id). The
  2FA-secret exporter/eraser in `class-two-factor-admin.php` is unchanged.
- **Privacy-text generator pointer.** Site operators can generate a
  configuration-aware, copy/paste privacy passage (German / English) at
  `https://reportedip.de/dashboard/dsgvo`; linked from the readme and the
  Privacy Policy Guide entry.

### Changed

- **SMS 2FA is now a Professional feature, delivered exclusively through the
  managed reportedip.de relay.** The self-hosted SMS provider option and its
  three third-party adapters were removed; `ReportedIP_Hive_Two_Factor_SMS`
  routes every dispatch through `ReportedIP_Hive_SMS_Provider_Relay`, gated by
  `Mode_Manager::is_relay_available('sms')`. `is_ready()` is true only while the
  relay is available for the current tier.
- **Admin UI** on Settings → 2FA → SMS collapses to a relay-status panel with a
  test-dispatch button (Professional+) or a tier-lock card (everyone else). The
  provider selector, per-provider credential fields and the per-provider AVV
  checkbox are gone — the relay AVV is part of the plan subscription.
- **HaveIBeenPwned documentation corrected.** The readme described the HIBP
  range check as "off / opt-in"; it is on by default together with the password
  policy (server-side, k-anonymity — only a 5-char hash prefix leaves the
  server, no visitor IP). Behaviour is unchanged; the documentation now matches
  the code default.
- **Contact addresses rotated.** Security disclosures now use
  `abuse@reportedip.de`; general and authorship contacts use `1@reportedip.de`.
  `ps@cms-admins.de` is retired from the repository (file headers,
  `composer.json`, `REPORTEDIP_HIVE_CONTACT_MAIL`, readme and issue templates).

### Removed

- Third-party SMS provider adapters (`includes/sms-providers/class-sms-provider-{sipgate,messagebird,sevenio}.php`).
- The `reportedip_2fa_sms_providers` extension filter.
- Options `reportedip_hive_2fa_sms_provider`, `…_sms_avv_confirmed`,
  `…_sms_provider_config`, `…_sms_from` and their settings registration,
  sanitizers, import/export keys and the deprecated `Phone_Validator::is_eu()`
  shim.

### Fixed

- **Dead documentation links.** The readme's "External Services" and contact
  sections linked `reportedip.de/privacy`, `/terms` and `/legal/avv`, none of
  which existed. They now point to the live `/datenschutzerklaerung/`,
  `/nutzungsbedingungen/` and `/legal/avv/` pages.

### Migration

- **Schema v8** (`Migration_Manager::migrate_to_v8()`) deletes the now-orphaned
  SMS provider options on upgrade, on both single-site and Multisite storage.

### Breaking

- Sites that sent 2FA SMS via a self-configured provider — or on any tier that
  does not run the managed relay (Free / Contributor) — can no longer send SMS.
  Affected users fall back to TOTP, Email or a passkey. A user whose only
  enrolled method was SMS hits the existing no-usable-method path
  (`Two_Factor_Reset_Gate::assess_methods_health()`), which alerts the admin.

## [2.0.23] — 2026-06-02

### Fixed

- **Setup wizard silently dropped settings — the 2FA step saved nothing on a
  fresh install.** The wizard staged values in `sessionStorage` and committed
  them only from one late step, so any step not re-collected was lost and the
  PHP handler quietly fell back to hard-coded defaults. The wizard now saves
  each step server-side on every navigation (Back included) through a single
  `reportedip_wizard_save_step` endpoint and a shared field schema, so render,
  collection and persistence can never drift again. The 2FA frontend toggle and
  enforce-role list, previously never collected, now persist.
- **Boolean options stored as PHP `false` could read back as their truthy
  default.** WordPress' `get_option($key, true)` returns the default for a
  stored `false`, so a toggle switched off re-appeared on. Booleans are now
  persisted as `1`/`0` everywhere (wizard schema, default seeding,
  `sanitize_boolean`), eliminating the round-trip footgun.
- **Multisite default seeding wrote to a single blog instead of the network.**
  Activation, the wizard-skip seed and the settings reset now route through
  `ReportedIP_Hive_Option_Routing`, so network-wide defaults land in sitemeta.
- **404 scanner false-positives auto-blocked real visitors.** The rate-based
  404 trigger counted browser, OS and crawler auto-requests — a single iOS page
  view fires several `apple-touch-icon` requests, and a broken or migrated page
  can 404 a whole gallery of images — so ordinary traffic crossed the burst
  threshold and earned a 24 h block. Those requests are now excluded from the
  rate trigger: a benign-path allowlist (apple-touch-icon / favicon / mstile
  families, web manifests, `browserconfig.xml`, `robots.txt`, `ads.txt`,
  `.well-known` endpoints) plus a render-asset extension skip (images, fonts,
  media). Honeypot pattern hits (`/.env`, `/wp-config.php.bak`, `/.git/config`,
  …) stay armed for every extension. Both lists are filterable via
  `reportedip_hive_scan_404_benign_paths` and
  `reportedip_hive_scan_404_asset_extensions`.
- **REST burst trigger blocked legitimate first-party plugin traffic.** The
  global REST rate-limit counted anonymous render traffic from content and
  commerce plugins — Slider Revolution re-fetching a slider, a WooCommerce
  cart-fragment poll — so a single visitor on a slider-heavy page could cross
  the threshold and earn an auto-block. The default bypass set now covers
  high-volume first-party namespaces (`/sliderrevolution`, `/elementor/v1`,
  `/wc/store`) alongside the existing cookie-consent ones; logged-in users were
  already exempt. Extend it via `reportedip_hive_rest_bypass_routes`.
- **A logged-in admin, editor or shop manager could be locked out of their own
  site by an automatic IP block.** Once an IP was auto-blocked — for example by
  one of the false positives above, triggered by anonymous front-end traffic
  from the same network — the front-end and wp-admin block enforcement refused
  it unconditionally, with no exemption for an authenticated operator on that
  IP. A logged-in user with the `edit_others_posts` capability is now exempt
  from the auto-block lockout on both surfaces; the exemption runs before the
  per-IP access cache, so a cached block cannot lock them out either. It is
  capability-gated and cannot be used without valid privileged credentials.

### Changed

- **Hardening Mode is on by default on Professional and higher.** A tier-aware
  master default plus a retroactive enable on the `reportedip_hive_tier_changed`
  upgrade hook; an explicit opt-out is preserved. The settings tab now shows the
  PRO lock chip consistently with the other PRO features.
- Option defaults are now a single canonical map in `ReportedIP_Hive_Defaults`
  (`all_option_defaults()`); the former duplicated `get_default_options()` and
  `SAFE_OPTIONS` maps and their conflicting `2fa_enforce_roles` default are gone.

### New

- `ReportedIP_Hive_Wizard_Schema` — the per-step field map + typed save routine
  that backs the wizard's per-step persistence.

## [2.0.22] — 2026-06-02

### Fixed

- **2FA challenge reverted to the default method after a failed attempt.**
  With several methods configured, switching from Email to the SMS tab,
  requesting a code and submitting a wrong or expired one snapped the page
  back to the Email tab — the chosen method and the typed code were both
  lost. The challenge handler now keeps the submitted method across a
  re-render (failed verify, soft lockout), so the user stays on their tab,
  sees the error and can re-enter. The value is still validated against the
  account's active methods, so a forged method falls back safely. Fixes both
  the wp-login.php and the WooCommerce frontend flow.

## [2.0.21] — 2026-06-02

### New

- **Hide-Login probe sensor.** When Hide Login is active, repeated direct
  hits on the old `/wp-login.php` from one IP are now treated as a scan and
  blocked on the standard escalation ladder, with a community report — reusing
  the same path as the other sensors. A single accidental visit stays harmless
  (only the existing low-severity recon log fires); a pattern triggers the
  block. Tunable on the Login settings tab: a master toggle (on by default),
  a hit threshold (default 5) and a timeframe (default 10 minutes). Whitelisted
  IPs are never counted.

### Changed

- **2FA challenge method picker no longer truncates on narrow login cards.**
  Inside a narrow themed storefront login column the method tabs collapsed to
  "A…/E…/S…/W…". The selector now reacts to the actual card width (CSS
  container query) and stacks the methods as a vertical, full-label list when
  space is tight, so every method stays readable.

## [2.0.20] — 2026-06-01

### Fixed

- **Repeated "plan is active" tier-change emails.** The welcome/goodbye
  mail (and the `reportedip_hive_tier_changed` action) derived the previous
  tier from the five-minute `reportedip_hive_api_status` transient. Once
  that transient lapsed, the previous tier collapsed to `free`, so every
  subsequent refresh of a paid key re-detected a phantom free→paid
  transition and re-sent the "[Site] <Plan> plan is active" mail — over and
  over. The change baseline now lives in the durable `reportedip_hive_known_tier`
  option; the first observation seeds it silently and the action fires only
  on a genuine tier flip. Verified live: 0 firings across repeated refreshes
  of an already-active tier, exactly 1 firing on a real upgrade.
- **Setup wizard silently dropped enforced-2FA roles with non-lowercase
  slugs.** The wizard ran posted roles through `sanitize_key()`, which
  lowercases and strips the slug, so roles whose slug is not already
  `[a-z0-9_-]` (e.g. membership-plugin roles like `um_Premium-Member`)
  no longer matched the registered roles and were discarded. The wizard
  now preserves the slug, matching the settings-tab behaviour, so every
  selected role is enforced.
- **Admin notices were unstyled on non-plugin admin pages and the primary
  button lost its contrast.** The notice CSS only loaded on the plugin's
  own screens, yet the banners fire on every admin page; and inside a WP
  `.notice` the core link styling overrode the button colour, leaving
  washed-out, underlined text. A self-contained stylesheet now ships on
  every admin screen and the button contrast is locked in.

### Changed

- **2FA login no longer auto-sends the email or SMS one-time code.**
  Previously, when a user's primary method was email (or SMS), the code
  was dispatched the moment the challenge screen loaded — before the user
  could pick a method. Both delivery methods now start in their request
  phase: the user selects the method and clicks "Send code" before
  anything goes out. This stops unsolicited mail/SMS and avoids burning
  the rate limit or relay quota for a method the user did not choose.
  Stateless methods (authenticator app, passkey, recovery codes) are
  unaffected and show their input directly. The "Send code" button and
  the no-JavaScript `resend_email` / `resend_sms` fallback already drove
  the on-demand send path; only the eager dispatch was removed.
- **All backend admin notices now share one renderer** with a consistent,
  design-system look (no more mixed WordPress-core and custom styles).
- **The 2FA onboarding wizard is leaner.** Trimmed the welcome explainer
  cards, per-method bullet lists, the authenticator-app link list and the
  celebration overhead so each step shows less at once.

### New

- **The guided 2FA wizard is now reachable directly.** The "Two-factor
  authentication is recommended" reminder banner and the profile 2FA
  section both link straight into the step-by-step onboarding wizard.

## [2.0.19] — 2026-05-29

### Security

- **Fatal error on the 2FA settings tab and 2FA setup-wizard step.**
  When `2fa_enforce_roles` or `2fa_allowed_methods` were stored as an
  array (the network-default form), `render_global_settings()` and the
  wizard called `json_decode()` on a value that was already an array —
  a `TypeError` on PHP 8 that took the whole page down. Reads now go
  through the format-tolerant `Option_Routing::to_array()` and the
  canonical `Option_Routing::get_network_enforce_roles()`.
- **`wp reportedip 2fa enforce` silently dropped stored roles.** The
  CLI cast the option to string before `json_decode()`, so an
  array-stored enforce-roles list decoded to empty and the command
  overwrote it. It now reads through `Option_Routing::to_array()` too.

### New

- **German translation (de_DE, formal "Sie").** All user-facing
  strings (~1845) are now translated into German and shipped as
  `languages/reportedip-hive-de_DE.po` / `.mo`. Source strings stay
  English; WordPress loads the German translation automatically when
  the site language is German, so other locales are unaffected.
- **Translation-freshness gate.** `composer i18n:check` (also
  `./run.sh i18n-check`) fails when the POT is stale, the German PO
  has untranslated or fuzzy entries, or the compiled MO is out of
  sync with the PO. It runs as a step in `check-all` and as a
  blocking CI job, so the translation stays current with the source
  on every change. `composer i18n` refreshes POT → PO → MO in one
  step.

### Changed

- Bumped the tested-up-to header to WordPress 7.0.
- Regenerated `languages/reportedip-hive.pot` from the current source
  (the committed template had drifted out of date).
- Quieted the WordPress.org Plugin Check on shipped code only:
  documented `phpcs:ignore` annotations for the legitimate `.htaccess`
  writability probes and the plugin-table admin queries, a correctly
  placed translators comment in the setup wizard, and a trimmed Upgrade
  Notice section. Dev-only tooling (`bin/`, `tests/`, CI config, dotfiles)
  is excluded from the check so it validates only what ships.
- Removed an obsolete manual option-routing debug script
  (`scripts/option-roundtrip-test.php`).

## [2.0.17] — 2026-05-29

### Fixed

- **2FA-enforcement lockout no longer masked as "Invalid
  credentials".** When an enforced user exhausted the 2FA
  onboarding skip quota, the user-enumeration login-error mask
  rewrote the real reason ("Two-factor authentication required —
  skip quota exhausted, contact an administrator") down to the
  generic "Invalid credentials.", sending locked-out admins on a
  pointless password reset. The mask now passes 2FA messages
  through on the login action: that block fires only *after* the
  password has validated, so the username is already confirmed and
  surfacing the reason leaks nothing about user existence. Genuine
  credential errors stay masked.

## [2.0.16] — 2026-05-27

### Changed

- **Unified Pro-promo frequency cap.** New
  `ReportedIP_Hive_Promo_Manager` is the single source of truth for
  "may this upgrade hint show now?" — kill-switch (Settings →
  Notifications), 90-day global cap per admin across all promo
  surfaces, 60-day cooldown after a dismiss per feature, and a
  permanent per-user opt-out. WooCommerce 2FA banner, Frontend-2FA
  inline upsell card, Mail/SMS-Relay dashboard card and the
  Hardening Mode info block now all route through it instead of
  carrying their own ad-hoc cooldowns. A free-tier admin will see
  at most ~4 dezente promo touches per year.
- **Removed a duplicate Frontend-2FA upsell card from the Hardening
  Mode tab.** The card belonged to the WC-Frontend-2FA feature and
  had no business advertising itself on the Hardening tab.
- **`Two_Factor_Recommend` soft banner.** Dismiss cooldown raised
  from 30 minutes to 14 days and a new "Don't show this again" link
  records a per-user permanent opt-out. The hard-block onboarding
  path for privileged roles is untouched — security recommendation
  still wins over comfort.

### Added

- **Cap-status notice.** When the mail or SMS relay returns HTTP 402
  (monthly cap) or 429 (recipient/site backoff) the provider stamps
  a network-wide `reportedip_hive_relay_cap_state_*` site-transient.
  Admin pages render a non-promotional warning notice (priority 5,
  dismissible for 24 h) explaining that mails currently fall back to
  `wp_mail()` and SMS-2FA is paused, with a link to the quota
  details. The cap state is auto-cleared by the next successful
  `/relay-quota` refresh whose snapshot shows usage below the limit.
- **Quota-warning mails (PRICING-PLAN.md §8).** New
  `ReportedIP_Hive_Quota_Notifier` evaluates the relay-quota
  snapshot after every six-hour cron refresh and sends one factual
  mail to the alert-recipient list when a channel crosses 80 % or
  100 % of its monthly allowance. Per channel + stage there is a
  30-day cooldown, and the cooldown automatically resets at every
  new billing period (`period_start` flip).
- **Welcome / goodbye mail on tier change.** `Tier_Upgrade::on_tier_changed`
  now also handles the downgrade path: clears the stale post-upgrade
  banner state, soft-disables the WooCommerce Frontend-2FA toggle
  (data preserved for seamless re-upgrade) and sends a short,
  factual mail. Upgrades trigger a similarly factual welcome mail
  pointing at the remaining setup steps. Both mails can be
  suppressed via the new Settings → Notifications toggle.
- **Settings → Notifications.** Three new toggles: hide all upgrade
  hints (default off — hints stay on), email when the relay quota
  reaches 80 % / 100 %, email when the plan changes. Security
  recommendations and operational status notices are deliberately
  not gated by these toggles.

### Fixed

- **Hardening Mode no longer re-arms itself after natural expiry or
  admin deactivate when the same minute-bucket is still in the 2 h SQL
  lookback.** The per-`time_window` marker now stores the canonical
  strongest reason payload (not just a presence flag), so suppression
  survives the lazy wipe of `TRANSIENT_REASON` in {@see is_active()}
  and the explicit clear in {@see deactivate()}. The activate path
  compares the candidate against the marker payload when the live
  reason transient is gone, instead of treating "no live reason" as
  "fresh trigger". `deactivate('admin')` now also clears the marker
  for the live reason's `time_window` so an admin override sticks.
- **TTL-low extension keeps the strongest reason and the suppression
  marker alive past 25 h.** Previously `TRANSIENT_REASON` (TTL =
  duration + 1 d) expired while `TRANSIENT_UNTIL` kept getting bumped
  by hourly extensions; once the reason was gone the next weak sweep
  fell into the full-activate path and clobbered the original
  strongest trigger payload with a high-severity event. The extension
  branch now refreshes the marker TTL alongside `TRANSIENT_UNTIL` and
  records a marker for the candidate's `time_window` so a follow-up
  sweep cannot trigger another `hardening_mode_extended` log for the
  same bucket.
- **Per-row `coordinated_attack_detected` critical events are now
  suppressed across cron sweeps for the same minute-bucket.**
  `Security_Monitor::check_coordinated_attacks()` writes a 2 h log
  marker per `time_window` so the structured critical event fires once
  per pattern instead of once per cron tick — the hourly Activity-log
  noise the previous changelog blamed on the cron wrapper entry was in
  fact this inner stream.
- **`cron_sync_reputation()` no longer logs a duplicate critical
  `Coordinated attacks detected` aggregate.** Subsumed by the inner
  per-pattern `coordinated_attack_detected` events above.
- **Enterprise / Honeypot tier no longer hits the queue `no_quota`
  short-circuit when the upstream stamps `remaining_reports = 0` on
  an unlimited account.** A shared helper `quota_is_unlimited()`
  drives both `has_report_quota()` and `get_quota_status()`, so the
  unlimited-detection cannot drift between the two helpers; unlimited
  tiers are reported back as `remaining = -1`, matching the `>= 0`
  guard in `process_report_queue()`.
- **Relay-mail / relay-sms 429 backoff now uses `set_site_transient`
  (network-wide on multisite), preserves the original HTTP status
  code in the cooldown payload, parses HTTP-date `Retry-After`
  headers correctly, and caps the cooldown at `DAY_IN_SECONDS` (not
  one hour).** Each fix corrects a real observable behaviour on
  alre.de's relay-mail history: per-blog transients let three
  subsites independently flood the per-recipient server cap; the
  prior synthetic 429 masked a 402 monthly-cap as a "too many sends"
  message and hid the upgrade prompt; HTTP-date Retry-After cast to
  `(int)` collapsed to 0 → 5-minute default; the 1 h clamp generated
  hourly probes against a 24 h server cap.
- **2FA SMS code transient is now written AFTER the provider accepts
  the send, not before.** A pre-dispatch write left stale code hashes
  in `_transient_rip_2fa_sms_code_<user>` for 10 minutes when the
  relay short-circuited (e.g. via the new client_backoff cooldown),
  and the local backoff ladder never advanced because
  `record_send()` ran on the success branch.
- **Admin "Send test mail" now surfaces a banner when the relay
  fallback to `wp_mail()` was used.** A new
  `ReportedIP_Hive_API::is_relay_in_backoff()` probe runs before the
  mailer call so the AJAX response can warn the admin that they did
  not just validate the managed-relay path.
- **Plugin uninstall now also flushes plugin transients.**
  `delete_all_plugin_options` enumerated `option_name LIKE
  'reportedip_hive_%'`, which does not match the `_transient_…` /
  `_site_transient_…` rows WordPress stores transients under. The new
  `reportedip_hive_hardening_seen_*`, `reportedip_hive_hardening_logged_window_*`
  and `reportedip_hive_relay_bo_*` keys would otherwise survive
  uninstall and confuse a fresh re-install.
- **Logs UI dropdown lists the new event types.** Operators can now
  filter for `hardening_mode_extended` and the structured
  `coordinated_attack_detected` events directly.

## [2.0.15] — 2026-05-21

### Fixed

- **Multi-recipient admin notifications now actually go out via the
  managed mail relay.** `Security_Monitor::send_admin_alert()`
  (`class-security-monitor.php:912`) builds the recipient field as
  `implode(', ', $recipients)` — the standard WP_Mail convention. The
  Hive Relay REST endpoint (`POST /relay-mail` in `reportedip-service`)
  validates a single address per request via
  `sanitize_email` + `is_email`, so `"a@x, b@y"` 422s and the whole
  alert is dropped. The site logs `mail_failed` and the admin never
  sees the notification.
- `ReportedIP_Hive_Mailer::send()` now detects a comma-separated `to`
  field, splits it into individual recipients and dispatches one mail
  per address through the same provider stack. `split_recipients()`
  trims/filters empty fragments; `dispatch_one()` houses the existing
  render → provider → log path so the per-recipient bookkeeping stays
  identical to the previous single-recipient flow. Local `wp_mail`
  fallback is unaffected (it accepts comma-lists natively, but the
  split path is consistent across providers).

### Notes

- The 14-day per-event cooldown and the burst-suppression cap in
  `send_admin_alert()` still apply to the **first** recipient — once
  the cooldown fires for that combination, the remaining recipients in
  the same call all benefit from the same `set_transient()` slot.
  That matches the legacy behaviour and avoids N× the cooldown
  bookkeeping per delivery.

## [2.0.14] — 2026-05-20

### New

- **Decoy bait-path list expanded from 16 to 40 entries.** New additions:
  - Full `wp-config.php.*` Backup family — `.bak`, `.old`, `.save`,
    `.orig`, `.swp`, `.txt`, trailing `~`.
  - More `.env*` Backups — `.production.bak`, `.local.bak`, `.orig`.
  - Joomla `configuration.php.bak`.
  - Common SQL dumps at the webroot — `dump.sql`, `database.sql`,
    `backup.sql`, `db.sql`.
  - Apache `.htpasswd`, `.htaccess.bak`.
  - Cloud credentials — `.aws/credentials`, `.aws/config`.
  - SSH keys — `.ssh/id_rsa`, `.ssh/authorized_keys`.
  - Private-key files at the webroot — `id_rsa`, `private.key`,
    `server.key`.
- **`nginx_snippet_exact_match()`** — new alternative server snippet
  that emits one `location = /<bait>` line per default path. Exact-match
  locations have higher nginx priority than any regex location, so the
  snippet still works when the host template ships a
  `location ~ /\.  { deny all; }` dot-file deny rule before the site's
  custom directives (typical on ISPConfig). The Settings tab shows both
  variants — regex form (plain nginx) and exact-match form (ISPConfig
  & managed stacks) — with a short hint when to pick which.

### Changed

- **`is_decoy_path()` accepts nested decoy paths with the same
  one-optional-subdir prefix rule the rewrite regex uses.** Detection
  matches `/.aws/credentials`, `/site-a/.aws/credentials` and
  `/wp-content/.aws/credentials`, but stops at two or more subdir
  segments (`/wp-content/uploads/.ssh/id_rsa` does NOT match). Keeps
  PHP detection consistent with the auto-managed `.htaccess` block and
  both nginx snippets.

## [2.0.13] — 2026-05-20

### Fixed

- **Every locally auto-blocked offender is now actually reported to the
  community.** `Database::is_recently_processed()`
  (`class-database.php:545`) used to count rows in
  `wp_reportedip_hive_blocked` and short-circuit with
  `reason=recently_blocked` whenever a block existed for that IP in the
  last 24 hours. But the auto-block is the **direct consequence** of the
  detection that is calling `queue_api_report()` — so every fresh hit
  was guaranteed to find its own block in the table and skip the queue
  insert. End result: `Total API calls > 0`, `Submission counter = 0`
  forever, `api_queue` permanently empty.
- The blocked-table check is removed. Only the existing `api_queue`
  check (rows with `status=completed` in the last 24 h) gates the
  cooldown now, which is the dedup behaviour the helper is supposed to
  enforce. Combined with the 2.0.12 Decoy fix, every sensor
  (`decoy_pathblock_hit`, `user_enumeration`, `failed_login`,
  `scan_404`, `wc_login_failed`, `2fa_brute_force`, …) now reaches the
  Hive API after the local block.

### Tests

- `ApiQueueRecoveryTest::test_is_recently_processed_filters_to_completed_only`
  updated — the helper now executes a single prepared query against
  `api_queue` (no more redundant `blocked`-table count).
- New `ApiQueueRecoveryTest::test_recently_blocked_ip_is_no_longer_excluded`
  regression-guards the fix.

## [2.0.12] — 2026-05-20

### Fixed

- **Decoy Path Block now actually reaches the community-report queue.** The
  2.0.11 rewrite assumed `Logger::log_security_event()` would forward
  `severity=high` events to the API automatically — it does not. The logger
  only writes to the local `logs` table; queueing to `api_queue` always
  goes through `Security_Monitor::report_security_event()` explicitly
  (see `class-security-monitor.php:521`). `Decoy_Path_Block::maybe_block()`
  now calls both: local log first (so the event is visible on the
  dashboard even if the community layer is throttled / disabled / local
  mode), then `report_security_event()` so Hive picks the right category
  IDs, runs the cooldown / dedup checks and inserts the row in
  `api_queue`.
- **`Security_Monitor::$default_category_mapping`** gets a new entry
  `decoy_pathblock_hit => [21, 15]` (admin-scanning + reputation),
  consistent with the existing `admin_scanning` mapping. Without this
  entry the call would have fallen through to the generic `[15]`
  fallback.

### Notes

- Historical `decoy_pathblock_hit` rows in `logs` from 2.0.9 → 2.0.11
  cannot be retro-reported: the `queue_api_report()` dedup window
  (1 h pending / 15 min failed / 24 h cooldown) would suppress them
  anyway. Fresh hits after the upgrade start queueing as expected.

## [2.0.11] — 2026-05-20

### Changed

- **Decoy Path Block is now detect-and-report, not detect-and-block.** The
  sensor in `includes/class-decoy-path-block.php` no longer calls
  `IP_Manager::block_ip()` — a single false-positive (backup plugin writing
  `wp-config.old.php`, admin testing the bait URL, an old crawler probing
  stale paths) would otherwise have locked the site out of its own traffic
  for 24 hours. The hit is still logged at severity `high` and forwarded to
  the community-reputation queue by the existing `Logger` → `api_queue`
  pipeline; the visitor still sees a per-request 403.
- **Server-config snippets now rewrite to WordPress, not `[F,L]` / `return
  403`.** An Apache `[F,L]` would skip PHP entirely and silence both the
  local log and the community report — defeating the sensor. The new
  Apache snippet is `RewriteRule ^ /index.php [L,QSA]`; nginx equivalent
  is `rewrite ^ /index.php last;`. Both cover Multisite subdir prefixes
  (`/site-a/.env.backup`) via the same regex group the PHP basename
  fallback uses.

### New

- **`includes/class-decoy-htaccess-writer.php`** — Hive now auto-manages
  the Apache rewrite block inside the site's root `.htaccess` (markers
  `# BEGIN ReportedIP Hive Decoy` / `# END ReportedIP Hive Decoy`). The
  block is placed ABOVE `# BEGIN WordPress` so it wins over WP's
  `RewriteCond %{REQUEST_FILENAME} -f` short-circuit — that is the only
  position where a real bait file on disk (`.env.backup` left by
  Composer, etc.) is reliably routed through WordPress instead of being
  served directly by Apache. The writer uses WP-Core
  `insert_with_markers()` (no roll-your-own parser), self-heals once per
  hour on `admin_init`, hooks activation / deactivation to write / remove
  the block, and exposes `is_writable_target()` / `is_block_present()`
  for the Settings status box.
- **Settings UI** (`admin/class-admin-settings.php`) — status box shows
  "Auto-managed" (success) when the writer holds the block, "Read-only"
  (warning) when `.htaccess` is not writable or this server does not
  use one (nginx). The Apache + nginx snippets remain visible below as
  live preview and copy-paste fallback.

### Removed

- Option `reportedip_hive_decoy_block_hours` is gone (no local block, no
  duration knob). `Defaults::SAFE_OPTIONS` and the settings form lose
  the key.

### Migrations

- `Migration_Manager::migrate_to_v7()` runs once and
  - deletes all rows in `wp_reportedip_hive_blocked` with `reason LIKE
    'decoy_pathblock:%'` — cleanup of stale entries written by 2.0.9 /
    2.0.10,
  - deletes the now-defunct `reportedip_hive_decoy_block_hours` option
    site-wide on Multisite and locally on single-site.

## [2.0.10] — 2026-05-20

### Fixed

- **Decoy Path Block respects report-only mode.** `maybe_block()` was sending
  the 403 + `exit` even when `reportedip_hive_report_only_mode` was active.
  The event was still logged (correct) but the user-visible block surfaced
  during audits. The report-only guard now runs before the 403/exit branch.
- **Decoy Path matcher recognises subdirectory-prefixed bait names.** On
  Multisite subdir installs the request URI for a subsite is
  `/site-a/.env.backup`. The matcher previously compared the full path only
  and missed the bait. Added a basename fallback: the canonical full-path
  match keeps running first; only if it misses does the matcher also check
  the basename against the bait list. New unit-test case
  `test_basename_match_for_multisite_subdirs` covers the scenario.

### Notes

- Behaviour on `.php`-suffixed bait paths inside a Multisite subdir (e.g.
  `/site-a/wp-config.old.php`) is unchanged — the default WordPress `.htaccess`
  rewrites strip the leading subsite segment and Apache returns 404 before
  PHP loads. That is exactly what the optional server-level `.htaccess` /
  nginx snippets in Settings → Detection are for.

## [2.0.9] — 2026-05-21

### Security

- **Decoy Path Block (Free).** New sensor in `includes/class-decoy-path-block.php`
  bans the source IP on the **first** request to a known bait path
  (`.env.backup`, `wp-config.old.php`, `db-dump-master.sql.php`,
  `admin-shell-console.php`, `debug-logs-temp.php`, …). Distinct from the
  existing `Scan_Detector` which counts honeypath-404s in an N-of-Y window —
  legitimate visitors never request these paths, the first hit IS the attack.
  Default 24-hour block, configurable in Settings → Detection. Default-on,
  available on every tier.
- **No physical decoy files.** Detection lives entirely in the request
  pipeline; nothing is dropped on disk. Compatible with every backup /
  migration workflow.
- **Optional server-level snippets.** The Settings tab exposes ready-to-paste
  `.htaccess` and nginx snippets so admins can block these paths at the
  server level (pre-PHP) if they want extra hardening. The plugin does NOT
  write to server configs.

### New

- Filter `reportedip_hive_decoy_paths` to extend the built-in bait list.
- `Mode_Manager::FEATURE_MATRIX` entry `decoy_pathblock`.
- Options `reportedip_hive_decoy_pathblock_enabled` (bool, default true) +
  `reportedip_hive_decoy_block_hours` (int 1–168, default 24).
- Log event `decoy_pathblock_hit` (severity high). Hardening-Mode log
  decoration from 2.0.8 applies automatically.

## [2.0.8] — 2026-05-20

### Security

- **Hardening Mode on coordinated attacks (Professional plan and higher).**
  When `Security_Monitor::check_coordinated_attacks()` detects ≥ 3 IPs /
  ≥ 20 failed logins in the same minute, the plugin activates a
  network-wide hardening window (default 60 min, configurable 5–360).
  During the window:
    - failed-login threshold tightens from 5 / 15 min → 2 / 5 min
    - reputation block threshold from 75 % → 60 %
  Effective thresholds are always `min( admin-configured, hardening
  default )` — stricter manual values are never softened.
- **Realtime detection.** The coordinated-attack probe now also runs
  inside `wp_login_failed` (debounced to once per 60 s via a site-wide
  transient). Reaction time drops from up to one hour (cron-only) to
  under a minute. Toggle in the new Settings tab; the hourly cron stays
  as a fallback.

### New

- **`ReportedIP_Hive_Hardening_Mode`** helper class
  (`includes/class-hardening-mode.php`) exposes `is_active()`,
  `expires_at()`, `current_reason()`, `is_available()`, `activate()`,
  `deactivate()` and the three `effective_*` clamps used by
  `pre_auth_check()` and `check_failed_login_threshold()`.
- **PRO-tier feature flag** `hardening_mode` added to
  `Mode_Manager::FEATURE_MATRIX` with `requires_tier = 'professional'`.
  Free / Contributor see the Settings tab with a PRO-upsell card; the
  master toggle and sub-fields are disabled.
- **Dedicated Settings tab "Hardening Mode"** with master toggle and
  five sub-settings (duration, realtime detection, failed-login
  threshold, failed-login timeframe, reputation threshold). Sub-fields
  visually grey out while the master is off (`assets/js/admin.js`).
- **Admin-bar indicator.** While hardening is active the WordPress admin
  bar shows a red node with countdown + dropdown (trigger reason,
  manage link). Implemented in `ReportedIP_Hive_Admin_Bar`
  (`includes/class-admin-bar.php`); inline-styles attached to
  `admin-bar` so the indicator is visible on every wp-admin page, not
  just plugin pages.
- **WP-CLI commands** `wp reportedip hardening status|activate
  [--minutes=<int>]|deactivate`.
- **AJAX action** `reportedip_hive_hardening_deactivate` for the
  Settings-tab banner button (nonce + `manage_options` /
  `manage_network_options`).
- **Log markers during hardening.** `Logger::log_security_event()` now
  decorates every event written while
  `Hardening_Mode::is_active()` with `details.hardening_active = true`
  and `details.hardening_expires_at`. The Logs admin table renders a
  `Hardening` badge next to the event type and offers a "During
  Hardening only" filter checkbox. Dedicated events
  `hardening_mode_activated` (severity `high`) and
  `hardening_mode_deactivated` (severity `low`) record activations and
  the actor (`admin` / `cli` / `expired`).

## [2.0.7] — 2026-05-20

### Changed

- **Hourly API rate-limit is now split into three independent buckets.**
  `reputation` (IP lookups), `submission` (report queue / positive
  feedback) and `meta` (verify-key, quota sync, notification config)
  each have their own counter. A bot-driven reputation scan storm can
  no longer freeze the report queue or starve quota sync — the buckets
  are isolated, and each one tracks its own `set_transient(
  reportedip_hive_hourly_api_calls_<bucket>, … )`.
- **Caps now scale with the active tier.** New
  `ReportedIP_Hive_Mode_Manager::default_api_rate_limits_for_tier()`
  resolves the per-bucket caps from the current tier
  (Free 150/h reputation · Professional 3 000/h · Business 12 000/h ·
  Enterprise unlimited), derived from the daily quotas with a 3× spike
  factor so a single hour cannot burn the whole daily allowance.
- **`Max API calls per hour` setting accepts 0 = auto.** Migration v6
  resets the value to `0` on every install (including manual
  overrides) so tier-bound caps kick in automatically. A positive
  number remains a uniform override across all three buckets. Min is
  now 0 (was 10), max raised to 100 000 (was 10 000).
- **Counter telemetry now tracks all outgoing endpoints.** Previously
  only `check_ip_reputation()` incremented the counter, so the report
  queue and meta calls were invisible. `report_ip()`,
  `report_positive_feedback()`, `verify_api_key()`, `get_relay_quota()`,
  `sync_notification_config()`, `get_categories()` and
  `test_connection()` now call `track_api_call()` with the correct
  bucket so the admin "API call usage" card and the new bucket counters
  reflect reality.

### New

- **`Mode_Manager::get_api_rate_limit_snapshot()`** returns `{tier,
  source:'auto'|'manual', limits:{reputation,submission,meta},
  used:{reputation,submission,meta}}` — single contract for the admin
  card, the degraded-banner helper and future dashboards.
- **`Mode_Manager::is_community_layer_degraded()`** is true when
  Community mode is active and either the server-side 429 reset is
  pending or any bucket sits at ≥ 80 % of its effective limit.
- **`render_api_usage_card()` shows three separate "This hour"
  buckets** (reputation / submission / meta) with the tier source
  label ("auto · Free tier" or "manual override"). Unlimited buckets
  render as ∞.
- **Inline admin banner.** When `is_community_layer_degraded()` flips
  to true the Hive admin pages show a `rip-alert--warning` banner
  explaining that the local firewall remains active and the community
  threat-check pauses until the hourly counter resets. Links to the
  Community / pricing page for a tier upgrade.

### Fixed

- **`process_report_queue()` now consults the right bucket.** The
  pre-flight `is_rate_limited()` check inside the queue cron now asks
  the `submission` bucket only, so a saturated reputation bucket
  cannot block report drains.
- **`has_report_quota()` mirrors that** so the in-line `report_ip()`
  guard agrees with the queue-cron guard.

### Migration

- Schema version bumps to **6**. `Migration_Manager::migrate_to_v6()`
  resets `reportedip_hive_max_api_calls_per_hour` to `0` (auto /
  tier-bound) for every installation, idempotent on re-run, and drops
  the legacy single-counter transient so the new per-bucket counters
  start clean.

## [2.0.6] — 2026-05-19

### Fixed

- **2FA onboarding buttons stay readable under hostile themes.** The
  filled button variants (`rip-button--primary/success/danger`) on the
  `/wp-admin/admin.php?page=reportedip-hive-2fa-onboarding` page now
  pin their text to white via `!important`. Some themes ship a global
  `body button { color: … }` rule that, despite the design-system's
  scoped selector, won on specificity and produced unreadable buttons
  (white text on white background) on those installs.
- **Setup wizard now actually opens after a fresh activation.** The
  activation hook wrote `set_site_transient(…activation_redirect…)`, but
  the redirect guard in `admin_init` consumed it with `get_transient()`
  — read and write hit different storage keys (`_site_transient_…` vs.
  `_transient_…`) on single-site as well as multisite, so the wizard
  redirect never fired. Both halves now use the `_site_transient_`
  family.

### Changed

- **Admin email burst protection.** `send_admin_notification()` keeps
  the existing per-(IP × event_type) 60-minute cooldown but adds a
  second, global per-event_type cap (`reportedip_hive_notify_event_cap_minutes`,
  default 15 min). During a distributed brute-force the first alert
  still goes out immediately; further alerts of the same `event_type`
  from any IP are folded into a suppression counter and surfaced as a
  "Burst suppression: N additional alerts (M distinct IPs) since …"
  block — both in the HTML and the plain-text body — on the next
  outgoing mail. Suppressed alerts continue to land in the logs as
  `notification_event_cap_suppressed` events. Solves the situation
  where the relay server's per-recipient progressive backoff was
  rejecting (HTTP 429) tens of identical alerts and the wp_mail()
  fallback was flooding the operator's mailbox.

## [2.0.5] — 2026-05-18

### Security

- Search engine and AI crawler User-Agents (Googlebot, Bingbot, DuckDuckBot,
  Applebot, YandexBot, GPTBot, ChatGPT-User, ClaudeBot, PerplexityBot,
  Amazonbot, CCBot, MetaExternalAgent and others) are now excluded from the
  404 burst trigger (`ReportedIP_Hive_Scan_Detector`) and the REST burst
  trigger (`ReportedIP_Hive_REST_Monitor`). Sites no longer fall out of
  Google or AI-crawler indexes because a legitimate sweep over stale URLs
  pushed the source IP into the progressive block ladder.
- Honeypot-path detection (`/.env`, `/wp-config.php.bak`, `/.git/config`,
  `/phpmyadmin/`, `/.aws/credentials`, `/.ssh/id_rsa`, …) stays active for
  **all** visitors, including requests that present a spoofed bot
  User-Agent — a "Googlebot" request to `/.env` IS the attack indicator
  and continues to trigger immediately.

### New

- `ReportedIP_Hive_Bot_Allowlist` class — stateless, request-cached
  User-Agent pattern matcher. Default list covers the major search
  engines, social-preview crawlers and AI/LLM crawlers; extensible via
  the `reportedip_hive_bot_allowlist_patterns` filter.
- New option `reportedip_hive_bot_allowlist_enabled` (default `true`) with
  a toggle in **Settings → Protection → 404 / Scanner detection** so
  operators can disable the bypass site-wide if needed.

## [2.0.4] — 2026-05-13

### Changed

- **SMS routing decisions move from the client to the relay server.** The
  29-country EU country-code whitelist that `ReportedIP_Hive_Phone_Validator`
  enforced on the plugin side is gone. The plugin now validates only that
  the input is a well-formed E.164 number and forwards it to the relay;
  the relay returns HTTP 422 with code `country_not_supported` for any
  destination it does not serve, mapped to a typed `WP_Error`
  (`reportedip_sms_country_not_supported`) so the 2FA UI can encourage
  TOTP, Email or a passkey instead. This removes the situation where a
  fully valid US/UK/AU number was rejected client-side even though the
  managed relay would have delivered the SMS without complaint.
- **`Two_Factor_SMS::sanitize_phone()` no longer hard-rejects non-EU
  numbers.** The blanket "Only EU phone numbers are supported for
  SMS-2FA." error is removed; format validation stays.
- **`SMS_Provider_Relay::send()` is consolidated.** Inline duplicates of
  the HTTP 402 / 429 handling are replaced with a single call into
  `interpret_result()`, which now also maps the new 422
  `country_not_supported` response.
- **UI / docs / wizard copy reworded.** Setup wizard, admin settings,
  user 2FA admin, frontend onboarding template, README and readme.txt
  no longer claim "EU-only" delivery; they describe worldwide routing
  with anti-fraud capping and the unsupported-destination behaviour.

### Deprecated

- `ReportedIP_Hive_Phone_Validator::is_eu()` and `::get_country_code()`
  retained as no-op compatibility shims for any out-of-tree caller —
  `is_eu()` now returns true for every valid E.164 input,
  `get_country_code()` returns a best-effort 1–3-digit prefix without
  consulting any whitelist. Callers inside this plugin no longer use
  either; both will go away in a future major.

### Removed

- `ReportedIP_Hive_Phone_Validator::DEFAULT_EU_CODES` constant,
  `::get_whitelist()` helper, the option
  `reportedip_hive_eu_phone_country_codes` and the filter
  `reportedip_hive_eu_phone_country_codes`.

### Tests

- `SmsProviderRelayTest` rewritten around the new contract: US numbers
  pass through to the relay, garbage strings are rejected client-side,
  HTTP 422 `country_not_supported` maps to
  `reportedip_sms_country_not_supported`. Locked-down `region()` text
  flipped from `EU (via reportedip.de)` to
  `Worldwide (via reportedip.de)`. Full unit suite stays at 463/463;
  multisite suite at 19/19.

## [2.0.3] — 2026-05-12

### Fixed

- **Password reset is no longer gated for users without a real second
  factor.** The reset challenge used to fire as soon as any 2FA method was
  set on the account — including email, which the gate then excluded from
  the picker. Users who had only email-2FA enrolled (plus stale recovery
  codes from an earlier setup) were forced onto a recovery-code prompt
  for codes they may never have stored, with no way out except contacting
  an admin. The gate now uses `should_gate_user()`, which fires only when
  at least one non-excluded factor (TOTP, SMS, WebAuthn) is enrolled.
  Email-only or recovery-codes-only users get the standard WordPress
  password reset flow.
- **API-stats counter no longer warns on partial state.** `track_api_call()`
  read the stored `reportedip_hive_api_stats` array and accessed
  `successful_calls` / `failed_calls` directly. If the option was missing
  one of those keys (e.g. after a partial migration), PHP emitted an
  `Undefined array key` warning that surfaced as visible output ahead of
  cookie / redirect headers on the very next request. The helper now
  merges the stored array on top of the full defaults before incrementing.

### Tests

- New unit coverage for `Two_Factor_Reset_Gate::should_gate_user()` plus a
  source-pattern lock so the gate is forced to route both
  `on_validate_reset()` and `on_password_reset()` through the helper.
- Multisite E2E `network-active` smoke test now asserts the row's `active`
  class and the "Network Deactivate" action, matching what current
  WordPress core actually renders. The previous `span.network-active` /
  `td.column-active` selectors targeted markup that is no longer emitted.

## [2.0.1] — 2026-05-08

Fixes silent failures and invisible errors on the password-reset 2FA
challenge page (`wp-login.php?action=reportedip_2fa_reset`), and lifts
the verify switch into a shared helper so the login + reset surfaces
can no longer drift apart.

### Fixed

- **Wrong recovery / TOTP / SMS code now shows an error.** The challenge
  page used to render the failure only via `login_header()` — third-party
  plugins that filter `wp_login_errors` would strip it, and the WP-default
  `#login_error` block was outside our card. Errors are now rendered
  inline as a `rip-alert--danger` block inside the `.rip-2fa-challenge`
  card and remain visible regardless of `wp_login_errors` filters.
- **Initial SMS / email is dispatched on first land.** Previously the
  challenge page only sent an SMS when `?method=sms` was already in the
  URL — which never happened on the first redirect from
  `validate_password_reset`. Users with SMS-only 2FA saw an empty form
  and no message. The dispatch now happens in `on_validate_reset()`
  before the redirect, mirroring the login flow.
- **Send-failures are surfaced.** The `WP_Error` returned by
  `Two_Factor_SMS::send_code()` / `Two_Factor_Email::send_code()` is no
  longer discarded — it lands in the inline error alert with the
  provider's reason (`SMS sending is not configured.`,
  `No phone number is stored for this user.`, …) and is logged under the
  new `2fa_reset_send_failed` event.
- **CSS scope covers the reset action.** `assets/css/two-factor.css`
  selectors now include `body.login-action-reportedip_2fa_reset` so the
  page chrome, font, and `#login_error` styling match the login flow.

### New

- **Server-side resend.** `?resend_sms=1` / `?resend_email=1` URL
  parameters trigger a fresh OTP without losing the challenge session,
  matching the login flow's resend pattern. The challenge template
  renders a "Resend the SMS / email code" link with the cooldown from
  `Two_Factor_SMS::get_resend_wait_seconds()` /
  `Two_Factor_Email::get_resend_wait_seconds()`.
- **Method-health assessment.** `assess_methods_health()` checks each
  eligible method for usability before render: TOTP secrets are checked
  for presence and decryptability, SMS for provider readiness and a
  stored phone number, WebAuthn for the provider class. Methods that
  fail the check are removed from the picker. When **none** of the
  eligible methods is usable the gate hard-stops with a new
  `2fa_reset_no_usable_method` event and a "contact your administrator"
  page — instead of dropping the user into an "Invalid code" loop.
- **Admin alert covers all lockout reasons.** The previous
  `notify_admins_email_only_block()` is now `notify_admins_user_locked_out()`
  and accepts a reason key (`email_only`, `no_eligible_method`,
  `no_usable_method`). For the new `no_usable_method` case the email
  body lists which methods are broken and why, so the admin can fix the
  account directly without a back-and-forth.

### Changed

- **Shared verify helper.** The per-method verification switch (TOTP /
  SMS / Email / WebAuthn / Recovery) is extracted into
  `ReportedIP_Hive_Two_Factor_Verifier::verify_method()`. Both
  `Two_Factor::verify_2fa_code()` and `Two_Factor_Reset_Gate::verify_method_code()`
  delegate to it. The reset path passes a callback so its surface-specific
  `2fa_reset_verify_internal_error` events still fire on
  `missing_secret` / `decrypt_failed`. No behaviour change for the login
  flow.

## [2.0.0] — 2026-05-08

Promotes `2.0.0-beta.1` to GA after a week of dual-stack hardening on the
WPMU+single-site Docker setup. All beta-1 functionality is unchanged;
this section lists the additions and fixes that landed on top.

### New

- **Per-blog resolve-cache isolation**: `Option_Routing::cache_key()` now
  suffixes the bucket with `get_current_blog_id()` so a `switch_to_blog()`
  in the same request no longer leaks resolved overrides across sub-sites.
- **`Option_Routing::get_network_enforce_roles()` / `get_site_enforce_roles_extra()`** —
  pure-list helpers consumed by the Site-2FA UI to draw the
  "enforced by network" badge without merging the two lists.
- **Network-admin Settings-API save handler**: forms now post to a custom
  `network_admin_edit_reportedip_hive_save_settings` route. WordPress'
  `options.php` is wp_options-only on multisite, so saves silently
  vanished into the main site's wp_options instead of landing in
  sitemeta. The new handler hands the value to `update_site_option`,
  which routes through `sanitize_option` exactly once — fixes complex
  array sanitizers (`enforce_roles`, `allowed_methods`,
  `reminder_hard_roles`) collapsing to `'[]'`.
- **`Two_Factor_Frontend::flush_slug_memo()`** plus the matching
  `update_*_option_*`-hook chain so a Site-2FA save is reflected on the
  same render.
- **Mode_Manager site-option adapter** (`on_mode_site_option_updated`)
  mirrors the single-site `update_option_*` listener for the sitemeta
  storage path so the cached mode and `reportedip_hive_mode_changed`
  action stay accurate on Multisite.
- **Site-2FA UI redesign** in `rip-settings-section` style matching the
  Network 2FA tab: Network configuration block lists every relevant
  network-default with a status badge, Frontend-2FA section gates with
  the standard tier-lock card, additional-roles checklist marks
  network-required roles as `checked + disabled` with an "enforced by
  network" badge.
- **Extended multisite test suite** (`tests/Multisite/OptionRoutingExtendedTest.php`,
  +10 tests) lock in: per-blog cache isolation, setup-slug override,
  pure-network/pure-site role helpers, slug-memo invalidation,
  Mode_Manager sitemeta-hook adapter, network-admin save handler,
  default-slug constant.
- **Round-trip diagnostic** (`scripts/option-roundtrip-test.php`)
  exercises 105 representative option keys via WP-CLI on demand;
  100 % pass on both stacks confirms storage routing is correct.

### Changed

- Direct `get_option`/`update_option`/`delete_option` calls for plugin
  options removed from `Mode_Manager`, `Two_Factor_Frontend`,
  `Two_Factor_Recommend`, `Two_Factor_SMS`, `Two_Factor_Reset_Gate`,
  `Two_Factor_WC_Notice`, `Tier_Upgrade`, `API_Client`, `Cache`,
  `Setup_Wizard`, `Admin_Settings::sanitize_operation_mode()`, plus
  the activation hook in `reportedip-hive.php`. Every read/write of a
  `reportedip_hive_*` key now goes through `Option_Routing` —
  consistent with the beta-1 sweep that missed these later additions.
- `DEFAULT_FRONTEND_SLUG` changed from `2fa-login` (introduced in beta-1)
  back to `reportedip-hive-2fa` so installs that already exposed
  `/reportedip-hive-2fa/` keep their public URL across the upgrade.
- `Site-2FA-Settings` save handler `array_diff()`s network-required
  roles out of the persisted extras so a future network-admin removal
  does not leave stale per-site overrides behind.
- Network admin save no longer pre-sanitises before
  `update_site_option`; relies on `sanitize_option_*` running once
  inside `update_network_option`. Avoids the double-callback regression
  that collapsed array values to `'[]'`.

### Fixed

- 2FA reminder *Hard-block roles* and the WooCommerce *Frontend login*
  toggles silently bounced back to their previous value on every save
  in Network Admin — the Settings API form posted to `options.php`
  which on Multisite writes to wp_options of the main site, while the
  rest of the codebase reads from sitemeta. Fixed via the new
  network-admin save handler.
- API-Key *Test Connection* button on the Network Admin reported "no
  API key configured" right after a successful save because the API
  client read the key from sitemeta but the save had landed in
  wp_options. Same root cause, same fix.
- "Settings saved." admin notice now appears after a successful
  network-admin save (was silently missing).
- Frontend-2FA `Available with Professional plan` upsell card extracted
  into the shared `render_frontend_2fa_pro_upsell()` helper and styled
  with `.rip-pro-upsell__title/__features/__cta` BEM classes —
  removes inline `style=""` and unifies the bullet list across the
  Network and Site-Admin views (the Site variant was missing the WC
  Blocks bullet).
- Inline `margin-left: var(--rip-space-2)` on the "enforced by network"
  badge replaced with a `.rip-badge--inline` modifier (anti-AI-watermark
  rule from `CLAUDE.md`).

### Tooling

- PHPStan bumped from 1.12 to **2.1** and `szepeviktor/phpstan-wordpress`
  from 1.3 to **2.0**. Twelve newly-flagged errors fixed at the source
  (no `@phpstan-ignore` baseline): redundant `!== null` / `!== ''`
  guards after type narrowing, dead `class_exists()` /
  `method_exists()` defensive shims, `defined('DOING_CRON')` swapped
  for `wp_doing_cron()`, `Defaults::get()` return type tightened to
  `int|string`, the IP-export `array_filter` replaced with a foreach
  PHPStan can resolve.
- `phpstan.neon` excludePaths now mark optional dirs with the `(?)`
  suffix that PHPStan 2.x requires; `tests/phpstan-bootstrap.php`
  defines `REPORTEDIP_HIVE_PLUGIN_DIR` as `dirname(__DIR__)` so
  `require_once` paths inside the analysed code resolve to real files.
- `dealerdirect/phpcodesniffer-composer-installer` patch bump to 1.2.1.

### Verified

- 0 PHPCS errors, PHPStan 2.1.54 *No errors*, 435/435 single-site
  PHPUnit assertions, 19/19 multisite PHPUnit assertions, 105/105
  option round-trip pass on both Docker stacks.

## [2.0.0-beta.1] — 2026-05-07

This is a **breaking change** that turns ReportedIP Hive into a fully
network-aware Multisite plugin. Single-site installs auto-migrate on the
first admin visit and behave identically to v1.x.

### New

- **Network-only activation** (`Network: true` in plugin header). On
  Multisite the plugin can only be network-activated; per-site activation
  is hidden by WordPress.
- **Service layer**: three new classes mediate all Multisite-relevant
  access — `Schema`, `Migration_Manager`, `Option_Routing`. Existing
  classes call these services rather than WordPress functions so routing
  changes are one-place work.
- **Hybrid table layout** — all seven plugin tables live under
  `$wpdb->base_prefix` (network-wide). `logs`, `api_queue`, `stats` carry
  a `blog_id` column so the Network Admin can filter and Site Admins are
  auto-scoped. `whitelist`, `blocked`, `attempts`, `trusted_devices` are
  IP-centric or user-global and intentionally have no `blog_id` so a
  single decision applies network-wide.
- **Cross-site brute-force detection** — failed logins on Site A and
  Site B aggregate into the same central `attempts` row, so a streamed
  attack across sub-sites trips the threshold faster, and one
  `blocked`-table entry blocks the IP on every site of the network.
- **Versioned migration system** with atomic site-option lock and
  automatic v4→v5 upgrade on first admin visit. Future schema bumps add
  one method (`migrate_to_v6`, `migrate_to_v7`, …) — no existing-method
  changes required.
- **Site lifecycle handling** — `wp_initialize_site` and `wp_delete_site`
  hooks keep the central tables consistent; `wpmu_delete_user` /
  `delete_user` clean up trusted-device rows for deleted users.
- **Cron scheduling on the main site only** with `is_main_site()` guard
  + `admin_init` self-heal (single source of truth in
  `Cron_Handler::schedule_cron_jobs_static()`). Avoids the N-fold
  execution problem on large networks.
- **Network-Admin UI** registered via `network_admin_menu` with the
  `manage_network_options` cap; Setup-Wizard available in the network
  admin too.
- **Read-only Site-Admin UI on Multisite** — sub-site admins see Status,
  own-site Logs (auto-scoped via `blog_id`), plus a single 2FA Site
  Settings page that exposes exactly two writable overrides:
  Frontend-2FA slug (per-site) and 2FA enforcement roles (additive only —
  cannot drop network-required roles).
- **2FA Super-Admin enforce toggle** (`reportedip_hive_2fa_enforce_super_admins`,
  default on) — Multisite Super Admins are required to set up 2FA
  unconditionally, decoupled from per-site role rules.
- **Trust cookie network-wide** — `TRUSTED_COOKIE` is set with
  `SITECOOKIEPATH` so a single trust decision carries across all sites
  of a Multisite network; matches the new `trusted_devices` central
  table layout.
- **Cross-site REST throttle** — `Two_Factor_REST` IP throttle counters
  use `set_site_transient` so an attacker hitting multiple sub-sites
  cannot reset their counter by switching the host.
- **Per-site relay usage tracker** — `Relay_Usage_Tracker` keeps a
  rolling 6-month, per-blog-id counter for mail/SMS sends through the
  Hive relay, so a Network Admin can answer "which site is consuming
  the shared pool?" without round-tripping to the service.
- **Multisite PHPUnit suite** in `tests/Multisite/` driven by
  `phpunit-multisite.xml` with `WP_TESTS_MULTISITE=1`.
- **Playwright E2E suite** in `tests/e2e/` with separate projects for
  the single-site and multisite Docker stacks.
- **CI**: new `phpunit-multisite` matrix job (PHP 8.1–8.5),
  `e2e-single-site` and `e2e-multisite` job stubs.

### Changed

- `ReportedIP_Hive_Database` is now a thin shim around `Schema` for
  table creation/teardown and around `Migration_Manager` for schema
  upgrades. All other read/write methods are unchanged but operate on
  the central (`base_prefix`) tables.
- `register_activation_hook` / `register_deactivation_hook` /
  `register_uninstall_hook` route through the service layer.
- 353 plugin option calls (`get_option` / `update_option` / `delete_option`
  on any `reportedip_hive_*` key) now go through
  `Option_Routing::get/set/delete` so the network-vs-site scope is
  decided in one place. On single-site nothing changes — `get_site_option`
  falls through to `get_option`, behaviour is byte-identical to v1.x.
- `Two_Factor` cookie handling consolidated into a single
  `set_secure_cookie()` helper across the four call sites; trust-cookie
  path widens to `SITECOOKIEPATH` on Multisite.
- Single source of truth for the schema version is
  `Migration_Manager::CURRENT_VERSION = 5`. The legacy
  `Database::DB_VERSION` and `DB_VERSION_OPTION` constants were removed.
- `version` bumped to `2.0.0-beta.1`.

### Fixed

- `Two_Factor::get_trusted_table()` was still using `$wpdb->prefix` after
  the table moved to `base_prefix` in 2.0.0 — silently broken on
  Multisite. Fixed via `Schema::table()`.
- Setup wizard registers on `network_admin_menu` so a Super Admin can
  reach `/wp-admin/network/admin.php?page=reportedip-hive-wizard`
  instead of getting a "Sorry, you are not allowed" page.
- Site-2FA-Settings POST: role slugs are now intersected against
  `wp_roles()->get_names()` before persist, so a crafted POST cannot
  smuggle non-existent role slugs into the enforcement list. Nonce
  failures now `wp_die()` instead of falling through silently.
- Inline `style="margin: 12px 0"` on the read-only banner replaced with
  the new design-system class `.rip-alert--banner` (anti-AI-watermark
  rule from `CLAUDE.md`).

### Performance

- `Schema::tables_exist()` folds 7 separate `SHOW TABLES` probes into a
  single `information_schema.TABLES` query.
- `Option_Routing::is_site_option()` switched from O(N) `in_array()` to
  an O(1) flipped `isset()` lookup map (350+ call sites per request).
- Per-request resolve cache for `resolve_2fa_frontend_slug()` and
  `resolve_2fa_enforce_roles()` (both are called in the login filter
  hot path); cache is invalidated via `update_option_*` /
  `update_site_option_*` action hooks for the four relevant keys.
- `admin_init` cron self-heal is gated by `!is_multisite() ||
  is_main_site()`.

### Migration notes

- Existing single-site installs migrate transparently — no data movement
  required, only `ALTER TABLE … ADD COLUMN blog_id` (default 1).
- Existing Multisite installs that ran Hive on individual sites without
  `Network: true` get a one-time option-promotion pass: per-site
  network-class options are copied into sitemeta (first site to provide
  a value wins, no overwrites).
- Existing `trusted_devices` rows have their `expires_at` capped at
  NOW()+24h so users get a smooth re-trust window after the trust cookie
  path widens to `SITECOOKIEPATH`.

### Verified

- PHPCS clean, PHPStan level 5 clean, PHPUnit 435/435 green.
- Live-tested on a 4-site subdir Multisite stack: Network Admin (5 plugin
  pages render fault-free), Site-Admin Read-Only-UI (Status, Logs,
  2FA Site Settings with working save + per-site override isolation),
  Setup-Wizard 9 steps reachable, Super-Admin 2FA enforcement triggers
  the onboarding redirect, cross-site brute-force aggregates into one
  attempts row and the resulting block applies to a sub-site that was
  never attacked, per-site relay-usage tracker increments correctly.

## [1.7.1] — 2026-05-06

### Fixes

- **Setup wizard 2FA enforce-roles list now reflects every WP role.** The wizard previously rendered only four hardcoded checkboxes (`administrator`, `editor`, `author`, `shop_manager`) and the AJAX save handler intersected the posted roles against the same hardcoded list — every other role (`subscriber`, `contributor`, `customer`, custom roles like `seo_editor`, `shop_accountant` etc.) was silently dropped on save. The wizard now iterates over `wp_roles()->get_names()` like the 2FA settings tab and the save handler accepts every registered role, so a `subscriber` selection made in settings survives a wizard re-run instead of being reset to `["administrator"]`.

## [1.7.0] — 2026-05-06

### New

- **WooCommerce frontend login 2FA (Professional plan).** The second factor is now rendered inside the active storefront theme when a customer signs in via My Account, the classic checkout, or the WooCommerce blocks — no more bouncing them to wp-login.php. A new feature flag `frontend_2fa` in `Mode_Manager` gates the module to the Professional / Business / Enterprise tiers; existing customer 2FA secrets keep working after a downgrade, only new onboardings are blocked while the plan is below Professional.
- **Themed challenge slug + onboarding slug.** Two configurable slugs (`reportedip-hive-2fa` and `reportedip-hive-2fa-setup`, both customisable) are routed via `add_rewrite_rule()` and rendered with `get_header()` / `get_footer()`. Cache-Control, LiteSpeed and DONOTCACHE* headers are emitted up front so WP Rocket / W3TC / LiteSpeed never serve a stale challenge. Hide-Login bypass is automatic.
- **WC origin tracking on the authenticate filter.** `Two_Factor::filter_authenticate()` now persists the login origin (`wc`, `wc-block`, or empty), the referrer URL and the WooCommerce session customer-id alongside the challenge nonce. After a successful verify the customer lands back on `wc_get_checkout_url()` / `wc_get_page_permalink('myaccount')` instead of the WordPress dashboard their role cannot reach.
- **WC blocks-checkout error redirect.** A small listener on `wp.hooks` converts a `reportedip_2fa_required` REST error from the Cart / Checkout block into a `window.location` redirect to the themed challenge slug.
- **Setup wizard sub-section for the new feature.** Step 4 of the onboarding wizard now exposes the frontend toggle whenever WooCommerce is active, with a tier-lock chip on Free / Contributor.
- **Frontend-2FA settings section.** New section in the 2FA settings tab with the master toggle, the customer-opt-in flag and a descriptive help block. Sanitiser refuses to flip the toggle on when the plan does not include the feature.
- **14-day "promote to Professional" admin notice.** Free / Contributor admins on WooCommerce stores see a single `rip-alert--info` banner pitching the frontend feature, dismissable for 14 days per user. Survives a tier change cleanly: the banner falls silent the moment `feature_status('frontend_2fa')` flips to available.
- **Conflict detection.** Surfaces a warning banner inside the new settings section when Solid Security, the WordPress.org "Two Factor" plugin or Wordfence is active alongside Hive. Adds an informational note for WooCommerce Subscriptions / Memberships about the intentional magic-login bypass.

### Changed

- `Two_Factor::handle_2fa_challenge()` now accepts an optional render-context parameter so the wp-login interstitial and the new theme-frame variant share the same verify pipeline.
- `Two_Factor_Onboarding::get_onboarding_url()` returns the frontend setup slug for users without `manage_options` / `edit_posts` when the frontend module is available, so customers no longer hit a wp-admin redirect.

## [1.6.8] — 2026-05-05

### New

- **Cron Status panel: setup hint for shared-WP-Cron environments.** When all four plugin hooks have been overdue for more than 24 h, the panel now flags it with a danger banner and shows a copy-pasteable crontab snippet that runs only ReportedIP Hive's hooks via WP-CLI on a 5-minute schedule. This bypasses `WP_CRON_LOCK_TIMEOUT` (the per-spawn time budget that other plugins' heavy cron workers can exhaust before our hooks are reached). Both a standard crontab line and an ISPConfig-template variant (`{SITE_PHP}` / `{DOCROOT_CLIENT}`) are rendered; the WP-CLI path is auto-detected from the WordPress install directory.

## [1.6.7] — 2026-05-05

### Fixes

- **Relay quota dashboard no longer shows "Awaiting fresh quota data" most of the time.** The `reportedip_hive_relay_quota` transient was written with a 1 h TTL, but `cron_refresh_quota` only runs every 6 h — so for 5 of every 6 hours the dashboard rendered an empty snapshot with `is_stale = true`. TTL is now 12 h, longer than the cron interval plus one buffer window.
- **API queue cron now logs every skip reason, including `no_quota`.** The previous code suppressed the `no_quota` skip silently, which made it hard to tell whether a stuck queue was caused by an exhausted daily report limit, a stale local quota cache, or WP-Cron not firing at all. All four reasons (`unknown`, `no_quota`, `no_permission`, `daily_limit`, `rate_limited`) now produce an info-level log entry.

### New

- **Cron status panel on the System Status page.** Shows the next scheduled run for each plugin cron (`process_queue`, `refresh_quota`, `sync_reputation`, `cleanup`), highlights overdue hooks, and exposes the queue lock state. Two new admin-only AJAX actions — `reportedip_hive_run_queue_now` and `reportedip_hive_clear_queue_lock` — provide an escape hatch when WP-Cron is being blocked by a CDN or cache plugin and the queue stops draining.

## [1.6.6] — 2026-05-04

### Security (E2E hardening of the 1.6.5 password-reset gate)

- **Reset key resolver now reads the WordPress reset cookie.** The 1.6.5
  implementation only looked at `$_REQUEST['key']`, but in step 2 of the
  WordPress reset flow (`?action=rp` after the cookie-set redirect) the key
  lives in `$_COOKIE['wp-resetpass-COOKIEHASH']` as `login:key` — and in
  step 3 (resetpass POST) it lives in `$_POST['rp_key']`. The
  `validate_password_reset` hook fired but bailed out without effect on
  every standard reset, so the gate was bypassable end-to-end. Resolver now
  inspects URL → POST → cookie in that order; same fix applied to
  `get_query_login()`. Discovered while running the full Docker-stack E2E.
- **Email-only lockout no longer relies on `WP_Error`.** The
  `User_Enumeration::normalize_login_errors()` filter rewrites every
  non-2FA-flow login error to a generic `"Invalid credentials."` string to
  defeat username probing; the reset-gate lockout text was caught by that
  filter and the affected user never saw the real reason. The gate now
  renders a dedicated 403 page via `wp_die()` plus
  `emit_block_response_headers()`, which no `login_errors` filter can
  rewrite. Same path used for the no-eligible-method lockout.
- **`User_Enumeration::normalize_login_errors()` whitelist extended.**
  The filter now lets `?action=reportedip_2fa_reset` pages and any error
  text containing "reset blocked" or, on `rp` / `resetpass`, "two-factor"
  through unmasked, so future reset-gate messages reach the user verbatim.

## [1.6.5] — 2026-05-03

### Security

- **2FA gate on the WordPress password reset flow.** A user with a 2FA method
  configured now has to verify a non-email second factor (Authenticator, SMS,
  passkey, or recovery code) before the password is set through the
  `lostpassword` flow. Email is excluded by design — it is the channel the
  reset link itself was delivered on, so allowing it as the second factor
  would collapse to single-factor security if the mailbox is compromised.
  Hooks `validate_password_reset` (priority 5, gates the form render) and
  `password_reset` (priority 5, last-mile guard before `wp_set_password`).
  Failures share the IP-block ladder with login-flow failures via the
  canonical `2fa_brute_force` event.
- **Email-only lockout.** Accounts whose only enrolled second factor is
  email and which have no recovery codes are blocked from the reset flow
  entirely. All site administrators get an alert mail; unblock manually
  with `wp user reset-password <id> --skip-email` or by enrolling an
  additional 2FA method on the user's behalf.
- **Two new options under *Settings → Two-Factor → Password reset gate*:**
  `reportedip_hive_2fa_require_on_password_reset` (master toggle, default
  `true`) and `reportedip_hive_2fa_password_reset_block_email_only`
  (default `true`). The list of methods that may not be used as the
  second factor is filterable via
  `reportedip_hive_2fa_password_reset_excluded_methods` and defaults to
  `["email"]`.

### Fixes

- **2FA challenge: silent redirect on expired session replaced with explicit
  feedback.** When the 15-minute login nonce had timed out, or when the
  `SameSite=Strict` nonce cookie was dropped (routine when wp-login.php is
  loaded inside an iframe), `handle_2fa_challenge()` used to
  `wp_safe_redirect( wp_login_url() )` with no message — users saw a clean
  login form and assumed their submitted SMS / TOTP code had been silently
  rejected. The handler now renders an inline "Two-Factor session expired"
  page through `login_header()`/`login_footer()` with a clear explanation
  (15-minute timeout / iframe cookie loss) and a `target="_top"` "Back to
  login" link that escapes a broken iframe context.
- **Lockout redirect actually shows a message now.** The
  `?reportedip_2fa_locked=1` query flag emitted after
  `SESSION_INVALIDATION_THRESHOLD` failed verification attempts was set but
  read nowhere — users hit the brute-force lockout and landed on a
  message-free login form. New `wp_login_errors` filter
  (`Two_Factor::filter_login_errors()`) translates both
  `?reportedip_2fa_locked=1` and `?reportedip_2fa_expired=1` into visible
  WP_Error messages.
- **User-enumeration normalizer no longer masks 2FA-flow messages.**
  `User_Enumeration::normalize_login_errors()` runs at priority 99 on
  `login_errors` and rewrites every login error to the generic
  "Invalid credentials." string to defeat username probing. It now
  recognises the plugin's own 2FA-flow context
  (`?reportedip_2fa_locked=1`, `?reportedip_2fa_expired=1`,
  `?action=reportedip_2fa`) and lets those messages through unmasked —
  they reveal nothing about user existence and would otherwise be replaced
  with the misleading "Invalid credentials." text.

## [1.6.4] — 2026-05-01

### Fixes

- **2FA onboarding "Go to dashboard" had unreadable contrast.** A scoped
  `body.rip-2fa-onboarding a { color: var(--rip-primary); }` rule outranked
  `.rip-button--primary { color: white; }` on specificity, so the success-step
  CTA rendered indigo-on-indigo. The anchor selector now excludes
  `.rip-button` and an explicit override pins primary-button anchors to
  `#fff`.
- **Operation mode now persists from the General settings tab.** Previously the
  Local/Community radio cards on `Settings → General` lived outside any form
  and the option had no `register_setting()` entry, so clicking save did
  nothing. The cards are now wrapped in a real `options.php` form, the option
  is registered with a `sanitize_operation_mode()` callback, and the cache /
  audit-log side effects (`reportedip_hive_mode_changed`) fire from
  `update_option_<OPTION_MODE>` so AJAX (wizard) and Settings-API paths run
  identical post-save code.
- **Wizard no longer disables detection sensors when Step 3 is skipped.**
  Missing POST fields used to coerce to `false`, leaving every monitor toggle
  off after the wizard. The handler now falls back to a centrally-defined
  "default everything on" profile (new
  `Defaults::wizard_protection_defaults()`).
- **Skipping the wizard now seeds safe defaults too**, not only completing it.
- **Test-SMS button on the 2FA tab.** Replaced the bare `r.json()` call with a
  text-then-parse pattern so PHP notices or non-JSON responses surface as a
  readable error (HTTP status code, server message) instead of always saying
  "Network error". The button now also disables itself when the SMS provider
  isn't configured yet, with an inline hint about what's missing.
- **"Set up now" reminder banner** for 2FA users now actually scrolls to the
  setup section: the user-profile heading carries the missing
  `id="reportedip-hive-2fa"` anchor.
- **Reply-To header.** The mailer now adds an explicit `Reply-To` header
  derived from `Defaults::notify_from()` whenever a caller doesn't supply one,
  so PRO+ relay sends preserve replies to the configured site contact.

### Changed

- **2FA onboarding wizard polish.** Trust signal added to the header (a
  site-name + domain strip rendered on every step, plus the Welcome title now
  reads "Welcome to Two-Factor Authentication for *&lt;site name&gt;*"). Email
  and SMS setup panels now use numbered substeps instead of a bare `<ol>`.
  The email "Send code" button starts a 60-second client-side resend
  countdown; the SMS "Send code" button does the same and additionally shows
  a "SMS sent — delivery can take up to 60 s" countdown next to the status
  line. The SMS privacy notice has been promoted from a generic warning
  alert to a dedicated `.rip-privacy-notice` component (lock icon, soft
  background); the recovery-codes warning now uses the same component in its
  amber `--warning` variant. The "I have stored my recovery codes safely"
  acknowledgement + Finish button now sit centred in a card, and the Back
  button moved into a separate secondary actions row so the gate is
  visually obvious.
- **Strict client-side phone validation in the SMS onboarding step.** The
  number input now runs the same E.164 regex as the server
  (`/^\+[1-9]\d{6,14}$/`) on every keystroke, rendering inline ✓ / ✕
  feedback and gating the "Send" button until a valid international number
  is entered together with the consent checkbox. Numbers without country
  code (e.g. `0176…`) are refused before they ever reach the AJAX endpoint,
  reducing accidental SMS spend.
- **Settings → Privacy & Logs** loses the "Delete plugin data on uninstall"
  toggle (moved to Performance & Tools) and the "Maintenance & exports" panel
  (moved to System Status). The `reportedip_hive_delete_data_on_uninstall`
  option moved from the `reportedip_hive_advanced_privacy` settings group to
  `reportedip_hive_advanced_performance` accordingly.
- **Settings → Performance & Tools** loses the Cache management buttons,
  Setup-wizard restart link, and Settings import/export panel — all moved to
  System Status. An info card on the tab points users to the new location.
- **Settings → 2FA** loses the "Sign-in notifications" section. The
  `reportedip_hive_2fa_notify_new_device` option now belongs to the
  Notifications settings group and is rendered inside the Notifications tab.
- **Settings → Notifications** gains a tier-aware banner explaining the PRO
  mail-relay flow, plus the migrated Sign-in notifications section.
- **Settings → Blocking** "How blocking decides" box is now a numbered
  decision-flow card. The blocked-page contact field accepts `mailto:` links
  too, with a one-click "Use site admin email" suggestion.
- **System Status** (formerly "Debug") now hosts cache management, the
  setup-wizard restart entry point, settings import/export, and maintenance
  buttons. Health badges grew an inline status pill with a checkmark / warning
  / error icon next to the operational text.
- **Settings → 2FA** master toggle now disables every dependent section
  (methods, enforcement, reminders, IP allowlist, SMS provider, XML-RPC
  protection, trusted devices, branded login) via a single
  `rip-2fa-dependent-fields` wrapper.
- **Community page activity stats** broadened from 3 cards to 6+: failed
  logins, comment spam, reputation blocks and lifetime API call counters
  (the latter shown only once the API has been used).
- **Dashboard.** Day-1 "Security Events" card now shows an inviting empty
  state instead of a bare empty chart. New API-usage card surfaces total
  calls / success rate / current-hour usage / average response time pulled
  from `reportedip_hive_api_stats`. Free-tier Community sites see a
  Mail/SMS upgrade card mirroring the relay quota layout.

### Defaults

- `Defaults::SAFE_OPTIONS` now seeds an explicit baseline for
  `operation_mode`, every `monitor_*` and `block_*` toggle (default ON),
  `2fa_trusted_devices`, `2fa_frontend_onboarding`, and
  `2fa_enforce_roles` (`["administrator"]`). `add_option()`-based — never
  overwrites an existing user value.

## [1.6.3] — 2026-04-30

### New

- **Managed mail relay (Hive ↔ reportedip.de).** New
  `ReportedIP_Hive_Mail_Provider_Relay` routes 2FA mails through the
  service-side `POST /reportedip/v2/relay-mail` endpoint when the
  current site is in Community mode and the API key belongs to a
  Professional / Business / Enterprise tier. The mailer wraps the
  WordPress provider as a transparent fallback — HTTP 402 (cap),
  HTTP 429 (backoff) and any network error fall back to local
  `wp_mail()` so the 2FA flow never breaks. Reply-To is hoisted out
  of the headers list into a dedicated payload field, with a
  `reportedip_hive_mail_reply_to` option / filter for site-wide
  defaults.
- **Managed SMS relay (Hive ↔ reportedip.de).** New
  `ReportedIP_Hive_SMS_Provider_Relay` registers as the highest-
  priority SMS provider on PRO+ tiers and uses the template-based
  `POST /reportedip/v2/relay-sms` route — only the template code
  (`2fa_login`) and the verification digits leave the site, never
  the rendered SMS body. HTTP 402 / 429 / generic errors are
  surfaced as typed `WP_Error`s so the 2FA layer can encourage the
  user to pick another method instead of silently switching to a
  third-party SMS contract.
- **EU phone validator.** New `ReportedIP_Hive_Phone_Validator`
  normalises numbers to E.164, looks up the country code against a
  29-country EU whitelist (DE, AT, CH, BeNeLux, FR, IT, ES, PL,
  Nordics, Baltics, Balkans, Malta, Cyprus, …) and exposes a
  `reportedip_hive_phone_eu_whitelist` filter so site operators
  can extend or override the list.
- **Progressive SMS backoff ladder.** `class-two-factor-sms.php`
  now stores a `next_allowed_at` timestamp per recipient and walks
  the backoff ladder (0s → 2m → 5m → 15m → 30m → 60m) before
  resetting, mirroring the service-side relay rate-limiter.
- **Two new unit-test suites.** `MailProviderRelayTest` (10 tests)
  and `SmsProviderRelayTest` (9 tests) lock down the relay → fall
  back contract, the EU-only validation, the template-route payload
  shape and the HTTP 402 / 429 → typed-error mapping.

### Changed

- **Setup wizard slimmed from 8 to 7 steps.** The standalone
  "Promote" footer-preview step was retired; its function moved
  into the Welcome step's tier teaser cards. The wizard's docblock
  and the `get_step_labels()` map are now the single source of
  truth for the step list.
- **`class-two-factor-sms.php` is_ready()** now treats
  `reportedip_relay` as configured-by-default when the relay is
  available for the current tier — no separate provider config is
  required because the existing API key authenticates the call.
- **IP-lookup form in the security tab** redirects via plain URL
  arguments instead of building the link in JavaScript, which keeps
  the hash state when the user lands back on the lookup tab.

### Fixes

- **Scan detector path lookup runs once per request.** The
  honeypot-pattern matcher used to walk the path twice on the same
  request (once for the 404 counter, once for the bypass list).
  Refactored to a single pass; no behaviour change, slightly less
  CPU on high-404 sites.

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
  the plan subscription. For a self-hosted provider the original
  *"I confirm that a DPA …"* wording is preserved. The privacy hard
  gate behaviour is unchanged: no SMS is dispatched until the flag
  is true.
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
- **2FA suite with 4 methods**: TOTP (RFC 6238), email OTP, SMS (numbers encrypted at rest), WebAuthn/FIDO2 (Face ID, Touch ID, Windows Hello, YubiKey) — including a 5-step onboarding wizard.
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
