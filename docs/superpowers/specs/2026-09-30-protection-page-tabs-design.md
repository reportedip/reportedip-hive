# Protection page: tabs, toggle rows, inline technical details

Date: 2026-09-30
Status: approved design, not yet implemented
Scope: `admin/class-protection-page.php`, `assets/js/protection.js`, `assets/css/design-system.css`, tests, docs

## Goal

A customer sent a mockup of the Protection page: a status banner, four tabs
with a status pill each, one toggle row per setting with a lay description,
plan-gated rows with a "Pro" badge and a "Learn more" button, a collapsible
"Show technical details" block, and one "Restore defaults" plus one "Save
changes" button per tab.

This design adopts that layout as a presentation layer only. The settings
registry, the apply service, the remote schema, MainWP, the cloud fleet, the
quickstart and the JSON import stay exactly as they are. Every key keeps its
section, every section keeps its id, and every anchor link into the page
keeps working.

## What stays untouched

- `Settings_Registry::spec()`, `sections()`, `export_schema()`, `SCHEMA_VERSION`
- `Settings_Apply::apply()` and the sanitizer
- The fourteen section ids (`detection`, `blocking`, `waf`, `registration`,
  `forms`, `hardening_mode`, `hide_login`, `headers`, `lockdown`,
  `account_security`, `twofa_policies`, `account_password`, `privacy_logs`,
  `notifications`, `performance`) as anchors and as the ids the aliases, the
  readiness links, the admin bar, the score and the dashboard area rows use
- `Protection_Page::section_state()` and `section_status()` (the dashboard
  area rows read them)
- `Protection_Page::collect_values()`, `writable_values()`, `field_status()`,
  `tier_marker_state()`, `current_preset()`, `choices_for()`
- The expert mode user meta `reportedip_hive_expert_mode`, its handler, the
  header toggle, the quickstart link that sets it, and the Tools menu entry
  that depends on it

## 1. Data model

### Tabs

`Protection_Page::tabs()` returns the five tabs in display order. Each tab
has a slug, a label, an inline SVG icon key, the sections it holds in
registry order, and one recommendation sentence.

| Slug | Label | Sections |
|---|---|---|
| `basics` | Core protection | detection, blocking, hide_login, account_security, account_password |
| `forms` | Forms | forms, registration |
| `firewall` | Firewall & Bots | waf, lockdown, headers |
| `advanced` | Advanced | hardening_mode, twofa_policies |
| `operations` | Operations | privacy_logs, notifications, performance |

A unit test asserts that the union of all tabs is exactly the fourteen
sections and that no section appears twice.

`Protection_Page::tab_of( $section )` returns the slug of the tab a section
lives in. The save redirect and the hash handling use it.

### Main rows and technical details

The registry flags `simple` and `simple_form` keep their values and get a new
reading: a key with `simple`, or with a `simple_form` whose plugin is
detected, is a main row of its section. Every other key of the section is a
technical detail. `is_visible()` stays the pure test for this, called with
`$expert = false`; it now decides placement, not existence.

Both views render every key. Expert mode only decides whether the details
block starts open.

### Tab state

`Protection_Page::tab_state( $tab, array $current, array $statuses )` (the
statuses come from `field_statuses( $current, $mode_manager )`, computed
once per page) returns
`{text, tone}` in the same shape as `section_state()`. It aggregates the
section states of the tab instead of counting switches, so the pill and the
dashboard area rows can never disagree:

- A section whose every key is plan-locked (status `available` false,
  reason `tier`, not `partial`; `section_locked()` is the pure helper) is
  excluded and remembered as locked.
- A section with tone `neutral` is excluded.
- The remaining sections count: `success` is on, `danger` is off.

| Situation | Text | Tone |
|---|---|---|
| no counted section, at least one locked | the plan label from `get_tier_info()` of the lowest missing tier (for example "Pro") | `neutral` |
| no counted section, none locked | empty text, the pill is not rendered | `neutral` |
| every counted section is on | "Active" | `success` |
| some are on | "2 of 3 active" | `neutral` |
| none is on | "Off" | `danger` |

`advanced` on Free therefore shows the plan label, because both of its
sections are locked. On a paid plan it counts `hardening_mode` (a switch
state) and excludes `twofa_policies` (neutral trigger count). A section's
lead switch stays the one `section_state()` already picks, which keeps
`report_only_mode` and `minimal_logging` from being read as protection
that is "on".

### Reset values

`Protection_Page::reset_values( $tab, $tier, $mode )` is pure: it takes
`Defaults::recommended( $tier, $mode )` and keeps only the keys whose section
belongs to the tab. Keys without a recommendation are absent from the result
and are therefore left alone by the reset.

## 2. Page layout

Top to bottom:

1. Page header as today, expert toggle included.
2. Status banner: `Dashboard_Next_Steps::render_banner( $api )`, reused
   unchanged. The mockup's "Check protection" button is a
   `rip-button--secondary` link to the dashboard, rendered next to the banner
   text through the existing `rip-alert__content--row` layout.
3. The search field, above the tabs, so a search spans every tab.
4. The tab bar: `rip-nav-tabs`, one `<a>` per tab with icon, label and a
   `rip-badge` in the tone of `tab_state()`. The link carries `?tab=<slug>`
   so the page works without JavaScript and so a bookmark opens the right
   tab.
5. One panel per tab. All five panels are rendered; the active one is
   visible, the others carry `rip-hidden`. Without JavaScript the stylesheet
   shows every panel stacked (`.no-js` is not used; the panels simply start
   without `rip-hidden` and the script hides the inactive ones on load).

The active tab is resolved server-side from `?tab=`, falling back to the
first tab. The script overrides that on load when the URL carries a
`#section` hash that belongs to another tab.

### Panel

A panel is one `<form>` posting to `admin-post.php` with the existing action
`reportedip_hive_protection_save`, the nonce, and `rip_tab=<slug>`. It holds,
in order:

- A `rip-alert--info` with the tab's recommendation sentence.
- One block per section:
  - Section head: label, the registry description, the `section_state()`
    badge. The `id` attribute on the block is the section id, so every
    `#section` link still lands here.
  - The preset radio group, in `detection` only, before the main rows.
  - The main rows (see 3).
  - `<details class="rip-protection__details">` with the summary "Show
    technical details" and the remaining fields of the section. The block is
    rendered with `open` when the user is in expert mode. A section without
    a main row consists of the head and the details only. A section whose
    keys are all main rows renders no details block.
- Footer: a ghost button "Restore defaults" (`type="submit"`,
  `name="rip_reset"`, `value="1"`, with a `confirm()` prompt attached by the
  script) and the primary button "Save changes".

Form-adapter switches whose plugin is not detected are technical details of
`forms` and carry their runtime note, exactly as they do in expert mode
today. `missing_form_plugin()` and `hint_reason()` keep feeding that note.

### Removed

`hint_markup()`, `render_expert_hints()`, `expert_summary()`,
`expert_jump_url()`, `expert_only_keys()` and `section_is_expert_only()` go
away, together with the stand-in markup, the "Show these" link, the
`rip-protection__hint` and `rip-protection__more` styles, and the
`rip_anchor` branch of the expert toggle handler. The search finds fields
inside the details block and opens it instead.

## 3. Field rows

`field_markup()` keeps its signature and its outer structure
(`rip-protection__field` with `data-search` and `data-key`, a head with the
label and the marker, a control, a help text). Changes:

- Kinds `bool`, `int` and `enum` add the class `rip-protection__field--row`.
  The stylesheet lays these out as one row: head and help text on the left,
  control on the right. `textarea`, `json_list`, `text`, `email`, `url`,
  `slug`, `email_list` and `csv_int_list` stay stacked.
- A `bool` control is followed by `<span class="rip-protection__state">`
  reading "Active" or "Off". The span carries `data-on` and `data-off` with
  the two strings; the script swaps the text when the toggle changes. The
  span is decorative (`aria-hidden="true"`), the checkbox stays the
  accessible control.
- A plan-locked switch (kind `bool`, status `available` false, reason
  `tier`, not `partial`, so not a switch that is currently on) renders no
  control at all. In its place: a `rip-badge` with the plan label and a
  `rip-button--secondary rip-button--sm` "Learn more" linking to
  `Admin_Settings::pricing_url()` with the feature key as the fragment.
  The label and the link travel inside the status (`plan_label`,
  `plan_url`, added by `field_statuses()` in the page), so
  `field_markup()` stays free of the mode manager. Locked fields of any
  other kind keep their disabled control, because a stored list or text
  must stay readable. Because nothing is posted, `collect_values()` fills
  the empty value and `writable_values()` drops it, which is the existing
  behaviour for a disabled input. The `rip-protection__field--locked` class
  stays on the wrapper.
- Every other lock keeps today's rendering: mode locks and runtime notes
  render a disabled control plus the note; `forced` switches render checked
  and disabled; `partial` fields stay editable.

### Closed details and browser validation

A closed `<details>` still submits its fields, but the browser cannot focus
a field it cannot show. An out-of-range number typed into the details and
then folded away would block the submit without a message. The script
listens for the `invalid` event (capture phase) on every form and opens the
`<details>` that contains the offending control before the browser reports
it.

## 4. Save and reset

### `handle_save()`

1. Permission check and nonce as today.
2. Read `rip_tab`; unknown slug dies with 400.
3. For each section of the tab: `collect_values( $post, $section )`, build
   the statuses with `field_status()`, then
   `writable_values( $values, <all keys of the section>, $statuses )`. The
   visible list is the whole section, because every key is rendered in
   every view now. `expert_only_keys()` is no longer needed here.
4. Merge the per-section results and call `Settings_Apply::apply( $values,
   'admin' )` once.
5. Store the result transient as `{tab, applied, errors}`; `errors` stays
   keyed by registry key, so the per-field error paragraph renders exactly
   as today.
6. Redirect to `?page=reportedip-hive-protection&tab=<slug>`; when there are
   errors, append `#<section of the first error>` so the browser lands on
   the section and the script opens its details if the field sits there.

When the POST carries `rip_reset`, step 3 and 4 are replaced by
`reset_values( $tab, $tier, $mode )`, filtered through `writable_values()`
with the same statuses (a locked key is never written by a reset either),
then `apply()`. The transient records `reset => true` so the page can say
"N settings set back to the recommendation." instead of "N settings saved."

The four preset keys keep their special standing in `writable_values()`.

## 5. Stylesheet and script

### `design-system.css`

New blocks under the `.rip-protection` namespace:

- `__tabs` (spacing around the reused `rip-nav-tabs`)
- `__panel` and `__panel.rip-hidden`
- `__section` (now a plain block, no longer a `details`) and
  `__section-head` (title, description, status badge in one row)
- `__field--row` (two-column row), `__state` (the on/off text)
- `__details` and its `summary` (link-styled with a chevron, the same
  chevron rotation the cards use today)
- `__pro` (badge plus button, right-aligned in the row)

Removed: the `__section > summary`, `__chevron`, `__hint` and `__more`
rules. `__field`, `__field-head`, `__field--locked`, `__presets`,
`__footer`, `__error` and `mark` stay.

No new colors, no inline styles, no rounded content boxes beyond the
design-system defaults.

### `protection.js`

Still dependency-free. Responsibilities:

- Tab switching: click on a tab link toggles the panels and the active
  class, updates `?tab=` through `history.replaceState`, keeps the hash.
- Hash handling on load and `hashchange`: find the element, switch to its
  tab, open the `<details>` that contains it, scroll to it.
- Search: with a term, every panel becomes visible, the tab bar is dimmed,
  sections without a hit are hidden, and the details of a hit open. With an
  empty term, the panels return to the active tab and the details fold back
  to their rendered state.
- Toggle state text: on `change` of a `bool` control, swap the neighbouring
  `__state` text.
- Preset coupling: typing into one of the four threshold fields selects the
  "Custom" radio, as today.
- `invalid` listener that opens the enclosing details (see 3).
- `confirm()` on the reset button.

## 6. Compatibility

- Every existing link into the page (`#blocking`, `#account_security`,
  `#hardening_mode`, `#privacy_logs` and the rest) keeps working: the id is
  still on the section block, the script switches the tab.
- `Dashboard_Next_Steps` area rows read `section_state()`; unchanged.
- `Admin_Aliases::resolve()` maps the old tab names of the former settings
  and firewall pages to section anchors; unchanged.
- The expert mode affects only the initial `open` of the details blocks and
  the Tools menu entry. The quickstart keeps setting it.
- Multisite: the page is Network Admin only, as today.
- Remote schema: no change, `SCHEMA_VERSION` stays.
- Translations: new strings run through `composer i18n` before the tag.

## 7. Tests and documentation

### Unit (`tests/Unit/ProtectionPageTest.php`)

- `tabs()` covers every registry section exactly once; `tab_of()` inverts it.
- `tab_state()`: all on, some on, none on, all plan-locked, neutral only;
  `section_locked()` for a fully gated and a partially gated section.
- `field_markup()` for a plan-locked field renders no `input`, `select` or
  `textarea`, but the plan badge and the pricing link with the feature key.
- `field_markup()` for a `bool` carries the state span with both strings;
  `int` and `enum` carry the row class, `textarea` does not.
- `reset_values()` keeps only the tab's keys of the recommendation.
- The details block is rendered `open` in expert mode and closed otherwise
  (a render helper for one section, called with both values).
- Removed tests: the stand-in rendering, `expert_summary()`, "the simple
  view never renders a control for an expert setting".
- The CSS assertions that check the `summary` marker move to the details
  summary.

`AdminSurfaceParityTest` (every registry key is drawn by the renderer) and
`SettingsRegistryTest` stay as they are and must stay green.

### E2E (`tests/e2e/specs/single-site/protection-page.spec.ts`)

Rewritten around the tabs:

- the tab bar shows five tabs with a status pill each
- a section saves through the tab form and reports the change
- the preset writes its four values and the section status names it
- a plan-locked row has no control, shows the badge and the link
- a switched-on plan feature stays editable after a downgrade and a locked
  value survives a save (both cases as today, through the tab form)
- runtime locks and fixed choices render as before
- a stored role list round-trips
- search finds Tor across tabs, opens the details and marks the label
- a `#section` link opens the right tab and scrolls to the section
- reset sets the tab's keys back to the recommendation and leaves a key
  without a recommendation alone

Selectors in `two-factor-policies.spec.ts`, `registration-rules.spec.ts`
(single and multisite) and `hardening-switches.spec.ts` (multisite) are
adjusted from `summary` clicks to tab clicks and details opening.

### Documentation

- `CHANGELOG.md`, `readme.txt`, `README.md`
- `CLAUDE.md`: the `Protection_Page` row in the admin classes table and the
  lock semantics paragraph (point 5 of the options section: the stand-in
  sentence is replaced by the closed-details rule)
- Service docs `templates/shortcodes/docs/wordpress-plugin.php` (the
  Protection page walkthrough)

## Out of scope

- Any change to which keys are `simple`; the customer's mockup happens to
  match the current flags for the forms section.
- Per-user tab memory; `?tab=` in the URL is enough.
- A redesign of the Tools page.
