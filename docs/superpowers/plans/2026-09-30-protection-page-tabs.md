# Protection Page Tabs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the Protection page presentation as five tabs with toggle rows, a plan row for locked switches, inline technical details, and a per-tab save plus reset, without touching the settings registry or the apply service.

**Architecture:** Everything lives in `ReportedIP_Hive_Protection_Page` (pure static helpers for tabs, tab state and reset values; one `section_markup()` string renderer; `render_page()` and `handle_save()` as the two entry points), plus one stylesheet block and one dependency-free script. The fourteen registry sections keep their ids and become blocks inside five tab panels. Locked and hidden keys never reach `Settings_Apply::apply()`, exactly as today, because both views now render every key and the closed `<details>` still posts its fields.

**Tech Stack:** PHP 8.1 (WordPress plugin, WPCS, PHPStan 5), PHPUnit unit suite with the mocked WP of `tests/bootstrap.php`, Playwright E2E against the Docker stacks, `composer i18n` for the German catalogue.

Spec: `docs/superpowers/specs/2026-09-30-protection-page-tabs-design.md`.

Working directory for every command below: `dev/` (the plugin repo). Run `./run.sh` commands from the workspace root one level up.

---

## File map

| File | Change |
|---|---|
| `admin/class-protection-page.php` | new `tabs()`, `tab_of()`, `tab_icon()`, `section_locked()`, `tab_state()`, `reset_values()`, `field_statuses()`, `plan_row_markup()`, `section_markup()`, `active_tab()`; `field_markup()` learns the row class, the state span and the plan row; `render_page()` and `handle_save()` rewritten; `hint_markup()`, `render_expert_hints()`, `expert_summary()`, `expert_jump_url()`, `expert_only_keys()`, `section_is_expert_only()`, `summary_markup()`, `render_section_tools_link()` removed; `rip_anchor` branch removed from `handle_expert_toggle()` |
| `assets/js/protection.js` | rewritten: tabs, hash, search across tabs, state text, invalid opener, reset confirm, preset coupling |
| `assets/css/design-system.css` | Protection block rewritten |
| `tests/Unit/ProtectionPageTest.php` | new tests for the helpers, stand-in tests removed, lock test adjusted |
| `tests/e2e/specs/single-site/protection-page.spec.ts` | rewritten around tabs |
| `tests/e2e/specs/single-site/two-factor-policies.spec.ts`, `registration-rules.spec.ts` (single and multisite), `tests/e2e/specs/multisite/hardening-switches.spec.ts` | selectors adjusted |
| `languages/*` | `composer i18n` + German strings |
| `CHANGELOG.md`, `README.md`, `readme.txt`, `../CLAUDE.md`, service docs | wording |

Section ids, `section_state()`, `section_status()`, `collect_values()`, `writable_values()`, `field_status()`, `tier_marker_state()`, `current_preset()`, `choices_for()`, `choices_note()`, `is_visible()`, `visible_keys()`, `detected_forms()`, `missing_form_plugin()`, `hint_reason()`, `search_terms()`, `field_id()`, `section_url()` stay as they are.

---

### Task 1: The tab table

**Files:**
- Modify: `admin/class-protection-page.php` (after `PRESET_KEYS`)
- Test: `tests/Unit/ProtectionPageTest.php`

- [ ] **Step 1: Write the failing tests**

Append inside the `ProtectionPageTest` class:

```php
		public function test_tabs_cover_every_registry_section_exactly_once(): void {
			$seen = array();
			foreach ( ReportedIP_Hive_Protection_Page::tabs() as $slug => $tab ) {
				$this->assertMatchesRegularExpression( '/^[a-z]+$/', $slug );
				$this->assertNotSame( '', (string) $tab['label'] );
				$this->assertNotSame( '', (string) $tab['advice'] );
				$this->assertNotSame( '', ReportedIP_Hive_Protection_Page::tab_icon( $tab['icon'] ), "tab {$slug} has no icon" );
				foreach ( $tab['sections'] as $section ) {
					$this->assertArrayNotHasKey( $section, $seen, "section {$section} sits in two tabs" );
					$seen[ $section ] = $slug;
				}
			}
			$this->assertSame(
				array_keys( \ReportedIP_Hive_Settings_Registry::sections() ),
				array_keys( $seen ),
				'the tabs hold exactly the registry sections, in registry order'
			);
		}

		public function test_tab_of_names_the_tab_of_a_section(): void {
			$this->assertSame( 'firewall', ReportedIP_Hive_Protection_Page::tab_of( 'headers' ) );
			$this->assertSame( 'basics', ReportedIP_Hive_Protection_Page::tab_of( 'detection' ) );
			$this->assertSame( '', ReportedIP_Hive_Protection_Page::tab_of( 'nope' ) );
		}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `vendor/bin/phpunit --no-coverage --filter 'test_tabs_cover|test_tab_of' tests/Unit/ProtectionPageTest.php`
Expected: 2 errors, `Call to undefined method ReportedIP_Hive_Protection_Page::tabs()`.

- [ ] **Step 3: Add the table, the lookup and the icons**

Insert after the `PRESET_KEYS` constant:

```php
	/**
	 * Query parameter that names the open tab.
	 *
	 * @var string
	 * @since 2.1.69
	 */
	const TAB_PARAM = 'tab';

	/**
	 * The five tabs of the page, in display order.
	 *
	 * A tab is a group of registry sections and nothing more. The sections
	 * keep their ids, their order inside a tab is the registry order, and
	 * nothing outside this class ever needs to know which tab holds which
	 * section: every link into the page still points at a section id.
	 *
	 * @return array<string, array{label:string,icon:string,sections:string[],advice:string}>
	 * @since  2.1.69
	 */
	public static function tabs() {
		return array(
			'basics'     => array(
				'label'    => __( 'Core protection', 'reportedip-hive' ),
				'icon'     => 'shield',
				'sections' => array( 'detection', 'blocking', 'hide_login', 'account_security', 'account_password' ),
				'advice'   => __( 'Recommended: keep the defaults on. Change a threshold only when a sign-in or a block does not behave as expected.', 'reportedip-hive' ),
			),
			'forms'      => array(
				'label'    => __( 'Forms', 'reportedip-hive' ),
				'icon'     => 'file',
				'sections' => array( 'forms', 'registration' ),
				'advice'   => __( 'Recommended: keep the defaults on. Changes are only needed when a form does not work as expected.', 'reportedip-hive' ),
			),
			'firewall'   => array(
				'label'    => __( 'Firewall & Bots', 'reportedip-hive' ),
				'icon'     => 'users',
				'sections' => array( 'waf', 'lockdown', 'headers' ),
				'advice'   => __( 'Recommended: keep the firewall on. Add an exception on the Tools page before switching a rule off.', 'reportedip-hive' ),
			),
			'advanced'   => array(
				'label'    => __( 'Advanced', 'reportedip-hive' ),
				'icon'     => 'settings',
				'sections' => array( 'hardening_mode', 'twofa_policies' ),
				'advice'   => __( 'These settings only matter during a coordinated attack or for a second factor asked again. The recommendation covers both.', 'reportedip-hive' ),
			),
			'operations' => array(
				'label'    => __( 'Operations', 'reportedip-hive' ),
				'icon'     => 'activity',
				'sections' => array( 'privacy_logs', 'notifications', 'performance' ),
				'advice'   => __( 'Logs, mails and the footprint per request. None of it decides what is blocked.', 'reportedip-hive' ),
			),
		);
	}

	/**
	 * Slug of the tab that holds one section.
	 *
	 * @param string $section Section id.
	 * @return string Tab slug, or an empty string for an unknown section.
	 * @since  2.1.69
	 */
	public static function tab_of( $section ) {
		foreach ( self::tabs() as $slug => $tab ) {
			if ( in_array( (string) $section, $tab['sections'], true ) ) {
				return (string) $slug;
			}
		}
		return '';
	}

	/**
	 * Inline SVG of a tab icon.
	 *
	 * @param string $icon Icon key from {@see tabs()}.
	 * @return string Escaped markup, empty for an unknown key.
	 * @since  2.1.69
	 */
	public static function tab_icon( $icon ) {
		$open  = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">';
		$paths = array(
			'shield'   => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
			'file'     => '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/>',
			'users'    => '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
			'settings' => '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
			'activity' => '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
		);
		if ( ! isset( $paths[ (string) $icon ] ) ) {
			return '';
		}
		return $open . $paths[ (string) $icon ] . '</svg>';
	}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `vendor/bin/phpunit --no-coverage --filter 'test_tabs_cover|test_tab_of' tests/Unit/ProtectionPageTest.php`
Expected: `OK (2 tests, ...)`.

- [ ] **Step 5: Commit**

```bash
git add admin/class-protection-page.php tests/Unit/ProtectionPageTest.php
git commit -m "add the tab table of the protection page"
```

---

### Task 2: Section lock and tab state

**Files:**
- Modify: `admin/class-protection-page.php` (after `section_state()`)
- Test: `tests/Unit/ProtectionPageTest.php`

`tab_state()` takes the field statuses as a plain array instead of the mode manager, so the test needs no manager stub and `render_page()` computes the statuses once for every key.

- [ ] **Step 1: Write the failing tests**

Append inside the test class:

```php
		/**
		 * @return array<string,array<string,mixed>>
		 */
		private function statuses_for( string $section, array $status ): array {
			$out = array();
			foreach ( ReportedIP_Hive_Protection_Page::visible_keys( $section, true, array() ) as $key ) {
				$out[ $key ] = $status;
			}
			return $out;
		}

		public function test_section_locked_needs_every_key_behind_the_plan(): void {
			$locked = array(
				'available' => false,
				'reason'    => 'tier',
				'min_tier'  => 'professional',
			);
			$this->assertTrue( ReportedIP_Hive_Protection_Page::section_locked( 'hardening_mode', $this->statuses_for( 'hardening_mode', $locked ) ) );

			$partly = $this->statuses_for( 'hardening_mode', $locked );
			$partly['reportedip_hive_hardening_duration_minutes'] = array( 'available' => true );
			$this->assertFalse( ReportedIP_Hive_Protection_Page::section_locked( 'hardening_mode', $partly ), 'one open key opens the section' );

			$partial = $this->statuses_for( 'hardening_mode', $locked + array( 'partial' => true ) );
			$this->assertFalse( ReportedIP_Hive_Protection_Page::section_locked( 'hardening_mode', $partial ), 'a partial field is editable' );

			$runtime = $this->statuses_for( 'hardening_mode', array( 'available' => false, 'reason' => 'runtime' ) );
			$this->assertFalse( ReportedIP_Hive_Protection_Page::section_locked( 'hardening_mode', $runtime ), 'a runtime lock is not a plan lock' );

			$this->assertFalse( ReportedIP_Hive_Protection_Page::section_locked( 'blocking', array() ), 'no status means open' );
		}

		public function test_tab_state_aggregates_the_section_states(): void {
			$on = array(
				'reportedip_hive_waf_enabled'      => 1,
				'reportedip_hive_headers_enabled'  => 1,
				'reportedip_hive_rest_access_mode' => 'open',
			);
			$this->assertSame(
				array( 'text' => 'Active', 'tone' => 'success', 'plan' => '' ),
				ReportedIP_Hive_Protection_Page::tab_state( 'firewall', $on, array() ),
				'lockdown is neutral and does not count'
			);

			$some = array( 'reportedip_hive_waf_enabled' => 1 ) + $on;
			$some['reportedip_hive_headers_enabled'] = 0;
			$this->assertSame(
				array( 'text' => '1 of 2 active', 'tone' => 'neutral', 'plan' => '' ),
				ReportedIP_Hive_Protection_Page::tab_state( 'firewall', $some, array() )
			);

			$off = $on;
			$off['reportedip_hive_waf_enabled']     = 0;
			$off['reportedip_hive_headers_enabled'] = 0;
			$this->assertSame(
				array( 'text' => 'Off', 'tone' => 'danger', 'plan' => '' ),
				ReportedIP_Hive_Protection_Page::tab_state( 'firewall', $off, array() )
			);
		}

		public function test_tab_state_names_the_plan_when_every_section_is_locked(): void {
			$locked   = array(
				'available' => false,
				'reason'    => 'tier',
				'min_tier'  => 'professional',
			);
			$statuses = $this->statuses_for( 'hardening_mode', $locked ) + $this->statuses_for( 'twofa_policies', $locked );
			$this->assertSame(
				array( 'text' => '', 'tone' => 'neutral', 'plan' => 'professional' ),
				ReportedIP_Hive_Protection_Page::tab_state( 'advanced', array(), $statuses )
			);

			$this->assertSame(
				array( 'text' => '', 'tone' => 'neutral', 'plan' => '' ),
				ReportedIP_Hive_Protection_Page::tab_state( 'nope', array(), array() ),
				'an unknown tab counts nothing and shows no pill'
			);

			$paid = $this->statuses_for( 'twofa_policies', $locked );
			$this->assertSame(
				array( 'text' => 'Active', 'tone' => 'success', 'plan' => '' ),
				ReportedIP_Hive_Protection_Page::tab_state( 'advanced', array( 'reportedip_hive_hardening_realtime_detection' => 1 ), $paid ),
				'one open section decides, a locked one is left out'
			);
		}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `vendor/bin/phpunit --no-coverage --filter 'test_section_locked|test_tab_state' tests/Unit/ProtectionPageTest.php`
Expected: 3 errors, undefined method `section_locked`.

- [ ] **Step 3: Implement both helpers**

Insert after `section_state()`:

```php
	/**
	 * Whether every key of a section sits behind the plan.
	 *
	 * Only a plan lock counts (`reason` `tier`, not `partial`). A runtime
	 * lock, a partial field or a single open key leaves the section open.
	 *
	 * @param string                            $section  Section id.
	 * @param array<string,array<string,mixed>> $statuses Key => status from {@see field_status()}.
	 * @return bool
	 * @since  2.1.69
	 */
	public static function section_locked( $section, array $statuses ) {
		$keys = self::visible_keys( $section, true, array() );
		if ( array() === $keys ) {
			return false;
		}
		foreach ( $keys as $key ) {
			$status = $statuses[ $key ] ?? array( 'available' => true );
			if ( ! empty( $status['available'] ) || 'tier' !== (string) ( $status['reason'] ?? '' ) || ! empty( $status['partial'] ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Short state of one tab, aggregated from its section states.
	 *
	 * Counting sections rather than switches keeps the pill and the
	 * dashboard area rows on the same verdict, and keeps a switch whose
	 * "on" means less protection (report-only, minimal logging) from being
	 * read as protection. A locked section is left out and remembered; a
	 * neutral section is left out. `plan` names the plan a fully locked tab
	 * waits for, so the renderer can label it without this method needing
	 * the mode manager.
	 *
	 * @param string                            $tab      Tab slug.
	 * @param array<string,mixed>               $current  Current values.
	 * @param array<string,array<string,mixed>> $statuses Key => status from {@see field_status()}.
	 * @return array{text:string,tone:string,plan:string}
	 * @since  2.1.69
	 */
	public static function tab_state( $tab, array $current, array $statuses ) {
		$sections = self::tabs()[ $tab ]['sections'] ?? array();
		$counted  = 0;
		$on       = 0;
		$plan     = '';
		foreach ( $sections as $section ) {
			if ( self::section_locked( $section, $statuses ) ) {
				if ( '' === $plan ) {
					$first = self::visible_keys( $section, true, array() )[0];
					$plan  = (string) ( $statuses[ $first ]['min_tier'] ?? '' );
				}
				continue;
			}
			$tone = self::section_state( $section, $current )['tone'];
			if ( 'neutral' === $tone ) {
				continue;
			}
			++$counted;
			if ( 'success' === $tone ) {
				++$on;
			}
		}
		if ( 0 === $counted ) {
			return array(
				'text' => '',
				'tone' => 'neutral',
				'plan' => $plan,
			);
		}
		if ( $on === $counted ) {
			return array(
				'text' => __( 'Active', 'reportedip-hive' ),
				'tone' => 'success',
				'plan' => '',
			);
		}
		if ( 0 === $on ) {
			return array(
				'text' => __( 'Off', 'reportedip-hive' ),
				'tone' => 'danger',
				'plan' => '',
			);
		}
		return array(
			/* translators: 1: sections switched on, 2: sections counted */
			'text' => sprintf( __( '%1$d of %2$d active', 'reportedip-hive' ), $on, $counted ),
			'tone' => 'neutral',
			'plan' => '',
		);
	}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `vendor/bin/phpunit --no-coverage --filter 'test_section_locked|test_tab_state' tests/Unit/ProtectionPageTest.php`
Expected: `OK (3 tests, ...)`.

- [ ] **Step 5: Commit**

```bash
git add admin/class-protection-page.php tests/Unit/ProtectionPageTest.php
git commit -m "aggregate the section states into a tab state"
```

---

### Task 3: Reset values and the status map

**Files:**
- Modify: `admin/class-protection-page.php` (after `writable_values()`)
- Test: `tests/Unit/ProtectionPageTest.php`

- [ ] **Step 1: Write the failing test**

```php
		public function test_reset_values_keeps_only_the_recommendation_of_the_tab(): void {
			$firewall = ReportedIP_Hive_Protection_Page::reset_values( 'firewall', 'professional', 'community' );
			$this->assertSame( 1, $firewall['reportedip_hive_headers_enabled'] );
			$this->assertSame( 1, $firewall['reportedip_hive_hsts_enabled'] );
			$this->assertSame( 'block', $firewall['reportedip_hive_bot_action'] );
			$this->assertArrayNotHasKey( 'reportedip_hive_block_tor', $firewall, 'a key of another tab is left alone' );
			$this->assertArrayNotHasKey( 'reportedip_hive_waf_enabled', $firewall, 'a key without a recommendation is left alone' );

			$free = ReportedIP_Hive_Protection_Page::reset_values( 'firewall', 'free', 'local' );
			$this->assertSame( 'flag', $free['reportedip_hive_bot_action'] );
			$this->assertArrayNotHasKey( 'reportedip_hive_hsts_enabled', $free );

			$this->assertSame( array(), ReportedIP_Hive_Protection_Page::reset_values( 'nope', 'free', 'local' ) );
		}
```

- [ ] **Step 2: Run the test to see it fail**

Run: `vendor/bin/phpunit --no-coverage --filter test_reset_values tests/Unit/ProtectionPageTest.php`
Expected: error, undefined method `reset_values`.

- [ ] **Step 3: Implement `reset_values()` and `field_statuses()`**

Insert after `writable_values()`:

```php
	/**
	 * The recommendation for the keys of one tab.
	 *
	 * Pure. Keys the recommendation does not name are absent, so a reset
	 * leaves them where they are.
	 *
	 * @param string $tab  Tab slug.
	 * @param string $tier Tier slug.
	 * @param string $mode `community` or `local`.
	 * @return array<string,mixed>
	 * @since  2.1.69
	 */
	public static function reset_values( $tab, $tier, $mode ) {
		$keys = array();
		foreach ( self::tabs()[ $tab ]['sections'] ?? array() as $section ) {
			$keys = array_merge( $keys, self::visible_keys( $section, true, array() ) );
		}
		return array_intersect_key( ReportedIP_Hive_Defaults::recommended( (string) $tier, (string) $mode ), array_flip( $keys ) );
	}

	/**
	 * Lock status of every registry key for the current values.
	 *
	 * A plan lock additionally carries `plan_label` (the plan's display
	 * name) and `plan_url` (the pricing page with the feature key as the
	 * fragment), so {@see field_markup()} can draw the plan row without
	 * reaching for the mode manager itself.
	 *
	 * @param array<string,mixed>          $current      Current values.
	 * @param ReportedIP_Hive_Mode_Manager $mode_manager Mode manager.
	 * @return array<string,array<string,mixed>>
	 * @since  2.1.69
	 */
	public static function field_statuses( array $current, $mode_manager ) {
		$statuses = array();
		foreach ( ReportedIP_Hive_Settings_Registry::spec() as $key => $entry ) {
			$status = self::field_status( $entry, $key, $current[ $key ] ?? '', $mode_manager );
			if ( empty( $status['available'] ) && 'tier' === (string) ( $status['reason'] ?? '' ) && ! empty( $status['min_tier'] ) ) {
				$feature              = (string) ( $entry['tier'] ?? ( $entry['ui_lock'] ?? '' ) );
				$status['plan_label'] = (string) $mode_manager->get_tier_info( (string) $status['min_tier'] )['label'];
				$status['plan_url']   = ReportedIP_Hive_Admin_Settings::pricing_url() . ( '' !== $feature ? '#' . rawurlencode( $feature ) : '' );
			}
			$statuses[ $key ] = $status;
		}
		return $statuses;
	}
```

- [ ] **Step 4: Run the test to see it pass**

Run: `vendor/bin/phpunit --no-coverage --filter test_reset_values tests/Unit/ProtectionPageTest.php`
Expected: `OK (1 test, ...)`.

- [ ] **Step 5: Commit**

```bash
git add admin/class-protection-page.php tests/Unit/ProtectionPageTest.php
git commit -m "add the per-tab reset values"
```

---

### Task 4: Field rows, state text and the plan row

**Files:**
- Modify: `admin/class-protection-page.php` (`field_markup()`, new `plan_row_markup()`)
- Test: `tests/Unit/ProtectionPageTest.php`

- [ ] **Step 1: Adjust the existing lock test and add the row tests**

In `test_field_markup_carries_the_registry_name_and_the_lock()` replace the first block (the `block_tor` call and its four assertions) with:

```php
			$html = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_block_tor',
				array(
					'kind'        => 'bool',
					'tier'        => 'tor_blocking',
					'label'       => 'Block Tor',
					'description' => 'Refuse Tor.',
				),
				'0',
				array(
					'available'  => false,
					'min_tier'   => 'professional',
					'reason'     => 'tier',
					'label'      => 'Tor',
					'plan_label' => 'Professional',
					'plan_url'   => 'https://reportedip.com/pricing/#tor_blocking',
				)
			);
			$this->assertStringNotContainsString( 'name="reportedip_hive_block_tor"', $html, 'a plan-locked switch posts nothing' );
			$this->assertStringNotContainsString( '<input', $html );
			$this->assertStringContainsString( 'data-search="', $html );
			$this->assertStringContainsString( 'rip-protection__field--locked', $html );
			$this->assertStringContainsString( 'rip-protection__plan', $html );
			$this->assertStringContainsString( 'href="https://reportedip.com/pricing/#tor_blocking"', $html );
			$this->assertStringContainsString( 'Learn more', $html );
			$this->assertStringNotContainsString( 'rip-protection__state', $html, 'no on/off text without a switch' );
```

Append new tests:

```php
		public function test_switches_numbers_and_choices_render_as_rows(): void {
			$bool = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_auto_block',
				array( 'kind' => 'bool', 'label' => 'Auto block', 'description' => 'Block.' ),
				'1',
				array( 'available' => true )
			);
			$this->assertStringContainsString( 'rip-protection__field--row', $bool );
			$this->assertStringContainsString( '<span class="rip-protection__state" data-on="Active" data-off="Off" aria-hidden="true">Active</span>', $bool );

			$off = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_auto_block',
				array( 'kind' => 'bool', 'label' => 'Auto block', 'description' => 'Block.' ),
				'0',
				array( 'available' => true )
			);
			$this->assertStringContainsString( 'aria-hidden="true">Off</span>', $off );

			$int = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_block_duration',
				array( 'kind' => 'int', 'min' => 0, 'max' => 10, 'label' => 'Duration', 'description' => '' ),
				'5',
				array( 'available' => true )
			);
			$this->assertStringContainsString( 'rip-protection__field--row', $int );
			$this->assertStringNotContainsString( 'rip-protection__state', $int );

			$text = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_trusted_proxy_ranges',
				array( 'kind' => 'textarea', 'label' => 'Ranges', 'description' => '' ),
				'',
				array( 'available' => true )
			);
			$this->assertStringNotContainsString( 'rip-protection__field--row', $text );
		}

		public function test_a_plan_locked_list_keeps_its_disabled_control(): void {
			$html = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_prohibited_usernames',
				array( 'kind' => 'textarea', 'tier' => 'registration_rules_unlimited', 'label' => 'Names', 'description' => '' ),
				"a\nb",
				array( 'available' => false, 'reason' => 'tier', 'min_tier' => 'professional' )
			);
			$this->assertStringContainsString( '<textarea', $html, 'stored text stays readable' );
			$this->assertStringContainsString( 'disabled', $html );
			$this->assertStringNotContainsString( 'rip-protection__plan', $html );
		}

		public function test_plan_row_markup_is_a_badge_and_a_link(): void {
			$html = ReportedIP_Hive_Protection_Page::plan_row_markup( 'Professional', 'https://example.org/p#f' );
			$this->assertSame(
				'<span class="rip-protection__plan"><span class="rip-badge rip-badge--warning">Professional feature</span><a class="rip-button rip-button--secondary rip-button--sm" href="https://example.org/p#f" target="_blank" rel="noopener">Learn more</a></span>',
				$html
			);
		}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `vendor/bin/phpunit --no-coverage --filter 'test_field_markup_carries|test_switches_numbers|test_a_plan_locked_list|test_plan_row_markup' tests/Unit/ProtectionPageTest.php`
Expected: 3 failures and 1 error (`plan_row_markup` undefined).

- [ ] **Step 3: Change `field_markup()`**

Replace the head of the method up to and including the `switch ( $kind )` opening, and the `bool` case, with:

```php
	public static function field_markup( $key, array $entry, $value, array $status, array $choices = array() ) {
		$gated    = empty( $status['available'] );
		$locked   = $gated && empty( $status['partial'] );
		$id       = self::field_id( $key );
		$label    = (string) ( $entry['label'] ?? $key );
		$desc     = (string) ( $entry['description'] ?? '' );
		$search   = self::search_terms( $key, $entry );
		$disabled = $locked ? ' disabled' : '';
		$kind     = (string) $entry['kind'];
		$row      = in_array( $kind, array( 'bool', 'int', 'enum' ), true );
		$plan_row = 'bool' === $kind && $locked && ! empty( $status['plan_url'] );
		$classes  = 'rip-protection__field' . ( $row ? ' rip-protection__field--row' : '' ) . ( $locked ? ' rip-protection__field--locked' : '' );

		if ( $plan_row ) {
			$control = self::plan_row_markup( (string) ( $status['plan_label'] ?? $status['min_tier'] ), (string) $status['plan_url'] );
			$kind    = 'plan';
		}

		switch ( $kind ) {
			case 'plan':
				break;
			case 'bool':
				$on      = ! empty( $value ) || ! empty( $status['forced'] );
				$control = sprintf(
					'<label class="rip-toggle"><input type="checkbox" class="rip-toggle__input" id="%1$s" name="%2$s" value="1"%3$s%4$s /><span class="rip-toggle__slider"></span></label><span class="rip-protection__state" data-on="%5$s" data-off="%6$s" aria-hidden="true">%7$s</span>',
					esc_attr( $id ),
					esc_attr( $key ),
					$on ? ' checked' : '',
					$disabled,
					esc_attr__( 'Active', 'reportedip-hive' ),
					esc_attr__( 'Off', 'reportedip-hive' ),
					$on ? esc_html__( 'Active', 'reportedip-hive' ) : esc_html__( 'Off', 'reportedip-hive' )
				);
				break;
```

Every other `case` stays. After the `switch`, change the marker block so a plan row carries no second marker:

```php
		$marker = '';
		$state  = $plan_row ? '' : self::tier_marker_state( $entry, $status );
```

The final `sprintf` stays as it is (the plan row goes out through `$control`).

Add the helper after `field_markup()`:

```php
	/**
	 * What a plan-locked switch shows in place of its toggle.
	 *
	 * @param string $plan_label Name of the plan the feature needs.
	 * @param string $href       Pricing link.
	 * @return string
	 * @since  2.1.69
	 */
	public static function plan_row_markup( $plan_label, $href ) {
		return sprintf(
			'<span class="rip-protection__plan"><span class="rip-badge rip-badge--warning">%1$s</span><a class="rip-button rip-button--secondary rip-button--sm" href="%2$s" target="_blank" rel="noopener">%3$s</a></span>',
			/* translators: %s: plan name, for example Professional */
			esc_html( sprintf( __( '%s feature', 'reportedip-hive' ), (string) $plan_label ) ),
			esc_url( (string) $href ),
			esc_html__( 'Learn more', 'reportedip-hive' )
		);
	}
```

- [ ] **Step 4: Run the whole unit file**

Run: `vendor/bin/phpunit --no-coverage tests/Unit/ProtectionPageTest.php tests/Unit/AdminSurfaceParityTest.php`
Expected: everything green except the stand-in tests, which Task 5 removes. `AdminSurfaceParityTest` passes `available => true`, so every key still emits its input.

- [ ] **Step 5: Commit**

```bash
git add admin/class-protection-page.php tests/Unit/ProtectionPageTest.php
git commit -m "render switches as rows and locked switches as a plan row"
```

---

### Task 5: The section renderer, stand-ins removed

**Files:**
- Modify: `admin/class-protection-page.php`
- Test: `tests/Unit/ProtectionPageTest.php`

- [ ] **Step 1: Remove the stand-in tests, add the section test**

Delete these tests: `test_sections_without_a_simple_key_are_reported`, `test_an_adapter_switch_joins_the_simple_view_with_its_plugin`, `test_the_simple_view_never_renders_a_control_for_an_expert_setting`, `test_expert_summary_names_a_few_settings_and_counts_the_rest`, `test_the_section_head_carries_the_chevron_and_the_tinted_status`.

In the `namespace {}` block at the top of the test file add three requires after the registry, because `section_markup()` reaches `Form_Adapters::names()` for a missing form plugin and `choices_note()` reaches `Login_Context` and `Mode_Manager` for the policy keys (all three load cleanly in the mocked bootstrap; without them the test only passes when an earlier test file happened to load the classes):

```php
	require_once dirname( __DIR__, 2 ) . '/includes/class-form-adapters.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-login-context.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-mode-manager.php';
```

`wp_roles()` is not stubbed, so the tests hand `section_markup()` a choice map for every `json_list` key through its last parameter. Add the helpers and the tests:

```php
		/**
		 * @return array{0:array<string,mixed>,1:array<string,array<string,mixed>>,2:array<string,array<string,string>>}
		 */
		private function section_fixture(): array {
			$current  = \ReportedIP_Hive_Defaults::all_option_defaults();
			$statuses = array();
			$choices  = array();
			foreach ( \ReportedIP_Hive_Settings_Registry::spec() as $key => $entry ) {
				$statuses[ $key ] = array( 'available' => true );
				if ( 'json_list' === $entry['kind'] ) {
					$choices[ $key ] = array( 'x' => 'X' );
				}
			}
			return array( $current, $statuses, $choices );
		}

		public function test_section_markup_puts_main_rows_first_and_the_rest_behind_details(): void {
			list( $current, $statuses, $choices ) = $this->section_fixture();

			$closed = ReportedIP_Hive_Protection_Page::section_markup( 'blocking', $current, $statuses, false, array(), array(), $choices );
			$this->assertStringContainsString( 'id="blocking"', $closed );
			$this->assertStringContainsString( 'class="rip-protection__section-head"', $closed );
			$this->assertStringContainsString( 'rip-protection__status', $closed );
			$this->assertStringContainsString( '<details class="rip-protection__details">', $closed );
			$this->assertStringContainsString( 'Show technical details', $closed );
			$this->assertLessThan(
				strpos( $closed, 'name="reportedip_hive_block_ladder_minutes"' ),
				strpos( $closed, '<details' ),
				'an expert key sits inside the details'
			);
			$this->assertGreaterThan(
				strpos( $closed, 'name="reportedip_hive_auto_block"' ),
				strpos( $closed, '<details' ),
				'a simple key sits before the details'
			);

			$open = ReportedIP_Hive_Protection_Page::section_markup( 'blocking', $current, $statuses, true, array(), array(), $choices );
			$this->assertStringContainsString( '<details class="rip-protection__details" open>', $open );

			$headers = ReportedIP_Hive_Protection_Page::section_markup( 'headers', $current, $statuses, false, array(), array(), $choices );
			$this->assertLessThan(
				strpos( $headers, 'name="reportedip_hive_' ),
				strpos( $headers, '<details' ),
				'a section without a main row is head plus details: every field sits inside the details'
			);

			$errors = ReportedIP_Hive_Protection_Page::section_markup( 'blocking', $current, $statuses, false, array(), array( 'reportedip_hive_block_duration' => 'Too long.' ), $choices );
			$this->assertStringContainsString( 'data-for="reportedip_hive_block_duration">Too long.', $errors );

			$detection = ReportedIP_Hive_Protection_Page::section_markup( 'detection', $current, $statuses, false, array(), array(), $choices );
			$this->assertStringContainsString( 'name="rip_protection_level"', $detection );

			$forms = ReportedIP_Hive_Protection_Page::section_markup( 'forms', $current, $statuses, false, array( 'cf7' ), array(), $choices );
			$this->assertLessThan( strpos( $forms, '<details' ), strpos( $forms, 'name="reportedip_hive_form_proof_cf7"' ), 'a detected form plugin makes its switch a main row' );
			$this->assertStringContainsString( 'Gravity Forms is not active on this site.', $forms, 'a missing form plugin is named in the details' );
		}

		public function test_section_markup_renders_every_key_of_the_section(): void {
			list( $current, $statuses, $choices ) = $this->section_fixture();
			foreach ( array_keys( \ReportedIP_Hive_Settings_Registry::sections() ) as $section ) {
				$html = ReportedIP_Hive_Protection_Page::section_markup( $section, $current, $statuses, false, array(), array(), $choices );
				foreach ( ReportedIP_Hive_Protection_Page::visible_keys( $section, true, array() ) as $key ) {
					$this->assertStringContainsString( 'name="' . $key, $html, "{$section} does not render {$key}" );
				}
			}
		}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `vendor/bin/phpunit --no-coverage --filter test_section_markup tests/Unit/ProtectionPageTest.php`
Expected: 2 errors, undefined method `section_markup`.

- [ ] **Step 3: Delete the stand-in helpers**

Remove from `admin/class-protection-page.php`: `expert_only_keys()`, `section_is_expert_only()`, `hint_markup()`, `expert_summary()`, `expert_jump_url()`, `summary_markup()`, `render_expert_hints()`, `render_section_tools_link()`. Keep `missing_form_plugin()` and `hint_reason()` (the adapter note in the details uses them). Change the private `section_keys()` into the two-line body of `visible_keys()`:

```php
	public static function visible_keys( $section, $expert, $detected = null ) {
		$detected = null === $detected ? self::detected_forms() : array_map( 'strval', (array) $detected );
		$keys     = array();
		foreach ( ReportedIP_Hive_Settings_Registry::spec() as $key => $entry ) {
			if ( ( $entry['section'] ?? '' ) === $section && self::is_visible( $entry, (bool) $expert, $detected ) ) {
				$keys[] = $key;
			}
		}
		return $keys;
	}
```

and delete `section_keys()`.

In `handle_expert_toggle()` delete the `$anchor` lines (from `$anchor = isset(...)` through the closing `}` of the `if ( '' !== $anchor )` block).

Update the `search_terms()` DocBlock: replace "Shared by the rendered field and by the stand-in the simple view draws for an expert setting, so a search behaves the same in both views." with "Shared by every rendered field, so a search behaves the same in every tab."

- [ ] **Step 4: Add `section_markup()`**

Insert before `render_page()`:

```php
	/**
	 * One section inside a tab panel: head, main rows, technical details.
	 *
	 * Every key of the section is rendered, the day-to-day keys as rows
	 * and the rest inside a `<details>` that starts open in expert mode.
	 * A closed details block still posts its fields, so nothing here can
	 * come back empty on the next save; a locked field is still dropped by
	 * {@see writable_values()}.
	 *
	 * @param string                            $section  Section id.
	 * @param array<string,mixed>               $current  Current values.
	 * @param array<string,array<string,mixed>> $statuses Key => status from {@see field_statuses()}.
	 * @param bool                              $expert   Whether the details start open.
	 * @param string[]                          $detected Adapter slugs whose form plugin is active.
	 * @param array<string,string>              $errors   Key => message from the last save.
	 * @param array<string,array<string,mixed>> $choices  Key => choice map for `json_list` keys; resolved through {@see choices_for()} when absent.
	 * @return string
	 * @since  2.1.69
	 */
	public static function section_markup( $section, array $current, array $statuses, $expert, array $detected, array $errors, array $choices = array() ) {
		$meta  = ReportedIP_Hive_Settings_Registry::sections()[ $section ] ?? array();
		$spec  = ReportedIP_Hive_Settings_Registry::spec();
		$state = self::section_state( $section, $current );
		$main  = self::visible_keys( $section, false, $detected );
		$rest  = array_values( array_diff( self::visible_keys( $section, true, $detected ), $main ) );

		$rows = static function ( array $keys ) use ( $spec, $current, $statuses, $errors, $detected, $choices ) {
			$out = '';
			foreach ( $keys as $key ) {
				$entry  = $spec[ $key ];
				$status = $statuses[ $key ] ?? array( 'available' => true );
				$note   = 'json_list' === $entry['kind'] ? self::choices_note( $key ) : '';
				$missed = self::missing_form_plugin( $entry, $detected );
				if ( '' !== $missed && empty( $status['note'] ) ) {
					$note = trim( $note . ' ' . self::hint_reason( $missed ) );
				}
				if ( '' !== $note ) {
					$status['note'] = trim( (string) ( $status['note'] ?? '' ) . ' ' . $note );
				}
				$map  = isset( $choices[ $key ] ) ? $choices[ $key ] : ( 'json_list' === $entry['kind'] ? self::choices_for( $entry, $key ) : array() );
				$out .= self::field_markup( $key, $entry, $current[ $key ] ?? '', $status, $map );
				if ( isset( $errors[ $key ] ) ) {
					$out .= '<p class="rip-alert rip-alert--error rip-protection__error" data-for="' . esc_attr( $key ) . '">' . esc_html( (string) $errors[ $key ] ) . '</p>';
				}
			}
			return $out;
		};

		$html = sprintf(
			'<div class="rip-protection__section" id="%1$s"><div class="rip-protection__section-head"><span class="rip-protection__title">%2$s</span><span class="rip-protection__desc">%3$s</span><span class="rip-badge rip-badge--%4$s rip-protection__status">%5$s</span></div>',
			esc_attr( $section ),
			esc_html( (string) ( $meta['label'] ?? $section ) ),
			esc_html( (string) ( $meta['description'] ?? '' ) ),
			esc_attr( $state['tone'] ),
			esc_html( $state['text'] )
		);
		if ( 'detection' === $section ) {
			ob_start();
			self::render_preset_field( self::current_preset( $current ) );
			$html .= (string) ob_get_clean();
		}
		$html .= $rows( $main );
		if ( array() !== $rest ) {
			$html .= sprintf(
				'<details class="rip-protection__details"%1$s><summary><svg class="rip-protection__chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><polyline points="6 9 12 15 18 9"/></svg>%2$s</summary>%3$s</details>',
				$expert ? ' open' : '',
				esc_html__( 'Show technical details', 'reportedip-hive' ),
				$rows( $rest )
			);
		}
		return $html . '</div>';
	}
```

- [ ] **Step 5: Run the unit file and PHPStan**

Run: `vendor/bin/phpunit --no-coverage tests/Unit/ProtectionPageTest.php && vendor/bin/phpstan analyse --memory-limit=2G admin/class-protection-page.php`
Expected: `OK`, and `[OK] No errors`. `render_page()` still references the removed helpers at this point; PHPStan reports them. Fix them in Task 6, so run PHPStan again there. If PHPStan blocks here, continue to Task 6 and commit both tasks together.

- [ ] **Step 6: Commit**

```bash
git add admin/class-protection-page.php tests/Unit/ProtectionPageTest.php
git commit -m "render a section as rows plus technical details"
```

---

### Task 6: The page

**Files:**
- Modify: `admin/class-protection-page.php` (`render_page()`, new `active_tab()`, `render_page_banner()`)

- [ ] **Step 1: Add `active_tab()`**

Insert before `render_page()`:

```php
	/**
	 * Slug of the tab the request asks for.
	 *
	 * @param string $requested Value of the `tab` parameter.
	 * @return string A known slug; the first tab when the parameter is missing or unknown.
	 * @since  2.1.69
	 */
	public static function active_tab( $requested ) {
		$tabs = self::tabs();
		$slug = sanitize_key( (string) $requested );
		return isset( $tabs[ $slug ] ) ? $slug : (string) array_key_first( $tabs );
	}
```

- [ ] **Step 2: Replace `render_page()`**

```php
	public static function render_page() {
		$expert  = self::is_expert();
		$current = ReportedIP_Hive_Settings_Registry::current_values();
		$user_id = get_current_user_id();
		$result  = get_transient( self::RESULT_TRANSIENT . $user_id );
		$result  = is_array( $result ) ? $result : array();
		delete_transient( self::RESULT_TRANSIENT . $user_id );
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$statuses     = self::field_statuses( $current, $mode_manager );
		$detected     = self::detected_forms();
		$active       = self::active_tab( isset( $_GET[ self::TAB_PARAM ] ) ? wp_unslash( $_GET[ self::TAB_PARAM ] ) : '' ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only tab choice, sanitised in active_tab()
		$page_url     = ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=' . self::PAGE_SLUG );
		$errors       = ! empty( $result['errors'] ) && is_array( $result['errors'] ) ? $result['errors'] : array();

		ReportedIP_Hive_Admin_Settings::render_page_header(
			__( 'Protection', 'reportedip-hive' ),
			__( 'Every setting, grouped by area; the technical details fold away', 'reportedip-hive' )
		);
		?>
		<div class="rip-content rip-protection">
			<?php self::render_page_banner(); ?>
			<div class="rip-protection__search">
				<input type="search" id="rip-protection-search" class="rip-input" placeholder="<?php esc_attr_e( 'Search settings, e.g. Tor, HSTS, retention', 'reportedip-hive' ); ?>" autocomplete="off" />
				<p class="rip-help-text rip-protection__no-results rip-hidden" id="rip-protection-no-results"><?php esc_html_e( 'No setting matches.', 'reportedip-hive' ); ?></p>
			</div>
			<?php if ( isset( $result['applied'] ) ) : ?>
				<div class="rip-alert <?php echo array() === $errors ? 'rip-alert--success' : 'rip-alert--warning'; ?>">
					<?php
					if ( array() !== $errors ) {
						/* translators: %d: number of rejected settings */
						echo esc_html( sprintf( _n( '%d field was not saved, see the marked field.', '%d fields were not saved, see the marked fields.', count( $errors ), 'reportedip-hive' ), count( $errors ) ) );
					} elseif ( ! empty( $result['reset'] ) ) {
						/* translators: %d: number of changed settings */
						echo esc_html( sprintf( _n( '%d setting set back to the recommendation.', '%d settings set back to the recommendation.', (int) $result['applied'], 'reportedip-hive' ), (int) $result['applied'] ) );
					} else {
						/* translators: %d: number of changed settings */
						echo esc_html( sprintf( _n( '%d setting saved.', '%d settings saved.', (int) $result['applied'], 'reportedip-hive' ), (int) $result['applied'] ) );
					}
					?>
				</div>
			<?php endif; ?>
			<nav class="rip-nav-tabs rip-protection__tabs" aria-label="<?php esc_attr_e( 'Protection areas', 'reportedip-hive' ); ?>">
				<?php foreach ( self::tabs() as $slug => $tab ) : ?>
					<?php $state = self::tab_state( $slug, $current, $statuses ); ?>
					<?php
					$pill = $state['text'];
					if ( '' === $pill && '' !== $state['plan'] ) {
						$pill = (string) $mode_manager->get_tier_info( $state['plan'] )['label'];
					}
					?>
					<a href="<?php echo esc_url( add_query_arg( self::TAB_PARAM, $slug, $page_url ) ); ?>" class="rip-nav-tabs__tab<?php echo $slug === $active ? ' rip-nav-tabs__tab--active' : ''; ?>" data-tab="<?php echo esc_attr( $slug ); ?>">
						<?php echo self::tab_icon( $tab['icon'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static inline SVG ?>
						<span><?php echo esc_html( $tab['label'] ); ?></span>
						<?php if ( '' !== $pill ) : ?>
							<span class="rip-badge rip-badge--<?php echo esc_attr( $state['tone'] ); ?>"><?php echo esc_html( $pill ); ?></span>
						<?php endif; ?>
					</a>
				<?php endforeach; ?>
			</nav>
			<?php foreach ( self::tabs() as $slug => $tab ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="rip-card rip-protection__panel<?php echo $slug === $active ? '' : ' rip-hidden'; ?>" data-tab="<?php echo esc_attr( $slug ); ?>">
					<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_SAVE ); ?>" />
					<input type="hidden" name="rip_tab" value="<?php echo esc_attr( $slug ); ?>" />
					<?php wp_nonce_field( self::NONCE ); ?>
					<div class="rip-card__body">
						<div class="rip-alert rip-alert--info"><?php echo esc_html( $tab['advice'] ); ?></div>
						<?php foreach ( $tab['sections'] as $section ) : ?>
							<?php echo self::section_markup( $section, $current, $statuses, $expert, $detected, $errors ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside ?>
						<?php endforeach; ?>
						<div class="rip-card__footer rip-protection__footer">
							<button type="submit" name="rip_reset" value="1" class="rip-button rip-button--ghost rip-protection__reset" data-confirm="<?php esc_attr_e( 'Set every setting of this tab back to the recommendation for your plan?', 'reportedip-hive' ); ?>"><?php esc_html_e( 'Restore defaults', 'reportedip-hive' ); ?></button>
							<button type="submit" class="rip-button rip-button--primary"><?php esc_html_e( 'Save changes', 'reportedip-hive' ); ?></button>
						</div>
					</div>
				</form>
			<?php endforeach; ?>
		</div>
		<?php
		ReportedIP_Hive_Admin_Settings::render_page_footer();
	}

	/**
	 * The status banner above the tabs, shared with the dashboard.
	 *
	 * @return void
	 * @since  2.1.69
	 */
	private static function render_page_banner() {
		if ( ! class_exists( 'ReportedIP_Hive_Dashboard_Next_Steps' ) ) {
			return;
		}
		?>
		<div class="rip-protection__banner">
			<?php ReportedIP_Hive_Dashboard_Next_Steps::render_banner( ReportedIP_Hive_API::get_instance() ); ?>
			<a class="rip-button rip-button--secondary rip-button--sm rip-protection__check" href="<?php echo esc_url( ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive' ) ); ?>"><?php esc_html_e( 'Check protection', 'reportedip-hive' ); ?></a>
		</div>
		<?php
	}
```

Delete the now unused `render_preset_field()`? No: `section_markup()` calls it. Keep it. Delete `$tools_url` and the tools link: the Tools page stays reachable through the menu and the dashboard.

- [ ] **Step 3: Update the class DocBlock**

Replace the file DocBlock summary lines with:

```
 * Protection page: five tabs over the registry sections, one form per tab.
 *
 * Every key is rendered in every view: the day-to-day keys as rows, the
 * rest behind "Show technical details", which expert mode opens by
 * default. Saving posts one tab to admin-post.php and writes through
 * `ReportedIP_Hive_Settings_Apply`, the same path MainWP, the cloud
 * fleet, the import and the quickstart use.
```

- [ ] **Step 4: PHPStan and PHPCS**

Run: `vendor/bin/phpstan analyse --memory-limit=2G admin/class-protection-page.php && vendor/bin/phpcs -q --runtime-set ignore_warnings_on_exit 1 admin/class-protection-page.php`
Expected: `[OK] No errors`, no PHPCS errors.

- [ ] **Step 5: Look at it**

Run from the workspace root: `./run.sh up` (if not running), then open `http://localhost:8080/wp-admin/admin.php?page=reportedip-hive-protection`. Expected: banner, five tabs, the first panel visible, the other four stacked below (the script hides them in Task 8).

- [ ] **Step 6: Commit**

```bash
git add admin/class-protection-page.php
git commit -m "render the protection page as five tabs"
```

---

### Task 7: Save and reset per tab

**Files:**
- Modify: `admin/class-protection-page.php` (`handle_save()`)

- [ ] **Step 1: Replace `handle_save()`**

```php
	/**
	 * admin-post handler: save or reset one tab through the apply service.
	 *
	 * See {@see writable_values()} for which posted keys are written and
	 * {@see reset_values()} for what a reset writes.
	 *
	 * @return void
	 */
	public function handle_save() {
		if ( ! ReportedIP_Hive_Option_Routing::current_user_can_manage() ) {
			wp_die( esc_html__( 'Permission denied.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::NONCE );
		$post = wp_unslash( $_POST ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- every value passes the registry sanitizer in Settings_Apply
		$tab  = isset( $post['rip_tab'] ) ? sanitize_key( $post['rip_tab'] ) : '';
		$tabs = self::tabs();
		if ( ! isset( $tabs[ $tab ] ) ) {
			wp_die( esc_html__( 'Unknown tab.', 'reportedip-hive' ), '', array( 'response' => 400 ) );
		}
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$current      = ReportedIP_Hive_Settings_Registry::current_values();
		$statuses     = self::field_statuses( $current, $mode_manager );
		$reset        = ! empty( $post['rip_reset'] );
		$values       = array();

		if ( $reset ) {
			$tier   = (string) ( $mode_manager->get_tier_info()['key'] ?? 'free' );
			$values = self::reset_values( $tab, $tier, (string) $mode_manager->get_mode() );
			$values = self::writable_values( $values, array_keys( $values ), $statuses );
		} else {
			foreach ( $tabs[ $tab ]['sections'] as $section ) {
				$all     = self::visible_keys( $section, true, array() );
				$values += self::writable_values( self::collect_values( (array) $post, $section ), $all, $statuses );
			}
		}

		$result = ReportedIP_Hive_Settings_Apply::apply( $values, 'admin' );
		$errors = array();
		foreach ( $result['results'] as $key => $row ) {
			if ( in_array( $row['status'], array( ReportedIP_Hive_Settings_Apply::STATUS_INVALID, ReportedIP_Hive_Settings_Apply::STATUS_SKIPPED_TIER ), true ) ) {
				$errors[ $key ] = (string) ( $row['message'] ?? __( 'Rejected.', 'reportedip-hive' ) );
			}
		}
		set_transient(
			self::RESULT_TRANSIENT . get_current_user_id(),
			array(
				'tab'     => $tab,
				'applied' => (int) $result['applied'],
				'errors'  => $errors,
				'reset'   => $reset,
			),
			60
		);
		$url = add_query_arg( self::TAB_PARAM, $tab, ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=' . self::PAGE_SLUG ) );
		if ( array() !== $errors ) {
			$spec = ReportedIP_Hive_Settings_Registry::spec();
			$url .= '#' . (string) ( $spec[ array_key_first( $errors ) ]['section'] ?? $tab );
		}
		wp_safe_redirect( $url );
		exit;
	}
```

Note on `visible_keys( $section, true, array() )`: with `$expert = true` every key of the section is returned, so `$detected` is irrelevant and an empty array saves the plugin probes.

- [ ] **Step 2: Try it in the browser**

On `http://localhost:8080/wp-admin/admin.php?page=reportedip-hive-protection&tab=operations` change the retention days, save. Expected: back on the Operations tab, "1 setting saved.", the section status shows the new value. Click "Restore defaults" (no confirm yet). Expected: "N settings set back to the recommendation." From the container: `docker exec reportedip-hive-wordpress-1 wp --allow-root option get reportedip_hive_data_retention_days` prints the recommendation for the stack's plan.

- [ ] **Step 3: PHPStan and PHPCS**

Run: `vendor/bin/phpstan analyse --memory-limit=2G admin/class-protection-page.php && vendor/bin/phpcs -q --runtime-set ignore_warnings_on_exit 1 admin/class-protection-page.php`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add admin/class-protection-page.php
git commit -m "save and reset the protection page per tab"
```

---

### Task 8: Script

**Files:**
- Rewrite: `assets/js/protection.js`

- [ ] **Step 1: Replace the file**

```javascript
/**
 * Protection page: tab switching, hash handling, search across tabs, the
 * on/off text next to a switch, the preset coupling and two guards (an
 * invalid field inside a closed details block, the reset confirmation).
 * No server roundtrip; everything the filter needs is in `data-search`.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     2.1.56
 */
(function () {
	'use strict';

	var root = document.querySelector('.rip-protection');
	if (!root) {
		return;
	}
	var tabs = root.querySelectorAll('.rip-protection__tabs .rip-nav-tabs__tab');
	var panels = root.querySelectorAll('.rip-protection__panel');
	var input = document.getElementById('rip-protection-search');
	var empty = document.getElementById('rip-protection-no-results');

	function activate(slug, pushUrl) {
		panels.forEach(function (panel) {
			panel.classList.toggle('rip-hidden', panel.dataset.tab !== slug);
		});
		tabs.forEach(function (tab) {
			tab.classList.toggle('rip-nav-tabs__tab--active', tab.dataset.tab === slug);
		});
		if (pushUrl && window.history && window.history.replaceState) {
			var url = new URL(window.location.href);
			url.searchParams.set('tab', slug);
			window.history.replaceState(null, '', url.toString());
		}
	}

	tabs.forEach(function (tab) {
		tab.addEventListener('click', function (event) {
			event.preventDefault();
			activate(tab.dataset.tab, true);
		});
	});

	function reveal() {
		var target = location.hash ? document.getElementById(location.hash.slice(1)) : null;
		if (!target) {
			return;
		}
		var panel = target.closest('.rip-protection__panel');
		if (panel) {
			activate(panel.dataset.tab, false);
		}
		var details = target.closest('details');
		if (details) {
			details.open = true;
		}
		target.scrollIntoView();
	}

	reveal();
	window.addEventListener('hashchange', reveal);

	function highlight(field, term) {
		var label = field.querySelector('.rip-label');
		if (!label) {
			return;
		}
		if (!label.dataset.text) {
			label.dataset.text = label.textContent;
		}
		var text = label.dataset.text;
		var idx = term ? text.toLowerCase().indexOf(term) : -1;
		if (idx < 0) {
			label.textContent = text;
			return;
		}
		label.textContent = '';
		label.appendChild(document.createTextNode(text.slice(0, idx)));
		var mark = document.createElement('mark');
		mark.textContent = text.slice(idx, idx + term.length);
		label.appendChild(mark);
		label.appendChild(document.createTextNode(text.slice(idx + term.length)));
	}

	function filter() {
		var term = input.value.trim().toLowerCase();
		var hits = 0;
		root.classList.toggle('rip-protection--searching', term !== '');
		root.querySelectorAll('.rip-protection__section').forEach(function (section) {
			var sectionHits = 0;
			section.querySelectorAll('.rip-protection__field').forEach(function (field) {
				var match = !term || (field.dataset.search || '').indexOf(term) >= 0;
				field.classList.toggle('rip-hidden', !match);
				highlight(field, match && term ? term : '');
				if (match) {
					sectionHits += 1;
					var details = field.closest('details');
					if (term && details) {
						details.open = true;
					}
				}
			});
			section.classList.toggle('rip-hidden', term !== '' && sectionHits === 0);
			hits += sectionHits;
		});
		if (term) {
			panels.forEach(function (panel) {
				panel.classList.toggle('rip-hidden', panel.querySelectorAll('.rip-protection__section:not(.rip-hidden)').length === 0);
			});
		} else {
			var active = root.querySelector('.rip-nav-tabs__tab--active');
			activate(active ? active.dataset.tab : panels[0].dataset.tab, false);
			root.querySelectorAll('.rip-protection__details').forEach(function (details) {
				details.open = details.hasAttribute('data-open');
			});
		}
		if (empty) {
			empty.classList.toggle('rip-hidden', !term || hits > 0);
		}
	}

	root.querySelectorAll('.rip-protection__details[open]').forEach(function (details) {
		details.setAttribute('data-open', '');
	});
	if (input) {
		input.addEventListener('input', filter);
	}

	root.addEventListener('change', function (event) {
		var box = event.target;
		if (!box.classList || !box.classList.contains('rip-toggle__input')) {
			return;
		}
		var state = box.closest('.rip-protection__control');
		state = state ? state.querySelector('.rip-protection__state') : null;
		if (state) {
			state.textContent = box.checked ? state.dataset.on : state.dataset.off;
		}
	});

	panels.forEach(function (panel) {
		panel.addEventListener('invalid', function (event) {
			var details = event.target.closest('details');
			if (details) {
				details.open = true;
			}
		}, true);
	});

	root.querySelectorAll('.rip-protection__reset').forEach(function (button) {
		button.addEventListener('click', function (event) {
			if (!window.confirm(button.dataset.confirm)) {
				event.preventDefault();
			}
		});
	});

	var presets = document.querySelectorAll('input[name="rip_protection_level"]');
	['failed_login_threshold', 'failed_login_timeframe', 'block_duration', 'block_threshold'].forEach(function (short) {
		var el = document.getElementById('rip-field-' + short);
		if (!el) {
			return;
		}
		el.addEventListener('input', function () {
			presets.forEach(function (radio) {
				radio.checked = radio.value === 'custom';
			});
		});
	});
})();
```

- [ ] **Step 2: Try it**

Reload the Protection page. Expected: only one panel visible; clicking a tab switches without reload and the URL gets `&tab=`; `#hardening_mode` in the URL opens the Advanced tab and scrolls to the section; typing `tor` in the search shows the Core protection panel with the Blocking section, its details open, `Tor` marked; clearing the search returns to the previous tab; a switch flips its "Active"/"Off" text; the reset button asks first.

- [ ] **Step 3: Commit**

```bash
git add assets/js/protection.js
git commit -m "drive the protection tabs, search and details from the script"
```

---

### Task 9: Stylesheet

**Files:**
- Modify: `assets/css/design-system.css` (the "Protection page" block, lines around 1613 to 1720)

- [ ] **Step 1: Replace the block**

Replace everything from the comment `Protection page (registry-rendered sections)` up to (not including) `.rip-tier-included {` with:

```css
/* ==========================================================================
   Protection page (tabs over the registry sections)
   ========================================================================== */
.rip-protection__banner {
    display: flex;
    align-items: flex-start;
    gap: var(--rip-space-4);
    margin-bottom: var(--rip-space-5);
}
.rip-protection__banner .rip-status-banner {
    flex: 1;
    margin-bottom: 0;
}
.rip-protection__check {
    flex-shrink: 0;
    align-self: center;
}
.rip-protection__search {
    margin-bottom: var(--rip-space-5);
}
.rip-protection__search .rip-input {
    max-width: 480px;
}
.rip-protection__tabs .rip-nav-tabs__tab .rip-badge {
    margin-left: var(--rip-space-1);
}
.rip-protection--searching .rip-protection__tabs {
    opacity: 0.5;
    pointer-events: none;
}
.rip-protection__panel .rip-alert--info {
    margin-bottom: var(--rip-space-4);
}
.rip-protection__section {
    padding: var(--rip-space-4) 0;
    border-top: 1px solid var(--rip-gray-200);
}
.rip-protection__section:first-of-type {
    border-top: 0;
}
.rip-protection__section-head {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    grid-template-areas: "title status" "desc status";
    gap: var(--rip-space-1) var(--rip-space-4);
    margin-bottom: var(--rip-space-2);
}
.rip-protection__title {
    grid-area: title;
    font-weight: 600;
    font-size: var(--rip-text-base);
    color: var(--rip-gray-900);
}
.rip-protection__desc {
    grid-area: desc;
    color: var(--rip-gray-600);
    font-size: var(--rip-text-sm);
}
.rip-protection__status {
    grid-area: status;
    align-self: center;
}
.rip-protection__field {
    padding: var(--rip-space-4) 0;
    border-bottom: 1px solid var(--rip-gray-100);
}
.rip-protection__field:last-of-type {
    border-bottom: 0;
}
.rip-protection__field-head {
    display: flex;
    align-items: center;
    gap: var(--rip-space-3);
    margin-bottom: var(--rip-space-2);
}
.rip-protection__field--row {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    grid-template-areas: "head control" "help control";
    column-gap: var(--rip-space-5);
    align-items: center;
}
.rip-protection__field--row .rip-protection__field-head {
    grid-area: head;
    margin-bottom: 0;
}
.rip-protection__field--row .rip-help-text {
    grid-area: help;
    margin: var(--rip-space-1) 0 0;
}
.rip-protection__field--row .rip-protection__control {
    grid-area: control;
    display: flex;
    align-items: center;
    gap: var(--rip-space-3);
    justify-content: flex-end;
}
.rip-protection__field--row .rip-input--sm {
    width: 6em;
}
.rip-protection__state {
    min-width: 3em;
    font-size: var(--rip-text-sm);
    font-weight: 600;
    color: var(--rip-gray-700);
}
.rip-protection__plan {
    display: inline-flex;
    align-items: center;
    gap: var(--rip-space-3);
}
.rip-protection__field--locked .rip-protection__control {
    opacity: 0.6;
}
.rip-protection__field--locked .rip-protection__plan {
    opacity: 1;
}
.rip-protection__details > summary {
    list-style: none;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: var(--rip-space-2);
    padding: var(--rip-space-3) 0;
    color: var(--rip-primary);
    font-size: var(--rip-text-sm);
    font-weight: 500;
}
.rip-protection__details > summary::-webkit-details-marker {
    display: none;
}
.rip-protection__chevron {
    width: 18px;
    height: 18px;
    transition: transform var(--rip-transition);
}
.rip-protection__details[open] > summary .rip-protection__chevron {
    transform: rotate(180deg);
}
.rip-protection__presets {
    display: flex;
    flex-wrap: wrap;
    gap: var(--rip-space-4);
}
.rip-protection__footer {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: var(--rip-space-3);
    margin-top: var(--rip-space-4);
}
.rip-protection__error {
    margin: var(--rip-space-2) 0 0;
}
.rip-protection mark {
    background: var(--rip-warning);
    color: var(--rip-gray-900);
    padding: 0 2px;
}
@media (max-width: 782px) {
    .rip-protection__banner,
    .rip-protection__field--row {
        display: block;
    }
    .rip-protection__field--row .rip-protection__control {
        justify-content: flex-start;
        margin-top: var(--rip-space-2);
    }
}
```

- [ ] **Step 2: Add the CSS assertions to the unit file**

Append to `ProtectionPageTest`:

```php
		public function test_the_details_summary_hides_the_native_marker_and_turns_the_chevron(): void {
			$css = (string) file_get_contents( dirname( __DIR__, 2 ) . '/assets/css/design-system.css' );
			$this->assertMatchesRegularExpression( '/\.rip-protection__details > summary \{[^}]*list-style: none;/s', $css );
			$this->assertStringContainsString( '.rip-protection__details > summary::-webkit-details-marker', $css );
			$this->assertStringContainsString( '.rip-protection__details[open] > summary .rip-protection__chevron', $css );
			$this->assertStringNotContainsString( '.rip-protection__hint', $css, 'the stand-ins are gone' );
		}
```

Run: `vendor/bin/phpunit --no-coverage --filter test_the_details_summary tests/Unit/ProtectionPageTest.php`
Expected: `OK`.

- [ ] **Step 3: Look at it on both widths**

Reload the page at desktop width and at 600 px (browser devtools). Expected: rows with the control on the right at desktop, stacked at 600 px; no horizontal scroll; the plan row shows badge and button side by side.

- [ ] **Step 4: Commit**

```bash
git add assets/css/design-system.css tests/Unit/ProtectionPageTest.php
git commit -m "style the protection tabs, rows and details"
```

---

### Task 10: E2E, single site

**Files:**
- Rewrite: `tests/e2e/specs/single-site/protection-page.spec.ts`
- Modify: `tests/e2e/specs/single-site/two-factor-policies.spec.ts`, `tests/e2e/specs/single-site/registration-rules.spec.ts`

- [ ] **Step 1: Rewrite the spec**

Keep the file header, the imports, `wp()`, `wpArgs()`, `forgetExpert()`, `test.describe.configure`, `beforeAll` and `afterAll` exactly as they are. Replace every `test(...)` block from `'simple mode shows the simple keys...'` down to (not including) `'expert mode lists the tools page...'` with:

```typescript
	test('five tabs with a status pill each, the first one open', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		const tabs = page.locator('.rip-protection__tabs .rip-nav-tabs__tab');
		await expect(tabs).toHaveCount(5);
		await expect(tabs.first()).toHaveClass(/rip-nav-tabs__tab--active/);
		await expect(page.locator('.rip-protection__panel[data-tab="basics"]')).toBeVisible();
		await expect(page.locator('.rip-protection__panel[data-tab="forms"]')).toBeHidden();
		await expect(page.locator('.rip-protection__tabs .rip-nav-tabs__tab[data-tab="advanced"] .rip-badge')).toContainText(/professional/i);
		await expect(page.locator('.rip-status-banner')).toBeVisible();
	});

	test('every key is rendered, the expert keys behind closed details', async ({ page }) => {
		forgetExpert();
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await expect(page.locator('#blocking input[name="reportedip_hive_auto_block"]')).toBeVisible();
		const ladder = page.locator('#blocking input[name="reportedip_hive_block_ladder_minutes"]');
		await expect(ladder).toHaveCount(1);
		await expect(ladder).toBeHidden();
		await expect(page.locator('#blocking .rip-protection__details')).not.toHaveAttribute('open', '');
		await page.locator('#blocking .rip-protection__details > summary').click();
		await expect(ladder).toBeVisible();
	});

	test('expert mode opens the details by default', async ({ page }) => {
		wp('user meta update admin reportedip_hive_expert_mode 1');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await expect(page.locator('#blocking .rip-protection__details')).toHaveAttribute('open', '');
		await expect(page.locator('#blocking input[name="reportedip_hive_block_ladder_minutes"]')).toBeVisible();
		forgetExpert();
	});

	test('a tab saves through the registry and reports the change', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection&tab=operations');
		await page.locator('#privacy_logs input[name="reportedip_hive_data_retention_days"]').fill('45');
		await page.locator('.rip-protection__panel[data-tab="operations"] button.rip-button--primary').click();
		await page.waitForURL(/tab=operations/);
		await expect(page.locator('.rip-alert--success')).toContainText('saved');
		expect(wp('option get reportedip_hive_data_retention_days')).toBe('45');
		await expect(page.locator('#privacy_logs .rip-protection__status')).toContainText('45 days');
		await expect(page.locator('.rip-protection__panel[data-tab="operations"]')).toBeVisible();
	});

	test('a closed details block still round-trips its values', async ({ page }) => {
		forgetExpert();
		wp('option update reportedip_hive_block_ladder_minutes "5,15,30,1440"');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('.rip-protection__panel[data-tab="basics"] button.rip-button--primary').click();
		await page.waitForURL(/tab=basics/);
		expect(wp('option get reportedip_hive_block_ladder_minutes')).toBe('5,15,30,1440');
	});

	test('the preset writes its four values and the status names it', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#detection input[name="rip_protection_level"][value="high"]').check();
		await page.locator('.rip-protection__panel[data-tab="basics"] button.rip-button--primary').click();
		await page.waitForURL(/tab=basics/);
		expect(wp('option get reportedip_hive_block_threshold')).toBe('60');
		expect(wp('option get reportedip_hive_failed_login_threshold')).toBe('3');
		await expect(page.locator('#detection .rip-protection__status')).toContainText('Strict');
	});

	test('a plan-locked switch shows the plan and a link instead of a control', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		const field = page.locator('#blocking .rip-protection__field[data-key="reportedip_hive_block_tor"]');
		await expect(field).toHaveClass(/rip-protection__field--locked/);
		await expect(field.locator('input')).toHaveCount(0);
		await expect(field.locator('.rip-protection__plan .rip-badge')).toContainText(/professional/i);
		await expect(field.locator('.rip-protection__plan a')).toHaveAttribute('href', /pricing\/#tor_blocking/);
	});

	test('a switched-on plan feature stays editable after a downgrade and a locked value survives a save', async ({ page }) => {
		wp('option update reportedip_hive_block_tor 1');
		wp('option update reportedip_hive_permissions_policy "camera=()"');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#blocking .rip-protection__details > summary').click();
		await expect(page.locator('#blocking input[name="reportedip_hive_block_tor"]')).toBeEnabled();
		await expect(page.locator('#blocking input[name="reportedip_hive_block_tor"]')).toBeChecked();
		await page.locator('.rip-protection__panel[data-tab="basics"] button.rip-button--primary').click();
		await page.waitForURL(/tab=basics/);
		expect(wp('option get reportedip_hive_block_tor')).toBe('1');

		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection&tab=firewall');
		await page.locator('#headers .rip-protection__details > summary').click();
		await expect(page.locator('#headers input[name="reportedip_hive_permissions_policy"]')).toBeDisabled();
		await page.locator('.rip-protection__panel[data-tab="firewall"] button.rip-button--primary').click();
		await page.waitForURL(/tab=firewall/);
		expect(wp('option get reportedip_hive_permissions_policy')).toBe('camera=()');
		wp('option update reportedip_hive_block_tor 0');
	});

	test('runtime locks and fixed choices render as the old tabs did', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#detection .rip-protection__details > summary').click();
		await expect(page.locator('#detection input[name="reportedip_hive_monitor_woocommerce"]')).toBeDisabled();
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection&tab=firewall');
		await page.locator('#lockdown .rip-protection__details > summary').click();
		const admin = page.locator('#lockdown input[type="checkbox"][name="reportedip_hive_rest_allowed_roles[]"][value="administrator"]');
		await expect(admin).toBeChecked();
		await expect(admin).toBeDisabled();
		await expect(page.locator('#lockdown input[type="hidden"][name="reportedip_hive_rest_allowed_roles[]"][value="administrator"]')).toHaveCount(1);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#account_security .rip-protection__details > summary').click();
		await expect(page.locator('#account_security input[name="reportedip_hive_2fa_allowed_methods[]"][value="sms"]')).toBeDisabled();
	});

	test('a stored role list renders checked and round-trips through save', async ({ page }) => {
		wpArgs('option', 'update', 'reportedip_hive_2fa_enforce_roles', '["editor"]', '--format=json');
		try {
			await loginAsAdmin(page);
			await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
			const card = page.locator('#account_security');
			await expect(card.locator('.rip-protection__status')).toContainText(/1 role enforced/i);
			const roles = 'input[type="checkbox"][name="reportedip_hive_2fa_enforce_roles[]"]';
			await expect(card.locator(`${roles}[value="editor"]`)).toBeChecked();
			await expect(card.locator(`${roles}[value="author"]`)).not.toBeChecked();
			await card.locator(`${roles}[value="author"]`).check();
			await page.locator('.rip-protection__panel[data-tab="basics"] button.rip-button--primary').click();
			await page.waitForURL(/tab=basics/);
			await expect(card.locator('.rip-protection__status')).toContainText(/2 roles enforced/i);
			await expect(card.locator('.rip-alert--error')).toHaveCount(0);
			await expect(card.locator(`${roles}[value="author"]`)).toBeChecked();
		} finally {
			wpArgs('option', 'update', 'reportedip_hive_2fa_enforce_roles', '["administrator"]', '--format=json');
		}
	});

	test('search finds Tor across tabs, opens the details and marks the label', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection&tab=operations');
		await page.fill('#rip-protection-search', 'tor');
		await expect(page.locator('.rip-protection__panel[data-tab="basics"]')).toBeVisible();
		await expect(page.locator('#blocking .rip-protection__details')).toHaveAttribute('open', '');
		await expect(page.locator('#blocking mark').first()).toContainText(/tor/i);
		await expect(page.locator('#notifications')).toHaveClass(/rip-hidden/);
		await expect(page.locator('#rip-protection-no-results')).toHaveClass(/rip-hidden/);
		await page.fill('#rip-protection-search', '');
		await expect(page.locator('.rip-protection__panel[data-tab="operations"]')).toBeVisible();
		await expect(page.locator('.rip-protection__panel[data-tab="basics"]')).toBeHidden();
	});

	test('a section link opens its tab', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection#hardening_mode');
		await expect(page.locator('.rip-protection__panel[data-tab="advanced"]')).toBeVisible();
		await expect(page.locator('#hardening_mode')).toBeVisible();
	});

	test('restore defaults writes the recommendation of the tab and leaves the rest alone', async ({ page }) => {
		wp('option update reportedip_hive_headers_enabled 0');
		wp('option update reportedip_hive_waf_enabled 0');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection&tab=firewall');
		page.once('dialog', (dialog) => dialog.accept());
		await page.locator('.rip-protection__panel[data-tab="firewall"] .rip-protection__reset').click();
		await page.waitForURL(/tab=firewall/);
		await expect(page.locator('.rip-alert--success')).toContainText('recommendation');
		expect(wp('option get reportedip_hive_headers_enabled')).toBe('1');
		expect(wp('option get reportedip_hive_waf_enabled')).toBe('0');
		wp('option update reportedip_hive_waf_enabled 1');
	});
```

Keep the tests `'the uninstall switch lives on the tools page and round-trips'` and `'expert mode lists the tools page and the legacy urls land on their new home'` unchanged, except that in the legacy-URL test any `summary` click or `open` attribute assertion on a section is replaced by `await expect(page.locator('#<section>')).toBeVisible()`.

- [ ] **Step 2: Adjust the two neighbouring specs**

`two-factor-policies.spec.ts`: before every `#twofa_policies input[...]` interaction add a navigation to `&tab=advanced` (the section sits on that tab) and, where a field inside the details is touched, `await page.locator('#twofa_policies .rip-protection__details > summary').click();` once after the page load. Replace `'#twofa_policies form button[type="submit"]'` with `'.rip-protection__panel[data-tab="advanced"] button.rip-button--primary'`. The `administrator` choice lock (line 167) and the `rip-protection__field--locked` assertion (line 197) stay.

`registration-rules.spec.ts` (single site): navigate to `&tab=forms`; open the details of `#registration` once per page load before filling `textarea[name="reportedip_hive_prohibited_usernames"]` (the textarea is a technical detail); replace `'#registration form button[type="submit"]'` with `'.rip-protection__panel[data-tab="forms"] button.rip-button--primary'`. The error paragraph selector (line 362) and the `toBeAttached()` loop (line 405) stay.

- [ ] **Step 3: Run the three specs**

Run from the workspace root: `./run.sh e2e -- --grep "protection page|two-factor policies|registration rules"` (the exact `--grep` pass-through is in `cmd_e2e()` of `run.sh`; if it does not forward arguments, run `cd dev/tests/e2e && npx playwright test --project=single-site specs/single-site/protection-page.spec.ts specs/single-site/two-factor-policies.spec.ts specs/single-site/registration-rules.spec.ts` with the base URL the script derives from `.env`).
Expected: all passed.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/specs/single-site/protection-page.spec.ts tests/e2e/specs/single-site/two-factor-policies.spec.ts tests/e2e/specs/single-site/registration-rules.spec.ts
git commit -m "e2e: protection page tabs"
```

---

### Task 11: E2E, multisite

**Files:**
- Modify: `tests/e2e/specs/multisite/registration-rules.spec.ts`, `tests/e2e/specs/multisite/hardening-switches.spec.ts`

- [ ] **Step 1: Adjust the selectors**

`multisite/registration-rules.spec.ts` line 79: the `#registration .rip-protection__title` assertion needs the Forms tab, so the `goto` before it becomes `.../network/admin.php?page=reportedip-hive-protection&tab=forms`. `multisite/hardening-switches.spec.ts` line 137: the `goto` becomes `.../network/admin.php?page=reportedip-hive-protection&tab=firewall`; the two assertions stay.

- [ ] **Step 2: Run them**

Run from the workspace root: `./run.sh up-ms` (if not running), then `./run.sh e2e-ms` filtered to the two specs the same way as in Task 10.
Expected: passed.

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/specs/multisite/registration-rules.spec.ts tests/e2e/specs/multisite/hardening-switches.spec.ts
git commit -m "e2e: multisite selectors for the protection tabs"
```

---

### Task 12: Translations

**Files:**
- Modify: `languages/reportedip-hive.pot`, `languages/reportedip-hive-de_DE.po`, `languages/reportedip-hive-de_DE.mo`

- [ ] **Step 1: Regenerate the catalogue inside the container**

```bash
docker exec -w /var/www/html/wp-content/plugins/reportedip-hive reportedip-hive-wordpress-1 sh -c 'wp i18n make-pot . languages/reportedip-hive.pot --allow-root && wp i18n update-po languages/reportedip-hive.pot languages/reportedip-hive-de_DE.po --allow-root'
```

- [ ] **Step 2: Translate the new entries**

Open `languages/reportedip-hive-de_DE.po` and fill every empty `msgstr ""` and every `#, fuzzy` entry that this work introduced. German is formal ("Sie"), no dashes as punctuation, real umlauts. The strings and their translations:

| msgid | msgstr |
|---|---|
| Core protection | Grundschutz |
| Forms | Formulare |
| Firewall & Bots | Firewall & Bots |
| Advanced | Erweitert |
| Operations | Betrieb |
| Recommended: keep the defaults on. Change a threshold only when a sign-in or a block does not behave as expected. | Empfehlung: Lassen Sie die Standards aktiv. Ändern Sie eine Schwelle nur, wenn sich eine Anmeldung oder eine Sperre nicht wie erwartet verhält. |
| Recommended: keep the defaults on. Changes are only needed when a form does not work as expected. | Empfehlung: Lassen Sie die Standards aktiv. Änderungen sind nur nötig, wenn ein Formular nicht wie erwartet funktioniert. |
| Recommended: keep the firewall on. Add an exception on the Tools page before switching a rule off. | Empfehlung: Lassen Sie die Firewall an. Legen Sie auf der Werkzeuge-Seite eine Ausnahme an, bevor Sie eine Regel abschalten. |
| These settings only matter during a coordinated attack or for a second factor asked again. The recommendation covers both. | Diese Einstellungen greifen nur bei einem koordinierten Angriff oder wenn der zweite Faktor erneut verlangt wird. Die Empfehlung deckt beides ab. |
| Logs, mails and the footprint per request. None of it decides what is blocked. | Protokolle, Mails und der Aufwand je Anfrage. Nichts davon entscheidet, was gesperrt wird. |
| Active | Aktiv |
| Off | Aus |
| %1$d of %2$d active | %1$d von %2$d aktiv |
| %s feature | %s-Funktion |
| Learn more | Mehr erfahren |
| Show technical details | Technische Details anzeigen |
| Every setting, grouped by area; the technical details fold away | Alle Einstellungen nach Bereich, die technischen Details klappen weg |
| %d field was not saved, see the marked field. / plural | %d Feld wurde nicht gespeichert, siehe das markierte Feld. / %d Felder wurden nicht gespeichert, siehe die markierten Felder. |
| %d setting set back to the recommendation. / plural | %d Einstellung auf die Empfehlung zurückgesetzt. / %d Einstellungen auf die Empfehlung zurückgesetzt. |
| Protection areas | Schutzbereiche |
| Set every setting of this tab back to the recommendation for your plan? | Alle Einstellungen dieses Reiters auf die Empfehlung für Ihren Tarif zurücksetzen? |
| Restore defaults | Standard wiederherstellen |
| Save changes | Änderungen speichern |
| Check protection | Schutz prüfen |
| Unknown tab. | Unbekannter Reiter. |

Entries whose msgid no longer exists in the source (the stand-in strings) are marked obsolete by `update-po`; delete the `#~` blocks.

- [ ] **Step 3: Build and check**

```bash
docker exec -w /var/www/html/wp-content/plugins/reportedip-hive reportedip-hive-wordpress-1 sh -c 'wp i18n make-mo languages/ --allow-root && wp i18n make-json languages/ languages/ --allow-root'
docker exec -w /var/www/html/wp-content/plugins/reportedip-hive reportedip-hive-wordpress-1 su -s /bin/sh -c 'php bin/i18n-check.php' www-data
```
Expected: `[i18n] OK, POT fresh, German translation complete, MO/JSON in sync.`

- [ ] **Step 4: Commit**

```bash
git add languages/
git commit -m "translate the protection tabs"
```

---

### Task 13: Documentation

**Files:**
- Modify: `CHANGELOG.md`, `README.md`, `readme.txt`, `../CLAUDE.md`
- Modify (service repo): `C:\Users\Contex\Projekte\dev\web\reportedip.de\web\wp-content\plugins\reportedip-service\templates\shortcodes\docs\wordpress-plugin.php` and its `-de`, `-es`, `-fr` siblings

- [ ] **Step 1: CHANGELOG**

Under `## [Unreleased]` add a `### Changed` block (after the existing `### Security`):

```markdown
### Changed

- **The Protection page is five tabs instead of fourteen cards.** Core
  protection, Forms, Firewall & Bots, Advanced and Operations, each with a
  status pill. A switch is one row: name and a plain sentence on the left,
  the toggle and its state on the right. A switch the plan does not
  include shows the plan and a link instead of a greyed-out toggle. The
  expert settings of every area sit behind "Show technical details";
  expert mode opens them by default, and a closed block still saves its
  values. One "Save changes" and one "Restore defaults" per tab, the
  latter writing the recommendation for the plan. Every link into the
  page still lands on its area, and the settings registry, the remote
  schema and the apply path are unchanged.
```

- [ ] **Step 2: README.md**

Replace the bullet at line 229 (`- **One Protection page** rendered from the settings registry: fifteen collapsible cards ...`) with:

```markdown
- **One Protection page** rendered from the settings registry: five tabs (Core protection, Forms, Firewall & Bots, Advanced, Operations) over the fourteen areas, each area with a short status, its day-to-day switches as rows and the expert settings behind "Show technical details". A search box spans every tab. Each tab saves through the same apply service MainWP and the cloud fleet use, so plan limits and validation are identical on every path, and "Restore defaults" writes the recommendation for the plan
```

- [ ] **Step 3: readme.txt**

No changelog line here (that block is written at release time). Nothing else in `readme.txt` describes the card layout; leave it.

- [ ] **Step 4: CLAUDE.md**

In the admin classes table replace the `ReportedIP_Hive_Protection_Page` row with:

```
| `ReportedIP_Hive_Protection_Page` | `class-protection-page.php` | Schutz-Seite (seit 2.1.56, Tabs seit 2.1.69): fünf Tabs aus `tabs()` (`basics`, `forms`, `firewall`, `advanced`, `operations`) über den 14 Registry-Sektionen, Sektions-IDs bleiben die Anker. Je Sektion `section_markup()`: Kopf mit `section_state()`, Hauptzeilen (`simple`/`simple_form` bei erkanntem Plugin) und `<details class="rip-protection__details">` mit den Expertenfeldern, im Expertenmodus (User-Meta `reportedip_hive_expert_mode`) `open`. Tab-Pille aus `tab_state()` (aggregiert Sektions-Töne, komplett tarifgesperrte Sektionen liefern `plan`). Feld-Renderer `field_markup()` nach `kind`: bool/int/enum als Zeile, gesperrter bool-Schalter als `plan_row_markup()` (Badge + Link, kein Input). Ein Formular je Tab: `admin-post.php?action=reportedip_hive_protection_save` mit `rip_tab`, Save läuft je Sektion durch `collect_values()` + `writable_values()` (alle Keys der Sektion sind sichtbar), `rip_reset=1` schreibt `reset_values()` (= `Defaults::recommended()` der Tab-Keys), beides über `Settings_Apply::apply( $values, 'admin' )`. Suche über alle Tabs (`assets/js/protection.js`). Wertabhängige Tier-Gates (`tier_gate`) sperren das Feld nur, wenn der gespeicherte Wert den höheren Tarif braucht (`field_status()`) |
```

In the options section point 5 ("A locked field is never reset by a save") replace the last three sentences (from "For the same reason the simple view renders `Protection_Page::hint_markup()`" to the end of the point) with:

```
Every key is rendered in every view since 2.1.69; the expert keys sit in a
closed `<details>`, which the browser still submits, so nothing comes back
empty. A hidden input that is not rendered would come back empty with the
next save and overwrite the stored value without a word, which is why the
page never hides a control with `display:none` alone.
```

- [ ] **Step 5: Service docs**

In `wordpress-plugin.php` replace the paragraph at line 635 (`<p>All settings live on one page, <strong>ReportedIP Hive &rarr; Protection</strong>: fourteen cards, ...`) up to "always reachable by URL." with:

```html
<p>All settings live on one page, <strong>ReportedIP Hive &rarr; Protection</strong>: five tabs (Core protection, Forms, Firewall &amp; Bots, Advanced, Operations) over fourteen areas, each area with a short status, its day-to-day switches as rows and its expert settings behind &ldquo;Show technical details&rdquo;. A search box spans every tab, expert mode in the page header opens the details by default, and each tab carries &ldquo;Save changes&rdquo; and &ldquo;Restore defaults&rdquo;, the latter writing the recommendation for the plan. What is not a setting (the Extended Protection drop-in, server snippets, rule sync, exceptions, import/export, test mail) sits on <strong>Tools</strong>, listed in expert mode and always reachable by URL.
```

Keep the rest of the paragraph. Apply the same change to the German (`-de`), Spanish (`-es`) and French (`-fr`) files with the matching wording:

- de: `Alle Einstellungen liegen auf einer Seite, <strong>ReportedIP Hive &rarr; Schutz</strong>: fünf Reiter (Grundschutz, Formulare, Firewall &amp; Bots, Erweitert, Betrieb) über vierzehn Bereichen, jeder Bereich mit Kurzstatus, seinen Alltagsschaltern als Zeilen und seinen Expertenfeldern hinter &bdquo;Technische Details anzeigen&ldquo;. Die Suche greift über alle Reiter, der Expertenmodus im Seitenkopf öffnet die Details vorab, und jeder Reiter trägt &bdquo;Änderungen speichern&ldquo; und &bdquo;Standard wiederherstellen&ldquo;, letzteres schreibt die Empfehlung für den Tarif.`
- es: `Todos los ajustes están en una página, <strong>ReportedIP Hive &rarr; Protección</strong>: cinco pestañas (Protección básica, Formularios, Firewall y bots, Avanzado, Operación) sobre catorce áreas, cada área con un estado breve, sus interruptores diarios como filas y sus ajustes de experto tras &laquo;Mostrar detalles técnicos&raquo;. El buscador abarca todas las pestañas, el modo experto en la cabecera abre los detalles por defecto y cada pestaña lleva &laquo;Guardar cambios&raquo; y &laquo;Restaurar valores por defecto&raquo;, que escribe la recomendación del plan.`
- fr: `Tous les réglages tiennent sur une page, <strong>ReportedIP Hive &rarr; Protection</strong> : cinq onglets (Protection de base, Formulaires, Pare-feu et bots, Avancé, Exploitation) sur quatorze zones, chaque zone avec un état court, ses interrupteurs du quotidien en lignes et ses réglages experts derrière &laquo; Afficher les détails techniques &raquo;. La recherche couvre tous les onglets, le mode expert dans l'en-tête ouvre les détails par défaut, et chaque onglet porte &laquo; Enregistrer les modifications &raquo; et &laquo; Restaurer les valeurs par défaut &raquo;, ce dernier écrivant la recommandation du forfait.`

Also change "fourteen cards" wording in the line 341 paragraph: "in the Firewall &amp; Bots card" becomes "on the Firewall &amp; Bots tab", and in line 465 "jumps to the card" becomes "jumps to the area". The service docs are deployed separately (scp plus WP Rocket cache purge, see the workspace memory); this plan only edits the files.

- [ ] **Step 6: Commit the plugin docs**

```bash
git add CHANGELOG.md README.md
git commit -m "docs: protection page tabs"
```

`../CLAUDE.md` is workspace-only and not part of the `dev/` repo; the service docs are committed in their own repo.

---

### Task 14: Release gate

- [ ] **Step 1: Anti-KI gate**

Run from the workspace root: `./run.sh antiki`
Expected: `Anti-KI gate: clean (N files).`

- [ ] **Step 2: Static gates**

```bash
cd dev
vendor/bin/phpcs -q --runtime-set ignore_warnings_on_exit 1
vendor/bin/phpstan analyse --memory-limit=2G
vendor/bin/phpunit --testsuite unit --no-coverage
```
Expected: no PHPCS errors, `[OK] No errors`, `OK (N tests, ...)`.

- [ ] **Step 3: The full gate**

Run from the workspace root: `./run.sh check-all`
Expected: exit 0. If the E2E stage dies of memory, rerun the specs in batches of four to five (`cd dev/tests/e2e && npx playwright test --project=single-site <specs>`), as recorded in the workspace memory for 2.1.57.

- [ ] **Step 4: Stop**

Do not bump the version, tag or push a tag. Report the gate results and wait for the release instruction.
