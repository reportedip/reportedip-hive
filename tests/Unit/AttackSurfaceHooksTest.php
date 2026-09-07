<?php
/**
 * Architecture invariants of the attack-surface switches.
 *
 * The REST gate runs inside `rest_authentication_errors`, which needs a live
 * WordPress request to exercise end to end. The properties that must never
 * silently change — hook priority, the error pass-through, the CLI/cron
 * carve-out, "log only, never escalate", the `display_errors` guard and the
 * inline option fallbacks — are anchored by source inspection instead (the
 * established pattern, see SecurityMonitorBotGuardTest).
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class AttackSurfaceHooksTest extends TestCase {

		/**
		 * Source of the attack-surface runtime.
		 *
		 * @return string
		 */
		private function source(): string {
			$buf = file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-attack-surface.php' );
			$this->assertNotFalse( $buf, 'attack-surface source must be readable' );
			return (string) $buf;
		}

		public function test_rest_gate_runs_after_the_core_authentication_checks(): void {
			$this->assertSame(
				1,
				preg_match( "/add_filter\(\s*'rest_authentication_errors',\s*array\(\s*\\\$this,\s*'filter_rest_authentication'\s*\),\s*(\d+)\s*\)/", $this->source(), $m ),
				'The REST gate must be registered on rest_authentication_errors.'
			);
			$this->assertGreaterThanOrEqual(
				101,
				(int) $m[1],
				'Core checks the application password at 90 and the cookie nonce at 100 — running earlier would judge a request WordPress has not authenticated yet.'
			);
		}

		public function test_existing_error_is_passed_through_before_any_decision(): void {
			$source = $this->source();
			$start  = strpos( $source, 'function filter_rest_authentication' );
			$this->assertNotFalse( $start );

			$body     = substr( $source, $start );
			$passthru = strpos( $body, 'is_wp_error( $result )' );
			$decision = strpos( $body, 'rest_decision(' );

			$this->assertNotFalse( $passthru, 'The gate must pass an existing authentication error through untouched.' );
			$this->assertNotFalse( $decision );
			$this->assertLessThan( $decision, $passthru, 'The error pass-through has to precede our own verdict.' );
		}

		public function test_cli_and_cron_are_carved_out(): void {
			$source = $this->source();
			$start  = strpos( $source, 'function filter_rest_authentication' );
			$body   = substr( (string) $source, (int) $start, 2000 );

			$this->assertStringContainsString( "defined( 'WP_CLI' )", $body, 'WP-CLI must never be gated.' );
			$this->assertStringContainsString( 'wp_doing_cron()', $body, 'Cron must never be gated.' );
		}

		public function test_denials_are_logged_but_never_escalated(): void {
			$source = $this->source();

			$this->assertStringNotContainsString(
				'track_generic_attempt',
				$source,
				'A closed endpoint is not an attack: denials must not feed the escalation ladder or the community report.'
			);
			$this->assertStringContainsString( "->log( \$event, \$ip, 'low', \$details )", $source, 'Denials are low-severity log entries.' );
		}

		public function test_no_crawler_exemption(): void {
			$this->assertStringNotContainsString(
				'is_exempt_crawler',
				$this->source(),
				'An access-control switch has no crawler bypass — the allowlist is the only exemption.'
			);
		}

		public function test_whitelisted_ips_are_skipped_for_logging_only(): void {
			$source = $this->source();
			$start  = strpos( $source, 'function log_denied' );
			$this->assertNotFalse( $start );

			$this->assertStringContainsString(
				'is_whitelisted',
				substr( $source, $start ),
				'Whitelisted operators testing their own site must not fill the log.'
			);
			$this->assertStringNotContainsString(
				'is_whitelisted',
				substr( $source, 0, $start ),
				'The DB whitelist means "never block", not "authorize" — it must not open a closed endpoint.'
			);
		}

		public function test_display_errors_is_guarded_by_the_debug_constants(): void {
			$source = $this->source();

			$this->assertMatchesRegularExpression(
				"/ini_set\(\s*'display_errors',\s*'0'\s*\);\s*\/\/ phpcs:ignore [^\n]*--/",
				$source,
				'The ini_set call needs a phpcs:ignore with a stated reason.'
			);
			$this->assertStringContainsString(
				"defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY",
				$source,
				'A developer running WP_DEBUG with WP_DEBUG_DISPLAY must keep their error output.'
			);
		}

		public function test_inline_option_fallbacks_match_the_canonical_defaults(): void {
			require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
			$defaults = \ReportedIP_Hive_Defaults::all_option_defaults();
			$source   = $this->source();

			$this->assertStringContainsString(
				"ReportedIP_Hive_Option_Routing::get( self::OPT_REST_MODE, self::REST_MODE_OPEN )",
				$source
			);
			$this->assertSame( 'open', $defaults['reportedip_hive_rest_access_mode'] );

			$this->assertStringContainsString(
				"ReportedIP_Hive_Option_Routing::get( self::OPT_REST_ROLES, '[\"administrator\"]' )",
				$source
			);
			$this->assertSame( '["administrator"]', $defaults['reportedip_hive_rest_allowed_roles'] );

			foreach ( array(
				'reportedip_hive_disable_xmlrpc',
				'reportedip_hive_disable_feeds',
				'reportedip_hive_block_admin_guests',
				'reportedip_hive_block_uploads_php',
				'reportedip_hive_hide_software_info',
			) as $key ) {
				$this->assertFalse(
					$defaults[ $key ],
					"switch_on() falls back to false, so {$key} must default to false in SAFE_OPTIONS."
				);
			}

			$this->assertStringContainsString(
				'return (bool) ReportedIP_Hive_Option_Routing::get( $option, false );',
				$source,
				'switch_on() is the single read path for every boolean switch.'
			);
		}

		public function test_every_option_key_is_registered_and_exportable(): void {
			require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
			$spec     = \ReportedIP_Hive_Settings_Registry::spec();
			$settings = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-admin-settings.php' );
			$export   = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-settings-import-export.php' );

			foreach ( \ReportedIP_Hive_Attack_Surface::OPTION_KEYS as $key ) {
				$this->assertArrayHasKey( $key, $spec, "{$key} is missing from the settings registry." );
				$this->assertSame( 'lockdown', $spec[ $key ]['section'], "{$key} belongs in the lockdown section." );
				$this->assertStringContainsString( "'reportedip_hive_attack_surface',\n\t\t\t'" . $key . "'", $settings, "{$key} is not registered with the Settings API." );
				$this->assertStringContainsString( "'" . $key . "'", $export, "{$key} is not exportable." );
			}
		}
	}
}
