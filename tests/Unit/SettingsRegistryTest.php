<?php
/**
 * Unit tests for the canonical settings registry: spec invariants and the
 * snapshot lock on the remote key set.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.47
 */

declare(strict_types=1);

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-effects.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Locks the registry's structural invariants: every key has a canonical
	 * default, every kind is known, ranges are sane, side-effect tokens are
	 * executable and the remote key/kind set only changes deliberately.
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class SettingsRegistryTest extends TestCase {

		/**
		 * Frozen remote key => kind snapshot (protocol schema v1). Changing
		 * this list requires a conscious decision about SCHEMA_VERSION — see
		 * docs/remote-settings-protocol.md.
		 *
		 * @return array<string, string>
		 */
		private function expected_remote_kinds(): array {
			return array(
				'reportedip_hive_monitor_failed_logins'         => 'bool',
				'reportedip_hive_failed_login_threshold'        => 'int',
				'reportedip_hive_failed_login_timeframe'        => 'int',
				'reportedip_hive_monitor_comments'              => 'bool',
				'reportedip_hive_comment_spam_threshold'        => 'int',
				'reportedip_hive_comment_spam_timeframe'        => 'int',
				'reportedip_hive_monitor_xmlrpc'                => 'bool',
				'reportedip_hive_xmlrpc_threshold'              => 'int',
				'reportedip_hive_xmlrpc_timeframe'              => 'int',
				'reportedip_hive_disable_xmlrpc_multicall'      => 'bool',
				'reportedip_hive_monitor_rest_api'              => 'bool',
				'reportedip_hive_block_user_enumeration'        => 'bool',
				'reportedip_hive_monitor_404_scans'             => 'bool',
				'reportedip_hive_scan_404_threshold'            => 'int',
				'reportedip_hive_scan_404_timeframe'            => 'int',
				'reportedip_hive_auto_block'                    => 'bool',
				'reportedip_hive_block_duration'                => 'int',
				'reportedip_hive_block_threshold'               => 'int',
				'reportedip_hive_block_escalation_enabled'      => 'bool',
				'reportedip_hive_block_ladder_minutes'          => 'csv_int_list',
				'reportedip_hive_block_ladder_reset_days'       => 'int',
				'reportedip_hive_report_only_mode'              => 'bool',
				'reportedip_hive_block_tor'                     => 'bool',
				'reportedip_hive_blocked_page_contact_url'      => 'url',
				'reportedip_hive_waf_enabled'                   => 'bool',
				'reportedip_hive_waf_report_only'               => 'bool',
				'reportedip_hive_waf_paranoia'                  => 'int',
				'reportedip_hive_waf_block_threshold'           => 'int',
				'reportedip_hive_rule_sync_enabled'             => 'bool',
				'reportedip_hive_monitor_bot_verification'      => 'bool',
				'reportedip_hive_bot_action'                    => 'enum',
				'reportedip_hive_disposable_email_action'       => 'enum',
				'reportedip_hive_comment_honeypot_enabled'      => 'bool',
				'reportedip_hive_decoy_pathblock_enabled'       => 'bool',
				'reportedip_hive_hide_login_enabled'            => 'bool',
				'reportedip_hive_hide_login_slug'               => 'slug',
				'reportedip_hive_hide_login_response_mode'      => 'enum',
				'reportedip_hive_monitor_hide_login_probe'      => 'bool',
				'reportedip_hive_2fa_enabled_global'            => 'bool',
				'reportedip_hive_2fa_allowed_methods'           => 'json_list',
				'reportedip_hive_2fa_enforce_roles'             => 'json_list',
				'reportedip_hive_2fa_enforce_grace_days'        => 'int',
				'reportedip_hive_2fa_max_skips'                 => 'int',
				'reportedip_hive_2fa_enforce_action'            => 'enum',
				'reportedip_hive_2fa_trusted_devices'           => 'bool',
				'reportedip_hive_2fa_trusted_device_days'       => 'int',
				'reportedip_hive_2fa_require_on_password_reset' => 'bool',
				'reportedip_hive_password_policy_enabled'       => 'bool',
				'reportedip_hive_password_min_length'           => 'int',
				'reportedip_hive_password_check_hibp'           => 'bool',
				'reportedip_hive_log_level'                     => 'enum',
				'reportedip_hive_minimal_logging'               => 'bool',
				'reportedip_hive_log_user_agents'               => 'bool',
				'reportedip_hive_data_retention_days'           => 'int',
				'reportedip_hive_auto_anonymize_days'           => 'int',
				'reportedip_hive_audit_enabled'                 => 'bool',
				'reportedip_hive_audit_retention_days'          => 'int',
				'reportedip_hive_audit_anonymize_ip'            => 'bool',
				'reportedip_hive_notify_admin'                  => 'bool',
				'reportedip_hive_notify_recipients'             => 'email_list',
				'reportedip_hive_notify_from_name'              => 'text',
				'reportedip_hive_notify_from_email'             => 'email',
				'reportedip_hive_notification_cooldown_minutes' => 'int',
			);
		}

		public function test_remote_spec_matches_snapshot() {
			$actual = array();
			foreach ( \ReportedIP_Hive_Settings_Registry::remote_spec() as $key => $entry ) {
				$actual[ $key ] = (string) $entry['kind'];
			}
			$expected = $this->expected_remote_kinds();
			ksort( $actual );
			ksort( $expected );
			$this->assertSame(
				$expected,
				$actual,
				'The remote key/kind set changed — update the snapshot deliberately and decide whether SCHEMA_VERSION must bump.'
			);
		}

		public function test_every_registry_key_has_a_canonical_default() {
			$defaults = \ReportedIP_Hive_Defaults::all_option_defaults();
			foreach ( array_keys( \ReportedIP_Hive_Settings_Registry::spec() ) as $key ) {
				$this->assertArrayHasKey( $key, $defaults, "Registry key {$key} has no default in Defaults::SAFE_OPTIONS." );
			}
		}

		public function test_every_spec_entry_is_structurally_valid() {
			$known_kinds = array( 'bool', 'int', 'enum', 'text', 'textarea', 'email', 'email_list', 'url', 'slug', 'csv_int_list', 'json_list' );
			$sections    = array_keys( \ReportedIP_Hive_Settings_Registry::sections() );

			foreach ( \ReportedIP_Hive_Settings_Registry::spec() as $key => $entry ) {
				$this->assertContains( $entry['kind'], $known_kinds, "Key {$key} uses an unknown kind." );
				$this->assertContains( $entry['section'], $sections, "Key {$key} references an unknown section." );
				if ( 'enum' === $entry['kind'] ) {
					$this->assertNotEmpty( $entry['allowed'], "Enum key {$key} has no allowed list." );
				}
				if ( isset( $entry['min'], $entry['max'] ) ) {
					$this->assertLessThanOrEqual( $entry['max'], $entry['min'], "Key {$key} has min > max." );
				}
				if ( 'slug' === $entry['kind'] ) {
					$this->assertTrue( isset( $entry['sanitize'] ), "Slug key {$key} needs a sanitize override." );
				}
			}
		}

		public function test_block_threshold_min_is_pinned_to_the_false_positive_floor() {
			$spec = \ReportedIP_Hive_Settings_Registry::spec();

			$this->assertSame(
				\ReportedIP_Hive_Defaults::MIN_BLOCK_THRESHOLD,
				$spec['reportedip_hive_block_threshold']['min'],
				'the reputation threshold minimum guards against false-positive blocks; lowering it needs a deliberate decision'
			);
			$this->assertSame( 25, \ReportedIP_Hive_Defaults::MIN_BLOCK_THRESHOLD );
		}

		public function test_every_side_effect_token_is_known_to_the_dispatcher() {
			$known = \ReportedIP_Hive_Settings_Effects::known_tokens();
			foreach ( \ReportedIP_Hive_Settings_Effects::watched() as $key => $tokens ) {
				foreach ( $tokens as $token ) {
					$this->assertContains( $token, $known, "Option {$key} declares unexecutable side effect {$token}." );
				}
			}
		}

		public function test_every_default_survives_its_own_sanitizer() {
			$defaults = \ReportedIP_Hive_Defaults::all_option_defaults();
			foreach ( \ReportedIP_Hive_Settings_Registry::remote_spec() as $key => $entry ) {
				if ( isset( $entry['sanitize'] ) ) {
					continue;
				}
				$clean = \ReportedIP_Hive_Settings_Registry::sanitize( $key, $defaults[ $key ] );
				$this->assertFalse( is_wp_error( $clean ), "Default for {$key} is rejected by its own sanitizer." );
				$this->assertSame(
					\ReportedIP_Hive_Settings_Registry::normalize_value( $key, $defaults[ $key ] ),
					\ReportedIP_Hive_Settings_Registry::normalize_value( $key, $clean ),
					"Default for {$key} does not round-trip its sanitizer."
				);
			}
		}

		public function test_per_site_override_keys_are_absent_from_remote_spec() {
			$remote = \ReportedIP_Hive_Settings_Registry::remote_spec();
			$this->assertArrayNotHasKey( 'reportedip_hive_2fa_frontend_slug_site_override', $remote );
			$this->assertArrayNotHasKey( 'reportedip_hive_2fa_frontend_setup_slug_site_override', $remote );
			$this->assertArrayNotHasKey( 'reportedip_hive_2fa_enforce_roles_extra', $remote );
		}

		public function test_export_schema_covers_every_remote_key_exactly_once() {
			$schema = \ReportedIP_Hive_Settings_Registry::export_schema();
			$this->assertSame( \ReportedIP_Hive_Settings_Registry::SCHEMA_VERSION, $schema['schema_version'] );

			$section_keys = array();
			foreach ( $schema['sections'] as $section ) {
				foreach ( $section['keys'] as $key ) {
					$section_keys[] = $key;
				}
			}
			sort( $section_keys );

			$remote_keys = array_keys( \ReportedIP_Hive_Settings_Registry::remote_spec() );
			sort( $remote_keys );

			$field_keys = array_keys( $schema['fields'] );
			sort( $field_keys );

			$this->assertSame( $remote_keys, $section_keys, 'Every remote key must appear in exactly one schema section.' );
			$this->assertSame( $remote_keys, $field_keys, 'The fields map must carry every remote key.' );
		}
	}
}
