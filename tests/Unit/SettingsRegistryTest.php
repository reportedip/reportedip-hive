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
	require_once dirname( __DIR__, 2 ) . '/includes/class-proxy-trust.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-waf.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-registration-guard.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-security-headers.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-frontend.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-hide-login.php';
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
				'reportedip_hive_headers_enabled'              => 'bool',
				'reportedip_hive_header_xcto'                  => 'bool',
				'reportedip_hive_header_xfo'                   => 'enum',
				'reportedip_hive_header_referrer'              => 'enum',
				'reportedip_hive_hsts_enabled'                 => 'bool',
				'reportedip_hive_hsts_max_age'                 => 'int',
				'reportedip_hive_hsts_subdomains'              => 'bool',
				'reportedip_hive_hsts_preload'                 => 'bool',
				'reportedip_hive_permissions_policy'           => 'text',
				'reportedip_hive_csp_mode'                     => 'enum',
				'reportedip_hive_csp_policy'                   => 'textarea',
				'reportedip_hive_csp_report_uri'               => 'url',
				'reportedip_hive_coop'                         => 'enum',
				'reportedip_hive_corp'                         => 'enum',
				'reportedip_hive_coep'                         => 'enum',
				'reportedip_hive_monitor_app_passwords' => 'bool',
				'reportedip_hive_app_password_threshold' => 'int',
				'reportedip_hive_app_password_timeframe' => 'int',
				'reportedip_hive_app_password_require_2fa' => 'bool',
				'reportedip_hive_rest_threshold' => 'int',
				'reportedip_hive_rest_timeframe' => 'int',
				'reportedip_hive_rest_sensitive_threshold' => 'int',
				'reportedip_hive_rest_sensitive_timeframe' => 'int',
				'reportedip_hive_user_enum_threshold' => 'int',
				'reportedip_hive_user_enum_timeframe' => 'int',
				'reportedip_hive_allow_author_archives' => 'bool',
				'reportedip_hive_monitor_geo_anomaly' => 'bool',
				'reportedip_hive_geo_window_days' => 'int',
				'reportedip_hive_geo_revoke_trusted_devices' => 'bool',
				'reportedip_hive_geo_report_to_api' => 'bool',
				'reportedip_hive_password_spray_threshold' => 'int',
				'reportedip_hive_password_spray_timeframe' => 'int',
				'reportedip_hive_monitor_woocommerce' => 'bool',
				'reportedip_hive_bot_allowlist_enabled' => 'bool',
				'reportedip_hive_hide_login_probe_threshold' => 'int',
				'reportedip_hive_hide_login_probe_timeframe' => 'int',
				'reportedip_hive_hide_login_token_in_urls' => 'bool',
				'reportedip_hive_password_min_classes' => 'int',
				'reportedip_hive_password_policy_all_users' => 'bool',
				'reportedip_hive_2fa_enforce_super_admins' => 'bool',
				'reportedip_hive_2fa_extended_remember' => 'bool',
				'reportedip_hive_2fa_ip_allowlist' => 'textarea',
				'reportedip_hive_2fa_branded_login' => 'bool',
				'reportedip_hive_2fa_notify_new_device' => 'bool',
				'reportedip_hive_2fa_xmlrpc_app_password_only' => 'bool',
				'reportedip_hive_2fa_password_reset_block_email_only' => 'bool',
				'reportedip_hive_2fa_frontend_enabled' => 'bool',
				'reportedip_hive_2fa_frontend_onboarding' => 'bool',
				'reportedip_hive_2fa_frontend_slug' => 'text',
				'reportedip_hive_2fa_frontend_setup_slug' => 'text',
				'reportedip_hive_2fa_frontend_customer_optional' => 'bool',
				'reportedip_hive_detailed_logging' => 'bool',
				'reportedip_hive_log_referer_domains' => 'bool',
				'reportedip_hive_enable_caching' => 'bool',
				'reportedip_hive_cache_duration' => 'int',
				'reportedip_hive_negative_cache_duration' => 'int',
				'reportedip_hive_max_api_calls_per_hour' => 'int',
				'reportedip_hive_report_cooldown_hours' => 'int',
				'reportedip_hive_queue_max_age_days' => 'int',
				'reportedip_hive_queue_warning_threshold' => 'int',
				'reportedip_hive_queue_critical_threshold' => 'int',
				'reportedip_hive_processing_timeout_minutes' => 'int',
				'reportedip_hive_auto_footer_enabled' => 'bool',
				'reportedip_hive_auto_footer_variant' => 'enum',
				'reportedip_hive_auto_footer_align' => 'enum',
				'reportedip_hive_notify_sync_to_api' => 'bool',
				'reportedip_hive_notify_event_cap_minutes' => 'int',
				'reportedip_hive_audit_new_ip_alert' => 'bool',
				'reportedip_hive_trusted_ip_header'             => 'enum',
				'reportedip_hive_trusted_proxy_ranges'          => 'textarea',
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
				'reportedip_hive_hardening_realtime_detection'  => 'bool',
				'reportedip_hive_hardening_duration_minutes'    => 'int',
				'reportedip_hive_hardening_login_threshold'     => 'int',
				'reportedip_hive_hardening_login_timeframe'     => 'int',
				'reportedip_hive_hardening_block_threshold'     => 'int',
				'reportedip_hive_hardening_detect_window_minutes' => 'int',
				'reportedip_hive_hardening_detect_min_ips'      => 'int',
				'reportedip_hive_hardening_detect_min_attempts' => 'int',
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
				'reportedip_hive_block_email_relays'            => 'bool',
				'reportedip_hive_comment_honeypot_enabled'      => 'bool',
				'reportedip_hive_form_proof_enabled'            => 'bool',
				'reportedip_hive_form_proof_login_forms'        => 'bool',
				'reportedip_hive_comment_spam_action'           => 'enum',
				'reportedip_hive_prohibited_usernames'          => 'textarea',
				'reportedip_hive_prohibited_usernames_baseline' => 'bool',
				'reportedip_hive_email_rule_mode'               => 'enum',
				'reportedip_hive_email_rules'                   => 'textarea',
				'reportedip_hive_registration_limit_enabled'    => 'bool',
				'reportedip_hive_registration_limit_count'      => 'int',
				'reportedip_hive_registration_limit_timeframe'  => 'int',
				'reportedip_hive_registration_allowlist'        => 'textarea',
				'reportedip_hive_block_unknown_username_login'  => 'bool',
				'reportedip_hive_decoy_pathblock_enabled'       => 'bool',
				'reportedip_hive_hide_login_enabled'            => 'bool',
				'reportedip_hive_hide_login_slug'               => 'slug',
				'reportedip_hive_hide_login_response_mode'      => 'enum',
				'reportedip_hive_monitor_hide_login_probe'      => 'bool',
				'reportedip_hive_rest_access_mode'              => 'enum',
				'reportedip_hive_rest_allowed_namespaces'       => 'textarea',
				'reportedip_hive_rest_allowed_roles'            => 'json_list',
				'reportedip_hive_disable_xmlrpc'                => 'bool',
				'reportedip_hive_disable_feeds'                 => 'bool',
				'reportedip_hive_block_admin_guests'            => 'bool',
				'reportedip_hive_block_uploads_php'             => 'bool',
				'reportedip_hive_hide_software_info'            => 'bool',
				'reportedip_hive_2fa_enabled_global'            => 'bool',
				'reportedip_hive_2fa_allowed_methods'           => 'json_list',
				'reportedip_hive_2fa_enforce_roles'             => 'json_list',
				'reportedip_hive_2fa_enforce_grace_days'        => 'int',
				'reportedip_hive_2fa_max_skips'                 => 'int',
				'reportedip_hive_2fa_enforce_action'            => 'enum',
				'reportedip_hive_2fa_trusted_devices'           => 'bool',
				'reportedip_hive_2fa_trusted_device_days'       => 'int',
				'reportedip_hive_2fa_policy_new_country' => 'json_list',
				'reportedip_hive_2fa_policy_new_ip' => 'json_list',
				'reportedip_hive_2fa_policy_new_subnet' => 'json_list',
				'reportedip_hive_2fa_policy_new_device' => 'json_list',
				'reportedip_hive_2fa_policy_every_n_days' => 'json_list',
				'reportedip_hive_2fa_policy_every_n_logins' => 'json_list',
				'reportedip_hive_2fa_policy_sessions_above_n' => 'json_list',
				'reportedip_hive_2fa_policy_days' => 'int',
				'reportedip_hive_2fa_policy_logins' => 'int',
				'reportedip_hive_2fa_policy_sessions' => 'int',
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
				if ( isset( $entry['sanitize'] ) ) {
					$this->assertTrue(
						is_callable( $entry['sanitize'] ),
						"Sanitizer for {$key} is not callable. An unreachable override does not fail loudly: sanitize() silently falls back to the generic kind sanitizer, which then rejects perfectly valid values."
					);
				}
				if ( isset( $entry['tier_gate'] ) ) {
					$this->assertTrue( is_callable( $entry['tier_gate'] ), "The tier gate of {$key} is not callable." );
				}
				$this->assertNotEmpty(
					$entry['description'] ?? '',
					"Key {$key} has no description. The settings page, the MainWP form and the cloud fleet all render this one sentence, so an option without it is a bare label on three surfaces at once."
				);
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
