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
		 * this list requires a conscious decision about SCHEMA_VERSION, see
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
				'reportedip_hive_2fa_email_subject' => 'text',
				'reportedip_hive_2fa_reminder_enabled' => 'bool',
				'reportedip_hive_2fa_reminder_hard_threshold' => 'int',
				'reportedip_hive_2fa_reminder_hard_roles' => 'json_list',
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
				'reportedip_hive_promo_enabled' => 'bool',
				'reportedip_hive_quota_notif_enabled' => 'bool',
				'reportedip_hive_tier_change_mail_enabled' => 'bool',
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
				'reportedip_hive_waf_dropin_skip_authenticated' => 'bool',
				'reportedip_hive_rule_sync_enabled'             => 'bool',
				'reportedip_hive_monitor_bot_verification'      => 'bool',
				'reportedip_hive_bot_action'                    => 'enum',
				'reportedip_hive_disposable_email_action'       => 'enum',
				'reportedip_hive_block_email_relays'            => 'bool',
				'reportedip_hive_comment_honeypot_enabled'      => 'bool',
				'reportedip_hive_form_proof_enabled'            => 'bool',
				'reportedip_hive_form_proof_login_forms'        => 'bool',
				'reportedip_hive_form_proof_pow'                => 'bool',
				'reportedip_hive_form_proof_cf7'                => 'bool',
				'reportedip_hive_form_proof_formidable'         => 'bool',
				'reportedip_hive_form_proof_elementor'          => 'bool',
				'reportedip_hive_reputation_on_forms'           => 'bool',
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
				'The remote key/kind set changed, update the snapshot deliberately and decide whether SCHEMA_VERSION must bump.'
			);
		}

		public function test_form_protection_is_its_own_section_next_to_the_registration_rules() {
			$sections = \ReportedIP_Hive_Settings_Registry::sections();
			$order    = array_keys( $sections );

			$this->assertArrayHasKey( 'forms', $sections );
			$this->assertSame(
				array_search( 'registration', $order, true ) + 1,
				array_search( 'forms', $order, true ),
				'the form section sits directly after the registration rules'
			);

			$by_section = array(
				'forms'        => array(),
				'registration' => array(),
			);
			foreach ( \ReportedIP_Hive_Settings_Registry::spec() as $key => $entry ) {
				if ( isset( $by_section[ $entry['section'] ] ) ) {
					$by_section[ $entry['section'] ][] = $key;
				}
			}

			sort( $by_section['forms'] );
			$this->assertSame(
				array(
					'reportedip_hive_comment_honeypot_enabled',
					'reportedip_hive_comment_spam_action',
					'reportedip_hive_form_proof_cf7',
					'reportedip_hive_form_proof_elementor',
					'reportedip_hive_form_proof_enabled',
					'reportedip_hive_form_proof_formidable',
					'reportedip_hive_form_proof_login_forms',
					'reportedip_hive_form_proof_pow',
					'reportedip_hive_reputation_on_forms',
				),
				$by_section['forms']
			);

			sort( $by_section['registration'] );
			$this->assertSame(
				array(
					'reportedip_hive_block_email_relays',
					'reportedip_hive_block_unknown_username_login',
					'reportedip_hive_disposable_email_action',
					'reportedip_hive_email_rule_mode',
					'reportedip_hive_email_rules',
					'reportedip_hive_prohibited_usernames',
					'reportedip_hive_prohibited_usernames_baseline',
					'reportedip_hive_registration_allowlist',
					'reportedip_hive_registration_limit_count',
					'reportedip_hive_registration_limit_enabled',
					'reportedip_hive_registration_limit_timeframe',
				),
				$by_section['registration']
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

		/**
		 * The simple view lists exactly the keys the spec names, and no section
		 * carries more than six of them. A key flagged `simple_form` counts
		 * against that budget as well: on a site running the form plugin it
		 * sits in the simple view like any other day-to-day switch.
		 */
		public function test_simple_keys_match_the_spec_and_stay_short_per_section(): void {
			$spec   = \ReportedIP_Hive_Settings_Registry::spec();
			$simple = array();
			foreach ( $spec as $key => $entry ) {
				if ( ! empty( $entry['simple'] ) || ! empty( $entry['simple_form'] ) ) {
					$simple[] = $key;
				}
			}
			sort( $simple );
			$expected = array(
				'reportedip_hive_2fa_enabled_global',
				'reportedip_hive_2fa_enforce_roles',
				'reportedip_hive_2fa_frontend_enabled',
				'reportedip_hive_auto_block',
				'reportedip_hive_auto_footer_enabled',
				'reportedip_hive_auto_footer_variant',
				'reportedip_hive_bot_action',
				'reportedip_hive_comment_honeypot_enabled',
				'reportedip_hive_comment_spam_action',
				'reportedip_hive_data_retention_days',
				'reportedip_hive_disposable_email_action',
				'reportedip_hive_form_proof_cf7',
				'reportedip_hive_form_proof_elementor',
				'reportedip_hive_form_proof_enabled',
				'reportedip_hive_form_proof_formidable',
				'reportedip_hive_hide_login_enabled',
				'reportedip_hive_hide_login_slug',
				'reportedip_hive_minimal_logging',
				'reportedip_hive_notify_admin',
				'reportedip_hive_notify_recipients',
				'reportedip_hive_report_only_mode',
				'reportedip_hive_waf_enabled',
			);
			$this->assertSame( $expected, $simple );

			$per_section = array();
			foreach ( $simple as $key ) {
				$section                 = $spec[ $key ]['section'];
				$per_section[ $section ] = ( $per_section[ $section ] ?? 0 ) + 1;
			}
			foreach ( $per_section as $section => $count ) {
				$this->assertLessThanOrEqual( 6, $count, "Section {$section} carries {$count} simple keys." );
			}
		}

		/**
		 * Every json_list key names its choice source so the generic renderer can
		 * draw a checkbox group instead of a raw textarea.
		 */
		/**
		 * Every `simple_form` value names an adapter the form bridge knows, so
		 * a typo cannot quietly park a switch in the expert view forever.
		 */
		public function test_every_conditional_simple_key_names_a_known_form_adapter(): void {
			require_once dirname( __DIR__, 2 ) . '/includes/class-form-adapters.php';
			foreach ( \ReportedIP_Hive_Settings_Registry::spec() as $key => $entry ) {
				if ( empty( $entry['simple_form'] ) ) {
					continue;
				}
				$this->assertArrayHasKey( (string) $entry['simple_form'], \ReportedIP_Hive_Form_Adapters::ADAPTERS, "{$key} names an unknown form adapter." );
			}
		}

		public function test_every_json_list_key_declares_choices(): void {
			foreach ( \ReportedIP_Hive_Settings_Registry::spec() as $key => $entry ) {
				if ( 'json_list' !== $entry['kind'] ) {
					continue;
				}
				$this->assertContains( $entry['choices'] ?? '', array( 'roles', 'methods' ), "{$key} has no choices source." );
			}
		}

		/**
		 * The plan gates the protection page renders: a partial key has a
		 * value-dependent gate, and the fields the old tabs locked as a block
		 * carry the feature of that block as a form-only lock.
		 */
		public function test_plan_gates_match_the_former_tab_locks(): void {
			$spec = \ReportedIP_Hive_Settings_Registry::spec();
			foreach ( $spec as $key => $entry ) {
				if ( ! empty( $entry['partial'] ) ) {
					$this->assertNotEmpty( $entry['tier'], "{$key} is partial without a plan" );
					$this->assertTrue( is_callable( $entry['tier_gate'] ?? null ), "{$key} is partial without a value gate" );
				}
			}
			$expected = array(
				'reportedip_hive_2fa_frontend_onboarding'        => 'frontend_2fa',
				'reportedip_hive_2fa_frontend_slug'              => 'frontend_2fa',
				'reportedip_hive_2fa_frontend_setup_slug'        => 'frontend_2fa',
				'reportedip_hive_2fa_frontend_customer_optional' => 'frontend_2fa',
				'reportedip_hive_hardening_realtime_detection'   => 'hardening_mode',
				'reportedip_hive_hardening_detect_min_attempts'  => 'hardening_mode',
				'reportedip_hive_hsts_max_age'                   => 'security_headers_advanced',
				'reportedip_hive_hsts_preload'                   => 'security_headers_advanced',
				'reportedip_hive_csp_policy'                     => 'security_headers_advanced',
				'reportedip_hive_csp_report_uri'                 => 'security_headers_advanced',
			);
			foreach ( $expected as $key => $feature ) {
				$this->assertSame( $feature, $spec[ $key ]['ui_lock'] ?? '', $key );
				$this->assertArrayNotHasKey( 'tier', $spec[ $key ], "{$key} locks the form only; the sanitizer stays open for remote channels" );
			}
			$this->assertSame( array( 'administrator' ), $spec['reportedip_hive_rest_allowed_roles']['choices_fixed'] );
		}
	}
}
