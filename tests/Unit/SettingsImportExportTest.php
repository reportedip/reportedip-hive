<?php
/**
 * Unit tests for the settings import/export pipeline.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.2.0
 */

declare(strict_types=1);

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;
use ReportedIP_Hive_Settings_Import_Export;
use ReportedIP_Hive_Settings_Registry;

/**
 * Verifies the export-payload shape and the import allowlist.
 *
 * Pure-PHP tests only — AJAX endpoints are covered separately by the
 * integration suite because they need a live WP request lifecycle.
 */
class SettingsImportExportTest extends TestCase {

	/**
	 * Loads the SUT once and resets the option mock between cases.
	 */
	protected function set_up() {
		parent::set_up();

		require_once dirname( __DIR__, 2 ) . '/includes/class-option-routing.php';
		require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
		require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
		require_once dirname( __DIR__, 2 ) . '/includes/class-settings-apply.php';
		require_once dirname( __DIR__, 2 ) . '/includes/class-security-headers.php';
		require_once dirname( __DIR__, 2 ) . '/includes/class-proxy-trust.php';
		require_once dirname( __DIR__, 2 ) . '/includes/class-registration-guard.php';
		require_once dirname( __DIR__, 2 ) . '/includes/class-hide-login.php';

		$class_path = dirname( __DIR__, 2 ) . '/admin/class-settings-import-export.php';
		if ( ! class_exists( ReportedIP_Hive_Settings_Import_Export::class ) ) {
			require_once $class_path;
		}

		$GLOBALS['wp_options'] = array();
	}

	/**
	 * The catalogue mirrors the registry, plus the two areas the registry
	 * cannot describe.
	 */
	public function test_sections_mirror_the_registry(): void {
		$slugs = array_keys( ReportedIP_Hive_Settings_Import_Export::sections() );

		$this->assertContains( 'general', $slugs, 'connection identity is not a registry section and must be added by hand' );
		$this->assertContains( 'ip_lists', $slugs, 'IP lists are rows, not options' );

		foreach ( array_keys( ReportedIP_Hive_Settings_Registry::sections() ) as $registry_slug ) {
			$this->assertContains(
				$registry_slug,
				$slugs,
				"Registry section {$registry_slug} is missing from the export catalogue."
			);
		}
	}

	/**
	 * Every remotely manageable option is exportable.
	 *
	 * Fifty-five registry keys used to be missing from the hand-maintained
	 * catalogue, so an export claimed to hold the configuration while leaving
	 * out the sensor thresholds, the hide-login setup and the password policy.
	 */
	public function test_every_registry_key_is_exportable(): void {
		$exportable = ReportedIP_Hive_Settings_Import_Export::importable_keys();
		$missing    = array();

		foreach ( array_keys( ReportedIP_Hive_Settings_Registry::remote_spec() ) as $key ) {
			if ( ! in_array( $key, $exportable, true ) ) {
				$missing[] = $key;
			}
		}

		$this->assertSame( array(), $missing, "These settings cannot be exported:\n" . implode( "\n", $missing ) );
	}

	/**
	 * The firewall section carries the portable sensor settings but must never
	 * export host-specific state: the drop-in toggle would write server config
	 * files on import, and stored rulesets are runtime state.
	 */
	public function test_firewall_section_excludes_host_specific_state(): void {
		$keys = ReportedIP_Hive_Settings_Import_Export::importable_keys();

		$this->assertContains( 'reportedip_hive_waf_enabled', $keys );
		$this->assertContains( 'reportedip_hive_bot_action', $keys );
		$this->assertContains( 'reportedip_hive_disposable_email_action', $keys );
		$this->assertContains( 'reportedip_hive_comment_honeypot_enabled', $keys );
		$registration_keys = array(
			'reportedip_hive_prohibited_usernames',
			'reportedip_hive_prohibited_usernames_baseline',
			'reportedip_hive_email_rule_mode',
			'reportedip_hive_email_rules',
			'reportedip_hive_registration_limit_enabled',
			'reportedip_hive_registration_limit_count',
			'reportedip_hive_registration_limit_timeframe',
			'reportedip_hive_registration_allowlist',
			'reportedip_hive_block_unknown_username_login',
		);
		foreach ( $registration_keys as $registration_key ) {
			$this->assertContains( $registration_key, $keys, "Registration key {$registration_key} must be exportable." );
		}
		$this->assertContains( 'reportedip_hive_headers_enabled', $keys );
		$this->assertContains( 'reportedip_hive_csp_policy', $keys );
		$this->assertContains( 'reportedip_hive_audit_retention_days', $keys );

		$this->assertNotContains( 'reportedip_hive_waf_dropin_enabled', $keys, 'Drop-in toggle is host-specific and must stay local.' );
		$this->assertNotContains( 'reportedip_hive_rule_sync_last_run', $keys, 'Sync timestamps are runtime state.' );
		$this->assertNotContains( 'reportedip_hive_readiness_state', $keys, 'Readiness state is runtime state.' );
		$this->assertNotContains( 'reportedip_hive_ruleset_waf', $keys, 'Stored rulesets are runtime state.' );
	}

	/**
	 * Round-trip: exporting the firewall + headers sections and applying the
	 * payload elsewhere reproduces the configuration.
	 */
	public function test_firewall_and_headers_round_trip(): void {
		$GLOBALS['wp_options']['reportedip_hive_waf_report_only'] = true;
		$GLOBALS['wp_options']['reportedip_hive_bot_action']      = 'block';
		$GLOBALS['wp_options']['reportedip_hive_headers_enabled'] = true;
		$GLOBALS['wp_options']['reportedip_hive_csp_mode']        = 'report_only';

		$payload = ReportedIP_Hive_Settings_Import_Export::get_instance()
			->build_export_payload( array( 'waf', 'headers' ), false );

		$GLOBALS['wp_options'] = array();

		$result = ReportedIP_Hive_Settings_Import_Export::get_instance()
			->apply_payload( json_decode( (string) wp_json_encode( $payload ), true ), array( 'waf', 'headers' ) );

		$this->assertGreaterThanOrEqual( 3, $result['written'] );
		$this->assertSame( 1, $GLOBALS['wp_options']['reportedip_hive_waf_report_only'], 'Registry-managed bools are stored canonically as 1/0 since 2.1.47.' );
		$this->assertSame( 'block', $GLOBALS['wp_options']['reportedip_hive_bot_action'] );
		$this->assertSame( 1, $GLOBALS['wp_options']['reportedip_hive_headers_enabled'], 'the basic header switch is free and must survive the round trip' );
	}

	/**
	 * An import cannot hand a site a header its plan does not include.
	 *
	 * The header options only joined the registry in 2.1.51; before that the
	 * import wrote them raw, so a payload from a Business site turned on CSP
	 * on a Free site and the engine then quietly refused to emit it. Now the
	 * tier gate answers at write time, which is also what MainWP and the
	 * cloud fleet already do.
	 *
	 * @return void
	 */
	public function test_import_skips_advanced_headers_without_the_plan(): void {
		$GLOBALS['wp_options']['reportedip_hive_csp_mode'] = 'report_only';

		$payload = ReportedIP_Hive_Settings_Import_Export::get_instance()
			->build_export_payload( array( 'headers' ), false );

		$GLOBALS['wp_options'] = array();

		ReportedIP_Hive_Settings_Import_Export::get_instance()
			->apply_payload( json_decode( (string) wp_json_encode( $payload ), true ), array( 'headers' ) );

		$this->assertArrayNotHasKey(
			'reportedip_hive_csp_mode',
			$GLOBALS['wp_options'],
			'advanced hardening is gated, so the Content-Security-Policy must not be written on a plan without it'
		);
	}

	/**
	 * Importable allowlist must include every option key from the catalogue
	 * plus the secret keys.
	 */
	public function test_importable_keys_includes_secrets_and_section_options(): void {
		$keys = ReportedIP_Hive_Settings_Import_Export::importable_keys();

		$this->assertContains( 'reportedip_hive_failed_login_threshold', $keys, 'detection key missing' );
		$this->assertContains( 'reportedip_hive_block_threshold', $keys, 'blocking key missing' );
		$this->assertContains( 'reportedip_hive_log_level', $keys, 'privacy_logs key missing' );
		$this->assertContains( 'reportedip_hive_2fa_enabled_global', $keys, '2FA key missing' );
		$this->assertContains( 'reportedip_hive_api_key', $keys, 'secret key missing' );
	}

	/**
	 * Per-user 2FA secrets must NEVER appear in the importable allowlist —
	 * they are encrypted with a site-specific key and would be useless on
	 * another site even if exported.
	 */
	public function test_user_meta_secrets_are_never_listed(): void {
		$keys = ReportedIP_Hive_Settings_Import_Export::importable_keys();
		$this->assertNotContains( 'reportedip_hive_2fa_totp_secret', $keys );
		$this->assertNotContains(
			'reportedip_hive_2fa_policy_admin_verified',
			$keys,
			'The administrator latch is runtime state — importing it would unlock the administrator column on another site.'
		);
		$this->assertNotContains( 'reportedip_hive_2fa_webauthn_credentials', $keys );
		$this->assertNotContains( 'reportedip_hive_2fa_sms_number', $keys );
	}

	/**
	 * Export without secrets must not emit any of the credential keys.
	 */
	public function test_export_without_secrets_excludes_credentials(): void {
		$GLOBALS['wp_options']['reportedip_hive_api_key']             = 'super-secret';
		$GLOBALS['wp_options']['reportedip_hive_failed_login_threshold'] = 9;

		$payload = ReportedIP_Hive_Settings_Import_Export::get_instance()
			->build_export_payload( array( 'detection' ), false );

		$this->assertSame( 'reportedip-hive', $payload['_meta']['plugin'] );
		$this->assertFalse( $payload['_meta']['includes_secrets'] );
		$this->assertArrayHasKey( 'reportedip_hive_failed_login_threshold', $payload['options'] );
		$this->assertArrayNotHasKey( 'reportedip_hive_api_key', $payload['options'] );
	}

	/**
	 * Export with the explicit opt-in must include the credential keys.
	 */
	public function test_export_with_secrets_includes_credentials(): void {
		$GLOBALS['wp_options']['reportedip_hive_api_key'] = 'super-secret';

		$payload = ReportedIP_Hive_Settings_Import_Export::get_instance()
			->build_export_payload( array( 'general' ), true );

		$this->assertTrue( $payload['_meta']['includes_secrets'] );
		$this->assertSame( 'super-secret', $payload['options']['reportedip_hive_api_key'] );
	}

	/**
	 * apply_payload must reject keys not on the allowlist (defence in depth
	 * against malicious payloads that try to overwrite WordPress core options).
	 */
	public function test_apply_payload_rejects_foreign_keys(): void {
		$GLOBALS['wp_options']['wp_user_roles'] = 'original';

		$payload = array(
			'_meta'   => array( 'plugin' => 'reportedip-hive', 'schema_version' => 1 ),
			'options' => array(
				'wp_user_roles'                          => 'tampered',
				'reportedip_hive_failed_login_threshold' => 12,
			),
		);

		$result = ReportedIP_Hive_Settings_Import_Export::get_instance()
			->apply_payload( $payload, array( 'detection' ) );

		$this->assertSame( 'original', $GLOBALS['wp_options']['wp_user_roles'], 'foreign key was written' );
		$this->assertSame( 12, $GLOBALS['wp_options']['reportedip_hive_failed_login_threshold'] );
		$this->assertSame( 1, $result['written'] );
		$this->assertGreaterThanOrEqual( 1, $result['skipped'] );
	}

	/**
	 * Sections not in the user's selection must not have their keys written,
	 * even if they appear in the payload.
	 */
	public function test_apply_payload_honours_selected_sections(): void {
		$payload = array(
			'_meta'   => array( 'plugin' => 'reportedip-hive', 'schema_version' => 1 ),
			'options' => array(
				'reportedip_hive_failed_login_threshold' => 12,
				'reportedip_hive_log_level'              => 'debug',
			),
		);

		ReportedIP_Hive_Settings_Import_Export::get_instance()
			->apply_payload( $payload, array( 'detection' ) );

		$this->assertSame( 12, $GLOBALS['wp_options']['reportedip_hive_failed_login_threshold'] );
		$this->assertArrayNotHasKey( 'reportedip_hive_log_level', $GLOBALS['wp_options'] );
	}

	/**
	 * Schema version is part of the public contract — bumping it must be a
	 * deliberate decision (matches the import-side check in the AJAX handler).
	 */
	public function test_schema_version_is_one(): void {
		$this->assertSame( 1, ReportedIP_Hive_Settings_Import_Export::SCHEMA_VERSION );
	}
}
