<?php
/**
 * Unit tests for the settings import/export pipeline.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.2.0
 */

declare(strict_types=1);

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;
use ReportedIP_Hive_Settings_Import_Export;

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

		$class_path = dirname( __DIR__, 2 ) . '/admin/class-settings-import-export.php';
		if ( ! class_exists( ReportedIP_Hive_Settings_Import_Export::class ) ) {
			require_once $class_path;
		}

		$GLOBALS['wp_options'] = array();
	}

	/**
	 * Catalogue must include every section the plan promised.
	 */
	public function test_sections_cover_expected_areas(): void {
		$slugs = array_keys( ReportedIP_Hive_Settings_Import_Export::sections() );
		$this->assertContains( 'general', $slugs );
		$this->assertContains( 'detection', $slugs );
		$this->assertContains( 'blocking', $slugs );
		$this->assertContains( 'notifications', $slugs );
		$this->assertContains( 'privacy_logs', $slugs );
		$this->assertContains( 'performance', $slugs );
		$this->assertContains( 'twofactor_global', $slugs );
		$this->assertContains( 'ip_lists', $slugs );
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
		$this->assertContains( 'reportedip_hive_2fa_sms_provider_config_raw', $keys, 'SMS secret missing' );
	}

	/**
	 * Per-user 2FA secrets must NEVER appear in the importable allowlist —
	 * they are encrypted with a site-specific key and would be useless on
	 * another site even if exported.
	 */
	public function test_user_meta_secrets_are_never_listed(): void {
		$keys = ReportedIP_Hive_Settings_Import_Export::importable_keys();
		$this->assertNotContains( 'reportedip_hive_2fa_totp_secret', $keys );
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
