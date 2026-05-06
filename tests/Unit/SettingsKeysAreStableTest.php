<?php
/**
 * Snapshot test that locks down all persisted settings option keys.
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

/**
 * Guards every register_setting() option key against silent renames.
 *
 * The Settings refactor in 1.2.0 reorganises tabs and may split settings
 * groups, but every option key must remain byte-identical so existing
 * sites do not lose configuration after upgrade.
 */
class SettingsKeysAreStableTest extends TestCase {

	/**
	 * Path to admin-settings source file.
	 *
	 * @return string
	 */
	private function admin_settings_path(): string {
		return dirname( __DIR__, 2 ) . '/admin/class-admin-settings.php';
	}

	/**
	 * Path to two-factor-admin source file.
	 *
	 * @return string
	 */
	private function two_factor_admin_path(): string {
		return dirname( __DIR__, 2 ) . '/admin/class-two-factor-admin.php';
	}

	/**
	 * Frozen list of every option key registered via register_setting().
	 *
	 * Adding a key requires updating this snapshot deliberately.
	 * Removing a key without a migration is a breaking change.
	 *
	 * @return array<int, string>
	 */
	private function expected_keys(): array {
		return array(
			'reportedip_hive_api_endpoint',
			'reportedip_hive_api_key',
			'reportedip_hive_auto_anonymize_days',
			'reportedip_hive_auto_block',
			'reportedip_hive_auto_footer_align',
			'reportedip_hive_auto_footer_enabled',
			'reportedip_hive_auto_footer_variant',
			'reportedip_hive_block_duration',
			'reportedip_hive_block_threshold',
			'reportedip_hive_block_escalation_enabled',
			'reportedip_hive_block_ladder_minutes',
			'reportedip_hive_block_ladder_reset_days',
			'reportedip_hive_blocked_page_contact_url',
			'reportedip_hive_cache_duration',
			'reportedip_hive_comment_spam_threshold',
			'reportedip_hive_comment_spam_timeframe',
			'reportedip_hive_data_retention_days',
			'reportedip_hive_delete_data_on_uninstall',
			'reportedip_hive_detailed_logging',
			'reportedip_hive_enable_caching',
			'reportedip_hive_failed_login_threshold',
			'reportedip_hive_failed_login_timeframe',
			'reportedip_hive_hide_login_enabled',
			'reportedip_hive_hide_login_response_mode',
			'reportedip_hive_hide_login_slug',
			'reportedip_hive_hide_login_token_in_urls',
			'reportedip_hive_log_level',
			'reportedip_hive_log_referer_domains',
			'reportedip_hive_log_user_agents',
			'reportedip_hive_max_api_calls_per_hour',
			'reportedip_hive_minimal_logging',
			'reportedip_hive_monitor_comments',
			'reportedip_hive_monitor_failed_logins',
			'reportedip_hive_monitor_xmlrpc',
			'reportedip_hive_negative_cache_duration',
			'reportedip_hive_notify_admin',
			'reportedip_hive_notify_from_email',
			'reportedip_hive_notify_from_name',
			'reportedip_hive_notify_recipients',
			'reportedip_hive_notify_sync_to_api',
			'reportedip_hive_operation_mode',
			'reportedip_hive_report_cooldown_hours',
			'reportedip_hive_report_only_mode',
			'reportedip_hive_trusted_ip_header',
			'reportedip_hive_xmlrpc_threshold',
			'reportedip_hive_xmlrpc_timeframe',
			'reportedip_hive_2fa_allowed_methods',
			'reportedip_hive_2fa_branded_login',
			'reportedip_hive_2fa_enabled_global',
			'reportedip_hive_2fa_enforce_grace_days',
			'reportedip_hive_2fa_enforce_roles',
			'reportedip_hive_2fa_extended_remember',
			'reportedip_hive_2fa_frontend_customer_optional',
			'reportedip_hive_2fa_frontend_enabled',
			'reportedip_hive_2fa_frontend_onboarding',
			'reportedip_hive_2fa_frontend_setup_slug',
			'reportedip_hive_2fa_frontend_slug',
			'reportedip_hive_2fa_ip_allowlist',
			'reportedip_hive_2fa_max_skips',
			'reportedip_hive_2fa_notify_new_device',
			'reportedip_hive_2fa_password_reset_block_email_only',
			'reportedip_hive_2fa_reminder_enabled',
			'reportedip_hive_2fa_reminder_hard_roles',
			'reportedip_hive_2fa_reminder_hard_threshold',
			'reportedip_hive_2fa_require_on_password_reset',
			'reportedip_hive_2fa_sms_avv_confirmed',
			'reportedip_hive_2fa_sms_provider',
			'reportedip_hive_2fa_sms_provider_config_raw',
			'reportedip_hive_2fa_trusted_device_days',
			'reportedip_hive_2fa_trusted_devices',
			'reportedip_hive_2fa_xmlrpc_app_password_only',
		);
	}

	/**
	 * Extracts every option key from register_setting() blocks.
	 *
	 * Matches both single- and double-quoted second arguments, regardless
	 * of formatting (single- or multi-line, with or without trailing
	 * arguments).
	 *
	 * @param string $source Source code to scan.
	 * @return array<int, string>
	 */
	private function extract_keys_from_source( string $source ): array {
		$pattern = '/register_setting\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*[\'"](reportedip_hive_[a-z0-9_]+)[\'"]/';
		preg_match_all( $pattern, $source, $matches );
		return $matches[1];
	}

	/**
	 * Snapshot must match exactly — no missing keys, no surprise additions.
	 */
	public function test_every_registered_key_matches_snapshot(): void {
		$sources = array_merge(
			$this->extract_keys_from_source( (string) file_get_contents( $this->admin_settings_path() ) ),
			$this->extract_keys_from_source( (string) file_get_contents( $this->two_factor_admin_path() ) )
		);

		$actual   = array_values( array_unique( $sources ) );
		$expected = $this->expected_keys();

		sort( $actual );
		sort( $expected );

		$missing  = array_values( array_diff( $expected, $actual ) );
		$surprise = array_values( array_diff( $actual, $expected ) );

		$this->assertSame(
			array(),
			$missing,
			'Snapshot drift: option keys were removed/renamed without migration: ' . implode( ', ', $missing )
		);
		$this->assertSame(
			array(),
			$surprise,
			'Snapshot drift: option keys were added without updating expected_keys(): ' . implode( ', ', $surprise )
		);
	}

	/**
	 * Each key must be registered exactly once. Duplicate registrations
	 * indicate a copy-paste accident.
	 */
	public function test_no_duplicate_registrations(): void {
		$sources = array_merge(
			$this->extract_keys_from_source( (string) file_get_contents( $this->admin_settings_path() ) ),
			$this->extract_keys_from_source( (string) file_get_contents( $this->two_factor_admin_path() ) )
		);

		$counts     = array_count_values( $sources );
		$duplicates = array_keys( array_filter( $counts, static fn( int $n ): bool => $n > 1 ) );

		$this->assertSame(
			array(),
			$duplicates,
			'Duplicate register_setting() for: ' . implode( ', ', $duplicates )
		);
	}
}
