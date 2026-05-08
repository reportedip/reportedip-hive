<?php
/**
 * Pre-flight setup for the password-reset 2FA E2E spec.
 *
 * Run via:
 *   wp eval-file wp-content/plugins/reportedip-hive/tests/e2e/fixtures/reset-flow-setup.php
 *
 * Provisions a deterministic recovery-code matrix on the `admin` user so
 * the Playwright spec can submit a known-bad and a known-good code without
 * re-deriving them from the live install. Idempotent — re-running resets
 * the user back to the test baseline.
 *
 * The script bails out hard (non-zero `WP_CLI::error`) on any unexpected
 * state so a failing setup can never be mistaken for a flaky test.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\E2E
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.1
 */

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	exit( "This script must run via wp eval-file.\n" );
}

if ( ! class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
	WP_CLI::error( 'ReportedIP Hive plugin is not loaded — activate it before running setup.' );
}

$test_login = 'e2e-reset-user';
$test_email = 'e2e-reset-user@example.test';

$user = get_user_by( 'login', $test_login );
if ( ! ( $user instanceof WP_User ) ) {
	$user_id = wp_insert_user(
		array(
			'user_login' => $test_login,
			'user_email' => $test_email,
			'user_pass'  => wp_generate_password( 24, true, true ),
			'role'       => 'subscriber',
		)
	);
	if ( is_wp_error( $user_id ) ) {
		WP_CLI::error( 'Failed to create reset-flow test user: ' . $user_id->get_error_message() );
	}
	$user = get_user_by( 'id', $user_id );
}

update_option( 'reportedip_hive_2fa_enabled_global', '1' );
update_option( 'reportedip_hive_2fa_require_on_password_reset', '1' );
update_option( 'reportedip_hive_2fa_password_reset_excluded_methods', '["email"]' );

update_option( 'reportedip_hive_hide_login_enabled', '0' );

$secret_plain = ReportedIP_Hive_Two_Factor_TOTP::generate_secret();
$secret_enc   = ReportedIP_Hive_Two_Factor_Crypto::encrypt( $secret_plain );
if ( false === $secret_enc ) {
	WP_CLI::error( 'TOTP secret encryption failed.' );
}
update_user_meta( $user->ID, ReportedIP_Hive_Two_Factor::META_TOTP_SECRET, $secret_enc );
update_user_meta( $user->ID, 'reportedip_hive_2fa_totp_enabled', '1' );
update_user_meta( $user->ID, ReportedIP_Hive_Two_Factor::META_ENABLED, '1' );
update_user_meta( $user->ID, 'reportedip_hive_2fa_method', 'totp' );

$recovery_codes = array(
	'aaaa-aaaa',
	'bbbb-bbbb',
	'cccc-cccc',
	'dddd-dddd',
	'eeee-eeee',
);
ReportedIP_Hive_Two_Factor_Recovery::store_codes( $user->ID, $recovery_codes );

delete_user_meta( $user->ID, ReportedIP_Hive_Two_Factor_Reset_Gate::META_FAILED_ATTEMPTS );

$remaining = ReportedIP_Hive_Two_Factor_Recovery::get_remaining_count( $user->ID );
if ( count( $recovery_codes ) !== $remaining ) {
	WP_CLI::error(
		sprintf(
			'Recovery code persistence mismatch: stored %d, remaining count says %d.',
			count( $recovery_codes ),
			$remaining
		)
	);
}

$eligible = ReportedIP_Hive_Two_Factor_Reset_Gate::get_eligible_methods( $user->ID );
if ( ! in_array( 'totp', $eligible, true ) || ! in_array( 'recovery', $eligible, true ) ) {
	WP_CLI::error(
		'Eligible methods missing TOTP or recovery: ' . wp_json_encode( $eligible )
	);
}

WP_CLI::success(
	sprintf(
		'Reset-flow E2E baseline ready: user_login=%s, user_id=%d, eligible=%s, recovery_codes=%d',
		$user->user_login,
		$user->ID,
		implode( ',', $eligible ),
		$remaining
	)
);
