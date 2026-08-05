<?php
/**
 * Pre-flight setup for the WebAuthn / security-key E2E specs.
 *
 * Run via:
 *   wp eval-file wp-content/plugins/reportedip-hive/tests/e2e/fixtures/webauthn-setup.php
 *
 * Provisions a dedicated test user with a known password and no 2FA state,
 * and enables the webauthn method site-wide so the Playwright spec can walk
 * the real enrolment ceremony with the Chromium virtual authenticator.
 * Idempotent — re-running resets the user to a credential-free baseline.
 *
 * Options are written through ReportedIP_Hive_Option_Routing so the same
 * fixture works on the single-site and the multisite stack (where these
 * keys live in sitemeta).
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\E2E
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.33
 */

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	exit( "This script must run via wp eval-file.\n" );
}

if ( ! class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
	WP_CLI::error( 'ReportedIP Hive plugin is not loaded — activate it before running setup.' );
}

$test_login = 'e2e-webauthn-user';
$test_email = 'e2e-webauthn-user@example.test';
$test_pass  = 'E2eWebauthnPass!42';

$user = get_user_by( 'login', $test_login );
if ( ! ( $user instanceof WP_User ) ) {
	$user_id = wp_insert_user(
		array(
			'user_login' => $test_login,
			'user_email' => $test_email,
			'user_pass'  => $test_pass,
			'role'       => 'administrator',
		)
	);
	if ( is_wp_error( $user_id ) ) {
		WP_CLI::error( 'Failed to create webauthn test user: ' . $user_id->get_error_message() );
	}
	$user = get_user_by( 'id', $user_id );
} else {
	wp_set_password( $test_pass, $user->ID );
	if ( is_multisite() && ! is_user_member_of_blog( $user->ID, get_current_blog_id() ) ) {
		add_user_to_blog( get_current_blog_id(), $user->ID, 'administrator' );
	}
}

delete_user_meta( $user->ID, ReportedIP_Hive_Two_Factor::META_ENABLED );
delete_user_meta( $user->ID, ReportedIP_Hive_Two_Factor::META_WEBAUTHN_ENABLED );
delete_user_meta( $user->ID, ReportedIP_Hive_Two_Factor::META_WEBAUTHN_CREDENTIALS );
delete_user_meta( $user->ID, 'reportedip_hive_2fa_method' );
delete_user_meta( $user->ID, 'reportedip_hive_2fa_totp_enabled' );
delete_user_meta( $user->ID, ReportedIP_Hive_Two_Factor::META_TOTP_SECRET );
delete_user_meta( $user->ID, 'reportedip_hive_2fa_recovery_codes' );
delete_user_meta( $user->ID, ReportedIP_Hive_Two_Factor_Reset_Gate::META_FAILED_ATTEMPTS );

ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_2fa_enabled_global', '1' );
ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_2fa_allowed_methods', '["totp","email","webauthn"]' );
ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_2fa_require_on_password_reset', '1' );
ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_2fa_password_reset_excluded_methods', '["email"]' );
ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_hide_login_enabled', '0' );

WP_CLI::success(
	sprintf(
		'WebAuthn E2E baseline ready: user_login=%s, user_id=%d',
		$user->user_login,
		$user->ID
	)
);
