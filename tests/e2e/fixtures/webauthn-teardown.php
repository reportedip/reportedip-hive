<?php
/**
 * Tear down the WebAuthn E2E baseline.
 *
 * Run via:
 *   wp eval-file wp-content/plugins/reportedip-hive/tests/e2e/fixtures/webauthn-teardown.php
 *
 * Deletes the dedicated test user (which drops all its 2FA user meta) and
 * removes the fixture options so later specs see the stack defaults again.
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

$user = get_user_by( 'login', 'e2e-webauthn-user' );
if ( $user instanceof WP_User ) {
	require_once ABSPATH . 'wp-admin/includes/user.php';
	if ( is_multisite() ) {
		require_once ABSPATH . 'wp-admin/includes/ms.php';
		wpmu_delete_user( $user->ID );
	} else {
		wp_delete_user( $user->ID );
	}
}

ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_2fa_enabled_global' );
ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_2fa_allowed_methods' );
ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_2fa_require_on_password_reset' );
ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_2fa_password_reset_excluded_methods' );

WP_CLI::success( 'WebAuthn E2E baseline torn down.' );
