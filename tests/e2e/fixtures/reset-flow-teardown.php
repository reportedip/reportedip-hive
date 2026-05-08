<?php
/**
 * Tear down the password-reset 2FA E2E baseline.
 *
 * Run via:
 *   wp eval-file wp-content/plugins/reportedip-hive/tests/e2e/fixtures/reset-flow-teardown.php
 *
 * Reverses everything `reset-flow-setup.php` did so unrelated specs that
 * run after the reset-flow suite (admin dashboard render, etc.) get back
 * to a 2FA-disabled admin user. Pair with `setupResetFlowBaseline()` via
 * a `test.afterAll` hook.
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

$user = get_user_by( 'login', 'e2e-reset-user' );
if ( $user instanceof WP_User ) {
	require_once ABSPATH . 'wp-admin/includes/user.php';
	wp_delete_user( $user->ID );
}

delete_option( 'reportedip_hive_2fa_enabled_global' );
delete_option( 'reportedip_hive_2fa_require_on_password_reset' );
delete_option( 'reportedip_hive_2fa_password_reset_excluded_methods' );

WP_CLI::success( 'Reset-flow E2E baseline torn down.' );
