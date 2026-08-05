<?php
/**
 * Reset accumulated 2FA nag/enforcement state on the stack's admin user.
 *
 * Run via:
 *   wp eval-file wp-content/plugins/reportedip-hive/tests/e2e/fixtures/admin-reset.php
 *
 * The E2E stacks are long-lived: every suite run logs the `admin` user in
 * several times without 2FA, so the reminder counter grows across runs and
 * the enforcement grace clock keeps ticking. Once the 24h onboarding snooze
 * expires, the hard-block redirect hijacks the first wp-admin navigation and
 * unrelated smoke specs fail. This fixture restores a deterministic
 * baseline: no reminder history, no enforcement clock, no enforced roles.
 * Idempotent; used by the plugin-active / network-active smoke specs.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\E2E
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.36
 */

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	exit( "This script must run via wp eval-file.\n" );
}

if ( ! class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
	WP_CLI::error( 'ReportedIP Hive plugin is not loaded — activate it before running the reset.' );
}

$admin = get_user_by( 'login', 'admin' );
if ( ! ( $admin instanceof WP_User ) ) {
	WP_CLI::error( 'No admin user found on this stack.' );
}

delete_user_meta( $admin->ID, ReportedIP_Hive_Two_Factor_Recommend::META_COUNT );
delete_user_meta( $admin->ID, ReportedIP_Hive_Two_Factor_Recommend::META_LAST_SEEN );
delete_user_meta( $admin->ID, ReportedIP_Hive_Two_Factor::META_ENFORCEMENT_START );
delete_user_meta( $admin->ID, ReportedIP_Hive_Two_Factor::META_SKIP_COUNT );

ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_2fa_enforce_roles', '[]' );

if ( class_exists( 'ReportedIP_Hive_Two_Factor_Onboarding' ) ) {
	delete_transient( ReportedIP_Hive_Two_Factor_Onboarding::TRANSIENT_PREFIX . $admin->ID );
	delete_user_meta( $admin->ID, ReportedIP_Hive_Two_Factor_Onboarding::META_SKIP_UNTIL );
}

WP_CLI::success( 'Admin 2FA baseline reset for E2E.' );
