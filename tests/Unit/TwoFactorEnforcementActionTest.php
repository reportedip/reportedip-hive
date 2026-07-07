<?php
/**
 * Unit tests for the post-grace 2FA enforcement decision.
 *
 * Covers ReportedIP_Hive_Two_Factor::resolve_no_method_action(), which decides
 * whether a login by an enforced user with no configured method and an
 * exhausted grace period / skip quota is allowed through (forced enrolment) or
 * rejected outright (legacy hard lockout). Two layers:
 *   1. Pure-logic tests drive the real static method with option + user-meta
 *      stubs from the unit bootstrap.
 *   2. A source-pattern test locks down that filter_authenticate() routes the
 *      no-method case through the helper instead of an inline WP_Error.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.22
 */

namespace {

	if ( ! defined( 'DAY_IN_SECONDS' ) ) {
		define( 'DAY_IN_SECONDS', 86400 );
	}

	if ( ! function_exists( 'is_super_admin' ) ) {
		/**
		 * Unit stub: a user is a super admin when their id is listed in
		 * $GLOBALS['rip_test_super_admins'].
		 *
		 * @param int $user_id User id.
		 * @return bool
		 */
		function is_super_admin( $user_id = 0 ) {
			$ids = $GLOBALS['rip_test_super_admins'] ?? array();
			return in_array( (int) $user_id, array_map( 'intval', $ids ), true );
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor', false ) ) {
		require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor.php';
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Isolation: exercises the real ReportedIP_Hive_Two_Factor static logic
	 * against the lightweight option + user-meta stubs from the unit bootstrap.
	 * Runs in separate processes so global option/meta state cannot leak
	 * between cases.
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class TwoFactorEnforcementActionTest extends TestCase {

		/**
		 * Reset the in-memory option / user-meta / capability buckets.
		 */
		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options']            = array();
			$GLOBALS['wp_user_meta']          = array();
			$GLOBALS['wp_user_caps']          = array();
			$GLOBALS['rip_test_super_admins'] = array();
		}

		/**
		 * Build a minimal user-like object carrying just an ID.
		 *
		 * @param int $id User id.
		 * @return object
		 */
		private function user( int $id ) {
			return (object) array( 'ID' => $id );
		}

		/**
		 * Put a user past the grace period with a given skip state and policy.
		 *
		 * @param int    $id     User id.
		 * @param int    $skips  Recorded skip count.
		 * @param int    $max    Max-skips option.
		 * @param string $action Enforcement action option.
		 */
		private function seed_exhausted( int $id, int $skips, int $max = 3, string $action = 'lockout' ): void {
			$GLOBALS['wp_options']['reportedip_hive_2fa_enforce_grace_days'] = 7;
			$GLOBALS['wp_options']['reportedip_hive_2fa_max_skips']         = $max;
			$GLOBALS['wp_options']['reportedip_hive_2fa_enforce_action']    = $action;
			$GLOBALS['wp_user_meta'][ $id ]['reportedip_hive_2fa_enforcement_start'] = 1;
			$GLOBALS['wp_user_meta'][ $id ]['reportedip_hive_2fa_skip_count']        = $skips;
		}

		public function test_in_grace_period_always_allows(): void {
			$GLOBALS['wp_options']['reportedip_hive_2fa_enforce_grace_days'] = 7;
			$GLOBALS['wp_options']['reportedip_hive_2fa_enforce_action']    = 'lockout';
			$GLOBALS['wp_user_meta'][7]['reportedip_hive_2fa_enforcement_start'] = 0;
			$GLOBALS['wp_user_caps']['7|manage_options'] = false;

			$this->assertSame(
				'allow',
				\ReportedIP_Hive_Two_Factor::resolve_no_method_action( $this->user( 7 ) )
			);
		}

		public function test_skips_remaining_allows(): void {
			$this->seed_exhausted( 7, 1, 3, 'lockout' );
			$GLOBALS['wp_user_caps']['7|manage_options'] = false;

			$this->assertSame(
				'allow',
				\ReportedIP_Hive_Two_Factor::resolve_no_method_action( $this->user( 7 ) )
			);
		}

		public function test_exhausted_enroll_mode_allows(): void {
			$this->seed_exhausted( 7, 3, 3, 'enroll' );
			$GLOBALS['wp_user_caps']['7|manage_options'] = false;

			$this->assertSame(
				'allow',
				\ReportedIP_Hive_Two_Factor::resolve_no_method_action( $this->user( 7 ) )
			);
		}

		public function test_exhausted_lockout_mode_blocks_regular_user(): void {
			$this->seed_exhausted( 7, 3, 3, 'lockout' );
			$GLOBALS['wp_user_caps']['7|manage_options'] = false;

			$this->assertSame(
				'lockout',
				\ReportedIP_Hive_Two_Factor::resolve_no_method_action( $this->user( 7 ) )
			);
		}

		public function test_exhausted_lockout_mode_allows_admin(): void {
			$this->seed_exhausted( 7, 5, 3, 'lockout' );
			$GLOBALS['wp_user_caps']['7|manage_options'] = true;

			$this->assertSame(
				'allow',
				\ReportedIP_Hive_Two_Factor::resolve_no_method_action( $this->user( 7 ) )
			);
		}

		public function test_exhausted_lockout_mode_allows_super_admin(): void {
			$this->seed_exhausted( 7, 5, 3, 'lockout' );
			$GLOBALS['wp_user_caps']['7|manage_options'] = false;
			$GLOBALS['rip_test_super_admins']            = array( 7 );

			$this->assertSame(
				'allow',
				\ReportedIP_Hive_Two_Factor::resolve_no_method_action( $this->user( 7 ) )
			);
		}

		public function test_max_skips_zero_never_locks_out(): void {
			$this->seed_exhausted( 7, 0, 0, 'lockout' );
			$GLOBALS['wp_user_caps']['7|manage_options'] = false;

			$this->assertSame(
				'allow',
				\ReportedIP_Hive_Two_Factor::resolve_no_method_action( $this->user( 7 ) )
			);
		}

		public function test_filter_authenticate_routes_through_helper(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor.php' );
			$this->assertStringContainsString(
				"'lockout' === self::resolve_no_method_action( \$user )",
				$source,
				'filter_authenticate must delegate the no-method decision to resolve_no_method_action().'
			);
		}
	}
}
