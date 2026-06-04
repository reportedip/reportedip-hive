<?php
/**
 * Unit tests for the operator lockout-exemption contract.
 *
 * Locks down the 2.0.23 fix: an automatic IP block (e.g. one tripped by
 * anonymous front-end plugin traffic) used to wp_die() a logged-in admin,
 * editor or shop manager out of their own site and backend, because neither
 * the front-end block (check_ip_access) nor the admin block
 * (block_admin_access) consulted the login/capability state. Both now exempt
 * `edit_others_posts` operators via is_block_exempt_operator(), and the
 * front-end exemption must run before the per-IP access cache so a cached
 * "blocked" verdict cannot lock the operator out either.
 *
 * Source-inspection only (the block methods wp_die()/exit), matching the
 * style of BlockedPageCacheHeadersTest.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.23
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class LockoutExemptionTest extends TestCase {

		private function source(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );
		}

		public function test_exemption_is_gated_on_operator_capability(): void {
			$this->assertStringContainsString(
				"return is_user_logged_in() && current_user_can( 'edit_others_posts' );",
				$this->source(),
				'The lockout exemption must require both an active login and the edit_others_posts capability (admin / editor / shop manager), never login alone.'
			);
		}

		public function test_both_lockout_surfaces_call_the_exemption(): void {
			$this->assertSame(
				2,
				substr_count( $this->source(), '$this->is_block_exempt_operator()' ),
				'Exactly the two lockout surfaces — check_ip_access() (front-end) and block_admin_access() (wp-admin) — must call the operator exemption.'
			);
		}

		public function test_front_end_exemption_runs_before_the_ip_access_cache(): void {
			$source = $this->source();
			$start  = strpos( $source, 'function check_ip_access' );
			$this->assertNotFalse( $start, 'check_ip_access() must exist.' );

			$slice     = substr( $source, $start, 1500 );
			$exempt_at = strpos( $slice, '$this->is_block_exempt_operator()' );
			$cache_at  = strpos( $slice, 'wp_cache_get( $cache_key' );

			$this->assertNotFalse( $exempt_at, 'check_ip_access() must call the operator exemption.' );
			$this->assertNotFalse( $cache_at, 'check_ip_access() must read the per-IP access cache.' );
			$this->assertLessThan(
				$cache_at,
				$exempt_at,
				'The operator exemption must run BEFORE the per-IP access cache lookup, otherwise a cached "blocked" verdict for the shared IP would still lock the operator out.'
			);
		}
	}
}
