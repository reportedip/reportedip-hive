<?php
/**
 * Unit tests for the client-side Tor exit-node blocking feature.
 *
 * Covers the delivery plumbing (empty bundled baseline, `tor_exits` as a
 * valid Rule_Store key with a stored round-trip), the tier gate
 * (`tor_blocking` requires Community mode and the Professional tier) and —
 * because the main plugin file cannot be loaded under the unit stubs — the
 * source-locked properties of `is_tor_exit()` / `should_block_tor_exit()`
 * and the no-community-report guarantee of the Tor block branch.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.41
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-rule-store.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-mode-manager.php';

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class TorExitClientTest extends TestCase {

		protected function set_up() {
			parent::set_up();

			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();

			\ReportedIP_Hive_Rule_Store::flush_cache();
			\ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
		}

		/**
		 * Pretend the API has reported a specific user role.
		 *
		 * @param string $tier Tier key (free|professional|business|...).
		 */
		private function pretend_tier( string $tier ): void {
			$role_map                                               = array(
				'free'         => 'reportedip_free',
				'professional' => 'reportedip_professional',
				'business'     => 'reportedip_business',
			);
			$GLOBALS['wp_transients']['reportedip_hive_api_status'] = array(
				'value'   => array( 'userRole' => $role_map[ $tier ] ?? 'reportedip_free' ),
				'expires' => time() + 600,
			);
			\ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
		}

		/**
		 * Switch operation mode and reset the singleton's mode cache.
		 *
		 * @param string $mode Operation mode (local|community).
		 */
		private function pretend_mode( string $mode ): void {
			$GLOBALS['wp_options']['reportedip_hive_operation_mode'] = $mode;
			$mm                                                      = \ReportedIP_Hive_Mode_Manager::get_instance();
			$ref                                                     = new \ReflectionProperty( $mm, 'cached_mode' );
			$ref->setValue( $mm, null );
		}

		/**
		 * Raw source of the main plugin file for the source-locked assertions.
		 */
		private function main_file(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );
		}

		/**
		 * Slice one method out of the main file: from the marker to the next
		 * top-level DocBlock, so assertions cannot accidentally match code
		 * belonging to a later method.
		 *
		 * @param string $marker Method signature fragment to anchor on.
		 */
		private function method_source( string $marker ): string {
			$src   = $this->main_file();
			$start = strpos( $src, $marker );
			$this->assertNotFalse( $start, "Marker '{$marker}' must exist in reportedip-hive.php." );
			$end = strpos( $src, "\n\t/**", (int) $start );
			return substr( $src, (int) $start, false === $end ? strlen( $src ) - (int) $start : $end - (int) $start );
		}

		public function test_bundled_baseline_is_the_empty_tor_exits_ruleset() {
			$baseline = include dirname( __DIR__, 2 ) . '/data/rulesets/tor-exits-baseline.php';

			$this->assertIsArray( $baseline );
			$this->assertSame( 'tor_exits', $baseline['key'] );
			$this->assertSame( 0, $baseline['version'], 'The baseline must always lose against any synced ruleset.' );
			$this->assertSame( array(), $baseline['rules'], 'No static exit-node snapshot may ship — it would be stale on arrival.' );
		}

		public function test_rule_store_recognises_the_tor_exits_key() {
			$this->assertContains( 'tor_exits', \ReportedIP_Hive_Rule_Store::VALID_KEYS );
			$this->assertTrue( \ReportedIP_Hive_Rule_Store::is_valid_key( 'tor_exits' ) );
			$this->assertSame( 'reportedip_hive_ruleset_tor_exits', \ReportedIP_Hive_Rule_Store::option_key( 'tor_exits' ) );
		}

		public function test_tor_exits_ruleset_roundtrips_through_the_store() {
			$ruleset = array(
				'key'     => 'tor_exits',
				'version' => 3,
				'rules'   => array( '185.220.101.34/32', '2001:db8::9/128' ),
			);

			$this->assertTrue( \ReportedIP_Hive_Rule_Store::set( 'tor_exits', $ruleset ) );
			$this->assertArrayHasKey( 'reportedip_hive_ruleset_tor_exits', $GLOBALS['wp_options'], 'The ruleset must persist under its prefixed option key.' );

			\ReportedIP_Hive_Rule_Store::flush_cache();
			$got = \ReportedIP_Hive_Rule_Store::get( 'tor_exits' );

			$this->assertIsArray( $got );
			$this->assertSame( 3, $got['version'] );
			$this->assertSame( array( '185.220.101.34/32', '2001:db8::9/128' ), $got['rules'] );
		}

		public function test_tor_blocking_requires_professional_tier() {
			$this->pretend_mode( 'community' );
			$this->pretend_tier( 'free' );

			$status = \ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'tor_blocking' );

			$this->assertFalse( $status['available'] );
			$this->assertSame( 'tier', $status['reason'] );
			$this->assertSame( 'professional', $status['min_tier'] );
		}

		public function test_tor_blocking_unlocked_for_professional_tier() {
			$this->pretend_mode( 'community' );
			$this->pretend_tier( 'professional' );

			$status = \ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'tor_blocking' );

			$this->assertTrue( $status['available'] );
			$this->assertSame( 'ok', $status['reason'] );
		}

		public function test_tor_blocking_unavailable_in_local_mode() {
			$this->pretend_mode( 'local' );
			$this->pretend_tier( 'professional' );

			$status = \ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'tor_blocking' );

			$this->assertFalse( $status['available'], 'The exit-node list arrives over the signed sync, so Local Shield cannot offer the feature.' );
			$this->assertSame( 'mode', $status['reason'] );
			$this->assertSame( 'community', $status['mode_required'] );
		}

		public function test_is_tor_exit_reduces_host_entries_to_a_hash_set() {
			$body = $this->method_source( 'public static function is_tor_exit(' );

			$this->assertStringContainsString( "'/32'", $body, 'v4 host entries must be stripped of their /32 suffix.' );
			$this->assertStringContainsString( "'/128'", $body, 'v6 host entries must be stripped of their /128 suffix.' );
			$this->assertStringContainsString( '$exact[', $body, 'Host entries must land in a hash set for O(1) lookups.' );
		}

		public function test_is_tor_exit_falls_back_to_the_cidr_matcher_for_ranges() {
			$this->assertStringContainsString(
				'ReportedIP_Hive_Database::ip_in_cidr(',
				$this->method_source( 'public static function is_tor_exit(' ),
				'Genuine ranges must run through the canonical CIDR matcher.'
			);
		}

		public function test_is_tor_exit_consults_the_community_flag() {
			$this->assertStringContainsString(
				"\$reputation['isTor']",
				$this->method_source( 'public static function is_tor_exit(' ),
				'Addresses the (possibly stale) list misses must fall back to the community isTor flag.'
			);
		}

		public function test_should_block_tor_exit_checks_toggle_and_tier_gate() {
			$body = $this->method_source( 'private function should_block_tor_exit(' );

			$this->assertStringContainsString( 'reportedip_hive_block_tor', $body, 'The operator toggle must gate the feature.' );
			$this->assertStringContainsString( "feature_status( 'tor_blocking' )", $body, 'The tier gate must be consulted on every check.' );
		}

		/**
		 * Running an exit node is not abuse evidence: the Tor branch writes a
		 * temporary reputation block and rejects the login, but must never send
		 * a community report for the address.
		 */
		public function test_tor_block_branch_blocks_without_a_community_report() {
			$src   = $this->main_file();
			$start = strpos( $src, '$tor_candidate &&' );
			$this->assertNotFalse( $start, 'The Tor block branch must exist in pre_auth_check().' );
			$end = strpos( $src, "return new WP_Error( 'ip_tor_block'", (int) $start );
			$this->assertNotFalse( $end, 'The Tor branch must reject the sign-in with the ip_tor_block error.' );

			$branch = substr( $src, (int) $start, (int) $end - (int) $start );

			$this->assertStringContainsString( 'block_ip(', $branch, 'A Tor candidate must be written into the blocked table.' );
			$this->assertStringContainsString( "'Tor exit node'", $branch );
			$this->assertStringContainsString( "'reputation'", $branch, 'The block row must use the reputation block type.' );
			$this->assertStringNotContainsString( 'report_security_event', $branch, 'A Tor block must never produce a community report.' );
		}
	}
}
