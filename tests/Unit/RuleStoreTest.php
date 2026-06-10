<?php
/**
 * Unit tests for the ruleset persistence layer.
 *
 * Locks down the store/retrieve contract for synced rulesets: only known keys
 * are accepted, a round-trip preserves the ruleset, malformed input is rejected,
 * and the per-request cache reflects writes and deletes.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.2.0
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-rule-store.php';

	/**
	 * @covers \ReportedIP_Hive_Rule_Store
	 */
	class RuleStoreTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options'] = array();
			\ReportedIP_Hive_Rule_Store::flush_cache();
		}

		private function sample_ruleset(): array {
			return array(
				'key'     => 'waf',
				'version' => 7,
				'rules'   => array( array( 'id' => 'r1', 'pattern' => 'x' ) ),
			);
		}

		public function test_only_known_keys_are_valid(): void {
			$this->assertTrue( \ReportedIP_Hive_Rule_Store::is_valid_key( 'waf' ) );
			$this->assertTrue( \ReportedIP_Hive_Rule_Store::is_valid_key( 'bot_signatures' ) );
			$this->assertFalse( \ReportedIP_Hive_Rule_Store::is_valid_key( 'nope' ) );
			$this->assertFalse( \ReportedIP_Hive_Rule_Store::is_valid_key( '' ) );
		}

		public function test_option_key_is_prefixed(): void {
			$this->assertSame( 'reportedip_hive_ruleset_waf', \ReportedIP_Hive_Rule_Store::option_key( 'waf' ) );
		}

		public function test_set_get_roundtrip(): void {
			$this->assertTrue( \ReportedIP_Hive_Rule_Store::set( 'waf', $this->sample_ruleset() ) );
			$got = \ReportedIP_Hive_Rule_Store::get( 'waf' );
			$this->assertIsArray( $got );
			$this->assertSame( 7, $got['version'] );
			$this->assertSame( 'r1', $got['rules'][0]['id'] );
		}

		public function test_get_invalid_key_returns_null(): void {
			$this->assertNull( \ReportedIP_Hive_Rule_Store::get( 'bogus' ) );
		}

		public function test_get_unset_returns_null(): void {
			$this->assertNull( \ReportedIP_Hive_Rule_Store::get( 'scan_paths' ) );
		}

		public function test_set_rejects_missing_rules(): void {
			$this->assertFalse( \ReportedIP_Hive_Rule_Store::set( 'waf', array( 'version' => 1 ) ) );
			$this->assertNull( \ReportedIP_Hive_Rule_Store::get( 'waf' ) );
		}

		public function test_delete_clears_value_and_cache(): void {
			\ReportedIP_Hive_Rule_Store::set( 'waf', $this->sample_ruleset() );
			$this->assertIsArray( \ReportedIP_Hive_Rule_Store::get( 'waf' ) );

			$this->assertTrue( \ReportedIP_Hive_Rule_Store::delete( 'waf' ) );
			$this->assertNull( \ReportedIP_Hive_Rule_Store::get( 'waf' ) );
		}

		public function test_cache_does_not_mask_a_write(): void {
			$this->assertNull( \ReportedIP_Hive_Rule_Store::get( 'scan_paths' ) );
			\ReportedIP_Hive_Rule_Store::set( 'scan_paths', array( 'key' => 'scan_paths', 'version' => 1, 'rules' => array( '/x.php' ) ) );
			$got = \ReportedIP_Hive_Rule_Store::get( 'scan_paths' );
			$this->assertIsArray( $got );
			$this->assertSame( array( '/x.php' ), $got['rules'] );
		}
	}
}
