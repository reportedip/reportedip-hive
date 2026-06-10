<?php
/**
 * Unit tests for the WAF request-inspection engine.
 *
 * Locks the security-critical core: pattern matching is correct, a malformed
 * delivered rule fails open (never hangs or fatals the request), and the
 * Paranoia-Level ceiling clamps the active rule set so free tiers never run
 * deeper levels than they are entitled to.
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
	require_once dirname( __DIR__, 2 ) . '/includes/class-rule-sync.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-waf.php';

	/**
	 * @covers \ReportedIP_Hive_WAF
	 */
	class WafTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options'] = array();
			$GLOBALS['wp_filters'] = array();
			\ReportedIP_Hive_Rule_Store::flush_cache();
		}

		private function waf(): \ReportedIP_Hive_WAF {
			return \ReportedIP_Hive_WAF::get_instance();
		}

		private function call_private( string $method, array $args ) {
			$ref = new \ReflectionMethod( \ReportedIP_Hive_WAF::class, $method );
			$ref->setAccessible( true );
			return $ref->invoke( $this->waf(), ...$args );
		}

		public function test_matches_detects_sql_injection(): void {
			$pattern = '(?i)\bunion\b[\s\S]{0,80}?\bselect\b';
			$this->assertTrue( $this->call_private( 'matches', array( $pattern, 'id=1 UNION SELECT pwd FROM users' ) ) );
		}

		public function test_matches_ignores_clean_input(): void {
			$pattern = '(?i)\bunion\b[\s\S]{0,80}?\bselect\b';
			$this->assertFalse( $this->call_private( 'matches', array( $pattern, 'a perfectly ordinary search query' ) ) );
		}

		public function test_matches_escapes_tilde_delimiter(): void {
			$this->assertTrue( $this->call_private( 'matches', array( 'foo~bar', 'xx foo~bar yy' ) ) );
		}

		public function test_malformed_pattern_fails_open(): void {
			$this->assertFalse( $this->call_private( 'matches', array( '(unbalanced', 'anything at all' ) ) );
		}

		public function test_empty_pattern_never_matches(): void {
			$this->assertFalse( $this->call_private( 'matches', array( '', 'anything' ) ) );
		}

		public function test_required_targets_collapses_duplicates(): void {
			$rules = array(
				array( 'target' => 'uri' ),
				array( 'target' => 'uri' ),
				array( 'target' => 'ua' ),
				array(),
			);
			$targets = $this->call_private( 'required_targets', array( $rules ) );
			$this->assertArrayHasKey( 'uri', $targets );
			$this->assertArrayHasKey( 'ua', $targets );
			$this->assertArrayHasKey( 'all', $targets );
		}

		public function test_paranoia_cap_is_one_without_priority(): void {
			$this->assertSame( 1, $this->waf()->paranoia_cap() );
		}

		public function test_active_rules_drop_levels_above_cap(): void {
			\ReportedIP_Hive_Rule_Store::set(
				'waf',
				array(
					'key'     => 'waf',
					'version' => 9,
					'rules'   => array(
						array( 'id' => 'pl1', 'group' => 'xss', 'pattern' => '(?i)<script', 'paranoia' => 1, 'target' => 'all' ),
						array( 'id' => 'pl2', 'group' => 'xss', 'pattern' => '(?i)<svg', 'paranoia' => 2, 'target' => 'all' ),
						array( 'id' => 'pl3', 'group' => 'xss', 'pattern' => '(?i)<math', 'paranoia' => 3, 'target' => 'all' ),
					),
				)
			);

			$active = $this->waf()->get_active_rules();
			$ids    = array_map(
				static function ( $rule ) {
					return $rule['id'];
				},
				$active
			);
			$this->assertSame( array( 'pl1' ), $ids );
		}

		public function test_active_rules_skip_rules_without_pattern(): void {
			\ReportedIP_Hive_Rule_Store::set(
				'waf',
				array(
					'key'     => 'waf',
					'version' => 9,
					'rules'   => array(
						array( 'id' => 'ok', 'group' => 'xss', 'pattern' => '(?i)<script', 'paranoia' => 1, 'target' => 'all' ),
						array( 'id' => 'broken', 'group' => 'xss', 'paranoia' => 1, 'target' => 'all' ),
					),
				)
			);
			$this->assertCount( 1, $this->waf()->get_active_rules() );
		}
	}
}
