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
 * @since      2.1.2
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
			return $ref->invoke( $this->waf(), ...$args );
		}

		public function test_matches_detects_sql_injection(): void {
			$pattern = '(?i)\bunion\b[\s\S]{0,80}?\bselect\b';
			$this->assertNotNull( $this->call_private( 'match_fragment', array( $pattern, 'id=1 UNION SELECT pwd FROM users' ) ) );
		}

		public function test_matches_ignores_clean_input(): void {
			$pattern = '(?i)\bunion\b[\s\S]{0,80}?\bselect\b';
			$this->assertNull( $this->call_private( 'match_fragment', array( $pattern, 'a perfectly ordinary search query' ) ) );
		}

		public function test_matches_escapes_tilde_delimiter(): void {
			$this->assertSame( 'foo~bar', $this->call_private( 'match_fragment', array( 'foo~bar', 'xx foo~bar yy' ) ) );
		}

		public function test_malformed_pattern_fails_open(): void {
			$this->assertNull( $this->call_private( 'match_fragment', array( '(unbalanced', 'anything at all' ) ) );
		}

		public function test_empty_pattern_never_matches(): void {
			$this->assertNull( $this->call_private( 'match_fragment', array( '', 'anything' ) ) );
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

		public function test_evaluate_matches_uri_target(): void {
			$rules = array(
				array( 'id' => 'trav', 'group' => 'path_traversal', 'pattern' => '\.\./', 'paranoia' => 1, 'target' => 'uri' ),
			);
			$hit = $this->waf()->evaluate( $rules, array( 'REQUEST_URI' => '/?f=../../etc/passwd' ), array(), null );
			$this->assertIsArray( $hit );
			$this->assertSame( 'trav', $hit['id'] );
		}

		public function test_evaluate_exposes_matched_fragment_for_logging(): void {
			$rules = array(
				array( 'id' => 'trav', 'group' => 'path_traversal', 'pattern' => '\.\./', 'paranoia' => 1, 'target' => 'uri' ),
			);
			$hit = $this->waf()->evaluate( $rules, array( 'REQUEST_URI' => '/?f=../../etc/passwd' ), array(), null );
			$this->assertIsArray( $hit );
			$this->assertArrayHasKey( 'matched', $hit, 'A hit must carry the substring that tripped the rule.' );
			$this->assertSame( '../', $hit['matched'], 'Matched fragment must be the actual offending value.' );
			$this->assertSame( 'uri', $hit['matched_target'], 'Matched target must record which subject matched.' );
		}

		public function test_evaluate_decodes_encoded_traversal_in_uri(): void {
			$rules = array(
				array( 'id' => 'trav', 'group' => 'path_traversal', 'pattern' => '\.\./', 'paranoia' => 1, 'target' => 'uri' ),
			);
			$hit = $this->waf()->evaluate( $rules, array( 'REQUEST_URI' => '/?f=%2e%2e%2fetc' ), array(), null );
			$this->assertIsArray( $hit );
		}

		public function test_evaluate_matches_body_and_raw(): void {
			$rules = array(
				array( 'id' => 'sqli', 'group' => 'sql_injection', 'pattern' => '(?i)\bunion\b[\s\S]{0,80}?\bselect\b', 'paranoia' => 1, 'target' => 'body' ),
			);
			$hit_post = $this->waf()->evaluate( $rules, array(), array( 'q' => '1 UNION SELECT pw' ), null );
			$this->assertIsArray( $hit_post );
			$hit_raw = $this->waf()->evaluate( $rules, array(), array(), '{"q":"1 union select pw"}' );
			$this->assertIsArray( $hit_raw );
		}

		public function test_evaluate_returns_null_for_clean_request(): void {
			$rules = array(
				array( 'id' => 'sqli', 'group' => 'sql_injection', 'pattern' => '(?i)\bunion\b[\s\S]{0,80}?\bselect\b', 'paranoia' => 1, 'target' => 'all' ),
			);
			$hit = $this->waf()->evaluate( $rules, array( 'REQUEST_URI' => '/shop?page=2' ), array( 'name' => 'Jane' ), null );
			$this->assertNull( $hit );
		}

		public function test_evaluate_short_circuits_on_first_hit(): void {
			$rules = array(
				array( 'id' => 'first', 'group' => 'xss', 'pattern' => '(?i)<script', 'paranoia' => 1, 'target' => 'all' ),
				array( 'id' => 'second', 'group' => 'xss', 'pattern' => '(?i)<script', 'paranoia' => 1, 'target' => 'all' ),
			);
			$hit = $this->waf()->evaluate( $rules, array( 'REQUEST_URI' => '/?x=<script>' ), array(), null );
			$this->assertSame( 'first', $hit['id'] );
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

		public function test_resolve_route_pretty_permalink_strips_prefix(): void {
			$this->assertSame(
				'/reportedip/v2/report',
				$this->call_private( 'resolve_rest_route', array( '/wp-json/reportedip/v2/report?x=1', null, 'wp-json' ) )
			);
		}

		public function test_resolve_route_pretty_permalink_subdirectory_install(): void {
			$this->assertSame(
				'/reportedip/v2/check',
				$this->call_private( 'resolve_rest_route', array( '/blog/wp-json/reportedip/v2/check', null, 'wp-json' ) )
			);
		}

		public function test_resolve_route_plain_permalink_on_rest_entry(): void {
			$this->assertSame(
				'/reportedip/v2/report',
				$this->call_private( 'resolve_rest_route', array( '/index.php?rest_route=/reportedip/v2/report', '/reportedip/v2/report', 'wp-json' ) )
			);
			$this->assertSame(
				'/reportedip/v2',
				$this->call_private( 'resolve_rest_route', array( '/?rest_route=/reportedip/v2', '/reportedip/v2', 'wp-json' ) )
			);
		}

		public function test_resolve_route_ignores_non_rest_request(): void {
			$this->assertSame(
				'',
				$this->call_private( 'resolve_rest_route', array( '/shop?page=2', null, 'wp-json' ) )
			);
		}

		/**
		 * Anti-smuggle: a decoy bypass token in an unrelated query parameter on a
		 * non-REST endpoint must NOT resolve to a route, or the WAF could be
		 * disabled globally with `POST /xmlrpc.php?x=/reportedip/v2`.
		 */
		public function test_resolve_route_rejects_query_string_smuggle(): void {
			$this->assertSame(
				'',
				$this->call_private( 'resolve_rest_route', array( '/xmlrpc.php?x=/reportedip/v2', null, 'wp-json' ) )
			);
		}

		/**
		 * Anti-smuggle: a `rest_route` decoy carried on a real PHP endpoint that
		 * is NOT the REST entry script must be ignored, so an attacker cannot
		 * append `?rest_route=/reportedip/v2` to `/xmlrpc.php` to skip the WAF.
		 */
		public function test_resolve_route_rejects_rest_route_decoy_on_other_script(): void {
			$this->assertSame(
				'',
				$this->call_private( 'resolve_rest_route', array( '/xmlrpc.php?rest_route=/reportedip/v2', '/reportedip/v2', 'wp-json' ) )
			);
		}

		public function test_route_in_bypass_list_anchored_prefix_match(): void {
			$this->assertTrue(
				$this->call_private( 'route_in_bypass_list', array( '/reportedip/v2/report', array( '/reportedip/v2' ) ) )
			);
			$this->assertFalse(
				$this->call_private( 'route_in_bypass_list', array( '/wp/v2/posts', array( '/reportedip/v2' ) ) )
			);
		}

		public function test_route_in_bypass_list_ignores_empty_inputs(): void {
			$this->assertFalse( $this->call_private( 'route_in_bypass_list', array( '', array( '/reportedip/v2' ) ) ) );
			$this->assertFalse( $this->call_private( 'route_in_bypass_list', array( '/reportedip/v2', array( '' ) ) ) );
		}

		public function test_path_prefix_matches_request_path(): void {
			$this->assertTrue( $this->call_private( 'path_prefix_matches', array( '/kontakt', '', '/kontakt/form' ) ) );
		}

		public function test_path_prefix_matches_rest_route_on_plain_permalink(): void {
			$this->assertTrue(
				$this->call_private( 'path_prefix_matches', array( '/wp-json/reportedip/v2', '/reportedip/v2/report', '/index.php' ) )
			);
		}

		public function test_path_prefix_ignores_unrelated_path(): void {
			$this->assertFalse( $this->call_private( 'path_prefix_matches', array( '/wp-json/reportedip/v2', '', '/xmlrpc.php' ) ) );
		}

		public function test_ip_scope_matches_exact_only_without_database(): void {
			$this->assertTrue( $this->call_private( 'ip_scope_matches', array( '203.0.113.7', '203.0.113.7' ) ) );
			$this->assertFalse( $this->call_private( 'ip_scope_matches', array( '203.0.113.7', '203.0.113.8' ) ) );
		}

		public function test_exception_location_matches_path_scope(): void {
			$exception = (object) array(
				'path_prefix' => '/kontakt',
				'ip_address'  => '',
			);
			$this->assertTrue( $this->call_private( 'exception_location_matches', array( $exception, '', '/kontakt', '1.2.3.4' ) ) );
			$this->assertFalse( $this->call_private( 'exception_location_matches', array( $exception, '', '/shop', '1.2.3.4' ) ) );
		}

		public function test_hit_excepted_by_rule_scope_on_path(): void {
			$exception = (object) array(
				'scope'       => 'rule',
				'rule_id'     => 'waf_sqli_union',
				'path_prefix' => '/kontakt',
				'ip_address'  => '',
			);
			$hit = array(
				'id'    => 'waf_sqli_union',
				'group' => 'sql_injection',
			);
			$this->assertTrue( $this->call_private( 'hit_is_excepted', array( array( $exception ), '', '/kontakt', '1.2.3.4', $hit ) ) );
			$this->assertFalse( $this->call_private( 'hit_is_excepted', array( array( $exception ), '', '/shop', '1.2.3.4', $hit ) ) );
		}

		public function test_hit_not_excepted_for_different_rule(): void {
			$exception = (object) array(
				'scope'       => 'rule',
				'rule_id'     => 'waf_xss_onerror',
				'path_prefix' => '',
				'ip_address'  => '',
			);
			$hit = array(
				'id'    => 'waf_sqli_union',
				'group' => 'sql_injection',
			);
			$this->assertFalse( $this->call_private( 'hit_is_excepted', array( array( $exception ), '', '/kontakt', '1.2.3.4', $hit ) ) );
		}

		public function test_hit_excepted_by_group_scope(): void {
			$exception = (object) array(
				'scope'       => 'group',
				'rule_id'     => 'sql_injection',
				'path_prefix' => '',
				'ip_address'  => '',
			);
			$hit = array(
				'id'    => 'waf_sqli_union',
				'group' => 'sql_injection',
			);
			$this->assertTrue( $this->call_private( 'hit_is_excepted', array( array( $exception ), '', '/anywhere', '1.2.3.4', $hit ) ) );
		}

		public function test_request_fully_excepted_by_all_scope_on_path(): void {
			$exception = (object) array(
				'scope'       => 'all',
				'rule_id'     => null,
				'path_prefix' => '/wp-json/reportedip/v2',
				'ip_address'  => '',
			);
			$this->assertTrue(
				$this->call_private(
					'request_is_fully_excepted',
					array( array( $exception ), '/reportedip/v2/report', '/wp-json/reportedip/v2/report', '1.2.3.4' )
				)
			);
			$this->assertFalse(
				$this->call_private( 'request_is_fully_excepted', array( array( $exception ), '', '/shop', '1.2.3.4' ) )
			);
		}

		public function test_rule_scope_does_not_fully_except_request(): void {
			$exception = (object) array(
				'scope'       => 'rule',
				'rule_id'     => 'waf_sqli_union',
				'path_prefix' => '',
				'ip_address'  => '',
			);
			$this->assertFalse(
				$this->call_private( 'request_is_fully_excepted', array( array( $exception ), '', '/kontakt', '1.2.3.4' ) )
			);
		}
	}
}
