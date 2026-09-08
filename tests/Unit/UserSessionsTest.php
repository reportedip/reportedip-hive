<?php
/**
 * Unit tests for the session reader.
 *
 * Everything the admin table depends on is pure: the verifier hash must match
 * core's, expired entries must disappear while the verifier keys survive (core
 * `get_all()` drops them, which is why this reader exists), and the user query
 * must stay inside its orderby allowlist.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

declare(strict_types=1);

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-user-sessions.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class UserSessionsTest extends TestCase {

		public function test_hash_verifier_matches_core(): void {
			$this->assertSame(
				hash( 'sha256', 'token-value' ),
				\ReportedIP_Hive_User_Sessions::hash_verifier( 'token-value' )
			);
			$this->assertSame( '', \ReportedIP_Hive_User_Sessions::hash_verifier( '' ) );
		}

		public function test_live_drops_expired_sessions_and_keeps_verifier_keys(): void {
			$now      = 1000;
			$sessions = array(
				'aaa' => array( 'expiration' => 1500 ),
				'bbb' => array( 'expiration' => 900 ),
				'ccc' => array( 'expiration' => 1000 ),
				'ddd' => array( 'login' => 1 ),
			);

			$live = \ReportedIP_Hive_User_Sessions::live( $sessions, $now );

			$this->assertSame( array( 'aaa' ), array_keys( $live ) );
			$this->assertSame( 1500, $live['aaa']['expiration'] );
		}

		public function test_live_upgrades_the_legacy_integer_shape(): void {
			$live = \ReportedIP_Hive_User_Sessions::live( array( 'aaa' => 2000 ), 1000 );

			$this->assertSame( array( 'expiration' => 2000 ), $live['aaa'] );
		}

		public function test_display_ip_prefers_the_proxy_aware_address(): void {
			$this->assertSame(
				'203.0.113.7',
				\ReportedIP_Hive_User_Sessions::display_ip(
					array(
						'ip'     => '10.0.0.1',
						'rip_ip' => '203.0.113.7',
					)
				)
			);
			$this->assertSame( '10.0.0.1', \ReportedIP_Hive_User_Sessions::display_ip( array( 'ip' => '10.0.0.1' ) ) );
			$this->assertSame( '', \ReportedIP_Hive_User_Sessions::display_ip( array() ) );
		}

		public function test_ip_like_pattern_matches_the_serialised_value(): void {
			$this->assertSame( '%"203.0.113.7"%', \ReportedIP_Hive_User_Sessions::ip_like_pattern( '203.0.113.7' ) );
		}

		public function test_users_query_args_probe_the_session_meta(): void {
			$args = \ReportedIP_Hive_User_Sessions::users_query_args( array(), 20, 1, 0 );

			$this->assertSame( 'session_tokens', $args['meta_key'] );
			$this->assertSame( 'EXISTS', $args['meta_compare'] );
			$this->assertSame( 0, $args['blog_id'] );
			$this->assertTrue( $args['count_total'] );
			$this->assertSame( 20, $args['number'] );
			$this->assertSame( 0, $args['offset'] );
			$this->assertArrayNotHasKey( 'meta_value', $args );
		}

		public function test_users_query_args_paginate_and_filter(): void {
			$args = \ReportedIP_Hive_User_Sessions::users_query_args(
				array(
					'search' => 'jdoe',
					'ip'     => '203.0.113.7',
				),
				10,
				3,
				1
			);

			$this->assertSame( 20, $args['offset'] );
			$this->assertSame( 'LIKE', $args['meta_compare'] );
			$this->assertSame( '%"203.0.113.7"%', $args['meta_value'] );
			$this->assertSame( '*jdoe*', $args['search'] );
			$this->assertSame( array( 'user_login', 'user_email', 'display_name' ), $args['search_columns'] );
		}

		public function test_users_query_args_reject_an_unknown_orderby(): void {
			$args = \ReportedIP_Hive_User_Sessions::users_query_args(
				array(
					'orderby' => 'user_pass',
					'order'   => 'desc',
				),
				20,
				1,
				0
			);

			$this->assertSame( 'user_login', $args['orderby'] );
			$this->assertSame( 'DESC', $args['order'] );

			$allowed = \ReportedIP_Hive_User_Sessions::users_query_args( array( 'orderby' => 'display_name' ), 20, 1, 0 );
			$this->assertSame( 'display_name', $allowed['orderby'] );
			$this->assertSame( 'ASC', $allowed['order'] );
		}

		/**
		 * The reader exists exactly once: nothing else in the plugin may read
		 * the raw `session_tokens` meta.
		 */
		public function test_session_meta_is_read_in_one_place_only(): void {
			$root  = dirname( __DIR__, 2 );
			$files = array_merge(
				(array) glob( $root . '/includes/*.php' ),
				(array) glob( $root . '/admin/*.php' )
			);

			foreach ( $files as $file ) {
				if ( 'class-user-sessions.php' === basename( (string) $file ) ) {
					continue;
				}
				$this->assertStringNotContainsString(
					"'session_tokens'",
					(string) file_get_contents( (string) $file ),
					basename( (string) $file ) . ' must use ReportedIP_Hive_User_Sessions instead of the raw meta.'
				);
			}
		}
	}
}
