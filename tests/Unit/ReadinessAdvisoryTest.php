<?php
/**
 * Readiness advisory detectors that feed the dashboard's next steps.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.57
 */

declare(strict_types=1);

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-readiness.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use ReportedIP_Hive_Readiness;

	/**
	 * @covers ReportedIP_Hive_Readiness
	 */
	final class ReadinessAdvisoryTest extends TestCase {

		public function test_score_advisories_list_the_heaviest_open_items_first(): void {
			$item = static function ( string $key, int $weight, bool $available, bool $enabled, bool $present = true ): array {
				return array(
					'key'       => $key,
					'weight'    => $weight,
					'present'   => $present,
					'available' => $available,
					'enabled'   => $enabled,
				);
			};
			$issues = ReportedIP_Hive_Readiness::score_advisories(
				array(
					$item( 'password_hibp', 12, true, false ),
					$item( 'twofa_enforce', 18, true, false ),
					$item( 'waf', 15, true, true ),
					$item( 'security_headers', 12, true, false, false ),
					$item( 'hide_login', 14, true, false ),
					$item( 'feeds_off', 2, false, false ),
				)
			);
			$this->assertSame( array( 'score_twofa_enforce', 'score_password_hibp' ), array_column( $issues, 'key' ) );
			foreach ( $issues as $issue ) {
				$this->assertSame( ReportedIP_Hive_Readiness::SEV_ADVISORY, $issue['severity'] );
				$this->assertNotSame( '', $issue['message'] );
			}
			$this->assertSame( array(), ReportedIP_Hive_Readiness::score_advisories( array() ) );
		}

		public function test_hide_login_off_raises_only_while_the_slug_is_off(): void {
			$issue = ReportedIP_Hive_Readiness::hide_login_off( false );
			$this->assertSame( 'hide_login_off', $issue['key'] );
			$this->assertSame( ReportedIP_Hive_Readiness::SEV_ADVISORY, $issue['severity'] );
			$this->assertNull( ReportedIP_Hive_Readiness::hide_login_off( true ) );
		}

		public function test_the_adapter_advisory_names_no_plan_and_a_listener_words_it(): void {
			$GLOBALS['wp_filters'] = array();
			$issue                 = ReportedIP_Hive_Readiness::form_adapter_off( 'cf7', 'Contact Form 7', true, true, false );
			$this->assertSame( 'Contact Form 7 is active here and Hive can check it, but the switch is still off. A visitor sees nothing new once it runs, no image to read and no extra step.', $issue['message'] );

			add_filter(
				'reportedip_hive_form_adapter_off_message',
				static function ( $message, $slug, $label ) {
					return $slug . '|' . $label;
				},
				10,
				3
			);
			try {
				$this->assertSame( 'cf7|Contact Form 7', ReportedIP_Hive_Readiness::form_adapter_off( 'cf7', 'Contact Form 7', true, true, false )['message'] );
			} finally {
				$GLOBALS['wp_filters'] = array();
			}
		}

		public function test_no_badge_advisory_and_community_pending(): void {
			$this->assertFalse( method_exists( ReportedIP_Hive_Readiness::class, 'badge_off' ), 'A credit badge is no security advisory.' );
			$this->assertSame( 'community_pending', ReportedIP_Hive_Readiness::community_pending( 'local' )['key'] );
			$this->assertNull( ReportedIP_Hive_Readiness::community_pending( 'community' ) );
		}

		/**
		 * The group advisory left with the add-on; an add-on's issue reaches
		 * its deep link through the links filter, and a broken filter result
		 * leaves the free list.
		 */
		public function test_an_add_on_issue_gets_its_link_through_the_filter(): void {
			$this->assertFalse( method_exists( ReportedIP_Hive_Readiness::class, 'group_available' ) );
			$links = new \ReflectionMethod( ReportedIP_Hive_Readiness::class, 'links' );
			$this->assertArrayNotHasKey( 'group_available', $links->invoke( null ) );

			$filters_before = $GLOBALS['wp_filters'] ?? array();
			try {
				add_filter(
					'reportedip_hive_readiness_links',
					static function ( $rows ) {
						$rows['extra_issue'] = array( 'reportedip-hive-community', 'community' );
						return $rows;
					}
				);
				$this->assertSame( array( 'reportedip-hive-community', 'community' ), $links->invoke( null )['extra_issue'] );

				$GLOBALS['wp_filters']['reportedip_hive_readiness_links'] = array();
				add_filter( 'reportedip_hive_readiness_links', static fn() => null );
				$this->assertArrayHasKey( 'community_pending', $links->invoke( null ) );
			} finally {
				$GLOBALS['wp_filters'] = $filters_before;
			}

			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-readiness.php' );
			$after  = strpos( $source, "\$raised[] = self::community_pending(" );
			$filter = strpos( $source, "apply_filters( 'reportedip_hive_readiness_issues', \$raised )" );
			$forms  = strpos( $source, 'foreach ( self::form_adapters() as $slug => $row )' );
			$this->assertNotFalse( $filter );
			$this->assertGreaterThan( $after, $filter, 'Add-on advisories follow community_pending, where 2.1.74 raised the group advisory.' );
			$this->assertLessThan( $forms, $filter );
		}

		public function test_dropin_not_running_only_where_the_server_could_run_it(): void {
			$this->assertNotNull( ReportedIP_Hive_Readiness::dropin_not_running( true, false ) );
			$this->assertNull( ReportedIP_Hive_Readiness::dropin_not_running( true, true ), 'running' );
			$this->assertNull( ReportedIP_Hive_Readiness::dropin_not_running( false, false ), 'no supported server' );
		}

		public function test_cached_pages_without_headers_are_named_with_the_route_the_server_allows(): void {
			$auto = ReportedIP_Hive_Readiness::headers_cache_gap( true, true, false, true );
			$this->assertSame( 'headers_cache_gap', $auto['key'] );
			$this->assertSame( ReportedIP_Hive_Readiness::SEV_ADVISORY, $auto['severity'] );
			$this->assertStringContainsString( 'Switch on Extended protection', $auto['message'] );

			$manual = ReportedIP_Hive_Readiness::headers_cache_gap( true, true, false, false );
			$this->assertStringContainsString( 'web server configuration into nginx or Apache', $manual['message'] );

			$this->assertNull( ReportedIP_Hive_Readiness::headers_cache_gap( false, true, false, true ), 'headers off: the score step asks for them' );
			$this->assertNull( ReportedIP_Hive_Readiness::headers_cache_gap( true, false, false, true ), 'no page cache' );
			$this->assertNull( ReportedIP_Hive_Readiness::headers_cache_gap( true, true, true, true ), 'the guard sends them' );
		}

		public function test_the_advanced_headers_are_suggested_only_where_the_plan_has_them(): void {
			$row = static function ( bool $available ): array {
				return array(
					'key'       => 'security_headers_advanced',
					'weight'    => 6,
					'present'   => true,
					'available' => $available,
					'enabled'   => false,
				);
			};
			$this->assertSame( array( 'score_security_headers_advanced' ), array_column( ReportedIP_Hive_Readiness::score_advisories( array( $row( true ) ) ), 'key' ) );
			$this->assertSame( array(), ReportedIP_Hive_Readiness::score_advisories( array( $row( false ) ) ), 'a plan without the feature gets no suggestion' );
		}

		public function test_own_2fa_missing_is_a_user_issue(): void {
			$issue = ReportedIP_Hive_Readiness::own_2fa_missing( true, array() );
			$this->assertSame( 'own_2fa_missing', $issue['key'] );
			$this->assertNull( ReportedIP_Hive_Readiness::own_2fa_missing( true, array( 'totp' ) ) );
			$this->assertNull( ReportedIP_Hive_Readiness::own_2fa_missing( false, array() ), '2FA globally off' );
		}
	}
}
