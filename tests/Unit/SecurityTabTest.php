<?php
/**
 * The Activity page resolves its tab and sub-tab from the request, opens the
 * event log by default and keeps the former one-level slugs working.
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
	if ( ! defined( 'ABSPATH' ) ) {
		define( 'ABSPATH', __DIR__ . '/' );
	}
	require_once dirname( __DIR__, 2 ) . '/admin/class-admin-settings.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use ReportedIP_Hive_Admin_Settings;

	/**
	 * @covers ReportedIP_Hive_Admin_Settings::security_tab
	 * @covers ReportedIP_Hive_Admin_Settings::tab_intro
	 */
	final class SecurityTabTest extends TestCase {

		/**
		 * @dataProvider requests
		 */
		public function test_tab_and_sub_tab_resolve( $tab, $sub, array $expected ): void {
			$this->assertSame( $expected, ReportedIP_Hive_Admin_Settings::security_tab( $tab, $sub ) );
		}

		/**
		 * @return array<string,array{0:mixed,1:mixed,2:array{0:string,1:string}}>
		 */
		public static function requests(): array {
			return array(
				'no parameters open the event log' => array( '', '', array( 'activity', 'logs' ) ),
				'activity without sub'             => array( 'activity', '', array( 'activity', 'logs' ) ),
				'audit without the add-on'         => array( 'activity', 'audit', array( 'activity', 'logs' ) ),
				'ip lists default to blocked'      => array( 'ip_lists', '', array( 'ip_lists', 'blocked' ) ),
				'ip lists whitelist'               => array( 'ip_lists', 'whitelist', array( 'ip_lists', 'whitelist' ) ),
				'group without the add-on'         => array( 'ip_lists', 'group', array( 'ip_lists', 'blocked' ) ),
				'legacy tab=group without add-on'  => array( 'group', '', array( 'activity', 'logs' ) ),
				'advanced has no sub'              => array( 'advanced', 'logs', array( 'advanced', '' ) ),
				'legacy tab=logs'                  => array( 'logs', '', array( 'activity', 'logs' ) ),
				'legacy tab=lookup'                => array( 'lookup', '', array( 'activity', 'lookup' ) ),
				'legacy tab=blocked'               => array( 'blocked', '', array( 'ip_lists', 'blocked' ) ),
				'legacy tab=api_queue'             => array( 'api_queue', '', array( 'advanced', '' ) ),
				'sub from another tab is dropped'  => array( 'activity', 'blocked', array( 'activity', 'logs' ) ),
				'unknown tab falls back'           => array( 'nonsense', '', array( 'activity', 'logs' ) ),
				'unknown tab keeps a valid sub'    => array( 'nonsense', 'lookup', array( 'activity', 'lookup' ) ),
				'array input is ignored'           => array( array( 'audit' ), array( 'x' ), array( 'activity', 'logs' ) ),
			);
		}

		public function test_every_tab_has_a_title_and_a_text(): void {
			foreach ( array( 'logs', 'lookup', 'blocked', 'whitelist', 'queue' ) as $key ) {
				list( $title, $text ) = ReportedIP_Hive_Admin_Settings::tab_intro( $key );
				$this->assertNotSame( '', $title, $key );
				$this->assertGreaterThan( 80, strlen( $text ), $key );
			}
			$this->assertSame( array( '', '' ), ReportedIP_Hive_Admin_Settings::tab_intro( 'nonsense' ) );
			$this->assertSame( array( '', '' ), ReportedIP_Hive_Admin_Settings::tab_intro( 'audit' ), 'No audit intro without the add-on.' );
			$this->assertSame( array( '', '' ), ReportedIP_Hive_Admin_Settings::tab_intro( 'group' ), 'No group intro without the add-on.' );
		}

		/**
		 * An add-on adds a sub-tab through the filter; its slug then resolves
		 * like a free one, also as a former one-level tab, and its intro
		 * comes through the intro filter. A broken filter result changes
		 * nothing.
		 */
		public function test_an_add_on_sub_tab_resolves_through_the_filters(): void {
			$filters_before = $GLOBALS['wp_filters'] ?? array();
			try {
				add_filter(
					'reportedip_hive_activity_tabs',
					static function ( $tabs ) {
						$tabs['parents']['extra']   = 'activity';
						$tabs['subs']['activity'][] = 'extra';
						return $tabs;
					}
				);
				add_filter(
					'reportedip_hive_activity_tab_intro',
					static function ( $intro, $key ) {
						return 'extra' === $key ? array( 'Extra', 'Text' ) : $intro;
					},
					10,
					2
				);
				$this->assertSame( array( 'activity', 'extra' ), ReportedIP_Hive_Admin_Settings::security_tab( 'activity', 'extra' ) );
				$this->assertSame( array( 'activity', 'extra' ), ReportedIP_Hive_Admin_Settings::security_tab( 'extra', '' ) );
				$this->assertSame( array( 'ip_lists', 'blocked' ), ReportedIP_Hive_Admin_Settings::security_tab( 'ip_lists', 'extra' ) );
				$this->assertSame( array( 'Extra', 'Text' ), ReportedIP_Hive_Admin_Settings::tab_intro( 'extra' ) );

				$GLOBALS['wp_filters']['reportedip_hive_activity_tabs'] = array();
				add_filter( 'reportedip_hive_activity_tabs', static fn() => null );
				$this->assertSame( array( 'activity', 'lookup' ), ReportedIP_Hive_Admin_Settings::security_tab( 'activity', 'lookup' ) );
				$this->assertSame( array( 'activity', 'logs' ), ReportedIP_Hive_Admin_Settings::security_tab( 'activity', 'extra' ) );
			} finally {
				$GLOBALS['wp_filters'] = $filters_before;
			}
		}

		/**
		 * The renderer hands an unknown sub-tab to its action and prints the
		 * add-on links in both sub-tab bars.
		 */
		public function test_the_renderer_hands_add_on_sub_tabs_to_their_action(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-admin-settings.php' );
			$this->assertStringContainsString( "do_action( 'reportedip_hive_activity_render_' . sanitize_key( (string) \$sub_tab ) );", $source );
			$this->assertStringContainsString( "do_action( 'reportedip_hive_activity_sub_tabs', 'activity', \$sub_tab );", $source );
			$this->assertStringContainsString( "do_action( 'reportedip_hive_activity_sub_tabs', 'ip_lists', \$sub_tab );", $source );
			$this->assertStringNotContainsString( 'sub=audit', $source, 'The audit tab belongs to the add-on.' );
			$this->assertStringNotContainsString( 'sub=group', $source, 'The group tab belongs to the add-on.' );
			$this->assertStringContainsString( "do_action( 'reportedip_hive_dashboard_after_score' );", $source );
			$this->assertStringContainsString( "do_action( 'reportedip_hive_inline_notices' );", $source );
			$this->assertStringContainsString( "if ( has_action( 'reportedip_hive_reputation_section' ) ) {", $source, 'With a listener the add-on prints the section, never both.' );
			$this->assertStringContainsString( "do_action( 'reportedip_hive_reputation_section', (bool) \$with_link );", $source );
		}
	}
}
