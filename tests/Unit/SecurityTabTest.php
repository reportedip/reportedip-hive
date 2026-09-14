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
				'activity audit'                   => array( 'activity', 'audit', array( 'activity', 'audit' ) ),
				'ip lists default to blocked'      => array( 'ip_lists', '', array( 'ip_lists', 'blocked' ) ),
				'ip lists whitelist'               => array( 'ip_lists', 'whitelist', array( 'ip_lists', 'whitelist' ) ),
				'advanced has no sub'              => array( 'advanced', 'logs', array( 'advanced', '' ) ),
				'legacy tab=logs'                  => array( 'logs', '', array( 'activity', 'logs' ) ),
				'legacy tab=lookup'                => array( 'lookup', '', array( 'activity', 'lookup' ) ),
				'legacy tab=blocked'               => array( 'blocked', '', array( 'ip_lists', 'blocked' ) ),
				'legacy tab=api_queue'             => array( 'api_queue', '', array( 'advanced', '' ) ),
				'sub from another tab is dropped'  => array( 'activity', 'blocked', array( 'activity', 'logs' ) ),
				'unknown tab falls back'           => array( 'nonsense', '', array( 'activity', 'logs' ) ),
				'unknown tab keeps a valid sub'    => array( 'nonsense', 'audit', array( 'activity', 'audit' ) ),
				'array input is ignored'           => array( array( 'audit' ), array( 'x' ), array( 'activity', 'logs' ) ),
			);
		}

		public function test_every_tab_has_a_title_and_a_text(): void {
			foreach ( array( 'logs', 'lookup', 'audit', 'blocked', 'whitelist', 'queue' ) as $key ) {
				list( $title, $text ) = ReportedIP_Hive_Admin_Settings::tab_intro( $key );
				$this->assertNotSame( '', $title, $key );
				$this->assertGreaterThan( 80, strlen( $text ), $key );
			}
			$this->assertSame( array( '', '' ), ReportedIP_Hive_Admin_Settings::tab_intro( 'nonsense' ) );
		}
	}
}
