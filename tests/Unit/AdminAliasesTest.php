<?php
/**
 * Legacy settings and firewall URLs resolve to the protection page anchor
 * or the tools tab that carries the same content now.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.56
 */

declare(strict_types=1);

namespace {
	require_once dirname( __DIR__, 2 ) . '/admin/class-admin-aliases.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use ReportedIP_Hive_Admin_Aliases;

	/**
	 * @covers ReportedIP_Hive_Admin_Aliases
	 */
	final class AdminAliasesTest extends TestCase {

		/**
		 * @dataProvider legacy_urls
		 */
		public function test_legacy_slug_and_tab_resolve( string $page, string $tab, string $expected ): void {
			$this->assertSame( $expected, ReportedIP_Hive_Admin_Aliases::resolve( $page, $tab ) );
		}

		/**
		 * @return array<int,array{0:string,1:string,2:string}>
		 */
		public static function legacy_urls(): array {
			return array(
				array( 'reportedip-hive-settings', '', 'admin.php?page=reportedip-hive-protection' ),
				array( 'reportedip-hive-settings', 'general', 'admin.php?page=reportedip-hive-community' ),
				array( 'reportedip-hive-settings', 'detection', 'admin.php?page=reportedip-hive-protection#detection' ),
				array( 'reportedip-hive-settings', 'blocking', 'admin.php?page=reportedip-hive-protection#blocking' ),
				array( 'reportedip-hive-settings', 'hide_login', 'admin.php?page=reportedip-hive-protection#hide_login' ),
				array( 'reportedip-hive-settings', 'notifications', 'admin.php?page=reportedip-hive-protection#notifications' ),
				array( 'reportedip-hive-settings', 'privacy_logs', 'admin.php?page=reportedip-hive-protection#privacy_logs' ),
				array( 'reportedip-hive-settings', 'performance', 'admin.php?page=reportedip-hive-protection#performance' ),
				array( 'reportedip-hive-settings', 'two_factor', 'admin.php?page=reportedip-hive-protection#account_security' ),
				array( 'reportedip-hive-settings', 'hardening_mode', 'admin.php?page=reportedip-hive-protection#hardening_mode' ),
				array( 'reportedip-hive-settings', 'nonsense', 'admin.php?page=reportedip-hive-protection' ),
				array( 'reportedip-hive-firewall', '', 'admin.php?page=reportedip-hive-protection#waf' ),
				array( 'reportedip-hive-firewall', 'overview', 'admin.php?page=reportedip-hive-protection#waf' ),
				array( 'reportedip-hive-firewall', 'waf', 'admin.php?page=reportedip-hive-protection#waf' ),
				array( 'reportedip-hive-firewall', 'bot', 'admin.php?page=reportedip-hive-protection#waf' ),
				array( 'reportedip-hive-firewall', 'spam', 'admin.php?page=reportedip-hive-protection#registration' ),
				array( 'reportedip-hive-firewall', 'scan', 'admin.php?page=reportedip-hive-protection#detection' ),
				array( 'reportedip-hive-firewall', 'hardening', 'admin.php?page=reportedip-hive-protection#headers' ),
				array( 'reportedip-hive-firewall', 'rule_sync', 'admin.php?page=reportedip-hive-tools&tab=rules' ),
				array( 'reportedip-hive-firewall', 'server', 'admin.php?page=reportedip-hive-tools&tab=server' ),
				array( 'reportedip-hive-other', 'x', '' ),
			);
		}
	}
}
