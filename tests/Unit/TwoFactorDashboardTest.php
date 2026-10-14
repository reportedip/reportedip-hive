<?php
/**
 * 2FA status page: the list filter over the user rows.
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
	require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-dashboard.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use ReportedIP_Hive_Two_Factor_Dashboard;

	/**
	 * @covers ReportedIP_Hive_Two_Factor_Dashboard
	 */
	final class TwoFactorDashboardTest extends TestCase {

		/**
		 * Four users covering every status and method combination the filter knows.
		 *
		 * @return array
		 */
		private function rows(): array {
			return array(
				$this->row( 1, true, true, 'totp,email', array( 'administrator' ) ),
				$this->row( 2, false, true, '', array( 'editor' ) ),
				$this->row( 3, false, false, '', array( 'subscriber' ) ),
				$this->row( 4, true, false, 'email', array( 'editor', 'shop_manager' ) ),
			);
		}

		private function row( int $id, bool $enabled, bool $enforced, string $methods, array $roles ): array {
			return array(
				'id'         => $id,
				'enabled'    => $enabled,
				'enforced'   => $enforced,
				'methods'    => $methods,
				'roles'      => array_map( 'ucfirst', $roles ),
				'role_slugs' => $roles,
			);
		}

		private function ids( array $filters ): array {
			return array_column( ReportedIP_Hive_Two_Factor_Dashboard::filter_rows( $this->rows(), $filters ), 'id' );
		}

		public function test_no_filter_keeps_every_row_reindexed(): void {
			$rows = ReportedIP_Hive_Two_Factor_Dashboard::filter_rows( $this->rows(), array() );
			$this->assertSame( array( 0, 1, 2, 3 ), array_keys( $rows ) );
		}

		public function test_status_filter_matches_the_table_badges(): void {
			$this->assertSame( array( 1, 4 ), $this->ids( array( 'status' => 'active' ) ) );
			$this->assertSame( array( 2 ), $this->ids( array( 'status' => 'required' ) ) );
			$this->assertSame( array( 3 ), $this->ids( array( 'status' => 'optional' ) ) );
		}

		public function test_method_filter_matches_any_configured_method(): void {
			$this->assertSame( array( 1 ), $this->ids( array( 'method' => 'totp' ) ) );
			$this->assertSame( array( 1, 4 ), $this->ids( array( 'method' => 'email' ) ) );
			$this->assertSame( array( 2, 3 ), $this->ids( array( 'method' => 'none' ) ) );
		}

		public function test_role_filter_uses_the_raw_slugs_not_the_labels(): void {
			$this->assertSame( array( 2, 4 ), $this->ids( array( 'role' => 'editor' ) ) );
			$this->assertSame( array(), $this->ids( array( 'role' => 'Editor' ) ) );
		}

		public function test_filters_combine(): void {
			$this->assertSame( array( 4 ), $this->ids( array( 'status' => 'active', 'role' => 'editor' ) ) );
			$this->assertSame( array(), $this->ids( array( 'status' => 'required', 'method' => 'totp' ) ) );
		}

		/**
		 * Without the add-on the page offers the user status export only;
		 * further exports hang into the action slot and answer their own
		 * export type.
		 */
		public function test_further_exports_come_through_the_slot(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor-dashboard.php' );
			$this->assertStringContainsString( "do_action( 'reportedip_hive_2fa_dashboard_actions' );", $source );
			$this->assertStringNotContainsString( 'audit', strtolower( substr( $source, (int) strpos( $source, 'public function render(' ) ) ) );
			$this->assertLessThan( strpos( $source, "do_action( 'reportedip_hive_2fa_dashboard_actions' );" ), strpos( $source, 'User status CSV' ), 'The slot follows the user status button.' );
		}

		/**
		 * Without the add-on an export type other than the user status is
		 * refused with a 403 after the capability and nonce checks, as 2.x
		 * refused the audit export on a plan without it; the user status
		 * stays the default.
		 */
		public function test_an_unknown_export_type_is_refused_before_any_output(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor-dashboard.php' );
			$body   = substr( $source, (int) strpos( $source, 'public function export_csv()' ) );
			$body   = substr( $body, 0, (int) strpos( $body, "\n\t}" ) );

			$nonce  = strpos( $body, "check_admin_referer( 'reportedip_hive_2fa_export' );" );
			$refuse = strpos( $body, "if ( 'users' !== \$type ) {" );
			$open   = strpos( $body, "self::open_csv( 'users' )" );
			$this->assertNotFalse( $nonce );
			$this->assertNotFalse( $refuse );
			$this->assertLessThan( $refuse, $nonce );
			$this->assertLessThan( $open, $refuse, 'Refused before a header or a byte is sent.' );
			$this->assertStringContainsString( "sanitize_key( wp_unslash( \$_GET['type'] ) ) : 'users';", $body );
			$this->assertStringContainsString( "array( 'response' => 403 )", $body );
		}
	}
}
