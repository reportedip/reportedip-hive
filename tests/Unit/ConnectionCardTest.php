<?php
/**
 * The free plugin alone carries no remote management surface.
 *
 * The signed fleet transport (`reportedip-hive/v1/remote/settings/*`), its
 * opt-in switch and the settings headers it announces belong to the add-on.
 * Without it the connection card offers a slot and nothing else, the stored
 * opt-in is neither registered nor posted (so a save of the card leaves it
 * as it was), no route answers, and no screen names a plan to buy.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

declare(strict_types=1);

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class ConnectionCardTest extends TestCase {

		/**
		 * Read one source file from the plugin.
		 *
		 * @param string $relative Path relative to the plugin root.
		 * @return string
		 */
		private function source( string $relative ): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/' . $relative );
		}

		/**
		 * Every shipped PHP file of the free plugin, relative path to source.
		 *
		 * @return array<string, string>
		 */
		private function shipped(): array {
			$root  = dirname( __DIR__, 2 );
			$files = array();
			$it    = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS ) );
			foreach ( $it as $file ) {
				$path = str_replace( '\\', '/', (string) $file );
				$rel  = substr( $path, strlen( str_replace( '\\', '/', $root ) ) + 1 );
				if ( '.php' !== substr( $rel, -4 ) || preg_match( '#^(vendor|tests|node_modules|bin|coverage)/#', $rel ) ) {
					continue;
				}
				$files[ $rel ] = (string) file_get_contents( $path );
			}
			return $files;
		}

		public function test_the_card_offers_a_slot_inside_its_form_and_no_opt_in(): void {
			$source = $this->source( 'admin/class-admin-settings.php' );

			$this->assertStringNotContainsString( 'reportedip_hive_cloud_management', $source, 'neither registered nor rendered without the add-on' );
			$form    = substr( $source, (int) strpos( $source, "settings_fields( 'reportedip_hive_api' )" ) );
			$slot    = strpos( $form, "do_action( 'reportedip_hive_connection_card_after_proxy' )" );
			$actions = strpos( $form, 'rip-form-actions' );
			$this->assertIsInt( $slot );
			$this->assertIsInt( $actions );
			$this->assertLessThan( $actions, $slot, 'the slot sits inside the form, before the save button' );
			$this->assertLessThan( (int) strpos( $form, '</form>' ), $slot );
		}

		public function test_no_remote_management_route_and_no_plan_wording(): void {
			foreach ( $this->shipped() as $rel => $source ) {
				$this->assertStringNotContainsString( 'remote/settings', $source, "$rel registers no remote management route" );
				foreach ( array( '(Business plan)', 'Unlocks with Business', 'Included in Business' ) as $wording ) {
					$this->assertStringNotContainsString( $wording, $source, "$rel names no plan to buy" );
				}
			}
		}
	}
}
