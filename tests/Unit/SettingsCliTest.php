<?php
/**
 * Guards the wiring of `wp reportedip settings list|get|set`.
 *
 * The command is one more settings channel: it reads the registry and
 * writes through Settings_Apply, never through the option functions, and it
 * asks no plan itself.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.9
 */

declare(strict_types=1);

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class SettingsCliTest extends TestCase {

		/**
		 * Read one source file from the plugin.
		 *
		 * @param string $relative Path relative to the plugin root.
		 * @return string
		 */
		private function source( string $relative ): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/' . $relative );
		}

		public function test_command_is_registered(): void {
			$source = $this->source( 'includes/class-settings-cli.php' );

			$this->assertStringContainsString( "WP_CLI::add_command( 'reportedip settings', __CLASS__ )", $source );
			$this->assertStringContainsString( 'ReportedIP_Hive_Settings_CLI::register();', $source );
			foreach ( array( 'list', 'get', 'set' ) as $sub ) {
				$this->assertStringContainsString( 'public function ' . $sub . '(', $source );
			}
		}

		public function test_bootstrap_requires_the_cli_file(): void {
			$this->assertStringContainsString(
				"require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-settings-cli.php';",
				$this->source( 'reportedip-hive.php' )
			);
		}

		public function test_writes_only_through_the_shared_pipeline(): void {
			$source = $this->source( 'includes/class-settings-cli.php' );

			$this->assertStringContainsString( "ReportedIP_Hive_Settings_Apply::apply( array( \$key => \$value ), 'cli' )", $source );
			$this->assertDoesNotMatchRegularExpression( '/update_(site_)?option|Option_Routing::set|get_current_tier|feature_status/', $source, 'no direct write and no plan check of its own' );
		}

		public function test_a_refused_write_ends_in_an_error(): void {
			$source = $this->source( 'includes/class-settings-cli.php' );
			$body   = substr( $source, (int) strpos( $source, 'public function set(' ) );

			$this->assertStringContainsString( "WP_CLI::error( \$result['status']", $body );
			$this->assertStringContainsString( "\$result['message']", $body );
		}
	}
}
