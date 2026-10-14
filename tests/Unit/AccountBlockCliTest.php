<?php
/**
 * Guards the wiring of the free `wp reportedip user unblock|list` commands.
 *
 * Both run without the add-on, so a block written by an earlier release or
 * by the add-on can always be found and lifted from the command line. The
 * tests pin the command path, the bootstrap require, the `list` rename, that
 * unblocking never asks the plan, and that sessions are left to core's own
 * `wp user session`.
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

	class AccountBlockCliTest extends TestCase {

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
			$source = $this->source( 'includes/class-account-block-cli.php' );

			$this->assertStringContainsString( "WP_CLI::add_command( 'reportedip user', __CLASS__ )", $source );
			$this->assertStringContainsString( 'ReportedIP_Hive_Account_Block_CLI::register();', $source );
			$this->assertStringContainsString( '@subcommand list', $source );
			$this->assertStringContainsString( 'public function list_(', $source );
			$this->assertStringContainsString( 'public function unblock(', $source );
			$this->assertStringNotContainsString( 'public function block(', $source, 'blocking belongs to the add-on' );
		}

		public function test_bootstrap_requires_the_cli_file(): void {
			$this->assertStringContainsString(
				"require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-account-block-cli.php';",
				$this->source( 'reportedip-hive.php' ),
				'class-account-block-cli.php must be required from the WP_CLI bootstrap block.'
			);
		}

		public function test_unblock_is_never_tier_gated(): void {
			$source = $this->source( 'includes/class-account-block-cli.php' );
			$body   = substr( $source, (int) strpos( $source, 'public function unblock(' ) );
			$body   = substr( $body, 0, (int) strpos( $body, 'public function list_(' ) );

			$this->assertStringContainsString( 'Account_Block::unblock(', $body );
			$this->assertStringNotContainsString( 'is_available', $body );
			$this->assertStringNotContainsString( 'feature_status', $body );
		}

		/**
		 * Core already ships `wp user session list|destroy`; a second session
		 * command would be duplicate surface.
		 */
		public function test_no_session_commands_are_registered(): void {
			$this->assertStringNotContainsString(
				"add_command( 'reportedip user session",
				$this->source( 'includes/class-account-block-cli.php' )
			);
		}
	}
}
