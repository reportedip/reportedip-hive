<?php
/**
 * Guards the wiring of the IP-management WP-CLI surface.
 *
 * The whitelist/block/status commands exist so that a locked-out visitor
 * can be released from the shell without touching wp-admin. The commands
 * are thin wrappers around the service layer, so these tests pin the
 * wiring decisions that make them safe rather than executing WP-CLI:
 *
 *  - every command path is registered and required from the bootstrap,
 *  - `block` surfaces report-only mode as a warning instead of a plain
 *    success (the block is logged but NOT enforced),
 *  - `unblock` offers --reset-attempts, because a still-exceeded
 *    threshold re-blocks the address on the next request otherwise,
 *  - list-style commands honour --format.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.50
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class IpCliTest extends TestCase {

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
		 * Every IP-management command path must be registered.
		 */
		public function test_all_command_paths_are_registered(): void {
			$whitelist = $this->source( 'includes/class-whitelist-cli.php' );
			$block     = $this->source( 'includes/class-block-cli.php' );
			$status    = $this->source( 'includes/class-status-cli.php' );

			$this->assertStringContainsString( "WP_CLI::add_command( 'reportedip whitelist', __CLASS__ )", $whitelist );
			$this->assertStringContainsString( "WP_CLI::add_command( 'reportedip block', array( \$instance, 'block' ) )", $block );
			$this->assertStringContainsString( "WP_CLI::add_command( 'reportedip unblock', array( \$instance, 'unblock' ) )", $block );
			$this->assertStringContainsString( "WP_CLI::add_command( 'reportedip blocked list', array( \$instance, 'blocked_list' ) )", $block );
			$this->assertStringContainsString( "WP_CLI::add_command( 'reportedip attempts reset', array( \$instance, 'attempts_reset' ) )", $block );
			$this->assertStringContainsString( "WP_CLI::add_command( 'reportedip status', __CLASS__ )", $status );
		}

		/**
		 * The bootstrap must require every CLI file inside the WP_CLI guard.
		 */
		public function test_bootstrap_requires_the_cli_files(): void {
			$bootstrap = $this->source( 'reportedip-hive.php' );

			foreach ( array( 'class-whitelist-cli.php', 'class-block-cli.php', 'class-status-cli.php' ) as $file ) {
				$this->assertStringContainsString(
					"includes/{$file}",
					$bootstrap,
					"{$file} must be required from the WP_CLI bootstrap block."
				);
			}
		}

		/**
		 * `block` must warn when report-only mode swallows the enforcement.
		 */
		public function test_block_surfaces_report_only_mode_as_warning(): void {
			$source = $this->source( 'includes/class-block-cli.php' );

			$this->assertStringContainsString( 'reportedip_hive_report_only_mode', $source );
			$this->assertStringContainsString(
				'WP_CLI::warning',
				$source,
				'A report-only "block" is logged but not enforced — the command must warn, not report plain success.'
			);
		}

		/**
		 * `unblock` must offer --reset-attempts and hint at it otherwise.
		 */
		public function test_unblock_handles_reset_attempts_flag(): void {
			$source = $this->source( 'includes/class-block-cli.php' );

			$this->assertStringContainsString( "isset( \$assoc_args['reset-attempts'] )", $source );
			$this->assertStringContainsString(
				'reset_attempt_counter',
				$source,
				'--reset-attempts must clear the per-IP counters, or a still-exceeded threshold re-blocks immediately.'
			);
		}

		/**
		 * List-style commands must document and honour --format.
		 */
		public function test_list_commands_honour_format(): void {
			foreach ( array( 'includes/class-whitelist-cli.php', 'includes/class-block-cli.php', 'includes/class-status-cli.php' ) as $file ) {
				$source = $this->source( $file );

				$this->assertStringContainsString( '[--format=<format>]', $source, "$file must document --format." );
				$this->assertStringContainsString( "\$assoc_args['format']", $source, "$file must honour --format." );
				$this->assertStringContainsString( 'format_items', $source, "$file must render via format_items()." );
			}
		}

		/**
		 * CLI files must guard against non-CLI loads.
		 */
		public function test_cli_files_carry_both_guards(): void {
			foreach ( array( 'includes/class-whitelist-cli.php', 'includes/class-block-cli.php', 'includes/class-status-cli.php' ) as $file ) {
				$source = $this->source( $file );

				$this->assertStringContainsString( "if ( ! defined( 'ABSPATH' ) )", $source, "$file must guard ABSPATH." );
				$this->assertStringContainsString( "if ( ! defined( 'WP_CLI' ) || ! WP_CLI )", $source, "$file must return outside WP-CLI." );
			}
		}
	}
}
