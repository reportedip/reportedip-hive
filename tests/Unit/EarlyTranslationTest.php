<?php
/**
 * Guards against translating before `init`.
 *
 * WordPress 6.7 refuses to load a text domain before the `init` action and
 * raises a `_doing_it_wrong` notice instead. With `WP_DEBUG_DISPLAY` on, that
 * notice is printed before any header, so the canonical redirect that follows
 * fails with "headers already sent" and every front-end request renders as a
 * blank page. It surfaced the moment the development stack moved to 7.1: the
 * settings registry was read from the plugin constructor, and reading it
 * translates every label.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.53
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Source-level guard on the bootstrap.
	 */
	class EarlyTranslationTest extends TestCase {

		/**
		 * The body of `init_hooks()` in the main plugin file.
		 *
		 * @return string
		 */
		private function init_hooks_body(): string {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );
			$start  = strpos( $source, 'private function init_hooks()' );

			$this->assertNotFalse( $start, 'init_hooks() not found.' );

			$end = strpos( $source, "\n\t}\n", (int) $start );

			return substr( $source, (int) $start, (int) $end - (int) $start );
		}

		/**
		 * `Settings_Effects::init()` reads the registry, and the registry
		 * translates. It must be deferred to `init`, never called directly
		 * from the constructor path.
		 */
		public function test_settings_effects_are_registered_on_init(): void {
			$body = $this->init_hooks_body();

			$this->assertStringNotContainsString( 'ReportedIP_Hive_Settings_Effects::init();', $body );
			$this->assertStringContainsString(
				"add_action( 'init', array( 'ReportedIP_Hive_Settings_Effects', 'init' ), 0 );",
				$body
			);
		}

		/**
		 * Nothing in the constructor path may read the registry directly.
		 * Every `spec()` consumer that runs at load time inherits the same
		 * fault.
		 */
		public function test_the_constructor_path_never_reads_the_registry(): void {
			$body = $this->init_hooks_body();

			$this->assertStringNotContainsString( 'Settings_Registry::spec()', $body );
			$this->assertStringNotContainsString( 'Settings_Registry::remote_spec()', $body );
		}
	}
}
