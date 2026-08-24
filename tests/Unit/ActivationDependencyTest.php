<?php
/**
 * Unit tests for the class list the activation hook loads before rebaking.
 *
 * Activation runs outside the normal bootstrap: only the files listed inside
 * `activate_plugin_static()` are available. A class the guard bake reaches for
 * but the list omits turns activation into a fatal error, which is exactly how
 * 2.1.45 broke network activation on installs with the drop-in enabled.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.46
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * Guards the activation-time require list against the guard bake.
 *
 * @since 2.1.46
 */
class ActivationDependencyTest extends TestCase {

	/**
	 * Every plugin class the drop-in manager touches while generating the
	 * guard must be loadable from the activation path.
	 *
	 * @return void
	 */
	public function test_activation_loads_every_class_the_guard_bake_uses() {
		$plugin  = (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );
		$manager = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-waf-dropin-manager.php' );

		$this->assertSame(
			1,
			preg_match( '/public static function activate_plugin\(.*?\n\t\}/s', $plugin, $activation ),
			'activate_plugin() could not be located in the plugin bootstrap.'
		);
		$this->assertStringContainsString(
			"'includes/class-proxy-trust.php'",
			$activation[0],
			'Activation rebakes the guard without loading the trusted-proxy parser.'
		);
		$loaded = array();
		preg_match_all( "#'includes/([a-z0-9-]+)\.php'#", $activation[0], $files );
		foreach ( $files[1] as $slug ) {
			$loaded[] = str_replace( '-', '_', preg_replace( '/^class-/', '', $slug ) );
		}

		$this->assertSame(
			1,
			preg_match( '/private function generate_prepend\(\).*?\n\t\}/s', $manager, $bake ),
			'generate_prepend() could not be located in the drop-in manager.'
		);
		preg_match_all( '/ReportedIP_Hive_([A-Za-z_]+)::/', $bake[0], $used );

		$missing = array();
		foreach ( array_unique( $used[1] ) as $class ) {
			$slug = strtolower( $class );
			if ( in_array( $slug, array( 'waf_dropin_manager' ), true ) ) {
				continue;
			}
			foreach ( $loaded as $available ) {
				if ( $available === $slug ) {
					continue 2;
				}
			}
			$missing[] = 'ReportedIP_Hive_' . $class;
		}

		$this->assertSame(
			array(),
			$missing,
			'Activation would fatal: the guard bake uses ' . implode( ', ', $missing ) . ' without loading it.'
		);
	}
}
