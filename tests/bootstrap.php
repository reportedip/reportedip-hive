<?php
/**
 * PHPUnit Bootstrap File for ReportedIP Hive Tests.
 *
 * This file sets up the testing environment for both unit and integration tests.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.0.0
 */

$autoloader = dirname( __DIR__ ) . '/vendor/autoload.php';
if ( ! file_exists( $autoloader ) ) {
	echo 'Please run `composer install` before running tests.' . PHP_EOL;
	exit( 1 );
}
require_once $autoloader;

if ( ! defined( 'REPORTEDIP_HIVE_TESTING' ) ) {
	define( 'REPORTEDIP_HIVE_TESTING', true );
}

if ( ! defined( 'REPORTEDIP_HIVE_VERSION' ) ) {
	define( 'REPORTEDIP_HIVE_VERSION', '1.0.0-test' );
}

/**
 * Determine if we're running unit tests or integration tests
 *
 * Unit tests don't need WordPress, integration tests do.
 */
$suite = getenv( 'WP_TESTS_SUITE' ) ?: 'unit';

if ( 'integration' === $suite ) {
	/**
	 * Integration Tests - Load WordPress Test Framework
	 */

	$wp_tests_dir = getenv( 'WP_TESTS_DIR' );

	if ( ! $wp_tests_dir ) {
		$possible_paths = array(
			'/tmp/wordpress-tests-lib',
			dirname( __DIR__ ) . '/wordpress-tests-lib',
			getenv( 'HOME' ) . '/wordpress-tests-lib',
			'/var/www/wordpress-tests-lib',
		);

		foreach ( $possible_paths as $path ) {
			if ( file_exists( $path . '/includes/functions.php' ) ) {
				$wp_tests_dir = $path;
				break;
			}
		}
	}

	if ( ! $wp_tests_dir ) {
		echo 'WordPress test library not found. Please run bin/install-wp-tests.sh or set WP_TESTS_DIR environment variable.' . PHP_EOL;
		echo 'For unit tests only, run: WP_TESTS_SUITE=unit phpunit' . PHP_EOL;
		exit( 1 );
	}

	require_once $wp_tests_dir . '/includes/functions.php';

	/**
	 * Manually load the plugin being tested.
	 */
	function _manually_load_plugin() {
		$plugin_dir = dirname( __DIR__ );

		require_once $plugin_dir . '/reportedip-hive.php';
	}
	tests_add_filter( 'muplugins_loaded', '_manually_load_plugin' );

	require $wp_tests_dir . '/includes/bootstrap.php';

} else {
	/**
	 * Unit Tests - Minimal WordPress Stubs
	 *
	 * For pure unit tests, we mock WordPress functions rather than loading the full framework.
	 */

	require_once __DIR__ . '/stubs/wordpress-stubs.php';

	$plugin_dir = dirname( __DIR__ );

	if ( ! defined( 'ABSPATH' ) ) {
		define( 'ABSPATH', $plugin_dir . '/' );
	}

	if ( ! defined( 'REPORTEDIP_HIVE_PLUGIN_DIR' ) ) {
		define( 'REPORTEDIP_HIVE_PLUGIN_DIR', $plugin_dir . '/' );
	}

	if ( ! defined( 'REPORTEDIP_HIVE_PLUGIN_URL' ) ) {
		define( 'REPORTEDIP_HIVE_PLUGIN_URL', 'http://example.org/wp-content/plugins/reportedip-hive/' );
	}

	if ( ! defined( 'REPORTEDIP_HIVE_PLUGIN_FILE' ) ) {
		define( 'REPORTEDIP_HIVE_PLUGIN_FILE', $plugin_dir . '/reportedip-hive.php' );
	}

	if ( ! defined( 'REPORTEDIP_HIVE_PLUGIN_BASENAME' ) ) {
		define( 'REPORTEDIP_HIVE_PLUGIN_BASENAME', 'reportedip-hive/reportedip-hive.php' );
	}
}

/**
 * Load test utilities
 */
require_once __DIR__ . '/TestCase.php';
