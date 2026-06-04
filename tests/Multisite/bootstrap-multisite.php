<?php
/**
 * PHPUnit bootstrap for the ReportedIP Hive Multisite test suite.
 *
 * Mirrors `tests/bootstrap.php` but always runs the WordPress test framework
 * in network mode (`WP_TESTS_MULTISITE=1`). Tests in `tests/Multisite/`
 * therefore boot against a real `wp_*_options` / `wp_sitemeta` layout, which
 * exercises {@see ReportedIP_Hive_Option_Routing}, the schema layer and the
 * lifecycle hooks under their actual production constraints.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.0
 */

$autoloader = dirname( __DIR__, 2 ) . '/vendor/autoload.php';
if ( ! file_exists( $autoloader ) ) {
	echo 'Please run `composer install` before running tests.' . PHP_EOL;
	exit( 1 );
}
require_once $autoloader;

if ( ! defined( 'REPORTEDIP_HIVE_TESTING' ) ) {
	define( 'REPORTEDIP_HIVE_TESTING', true );
}

if ( ! defined( 'WP_TESTS_MULTISITE' ) ) {
	define( 'WP_TESTS_MULTISITE', 1 );
}
putenv( 'WP_TESTS_MULTISITE=1' );

$wp_tests_dir = getenv( 'WP_TESTS_DIR' );

if ( ! $wp_tests_dir ) {
	$possible_paths = array(
		'/tmp/wordpress-tests-lib',
		dirname( __DIR__, 2 ) . '/wordpress-tests-lib',
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
	echo 'WordPress test library not found. Run `bash scripts/install-wp-tests.sh wordpress_test_ms root \'\' 127.0.0.1 latest true` (the trailing `true` enables multisite) or set WP_TESTS_DIR.' . PHP_EOL;
	exit( 1 );
}

require_once $wp_tests_dir . '/includes/functions.php';

/**
 * Loads the plugin during the WordPress muplugins_loaded phase so the test
 * harness sees it as if it were installed network-wide.
 *
 * @return void
 */
function _reportedip_hive_load_plugin_for_multisite_tests() {
	$plugin_dir = dirname( __DIR__, 2 );
	require_once $plugin_dir . '/reportedip-hive.php';
}
tests_add_filter( 'muplugins_loaded', '_reportedip_hive_load_plugin_for_multisite_tests' );

require $wp_tests_dir . '/includes/bootstrap.php';

if ( file_exists( dirname( __DIR__ ) . '/TestCase.php' ) ) {
	require_once dirname( __DIR__ ) . '/TestCase.php';
}
