<?php
/**
 * PHPStan bootstrap file.
 *
 * Defines plugin and WordPress runtime constants that PHPStan's static scan
 * cannot resolve from `define()` calls in the main plugin file. Values are
 * sentinels — only the symbol existence matters for analysis.
 *
 * Lives outside the plugin folder so the WordPress.org Plugin Check does not
 * scan it as production code. Loaded by PHPStan via phpstan.neon's
 * `bootstrapFiles: ../phpstan-bootstrap.php`.
 *
 * @package ReportedIP_Hive
 */

namespace {
	defined( 'REPORTEDIP_HIVE_VERSION' ) || define( 'REPORTEDIP_HIVE_VERSION', '0.0.0-dev' );
	defined( 'REPORTEDIP_HIVE_PLUGIN_DIR' ) || define( 'REPORTEDIP_HIVE_PLUGIN_DIR', __DIR__ . '/' );
	defined( 'REPORTEDIP_HIVE_PLUGIN_URL' ) || define( 'REPORTEDIP_HIVE_PLUGIN_URL', 'https://example.test/wp-content/plugins/reportedip-hive/' );
	defined( 'REPORTEDIP_HIVE_PLUGIN_FILE' ) || define( 'REPORTEDIP_HIVE_PLUGIN_FILE', __DIR__ . '/reportedip-hive.php' );
	defined( 'REPORTEDIP_HIVE_PLUGIN_BASENAME' ) || define( 'REPORTEDIP_HIVE_PLUGIN_BASENAME', 'reportedip-hive/reportedip-hive.php' );
	defined( 'REPORTEDIP_HIVE_LANGUAGES_DIR' ) || define( 'REPORTEDIP_HIVE_LANGUAGES_DIR', __DIR__ . '/languages' );
	defined( 'REPORTEDIP_USER_AGENT_MAX_LENGTH' ) || define( 'REPORTEDIP_USER_AGENT_MAX_LENGTH', 50 );
	defined( 'REPORTEDIP_QUEUE_BATCH_SIZE' ) || define( 'REPORTEDIP_QUEUE_BATCH_SIZE', 20 );
	defined( 'REPORTEDIP_MAX_CSV_UPLOAD_SIZE' ) || define( 'REPORTEDIP_MAX_CSV_UPLOAD_SIZE', 1048576 );

	defined( 'COOKIEPATH' ) || define( 'COOKIEPATH', '/' );
	defined( 'COOKIE_DOMAIN' ) || define( 'COOKIE_DOMAIN', '' );
	defined( 'SITECOOKIEPATH' ) || define( 'SITECOOKIEPATH', '/' );
	defined( 'ADMIN_COOKIE_PATH' ) || define( 'ADMIN_COOKIE_PATH', '/wp-admin' );
	defined( 'PLUGINS_COOKIE_PATH' ) || define( 'PLUGINS_COOKIE_PATH', '/wp-content/plugins' );
}

namespace WP_CLI\Utils {
	if ( ! function_exists( 'WP_CLI\\Utils\\format_items' ) ) {
		/**
		 * @param string                            $format Output format (table, csv, yaml, json).
		 * @param array<int, array<string, mixed>>  $items  Rows to display.
		 * @param array<int, string>|string         $fields Field names.
		 * @return void
		 */
		function format_items( $format, $items, $fields ) {}
	}
}
