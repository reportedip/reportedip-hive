<?php
/**
 * Regression guard for how log details are rendered in the admin tables.
 *
 * Two shapes used to reach the operator unreadable: the rolling-window bucket
 * label (`rolling-60m-29421`), which a datetime formatter turned into
 * "1. January 1970", and Unix-timestamp values such as
 * `hardening_expires_at`, which were printed as a raw integer.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.30
 */

namespace {

	if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
		define( 'MINUTE_IN_SECONDS', 60 );
	}
	if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
		define( 'HOUR_IN_SECONDS', 3600 );
	}
	if ( ! defined( 'DAY_IN_SECONDS' ) ) {
		define( 'DAY_IN_SECONDS', 86400 );
	}
	if ( ! function_exists( 'wp_date' ) ) {
		function wp_date( $format, $timestamp = null, $timezone = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return gmdate( $format, null === $timestamp ? time() : (int) $timestamp );
		}
	}
	if ( ! function_exists( 'wp_json_encode' ) ) {
		function wp_json_encode( $data ) {
			return json_encode( $data ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Stub for the function under test.
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use ReflectionMethod;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class LogDetailRenderingTest extends TestCase {

		/**
		 * Invoke the private detail formatter with the real classes loaded.
		 *
		 * @param string $key   Detail key.
		 * @param mixed  $value Detail value.
		 * @return string
		 */
		private function render( $key, $value ) {
			require_once dirname( __DIR__, 2 ) . '/includes/class-hardening-mode.php';
			require_once dirname( __DIR__, 2 ) . '/includes/class-logger.php';

			$method = new ReflectionMethod( 'ReportedIP_Hive_Logger', 'format_detail_value' );

			return (string) $method->invoke( null, $key, $value );
		}

		public function test_rolling_window_label_is_rendered_as_a_timespan() {
			$output = $this->render( 'time_window', 'rolling-60m-29755200' );

			$this->assertStringNotContainsString( '1970', $output );
			$this->assertStringNotContainsString( 'rolling-', $output );
			$this->assertStringContainsString( 'rolling window', $output );
		}

		public function test_hardening_expiry_timestamp_is_rendered_as_a_date() {
			$output = $this->render( 'hardening_expires_at', 1785314321 );

			$this->assertStringNotContainsString( '1785314321', $output );
			$this->assertStringContainsString( '2026-07-29', $output );
		}

		public function test_zero_expiry_stays_verbatim() {
			$this->assertSame( '0', $this->render( 'hardening_expires_at', 0 ) );
		}

		public function test_unknown_keys_are_untouched() {
			$this->assertSame( '42', $this->render( 'unique_ips', 42 ) );
			$this->assertSame( 'multiple', $this->render( 'ip', 'multiple' ) );
		}

		public function test_arrays_are_json_encoded() {
			$this->assertSame( '{"attempts":6}', $this->render( 'threshold_details', array( 'attempts' => 6 ) ) );
		}
	}
}
