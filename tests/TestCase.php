<?php
/**
 * Base Test Case for ReportedIP Hive Tests.
 *
 * Provides common functionality for all test classes.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.0.0
 */

namespace ReportedIP\Hive\Tests;

use PHPUnit\Framework\TestCase as PHPUnitTestCase;
use Yoast\PHPUnitPolyfills\TestCases\TestCase as PolyfillTestCase;

/**
 * Base test case class that provides common functionality for all tests.
 */
class TestCase extends PolyfillTestCase {

	/**
	 * Mocked options storage for unit tests.
	 *
	 * @var array
	 */
	protected static $mocked_options = array();

	/**
	 * Mocked transients storage for unit tests.
	 *
	 * @var array
	 */
	protected static $mocked_transients = array();

	/**
	 * Set up before each test.
	 */
	protected function set_up() {
		parent::set_up();

		self::$mocked_options    = array();
		self::$mocked_transients = array();
	}

	/**
	 * Tear down after each test.
	 */
	protected function tear_down() {
		parent::tear_down();

		self::$mocked_options    = array();
		self::$mocked_transients = array();
	}

	/**
	 * Set a mocked option value (for unit tests without WordPress).
	 *
	 * @param string $option  Option name.
	 * @param mixed  $value   Option value.
	 */
	protected function set_mocked_option( $option, $value ) {
		self::$mocked_options[ $option ] = $value;
	}

	/**
	 * Get a mocked option value.
	 *
	 * @param string $option  Option name.
	 * @param mixed  $default Default value.
	 * @return mixed
	 */
	protected function get_mocked_option( $option, $default = false ) {
		return isset( self::$mocked_options[ $option ] ) ? self::$mocked_options[ $option ] : $default;
	}

	/**
	 * Set a mocked transient value.
	 *
	 * @param string $transient Transient name.
	 * @param mixed  $value     Transient value.
	 * @param int    $expiration Expiration in seconds.
	 */
	protected function set_mocked_transient( $transient, $value, $expiration = 0 ) {
		self::$mocked_transients[ $transient ] = array(
			'value'   => $value,
			'expires' => $expiration > 0 ? time() + $expiration : 0,
		);
	}

	/**
	 * Get a mocked transient value.
	 *
	 * @param string $transient Transient name.
	 * @return mixed|false
	 */
	protected function get_mocked_transient( $transient ) {
		if ( ! isset( self::$mocked_transients[ $transient ] ) ) {
			return false;
		}

		$data = self::$mocked_transients[ $transient ];

		if ( $data['expires'] > 0 && $data['expires'] < time() ) {
			unset( self::$mocked_transients[ $transient ] );
			return false;
		}

		return $data['value'];
	}

	/**
	 * Assert that a string contains another string.
	 *
	 * @param string $needle   String to search for.
	 * @param string $haystack String to search in.
	 * @param string $message  Optional message.
	 */
	protected function assertStringContainsStringCustom( $needle, $haystack, $message = '' ) {
		$this->assertStringContainsString( $needle, $haystack, $message );
	}

	/**
	 * Get a sample valid IP address for testing.
	 *
	 * @param string $type Type of IP ('ipv4', 'ipv6', 'private', 'localhost').
	 * @return string
	 */
	protected function get_sample_ip( $type = 'ipv4' ) {
		$ips = array(
			'ipv4'      => '8.8.8.8',
			'ipv6'      => '2001:4860:4860::8888',
			'private'   => '192.168.1.1',
			'localhost' => '127.0.0.1',
			'cidr_v4'   => '192.168.0.0/24',
			'cidr_v6'   => '2001:db8::/32',
			'malicious' => '185.220.101.1',
		);

		return isset( $ips[ $type ] ) ? $ips[ $type ] : $ips['ipv4'];
	}

	/**
	 * Get sample reputation data for testing.
	 *
	 * @param int $confidence_score Confidence percentage.
	 * @return array
	 */
	protected function get_sample_reputation_data( $confidence_score = 50 ) {
		return array(
			'ip_address'                 => '8.8.8.8',
			'is_public'                  => true,
			'abuse_confidence_percentage' => $confidence_score,
			'abuseConfidencePercentage'  => $confidence_score,
			'total_reports'              => 5,
			'totalReports'               => 5,
			'last_reported_at'           => gmdate( 'Y-m-d H:i:s', strtotime( '-1 day' ) ),
			'country_code'               => 'US',
			'countryCode'                => 'US',
			'isp'                        => 'Google LLC',
			'domain'                     => 'google.com',
			'usage_type'                 => 'Data Center/Web Hosting/Transit',
			'asn'                        => 15169,
			'threat_categories'          => array( 'dns_poisoning' ),
		);
	}

	/**
	 * Create a mock for a WordPress hook.
	 *
	 * @param string   $hook_name Hook name.
	 * @param callable $callback  Callback function.
	 * @param int      $priority  Priority.
	 * @param int      $args      Number of arguments.
	 */
	protected function mock_add_action( $hook_name, $callback, $priority = 10, $args = 1 ) {
		global $mocked_actions;
		if ( ! isset( $mocked_actions ) ) {
			$mocked_actions = array();
		}
		$mocked_actions[ $hook_name ][] = array(
			'callback' => $callback,
			'priority' => $priority,
			'args'     => $args,
		);
	}

	/**
	 * Trigger a mocked action hook.
	 *
	 * @param string $hook_name Hook name.
	 * @param mixed  ...$args   Arguments to pass.
	 */
	protected function do_mocked_action( $hook_name, ...$args ) {
		global $mocked_actions;
		if ( ! isset( $mocked_actions[ $hook_name ] ) ) {
			return;
		}

		foreach ( $mocked_actions[ $hook_name ] as $action ) {
			call_user_func_array( $action['callback'], array_slice( $args, 0, $action['args'] ) );
		}
	}
}
