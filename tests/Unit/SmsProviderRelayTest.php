<?php
/**
 * Unit tests for ReportedIP_Hive_SMS_Provider_Relay.
 *
 * Locks down: EU-only validation, payload shape for the template-based
 * `send_code()` path, the freeform `send()` path, and HTTP 402 / 429 /
 * generic-error → WP_Error mapping.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.6.3
 */

namespace {

	if ( ! function_exists( 'home_url' ) ) {
		function home_url( $path = '' ) {
			return 'https://example.org' . $path;
		}
	}
	if ( ! function_exists( 'get_locale' ) ) {
		function get_locale() {
			return 'en_US';
		}
	}
	if ( ! function_exists( 'trailingslashit' ) ) {
		function trailingslashit( $string ) {
			return rtrim( (string) $string, '/\\' ) . '/';
		}
	}
	if ( ! function_exists( 'apply_filters' ) ) {
		function apply_filters( $hook, $value, ...$args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return $value;
		}
	}
	if ( ! defined( 'REPORTEDIP_HIVE_SITE_URL' ) ) {
		define( 'REPORTEDIP_HIVE_SITE_URL', 'https://reportedip.de' );
	}

	if ( ! class_exists( 'WP_Error' ) ) {
		class WP_Error {
			public $code;
			public $message;
			public $data;
			public function __construct( $code = '', $message = '', $data = array() ) {
				$this->code    = $code;
				$this->message = $message;
				$this->data    = $data;
			}
			public function get_error_code() { return $this->code; }
			public function get_error_message() { return $this->message; }
			public function get_error_data() { return $this->data; }
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-phone-validator.php';

	if ( ! interface_exists( 'ReportedIP_Hive_SMS_Provider' ) ) {
		interface ReportedIP_Hive_SMS_Provider {
			public static function id();
			public static function display_name();
			public static function region();
			public static function avv_url();
			public static function config_fields();
			public static function send( $phone, $message, $config );
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_API' ) ) {
		class ReportedIP_Hive_API {
			private static $instance       = null;
			public $next_response          = array( 'ok' => true );
			public $relay_sms_calls        = array();

			public static function get_instance() {
				if ( null === self::$instance ) {
					self::$instance = new self();
				}
				return self::$instance;
			}
			public static function reset_instance() {
				self::$instance = null;
			}
			public function relay_sms( array $payload ) {
				$this->relay_sms_calls[] = $payload;
				return $this->next_response;
			}
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/sms-providers/class-sms-provider-relay.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class SmsProviderRelayTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options'] = array();
			\ReportedIP_Hive_API::reset_instance();
		}

		public function test_static_metadata() {
			$this->assertSame( 'reportedip_relay', \ReportedIP_Hive_SMS_Provider_Relay::id() );
			$this->assertNotEmpty( \ReportedIP_Hive_SMS_Provider_Relay::display_name() );
			$this->assertSame( 'EU (via reportedip.de)', \ReportedIP_Hive_SMS_Provider_Relay::region() );
			$this->assertSame( array(), \ReportedIP_Hive_SMS_Provider_Relay::config_fields() );
			$this->assertStringStartsWith( 'https://', \ReportedIP_Hive_SMS_Provider_Relay::avv_url() );
		}

		public function test_send_code_rejects_non_eu_number_before_api_call() {
			$result = \ReportedIP_Hive_SMS_Provider_Relay::send_code( '+15551234567', '123456' );
			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'reportedip_relay_not_eu', $result->get_error_code() );
			$this->assertCount( 0, \ReportedIP_Hive_API::get_instance()->relay_sms_calls );
		}

		public function test_send_code_happy_path_returns_true_and_uses_template_route() {
			$result = \ReportedIP_Hive_SMS_Provider_Relay::send_code( '+491511234567', '123456', 5, 'de' );
			$this->assertTrue( $result );

			$payload = \ReportedIP_Hive_API::get_instance()->relay_sms_calls[0];
			$this->assertSame( '+491511234567', $payload['recipient_phone'] );
			$this->assertSame( '2fa_login', $payload['template_code'] );
			$this->assertSame( '123456', $payload['template_vars']['code'] );
			$this->assertSame( 5, $payload['template_vars']['expiry_min'] );
			$this->assertSame( 'de', $payload['template_vars']['lang'] );
			$this->assertArrayNotHasKey( 'message', $payload, 'Template route must NOT leak the rendered SMS body to the client.' );
		}

		public function test_send_code_strips_non_digit_chars_from_code() {
			\ReportedIP_Hive_SMS_Provider_Relay::send_code( '+491511234567', 'AB12-34', 10 );
			$payload = \ReportedIP_Hive_API::get_instance()->relay_sms_calls[0];
			$this->assertSame( '1234', $payload['template_vars']['code'] );
		}

		public function test_send_code_402_returns_cap_reached_error() {
			$api = \ReportedIP_Hive_API::get_instance();
			$api->next_response = array( 'ok' => false, 'status_code' => 402, 'retry_after' => 3600 );

			$result = \ReportedIP_Hive_SMS_Provider_Relay::send_code( '+491511234567', '111111' );

			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'reportedip_relay_cap_reached', $result->get_error_code() );
			$this->assertSame( 402, $result->get_error_data()['status_code'] );
			$this->assertSame( 3600, $result->get_error_data()['retry_after'] );
		}

		public function test_send_code_429_returns_backoff_error() {
			$api = \ReportedIP_Hive_API::get_instance();
			$api->next_response = array( 'ok' => false, 'status_code' => 429, 'retry_after' => 120 );

			$result = \ReportedIP_Hive_SMS_Provider_Relay::send_code( '+491511234567', '111111' );

			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'reportedip_relay_backoff', $result->get_error_code() );
		}

		public function test_send_code_generic_failure_returns_failed_error() {
			$api = \ReportedIP_Hive_API::get_instance();
			$api->next_response = array( 'ok' => false, 'status_code' => 500, 'error' => 'upstream_500' );

			$result = \ReportedIP_Hive_SMS_Provider_Relay::send_code( '+491511234567', '111111' );

			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'reportedip_relay_failed', $result->get_error_code() );
		}

		public function test_send_freeform_rejects_invalid_e164() {
			$result = \ReportedIP_Hive_SMS_Provider_Relay::send( '0151-1234567', 'hello', array() );
			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'reportedip_relay_invalid_phone', $result->get_error_code() );
		}

		public function test_send_freeform_happy_path() {
			$result = \ReportedIP_Hive_SMS_Provider_Relay::send( '+491511234567', 'plain message', array() );
			$this->assertTrue( $result );

			$payload = \ReportedIP_Hive_API::get_instance()->relay_sms_calls[0];
			$this->assertSame( '+491511234567', $payload['recipient_phone'] );
			$this->assertSame( 'plain message', $payload['message'] );
			$this->assertArrayNotHasKey( 'template_code', $payload );
		}
	}
}
