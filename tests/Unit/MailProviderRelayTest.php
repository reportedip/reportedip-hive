<?php
/**
 * Unit tests for ReportedIP_Hive_Mail_Provider_Relay.
 *
 * Locks down the relay → fallback contract: success path returns true,
 * HTTP 402 (cap) and HTTP 429 (backoff) trigger the WordPress fallback,
 * Reply-To is hoisted out of the headers array into the payload, and
 * a missing API client also drops to fallback instead of erroring.
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
	if ( ! function_exists( 'apply_filters' ) ) {
		function apply_filters( $hook, $value, ...$args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return $value;
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/interface-mail-provider.php';

	if ( ! class_exists( 'ReportedIP_Hive_Mail_Provider_Stub' ) ) {
		class ReportedIP_Hive_Mail_Provider_Stub implements \ReportedIP_Hive_Mail_Provider_Interface {
			public $calls = array();
			public $return_value = true;
			public function get_name() { return 'stub'; }
			public function send( $to, $subject, $html_body, $plain_body, $headers ) {
				$this->calls[] = compact( 'to', 'subject', 'html_body', 'plain_body', 'headers' );
				return $this->return_value;
			}
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_API' ) ) {
		class ReportedIP_Hive_API {
			private static $instance = null;
			public $next_response = array( 'ok' => true );
			public $relay_mail_calls = array();

			public static function get_instance() {
				if ( null === self::$instance ) {
					self::$instance = new self();
				}
				return self::$instance;
			}
			public static function reset_instance() {
				self::$instance = null;
			}
			public function relay_mail( array $payload ) {
				$this->relay_mail_calls[] = $payload;
				return $this->next_response;
			}
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/mail-providers/class-mail-provider-relay.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class MailProviderRelayTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options'] = array();
			\ReportedIP_Hive_API::reset_instance();
		}

		private function make_provider(): array {
			$fallback = new \ReportedIP_Hive_Mail_Provider_Stub();
			$provider = new \ReportedIP_Hive_Mail_Provider_Relay( $fallback );
			return array( $provider, $fallback, \ReportedIP_Hive_API::get_instance() );
		}

		public function test_get_name_is_stable_identifier() {
			list( $provider ) = $this->make_provider();
			$this->assertSame( 'reportedip-relay', $provider->get_name() );
		}

		public function test_send_returns_true_on_relay_success() {
			list( $provider, $fallback, $api ) = $this->make_provider();
			$api->next_response = array( 'ok' => true );

			$result = $provider->send( 'a@b.test', 'Subj', '<p>html</p>', 'plain', array() );

			$this->assertTrue( $result );
			$this->assertCount( 1, $api->relay_mail_calls );
			$this->assertCount( 0, $fallback->calls, 'Fallback must not run on success.' );
		}

		public function test_send_payload_carries_recipient_subject_bodies_and_site_url() {
			list( $provider, , $api ) = $this->make_provider();
			$provider->send( 'a@b.test', 'Subj', '<p>html</p>', 'plain', array() );

			$payload = $api->relay_mail_calls[0];
			$this->assertSame( 'a@b.test', $payload['recipient'] );
			$this->assertSame( 'Subj', $payload['subject'] );
			$this->assertSame( 'plain', $payload['body_text'] );
			$this->assertSame( '<p>html</p>', $payload['body_html'] );
			$this->assertNotEmpty( $payload['site_url'] );
			$this->assertStringStartsWith( 'http', $payload['site_url'] );
		}

		public function test_send_402_falls_back_to_wordpress() {
			list( $provider, $fallback, $api ) = $this->make_provider();
			$api->next_response = array( 'ok' => false, 'status_code' => 402, 'error' => 'cap_reached' );

			$result = $provider->send( 'a@b.test', 'Subj', '<p>h</p>', 'p', array() );

			$this->assertTrue( $result, 'Fallback should report success when WP-mail succeeded.' );
			$this->assertCount( 1, $fallback->calls );
		}

		public function test_send_429_falls_back_to_wordpress() {
			list( $provider, $fallback, $api ) = $this->make_provider();
			$api->next_response = array( 'ok' => false, 'status_code' => 429, 'error' => 'backoff' );

			$provider->send( 'a@b.test', 'Subj', '<p>h</p>', 'p', array() );

			$this->assertCount( 1, $fallback->calls );
		}

		public function test_send_retryable_flag_falls_back() {
			list( $provider, $fallback, $api ) = $this->make_provider();
			$api->next_response = array( 'ok' => false, 'status_code' => 0, 'retryable' => true );

			$provider->send( 'a@b.test', 'Subj', '<p>h</p>', 'p', array() );

			$this->assertCount( 1, $fallback->calls, 'Network errors must fall back too.' );
		}

		public function test_send_400_returns_false_without_fallback() {
			list( $provider, $fallback, $api ) = $this->make_provider();
			$api->next_response = array( 'ok' => false, 'status_code' => 400, 'error' => 'bad_request' );

			$result = $provider->send( 'a@b.test', 'Subj', '<p>h</p>', 'p', array() );

			$this->assertFalse( $result );
			$this->assertCount( 0, $fallback->calls, '4xx other than 402/429 is a hard error, not a transient one.' );
		}

		public function test_reply_to_header_is_hoisted_into_payload_field() {
			list( $provider, , $api ) = $this->make_provider();
			$headers = array( 'From: test@example.test', 'Reply-To: human@example.test' );

			$provider->send( 'a@b.test', 'Subj', '<p>h</p>', 'p', $headers );

			$payload = $api->relay_mail_calls[0];
			$this->assertSame( 'human@example.test', $payload['reply_to'] );
			$this->assertArrayNotHasKey( 'Reply-To', $payload['headers'] );
			$this->assertSame( 'test@example.test', $payload['headers']['From'] );
		}

		public function test_default_reply_to_option_is_used_when_header_missing() {
			$GLOBALS['wp_options']['reportedip_hive_mail_reply_to'] = 'support@example.test';
			list( $provider, , $api ) = $this->make_provider();

			$provider->send( 'a@b.test', 'Subj', '<p>h</p>', 'p', array( 'From: t@example.test' ) );

			$payload = $api->relay_mail_calls[0];
			$this->assertSame( 'support@example.test', $payload['reply_to'] );
		}

		public function test_string_headers_are_split_per_line() {
			list( $provider, , $api ) = $this->make_provider();
			$provider->send( 'a@b.test', 'Subj', '<p>h</p>', 'p', "From: f@x.test\nX-Custom: y" );

			$payload = $api->relay_mail_calls[0];
			$this->assertSame( 'f@x.test', $payload['headers']['From'] );
			$this->assertSame( 'y', $payload['headers']['X-Custom'] );
		}
	}
}
