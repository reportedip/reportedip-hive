<?php
/**
 * Unit Tests for User-Enumeration login-error normalisation.
 *
 * Login-error filtering is the only path in ReportedIP_Hive_User_Enumeration
 * that runs without WordPress runtime context — the rest hooks into REST
 * dispatch / template_redirect and is exercised by integration tests.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.2.0
 */

namespace {

	if ( ! function_exists( 'add_action' ) ) {
		function add_action( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'add_filter' ) ) {
		function add_filter( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'apply_filters' ) ) {
		function apply_filters( $hook, $value, ...$args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return $value;
		}
	}
	if ( ! function_exists( 'wp_unslash' ) ) {
		function wp_unslash( $value ) {
			return is_string( $value ) ? stripslashes( $value ) : $value;
		}
	}
	if ( ! function_exists( 'sanitize_text_field' ) ) {
		function sanitize_text_field( $str ) {
			return is_string( $str ) ? trim( $str ) : '';
		}
	}
	if ( ! function_exists( '__' ) ) {
		function __( $text, $domain = '' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return $text;
		}
	}
	if ( ! function_exists( 'is_user_logged_in' ) ) {
		function is_user_logged_in() {
			return false;
		}
	}
	if ( ! function_exists( 'str_starts_with' ) ) {
		function str_starts_with( $haystack, $needle ) {
			return '' === $needle || 0 === strncmp( (string) $haystack, (string) $needle, strlen( (string) $needle ) );
		}
	}

	if ( ! class_exists( 'WP_Error' ) ) {
		class WP_Error {
			private $errors = array();
			public function __construct( $code = '', $message = '', $data = '' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				if ( '' !== $code ) {
					$this->errors[ $code ] = array( $message );
				}
			}
			public function get_error_code() {
				$keys = array_keys( $this->errors );
				return $keys ? $keys[0] : '';
			}
			public function get_error_message() {
				$code = $this->get_error_code();
				return $code ? $this->errors[ $code ][0] : '';
			}
			public function add( $code, $message ) {
				$this->errors[ $code ][] = $message;
			}
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-user-enumeration.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use WP_Error;

	class UserEnumerationTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options'] = array(
				'reportedip_hive_block_user_enumeration' => true,
			);
		}

		public function test_invalid_username_error_is_masked() {
			$instance = \ReportedIP_Hive_User_Enumeration::get_instance();
			$err      = new WP_Error( 'invalid_username', 'No such user' );
			$result   = $instance->unify_login_error_codes( $err, 'someone', 'pw' );
			$this->assertInstanceOf( WP_Error::class, $result );
			$this->assertSame( 'invalid_credentials', $result->get_error_code() );
		}

		public function test_incorrect_password_error_is_masked() {
			$instance = \ReportedIP_Hive_User_Enumeration::get_instance();
			$err      = new WP_Error( 'incorrect_password', 'Wrong password' );
			$result   = $instance->unify_login_error_codes( $err, 'someone', 'pw' );
			$this->assertSame( 'invalid_credentials', $result->get_error_code() );
		}

		public function test_other_error_codes_pass_through() {
			$instance = \ReportedIP_Hive_User_Enumeration::get_instance();
			$err      = new WP_Error( 'some_other_error', 'Whatever' );
			$result   = $instance->unify_login_error_codes( $err, 'someone', 'pw' );
			$this->assertSame( 'some_other_error', $result->get_error_code(), 'Codes outside the leaky-set must remain untouched' );
		}

		public function test_normalize_login_errors_replaces_message() {
			$instance = \ReportedIP_Hive_User_Enumeration::get_instance();
			$result   = $instance->normalize_login_errors( '<strong>ERROR</strong>: The username does not exist.' );
			$this->assertSame( 'Invalid credentials.', $result );
		}

		public function test_normalize_login_errors_passes_empty_through() {
			$instance = \ReportedIP_Hive_User_Enumeration::get_instance();
			$this->assertSame( '', $instance->normalize_login_errors( '' ) );
		}

		public function test_disabled_setting_disables_masking() {
			$GLOBALS['wp_options']['reportedip_hive_block_user_enumeration'] = false;
			$instance = \ReportedIP_Hive_User_Enumeration::get_instance();
			$err      = new WP_Error( 'invalid_username', 'Verbatim' );
			$result   = $instance->unify_login_error_codes( $err, 'someone', 'pw' );
			$this->assertSame( 'invalid_username', $result->get_error_code(), 'When disabled, error codes are unchanged' );
		}

		public function test_strip_author_from_oembed_removes_fields() {
			$instance = \ReportedIP_Hive_User_Enumeration::get_instance();
			$data     = array(
				'title'       => 'Hello',
				'author_name' => 'Alice',
				'author_url'  => 'https://example.org/author/alice',
			);
			$result   = $instance->strip_author_from_oembed( $data );
			$this->assertSame( 'Hello', $result['title'], 'Non-author fields stay intact' );
			$this->assertArrayNotHasKey( 'author_name', $result );
			$this->assertArrayNotHasKey( 'author_url', $result );
		}
	}
}
