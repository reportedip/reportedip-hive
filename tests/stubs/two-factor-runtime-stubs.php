<?php
/**
 * Runtime doubles for tests that drive the real two-factor classes
 * (ReportedIP_Hive_Two_Factor, the verifier, the reset gate) outside
 * WordPress. Every definition is guarded, so a test that brings its own
 * double keeps it. Load only from tests that run in a separate process.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Stubs
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

if ( ! defined( 'REPORTEDIP_HIVE_TESTING' ) ) {
	exit;
}

defined( 'COOKIEPATH' ) || define( 'COOKIEPATH', '/' );
defined( 'SITECOOKIEPATH' ) || define( 'SITECOOKIEPATH', '/' );
defined( 'COOKIE_DOMAIN' ) || define( 'COOKIE_DOMAIN', '' );
defined( 'DAY_IN_SECONDS' ) || define( 'DAY_IN_SECONDS', 86400 );
defined( 'YEAR_IN_SECONDS' ) || define( 'YEAR_IN_SECONDS', 31536000 );

if ( ! class_exists( 'ReportedIP_Hive_Test_Json_Response' ) ) {
	/**
	 * Thrown by the wp_send_json_* doubles, so a handler stops where
	 * WordPress would exit and the test can read the payload.
	 */
	class ReportedIP_Hive_Test_Json_Response extends RuntimeException {

		/**
		 * Whether the success variant was sent.
		 *
		 * @var bool
		 */
		public $success;

		/**
		 * Response payload.
		 *
		 * @var mixed
		 */
		public $data;

		/**
		 * HTTP status passed by the handler.
		 *
		 * @var int|null
		 */
		public $status;

		/**
		 * @param bool     $success Success flag.
		 * @param mixed    $data    Payload.
		 * @param int|null $status  HTTP status.
		 */
		public function __construct( $success, $data, $status = null ) {
			parent::__construct( $success ? 'json success' : 'json error' );
			$this->success = (bool) $success;
			$this->data    = $data;
			$this->status  = $status;
		}
	}
}

if ( ! function_exists( 'wp_send_json_success' ) ) {
	/**
	 * @param mixed    $data   Payload.
	 * @param int|null $status HTTP status.
	 * @throws ReportedIP_Hive_Test_Json_Response Always.
	 */
	function wp_send_json_success( $data = null, $status = null ) {
		throw new ReportedIP_Hive_Test_Json_Response( true, $data, $status );
	}
}

if ( ! function_exists( 'wp_send_json_error' ) ) {
	/**
	 * @param mixed    $data   Payload.
	 * @param int|null $status HTTP status.
	 * @throws ReportedIP_Hive_Test_Json_Response Always.
	 */
	function wp_send_json_error( $data = null, $status = null ) {
		throw new ReportedIP_Hive_Test_Json_Response( false, $data, $status );
	}
}

if ( ! function_exists( 'is_ssl' ) ) {
	/**
	 * @return bool
	 */
	function is_ssl() {
		return false;
	}
}

if ( ! function_exists( 'is_super_admin' ) ) {
	/**
	 * @param int $user_id User id.
	 * @return bool
	 */
	function is_super_admin( $user_id = 0 ) {
		unset( $user_id );
		return false;
	}
}

if ( ! function_exists( 'wp_login_url' ) ) {
	/**
	 * @return string
	 */
	function wp_login_url() {
		return 'http://example.org/wp-login.php';
	}
}

if ( ! function_exists( 'add_query_arg' ) ) {
	/**
	 * @param array<string, string> $args Query arguments.
	 * @param string                $url  Base URL.
	 * @return string
	 */
	function add_query_arg( $args, $url = '' ) {
		return $url . ( false === strpos( (string) $url, '?' ) ? '?' : '&' ) . http_build_query( (array) $args );
	}
}

if ( ! class_exists( 'WP_User' ) ) {
	/**
	 * Minimal user double.
	 */
	class WP_User {

		/**
		 * User id.
		 *
		 * @var int
		 */
		public $ID;

		/**
		 * Login name.
		 *
		 * @var string
		 */
		public $user_login = 'jane';

		/**
		 * Mail address.
		 *
		 * @var string
		 */
		public $user_email = 'jane@example.org';

		/**
		 * Display name.
		 *
		 * @var string
		 */
		public $display_name = 'Jane';

		/**
		 * Role slugs.
		 *
		 * @var string[]
		 */
		public $roles = array( 'subscriber' );

		/**
		 * @param int $id User id.
		 */
		public function __construct( $id = 0 ) {
			$this->ID = (int) $id;
		}
	}
}

if ( ! function_exists( 'get_userdata' ) ) {
	/**
	 * @param int $user_id User id.
	 * @return WP_User
	 */
	function get_userdata( $user_id ) {
		return new WP_User( (int) $user_id );
	}
}

if ( ! class_exists( 'ReportedIP_Hive' ) ) {
	/**
	 * Plugin double supplying the client IP.
	 */
	class ReportedIP_Hive {

		/**
		 * @return string
		 */
		public static function get_client_ip() {
			return '203.0.113.10';
		}

		/**
		 * @return void
		 */
		public static function emit_block_response_headers() {
		}
	}
}

if ( ! class_exists( 'ReportedIP_Hive_Logger' ) ) {
	/**
	 * Logger double recording every entry in $GLOBALS['rip_test_logs'].
	 */
	class ReportedIP_Hive_Logger {

		/**
		 * @return self
		 */
		public static function get_instance() {
			return new self();
		}

		/**
		 * @param string $name Method name (warning, info, log, log_security_event, ...).
		 * @param array  $args Arguments.
		 * @return bool
		 */
		public function __call( $name, $args ) {
			$GLOBALS['rip_test_logs'][] = array(
				'level' => $name,
				'args'  => $args,
			);
			return true;
		}
	}
}

if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Recovery' ) ) {
	/**
	 * Recovery double: remaining count and the accepted code come from globals.
	 */
	class ReportedIP_Hive_Two_Factor_Recovery {

		const META_KEY_CODES     = 'reportedip_hive_2fa_recovery_codes';
		const META_KEY_REMAINING = 'reportedip_hive_2fa_recovery_codes_remaining';

		/**
		 * @param int $user_id User id.
		 * @return int
		 */
		public static function get_remaining_count( $user_id ) {
			return (int) ( $GLOBALS['rip_test_recovery_remaining'][ $user_id ] ?? 0 );
		}

		/**
		 * @param int    $user_id User id.
		 * @param string $code    Submitted code.
		 * @return bool
		 */
		public static function verify_code( $user_id, $code ) {
			return isset( $GLOBALS['rip_test_recovery_code'][ $user_id ] ) && $GLOBALS['rip_test_recovery_code'][ $user_id ] === $code;
		}

		/**
		 * @param int $user_id User id.
		 * @return string[]
		 */
		public static function regenerate_codes( $user_id ) {
			$GLOBALS['rip_test_recovery_remaining'][ $user_id ] = 10;
			return array( 'aaaa-bbbb' );
		}

		/**
		 * @param int $user_id User id.
		 * @return void
		 */
		public static function delete_codes( $user_id ) {
			unset( $GLOBALS['rip_test_recovery_remaining'][ $user_id ] );
		}
	}
}

if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Policies' ) ) {
	/**
	 * Step-up double: no trigger fires.
	 */
	class ReportedIP_Hive_Two_Factor_Policies {

		const NO_METHOD_PREFIX = 'no_method:';

		/**
		 * @return string
		 */
		public static function evaluate() {
			return '';
		}
	}
}

if ( ! isset( $GLOBALS['wpdb'] ) ) {
	/**
	 * Database double for the trusted-device cleanup a full reset runs.
	 */
	$GLOBALS['wpdb'] = new class() {

		/**
		 * Network table prefix.
		 *
		 * @var string
		 */
		public $base_prefix = 'wp_';

		/**
		 * Site table prefix.
		 *
		 * @var string
		 */
		public $prefix = 'wp_';

		/**
		 * @return int Rows deleted.
		 */
		public function delete() {
			return 0;
		}
	};
}
