<?php
/**
 * JSON response doubles: wp_send_json_success() and wp_send_json_error()
 * throw ReportedIP_Hive_Test_Json_Response, so an AJAX handler stops where
 * WordPress would exit and the test can read the payload. Shared by the
 * two-factor runtime stubs and the add-on test bootstrap.
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
