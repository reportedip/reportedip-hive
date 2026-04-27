<?php
/**
 * sipgate (Basic REST API) provider adapter.
 *
 * Endpoint:     https://api.sipgate.com/v2/sessions/sms
 * Auth:         HTTP Basic (personal access token ID + token)
 * Region:       Germany (Düsseldorf)
 * AVV:          https://www.sipgate.de/agb#auftragsverarbeitung
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.4.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ReportedIP_Hive_SMS_Provider_Sipgate implements ReportedIP_Hive_SMS_Provider {

	public static function id() {
		return 'sipgate';
	}

	public static function display_name() {
		return 'sipgate';
	}

	public static function region() {
		return __( 'Germany (Düsseldorf)', 'reportedip-hive' );
	}

	public static function avv_url() {
		return 'https://www.sipgate.de/agb#auftragsverarbeitung';
	}

	public static function config_fields() {
		return array(
			'token_id' => array(
				'label'    => __( 'Personal Access Token ID (token-xxxxx)', 'reportedip-hive' ),
				'type'     => 'text',
				'required' => true,
			),
			'token'    => array(
				'label'    => __( 'Personal Access Token', 'reportedip-hive' ),
				'type'     => 'password',
				'required' => true,
			),
			'sms_id'   => array(
				'label'    => __( 'SMS extension (e.g. s0)', 'reportedip-hive' ),
				'type'     => 'text',
				'required' => true,
				'help'     => __( 'The ID of your SMS extension from the sipgate team.', 'reportedip-hive' ),
			),
		);
	}

	public static function send( $phone, $message, $config ) {
		$token_id = isset( $config['token_id'] ) ? (string) $config['token_id'] : '';
		$token    = isset( $config['token'] ) ? (string) $config['token'] : '';
		$sms_id   = isset( $config['sms_id'] ) ? (string) $config['sms_id'] : '';
		if ( '' === $token_id || '' === $token || '' === $sms_id ) {
			return new WP_Error( 'reportedip_sms_config', __( 'sipgate: Token ID, token or SMS extension is missing.', 'reportedip-hive' ) );
		}

		$payload = wp_json_encode(
			array(
				'smsId'     => $sms_id,
				'recipient' => $phone,
				'message'   => $message,
			)
		);

		$response = wp_remote_post(
			'https://api.sipgate.com/v2/sessions/sms',
			array(
				'timeout'     => 15,
				'headers'     => array(
					'Authorization' => 'Basic ' . base64_encode( $token_id . ':' . $token ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- HTTP Basic Auth requires base64 encoding per RFC 7617.
					'Content-Type'  => 'application/json',
					'Accept'        => 'application/json',
				),
				'body'        => $payload,
				'redirection' => 0,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 204 === $code ) {
			return true;
		}
		$body = wp_remote_retrieve_body( $response );
		return new WP_Error(
			'reportedip_sms_http_' . $code,
			sprintf( /* translators: 1: HTTP status, 2: response body */ __( 'sipgate error (HTTP %1$d): %2$s', 'reportedip-hive' ), $code, wp_strip_all_tags( (string) $body ) )
		);
	}
}
