<?php
/**
 * MessageBird (now Bird) provider adapter.
 *
 * Endpoint:     https://rest.messagebird.com/messages
 * Auth header:  Authorization: AccessKey <key>
 * Region:       Netherlands (Amsterdam) — EU data centre
 * AVV:          https://messagebird.com/legal/dpa
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

class ReportedIP_Hive_SMS_Provider_MessageBird implements ReportedIP_Hive_SMS_Provider {

	public static function id() {
		return 'messagebird';
	}

	public static function display_name() {
		return 'MessageBird / Bird';
	}

	public static function region() {
		return __( 'Netherlands (Amsterdam) — EU data centre', 'reportedip-hive' );
	}

	public static function avv_url() {
		return 'https://messagebird.com/legal/dpa';
	}

	public static function config_fields() {
		return array(
			'access_key' => array(
				'label'    => __( 'Live Access Key', 'reportedip-hive' ),
				'type'     => 'password',
				'required' => true,
				'help'     => __( 'From the MessageBird dashboard under Developers → API access.', 'reportedip-hive' ),
			),
			'originator' => array(
				'label'    => __( 'Sender (originator, max. 11 alphanumeric characters or E.164 number)', 'reportedip-hive' ),
				'type'     => 'text',
				'required' => true,
			),
		);
	}

	public static function send( $phone, $message, $config ) {
		$access_key = isset( $config['access_key'] ) ? (string) $config['access_key'] : '';
		$originator = isset( $config['originator'] ) ? (string) $config['originator'] : '';
		if ( '' === $access_key || '' === $originator ) {
			return new WP_Error( 'reportedip_sms_config', __( 'MessageBird: Access Key or sender is missing.', 'reportedip-hive' ) );
		}

		$recipient = ltrim( $phone, '+' );

		$payload = wp_json_encode(
			array(
				'originator' => $originator,
				'recipients' => array( $recipient ),
				'body'       => $message,
				'datacoding' => 'auto',
			)
		);

		$response = wp_remote_post(
			'https://rest.messagebird.com/messages',
			array(
				'timeout'     => 15,
				'headers'     => array(
					'Authorization' => 'AccessKey ' . $access_key,
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
		$body = wp_remote_retrieve_body( $response );
		if ( 201 === $code ) {
			return true;
		}

		$data   = json_decode( $body, true );
		$reason = isset( $data['errors'][0]['description'] ) ? (string) $data['errors'][0]['description'] : wp_strip_all_tags( (string) $body );
		return new WP_Error(
			'reportedip_sms_http_' . $code,
			sprintf( /* translators: 1: HTTP status, 2: error reason */ __( 'MessageBird error (HTTP %1$d): %2$s', 'reportedip-hive' ), $code, $reason )
		);
	}
}
