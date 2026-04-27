<?php
/**
 * seven.io (formerly sms77) provider adapter.
 *
 * Endpoint:     https://gateway.seven.io/api/sms
 * Auth header:  X-Api-Key
 * Region:       Germany (Köln)
 * AVV:          https://www.seven.io/agb
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

class ReportedIP_Hive_SMS_Provider_Sevenio implements ReportedIP_Hive_SMS_Provider {

	public static function id() {
		return 'sevenio';
	}

	public static function display_name() {
		return 'seven.io';
	}

	public static function region() {
		return __( 'Germany (Cologne)', 'reportedip-hive' );
	}

	public static function avv_url() {
		return 'https://www.seven.io/agb';
	}

	public static function config_fields() {
		return array(
			'api_key' => array(
				'label'    => __( 'API key', 'reportedip-hive' ),
				'type'     => 'password',
				'required' => true,
				'help'     => __( 'From the seven.io dashboard under Settings → API.', 'reportedip-hive' ),
			),
			'from'    => array(
				'label'    => __( 'Sender (max. 11 alphanumeric characters, or E.164 number)', 'reportedip-hive' ),
				'type'     => 'text',
				'required' => true,
				'help'     => __( 'Example: "MySite" or "+491510000000".', 'reportedip-hive' ),
			),
		);
	}

	public static function send( $phone, $message, $config ) {
		$api_key = isset( $config['api_key'] ) ? (string) $config['api_key'] : '';
		$from    = isset( $config['from'] ) ? (string) $config['from'] : '';
		if ( '' === $api_key || '' === $from ) {
			return new WP_Error( 'reportedip_sms_config', __( 'seven.io: API key or sender is missing.', 'reportedip-hive' ) );
		}

		$response = wp_remote_post(
			'https://gateway.seven.io/api/sms',
			array(
				'timeout'     => 15,
				'headers'     => array(
					'X-Api-Key'    => $api_key,
					'Content-Type' => 'application/x-www-form-urlencoded',
					'Accept'       => 'application/json',
					'SentWith'     => 'reportedip-hive',
				),
				'body'        => array(
					'to'   => $phone,
					'from' => $from,
					'text' => $message,
					'json' => '1',
				),
				'redirection' => 0,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( $code >= 400 ) {
			return new WP_Error(
				'reportedip_sms_http_' . $code,
				sprintf( /* translators: %d: HTTP status */ __( 'seven.io error (HTTP %d).', 'reportedip-hive' ), $code )
			);
		}

		$success_code = isset( $data['success'] ) ? (string) $data['success'] : '';
		if ( '100' !== $success_code && '101' !== $success_code ) {
			return new WP_Error(
				'reportedip_sms_api_' . $success_code,
				sprintf( /* translators: %s: provider status code */ __( 'seven.io API rejected the send (code %s).', 'reportedip-hive' ), $success_code )
			);
		}

		return true;
	}
}
