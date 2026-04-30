<?php
/**
 * ReportedIP Relay SMS provider.
 *
 * Routes SMS through the reportedip.de service-side relay (POST /relay-sms).
 * Activated automatically when the user runs in Community mode and the API key
 * belongs to a Professional/Business/Enterprise tier.
 *
 * Returns WP_Error when the relay rejects the request (HTTP 402 cap, HTTP 429
 * backoff, validation failure). The 2FA layer responds by encouraging the user
 * to choose another method (TOTP / Email / WebAuthn) — there is no SMS
 * fallback here, by design: silently switching to a local SMS provider would
 * surprise customers who specifically pay for relay routing.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.6.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ReportedIP_Hive_SMS_Provider_Relay implements ReportedIP_Hive_SMS_Provider {

	public static function id() {
		return 'reportedip_relay';
	}

	public static function display_name() {
		return __( 'ReportedIP Relay', 'reportedip-hive' );
	}

	public static function region() {
		return 'EU (via reportedip.de)';
	}

	public static function avv_url() {
		return defined( 'REPORTEDIP_HIVE_SITE_URL' )
			? trailingslashit( REPORTEDIP_HIVE_SITE_URL ) . 'legal/avv'
			: 'https://reportedip.de/legal/avv';
	}

	public static function config_fields() {
		// No provider-side config: authentication uses the existing API key.
		return array();
	}

	/**
	 * Send a 2FA code via template (client never renders the body).
	 *
	 * @param string $phone        E.164 phone number (must be EU).
	 * @param string $code         The verification code (digits only, 4–10 chars).
	 * @param int    $expiry_min   Minutes the code is valid for.
	 * @param string $lang         2-letter language code, defaults to site locale.
	 * @return true|WP_Error
	 */
	public static function send_code( $phone, $code, $expiry_min = 10, $lang = '' ) {
		if ( class_exists( 'ReportedIP_Hive_Phone_Validator' ) && ! ReportedIP_Hive_Phone_Validator::is_eu( $phone ) ) {
			return new WP_Error( 'reportedip_relay_not_eu', __( 'Only EU phone numbers are supported.', 'reportedip-hive' ) );
		}
		if ( ! class_exists( 'ReportedIP_Hive_API' ) ) {
			return new WP_Error( 'reportedip_relay_unavailable', __( 'API client not available.', 'reportedip-hive' ) );
		}
		if ( '' === $lang ) {
			$lang = substr( (string) get_locale(), 0, 2 );
		}
		$result = ReportedIP_Hive_API::get_instance()->relay_sms(
			array(
				'recipient_phone' => (string) $phone,
				'template_code'   => '2fa_login',
				'template_vars'   => array(
					'code'       => preg_replace( '/[^0-9]/', '', (string) $code ),
					'expiry_min' => (int) $expiry_min,
					'lang'       => $lang ?: 'en',
				),
				'site_url'        => home_url(),
			)
		);
		return self::interpret_result( $result );
	}

	public static function send( $phone, $message, $config ) {
		if ( class_exists( 'ReportedIP_Hive_Phone_Validator' ) ) {
			if ( ! ReportedIP_Hive_Phone_Validator::is_valid_e164( $phone ) ) {
				return new WP_Error( 'reportedip_relay_invalid_phone', __( 'Phone number is not in valid international format.', 'reportedip-hive' ) );
			}
			if ( ! ReportedIP_Hive_Phone_Validator::is_eu( $phone ) ) {
				return new WP_Error( 'reportedip_relay_not_eu', __( 'Only EU phone numbers are supported.', 'reportedip-hive' ) );
			}
		}

		if ( ! class_exists( 'ReportedIP_Hive_API' ) ) {
			return new WP_Error( 'reportedip_relay_unavailable', __( 'API client not available.', 'reportedip-hive' ) );
		}

		$api = ReportedIP_Hive_API::get_instance();
		if ( ! method_exists( $api, 'relay_sms' ) ) {
			return new WP_Error( 'reportedip_relay_unavailable', __( 'API client missing relay support.', 'reportedip-hive' ) );
		}

		$result = $api->relay_sms(
			array(
				'recipient_phone' => (string) $phone,
				'message'         => (string) $message,
				'site_url'        => home_url(),
			)
		);

		if ( ! empty( $result['ok'] ) ) {
			return true;
		}

		$status = (int) ( $result['status_code'] ?? 0 );

		if ( 402 === $status ) {
			return new WP_Error(
				'reportedip_relay_cap_reached',
				__( 'Your monthly SMS allowance is used up. Please upgrade your plan or choose another 2FA method.', 'reportedip-hive' ),
				array(
					'status_code' => 402,
					'retry_after' => (int) ( $result['retry_after'] ?? 0 ),
				)
			);
		}

		if ( 429 === $status ) {
			return new WP_Error(
				'reportedip_relay_backoff',
				__( 'Too many SMS sends to this recipient. Please wait before retrying.', 'reportedip-hive' ),
				array(
					'status_code' => 429,
					'retry_after' => (int) ( $result['retry_after'] ?? 0 ),
				)
			);
		}

		return new WP_Error(
			'reportedip_relay_failed',
			sprintf(
				/* translators: %s: error code from server */
				__( 'SMS relay failed (%s).', 'reportedip-hive' ),
				(string) ( $result['error'] ?? 'unknown' )
			),
			array( 'status_code' => $status )
		);
	}

	/**
	 * Translate the relay-API response into the contract return value.
	 *
	 * @param array $result Result from {@see ReportedIP_Hive_API::relay_sms()}.
	 * @return true|WP_Error
	 */
	private static function interpret_result( array $result ) {
		if ( ! empty( $result['ok'] ) ) {
			return true;
		}
		$status = (int) ( $result['status_code'] ?? 0 );
		if ( 402 === $status ) {
			return new WP_Error(
				'reportedip_relay_cap_reached',
				__( 'Your monthly SMS allowance is used up.', 'reportedip-hive' ),
				array(
					'status_code' => 402,
					'retry_after' => (int) ( $result['retry_after'] ?? 0 ),
				)
			);
		}
		if ( 429 === $status ) {
			return new WP_Error(
				'reportedip_relay_backoff',
				__( 'Too many SMS sends to this recipient.', 'reportedip-hive' ),
				array(
					'status_code' => 429,
					'retry_after' => (int) ( $result['retry_after'] ?? 0 ),
				)
			);
		}
		return new WP_Error(
			'reportedip_relay_failed',
			(string) ( $result['error'] ?? 'unknown' ),
			array( 'status_code' => $status )
		);
	}
}
