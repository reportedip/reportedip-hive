<?php
/**
 * ReportedIP Relay mail provider.
 *
 * Sends mails through the reportedip.de service-side relay (POST /relay-mail).
 * Tier-aware: only chosen by the Mailer when {@see ReportedIP_Hive_Mode_Manager::is_relay_available('mail')}
 * returns true (Community mode + Professional/Business/Enterprise tier).
 *
 * Falls back transparently to {@see ReportedIP_Hive_Mail_Provider_WordPress}
 * when the API replies HTTP 402 (monthly cap), HTTP 429 (recipient backoff or
 * site daily cap) or any network-level failure — the 2FA flow never breaks.
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

class ReportedIP_Hive_Mail_Provider_Relay implements ReportedIP_Hive_Mail_Provider_Interface {

	/**
	 * Local fallback used when the relay is unavailable.
	 *
	 * @var ReportedIP_Hive_Mail_Provider_Interface|null
	 */
	private $fallback;

	public function __construct( $fallback = null ) {
		if ( $fallback instanceof ReportedIP_Hive_Mail_Provider_Interface ) {
			$this->fallback = $fallback;
		} elseif ( class_exists( 'ReportedIP_Hive_Mail_Provider_WordPress' ) ) {
			$this->fallback = new ReportedIP_Hive_Mail_Provider_WordPress();
		}
	}

	public function get_name() {
		return 'reportedip-relay';
	}

	public function send( $to, $subject, $html_body, $plain_body, $headers ) {
		if ( ! class_exists( 'ReportedIP_Hive_API' ) ) {
			return $this->send_via_fallback( $to, $subject, $html_body, $plain_body, $headers );
		}

		$api = ReportedIP_Hive_API::get_instance();
		if ( ! method_exists( $api, 'relay_mail' ) ) {
			return $this->send_via_fallback( $to, $subject, $html_body, $plain_body, $headers );
		}

		$header_map = $this->headers_array_to_map( $headers );

		// Pull Reply-To (case-insensitive) out of the header map and pass it as a
		// dedicated payload field so the Service can prefer it over its own default.
		$reply_to = '';
		foreach ( $header_map as $hk => $hv ) {
			if ( is_string( $hk ) && strcasecmp( $hk, 'Reply-To' ) === 0 ) {
				$reply_to = (string) $hv;
				unset( $header_map[ $hk ] );
				break;
			}
		}
		// Allow sites to set a global Reply-To via filter/option without touching every send.
		if ( '' === $reply_to ) {
			$default_reply_to = (string) get_option( 'reportedip_hive_mail_reply_to', '' );
			$default_reply_to = (string) apply_filters( 'reportedip_hive_mail_reply_to', $default_reply_to, $to, $subject );
			if ( '' !== $default_reply_to ) {
				$reply_to = $default_reply_to;
			}
		}

		$payload = array(
			'recipient' => (string) $to,
			'subject'   => (string) $subject,
			'body_text' => (string) $plain_body,
			'body_html' => (string) $html_body,
			'headers'   => $header_map,
			'site_url'  => home_url(),
		);
		if ( '' !== $reply_to ) {
			$payload['reply_to'] = $reply_to;
		}

		$result = $api->relay_mail( $payload );

		if ( ! empty( $result['ok'] ) ) {
			return true;
		}

		$status = (int) ( $result['status_code'] ?? 0 );
		if ( in_array( $status, array( 402, 429 ), true ) || ! empty( $result['retryable'] ) ) {
			$this->log_fallback( $status, (string) ( $result['error'] ?? '' ) );
			return $this->send_via_fallback( $to, $subject, $html_body, $plain_body, $headers );
		}

		return false;
	}

	private function send_via_fallback( $to, $subject, $html_body, $plain_body, $headers ) {
		if ( $this->fallback instanceof ReportedIP_Hive_Mail_Provider_Interface ) {
			return (bool) $this->fallback->send( $to, $subject, $html_body, $plain_body, $headers );
		}
		return false;
	}

	/**
	 * Convert a flat headers list ('Name: value') into a map for the JSON payload.
	 *
	 * @param string[]|string $headers
	 * @return array<string,string>
	 */
	private function headers_array_to_map( $headers ) {
		$map = array();
		if ( is_string( $headers ) ) {
			$headers = explode( "\n", $headers );
		}
		if ( ! is_array( $headers ) ) {
			return $map;
		}
		foreach ( $headers as $line ) {
			if ( ! is_string( $line ) || false === strpos( $line, ':' ) ) {
				continue;
			}
			list( $name, $value ) = array_map( 'trim', explode( ':', $line, 2 ) );
			if ( '' === $name ) {
				continue;
			}
			$map[ $name ] = $value;
		}
		return $map;
	}

	private function log_fallback( $status, $error ) {
		if ( ! class_exists( 'ReportedIP_Hive_Logger' ) ) {
			return;
		}
		$logger = ReportedIP_Hive_Logger::get_instance();
		if ( ! $logger || ! method_exists( $logger, 'log' ) ) {
			return;
		}
		$ip = class_exists( 'ReportedIP_Hive' ) && method_exists( 'ReportedIP_Hive', 'get_client_ip' )
			? (string) ReportedIP_Hive::get_client_ip()
			: '';
		$logger->log(
			'mail_relay_fallback',
			$ip,
			'low',
			array(
				'status' => (int) $status,
				'error'  => (string) $error,
			)
		);
	}
}
