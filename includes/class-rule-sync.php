<?php
/**
 * Rule delivery framework — downloads, verifies and caches server-delivered
 * rulesets, and exposes them to the sensors.
 *
 * Sensor rules (WAF signatures, bot signatures, disposable domains, UA/scan
 * lists) are NOT hard-coded: reportedip.de serves versioned, Ed25519-signed,
 * tier-staggered rulesets; this class downloads them (ETag/304, size-capped),
 * verifies the detached signature against a bundled public-key set, stores the
 * result via {@see ReportedIP_Hive_Rule_Store}, and falls back to the bundled
 * baseline pack when there is no API key, no successful sync yet, or a
 * verification failure. The free baseline is a narrow floor; the value-adding
 * depth and freshness ship through the synced PRO+ ruleset.
 *
 * Signing follows the WordPress-core "signed updates" model: the private key
 * stays offline on the service, the public key is bundled here, and an unsigned
 * or tampered ruleset is never applied.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Server-delivered ruleset sync + signature verification.
 *
 * @since 2.2.0
 */
final class ReportedIP_Hive_Rule_Sync {

	/**
	 * Bundled Ed25519 public keys (base64), accepted for signature verification.
	 * `next` is reserved so a key rotation can ship before the service switches.
	 *
	 * @var array<string, string>
	 */
	const PUBLIC_KEYS = array(
		'current' => 'yS2qsbLsNNypVzLu9Z0Ughb5Rkpytk7cHqjJzYfKd+c=',
		'next'    => '',
	);

	/**
	 * Maximum accepted ruleset payload size (bytes); larger payloads are rejected.
	 */
	const MAX_PAYLOAD_BYTES = 524288;

	/**
	 * Site-transient that serialises sync runs (5-minute window).
	 */
	const SYNC_LOCK_TRANSIENT = 'reportedip_hive_rule_sync_lock';

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * @return self
	 * @since  2.2.0
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Return the active ruleset for a key: the stored (synced) copy when present,
	 * otherwise the bundled baseline. Always returns an array with a `rules` key.
	 *
	 * @param string $key Ruleset key.
	 * @return array<string, mixed>
	 * @since  2.2.0
	 */
	public function get_ruleset( $key ) {
		$stored = ReportedIP_Hive_Rule_Store::get( $key );
		if ( is_array( $stored ) && isset( $stored['rules'] ) && is_array( $stored['rules'] ) ) {
			return $stored;
		}
		return $this->load_baseline( $key );
	}

	/**
	 * Load the bundled baseline ruleset for a key.
	 *
	 * @param string $key Ruleset key.
	 * @return array<string, mixed>
	 * @since  2.2.0
	 */
	public function load_baseline( $key ) {
		$empty = array(
			'key'     => is_string( $key ) ? $key : '',
			'version' => 0,
			'rules'   => array(),
		);
		if ( ! ReportedIP_Hive_Rule_Store::is_valid_key( $key ) ) {
			return $empty;
		}
		$file = REPORTEDIP_HIVE_PLUGIN_DIR . 'data/rulesets/' . str_replace( '_', '-', $key ) . '-baseline.php';
		if ( ! file_exists( $file ) ) {
			return $empty;
		}
		$data = include $file;
		if ( is_array( $data ) && isset( $data['rules'] ) && is_array( $data['rules'] ) ) {
			return $data;
		}
		return $empty;
	}

	/**
	 * Accepted public keys (base64). Filterable so a key rotation or a test can
	 * inject additional keys without a code change.
	 *
	 * @return array<int|string, string>
	 * @since  2.2.0
	 */
	public function public_keys() {
		$keys = array_values(
			array_filter(
				self::PUBLIC_KEYS,
				static function ( $key ) {
					return '' !== $key;
				}
			)
		);
		/**
		 * Filter the accepted Ed25519 public keys (base64) for ruleset verification.
		 *
		 * @param array<int, string> $keys Base64-encoded public keys.
		 */
		$keys = apply_filters( 'reportedip_hive_rule_public_keys', $keys );
		return is_array( $keys ) ? $keys : array();
	}

	/**
	 * Verify a detached Ed25519 signature over the exact payload string against
	 * any accepted public key.
	 *
	 * @param string $payload       The exact signed payload string.
	 * @param string $signature_b64 Base64-encoded detached signature.
	 * @return bool True when the signature validates against an accepted key.
	 * @since  2.2.0
	 */
	public function verify_signature( $payload, $signature_b64 ) {
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			return false;
		}
		if ( ! is_string( $payload ) || ! is_string( $signature_b64 ) || '' === $signature_b64 ) {
			return false;
		}
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding a detached Ed25519 signature, not code.
		$sig = base64_decode( $signature_b64, true );
		if ( false === $sig || SODIUM_CRYPTO_SIGN_BYTES !== strlen( $sig ) ) {
			return false;
		}
		foreach ( $this->public_keys() as $pk_b64 ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding an Ed25519 public key, not code.
			$pk = base64_decode( (string) $pk_b64, true );
			if ( false === $pk || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $pk ) ) {
				continue;
			}
			if ( sodium_crypto_sign_verify_detached( $sig, $payload, $pk ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Validate a ruleset envelope and, if the signature checks out, store it.
	 *
	 * The envelope carries the exact signed `payload` string (canonical JSON of
	 * `{key, version, rules, …}`) plus its detached `signature`. Verifying the
	 * literal string and only then decoding it avoids any re-serialisation
	 * mismatch between client and server.
	 *
	 * @param string               $key      Expected ruleset key.
	 * @param array<string, mixed> $envelope Response envelope with `payload` + `signature`.
	 * @return bool True when the ruleset was verified and stored.
	 * @since  2.2.0
	 */
	public function apply_ruleset( $key, $envelope ) {
		if ( ! ReportedIP_Hive_Rule_Store::is_valid_key( $key ) || ! is_array( $envelope ) ) {
			return false;
		}
		$payload   = isset( $envelope['payload'] ) ? $envelope['payload'] : '';
		$signature = isset( $envelope['signature'] ) ? $envelope['signature'] : '';
		if ( ! is_string( $payload ) || strlen( $payload ) > self::MAX_PAYLOAD_BYTES ) {
			$this->log_signature_failure( $key, 'payload_too_large_or_invalid' );
			return false;
		}
		if ( ! $this->verify_signature( $payload, (string) $signature ) ) {
			$this->log_signature_failure( $key, 'signature_invalid' );
			return false;
		}
		$data = json_decode( $payload, true );
		if ( ! is_array( $data ) || ! isset( $data['key'], $data['rules'] ) || $data['key'] !== $key || ! is_array( $data['rules'] ) ) {
			$this->log_signature_failure( $key, 'payload_shape_invalid' );
			return false;
		}
		return ReportedIP_Hive_Rule_Store::set( $key, $data );
	}

	/**
	 * Sync all rulesets, guarded by a 5-minute lock and the opt-in eligibility
	 * check. Safe to call from cron and from the self-heal path.
	 *
	 * @return void
	 * @since  2.2.0
	 */
	public function sync_all() {
		if ( ! $this->is_sync_eligible() ) {
			return;
		}
		if ( get_site_transient( self::SYNC_LOCK_TRANSIENT ) ) {
			return;
		}
		set_site_transient( self::SYNC_LOCK_TRANSIENT, 1, 5 * MINUTE_IN_SECONDS );
		try {
			foreach ( ReportedIP_Hive_Rule_Store::VALID_KEYS as $key ) {
				$this->sync_ruleset( $key );
			}
			ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_rule_sync_last_run', time() );
		} finally {
			delete_site_transient( self::SYNC_LOCK_TRANSIENT );
		}
	}

	/**
	 * Download, verify and store a single ruleset. Honours ETag/304 and never
	 * throws — any failure leaves the previous/baseline copy in place.
	 *
	 * @param string $key Ruleset key.
	 * @return bool True when a fresh ruleset was applied.
	 * @since  2.2.0
	 */
	public function sync_ruleset( $key ) {
		if ( ! ReportedIP_Hive_Rule_Store::is_valid_key( $key ) ) {
			return false;
		}
		$url      = $this->endpoint_for( $key );
		$etag_key = 'reportedip_hive_ruleset_etag_' . $key;
		$response = $this->fetch_remote( $url, (string) get_site_transient( $etag_key ) );
		if ( ! is_array( $response ) ) {
			return false;
		}
		if ( 304 === $response['code'] ) {
			return false;
		}
		if ( 200 !== $response['code'] ) {
			return false;
		}
		$envelope = json_decode( (string) $response['body'], true );
		if ( ! is_array( $envelope ) ) {
			return false;
		}
		$applied = $this->apply_ruleset( $key, $envelope );
		if ( $applied && '' !== $response['etag'] ) {
			set_site_transient( $etag_key, $response['etag'], 0 );
		}
		return $applied;
	}

	/**
	 * Perform the HTTP GET. Isolated so tests can stub it.
	 *
	 * @param string $url  Endpoint URL.
	 * @param string $etag Previously stored ETag (sent as If-None-Match).
	 * @return array{code:int,body:string,etag:string}|null
	 * @since  2.2.0
	 */
	protected function fetch_remote( $url, $etag ) {
		if ( '' === $url ) {
			return null;
		}
		$args = array(
			'timeout'    => 15,
			'sslverify'  => true,
			'headers'    => array( 'X-Key' => (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' ) ),
			'user-agent' => 'ReportedIP-Hive/' . ( defined( 'REPORTEDIP_HIVE_VERSION' ) ? REPORTEDIP_HIVE_VERSION : '0' ),
		);
		if ( '' !== $etag ) {
			$args['headers']['If-None-Match'] = $etag;
		}
		$response = wp_remote_get( $url, $args );
		if ( is_wp_error( $response ) ) {
			return null;
		}
		return array(
			'code' => (int) wp_remote_retrieve_response_code( $response ),
			'body' => (string) wp_remote_retrieve_body( $response ),
			'etag' => (string) wp_remote_retrieve_header( $response, 'etag' ),
		);
	}

	/**
	 * Build the rules endpoint URL for a key from the configured API endpoint.
	 *
	 * @param string $key Ruleset key.
	 * @return string Endpoint URL, or '' when no API endpoint is configured.
	 * @since  2.2.0
	 */
	protected function endpoint_for( $key ) {
		$base = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_endpoint', '' );
		if ( '' === $base ) {
			return '';
		}
		return rtrim( $base, '/' ) . '/rules/' . rawurlencode( $key );
	}

	/**
	 * True when remote sync is allowed: master toggle on, community mode, API key
	 * present. Free/local installs use only the bundled baseline (no remote call,
	 * WP.org opt-in compliance).
	 *
	 * @return bool
	 * @since  2.2.0
	 */
	public function is_sync_eligible() {
		if ( ! ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_rule_sync_enabled', true ) ) {
			return false;
		}
		if ( '' === (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' ) ) {
			return false;
		}
		if ( class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			return ReportedIP_Hive_Mode_Manager::get_instance()->is_community_mode();
		}
		return false;
	}

	/**
	 * Log a verification/shape failure (high severity) without ever applying the
	 * ruleset. Availability beats strictness: the baseline stays active.
	 *
	 * @param string $key    Ruleset key.
	 * @param string $reason Machine reason.
	 * @return void
	 * @since  2.2.0
	 */
	private function log_signature_failure( $key, $reason ) {
		if ( class_exists( 'ReportedIP_Hive_Logger' ) ) {
			ReportedIP_Hive_Logger::get_instance()->log_security_event(
				'rule_sync_signature_fail',
				ReportedIP_Hive::get_client_ip(),
				array(
					'ruleset' => $key,
					'reason'  => $reason,
				),
				'high'
			);
		}
	}
}
