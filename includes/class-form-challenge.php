<?php
/**
 * Bound form challenge: a signed, single-use task the browser fetches from this site.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.64
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Mints and verifies the challenge behind the computation check.
 *
 * The page markup carries nothing but a static flag, so a full-page cache
 * and a CDN edge may serve it unchanged to every visitor. The visitor's own
 * task comes from a POST endpoint whose answer is never cacheable: a token
 * signed with the site salt, good for ten minutes and accepted once. The starting value of the task is derived from
 * the token itself, so a client can pick neither the value nor the
 * difficulty, and the difficulty climbs with the rate at which one network
 * asks for tasks.
 *
 * The token is deliberately not bound to the visitor's address. A phone that
 * moves from wifi to mobile data between page load and submit would be
 * refused otherwise, and that is a real person losing a message.
 *
 * Every path fails open. A server that cannot mint answers with a task of
 * zero difficulty, and a verifier that throws answers with `ok`. An internal
 * fault never turns a visitor into a bot.
 *
 * @since 2.1.64
 */
final class ReportedIP_Hive_Form_Challenge {

	/**
	 * Seconds a token stays valid.
	 */
	const TTL = 600;

	/**
	 * Longest lifetime a filter may ask for.
	 */
	const TTL_MAX = 1800;

	/**
	 * Leading zero bits a fresh network is asked for.
	 *
	 * About 16,000 hashes, well under a quarter of a second in a browser.
	 */
	const BITS_BASE = 14;

	/**
	 * Lowest difficulty, used on an insecure connection where the browser has
	 * no hash API. The token still binds, expires and is good once.
	 */
	const BITS_MIN = 0;

	/**
	 * Highest difficulty the ladder climbs to.
	 *
	 * About four million hashes, a second or two in a browser, and that only
	 * for a network that asked for hundreds of tasks in ten minutes.
	 */
	const BITS_MAX = 22;

	/**
	 * Mint requests a network may make within {@see MINT_WINDOW} before the
	 * endpoint answers 429. Generous on purpose: an office or a school sits
	 * behind one address, and minting is cheap; the cost lives in solving.
	 */
	const MINT_LIMIT = 120;

	/**
	 * Window of the mint counter in seconds.
	 */
	const MINT_WINDOW = 600;

	/**
	 * Transient prefix of spent tokens.
	 */
	const REPLAY_PREFIX = 'rip_fc_';

	/**
	 * Transient prefix of the per-network mint counter.
	 */
	const MINT_PREFIX = 'rip_fc_mint_';

	/**
	 * REST namespace and route.
	 */
	const NAMESPACE_STR = 'reportedip-hive/v1';

	/**
	 * REST route below the namespace.
	 */
	const ROUTE = '/form/challenge';

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Singleton accessor.
	 *
	 * @return self
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Hooks the endpoint.
	 */
	private function __construct() {
		if ( function_exists( 'add_action' ) ) {
			add_action( 'rest_api_init', array( $this, 'register_routes' ) );
		}
	}

	/**
	 * Mint a signed, bound challenge token.
	 *
	 * @param int      $bits Leading zero bits the solution must produce.
	 * @param int|null $now  Current time, injectable for tests.
	 * @return array{token:string,seed:string,bits:int,expires:int}
	 * @since  2.1.64
	 */
	public static function mint( $bits, $now = null ) {
		$now  = null === $now ? time() : (int) $now;
		$bits = max( self::BITS_MIN, min( self::BITS_MAX, (int) $bits ) );

		$claims = array(
			'v' => 1,
			't' => $now,
			'e' => $now + self::ttl(),
			'b' => $bits,
			'r' => bin2hex( random_bytes( 8 ) ),
		);

		$payload = self::b64url( (string) wp_json_encode( $claims ) );
		$token   = $payload . '.' . self::sign( $payload );

		return array(
			'token'   => $token,
			'seed'    => self::seed( $token ),
			'bits'    => $bits,
			'expires' => (int) $claims['e'],
		);
	}

	/**
	 * Starting value of the task, derived from the whole token so the client
	 * can choose neither it nor the difficulty it comes with.
	 *
	 * @param string $token Signed token.
	 * @return string
	 */
	public static function seed( $token ) {
		return substr( hash_hmac( 'sha256', (string) $token, wp_salt( 'nonce' ) ), 0, 16 );
	}

	/**
	 * Verify a token and its solution.
	 *
	 * Reasons come back as a word, `ok` on success. The cheapest check runs
	 * first. Any exception is answered with `ok`: failing open is the rule.
	 *
	 * @param string   $token Signed token as minted.
	 * @param string   $nonce Solution found by the browser.
	 * @param int|null $now   Current time, injectable for tests.
	 * @return string `ok`, `signature`, `expired`, `pow` or `replay`.
	 * @since  2.1.64
	 */
	public static function verify( $token, $nonce, $now = null ) {
		try {
			$now   = null === $now ? time() : (int) $now;
			$token = (string) $token;
			$dot   = strrpos( $token, '.' );

			if ( false === $dot ) {
				return 'signature';
			}

			$payload = substr( $token, 0, $dot );
			$sig     = substr( $token, $dot + 1 );

			if ( ! hash_equals( self::sign( $payload ), (string) $sig ) ) {
				return 'signature';
			}

			$claims = json_decode( (string) self::b64url_decode( $payload ), true );

			if ( ! is_array( $claims ) || empty( $claims['e'] ) ) {
				return 'signature';
			}

			if ( $now >= (int) $claims['e'] ) {
				return 'expired';
			}

			$bits = isset( $claims['b'] ) ? (int) $claims['b'] : 0;

			if ( $bits > 0 ) {
				$digest = hash( 'sha256', self::seed( $token ) . (string) $nonce, true );

				if ( ReportedIP_Hive_Form_Proof::leading_zero_bits( $digest ) < $bits ) {
					return 'pow';
				}
			}

			$key = self::REPLAY_PREFIX . hash( 'sha256', $token );

			if ( false !== get_transient( $key ) ) {
				return 'replay';
			}

			set_transient( $key, 1, max( 1, (int) $claims['e'] - $now ) );

			return 'ok';
		} catch ( \Throwable $e ) {
			return 'ok';
		}
	}

	/**
	 * Difficulty for a network that has minted `$mint_count` tasks in the
	 * current window. Eight are free, every doubling beyond costs one bit,
	 * the hardening mode adds two.
	 *
	 * @param int  $mint_count Mints of this network in the window, this one included.
	 * @param bool $hardening  Whether the hardening mode is active.
	 * @return int
	 * @since  2.1.64
	 */
	public static function bits_for( $mint_count, $hardening ) {
		$bits  = self::BITS_BASE;
		$count = max( 1, (int) $mint_count );
		$free  = 8;

		while ( $count > $free && $bits < self::BITS_MAX ) {
			++$bits;
			$free *= 2;
		}

		if ( $hardening ) {
			$bits += 2;
		}

		$bits = (int) apply_filters( 'reportedip_hive_form_proof_bits', $bits, 'challenge' );

		return max( self::BITS_MIN, min( self::BITS_MAX, $bits ) );
	}

	/**
	 * Whether a proof field value carries a token rather than a marker.
	 *
	 * A token value is `payload.signature.nonce`: three parts, the middle one
	 * 32 hex characters. A plain marker has no dot, the payload of the former
	 * hourly task had one.
	 *
	 * @param string $value Raw proof field value, seconds suffix removed.
	 * @return bool
	 * @since  2.1.64
	 */
	private static function looks_like_token( $value ) {
		$parts = explode( '.', (string) $value );

		return 3 === count( $parts )
			&& '' !== $parts[0]
			&& (bool) preg_match( '/^[0-9a-f]{32}$/', $parts[1] );
	}

	/**
	 * Judge a proof field value in one word.
	 *
	 * `marker` for a value that is no token at all (the plain marker, or the
	 * payload of the former hourly task), otherwise what {@see verify()} says.
	 *
	 * @param string   $value Raw proof field value, seconds suffix removed.
	 * @param int|null $now   Current time, injectable for tests.
	 * @return string `ok`, `marker`, `signature`, `expired`, `pow` or `replay`.
	 * @since  2.1.64
	 */
	public static function judge( $value, $now = null ) {
		if ( ! self::looks_like_token( $value ) ) {
			return 'marker';
		}

		$parts = self::split( $value );

		return self::verify( $parts['token'], $parts['nonce'], $now );
	}

	/**
	 * Split a proof field value into the signed token and the solution.
	 *
	 * @param string $value Raw proof field value, seconds suffix removed.
	 * @return array{token:string,nonce:string}
	 * @since  2.1.64
	 */
	private static function split( $value ) {
		$value = (string) $value;
		$dot   = strrpos( $value, '.' );

		if ( false === $dot ) {
			return array(
				'token' => '',
				'nonce' => $value,
			);
		}

		return array(
			'token' => substr( $value, 0, $dot ),
			'nonce' => substr( $value, $dot + 1 ),
		);
	}

	/**
	 * Mint a task for a network that has asked `$count` times in the window:
	 * arithmetic only over a secure connection, harder the more it asked.
	 *
	 * @param int $count Mints of this network in the window, this one included.
	 * @return array{token:string,seed:string,bits:int,expires:int}
	 * @since  2.1.64
	 */
	public static function issue( $count = 1 ) {
		$hardening = class_exists( 'ReportedIP_Hive_Hardening_Mode' ) && ReportedIP_Hive_Hardening_Mode::is_active();
		$bits      = ReportedIP_Hive_Form_Proof::connection_is_secure() ? self::bits_for( $count, $hardening ) : 0;

		return self::mint( $bits );
	}

	/**
	 * Token lifetime in seconds, filterable and capped.
	 *
	 * @return int
	 */
	public static function ttl() {
		$ttl = (int) apply_filters( 'reportedip_hive_form_challenge_ttl', self::TTL );

		return max( 60, min( self::TTL_MAX, $ttl ) );
	}

	/**
	 * Register the challenge route.
	 *
	 * The namespace is on the always-allowed list of the access lockdown and
	 * on the bypass list of the REST monitor already, so neither can lock a
	 * visitor out of a task.
	 *
	 * @since 2.1.64
	 */
	public function register_routes() {
		register_rest_route(
			self::NAMESPACE_STR,
			self::ROUTE,
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'handle_challenge' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Mint a challenge.
	 *
	 * The answer is never cacheable. Every error path still hands out a
	 * token, with zero difficulty, so a server fault never costs a visitor
	 * their message.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 * @since  2.1.64
	 */
	public function handle_challenge( WP_REST_Request $request ) {
		if ( class_exists( 'ReportedIP_Hive' ) ) {
			ReportedIP_Hive::emit_block_response_headers();
		}

		$cross = ReportedIP_Hive_Two_Factor_REST::reject_cross_origin();

		if ( is_wp_error( $cross ) ) {
			return $cross;
		}

		unset( $request );

		try {
			if ( ! ReportedIP_Hive_Form_Proof::get_instance()->pow_enabled() ) {
				return $this->respond( self::mint( 0 ) );
			}

			$count = $this->bump_mint( (string) ReportedIP_Hive::get_client_ip() );

			if ( $count > self::MINT_LIMIT ) {
				return new WP_Error(
					'reportedip_form_challenge_throttled',
					__( 'Too many requests. Please try again in a moment.', 'reportedip-hive' ),
					array( 'status' => 429 )
				);
			}

			return $this->respond( self::issue( $count ) );
		} catch ( \Throwable $e ) {
			return $this->respond( self::mint( 0 ) );
		}
	}

	/**
	 * Wrap a minted task in an uncacheable response.
	 *
	 * @param array $minted Result of {@see mint()}.
	 * @return WP_REST_Response
	 */
	private function respond( array $minted ) {
		$response = new WP_REST_Response( $minted, 200 );
		$response->header( 'Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0' );
		$response->header( 'X-LiteSpeed-Cache-Control', 'no-cache' );

		return $response;
	}

	/**
	 * Count one mint for this network and return the count it stands at.
	 *
	 * @param string $ip Client address.
	 * @return int
	 */
	private function bump_mint( $ip ) {
		$key   = self::MINT_PREFIX . md5( self::network( $ip ) );
		$count = (int) get_site_transient( $key ) + 1;

		set_site_transient( $key, $count, self::MINT_WINDOW );

		return $count;
	}

	/**
	 * The network an address belongs to, through the one reducer the plugin
	 * has (/24 for IPv4, /64 for IPv6). The counter is per network, not per
	 * address, so a bot rotating through one block shares one ladder.
	 *
	 * @param string $ip Client address.
	 * @return string
	 */
	public static function network( $ip ) {
		$network = ReportedIP_Hive_Two_Factor_Notifications::ip_to_network( (string) $ip );

		return '' === $network ? (string) $ip : $network;
	}

	/**
	 * Sign a payload with the site's auth salt, 32 hex characters.
	 *
	 * @param string $payload URL-safe base64 claims.
	 * @return string
	 */
	private static function sign( $payload ) {
		return substr( hash_hmac( 'sha256', (string) $payload, wp_salt( 'auth' ) ), 0, 32 );
	}

	/**
	 * URL-safe base64 without padding.
	 *
	 * @param string $raw Bytes.
	 * @return string
	 */
	private static function b64url( $raw ) {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- URL-safe transport of signed JSON claims, nothing is hidden.
		return rtrim( strtr( base64_encode( (string) $raw ), '+/', '-_' ), '=' );
	}

	/**
	 * Inverse of {@see b64url()}.
	 *
	 * @param string $encoded Encoded string.
	 * @return string|false
	 */
	private static function b64url_decode( $encoded ) {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Inverse of the URL-safe transport above.
		return base64_decode( strtr( (string) $encoded, '-_', '+/' ), true );
	}
}
