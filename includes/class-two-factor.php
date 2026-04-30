<?php
/**
 * Two-Factor Authentication Orchestrator for ReportedIP Hive.
 *
 * Intercepts the WordPress login flow to enforce 2FA verification.
 * Manages login nonces, trusted devices, and brute-force protection.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.3.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ReportedIP_Hive_Two_Factor
 *
 * Core orchestrator for the 2FA login flow.
 * Hooks into WordPress authentication to add a second factor step.
 */
class ReportedIP_Hive_Two_Factor {

	/**
	 * Login nonce transient prefix.
	 *
	 * @var string
	 */
	const NONCE_PREFIX = 'reportedip_2fa_nonce_';

	/**
	 * Login nonce cookie name.
	 *
	 * @var string
	 */
	const NONCE_COOKIE = 'reportedip_2fa_token';

	/**
	 * Trusted device cookie name.
	 *
	 * @var string
	 */
	const TRUSTED_COOKIE = 'reportedip_hive_trusted_device';

	/**
	 * Trusted devices table name suffix (without prefix).
	 *
	 * @var string
	 */
	const TABLE_TRUSTED_DEVICES = 'reportedip_hive_trusted_devices';

	/**
	 * Login nonce TTL in seconds (5 minutes).
	 *
	 * @var int
	 */
	const NONCE_TTL = 900;

	/**
	 * User meta keys.
	 */
	const META_ENABLED           = 'reportedip_hive_2fa_enabled';
	const META_METHOD            = 'reportedip_hive_2fa_method';
	const META_TOTP_SECRET       = 'reportedip_hive_2fa_totp_secret';
	const META_TOTP_CONFIRMED    = 'reportedip_hive_2fa_totp_confirmed';
	const META_FAILED_ATTEMPTS   = 'reportedip_hive_2fa_failed_attempts';
	const META_SETUP_DATE        = 'reportedip_hive_2fa_setup_date';
	const META_ENFORCEMENT_START = 'reportedip_hive_2fa_enforcement_start';

	const META_TOTP_ENABLED     = 'reportedip_hive_2fa_totp_enabled';
	const META_EMAIL_ENABLED    = 'reportedip_hive_2fa_email_enabled';
	const META_WEBAUTHN_ENABLED = 'reportedip_hive_2fa_webauthn_enabled';
	const META_SMS_ENABLED      = 'reportedip_hive_2fa_sms_enabled';

	const META_WEBAUTHN_CREDENTIALS = 'reportedip_hive_2fa_webauthn_credentials';
	const META_SMS_NUMBER           = 'reportedip_hive_2fa_sms_number';

	const META_SKIP_COUNT    = 'reportedip_hive_2fa_skip_count';
	const META_KNOWN_DEVICES = 'reportedip_hive_2fa_known_devices';

	/**
	 * 2FA method identifiers.
	 */
	const METHOD_TOTP     = 'totp';
	const METHOD_EMAIL    = 'email';
	const METHOD_WEBAUTHN = 'webauthn';
	const METHOD_SMS      = 'sms';
	const METHOD_RECOVERY = 'recovery';

	/**
	 * wp-login.php action slug for the 2FA challenge page.
	 *
	 * @var string
	 */
	const ACTION_CHALLENGE = 'reportedip_2fa';

	/**
	 * Failed attempts before session is invalidated (forces re-auth).
	 */
	const SESSION_INVALIDATION_THRESHOLD = 10;

	/**
	 * Brute-force lockout escalation thresholds.
	 *
	 * @var array
	 */
	const LOCKOUT_THRESHOLDS = array(
		3  => 30,
		5  => 300,
		10 => 1800,
		15 => 3600,
	);

	/**
	 * Constructor — registers authentication hooks.
	 *
	 * 2FA hooks run on every request (not just admin) because wp-login.php
	 * is not admin context. The authenticate filter runs at priority 99,
	 * after WordPress core password verification (priority 20) and the
	 * plugin's own IP reputation check (wp_authenticate_user, priority 10).
	 */
	public function __construct() {
		if ( ! self::is_globally_enabled() ) {
			return;
		}

		add_filter( 'authenticate', array( $this, 'filter_authenticate' ), 99, 3 );
		add_action( 'login_form_' . self::ACTION_CHALLENGE, array( $this, 'handle_2fa_challenge' ) );
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_scripts' ) );
		add_action( 'login_footer', array( $this, 'render_login_attribution' ) );

		add_action( 'wp_ajax_nopriv_reportedip_2fa_resend', array( $this, 'ajax_resend_code' ) );
		add_action( 'wp_ajax_reportedip_2fa_resend', array( $this, 'ajax_resend_code' ) );

		add_action( 'wp_logout', array( $this, 'cleanup_on_logout' ), 10, 1 );
	}

	/**
	 * AJAX handler: resend an email / SMS OTP during the 2FA challenge.
	 *
	 * Authenticates via the short-lived nonce cookie set when the challenge
	 * started. Returns JSON with the resend cooldown so the UI can run a
	 * countdown without a full page reload.
	 */
	public function ajax_resend_code() {
		$nonce_data = $this->validate_login_nonce();
		if ( false === $nonce_data ) {
			wp_send_json_error(
				array( 'message' => __( 'Your session has expired. Please sign in again.', 'reportedip-hive' ) ),
				403
			);
		}

		$user_id = (int) $nonce_data['user_id'];
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Identity verified via signed cookie + transient by validate_login_nonce() above; user is not yet logged in (no WP nonce available).
		$method = isset( $_POST['method'] ) ? sanitize_key( wp_unslash( $_POST['method'] ) ) : '';

		if ( ! in_array( $method, array( self::METHOD_EMAIL, self::METHOD_SMS ), true ) ) {
			wp_send_json_error(
				array( 'message' => __( 'This method does not support resending.', 'reportedip-hive' ) ),
				400
			);
		}

		$enabled = self::get_user_enabled_methods( $user_id );
		if ( ! in_array( $method, $enabled, true ) ) {
			wp_send_json_error(
				array( 'message' => __( 'This method is not active on your account.', 'reportedip-hive' ) ),
				400
			);
		}

		$this->refresh_login_nonce( $nonce_data );

		if ( self::METHOD_EMAIL === $method ) {
			$result      = ReportedIP_Hive_Two_Factor_Email::send_code( $user_id );
			$cooldown    = ReportedIP_Hive_Two_Factor_Email::get_resend_wait_seconds( $user_id );
			$destination = self::mask_email( get_userdata( $user_id )->user_email );
		} else {
			if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_SMS' ) ) {
				wp_send_json_error( array( 'message' => __( 'SMS is not available.', 'reportedip-hive' ) ), 400 );
			}
			$result      = ReportedIP_Hive_Two_Factor_SMS::send_code( $user_id );
			$cooldown    = method_exists( 'ReportedIP_Hive_Two_Factor_SMS', 'get_resend_wait_seconds' )
				? ReportedIP_Hive_Two_Factor_SMS::get_resend_wait_seconds( $user_id )
				: 60;
			$phone       = ReportedIP_Hive_Two_Factor_SMS::get_user_phone( $user_id );
			$destination = $phone ? ReportedIP_Hive_Two_Factor_SMS::mask_phone( $phone ) : '';
		}

		if ( is_wp_error( $result ) ) {
			wp_send_json_error(
				array(
					'message'  => $result->get_error_message(),
					'cooldown' => (int) $cooldown,
				),
				429
			);
		}

		wp_send_json_success(
			array(
				'message'     => self::METHOD_EMAIL === $method
					? __( 'We have sent you a new code by email.', 'reportedip-hive' )
					: __( 'We have sent you a new code by SMS.', 'reportedip-hive' ),
				'destination' => $destination,
				'cooldown'    => (int) $cooldown,
				'phase'       => 'code_sent',
			)
		);
	}

	/**
	 * Extend the lifetime of the current challenge nonce so a user who is
	 * actively reading the OTP mail does not get booted back to wp-login.php.
	 *
	 * @param array $nonce_data The validated nonce payload.
	 */
	private function refresh_login_nonce( $nonce_data ) {
		if ( ! isset( $_COOKIE[ self::NONCE_COOKIE ] ) ) {
			return;
		}
		$token      = sanitize_text_field( wp_unslash( $_COOKIE[ self::NONCE_COOKIE ] ) );
		$token_hash = hash( 'sha256', $token );
		set_transient( self::NONCE_PREFIX . $token_hash, $nonce_data, self::NONCE_TTL );

		$secure = is_ssl();
		setcookie(
			self::NONCE_COOKIE,
			$token,
			array(
				'expires'  => time() + self::NONCE_TTL,
				'path'     => COOKIEPATH,
				'domain'   => COOKIE_DOMAIN,
				'secure'   => $secure,
				'httponly' => true,
				'samesite' => 'Strict',
			)
		);
	}

	/**
	 * wp_logout callback — clear challenge cookies and transients.
	 *
	 * @param int $user_id Logged-out user ID (0 if unknown).
	 */
	/**
	 * Render a subtle "secured by ReportedIP" attribution under the login form.
	 * Loads the 2FA CSS so the pill styling is available regardless of whether
	 * the user is mid-challenge or just on the plain login page.
	 */
	public function render_login_attribution() {
		if ( ! wp_style_is( 'reportedip-hive-two-factor', 'enqueued' ) ) {
			wp_enqueue_style(
				'reportedip-hive-two-factor',
				REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/two-factor.css',
				array(),
				REPORTEDIP_HIVE_VERSION
			);
		}
		?>
		<p class="rip-2fa-login-attribution">
			<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
			<?php
			printf(
				/* translators: 1: opening link tag, 2: closing link tag */
				esc_html__( 'Secured by %1$sReportedIP%2$s — Open Threat Intelligence for a Safer Internet.', 'reportedip-hive' ),
				'<a href="https://reportedip.de/" target="_blank" rel="noopener">',
				'</a>'
			);
			?>
		</p>
		<?php
	}

	public function cleanup_on_logout( $user_id = 0 ) {
		$this->cleanup_login_nonce();
		if ( $user_id && class_exists( 'ReportedIP_Hive_Two_Factor_Onboarding' ) ) {
			delete_transient( ReportedIP_Hive_Two_Factor_Onboarding::TRANSIENT_PREFIX . (int) $user_id );
		}
	}

	/**
	 * Stretch the WP auth cookie lifetime for 2FA-verified remember-me logins
	 * from 14 days (core default) to 30 days — stronger auth earns longer
	 * sessions. Only active while wp_set_auth_cookie() is running inside
	 * handle_2fa_challenge after a successful verify.
	 *
	 * @param int  $expiration  Requested expiration in seconds.
	 * @param int  $user_id     User ID.
	 * @param bool $remember    Whether "remember me" was ticked.
	 * @return int
	 */
	public static function filter_extended_cookie_expiration( $expiration, $user_id, $remember ) {
		unset( $user_id );
		if ( ! $remember ) {
			return $expiration;
		}
		return max( $expiration, 30 * DAY_IN_SECONDS );
	}

	/**
	 * Check if 2FA is globally enabled.
	 *
	 * @return bool
	 */
	public static function is_globally_enabled() {
		return (bool) get_option( 'reportedip_hive_2fa_enabled_global', false );
	}

	/**
	 * Request-level cache for get_user_enabled_methods() results.
	 * Invalidated in enable_for_user / disable_method / disable_for_user.
	 *
	 * @var array<int, string[]>
	 */
	private static $methods_cache = array();

	/**
	 * Check if a user has 2FA enabled.
	 *
	 * Derived from the per-method flags so META_ENABLED can never drift away
	 * from what the user actually has configured.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool
	 */
	public static function is_user_enabled( $user_id ) {
		return ! empty( self::get_user_enabled_methods( $user_id ) );
	}

	/**
	 * Get the user's configured 2FA method.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string 'totp' or 'email'.
	 */
	public static function get_user_method( $user_id ) {
		$stored  = get_user_meta( $user_id, self::META_METHOD, true );
		$enabled = self::get_user_enabled_methods( $user_id );

		if ( $stored && in_array( $stored, $enabled, true ) ) {
			return $stored;
		}

		return ! empty( $enabled ) ? $enabled[0] : self::METHOD_TOTP;
	}

	/**
	 * Check if 2FA is enforced for a user's role.
	 *
	 * @param \WP_User $user WordPress user object.
	 * @return bool True if the user's role requires 2FA.
	 */
	public static function is_enforced_for_user( $user ) {
		$enforce_roles = json_decode( get_option( 'reportedip_hive_2fa_enforce_roles', '[]' ), true );
		if ( ! is_array( $enforce_roles ) || empty( $enforce_roles ) ) {
			return false;
		}

		foreach ( $user->roles as $role ) {
			if ( in_array( $role, $enforce_roles, true ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if a user is within the enforcement grace period.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool True if still within grace period.
	 */
	public static function is_in_grace_period( $user_id ) {
		$grace_days = (int) get_option( 'reportedip_hive_2fa_enforce_grace_days', 7 );
		if ( $grace_days <= 0 ) {
			return false;
		}

		$enforcement_start = (int) get_user_meta( $user_id, self::META_ENFORCEMENT_START, true );
		if ( $enforcement_start <= 0 ) {
			return true;
		}

		return time() < ( $enforcement_start + ( $grace_days * DAY_IN_SECONDS ) );
	}

	/**
	 * Return the list of 2FA methods the user has actively configured.
	 *
	 * Supports parallel activation (e.g. TOTP + E-Mail + Passkey at once).
	 * Falls back to legacy single-method meta for backward compatibility.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string[] Method identifiers (totp, email, webauthn, sms).
	 */
	public static function get_user_enabled_methods( $user_id ) {
		if ( isset( self::$methods_cache[ $user_id ] ) ) {
			return self::$methods_cache[ $user_id ];
		}

		$methods = array();

		if ( get_user_meta( $user_id, self::META_TOTP_ENABLED, true ) ) {
			$methods[] = self::METHOD_TOTP;
		}
		if ( get_user_meta( $user_id, self::META_EMAIL_ENABLED, true ) ) {
			$methods[] = self::METHOD_EMAIL;
		}
		if ( get_user_meta( $user_id, self::META_WEBAUTHN_ENABLED, true ) ) {
			$methods[] = self::METHOD_WEBAUTHN;
		}
		if ( get_user_meta( $user_id, self::META_SMS_ENABLED, true ) ) {
			$methods[] = self::METHOD_SMS;
		}

		if ( empty( $methods ) && get_user_meta( $user_id, self::META_ENABLED, true ) ) {
			$primary = get_user_meta( $user_id, self::META_METHOD, true );
			if ( in_array( $primary, array( self::METHOD_TOTP, self::METHOD_EMAIL ), true ) ) {
				$methods[] = $primary;
			}
		}

		$allowed_global = self::get_allowed_methods();
		if ( ! empty( $allowed_global ) ) {
			$methods = array_values( array_intersect( $methods, $allowed_global ) );
		}

		self::$methods_cache[ $user_id ] = $methods;
		return $methods;
	}

	/**
	 * Return the globally allowed 2FA methods from admin settings.
	 *
	 * Centralises the JSON-decode so callers don't each repeat it.
	 *
	 * @return string[] Method identifiers.
	 */
	public static function get_allowed_methods() {
		$raw     = get_option( 'reportedip_hive_2fa_allowed_methods', '["totp","email"]' );
		$decoded = json_decode( $raw, true );
		if ( ! is_array( $decoded ) || empty( $decoded ) ) {
			return array( self::METHOD_TOTP, self::METHOD_EMAIL );
		}
		return array_values( $decoded );
	}

	/**
	 * Map a method identifier to its "enabled" user-meta key.
	 *
	 * @param string $method Method identifier.
	 * @return string|null Meta key or null for unknown methods.
	 */
	public static function get_method_meta_key( $method ) {
		$map = array(
			self::METHOD_TOTP     => self::META_TOTP_ENABLED,
			self::METHOD_EMAIL    => self::META_EMAIL_ENABLED,
			self::METHOD_WEBAUTHN => self::META_WEBAUTHN_ENABLED,
			self::METHOD_SMS      => self::META_SMS_ENABLED,
		);
		return $map[ $method ] ?? null;
	}

	/**
	 * Check whether the current client IP is in the admin-configured bypass allowlist.
	 *
	 * Supports single IPs and CIDR blocks (IPv4 + IPv6). Lines starting with '#' are comments.
	 *
	 * @return bool True if current IP is allowlisted.
	 */
	public static function is_ip_allowlisted() {
		$raw = (string) get_option( 'reportedip_hive_2fa_ip_allowlist', '' );
		if ( '' === $raw ) {
			return false;
		}

		$ip = ReportedIP_Hive::get_client_ip();
		if ( empty( $ip ) ) {
			return false;
		}

		$entries = preg_split( '/\r\n|\r|\n/', $raw );
		foreach ( (array) $entries as $entry ) {
			$entry = trim( $entry );
			if ( '' === $entry || 0 === strpos( $entry, '#' ) ) {
				continue;
			}
			if ( self::ip_matches( $ip, $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Match an IP against a single IP or CIDR block.
	 *
	 * @param string $ip    Client IP (IPv4 or IPv6).
	 * @param string $range Single IP or CIDR block.
	 * @return bool
	 */
	private static function ip_matches( $ip, $range ) {
		if ( $ip === $range ) {
			return true;
		}
		if ( false === strpos( $range, '/' ) ) {
			return false;
		}

		list( $subnet, $bits ) = explode( '/', $range, 2 );
		$bits                  = (int) $bits;

		if ( false !== strpos( $ip, '.' ) && false !== strpos( $subnet, '.' ) ) {
			$ip_long     = ip2long( $ip );
			$subnet_long = ip2long( $subnet );
			if ( false === $ip_long || false === $subnet_long || $bits < 0 || $bits > 32 ) {
				return false;
			}
			$mask = ( 0 === $bits ) ? 0 : ( -1 << ( 32 - $bits ) );
			return ( $ip_long & $mask ) === ( $subnet_long & $mask );
		}

		if ( false !== strpos( $ip, ':' ) && false !== strpos( $subnet, ':' ) ) {
			$ip_bin     = inet_pton( $ip );
			$subnet_bin = inet_pton( $subnet );
			if ( false === $ip_bin || false === $subnet_bin || $bits < 0 || $bits > 128 ) {
				return false;
			}
			$full_bytes = intdiv( $bits, 8 );
			$remain     = $bits % 8;
			if ( substr( $ip_bin, 0, $full_bytes ) !== substr( $subnet_bin, 0, $full_bytes ) ) {
				return false;
			}
			if ( 0 === $remain ) {
				return true;
			}
			$mask     = chr( ( 0xFF << ( 8 - $remain ) ) & 0xFF );
			$ip_byte  = ord( substr( $ip_bin, $full_bytes, 1 ) );
			$sub_byte = ord( substr( $subnet_bin, $full_bytes, 1 ) );
			return ( $ip_byte & ord( $mask ) ) === ( $sub_byte & ord( $mask ) );
		}

		return false;
	}

	/**
	 * Authenticate filter — intercept login when 2FA is required.
	 *
	 * Runs at priority 99 on the 'authenticate' filter, after password verification.
	 * If the user has 2FA enabled or enforcement requires it, returns WP_Error
	 * to prevent cookie creation, and sets up the 2FA challenge nonce.
	 *
	 * @param \WP_User|\WP_Error|null $user     Authenticated user or error.
	 * @param string                  $username  Username.
	 * @param string                  $password  Password.
	 * @return \WP_User|\WP_Error Pass-through or 2FA intercept error.
	 */
	public function filter_authenticate( $user, $username, $password ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		if ( ! ( $user instanceof \WP_User ) ) {
			return $user;
		}

		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST
			&& get_option( 'reportedip_hive_2fa_xmlrpc_app_password_only', false )
			&& empty( $_SERVER['PHP_AUTH_USER'] ) ) {
			$logger = ReportedIP_Hive_Logger::get_instance();
			$logger->warning(
				'XMLRPC basic-auth blocked by policy',
				ReportedIP_Hive::get_client_ip(),
				array( 'user_id' => $user->ID )
			);
			return new \WP_Error(
				'reportedip_xmlrpc_app_password_only',
				__( 'XMLRPC on this site only allows application passwords. Please create an application password in your profile.', 'reportedip-hive' )
			);
		}

		$enabled_methods = self::get_user_enabled_methods( $user->ID );
		$has_any_method  = ! empty( $enabled_methods );
		$is_enforced     = self::is_enforced_for_user( $user );

		if ( ! $has_any_method && ! $is_enforced ) {
			return $user;
		}

		$bypass = (bool) apply_filters( 'reportedip_2fa_bypass', false, $user );
		if ( $bypass ) {
			return $user;
		}

		if ( self::is_ip_allowlisted() ) {
			$logger = ReportedIP_Hive_Logger::get_instance();
			$logger->info(
				'2FA bypassed via IP allowlist',
				ReportedIP_Hive::get_client_ip(),
				array( 'user_id' => $user->ID )
			);
			return $user;
		}

		if ( $this->verify_trusted_device( $user->ID ) ) {
			return $user;
		}

		if ( ! $has_any_method && $is_enforced ) {
			$in_grace   = self::is_in_grace_period( $user->ID );
			$skip_count = (int) get_user_meta( $user->ID, self::META_SKIP_COUNT, true );
			$max_skips  = (int) get_option( 'reportedip_hive_2fa_max_skips', 3 );

			if ( ! $in_grace && $skip_count >= $max_skips && $max_skips > 0 ) {
				return new \WP_Error(
					'reportedip_2fa_setup_required',
					__( '<strong>Two-factor authentication required.</strong> Your skip quota is exhausted. Please contact an administrator to reset 2FA.', 'reportedip-hive' )
				);
			}

			return $user;
		}

		$should_challenge = (bool) apply_filters(
			'reportedip_2fa_should_challenge',
			true,
			$user,
			array(
				'enabled_methods' => $enabled_methods,
				'enforced'        => $is_enforced,
			)
		);
		if ( ! $should_challenge ) {
			return $user;
		}

		$token      = bin2hex( random_bytes( 32 ) );
		$token_hash = hash( 'sha256', $token );

		$nonce_data = array(
			'user_id'     => $user->ID,
			'ip'          => ReportedIP_Hive::get_client_ip(),
			'created_at'  => time(),
			'redirect_to' => isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'remember'    => ! empty( $_REQUEST['rememberme'] ), // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		);
		set_transient( self::NONCE_PREFIX . $token_hash, $nonce_data, self::NONCE_TTL );

		$secure = is_ssl();
		setcookie(
			self::NONCE_COOKIE,
			$token,
			array(
				'expires'  => time() + self::NONCE_TTL,
				'path'     => COOKIEPATH,
				'domain'   => COOKIE_DOMAIN,
				'secure'   => $secure,
				'httponly' => true,
				'samesite' => 'Strict',
			)
		);

		$primary_method = self::get_user_method( $user->ID );
		if ( in_array( $primary_method, $enabled_methods, true ) ) {
			if ( self::METHOD_EMAIL === $primary_method ) {
				ReportedIP_Hive_Two_Factor_Email::send_code( $user->ID );
			} elseif ( self::METHOD_SMS === $primary_method && class_exists( 'ReportedIP_Hive_Two_Factor_SMS' ) ) {
				ReportedIP_Hive_Two_Factor_SMS::send_code( $user->ID );
			}
		}

		$challenge_url = wp_login_url() . '?action=' . self::ACTION_CHALLENGE;

		$is_api_context = ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
			|| ( defined( 'REST_REQUEST' ) && REST_REQUEST )
			|| wp_doing_ajax();

		if ( ! $is_api_context ) {
			$this->dispatch_browser_challenge_redirect( $challenge_url );
		}

		return new \WP_Error(
			'reportedip_2fa_required',
			__( 'Two-factor verification required.', 'reportedip-hive' ),
			array(
				'token'    => $token,
				'redirect' => $challenge_url,
			)
		);
	}

	/**
	 * Send the browser straight to the 2FA challenge page and terminate.
	 *
	 * Why this exists: returning a WP_Error from filter_authenticate routes the
	 * message through wp-login.php's login_errors filter, which third-party
	 * security/hardening plugins commonly override to mask all login errors with
	 * a generic string. That stripping removes any redirect hint (JS marker,
	 * <span data-url>, etc.), stranding the user on a generic error page.
	 *
	 * Doing the redirect server-side and exiting before wp-login.php enters its
	 * error-rendering pipeline bypasses that pipeline entirely, so reportedip-hive
	 * stays in control of the login flow regardless of what other plugins inject.
	 *
	 * @param string $challenge_url Absolute URL of the 2FA challenge page.
	 * @return void
	 * @since  1.1.5
	 */
	private function dispatch_browser_challenge_redirect( $challenge_url ) {
		if ( ! headers_sent() ) {
			nocache_headers();
			wp_safe_redirect( $challenge_url );
			exit;
		}

		$safe_url = esc_url_raw( $challenge_url );
		printf(
			'<!doctype html><meta http-equiv="refresh" content="0;url=%s"><script>window.location.replace(%s);</script>',
			esc_attr( $safe_url ),
			wp_json_encode( $safe_url )
		);
		exit;
	}

	/**
	 * Handle the 2FA challenge page (GET: display form, POST: validate code).
	 *
	 * Fires on wp-login.php?action=reportedip_2fa via the
	 * login_form_reportedip_2fa action hook.
	 */
	public function handle_2fa_challenge() {
		$nonce_data = $this->validate_login_nonce();
		if ( false === $nonce_data ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$user_id = $nonce_data['user_id'];
		$user    = get_userdata( $user_id );
		if ( ! $user ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$this->refresh_login_nonce( $nonce_data );

		$method = self::get_user_method( $user_id );
		$error  = '';

		$request_method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'POST' === $request_method ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- The submitted nonce is verified by verify_form_nonce() on the next line.
			$form_nonce = isset( $_POST['_reportedip_2fa_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['_reportedip_2fa_nonce'] ) ) : '';
			if ( ! $this->verify_form_nonce( $form_nonce, $user_id ) ) {
				$error = __( 'Security check failed. Please try again.', 'reportedip-hive' );
			} else {
				$lockout_remaining = max(
					$this->get_lockout_remaining( $user_id ),
					$this->get_ip_lockout_remaining( ReportedIP_Hive::get_client_ip() )
				);
				if ( $lockout_remaining > 0 ) {
					$error = sprintf(
						/* translators: %d: seconds remaining */
						__( 'Too many failed attempts. Please wait %d seconds.', 'reportedip-hive' ),
						$lockout_remaining
					);
				} else {
					// phpcs:disable WordPress.Security.NonceVerification.Missing -- Form nonce verified by verify_form_nonce() above.
					$submitted_code   = isset( $_POST['reportedip_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['reportedip_2fa_code'] ) ) : '';
					$submitted_method = isset( $_POST['reportedip_2fa_method'] ) ? sanitize_key( wp_unslash( $_POST['reportedip_2fa_method'] ) ) : $method;
					$trust_device     = ! empty( $_POST['reportedip_2fa_trust_device'] );
					// phpcs:enable WordPress.Security.NonceVerification.Missing

					$verified = $this->verify_2fa_code( $user_id, $submitted_code, $submitted_method );

					if ( $verified ) {
						$this->reset_failed_attempts( $user_id );
						$this->cleanup_login_nonce();

						$remember = ! empty( $nonce_data['remember'] );
						if ( $remember && get_option( 'reportedip_hive_2fa_extended_remember', false ) ) {
							add_filter( 'auth_cookie_expiration', array( __CLASS__, 'filter_extended_cookie_expiration' ), 20, 3 );
						}
						wp_set_auth_cookie( $user_id, $remember );
						if ( $remember && get_option( 'reportedip_hive_2fa_extended_remember', false ) ) {
							remove_filter( 'auth_cookie_expiration', array( __CLASS__, 'filter_extended_cookie_expiration' ), 20 );
						}
						wp_set_current_user( $user_id );

						if ( $trust_device && get_option( 'reportedip_hive_2fa_trusted_devices', true ) ) {
							$this->create_trusted_device( $user_id );
						}

						$logger = ReportedIP_Hive_Logger::get_instance();
						$logger->info(
							'2FA verification successful',
							ReportedIP_Hive::get_client_ip(),
							array(
								'user_id' => $user_id,
								'method'  => $submitted_method,
							)
						);

						$redirect_to = ! empty( $nonce_data['redirect_to'] ) ? $nonce_data['redirect_to'] : admin_url();
						wp_safe_redirect( $redirect_to );
						exit;
					} else {
						$failed = $this->increment_failed_attempts( $user_id );
						$this->increment_ip_failed_attempts( ReportedIP_Hive::get_client_ip() );

						if ( self::METHOD_EMAIL === $submitted_method && ! get_transient( 'reportedip_2fa_email_' . $user_id ) ) {
							$error = __( 'No valid code is active — you likely used an older code. Please click "Resend code" and use only the most recent code from your inbox.', 'reportedip-hive' );
						} elseif ( self::METHOD_SMS === $submitted_method && ! get_transient( 'reportedip_2fa_sms_' . $user_id ) ) {
							$error = __( 'No valid SMS code is active. Please request a new code and use only the most recent SMS.', 'reportedip-hive' );
						} else {
							$error = __( 'Invalid verification code. Please make sure you are using the most recent code.', 'reportedip-hive' );
						}
						if ( $failed >= self::SESSION_INVALIDATION_THRESHOLD ) {
							$this->cleanup_login_nonce();

							$logger = ReportedIP_Hive_Logger::get_instance();
							$logger->warning(
								'2FA brute force detected — session invalidated',
								ReportedIP_Hive::get_client_ip(),
								array(
									'user_id'  => $user_id,
									'attempts' => $failed,
								)
							);

							wp_safe_redirect( wp_login_url() . '?reportedip_2fa_locked=1' );
							exit;
						}
					}
				}
			}
		}

		$user_methods = self::get_user_enabled_methods( $user_id );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['resend_email'] ) && '1' === $_GET['resend_email']
			&& in_array( self::METHOD_EMAIL, $user_methods, true ) ) {
			$result = ReportedIP_Hive_Two_Factor_Email::send_code( $user_id );
			if ( is_wp_error( $result ) ) {
				$error = $result->get_error_message();
			}
			$method = self::METHOD_EMAIL;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['resend_sms'] ) && '1' === $_GET['resend_sms']
			&& in_array( self::METHOD_SMS, $user_methods, true )
			&& class_exists( 'ReportedIP_Hive_Two_Factor_SMS' ) ) {
			$result = ReportedIP_Hive_Two_Factor_SMS::send_code( $user_id );
			if ( is_wp_error( $result ) ) {
				$error = $result->get_error_message();
			}
			$method = self::METHOD_SMS;
		}

		$form_nonce = $this->create_form_nonce( $user_id );

		$allowed_methods = self::get_user_enabled_methods( $user_id );
		if ( empty( $allowed_methods ) ) {
			$allowed_methods = array( self::METHOD_TOTP, self::METHOD_EMAIL );
		}

		if ( ! in_array( $method, $allowed_methods, true ) ) {
			$method = $allowed_methods[0];
		}

		$template_data = array(
			'user'            => $user,
			'method'          => $method,
			'error'           => $error,
			'form_nonce'      => $form_nonce,
			'allowed_methods' => $allowed_methods,
			'trust_enabled'   => (bool) get_option( 'reportedip_hive_2fa_trusted_devices', true ),
			'resend_wait'     => ReportedIP_Hive_Two_Factor_Email::get_resend_wait_seconds( $user_id ),
			'recovery_count'  => ReportedIP_Hive_Two_Factor_Recovery::get_remaining_count( $user_id ),
			'email_code_sent' => in_array( self::METHOD_EMAIL, $allowed_methods, true )
				? (bool) get_transient( 'reportedip_2fa_email_' . $user_id )
				: false,
			'sms_code_sent'   => in_array( self::METHOD_SMS, $allowed_methods, true )
				? (bool) get_transient( 'reportedip_2fa_sms_' . $user_id )
				: false,
		);

		$this->render_challenge_page( $template_data );
		exit;
	}

	/**
	 * Verify a 2FA code based on the method.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $code    Submitted verification code.
	 * @param string $method  Verification method (totp, email, recovery).
	 * @return bool True if verified.
	 */
	private function verify_2fa_code( $user_id, $code, $method ) {
		switch ( $method ) {
			case 'totp':
				$encrypted_secret = get_user_meta( $user_id, self::META_TOTP_SECRET, true );
				if ( empty( $encrypted_secret ) ) {
					return false;
				}
				$secret = ReportedIP_Hive_Two_Factor_Crypto::decrypt( $encrypted_secret );
				if ( false === $secret ) {
					return false;
				}
				/**
				 * Configurable TOTP clock-skew tolerance in 30-second windows.
				 * Default 1 (±30 s). Admins can relax to 2 (±60 s) if users complain
				 * about clock drift, but larger windows reduce brute-force resistance.
				 */
				$window = (int) apply_filters( 'reportedip_2fa_totp_window', 1, $user_id );
				$window = max( 0, min( 3, $window ) );
				$result = ReportedIP_Hive_Two_Factor_TOTP::verify_code( $secret, $code, $window );
				ReportedIP_Hive_Two_Factor_Crypto::zero_memory( $secret );
				return $result;

			case 'email':
				return ReportedIP_Hive_Two_Factor_Email::verify_code( $user_id, $code );

			case 'sms':
				return class_exists( 'ReportedIP_Hive_Two_Factor_SMS' )
					&& ReportedIP_Hive_Two_Factor_SMS::verify_code( $user_id, $code );

			case 'webauthn':
				return class_exists( 'ReportedIP_Hive_Two_Factor_WebAuthn' )
					&& ReportedIP_Hive_Two_Factor_WebAuthn::verify( $user_id, $code );

			case 'recovery':
				return ReportedIP_Hive_Two_Factor_Recovery::verify_code( $user_id, $code );

			default:
				return false;
		}
	}

	/**
	 * Validate the login nonce from the cookie against the stored transient.
	 *
	 * @return array|false Nonce data array or false if invalid.
	 */
	private function validate_login_nonce() {
		if ( ! isset( $_COOKIE[ self::NONCE_COOKIE ] ) ) {
			return false;
		}

		$token      = sanitize_text_field( wp_unslash( $_COOKIE[ self::NONCE_COOKIE ] ) );
		$token_hash = hash( 'sha256', $token );
		$nonce_data = get_transient( self::NONCE_PREFIX . $token_hash );

		if ( false === $nonce_data || ! is_array( $nonce_data ) || empty( $nonce_data['user_id'] ) ) {
			return false;
		}

		$current_ip = ReportedIP_Hive::get_client_ip();
		if ( isset( $nonce_data['ip'] ) && $nonce_data['ip'] !== $current_ip ) {
			return false;
		}

		return $nonce_data;
	}

	/**
	 * Clean up the login nonce (transient + cookie).
	 */
	private function cleanup_login_nonce() {
		if ( isset( $_COOKIE[ self::NONCE_COOKIE ] ) ) {
			$token      = sanitize_text_field( wp_unslash( $_COOKIE[ self::NONCE_COOKIE ] ) );
			$token_hash = hash( 'sha256', $token );
			delete_transient( self::NONCE_PREFIX . $token_hash );
		}

		setcookie(
			self::NONCE_COOKIE,
			'',
			array(
				'expires'  => time() - YEAR_IN_SECONDS,
				'path'     => COOKIEPATH,
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Strict',
			)
		);
	}

	/**
	 * Create a form nonce for CSRF protection on the 2FA challenge form.
	 *
	 * Standard WordPress nonces are tied to the logged-in user, which doesn't
	 * exist during the 2FA challenge. We use an HMAC-based token instead.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string Nonce token.
	 */
	private function create_form_nonce( $user_id ) {
		$token = bin2hex( random_bytes( 16 ) );
		set_transient( 'reportedip_2fa_form_' . hash( 'sha256', $token ), $user_id, self::NONCE_TTL );
		return $token;
	}

	/**
	 * Verify a form nonce from the 2FA challenge form.
	 *
	 * @param string $token   Nonce token from the form.
	 * @param int    $user_id Expected user ID.
	 * @return bool True if valid.
	 */
	private function verify_form_nonce( $token, $user_id ) {
		if ( empty( $token ) ) {
			return false;
		}
		$key       = 'reportedip_2fa_form_' . hash( 'sha256', $token );
		$stored_id = get_transient( $key );
		delete_transient( $key );
		return (int) $stored_id === (int) $user_id;
	}

	/**
	 * Verify a trusted device cookie.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool True if trusted device is valid.
	 */
	private function verify_trusted_device( $user_id ) {
		if ( ! get_option( 'reportedip_hive_2fa_trusted_devices', true ) ) {
			return false;
		}

		if ( ! isset( $_COOKIE[ self::TRUSTED_COOKIE ] ) ) {
			return false;
		}

		$token      = sanitize_text_field( wp_unslash( $_COOKIE[ self::TRUSTED_COOKIE ] ) );
		$token_hash = hash( 'sha256', $token );

		global $wpdb;
		$table = self::get_trusted_table();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name built from $wpdb->prefix and a hardcoded constant; safe.
		$device = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM $table WHERE token_hash = %s AND user_id = %d AND expires_at > NOW()",
				$token_hash,
				$user_id
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		if ( ! $device ) {
			return false;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->update(
			$table,
			array( 'last_used_at' => current_time( 'mysql' ) ),
			array( 'id' => $device->id ),
			array( '%s' ),
			array( '%d' )
		);

		return true;
	}

	/**
	 * Create a trusted device entry for the current browser.
	 *
	 * @param int $user_id WordPress user ID.
	 */
	private function create_trusted_device( $user_id ) {
		$token      = bin2hex( random_bytes( 64 ) );
		$token_hash = hash( 'sha256', $token );
		$days       = (int) get_option( 'reportedip_hive_2fa_trusted_device_days', 30 );
		$expiry     = time() + ( $days * DAY_IN_SECONDS );

		$user_agent  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$device_name = substr( $user_agent, 0, 255 );

		global $wpdb;
		$table = self::get_trusted_table();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->insert(
			$table,
			array(
				'user_id'     => $user_id,
				'token_hash'  => $token_hash,
				'device_name' => $device_name,
				'ip_address'  => ReportedIP_Hive::get_client_ip(),
				'created_at'  => current_time( 'mysql' ),
				'expires_at'  => gmdate( 'Y-m-d H:i:s', $expiry ),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s' )
		);

		$secure = is_ssl();
		setcookie(
			self::TRUSTED_COOKIE,
			$token,
			array(
				'expires'  => $expiry,
				'path'     => COOKIEPATH,
				'domain'   => COOKIE_DOMAIN,
				'secure'   => $secure,
				'httponly' => true,
				'samesite' => 'Strict',
			)
		);
	}

	/**
	 * Increment failed 2FA attempts with escalating lockout.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return int New total failed attempt count.
	 */
	private function increment_failed_attempts( $user_id ) {
		$data = get_user_meta( $user_id, self::META_FAILED_ATTEMPTS, true );
		$data = ! empty( $data ) ? json_decode( $data, true ) : array();

		if ( ! is_array( $data ) ) {
			$data = array();
		}

		$count = ( $data['count'] ?? 0 ) + 1;
		$now   = time();

		$lockout_until = 0;
		foreach ( self::LOCKOUT_THRESHOLDS as $threshold => $duration ) {
			if ( $count >= $threshold ) {
				$lockout_until = $now + $duration;
			}
		}

		$data = array(
			'count'         => $count,
			'last_attempt'  => $now,
			'lockout_until' => $lockout_until,
		);

		update_user_meta( $user_id, self::META_FAILED_ATTEMPTS, wp_json_encode( $data ) );

		return $count;
	}

	/**
	 * Get remaining lockout seconds for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return int Seconds remaining (0 if no lockout).
	 */
	private function get_lockout_remaining( $user_id ) {
		$data = get_user_meta( $user_id, self::META_FAILED_ATTEMPTS, true );
		if ( empty( $data ) ) {
			return 0;
		}
		$data = json_decode( $data, true );
		if ( ! is_array( $data ) || empty( $data['lockout_until'] ) ) {
			return 0;
		}
		return max( 0, (int) $data['lockout_until'] - time() );
	}

	/**
	 * Reset failed 2FA attempts after successful verification.
	 *
	 * @param int $user_id WordPress user ID.
	 */
	private function reset_failed_attempts( $user_id ) {
		delete_user_meta( $user_id, self::META_FAILED_ATTEMPTS );
	}

	/**
	 * Seconds still remaining on the per-IP lockout (0 if none).
	 *
	 * Uses the same escalation thresholds as the per-user lockout so admins
	 * don't have to tune two schemas in parallel.
	 *
	 * @param string $ip
	 * @return int
	 */
	private function get_ip_lockout_remaining( $ip ) {
		if ( empty( $ip ) || 'unknown' === $ip ) {
			return 0;
		}
		$key  = 'reportedip_2fa_ip_attempts_' . md5( $ip );
		$data = get_transient( $key );
		if ( ! is_array( $data ) || empty( $data['lockout_until'] ) ) {
			return 0;
		}
		return max( 0, (int) $data['lockout_until'] - time() );
	}

	/**
	 * Increment the per-IP failure counter and set escalating lockout.
	 *
	 * @param string $ip
	 */
	private function increment_ip_failed_attempts( $ip ) {
		if ( empty( $ip ) || 'unknown' === $ip ) {
			return;
		}
		$key  = 'reportedip_2fa_ip_attempts_' . md5( $ip );
		$data = get_transient( $key );
		$data = is_array( $data ) ? $data : array();
		$now  = time();

		$count         = (int) ( $data['count'] ?? 0 ) + 1;
		$lockout_until = 0;
		foreach ( self::LOCKOUT_THRESHOLDS as $threshold => $duration ) {
			if ( $count >= $threshold ) {
				$lockout_until = $now + $duration;
			}
		}

		set_transient(
			$key,
			array(
				'count'         => $count,
				'last_attempt'  => $now,
				'lockout_until' => $lockout_until,
			),
			HOUR_IN_SECONDS
		);

		/*
		 * Graduate to a real DB block when the per-IP 2FA throttle reaches
		 * its top step. 15 wrong codes in a one-hour window is unambiguous
		 * brute force — the transient lockout was capping the response at
		 * one hour and forgetting; promoting to wp_reportedip_hive_blocked
		 * via handle_threshold_exceeded() runs the canonical post-trip
		 * pipeline (auto-block with progressive escalation, community-mode
		 * API report, admin notification, daily-stats bump) so the 2FA
		 * brute-forcer is treated identically to any other sensor trip.
		 */
		$top_threshold = (int) max( array_keys( self::LOCKOUT_THRESHOLDS ) );
		if ( $count >= $top_threshold && class_exists( 'ReportedIP_Hive' ) ) {
			$client  = ReportedIP_Hive::get_instance();
			$monitor = $client->get_security_monitor();
			if ( $monitor instanceof ReportedIP_Hive_Security_Monitor ) {
				$monitor->handle_threshold_exceeded(
					$ip,
					'2fa_brute_force',
					array(
						'attempts'  => $count,
						'threshold' => $top_threshold,
						'window'    => 'transient',
					)
				);
				delete_transient( $key );
			}
		}
	}

	/**
	 * Enqueue scripts and styles on the WordPress login page.
	 */
	public function enqueue_login_scripts() {
		$action      = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$is_2fa_page = ( self::ACTION_CHALLENGE === $action );

		wp_enqueue_script(
			'reportedip-hive-two-factor-login',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/two-factor-login.js',
			array(),
			REPORTEDIP_HIVE_VERSION,
			true
		);

		wp_localize_script(
			'reportedip-hive-two-factor-login',
			'reportedip2fa',
			array(
				'resendUrl' => wp_login_url() . '?action=' . self::ACTION_CHALLENGE . '&resend_email=1',
				'ajaxUrl'   => admin_url( 'admin-ajax.php' ),
				'strings'   => array(
					'newCodeSent'          => __( 'New code sent.', 'reportedip-hive' ),
					'sendingFailed'        => __( 'Sending failed.', 'reportedip-hive' ),
					'sessionExpired'       => __( 'Your session has expired. Please sign in again.', 'reportedip-hive' ),
					'passkeyRequesting'    => __( 'Passkey request in progress…', 'reportedip-hive' ),
					'passkeyOptionsFailed' => __( 'Failed to fetch passkey options.', 'reportedip-hive' ),
					'passkeyVerifyFailed'  => __( 'Verification failed.', 'reportedip-hive' ),
					'passkeyCancelled'     => __( 'Passkey login cancelled.', 'reportedip-hive' ),
				),
			)
		);

		wp_set_script_translations(
			'reportedip-hive-two-factor-login',
			'reportedip-hive',
			REPORTEDIP_HIVE_LANGUAGES_DIR
		);

		if ( $is_2fa_page ) {
			wp_enqueue_style(
				'reportedip-hive-design-system',
				REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/design-system.css',
				array(),
				REPORTEDIP_HIVE_VERSION
			);
			wp_enqueue_style(
				'reportedip-hive-two-factor',
				REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/two-factor.css',
				array( 'reportedip-hive-design-system' ),
				REPORTEDIP_HIVE_VERSION
			);
		}
	}

	/**
	 * Render the 2FA challenge page using the template.
	 *
	 * @param array $data Template data.
	 */
	private function render_challenge_page( $data ) {
		$template = REPORTEDIP_HIVE_PLUGIN_DIR . 'templates/two-factor-challenge.php';
		if ( file_exists( $template ) ) {
			extract( $data, EXTR_SKIP ); // phpcs:ignore WordPress.PHP.DontExtract.extract_extract -- Template rendering, controlled data
			include $template;
		} else {
			wp_die(
				esc_html__( '2FA template not found.', 'reportedip-hive' ),
				esc_html__( 'Error', 'reportedip-hive' ),
				array( 'response' => 500 )
			);
		}
	}

	/**
	 * Get the full trusted devices table name.
	 *
	 * @return string Table name with prefix.
	 */
	private static function get_trusted_table() {
		global $wpdb;
		return $wpdb->prefix . self::TABLE_TRUSTED_DEVICES;
	}

	/**
	 * Revoke a specific trusted device.
	 *
	 * @param int $device_id Device row ID.
	 * @param int $user_id   User ID (for authorization check).
	 * @return bool True if revoked.
	 */
	public static function revoke_trusted_device( $device_id, $user_id ) {
		global $wpdb;
		$table = self::get_trusted_table();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$deleted = $wpdb->delete(
			$table,
			array(
				'id'      => $device_id,
				'user_id' => $user_id,
			),
			array( '%d', '%d' )
		);

		return (bool) $deleted;
	}

	/**
	 * Revoke all trusted devices for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return int Number of devices revoked.
	 */
	public static function revoke_all_trusted_devices( $user_id ) {
		global $wpdb;
		$table = self::get_trusted_table();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->delete(
			$table,
			array( 'user_id' => $user_id ),
			array( '%d' )
		);
	}

	/**
	 * Get all trusted devices for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return array Array of device objects.
	 */
	public static function get_trusted_devices( $user_id ) {
		global $wpdb;
		$table = self::get_trusted_table();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name built from $wpdb->prefix and a hardcoded constant; safe.
		$results = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM $table WHERE user_id = %d ORDER BY created_at DESC",
				$user_id
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		return $results;
	}

	/**
	 * Clean up expired trusted devices (called from cron).
	 *
	 * @return int Number of expired devices removed.
	 */
	public static function cleanup_expired_devices() {
		global $wpdb;
		$table = self::get_trusted_table();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Safe: table name from $wpdb->prefix; no user input in SQL.
		return (int) $wpdb->query( "DELETE FROM $table WHERE expires_at < NOW()" );
	}

	/**
	 * Enable 2FA for a user (activates one method; other methods stay untouched).
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $method  2FA method (totp, email, webauthn, sms).
	 */
	public static function enable_for_user( $user_id, $method = 'totp' ) {
		update_user_meta( $user_id, self::META_ENABLED, '1' );

		update_user_meta( $user_id, self::META_METHOD, $method );

		$method_key = self::get_method_meta_key( $method );
		if ( $method_key ) {
			update_user_meta( $user_id, $method_key, '1' );
		}

		if ( ! get_user_meta( $user_id, self::META_SETUP_DATE, true ) ) {
			update_user_meta( $user_id, self::META_SETUP_DATE, time() );
		}

		delete_user_meta( $user_id, self::META_SKIP_COUNT );
		unset( self::$methods_cache[ $user_id ] );

		if ( 0 === ReportedIP_Hive_Two_Factor_Recovery::get_remaining_count( $user_id ) ) {
			ReportedIP_Hive_Two_Factor_Recovery::regenerate_codes( $user_id );
		}

		if ( class_exists( 'ReportedIP_Hive_Two_Factor_Onboarding' ) ) {
			delete_transient( ReportedIP_Hive_Two_Factor_Onboarding::TRANSIENT_PREFIX . $user_id );
		}

		/**
		 * Fires after a 2FA method has been activated for a user.
		 *
		 * Used by ReportedIP_Hive_Two_Factor_Recommend to clear the login-reminder
		 * counter; available for any third-party listener that needs to react to
		 * a method going live (audit log, welcome mail, …).
		 *
		 * @since 1.6.1
		 * @param int    $user_id The user whose method became active.
		 * @param string $method  Method id: totp | email | sms | webauthn.
		 */
		do_action( 'reportedip_hive_2fa_method_enabled', (int) $user_id, (string) $method );
	}

	/**
	 * Disable a single 2FA method for a user.
	 *
	 * If no methods remain active, fully disables 2FA for the user.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $method  Method to disable.
	 * @return bool True if disabled.
	 */
	public static function disable_method( $user_id, $method ) {
		$method_key = self::get_method_meta_key( $method );
		if ( ! $method_key ) {
			return false;
		}
		delete_user_meta( $user_id, $method_key );

		switch ( $method ) {
			case self::METHOD_TOTP:
				delete_user_meta( $user_id, self::META_TOTP_SECRET );
				delete_user_meta( $user_id, self::META_TOTP_CONFIRMED );
				break;
			case self::METHOD_WEBAUTHN:
				delete_user_meta( $user_id, self::META_WEBAUTHN_CREDENTIALS );
				break;
			case self::METHOD_SMS:
				delete_user_meta( $user_id, self::META_SMS_NUMBER );
				break;
		}

		unset( self::$methods_cache[ $user_id ] );

		$remaining = self::get_user_enabled_methods( $user_id );
		if ( empty( $remaining ) ) {
			self::disable_for_user( $user_id );
			return true;
		}

		$primary = get_user_meta( $user_id, self::META_METHOD, true );
		if ( $primary === $method ) {
			update_user_meta( $user_id, self::META_METHOD, $remaining[0] );
		}

		return true;
	}

	/**
	 * Disable 2FA for a user and clean up all related data.
	 *
	 * @param int $user_id WordPress user ID.
	 */
	public static function disable_for_user( $user_id ) {
		$meta_keys = array(
			self::META_ENABLED,
			self::META_METHOD,
			self::META_TOTP_SECRET,
			self::META_TOTP_CONFIRMED,
			self::META_TOTP_ENABLED,
			self::META_EMAIL_ENABLED,
			self::META_WEBAUTHN_ENABLED,
			self::META_WEBAUTHN_CREDENTIALS,
			self::META_SMS_ENABLED,
			self::META_SMS_NUMBER,
			self::META_FAILED_ATTEMPTS,
			self::META_SETUP_DATE,
			self::META_ENFORCEMENT_START,
			self::META_SKIP_COUNT,
			self::META_KNOWN_DEVICES,
		);

		foreach ( $meta_keys as $key ) {
			delete_user_meta( $user_id, $key );
		}

		unset( self::$methods_cache[ $user_id ] );

		ReportedIP_Hive_Two_Factor_Recovery::delete_codes( $user_id );
		self::revoke_all_trusted_devices( $user_id );
		if ( class_exists( 'ReportedIP_Hive_Two_Factor_Onboarding' ) ) {
			delete_transient( ReportedIP_Hive_Two_Factor_Onboarding::TRANSIENT_PREFIX . $user_id );
		}
	}

	/**
	 * Mask an email address for display (e.g., p***@example.com).
	 *
	 * @param string $email Email address.
	 * @return string Masked email.
	 */
	public static function mask_email( $email ) {
		$parts = explode( '@', $email );
		if ( count( $parts ) !== 2 ) {
			return '***@***';
		}
		$local  = $parts[0];
		$domain = $parts[1];
		$masked = substr( $local, 0, 1 ) . str_repeat( '*', max( 1, strlen( $local ) - 1 ) );
		return $masked . '@' . $domain;
	}

	/**
	 * Get all user meta keys used by 2FA (for data cleanup/export).
	 *
	 * @return array List of meta key strings.
	 */
	public static function get_all_meta_keys() {
		return array(
			self::META_ENABLED,
			self::META_METHOD,
			self::META_TOTP_SECRET,
			self::META_TOTP_CONFIRMED,
			self::META_TOTP_ENABLED,
			self::META_EMAIL_ENABLED,
			self::META_WEBAUTHN_ENABLED,
			self::META_WEBAUTHN_CREDENTIALS,
			self::META_SMS_ENABLED,
			self::META_SMS_NUMBER,
			self::META_FAILED_ATTEMPTS,
			self::META_SETUP_DATE,
			self::META_ENFORCEMENT_START,
			self::META_SKIP_COUNT,
			self::META_KNOWN_DEVICES,
			ReportedIP_Hive_Two_Factor_Recovery::META_KEY_CODES,
			ReportedIP_Hive_Two_Factor_Recovery::META_KEY_REMAINING,
		);
	}
}
