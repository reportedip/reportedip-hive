<?php
/**
 * Two-Factor Authentication Orchestrator for ReportedIP Hive.
 *
 * Intercepts the WordPress login flow to enforce 2FA verification.
 * Manages login nonces, trusted devices, and brute-force protection.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
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
 *
 * A challenged login never passes through `wp_signon()`: the authenticate
 * filter redirects into the challenge before core reaches its `wp_login`
 * call. The success branch of {@see self::handle_2fa_challenge()} therefore
 * fires the hooks itself once the second factor has been verified:
 *
 *   - `do_action( 'reportedip_hive_2fa_verified', $user_id, $method, $context )`
 *     with the verified method and the challenge context (`wp_login`, the
 *     context of a surface an add-on renders, `theme_frame` for the
 *     storefront; `rest` from the REST verify route).
 *   - `do_action( 'wp_login', $user_login, $user )` exactly as `wp_signon()`
 *     does, so audit trail, geo anomaly, new-device mail and the 2FA reminder
 *     see a challenged login like any other.
 *
 * The consumed-nonce replay ({@see self::maybe_replay_consumed_nonce()})
 * re-issues the same session and does not fire either hook again.
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
	 * Login nonce TTL in seconds (15 minutes).
	 *
	 * @var int
	 */
	const NONCE_TTL = 900;

	/**
	 * Transient prefix for consumed-nonce markers. Written the moment a
	 * challenge verifies successfully so a duplicate submit of the same
	 * form (auto-submit racing an Enter press or button click) can be
	 * replayed into the identical sign-in instead of hitting the
	 * "session expired" page.
	 *
	 * @var string
	 * @since 2.1.24
	 */
	const NONCE_CONSUMED_PREFIX = 'reportedip_2fa_done_';

	/**
	 * Lifetime of a consumed-nonce marker in seconds. Long enough to
	 * cover a duplicate POST racing the winning one, short enough that
	 * the replay window stays negligible next to the just-issued auth
	 * session it mirrors.
	 *
	 * @var int
	 * @since 2.1.24
	 */
	const NONCE_CONSUMED_TTL = 90;

	/**
	 * User meta keys.
	 */
	const META_ENABLED        = 'reportedip_hive_2fa_enabled';
	const META_METHOD         = 'reportedip_hive_2fa_method';
	const META_TOTP_SECRET    = 'reportedip_hive_2fa_totp_secret';
	const META_TOTP_CONFIRMED = 'reportedip_hive_2fa_totp_confirmed';

	/**
	 * Secret of an authenticator setup that has not been confirmed yet.
	 *
	 * Held separately so an abandoned re-enrolment cannot destroy the working
	 * secret, and so an unconfirmed secret is never a valid second factor:
	 * the verifier only ever reads META_TOTP_SECRET.
	 *
	 * @var string
	 */
	const META_TOTP_SECRET_PENDING = 'reportedip_hive_2fa_totp_secret_pending';

	/**
	 * Highest TOTP time step already accepted for this user.
	 *
	 * Enforces single use of a code (RFC 6238 §5.2): every step up to and
	 * including this one is spent, so a captured code cannot be replayed for
	 * the rest of its validity window in another session.
	 *
	 * @var string
	 */
	const META_TOTP_LAST_STEP    = 'reportedip_hive_2fa_totp_last_step';
	const META_FAILED_ATTEMPTS   = 'reportedip_hive_2fa_failed_attempts';
	const META_SETUP_DATE        = 'reportedip_hive_2fa_setup_date';
	const META_ENFORCEMENT_START = 'reportedip_hive_2fa_enforcement_start';

	const META_TOTP_ENABLED     = 'reportedip_hive_2fa_totp_enabled';
	const META_EMAIL_ENABLED    = 'reportedip_hive_2fa_email_enabled';
	const META_WEBAUTHN_ENABLED = 'reportedip_hive_2fa_webauthn_enabled';

	const META_WEBAUTHN_CREDENTIALS = 'reportedip_hive_2fa_webauthn_credentials';

	const META_SKIP_COUNT    = 'reportedip_hive_2fa_skip_count';
	const META_KNOWN_DEVICES = 'reportedip_hive_2fa_known_devices';

	/**
	 * Sign-in history behind the adaptive step-up triggers, as one JSON blob.
	 *
	 * Declared here so uninstall and the GDPR paths know the key without
	 * loading the class that records it.
	 *
	 * @var string
	 */
	const META_LOGIN_CONTEXT = 'reportedip_hive_login_context';

	/**
	 * Prefix of every user meta key that belongs to the second factor, the
	 * keys of methods an add-on registers included. A full reset, the GDPR
	 * eraser and the uninstall remove by this prefix, so the data of a
	 * method whose add-on is inactive does not survive them.
	 *
	 * @var string
	 * @since 3.0.0
	 */
	const META_PREFIX = 'reportedip_hive_2fa_';

	/**
	 * The user's choice to stop the 2FA reminder banner.
	 *
	 * @var string
	 * @since 3.0.0
	 */
	const META_REMINDER_OPTOUT = 'reportedip_hive_2fa_reminder_optout';

	/**
	 * Prefixed user meta a full reset keeps, exactly the keys 2.1.x left in
	 * place: the reminder opt-out (a preference), the failed password-reset
	 * challenge counter (a lockout must not be reset by turning 2FA off) and
	 * the WebAuthn user handle (stable per account, so a key registered
	 * later still maps to the same user). The GDPR eraser, the uninstall
	 * and the full data reset remove them like every other prefixed key.
	 *
	 * @var string[]
	 * @since 3.0.0
	 */
	const META_KEEP_ON_RESET = array(
		self::META_REMINDER_OPTOUT,
		'reportedip_hive_2fa_reset_failed_attempts',
		'reportedip_hive_2fa_webauthn_user_handle',
	);

	/**
	 * Prefix of a step-up verdict that names a trigger which fired for an
	 * account without a usable method: the sign-in goes on with the
	 * password and the skip is logged as `2fa_stepup_skipped_no_method`.
	 *
	 * @var string
	 * @since 3.0.0
	 */
	const STEPUP_NO_METHOD_PREFIX = 'no_method:';

	/**
	 * Cap on the unregistered method slugs the allowed-methods option keeps,
	 * so slugs from a crafted form post, import or push cannot pile up.
	 *
	 * @var int
	 * @since 3.0.0
	 */
	const MAX_UNREGISTERED_ALLOWED = 16;

	/**
	 * Shape of a method slug. A stored slug of this shape that no active
	 * plugin registers is kept in the allowed-methods option, see
	 * {@see self::sanitize_allowed_methods()}.
	 *
	 * @var string
	 * @since 3.0.0
	 */
	const METHOD_SLUG_PATTERN = '/^[a-z0-9_]{1,32}$/';

	/**
	 * 2FA method identifiers.
	 */
	const METHOD_TOTP     = 'totp';
	const METHOD_EMAIL    = 'email';
	const METHOD_WEBAUTHN = 'webauthn';
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
	 * Singleton-light handle so an add-on that serves the challenge on its
	 * own surface can dispatch it through the same instance that owns the
	 * authentication hooks, without re-registering them.
	 *
	 * @var ReportedIP_Hive_Two_Factor|null
	 * @since 1.7.0
	 */
	private static $instance = null;

	/**
	 * Return the bootstrapped instance, or lazily create one. Both code
	 * paths run the constructor exactly once because the constructor's
	 * own re-entry guard short-circuits subsequent `new` calls.
	 *
	 * @return ReportedIP_Hive_Two_Factor
	 * @since  1.7.0
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor, registers authentication hooks.
	 *
	 * 2FA hooks run on every request (not just admin) because wp-login.php
	 * is not admin context. The authenticate filter runs at priority 99,
	 * after WordPress core password verification (priority 20) and the
	 * plugin's own IP reputation check (wp_authenticate_user, priority 10).
	 */
	public function __construct() {
		if ( null !== self::$instance ) {
			return;
		}
		self::$instance = $this;

		if ( ! self::is_globally_enabled() ) {
			return;
		}

		add_filter( 'authenticate', array( $this, 'filter_authenticate' ), 99, 3 );
		add_action( 'login_form_' . self::ACTION_CHALLENGE, array( $this, 'handle_2fa_challenge' ) );
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_scripts' ) );
		add_action( 'login_footer', array( $this, 'render_login_attribution' ) );
		add_filter( 'wp_login_errors', array( $this, 'filter_login_errors' ), 10, 2 );

		add_action( 'wp_ajax_nopriv_reportedip_2fa_resend', array( $this, 'ajax_resend_code' ) );
		add_action( 'wp_ajax_reportedip_2fa_resend', array( $this, 'ajax_resend_code' ) );

		add_action( 'wp_logout', array( $this, 'cleanup_on_logout' ), 10, 1 );
	}

	/**
	 * AJAX handler: resend the one-time code of a method that sends one
	 * (email, or a method an add-on registers with a `send` callable)
	 * during the 2FA challenge.
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

		$definition = self::methods()[ $method ] ?? array();
		if ( ! isset( $definition['send'] ) || ! is_callable( $definition['send'] ) ) {
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

		$result      = call_user_func( $definition['send'], $user_id );
		$cooldown    = isset( $definition['resend_wait'] ) && is_callable( $definition['resend_wait'] ) ? (int) call_user_func( $definition['resend_wait'], $user_id ) : 0;
		$destination = isset( $definition['mask'] ) && is_callable( $definition['mask'] ) ? (string) call_user_func( $definition['mask'], $user_id ) : '';

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
				'message'     => (string) ( $definition['resent_message'] ?? __( 'New code sent.', 'reportedip-hive' ) ),
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

		self::set_secure_cookie( self::NONCE_COOKIE, $token, time() + self::NONCE_TTL );
	}

	/**
	 * wp_logout callback, clear challenge cookies and transients.
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
				esc_html__( 'Secured by %1$sReportedIP%2$s, Open Threat Intelligence for a Safer Internet.', 'reportedip-hive' ),
				'<a href="https://reportedip.com/" target="_blank" rel="noopener">',
				'</a>'
			);
			?>
		</p>
		<?php
	}

	public function cleanup_on_logout( $user_id = 0 ) {
		if ( isset( $_COOKIE[ self::NONCE_COOKIE ] ) ) {
			$token = sanitize_text_field( wp_unslash( $_COOKIE[ self::NONCE_COOKIE ] ) );
			delete_transient( self::NONCE_CONSUMED_PREFIX . hash( 'sha256', $token ) );
		}
		$this->cleanup_login_nonce();
		if ( $user_id && class_exists( 'ReportedIP_Hive_Two_Factor_Onboarding' ) ) {
			delete_transient( ReportedIP_Hive_Two_Factor_Onboarding::TRANSIENT_PREFIX . (int) $user_id );
		}
	}

	/**
	 * Stretch the WP auth cookie lifetime for 2FA-verified remember-me logins
	 * from 14 days (core default) to 30 days, stronger auth earns longer
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
		return (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_enabled_global', false );
	}

	/**
	 * Request-level cache for get_user_enabled_methods() results.
	 * Invalidated in enable_for_user / disable_method / disable_for_user.
	 *
	 * @var array<int, string[]>
	 */
	private static $methods_cache = array();

	/**
	 * Memoised method registry, see {@see self::methods()}.
	 *
	 * @var array<string, array<string, mixed>>|null
	 */
	private static $registry_cache = null;

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
	 * Multisite-aware (since 2.0.0): Super Admins are required to use 2FA
	 * unconditionally when `reportedip_hive_2fa_enforce_super_admins` is on
	 * (default). Normal roles are checked against the resolved enforcement
	 * list (`network ∪ site_extra`), so a Site Admin can extend the list
	 * for the local site but cannot drop a role the Super Admin requires.
	 *
	 * @param \WP_User $user WordPress user object.
	 * @return bool True if the user's role requires 2FA.
	 */
	public static function is_enforced_for_user( $user ) {
		if ( is_multisite() && function_exists( 'is_super_admin' ) && is_super_admin( $user->ID ) ) {
			$super_required = (bool) ReportedIP_Hive_Option_Routing::get(
				'reportedip_hive_2fa_enforce_super_admins',
				true
			);
			if ( $super_required ) {
				return true;
			}
		}

		$enforce_roles = ReportedIP_Hive_Option_Routing::resolve_2fa_enforce_roles();
		if ( empty( $enforce_roles ) ) {
			return false;
		}

		foreach ( (array) $user->roles as $role ) {
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
		$grace_days = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_enforce_grace_days', 7 );
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
	 * Decide how to handle a login by an enforced user who has no 2FA method
	 * configured and whose grace period and skip quota are both exhausted.
	 *
	 * Returns 'allow' to let the login through (the onboarding redirect and the
	 * skip-less setup wizard then force enrolment), or 'lockout' to reject the
	 * login outright. The hard lockout is only returned when the site policy
	 * option is explicitly set to 'lockout' and the user is not privileged.
	 * administrators and super admins are never locked out, so a site can never
	 * be left without a sign-in-capable administrator.
	 *
	 * @param \WP_User $user User attempting to sign in.
	 * @return string 'allow' or 'lockout'.
	 * @since  2.1.22
	 */
	public static function resolve_no_method_action( $user ) {
		$in_grace = self::is_in_grace_period( $user->ID );
		if ( $in_grace ) {
			return 'allow';
		}

		$skip_count = (int) get_user_meta( $user->ID, self::META_SKIP_COUNT, true );
		$max_skips  = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_max_skips', 3 );
		$exhausted  = $max_skips > 0 && $skip_count >= $max_skips;
		if ( ! $exhausted ) {
			return 'allow';
		}

		$action = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_enforce_action', 'enroll' );
		if ( 'lockout' !== $action ) {
			return 'allow';
		}

		if ( user_can( $user, 'manage_options' ) || is_super_admin( $user->ID ) ) {
			return 'allow';
		}

		return 'lockout';
	}

	/**
	 * Whether the site policy currently permits a verification method.
	 *
	 * The enrolment surfaces each need to refuse a disallowed method in their
	 * own idiom (JSON, WP-CLI), so they share the predicate rather than the
	 * response. {@see self::activate_method()} enforces the same rule as the
	 * last line of defence.
	 *
	 * @param string $method Method identifier.
	 * @return bool
	 * @since  2.1.44
	 */
	public static function is_method_allowed( $method ) {
		return in_array( (string) $method, self::get_allowed_methods(), true );
	}

	/**
	 * Methods the user configured, before the site policy is applied.
	 *
	 * {@see self::get_user_enabled_methods()} intersects this with the allowed
	 * list and therefore cannot answer "did this user ever set up a factor?"
	 * once the policy stopped permitting it, which is exactly what the
	 * silent-loss warning on the login path needs to know.
	 *
	 * Includes the legacy single-method meta, so accounts that predate the
	 * per-method flags are not treated as never having configured anything.
	 *
	 * Only registered methods count ({@see self::methods()}); the flag of a
	 * method whose add-on is inactive is left alone and shows up through
	 * {@see self::unavailable_method()} instead.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string[] Method identifiers.
	 * @since  2.1.44
	 */
	public static function configured_method_flags( $user_id ) {
		$configured = array();
		foreach ( self::methods() as $method => $definition ) {
			if ( get_user_meta( $user_id, (string) $definition['meta_key'], true ) ) {
				$configured[] = (string) $method;
			}
		}

		if ( empty( $configured ) && get_user_meta( $user_id, self::META_ENABLED, true ) ) {
			$primary = get_user_meta( $user_id, self::META_METHOD, true );
			if ( in_array( $primary, array( self::METHOD_TOTP, self::METHOD_EMAIL ), true ) ) {
				$configured[] = $primary;
			}
		}

		return $configured;
	}

	/**
	 * The default method of an account whose second factor this site cannot
	 * verify right now.
	 *
	 * That is an account with 2FA turned on and no usable method (no
	 * registered method it configured is allowed by the site policy) that
	 * also set up a method no active plugin registers: its stored default
	 * names such a method, or it carries the enabled flag
	 * (`reportedip_hive_2fa_{slug}_enabled`) of one. Such an account is
	 * challenged with its recovery codes instead of signing in with the
	 * password alone, and the data of the missing method stays untouched, so
	 * the method works again once its add-on returns.
	 *
	 * Only a slug the stored allowed-methods option still names counts: a
	 * method the site policy dropped would not have been asked for in
	 * 2.1.x either, the account signs in with the policy warning instead.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string Slug of the unavailable method, '' when the account is not affected.
	 * @since  3.0.0
	 */
	public static function unavailable_method( $user_id ) {
		if ( ! get_user_meta( $user_id, self::META_ENABLED, true ) || array() !== self::get_user_enabled_methods( $user_id ) ) {
			return '';
		}
		$policy = self::stored_allowed_slugs();
		$stored = (string) get_user_meta( $user_id, self::META_METHOD, true );
		if ( '' !== $stored && ! isset( self::methods()[ $stored ] ) && in_array( $stored, $policy, true ) ) {
			return $stored;
		}
		$unregistered = array_values( array_intersect( self::unregistered_method_flags( $user_id ), $policy ) );
		return empty( $unregistered ) ? '' : $unregistered[0];
	}

	/**
	 * The raw allowed-methods option, unregistered slugs included.
	 *
	 * @return string[]
	 * @since  3.0.0
	 */
	private static function stored_allowed_slugs() {
		return array_map( 'strval', ReportedIP_Hive_Option_Routing::to_array( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_allowed_methods', '["totp","email","webauthn"]' ) ) );
	}

	/**
	 * Slugs of the methods the user turned on that no active plugin
	 * registers, read from their enabled flags.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string[]
	 * @since  3.0.0
	 */
	private static function unregistered_method_flags( $user_id ) {
		$registered = array();
		foreach ( self::methods() as $definition ) {
			$registered[] = (string) $definition['meta_key'];
		}
		$pattern = '/^' . preg_quote( self::META_PREFIX, '/' ) . '([a-z0-9_]{1,32})_enabled$/';
		$slugs   = array();
		foreach ( (array) get_user_meta( $user_id ) as $key => $value ) {
			$flag = is_array( $value ) ? reset( $value ) : $value;
			if ( $flag && ! in_array( (string) $key, $registered, true ) && preg_match( $pattern, (string) $key, $match ) ) {
				$slugs[] = $match[1];
			}
		}
		return $slugs;
	}

	/**
	 * Return the list of 2FA methods the user has actively configured.
	 *
	 * Supports parallel activation (e.g. TOTP + E-Mail + Passkey at once).
	 * Falls back to legacy single-method meta for backward compatibility.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string[] Method identifiers (slugs of registered methods).
	 */
	public static function get_user_enabled_methods( $user_id ) {
		if ( isset( self::$methods_cache[ $user_id ] ) ) {
			return self::$methods_cache[ $user_id ];
		}

		$methods = self::configured_method_flags( $user_id );

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
	 * Centralises the JSON-decode so callers don't each repeat it. Only
	 * registered methods are returned: a stored slug no active plugin
	 * provides is kept in the option ({@see self::sanitize_allowed_methods()})
	 * but never offered, enrolled or verified.
	 *
	 * @return string[] Method identifiers.
	 */
	public static function get_allowed_methods() {
		$raw     = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_allowed_methods', '["totp","email","webauthn"]' );
		$allowed = self::filter_valid_methods( ReportedIP_Hive_Option_Routing::to_array( $raw ) );
		return empty( $allowed ) ? array( self::METHOD_TOTP, self::METHOD_EMAIL ) : $allowed;
	}

	/**
	 * Settings filter of the allowed-methods option: the registered methods
	 * of the new list, plus every slug of a method no active plugin
	 * registers, from the new list and from the stored one.
	 *
	 * The settings form can only post the methods it shows, so without the
	 * stored slugs a save on a site whose add-on is inactive would drop the
	 * add-on's method from the policy for good. The kept slugs have no
	 * effect while nobody registers them, see get_allowed_methods(). At most
	 * {@see self::MAX_UNREGISTERED_ALLOWED} of them are kept, the excess is
	 * dropped.
	 *
	 * @param array<int, mixed> $methods Candidate method slugs.
	 * @return string[]
	 * @since  3.0.0
	 */
	public static function sanitize_allowed_methods( array $methods ) {
		$known   = self::valid_methods();
		$stored  = array_filter(
			ReportedIP_Hive_Option_Routing::to_array( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_allowed_methods', '[]' ) ),
			static function ( $slug ) use ( $known ) {
				return ! in_array( $slug, $known, true );
			}
		);
		$result  = array();
		$unknown = 0;
		foreach ( array_merge( $methods, $stored ) as $slug ) {
			if ( ! is_scalar( $slug ) ) {
				continue;
			}
			$slug = (string) $slug;
			if ( in_array( $slug, $result, true ) ) {
				continue;
			}
			if ( in_array( $slug, $known, true ) ) {
				$result[] = $slug;
			} elseif ( 1 === preg_match( self::METHOD_SLUG_PATTERN, $slug ) && $unknown < self::MAX_UNREGISTERED_ALLOWED ) {
				$result[] = $slug;
				++$unknown;
			}
		}
		return $result;
	}

	/**
	 * The verification methods a site may offer for enrolment.
	 *
	 * Single source of truth for the allowed-method allow-list: the setup wizard,
	 * the settings-form sanitiser, tier-upgrade and settings import all validate
	 * against this list. METHOD_RECOVERY is intentionally excluded, recovery
	 * codes are an automatic fallback, not a method an admin opts into.
	 *
	 * @return string[] Method identifiers, the slugs of {@see self::methods()}.
	 * @since  2.0.28
	 */
	public static function valid_methods() {
		return array_keys( self::methods() );
	}

	/**
	 * The verification methods this site knows, core ones first.
	 *
	 * Each entry carries `meta_key` (the user's enabled flag), `label`,
	 * `prompt` and the callable `verify( $user_id, $code )`, plus the
	 * optional callables `send( $user_id )`, `resend_wait( $user_id )`,
	 * `mask( $user_id )` and `health( $user_id )` (returns '' while the
	 * method is usable, otherwise a short reason shown to administrators),
	 * the optional `icon` (inner SVG markup of its challenge tab, passed
	 * through {@see self::kses_icon()}) and the optional `data_keys`
	 * (further user meta the method owns, removed together with it).
	 *
	 * Further optional keys: `choice_label` (the method's name in the
	 * allowed-methods list of the settings, `label` when absent),
	 * `choice_lock` (callable returning '' while an administrator may allow
	 * the method, otherwise the name of the plan it needs; the choice is
	 * then shown disabled with that plan, and a stored choice stays stored),
	 * `resent_message` (the confirmation after a resend), `expired_message`
	 * (the error after a wrong code while the callable
	 * `code_active( $user_id )` reports no active code). The core methods
	 * render their panels in the
	 * templates; a method an add-on registers renders its own through the
	 * actions `reportedip_hive_2fa_challenge_panel_{slug}`,
	 * `reportedip_hive_2fa_onboarding_panel_{slug}` and
	 * `reportedip_hive_2fa_method_flow_{slug}`.
	 *
	 * @return array<string, array<string, mixed>> Method slug to definition.
	 * @since  3.0.0
	 */
	public static function methods() {
		if ( null !== self::$registry_cache ) {
			return self::$registry_cache;
		}
		$core = array(
			self::METHOD_TOTP     => array(
				'meta_key'     => self::META_TOTP_ENABLED,
				'label'        => __( 'Authenticator app', 'reportedip-hive' ),
				'choice_label' => __( 'Authenticator app (TOTP)', 'reportedip-hive' ),
				'prompt'       => __( 'Enter the 6-digit code from your authenticator app', 'reportedip-hive' ),
				'verify'       => array( 'ReportedIP_Hive_Two_Factor_Verifier', 'verify_totp' ),
			),
			self::METHOD_EMAIL    => array(
				'meta_key'        => self::META_EMAIL_ENABLED,
				'label'           => __( 'Email code', 'reportedip-hive' ),
				'choice_label'    => __( 'E-mail code', 'reportedip-hive' ),
				'prompt'          => __( 'Enter the 6-digit code from the email', 'reportedip-hive' ),
				'verify'          => array( 'ReportedIP_Hive_Two_Factor_Email', 'verify_code' ),
				'send'            => array( 'ReportedIP_Hive_Two_Factor_Email', 'send_code' ),
				'resend_wait'     => array( 'ReportedIP_Hive_Two_Factor_Email', 'get_resend_wait_seconds' ),
				'mask'            => static function ( $user_id ) {
					$user = get_userdata( (int) $user_id );
					return $user ? self::mask_email( (string) $user->user_email ) : '';
				},
				'resent_message'  => __( 'We have sent you a new code by email.', 'reportedip-hive' ),
				'expired_message' => __( 'No valid code is active, you likely used an older code. Please click "Resend code" and use only the most recent code from your inbox.', 'reportedip-hive' ),
				'code_active'     => static function ( $user_id ) {
					return (bool) get_transient( 'reportedip_2fa_email_' . (int) $user_id );
				},
			),
			self::METHOD_WEBAUTHN => array(
				'meta_key'     => self::META_WEBAUTHN_ENABLED,
				'label'        => __( 'Passkey / security key', 'reportedip-hive' ),
				'choice_label' => __( 'Security key / passkey', 'reportedip-hive' ),
				'prompt'       => __( 'Confirm your passkey or security key when prompted', 'reportedip-hive' ),
				'verify'       => array( 'ReportedIP_Hive_Two_Factor_WebAuthn', 'verify' ),
			),
		);

		/**
		 * Register further verification methods.
		 *
		 * A core slug cannot be replaced (the core entries are merged back
		 * over the result), and an entry without `meta_key` or `verify`
		 * is dropped.
		 *
		 * @param array<string, array<string, mixed>> $methods Method slug to definition, see methods().
		 * @since 3.0.0
		 */
		$methods = (array) apply_filters( 'reportedip_hive_2fa_methods', $core );
		foreach ( $methods as $slug => $definition ) {
			if ( ! is_string( $slug ) || ! is_array( $definition ) || empty( $definition['meta_key'] ) || empty( $definition['verify'] ) || self::METHOD_RECOVERY === $slug ) {
				unset( $methods[ $slug ] );
			}
		}
		self::$registry_cache = array_merge( $core, $methods, $core );
		return self::$registry_cache;
	}

	/**
	 * Forget the memoised method registry and the per-user method lists
	 * built from it, so a method registered after the first read (or a
	 * test) is picked up.
	 *
	 * @return void
	 * @since  3.0.0
	 */
	public static function flush_methods() {
		self::$registry_cache = null;
		self::$methods_cache  = array();
	}

	/**
	 * Every user meta key the registered methods own: each enabled flag plus
	 * the method's `data_keys`. A reset or an uninstall clears the data of an
	 * add-on method this way while the add-on is active; while it is
	 * inactive that data stays untouched.
	 *
	 * @return string[]
	 * @since  3.0.0
	 */
	private static function method_meta_keys() {
		$keys = array();
		foreach ( self::methods() as $definition ) {
			$keys[] = (string) $definition['meta_key'];
			foreach ( (array) ( $definition['data_keys'] ?? array() ) as $key ) {
				$keys[] = (string) $key;
			}
		}
		return $keys;
	}

	/**
	 * Reduce an arbitrary list of method slugs to the valid, de-duplicated set,
	 * preserving the input order.
	 *
	 * @param array<int, mixed> $methods Candidate method slugs.
	 * @return string[]
	 * @since  2.0.28
	 */
	public static function filter_valid_methods( array $methods ) {
		return array_values( array_unique( array_intersect( array_map( 'strval', $methods ), self::valid_methods() ) ) );
	}

	/**
	 * Reduce an arbitrary list of role slugs to the ones that actually exist on
	 * this site, de-duplicated and preserving the input order.
	 *
	 * @param array<int, mixed> $roles Candidate role slugs.
	 * @return string[]
	 * @since  2.0.28
	 */
	public static function filter_valid_roles( array $roles ) {
		$valid = function_exists( 'wp_roles' ) ? array_keys( wp_roles()->get_names() ) : array();
		return array_values( array_unique( array_intersect( array_map( 'strval', $roles ), $valid ) ) );
	}

	/**
	 * Map a method identifier to its "enabled" user-meta key.
	 *
	 * @param string $method Method identifier.
	 * @return string|null Meta key or null for unknown methods.
	 */
	public static function get_method_meta_key( $method ) {
		$methods = self::methods();
		return isset( $methods[ $method ] ) ? (string) $methods[ $method ]['meta_key'] : null;
	}

	/**
	 * Check whether the current client IP is in the admin-configured bypass allowlist.
	 *
	 * Supports single IPs and CIDR blocks (IPv4 + IPv6). Lines starting with '#' are comments.
	 *
	 * @return bool True if current IP is allowlisted.
	 */
	public static function is_ip_allowlisted() {
		$raw = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_ip_allowlist', '' );
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
	 * Authenticate filter, intercept login when 2FA is required.
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
			&& ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_xmlrpc_app_password_only', false )
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
		$unavailable     = $has_any_method ? '' : self::unavailable_method( $user->ID );
		$is_enforced     = self::is_enforced_for_user( $user );

		/**
		 * Ask for the second factor although the device is trusted.
		 *
		 * Return a non-empty trigger name to force the challenge: a hit
		 * skips the trusted-device bypass, while the `reportedip_2fa_bypass`
		 * filter and the IP allowlist still win. A name that starts with
		 * {@see self::STEPUP_NO_METHOD_PREFIX} records that a trigger fired
		 * for an account without a usable method and is no step-up: the
		 * account signs in as it would without the trigger.
		 *
		 * @param string   $stepup         Trigger name or empty string.
		 * @param \WP_User $user           The signing-in user.
		 * @param bool     $has_any_method Whether the user has a usable method.
		 * @param bool     $is_enforced    Whether the user's role enforces 2FA.
		 * @since 3.0.0
		 */
		$stepup = (string) apply_filters( 'reportedip_hive_2fa_stepup', '', $user, $has_any_method, $is_enforced );

		/*
		 * A `no_method:` verdict only records that a trigger fired for an
		 * account without a usable method. It is no step-up: the trusted
		 * device still counts and no `2fa_stepup_required` row is written,
		 * otherwise an account left with recovery codes only would spend a
		 * code on every sign-in.
		 */
		if ( 0 === strpos( $stepup, self::STEPUP_NO_METHOD_PREFIX ) ) {
			ReportedIP_Hive_Logger::get_instance()->log_security_event(
				'2fa_stepup_skipped_no_method',
				ReportedIP_Hive::get_client_ip(),
				array(
					'user_id' => $user->ID,
					'trigger' => substr( $stepup, strlen( self::STEPUP_NO_METHOD_PREFIX ) ),
				),
				'low'
			);
			$stepup = '';
		}

		if ( ! $has_any_method && ! $is_enforced && '' === $unavailable ) {
			/*
			 * The enabled list is intersected with the site's allowed methods,
			 * so removing a method from that policy silently drops the second
			 * factor of everyone who used only that one. Log it: the account
			 * goes back to password-only, which nobody involved asked for and
			 * nothing else would record.
			 */
			$configured = self::configured_method_flags( $user->ID );
			if ( ! empty( $configured ) ) {
				ReportedIP_Hive_Logger::get_instance()->warning(
					'2FA inactive: the user\'s only configured method is no longer permitted by the site policy',
					ReportedIP_Hive::get_client_ip(),
					array(
						'user_id'          => $user->ID,
						'allowed_methods'  => self::get_allowed_methods(),
						'configured_flags' => $configured,
					)
				);
			}

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

		if ( '' === $stepup && $this->verify_trusted_device( $user->ID ) ) {
			return $user;
		}

		if ( ! $has_any_method && '' === $unavailable ) {
			if ( 'lockout' === self::resolve_no_method_action( $user ) ) {
				return new \WP_Error(
					'reportedip_2fa_setup_required',
					__( '<strong>Two-factor authentication required.</strong> Your skip quota is exhausted. Please contact an administrator to reset 2FA.', 'reportedip-hive' )
				);
			}

			return $user;
		}

		if ( '' !== $unavailable ) {
			/*
			 * The account turned 2FA on with a method no active plugin
			 * provides any more. Signing in with the password alone would
			 * drop the second factor without anyone asking for it, so the
			 * challenge runs with the recovery codes, and the entry tells
			 * an administrator why the user cannot use their usual method.
			 */
			ReportedIP_Hive_Logger::get_instance()->warning(
				'2FA method unavailable: the user\'s only configured method is not provided by any active plugin, recovery code required',
				ReportedIP_Hive::get_client_ip(),
				array(
					'user_id' => $user->ID,
					'method'  => $unavailable,
				)
			);
		}

		$should_challenge = (bool) apply_filters(
			'reportedip_2fa_should_challenge',
			true,
			$user,
			array(
				'enabled_methods' => $enabled_methods,
				'enforced'        => $is_enforced,
				'stepup'          => $stepup,
			)
		);
		if ( ! $should_challenge ) {
			return $user;
		}

		if ( '' !== $stepup ) {
			/**
			 * Signals of the current sign-in, read for the step-up log row.
			 *
			 * @param array{country:string} $signals Signals; `country` is the ISO code or ''.
			 * @since 3.0.0
			 */
			$signals = (array) apply_filters( 'reportedip_hive_2fa_login_signals', array( 'country' => '' ) );
			ReportedIP_Hive_Logger::get_instance()->log_security_event(
				'2fa_stepup_required',
				ReportedIP_Hive::get_client_ip(),
				array(
					'user_id' => $user->ID,
					'trigger' => $stepup,
					'country' => (string) ( $signals['country'] ?? '' ),
				),
				'low'
			);
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

		/**
		 * Extra fields stored with a started challenge, read back by the
		 * listeners of `reportedip_hive_2fa_redirect_url`. The key `origin`
		 * names the surface the sign-in came from and is handed to
		 * `reportedip_hive_2fa_challenge_url`. The core fields above always
		 * win over an extra field of the same name.
		 *
		 * @param array<string,mixed> $extra Extra fields, empty by default.
		 * @param \WP_User           $user  The challenged user.
		 * @since 3.0.0
		 */
		$nonce_data = array_merge( (array) apply_filters( 'reportedip_hive_2fa_challenge_payload', array(), $user ), $nonce_data );
		set_transient( self::NONCE_PREFIX . $token_hash, $nonce_data, self::NONCE_TTL );

		self::set_secure_cookie( self::NONCE_COOKIE, $token, time() + self::NONCE_TTL );

		$challenge_url = self::resolve_challenge_url( (string) ( $nonce_data['origin'] ?? '' ) );

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
	 * Absolute URL of the 2FA challenge page: the wp-login.php interstitial
	 * unless a listener routes the sign-in to another surface.
	 *
	 * @param string $origin Origin token from the challenge payload, '' for wp-login.
	 * @return string
	 * @since  1.7.0
	 */
	public static function resolve_challenge_url( $origin ) {
		$default = wp_login_url() . '?action=' . self::ACTION_CHALLENGE;

		/**
		 * Route a challenge to another surface than wp-login.php.
		 *
		 * @param string $url    Challenge URL.
		 * @param string $origin Origin token from the challenge payload, '' for wp-login.
		 * @since 3.0.0
		 */
		return (string) apply_filters( 'reportedip_hive_2fa_challenge_url', $default, (string) $origin );
	}

	/**
	 * Where the challenge sends the browser next. The URL passed in is the
	 * wp-login target; a listener that renders the challenge on its own
	 * surface returns the target of that surface. The result passes the
	 * same host check as `wp_safe_redirect()`: a target on another host,
	 * from the stored `redirect_to` or from a listener, becomes the
	 * dashboard, so a caller that stores or replays the URL never holds an
	 * open redirect.
	 *
	 * @param string              $event      `verified` (second factor passed), `locked` (session invalidated after too many wrong codes) or `signed_in` (the challenge URL was opened by a signed-in visitor).
	 * @param string              $url        The wp-login target.
	 * @param string              $context    Challenge context.
	 * @param array<string,mixed> $nonce_data Stored challenge payload, empty for `signed_in`.
	 * @return string
	 * @since  3.0.0
	 */
	private static function challenge_redirect( $event, $url, $context, array $nonce_data ) {
		/**
		 * Target of a redirect the challenge issues.
		 *
		 * @param string              $url        The wp-login target.
		 * @param string              $event      `verified`, `locked` or `signed_in`.
		 * @param string              $context    Challenge context, `wp_login` or the context of an add-on surface.
		 * @param array<string,mixed> $nonce_data Stored challenge payload, empty for `signed_in`.
		 * @since 3.0.0
		 */
		$target = (string) apply_filters( 'reportedip_hive_2fa_redirect_url', (string) $url, (string) $event, (string) $context, $nonce_data );
		$safe   = (string) wp_validate_redirect( $target, '' );
		return '' !== $safe ? $safe : admin_url();
	}

	/**
	 * Normalise the challenge context: `wp_login` for the login_form action
	 * (which passes no argument), otherwise the key an add-on passed in.
	 *
	 * @param mixed $context Raw context.
	 * @return string
	 * @since  3.0.0
	 */
	private static function challenge_context( $context ) {
		$context = is_string( $context ) ? sanitize_key( $context ) : '';
		return '' === $context ? 'wp_login' : $context;
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
	 * login_form_reportedip_2fa action hook. An add-on that serves the
	 * challenge on its own surface calls it with its context; the page is
	 * then rendered by the listeners of
	 * `reportedip_hive_2fa_render_challenge_{context}` and
	 * `reportedip_hive_2fa_render_expired_{context}`, and wp-login renders
	 * when nobody listens.
	 *
	 * @param string $context `wp_login` or the context of an add-on surface.
	 * @return void
	 */
	public function handle_2fa_challenge( $context = 'wp_login' ) {
		$context    = self::challenge_context( $context );
		$nonce_data = $this->validate_login_nonce();
		if ( false === $nonce_data ) {
			$this->maybe_replay_consumed_nonce();
			$this->maybe_redirect_logged_in_user( $context );
			$this->render_session_expired_page( 'expired', $context );
			exit;
		}

		$user_id = $nonce_data['user_id'];
		$user    = get_userdata( $user_id );
		if ( ! $user ) {
			$this->cleanup_login_nonce();
			$this->render_session_expired_page( 'unknown_user', $context );
			exit;
		}

		$this->refresh_login_nonce( $nonce_data );

		$method = self::get_user_method( $user_id );
		$error  = '';

		$request_method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'POST' === $request_method ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Selects which method tab re-renders after a failed attempt; validated against $allowed_methods below and only acted upon (verified) once verify_form_nonce() passes.
			$submitted_method = isset( $_POST['reportedip_2fa_method'] ) ? sanitize_key( wp_unslash( $_POST['reportedip_2fa_method'] ) ) : '';
			if ( '' !== $submitted_method ) {
				$method = $submitted_method;
			}

			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- The submitted nonce is verified by verify_form_nonce() on the next line.
			$form_nonce = isset( $_POST['_reportedip_2fa_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['_reportedip_2fa_nonce'] ) ) : '';
			if ( ! $this->verify_form_nonce( $form_nonce, $user_id ) ) {
				$error = __( 'Security check failed. Please try again.', 'reportedip-hive' );
			} else {
				$lockout_remaining = max(
					$this->get_lockout_remaining( $user_id ),
					self::ip_lockout_remaining( ReportedIP_Hive::get_client_ip() )
				);
				if ( $lockout_remaining > 0 ) {
					$error = sprintf(
						/* translators: %d: seconds remaining */
						__( 'Too many failed attempts. Please wait %d seconds.', 'reportedip-hive' ),
						$lockout_remaining
					);
				} else {
					// phpcs:disable WordPress.Security.NonceVerification.Missing -- Form nonce verified by verify_form_nonce() above.
					$submitted_code = isset( $_POST['reportedip_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['reportedip_2fa_code'] ) ) : '';
					$trust_device   = ! empty( $_POST['reportedip_2fa_trust_device'] );
					// phpcs:enable WordPress.Security.NonceVerification.Missing

					$verified = $this->verify_2fa_code( $user_id, $submitted_code, $method );

					if ( $verified ) {
						$this->reset_failed_attempts( $user_id );

						$remember    = ! empty( $nonce_data['remember'] );
						$redirect_to = self::resolve_post_verify_redirect( $nonce_data, $context );

						$this->mark_login_nonce_consumed( $user_id, $remember, $redirect_to );
						$this->cleanup_login_nonce();

						$this->set_auth_cookie_with_remember( $user_id, $remember );
						wp_set_current_user( $user_id );

						do_action( 'reportedip_hive_2fa_verified', (int) $user_id, (string) $method, (string) $context );
						// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core login hook re-fired on purpose: wp_signon() never runs for a challenged sign-in.
						do_action( 'wp_login', $user->user_login, $user );

						/*
						 * A trust wish ticked on an earlier (failed) attempt of this same
						 * challenge session still counts: the re-rendered form used to lose
						 * the checkbox state, silently dropping the "trust this device"
						 * choice the user had already made.
						 */
						$trust_requested = $trust_device || ! empty( $nonce_data['trust_wanted'] );
						if ( $trust_requested && ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_trusted_devices', true ) ) {
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

						wp_safe_redirect( $redirect_to );
						exit;
					} else {
						if ( $trust_device && empty( $nonce_data['trust_wanted'] ) ) {
							$nonce_data['trust_wanted'] = 1;
							$this->refresh_login_nonce( $nonce_data );
						}

						$failed = $this->increment_failed_attempts( $user_id );
						self::record_ip_failure( ReportedIP_Hive::get_client_ip() );

						$error = self::wrong_code_message( (int) $user_id, (string) $submitted_method );
						if ( $failed >= self::SESSION_INVALIDATION_THRESHOLD ) {
							$this->cleanup_login_nonce();

							$logger = ReportedIP_Hive_Logger::get_instance();
							$logger->warning(
								'2FA brute force detected, session invalidated',
								ReportedIP_Hive::get_client_ip(),
								array(
									'user_id'  => $user_id,
									'attempts' => $failed,
								)
							);

							wp_safe_redirect( self::challenge_redirect( 'locked', wp_login_url() . '?reportedip_2fa_locked=1', $context, $nonce_data ) );
							exit;
						}
					}
				}
			}
		}

		$allowed_methods = self::get_user_enabled_methods( $user_id );

		$resent = self::send_requested_codes( (int) $user_id, $allowed_methods );
		if ( '' !== $resent['method'] ) {
			$method = $resent['method'];
		}
		if ( '' !== $resent['error'] ) {
			$error = $resent['error'];
		}

		$form_nonce = $this->create_form_nonce( $user_id );

		/*
		 * No usable method left (the one the account uses is not provided by
		 * any active plugin, see unavailable_method()): the page offers the
		 * recovery codes and says why, instead of tabs for methods the user
		 * never set up.
		 */
		if ( ! in_array( $method, $allowed_methods, true ) ) {
			$method = empty( $allowed_methods ) ? self::METHOD_RECOVERY : $allowed_methods[0];
		}

		$template_data = array(
			'user'            => $user,
			'method'          => $method,
			'error'           => $error,
			'form_nonce'      => $form_nonce,
			'allowed_methods' => $allowed_methods,
			'trust_enabled'   => (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_trusted_devices', true ),
			'resend_wait'     => ReportedIP_Hive_Two_Factor_Email::get_resend_wait_seconds( $user_id ),
			'recovery_count'  => ReportedIP_Hive_Two_Factor_Recovery::get_remaining_count( $user_id ),
			'email_code_sent' => in_array( self::METHOD_EMAIL, $allowed_methods, true )
				? (bool) get_transient( 'reportedip_2fa_email_' . $user_id )
				: false,
		);

		if ( 'wp_login' !== $context && has_action( 'reportedip_hive_2fa_render_challenge_' . $context ) ) {
			/**
			 * Render the challenge of a non wp-login surface. Without a
			 * listener, wp-login renders it.
			 *
			 * @param int                 $user_id The challenged user.
			 * @param array<string,mixed> $view    Template variables: user, method, error, form_nonce, allowed_methods, trust_enabled, resend_wait, recovery_count, email_code_sent.
			 * @since 3.0.0
			 */
			do_action( 'reportedip_hive_2fa_render_challenge_' . $context, (int) $user_id, $template_data );
		} else {
			$this->render_challenge_page( $template_data );
		}
		exit;
	}

	/**
	 * Server-side resend for clients without JavaScript: `?resend_{slug}=1`
	 * sends a fresh code for each method of the user that can send one.
	 *
	 * Only the methods passed in are considered, the ones the user has
	 * enabled; a method the account never set up never sends.
	 *
	 * @param int      $user_id The challenged user.
	 * @param string[] $enabled The user's enabled methods.
	 * @return array{method:string,error:string} Last method that was asked to send ('' for none) and the send error ('' for none).
	 * @since  3.0.0
	 */
	private static function send_requested_codes( $user_id, array $enabled ) {
		$outcome = array(
			'method' => '',
			'error'  => '',
		);
		foreach ( $enabled as $slug ) {
			$send = self::methods()[ $slug ]['send'] ?? null;
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only trigger; the user is identified by the signed challenge cookie, and the send is rate-limited per method.
			if ( ! is_callable( $send ) || ! isset( $_GET[ 'resend_' . $slug ] ) || '1' !== $_GET[ 'resend_' . $slug ] ) {
				continue;
			}
			$result = call_user_func( $send, $user_id );
			if ( is_wp_error( $result ) ) {
				$outcome['error'] = $result->get_error_message();
			}
			$outcome['method'] = (string) $slug;
		}
		return $outcome;
	}

	/**
	 * The error after a wrong code: the method's `expired_message` while it
	 * reports no active code, the generic sentence otherwise.
	 *
	 * @param int    $user_id The challenged user.
	 * @param string $method  The submitted method.
	 * @return string
	 * @since  3.0.0
	 */
	private static function wrong_code_message( $user_id, $method ) {
		$definition = self::methods()[ $method ] ?? array();
		if ( isset( $definition['expired_message'], $definition['code_active'] ) && is_callable( $definition['code_active'] ) && ! call_user_func( $definition['code_active'], $user_id ) ) {
			return (string) $definition['expired_message'];
		}
		return __( 'Invalid verification code. Please make sure you are using the most recent code.', 'reportedip-hive' );
	}

	/**
	 * Escape the SVG markup of a method icon: the `svg` element and the
	 * shapes `path`, `rect`, `polyline`, `polygon`, `circle` and `line`
	 * with their geometry and stroke attributes, nothing else. An icon may
	 * come from an add-on's registry entry.
	 *
	 * @param string $markup Icon markup.
	 * @return string
	 * @since  3.0.0
	 */
	public static function kses_icon( $markup ) {
		$shape = array_fill_keys( array( 'd', 'points', 'x', 'y', 'x1', 'x2', 'y1', 'y2', 'cx', 'cy', 'r', 'rx', 'ry', 'width', 'height', 'fill', 'stroke', 'stroke-width', 'stroke-linecap', 'stroke-linejoin' ), true );
		return wp_kses(
			(string) $markup,
			array(
				'svg'      => array_fill_keys( array( 'viewbox', 'fill', 'stroke', 'stroke-width', 'stroke-linecap', 'stroke-linejoin', 'width', 'height', 'aria-hidden', 'xmlns' ), true ),
				'path'     => $shape,
				'rect'     => $shape,
				'polyline' => $shape,
				'polygon'  => $shape,
				'circle'   => $shape,
				'line'     => $shape,
			)
		);
	}

	/**
	 * Pick the URL to send the user to after a successful 2FA verify: the
	 * stored `redirect_to`, else the dashboard, unless a listener of
	 * `reportedip_hive_2fa_redirect_url` routes the surface it rendered.
	 *
	 * @param array<string,mixed> $nonce_data Persisted challenge payload.
	 * @param string              $context    Challenge context.
	 * @return string Absolute URL.
	 * @since  1.7.0
	 */
	public static function resolve_post_verify_redirect( $nonce_data, $context = 'wp_login' ) {
		$nonce_data  = (array) $nonce_data;
		$redirect_to = isset( $nonce_data['redirect_to'] ) ? (string) $nonce_data['redirect_to'] : '';

		return self::challenge_redirect( 'verified', '' !== $redirect_to ? $redirect_to : admin_url(), (string) $context, $nonce_data );
	}

	/**
	 * Verify a 2FA code based on the method.
	 *
	 * The method arrives from the challenge form, so it is checked against the
	 * factors actually live for this user before any credential material is
	 * touched. Without that, a method the site policy no longer permits, or
	 * one the user disabled, still authenticated as long as its stored secret
	 * was left behind, because the verifier is a pure per-method switch. The
	 * REST and password-reset surfaces have always gated their input this way.
	 *
	 * Recovery codes are deliberately always eligible: they are the way back
	 * in when every configured factor is unavailable.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $code    Submitted verification code.
	 * @param string $method  Verification method (totp, email, recovery).
	 * @return bool True if verified.
	 */
	private function verify_2fa_code( $user_id, $code, $method ) {
		$eligible = array_merge( self::get_user_enabled_methods( (int) $user_id ), array( self::METHOD_RECOVERY ) );

		if ( ! in_array( (string) $method, $eligible, true ) ) {
			return false;
		}

		return ReportedIP_Hive_Two_Factor_Verifier::verify_method(
			(int) $user_id,
			(string) $method,
			(string) $code
		);
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

		self::set_secure_cookie( self::NONCE_COOKIE, '', time() - YEAR_IN_SECONDS );
	}

	/**
	 * Persist a short-lived "consumed" marker for the current login nonce.
	 *
	 * Written in the success branch right before {@see cleanup_login_nonce()}
	 * deletes the nonce transient. A duplicate submit of the same challenge
	 * form (the auto-submit racing an Enter press or a button click) arrives
	 * with the same cookie token but finds the nonce gone; the marker lets
	 * {@see maybe_replay_consumed_nonce()} finish that duplicate with the
	 * identical sign-in instead of the "session expired" page.
	 *
	 * @param int    $user_id     Verified user.
	 * @param bool   $remember    Remember-me flag captured at password login.
	 * @param string $redirect_to Resolved post-verify redirect target.
	 * @return void
	 * @since  2.1.24
	 */
	private function mark_login_nonce_consumed( $user_id, $remember, $redirect_to ) {
		if ( ! isset( $_COOKIE[ self::NONCE_COOKIE ] ) ) {
			return;
		}
		$token      = sanitize_text_field( wp_unslash( $_COOKIE[ self::NONCE_COOKIE ] ) );
		$token_hash = hash( 'sha256', $token );

		set_transient(
			self::NONCE_CONSUMED_PREFIX . $token_hash,
			array(
				'user_id'     => (int) $user_id,
				'remember'    => (bool) $remember,
				'redirect_to' => (string) $redirect_to,
				'ip'          => ReportedIP_Hive::get_client_ip(),
			),
			self::NONCE_CONSUMED_TTL
		);
	}

	/**
	 * Replay a duplicate challenge request whose nonce was already consumed
	 * by a successful verification moments ago.
	 *
	 * The bearer presents the same 256-bit token (HttpOnly, Secure,
	 * SameSite=Strict cookie) that just passed the second factor, from the
	 * same IP, inside a {@see NONCE_CONSUMED_TTL} window, the replay
	 * therefore re-issues the identical auth cookie and redirect the winning
	 * request already produced. The marker is left in place so every
	 * duplicate within the window lands correctly; it expires on its own.
	 *
	 * Exits on hit; returns normally when no marker matches.
	 *
	 * @return void
	 * @since  2.1.24
	 */
	private function maybe_replay_consumed_nonce() {
		if ( ! isset( $_COOKIE[ self::NONCE_COOKIE ] ) ) {
			return;
		}
		$token      = sanitize_text_field( wp_unslash( $_COOKIE[ self::NONCE_COOKIE ] ) );
		$token_hash = hash( 'sha256', $token );
		$consumed   = get_transient( self::NONCE_CONSUMED_PREFIX . $token_hash );

		if ( ! is_array( $consumed ) || empty( $consumed['user_id'] ) ) {
			return;
		}
		if ( isset( $consumed['ip'] ) && ReportedIP_Hive::get_client_ip() !== $consumed['ip'] ) {
			return;
		}

		$user_id = (int) $consumed['user_id'];
		if ( ! get_userdata( $user_id ) ) {
			return;
		}

		$this->set_auth_cookie_with_remember( $user_id, ! empty( $consumed['remember'] ) );
		wp_set_current_user( $user_id );

		$logger = ReportedIP_Hive_Logger::get_instance();
		$logger->info(
			'2FA duplicate submit replayed after successful verification',
			ReportedIP_Hive::get_client_ip(),
			array( 'user_id' => $user_id )
		);

		$redirect_to = ! empty( $consumed['redirect_to'] ) ? (string) $consumed['redirect_to'] : admin_url();
		wp_safe_redirect( $redirect_to );
		exit;
	}

	/**
	 * Redirect an already-authenticated visitor away from the challenge
	 * instead of showing the "session expired" page, a stale tab, a reload
	 * of the challenge URL or a bookmarked challenge link is not an error
	 * for someone who is signed in.
	 *
	 * Exits on hit; returns normally for anonymous visitors.
	 *
	 * @param string $context Challenge context.
	 * @return void
	 * @since  2.1.24
	 */
	private function maybe_redirect_logged_in_user( $context ) {
		if ( ! is_user_logged_in() ) {
			return;
		}

		wp_safe_redirect( self::challenge_redirect( 'signed_in', admin_url(), $context, array() ) );
		exit;
	}

	/**
	 * Set the WordPress auth cookie, honouring the extended-remember option.
	 *
	 * Centralises the `auth_cookie_expiration` filter sandwich so the
	 * success branch and the consumed-nonce replay issue byte-identical
	 * sessions.
	 *
	 * @param int  $user_id  User to sign in.
	 * @param bool $remember Remember-me flag.
	 * @return void
	 * @since  2.1.24
	 */
	private function set_auth_cookie_with_remember( $user_id, $remember ) {
		$extended = $remember && ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_extended_remember', false );

		if ( $extended ) {
			add_filter( 'auth_cookie_expiration', array( __CLASS__, 'filter_extended_cookie_expiration' ), 20, 3 );
		}
		wp_set_auth_cookie( $user_id, $remember );
		if ( $extended ) {
			remove_filter( 'auth_cookie_expiration', array( __CLASS__, 'filter_extended_cookie_expiration' ), 20 );
		}
	}

	/**
	 * Render a stand-alone "two-factor session expired" page.
	 *
	 * Replaces the previous silent `wp_safe_redirect( wp_login_url() )` that
	 * left users staring at a clean login form after the 2FA nonce had timed
	 * out (NONCE_TTL = 15 min) or after the SameSite=Strict nonce cookie was
	 * dropped, the latter happens routinely when wp-login.php is loaded
	 * inside an iframe, which is what triggered the original bug report.
	 *
	 * Mirrors the bypass-the-login_errors-pipeline approach used by
	 * {@see dispatch_browser_challenge_redirect()}: we render directly so
	 * third-party hardening plugins that override `login_errors` cannot strip
	 * the explanation.
	 *
	 * @param string $reason  One of 'expired', 'unknown_user'.
	 * @param string $context Challenge context.
	 * @return void
	 * @since  1.6.5
	 */
	private function render_session_expired_page( $reason = 'expired', $context = 'wp_login' ) {
		$messages = array(
			'expired'      => __( 'Your two-factor session has expired. This happens after 15 minutes of inactivity, or when the security cookie is missing, for example when the login form is loaded inside an iframe. Please sign in again.', 'reportedip-hive' ),
			'unknown_user' => __( 'The user account from your two-factor session is no longer available. Please sign in again.', 'reportedip-hive' ),
		);
		$message  = isset( $messages[ $reason ] ) ? $messages[ $reason ] : $messages['expired'];

		nocache_headers();

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

		if ( 'wp_login' !== $context && has_action( 'reportedip_hive_2fa_render_expired_' . $context ) ) {
			/**
			 * Render the "session expired" page of a non wp-login surface.
			 * Without a listener, wp-login renders it.
			 *
			 * @param string $message Explanation for the visitor.
			 * @param string $reason  `expired` or `unknown_user`.
			 * @since 3.0.0
			 */
			do_action( 'reportedip_hive_2fa_render_expired_' . $context, $message, (string) $reason );
			return;
		}

		login_header(
			__( 'Two-Factor Verification', 'reportedip-hive' ),
			'',
			new \WP_Error( 'reportedip_2fa_session_expired', $message )
		);
		?>
		<p class="rip-2fa-session-expired-actions" style="text-align:center;margin-top:1.5em;">
			<a class="rip-button rip-button--primary" href="<?php echo esc_url( wp_login_url() ); ?>" target="_top" rel="noopener">
				<?php esc_html_e( 'Back to login', 'reportedip-hive' ); ?>
			</a>
		</p>
		<?php
		login_footer();
	}

	/**
	 * Translate ReportedIP-Hive 2FA query flags into wp-login error messages.
	 *
	 * Two flags are recognised:
	 *   - `?reportedip_2fa_locked=1` , set by {@see handle_2fa_challenge()}
	 *     when the brute-force counter trips SESSION_INVALIDATION_THRESHOLD;
	 *     before this filter the flag was set but never read, so the user
	 *     landed on a clean login form with zero feedback.
	 *   - `?reportedip_2fa_expired=1`, reserved for callers that prefer a
	 *     redirect over the inline `render_session_expired_page()` shell
	 *     (e.g. integrations that redirect from outside the challenge handler).
	 *
	 * @param \WP_Error $errors      Existing login errors.
	 * @param string    $redirect_to Login redirect target (unused).
	 * @return \WP_Error
	 * @since  1.6.5
	 */
	public function filter_login_errors( $errors, $redirect_to ) {
		unset( $redirect_to );

		if ( ! ( $errors instanceof \WP_Error ) ) {
			$errors = new \WP_Error();
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only flag check; no state change is performed.
		$locked  = isset( $_GET['reportedip_2fa_locked'] ) && '1' === sanitize_text_field( wp_unslash( $_GET['reportedip_2fa_locked'] ) );
		$expired = isset( $_GET['reportedip_2fa_expired'] ) && '1' === sanitize_text_field( wp_unslash( $_GET['reportedip_2fa_expired'] ) );
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		if ( $locked ) {
			$errors->add(
				'reportedip_2fa_locked',
				__( 'Too many failed verification attempts. Your two-factor session was invalidated for security. Please sign in again.', 'reportedip-hive' )
			);
		}
		if ( $expired ) {
			$errors->add(
				'reportedip_2fa_session_expired',
				__( 'Your two-factor session expired. Please sign in again.', 'reportedip-hive' )
			);
		}

		return $errors;
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
		if ( ! ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_trusted_devices', true ) ) {
			return false;
		}

		if ( ! isset( $_COOKIE[ self::TRUSTED_COOKIE ] ) ) {
			return false;
		}

		$token      = sanitize_text_field( wp_unslash( $_COOKIE[ self::TRUSTED_COOKIE ] ) );
		$token_hash = hash( 'sha256', $token );

		global $wpdb;
		$table = self::get_trusted_table();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name built from Schema::table() with a hardcoded suffix; safe.
		$device = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM $table WHERE token_hash = %s AND user_id = %d AND expires_at > UTC_TIMESTAMP()",
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
			array( 'last_used_at' => current_time( 'mysql', true ) ),
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
		$days       = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_trusted_device_days', 30 );
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
				'created_at'  => current_time( 'mysql', true ),
				'expires_at'  => gmdate( 'Y-m-d H:i:s', $expiry ),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s' )
		);

		$path = is_multisite() && defined( 'SITECOOKIEPATH' ) ? SITECOOKIEPATH : COOKIEPATH;
		self::set_secure_cookie( self::TRUSTED_COOKIE, $token, $expiry, $path );
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
	 * don't have to tune two schemas in parallel. Public so ceremony
	 * endpoints outside this class (the WebAuthn AJAX handlers) share the
	 * same ladder as the challenge form instead of bypassing it.
	 *
	 * @param string $ip Client IP.
	 * @return int Seconds remaining, 0 when not locked out.
	 * @since 2.1.34
	 */
	public static function ip_lockout_remaining( $ip ) {
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
	 * Public so every failed WebAuthn AJAX verification feeds the same
	 * ladder (and the same DB-block graduation) as a wrong code typed
	 * into the challenge form.
	 *
	 * @param string $ip Client IP.
	 * @since 2.1.34
	 */
	public static function record_ip_failure( $ip ) {
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
		 * brute force, the transient lockout was capping the response at
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
					'passkeyRequesting'    => __( 'Passkey request in progress...', 'reportedip-hive' ),
					'enterCodeFirst'       => __( 'Please enter the verification code first. If you touched your security key, switch to the passkey tab and use its button instead.', 'reportedip-hive' ),
					'enterCodeFirstPlain'  => __( 'Please enter the verification code first.', 'reportedip-hive' ),
					'passkeyWaiting'       => __( 'Waiting for your security key. Insert and touch it now, or approve the passkey prompt.', 'reportedip-hive' ),
					'passkeyTimeout'       => __( 'The request timed out or was cancelled. Insert your key and touch it (on a phone, hold the key flat against the back for NFC), then try again.', 'reportedip-hive' ),
					'passkeySecurityError' => __( 'The domain of this page does not match the key registration.', 'reportedip-hive' ),
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
	 * Lives under `$wpdb->base_prefix` so a single trust decision applies to
	 * the whole Multisite network (matches the network-wide expires_at /
	 * SITECOOKIEPATH semantics added in 2.0.0). On single-site
	 * `base_prefix === prefix`, behaviour is unchanged.
	 *
	 * @return string Table name with prefix.
	 */
	private static function get_trusted_table() {
		return ReportedIP_Hive_Schema::table( self::TABLE_TRUSTED_DEVICES );
	}

	/**
	 * Set a 2FA cookie using the canonical secure flags.
	 *
	 * Centralises the four `setcookie()` call sites so the cookie attributes
	 * (Secure, HttpOnly, SameSite=Strict) cannot drift apart. The trust
	 * cookie is the only one that opts into `SITECOOKIEPATH` so the trust
	 * carries across all sites of a Multisite network.
	 *
	 * @param string $name    Cookie name.
	 * @param string $value   Cookie value (empty string clears).
	 * @param int    $expires Expiry timestamp.
	 * @param string $path    Cookie path. Defaults to COOKIEPATH; pass
	 *                        SITECOOKIEPATH for network-scoped cookies.
	 * @return void
	 * @since  2.0.0
	 */
	private static function set_secure_cookie( $name, $value, $expires, $path = COOKIEPATH ) {
		setcookie(
			$name,
			$value,
			array(
				'expires'  => $expires,
				'path'     => $path,
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Strict',
			)
		);
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

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name built from Schema::table() with a hardcoded suffix; safe.
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

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Safe: table name from Schema::table(); no user input in SQL.
		return (int) $wpdb->query( "DELETE FROM $table WHERE expires_at < UTC_TIMESTAMP()" );
	}

	/**
	 * Enable 2FA for a user (activates one method; other methods stay untouched).
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $method  2FA method, a registered method slug.
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
		 * a method going live (audit log, welcome mail, ...).
		 *
		 * @since 1.6.1
		 * @param int    $user_id The user whose method became active.
		 * @param string $method  Method id, a registered method slug.
		 */
		do_action( 'reportedip_hive_2fa_method_enabled', (int) $user_id, (string) $method );
	}

	/**
	 * Activate a single 2FA method for a user.
	 *
	 * Single enrolment path shared by the profile section, the onboarding
	 * wizard and WebAuthn key registration. The first method a user
	 * configures activates full 2FA via enable_for_user(); any additional
	 * method only sets its own flag, so the user's chosen default method
	 * and existing recovery codes survive.
	 *
	 * Callers must not write the method's enabled flag themselves before
	 * calling this, the first-method detection reads the flags.
	 *
	 * A method the site policy does not permit is refused here rather than
	 * only hidden in the profile UI: the enrolment endpoints are reachable
	 * directly, and a flag written for a disallowed method goes live the
	 * moment an administrator re-enables it.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $method  Method identifier, a registered method slug.
	 * @return array|null|false Freshly generated recovery codes when the user
	 *                          had none (show them once!), null when existing
	 *                          codes survived, false for an unknown or
	 *                          disallowed method.
	 * @since  2.1.36
	 */
	public static function activate_method( $user_id, $method ) {
		$method_key = self::get_method_meta_key( $method );
		if ( ! $method_key ) {
			return false;
		}

		if ( ! self::is_method_allowed( $method ) ) {
			return false;
		}

		$fresh_codes = null;
		if ( 0 === ReportedIP_Hive_Two_Factor_Recovery::get_remaining_count( $user_id ) ) {
			$fresh_codes = ReportedIP_Hive_Two_Factor_Recovery::regenerate_codes( $user_id );
		}

		if ( ! self::is_user_enabled( $user_id ) ) {
			self::enable_for_user( $user_id, $method );
			return $fresh_codes;
		}

		update_user_meta( $user_id, $method_key, '1' );
		unset( self::$methods_cache[ $user_id ] );

		/** This action is documented in includes/class-two-factor.php */
		do_action( 'reportedip_hive_2fa_method_enabled', (int) $user_id, (string) $method );

		return $fresh_codes;
	}

	/**
	 * Set the user's default (primary) sign-in method.
	 *
	 * The method must be one the user has actively configured; the guard
	 * mirrors the self-healing read in get_user_method() so a stale value
	 * can never be persisted.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $method  Method identifier, a registered method slug.
	 * @return bool True when stored, false when the method is not active.
	 * @since  2.1.36
	 */
	public static function set_user_method( $user_id, $method ) {
		if ( ! in_array( $method, self::get_user_enabled_methods( $user_id ), true ) ) {
			return false;
		}

		update_user_meta( $user_id, self::META_METHOD, $method );

		return true;
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
				delete_user_meta( $user_id, self::META_TOTP_SECRET_PENDING );
				delete_user_meta( $user_id, self::META_TOTP_CONFIRMED );
				delete_user_meta( $user_id, self::META_TOTP_LAST_STEP );
				break;
			case self::METHOD_WEBAUTHN:
				delete_user_meta( $user_id, self::META_WEBAUTHN_CREDENTIALS );
				break;
			default:
				foreach ( (array) ( self::methods()[ $method ]['data_keys'] ?? array() ) as $data_key ) {
					delete_user_meta( $user_id, (string) $data_key );
				}
				break;
		}

		unset( self::$methods_cache[ $user_id ] );

		/*
		 * The method just removed never counts as remaining: with no flag
		 * left, the legacy single-method fallback of configured_method_flags()
		 * would report it again and keep 2FA on without its secret. A method
		 * no active plugin registers counts while the stored policy names it,
		 * as it did in 2.1.x when its plugin was active, so its data and the
		 * account's 2FA survive the removal of the last visible method.
		 */
		$remaining = array_values(
			array_diff(
				array_merge(
					self::get_user_enabled_methods( $user_id ),
					array_intersect( self::unregistered_method_flags( $user_id ), self::stored_allowed_slugs() )
				),
				array( $method )
			)
		);
		if ( empty( $remaining ) ) {
			self::disable_for_user( $user_id );
			return true;
		}

		$primary = get_user_meta( $user_id, self::META_METHOD, true );
		if ( $primary === $method ) {
			update_user_meta( $user_id, self::META_METHOD, $remaining[0] );
		}
		unset( self::$methods_cache[ $user_id ] );

		return true;
	}

	/**
	 * Disable 2FA for a user and clean up all related data.
	 *
	 * Also resets the reminder counter and the onboarding skip snooze
	 * (literal keys, the Recommend/Onboarding classes are not loaded in
	 * every context this runs in), so a support reset really starts fresh.
	 * The keys of {@see self::META_KEEP_ON_RESET} stay.
	 *
	 * @param int $user_id WordPress user ID.
	 */
	public static function disable_for_user( $user_id ) {
		$meta_keys = array(
			self::META_ENABLED,
			self::META_METHOD,
			self::META_TOTP_SECRET,
			self::META_TOTP_SECRET_PENDING,
			self::META_TOTP_CONFIRMED,
			self::META_TOTP_LAST_STEP,
			self::META_TOTP_ENABLED,
			self::META_EMAIL_ENABLED,
			self::META_WEBAUTHN_ENABLED,
			self::META_WEBAUTHN_CREDENTIALS,
			self::META_FAILED_ATTEMPTS,
			self::META_SETUP_DATE,
			self::META_ENFORCEMENT_START,
			self::META_SKIP_COUNT,
			self::META_KNOWN_DEVICES,
			self::META_LOGIN_CONTEXT,
			'reportedip_hive_2fa_reminder_count',
			'reportedip_hive_2fa_reminder_last_seen',
			'reportedip_hive_2fa_skip_until',
		);

		$keys = array_diff( array_merge( $meta_keys, self::method_meta_keys(), self::stored_meta_keys( $user_id ) ), self::META_KEEP_ON_RESET );
		foreach ( array_unique( $keys ) as $key ) {
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
	 * The user's meta keys that start with {@see self::META_PREFIX}, the
	 * ones of methods no active plugin registers included.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string[]
	 * @since  3.0.0
	 */
	public static function stored_meta_keys( $user_id ) {
		$keys = array();
		foreach ( array_keys( (array) get_user_meta( (int) $user_id ) ) as $key ) {
			if ( 0 === strpos( (string) $key, self::META_PREFIX ) ) {
				$keys[] = (string) $key;
			}
		}
		return $keys;
	}

	/**
	 * Delete the 2FA user meta of every user: the keys of
	 * {@see self::get_all_meta_keys()} plus every stored key that starts
	 * with {@see self::META_PREFIX}, so the data of a method whose add-on is
	 * inactive goes as well. Used by the uninstall and the full data reset.
	 *
	 * @return void
	 * @since  3.0.0
	 */
	public static function delete_all_user_meta() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- One-off key discovery during uninstall or a full data reset; the deletion itself goes through delete_metadata().
		$stored = (array) $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT meta_key FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", $wpdb->esc_like( self::META_PREFIX ) . '%' ) );
		foreach ( array_unique( array_merge( self::get_all_meta_keys(), array_map( 'strval', $stored ) ) ) as $key ) {
			delete_metadata( 'user', 0, $key, '', true );
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
	 * Includes the keys of every registered method, see method_meta_keys().
	 *
	 * @return array List of meta key strings.
	 */
	public static function get_all_meta_keys() {
		$keys = array(
			self::META_ENABLED,
			self::META_METHOD,
			self::META_TOTP_SECRET,
			self::META_TOTP_SECRET_PENDING,
			self::META_TOTP_CONFIRMED,
			self::META_TOTP_LAST_STEP,
			self::META_TOTP_ENABLED,
			self::META_EMAIL_ENABLED,
			self::META_WEBAUTHN_ENABLED,
			self::META_WEBAUTHN_CREDENTIALS,
			self::META_FAILED_ATTEMPTS,
			self::META_SETUP_DATE,
			self::META_ENFORCEMENT_START,
			self::META_SKIP_COUNT,
			self::META_KNOWN_DEVICES,
			self::META_LOGIN_CONTEXT,
			ReportedIP_Hive_Two_Factor_Recovery::META_KEY_CODES,
			ReportedIP_Hive_Two_Factor_Recovery::META_KEY_REMAINING,
		);

		return array_values( array_unique( array_merge( $keys, self::method_meta_keys() ) ) );
	}
}
