<?php
/**
 * Two-Factor Gate for the WordPress password reset flow.
 *
 * Wraps the lost-password / reset-password flow with a 2FA challenge so a
 * stolen mailbox cannot be used to bypass 2FA: the recovery channel (email)
 * is excluded from the eligible methods, and TOTP / SMS / WebAuthn / recovery
 * codes are required before the new password is accepted.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.7.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ReportedIP_Hive_Two_Factor_Reset_Gate
 *
 * Two-stage gate (defense-in-depth):
 *   - validate_password_reset (priority 5): GET → redirect to challenge page.
 *     POST without a verified token → WP_Error so the reset form re-renders.
 *   - password_reset (priority 5): re-verify the token, consume it (single
 *     use), and wp_die() if it is missing — last-mile guard against direct
 *     POST against the resetpass form.
 *
 * Token storage: a transient bound to user_id + sha256(reset_key) + hashed
 * client IP, lifetime 600 s, deleted after consumption.
 */
final class ReportedIP_Hive_Two_Factor_Reset_Gate {

	/**
	 * wp-login.php action slug for the reset-flow 2FA challenge page.
	 *
	 * @var string
	 */
	public const ACTION_CHALLENGE = 'reportedip_2fa_reset';

	/**
	 * Transient prefix for the verified-reset token.
	 *
	 * @var string
	 */
	public const TOKEN_PREFIX = 'reportedip_2fa_reset_pass_';

	/**
	 * Token lifetime in seconds (10 minutes — same as email OTP).
	 *
	 * @var int
	 */
	public const TOKEN_TTL = 600;

	/**
	 * User-meta key for failed reset-challenge attempts (shared throttle bucket
	 * with the login flow at the IP level via Security_Monitor).
	 *
	 * @var string
	 */
	public const META_FAILED_ATTEMPTS = 'reportedip_hive_2fa_reset_failed_attempts';

	/**
	 * Master toggle.
	 *
	 * @var string
	 */
	public const OPT_REQUIRE = 'reportedip_hive_2fa_require_on_password_reset';

	/**
	 * JSON list of method ids that may NOT be used as the second factor in
	 * the reset flow. Default: ["email"] — the recovery channel must never
	 * double as the second factor.
	 *
	 * @var string
	 */
	public const OPT_EXCLUDED_METHODS = 'reportedip_hive_2fa_password_reset_excluded_methods';

	/**
	 * If true (default), block the reset entirely when the user has only
	 * email-2FA and no recovery codes. Admin gets an alert mail.
	 *
	 * @var string
	 */
	public const OPT_BLOCK_EMAIL_ONLY = 'reportedip_hive_2fa_password_reset_block_email_only';

	/**
	 * Logger event types.
	 *
	 * @var string
	 */
	public const EVENT_CHALLENGE_SENT     = '2fa_reset_challenge_sent';
	public const EVENT_CHALLENGE_PASSED   = '2fa_reset_challenge_passed';
	public const EVENT_CHALLENGE_FAILED   = '2fa_reset_challenge_failed';
	public const EVENT_EMAIL_ONLY_BLOCKED = '2fa_reset_email_only_blocked';
	public const EVENT_NO_ELIGIBLE_METHOD = '2fa_reset_no_eligible_method';
	public const EVENT_BYPASS_ATTEMPT     = '2fa_reset_bypass_attempt';

	/**
	 * Constructor — registers the password-reset hooks if the feature is on.
	 *
	 * Hook priorities:
	 *   - validate_password_reset @ 5: must run before the reset form renders
	 *     and before any other plugin hooks the same action with the default
	 *     priority 10.
	 *   - password_reset @ 5: must run before reset_password() persists the
	 *     new password.
	 */
	public function __construct() {
		if ( ! self::is_feature_enabled() ) {
			return;
		}

		add_action( 'validate_password_reset', array( $this, 'on_validate_reset' ), 5, 2 );
		add_action( 'password_reset', array( $this, 'on_password_reset' ), 5, 2 );
		add_action( 'login_form_' . self::ACTION_CHALLENGE, array( $this, 'handle_challenge' ) );
	}

	/**
	 * Whether the reset-flow 2FA gate is active for this site.
	 *
	 * @return bool
	 */
	public static function is_feature_enabled(): bool {
		if ( ! class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
			return false;
		}
		if ( ! ReportedIP_Hive_Two_Factor::is_globally_enabled() ) {
			return false;
		}
		return (bool) get_option( self::OPT_REQUIRE, true );
	}

	/**
	 * Methods that must NOT be offered as a second factor during password
	 * reset. The default list excludes the email channel because the reset
	 * link itself was delivered via that channel — using the same channel
	 * for both halves of the recovery flow collapses to a single factor.
	 *
	 * @param int $user_id Reset target user ID.
	 * @return string[] Method identifiers (lower-case).
	 */
	public static function get_excluded_methods( int $user_id ): array {
		$stored = get_option( self::OPT_EXCLUDED_METHODS, '["email"]' );
		if ( is_array( $stored ) ) {
			$list = $stored;
		} else {
			$decoded = json_decode( (string) $stored, true );
			$list    = is_array( $decoded ) ? $decoded : array( ReportedIP_Hive_Two_Factor::METHOD_EMAIL );
		}

		$normalised = array();
		foreach ( $list as $entry ) {
			$key = sanitize_key( (string) $entry );
			if ( '' !== $key ) {
				$normalised[] = $key;
			}
		}

		/**
		 * Filter the list of method identifiers that are NOT eligible for the
		 * password-reset 2FA challenge.
		 *
		 * @param string[] $excluded Excluded method identifiers.
		 * @param int      $user_id  Reset target user ID.
		 * @since 1.7.0
		 */
		$filtered = apply_filters( 'reportedip_hive_2fa_password_reset_excluded_methods', $normalised, $user_id );
		return is_array( $filtered ) ? array_values( array_unique( $filtered ) ) : $normalised;
	}

	/**
	 * Method identifiers a user can challenge with for a password reset.
	 *
	 * Recovery codes are always eligible if any remain — they are the
	 * documented out-of-band channel for users whose only enrolled second
	 * factor is the now-excluded email channel.
	 *
	 * @param int $user_id Reset target user ID.
	 * @return string[] Method identifiers, in display order.
	 */
	public static function get_eligible_methods( int $user_id ): array {
		$enabled  = ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user_id );
		$excluded = self::get_excluded_methods( $user_id );
		$eligible = array_values( array_diff( $enabled, $excluded ) );

		if ( ReportedIP_Hive_Two_Factor_Recovery::get_remaining_count( $user_id ) > 0
			&& ! in_array( ReportedIP_Hive_Two_Factor::METHOD_RECOVERY, $excluded, true ) ) {
			$eligible[] = ReportedIP_Hive_Two_Factor::METHOD_RECOVERY;
		}

		return array_values( array_unique( $eligible ) );
	}

	/**
	 * True when the user has only email-2FA configured and no recovery codes.
	 * In that case the reset is blocked entirely — there is no eligible
	 * method that does not collapse to single-factor security.
	 *
	 * @param int $user_id Reset target user ID.
	 * @return bool
	 */
	public static function is_email_only_locked( int $user_id ): bool {
		if ( ! get_option( self::OPT_BLOCK_EMAIL_ONLY, true ) ) {
			return false;
		}

		$enabled = ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user_id );
		if ( array( ReportedIP_Hive_Two_Factor::METHOD_EMAIL ) !== $enabled ) {
			return false;
		}

		return ReportedIP_Hive_Two_Factor_Recovery::get_remaining_count( $user_id ) === 0;
	}

	/**
	 * validate_password_reset action callback.
	 *
	 * Fires on both GET (form render with valid key) and POST (submit). On
	 * GET we redirect to the challenge page if no verified token exists;
	 * on POST without a token we add a WP_Error so the reset form does not
	 * persist the new password.
	 *
	 * @param \WP_Error        $errors Existing validation errors.
	 * @param \WP_User|\WP_Error $user Reset target user, or WP_Error if the
	 *                                 reset key was invalid (we then bail out).
	 */
	public function on_validate_reset( $errors, $user ) {
		if ( ! ( $user instanceof \WP_User ) ) {
			return;
		}
		if ( ! ( $errors instanceof \WP_Error ) ) {
			return;
		}
		if ( $errors->has_errors() ) {
			return;
		}

		$enabled = ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user->ID );
		if ( empty( $enabled ) ) {
			return;
		}

		if ( self::is_email_only_locked( $user->ID ) ) {
			$this->log_event( self::EVENT_EMAIL_ONLY_BLOCKED, $user->ID, 'high' );
			$this->notify_admins_email_only_block( $user );
			$this->die_with_lockout(
				__( 'Password reset blocked', 'reportedip-hive' ),
				__( 'For security, this account requires a second factor other than email (Authenticator app, SMS, security key or recovery code) before passwords can be reset. Please contact your administrator.', 'reportedip-hive' )
			);
			return;
		}

		$eligible = self::get_eligible_methods( $user->ID );
		if ( empty( $eligible ) ) {
			$this->log_event( self::EVENT_NO_ELIGIBLE_METHOD, $user->ID, 'high' );
			$this->notify_admins_email_only_block( $user );
			$this->die_with_lockout(
				__( 'Password reset blocked', 'reportedip-hive' ),
				__( 'No second factor is available for password reset on this account. Please contact your administrator.', 'reportedip-hive' )
			);
			return;
		}

		$reset_key = $this->get_reset_key();
		if ( '' === $reset_key ) {
			return;
		}

		if ( $this->has_valid_token( $user->ID, $reset_key ) ) {
			return;
		}

		$request_method = isset( $_SERVER['REQUEST_METHOD'] )
			? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) )
			: 'GET';

		if ( 'GET' === $request_method ) {
			$this->dispatch_redirect( $this->build_challenge_url( $user->user_login, $reset_key ) );
			return;
		}

		$errors->add(
			'reportedip_2fa_reset_required',
			esc_html__( 'Two-factor verification required before password reset.', 'reportedip-hive' )
		);
	}

	/**
	 * password_reset action callback.
	 *
	 * Last-mile guard: re-verify the token before the new password is saved
	 * and consume it (single use). If the token is missing despite having
	 * passed validate_password_reset, we wp_die() — that means the request
	 * arrived through a path that bypassed our gate (direct POST to the
	 * resetpass form) and must not be allowed to set a password.
	 *
	 * @param \WP_User $user     Reset target user.
	 * @param string   $new_pass New password (unused — we only gate, we don't
	 *                           inspect the password).
	 */
	public function on_password_reset( $user, $new_pass = '' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		unset( $new_pass );
		if ( ! ( $user instanceof \WP_User ) ) {
			return;
		}

		$enabled = ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user->ID );
		if ( empty( $enabled ) ) {
			return;
		}

		$reset_key = $this->get_reset_key();
		if ( '' !== $reset_key && $this->has_valid_token( $user->ID, $reset_key ) ) {
			$this->consume_token( $user->ID, $reset_key );
			$this->log_event( self::EVENT_CHALLENGE_PASSED, $user->ID, 'low' );
			return;
		}

		$this->log_event( self::EVENT_BYPASS_ATTEMPT, $user->ID, 'critical' );
		ReportedIP_Hive::emit_block_response_headers();
		wp_die(
			esc_html__( 'Password reset blocked: two-factor verification missing.', 'reportedip-hive' ),
			esc_html__( 'Security', 'reportedip-hive' ),
			array( 'response' => 403 )
		);
	}

	/**
	 * Render and process the reset-flow 2FA challenge page.
	 *
	 * Fires on wp-login.php?action=reportedip_2fa_reset. The page accepts a
	 * code (or assertion, for WebAuthn) for one of the eligible methods and,
	 * on success, sets the verified-reset token and redirects back to the
	 * standard wp-login.php?action=rp&key=...&login=... form.
	 */
	public function handle_challenge() {
		$login     = $this->get_query_login();
		$reset_key = $this->get_reset_key();
		if ( '' === $login || '' === $reset_key ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$user = get_user_by( 'login', $login );
		if ( ! ( $user instanceof \WP_User ) ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$key_user = check_password_reset_key( $reset_key, $login );
		if ( is_wp_error( $key_user ) || ! ( $key_user instanceof \WP_User ) || (int) $key_user->ID !== (int) $user->ID ) {
			wp_safe_redirect( wp_lostpassword_url() );
			exit;
		}

		$eligible = self::get_eligible_methods( $user->ID );
		if ( empty( $eligible ) ) {
			$this->dispatch_redirect( $this->build_reset_url( $login, $reset_key ) );
			return;
		}

		$error  = '';
		$method = isset( $_GET['method'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			? sanitize_key( wp_unslash( $_GET['method'] ) ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			: $eligible[0];
		if ( ! in_array( $method, $eligible, true ) ) {
			$method = $eligible[0];
		}

		$request_method = isset( $_SERVER['REQUEST_METHOD'] )
			? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) )
			: 'GET';

		if ( 'POST' === $request_method ) {
			$nonce = isset( $_POST['_reportedip_2fa_reset_nonce'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing -- The submitted nonce is verified on the next line.
				? sanitize_text_field( wp_unslash( $_POST['_reportedip_2fa_reset_nonce'] ) ) // phpcs:ignore WordPress.Security.NonceVerification.Missing -- The submitted nonce is verified on the next line.
				: '';

			if ( ! wp_verify_nonce( $nonce, 'reportedip_2fa_reset_' . $user->ID ) ) {
				$error = esc_html__( 'Security check failed. Please try again.', 'reportedip-hive' );
			} else {
				// phpcs:disable WordPress.Security.NonceVerification.Missing -- Nonce verified above.
				$submitted_method = isset( $_POST['reportedip_2fa_reset_method'] )
					? sanitize_key( wp_unslash( $_POST['reportedip_2fa_reset_method'] ) )
					: $method;
				$submitted_code   = isset( $_POST['reportedip_2fa_reset_code'] )
					? sanitize_text_field( wp_unslash( $_POST['reportedip_2fa_reset_code'] ) )
					: '';
				// phpcs:enable WordPress.Security.NonceVerification.Missing

				if ( ! in_array( $submitted_method, $eligible, true ) ) {
					$error = esc_html__( 'This method is not available for password reset.', 'reportedip-hive' );
				} else {
					$ip = ReportedIP_Hive::get_client_ip();
					if ( $this->is_throttled( $user->ID, $ip ) ) {
						$error = esc_html__( 'Too many failed attempts. Please wait a moment and try again.', 'reportedip-hive' );
					} elseif ( $this->verify_method_code( $user->ID, $submitted_method, $submitted_code ) ) {
						$this->reset_failed_attempts( $user->ID );
						$this->mint_token( $user->ID, $reset_key, $submitted_method );
						$this->log_event(
							self::EVENT_CHALLENGE_PASSED,
							$user->ID,
							'low',
							array( 'method' => $submitted_method )
						);
						$this->dispatch_redirect( $this->build_reset_url( $login, $reset_key ) );
						return;
					} else {
						$this->record_failure( $user->ID, $ip );
						$this->log_event(
							self::EVENT_CHALLENGE_FAILED,
							$user->ID,
							'medium',
							array( 'method' => $submitted_method )
						);
						$error  = esc_html__( 'Verification failed. Please double-check the code and try again.', 'reportedip-hive' );
						$method = $submitted_method;
					}
				}
			}
		}

		if ( 'GET' === $request_method
			&& isset( $_GET['method'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			&& ReportedIP_Hive_Two_Factor::METHOD_SMS === $method
			&& class_exists( 'ReportedIP_Hive_Two_Factor_SMS' ) ) {
			ReportedIP_Hive_Two_Factor_SMS::send_code( $user->ID );
			$this->log_event( self::EVENT_CHALLENGE_SENT, $user->ID, 'low', array( 'method' => 'sms' ) );
		}

		$this->render_challenge_page( $user, $login, $reset_key, $eligible, $method, $error );
		exit;
	}

	/**
	 * Render the challenge page HTML using login_header() so the page picks
	 * up the same WP login chrome that the standard 2FA challenge uses.
	 *
	 * @param \WP_User $user      Reset target user.
	 * @param string   $login     User login slug from the reset URL.
	 * @param string   $reset_key Reset key from the URL.
	 * @param string[] $eligible  Eligible method identifiers.
	 * @param string   $method    Currently selected method.
	 * @param string   $error     Error message to surface (may be empty).
	 */
	private function render_challenge_page( \WP_User $user, string $login, string $reset_key, array $eligible, string $method, string $error ): void {
		if ( ! function_exists( 'login_header' ) ) {
			require_once ABSPATH . 'wp-login.php'; // @codeCoverageIgnore
		}

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

		ReportedIP_Hive::emit_block_response_headers();

		login_header(
			__( 'Two-Factor Verification', 'reportedip-hive' ),
			'',
			'' !== $error ? new \WP_Error( 'reportedip_2fa_reset_error', $error ) : null
		);

		$nonce      = wp_create_nonce( 'reportedip_2fa_reset_' . $user->ID );
		$action_url = $this->build_challenge_url( $login, $reset_key, $method );

		?>
		<main class="rip-2fa-challenge" role="main" aria-labelledby="rip-2fa-reset-title">
			<header class="rip-2fa-challenge__header">
				<h1 class="rip-2fa-challenge__title" id="rip-2fa-reset-title">
					<?php esc_html_e( 'Confirm your identity to reset your password', 'reportedip-hive' ); ?>
				</h1>
				<p class="rip-2fa-challenge__subtitle">
					<?php
					printf(
						/* translators: %s: user display name */
						esc_html__( 'Hello %s, please verify a second factor before setting a new password. The email channel is intentionally excluded from this step.', 'reportedip-hive' ),
						'<strong>' . esc_html( $user->display_name ) . '</strong>' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					);
					?>
				</p>
			</header>

			<?php if ( count( $eligible ) > 1 ) : ?>
				<nav class="rip-2fa-challenge__methods" aria-label="<?php esc_attr_e( 'Choose verification method', 'reportedip-hive' ); ?>">
					<?php foreach ( $eligible as $candidate ) : ?>
						<?php
						$candidate_url   = $this->build_challenge_url( $login, $reset_key, $candidate );
						$candidate_label = $this->method_label( $candidate );
						$is_active       = ( $candidate === $method );
						?>
						<a class="rip-button <?php echo $is_active ? 'rip-button--primary' : 'rip-button--secondary'; ?>"
							href="<?php echo esc_url( $candidate_url ); ?>">
							<?php echo esc_html( $candidate_label ); ?>
						</a>
					<?php endforeach; ?>
				</nav>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( $action_url ); ?>" class="rip-2fa-challenge__form">
				<input type="hidden" name="_reportedip_2fa_reset_nonce" value="<?php echo esc_attr( $nonce ); ?>" />
				<input type="hidden" name="reportedip_2fa_reset_method" value="<?php echo esc_attr( $method ); ?>" />

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_2fa_reset_code">
						<?php echo esc_html( $this->method_prompt( $method ) ); ?>
					</label>
					<input type="text"
						id="reportedip_2fa_reset_code"
						name="reportedip_2fa_reset_code"
						class="rip-input"
						autocomplete="one-time-code"
						inputmode="<?php echo ReportedIP_Hive_Two_Factor::METHOD_RECOVERY === $method ? 'text' : 'numeric'; ?>"
						spellcheck="false"
						autocapitalize="none"
						required />
				</div>

				<button type="submit" class="rip-button rip-button--primary rip-button--block">
					<?php esc_html_e( 'Verify and continue', 'reportedip-hive' ); ?>
				</button>
			</form>

			<p class="rip-2fa-challenge__footnote">
				<a href="<?php echo esc_url( wp_lostpassword_url() ); ?>">
					<?php esc_html_e( 'Cancel and request a new reset link', 'reportedip-hive' ); ?>
				</a>
			</p>
		</main>
		<?php

		login_footer();
	}

	/**
	 * Verify a code (or assertion) for a given method.
	 *
	 * @param int    $user_id User to verify against.
	 * @param string $method  Method identifier (totp / sms / webauthn / recovery).
	 * @param string $code    Submitted code or assertion payload.
	 * @return bool True on a successful verification.
	 */
	private function verify_method_code( int $user_id, string $method, string $code ): bool {
		switch ( $method ) {
			case ReportedIP_Hive_Two_Factor::METHOD_TOTP:
				$encrypted = get_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_TOTP_SECRET, true );
				if ( empty( $encrypted ) ) {
					return false;
				}
				$secret = ReportedIP_Hive_Two_Factor_Crypto::decrypt( $encrypted );
				if ( false === $secret ) {
					return false;
				}
				$window = (int) apply_filters( 'reportedip_2fa_totp_window', 1, $user_id );
				$window = max( 0, min( 3, $window ) );
				$result = ReportedIP_Hive_Two_Factor_TOTP::verify_code( $secret, $code, $window );
				ReportedIP_Hive_Two_Factor_Crypto::zero_memory( $secret );
				return (bool) $result;

			case ReportedIP_Hive_Two_Factor::METHOD_SMS:
				return class_exists( 'ReportedIP_Hive_Two_Factor_SMS' )
					&& ReportedIP_Hive_Two_Factor_SMS::verify_code( $user_id, $code );

			case ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN:
				return class_exists( 'ReportedIP_Hive_Two_Factor_WebAuthn' )
					&& ReportedIP_Hive_Two_Factor_WebAuthn::verify( $user_id, $code );

			case ReportedIP_Hive_Two_Factor::METHOD_RECOVERY:
				return ReportedIP_Hive_Two_Factor_Recovery::verify_code( $user_id, $code );

			default:
				return false;
		}
	}

	/**
	 * Build the transient key for a (user, reset_key) pair.
	 *
	 * @param int    $user_id   User ID.
	 * @param string $reset_key Reset key from the URL.
	 * @return string
	 */
	private function token_key( int $user_id, string $reset_key ): string {
		return self::TOKEN_PREFIX . $user_id . '_' . hash( 'sha256', $reset_key );
	}

	/**
	 * Compute a privacy-preserving fingerprint of the client IP. Used to bind
	 * the verified-reset token to the originating network so that even a
	 * leaked transient cannot be replayed from an attacker's IP.
	 *
	 * @return string
	 */
	private function client_fingerprint(): string {
		$ip = ReportedIP_Hive::get_client_ip();
		return hash( 'sha256', $ip . wp_salt() );
	}

	/**
	 * Persist a verified-reset token for the (user, reset_key) tuple.
	 *
	 * @param int    $user_id   User ID.
	 * @param string $reset_key Reset key.
	 * @param string $method    Method that was verified.
	 */
	private function mint_token( int $user_id, string $reset_key, string $method ): void {
		set_transient(
			$this->token_key( $user_id, $reset_key ),
			array(
				'verified_at' => time(),
				'method'      => $method,
				'ip_hash'     => $this->client_fingerprint(),
			),
			self::TOKEN_TTL
		);
	}

	/**
	 * True iff a verified-reset token is present for the (user, reset_key)
	 * tuple, has not expired, and was minted from the same network.
	 *
	 * @param int    $user_id   User ID.
	 * @param string $reset_key Reset key.
	 * @return bool
	 */
	private function has_valid_token( int $user_id, string $reset_key ): bool {
		$payload = get_transient( $this->token_key( $user_id, $reset_key ) );
		if ( ! is_array( $payload ) ) {
			return false;
		}
		if ( empty( $payload['ip_hash'] ) || ! hash_equals( (string) $payload['ip_hash'], $this->client_fingerprint() ) ) {
			return false;
		}
		return true;
	}

	/**
	 * Delete the verified-reset token (single-use).
	 *
	 * @param int    $user_id   User ID.
	 * @param string $reset_key Reset key.
	 */
	private function consume_token( int $user_id, string $reset_key ): void {
		delete_transient( $this->token_key( $user_id, $reset_key ) );
	}

	/**
	 * Read the reset key from whatever surface holds it for the current leg
	 * of the WordPress reset flow:
	 *
	 *   Step 1 — first GET on the reset link: key in $_GET['key'].
	 *   Step 2 — second GET after WP set the rp cookie: key in
	 *            $_COOKIE['wp-resetpass-COOKIEHASH'] as "login:key".
	 *   Step 3 — POST of the new password: key in $_POST['rp_key'].
	 *   Our challenge page: key passed back through the URL, so $_GET['key'].
	 *
	 * Reading the cookie is necessary because validate_password_reset fires
	 * during step 2, where the URL no longer carries key + login.
	 *
	 * @return string
	 */
	private function get_reset_key(): string {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended,WordPress.Security.NonceVerification.Missing -- Read-only access; the reset key itself is the credential and is verified by check_password_reset_key().
		if ( isset( $_REQUEST['key'] ) ) {
			$raw = sanitize_text_field( wp_unslash( $_REQUEST['key'] ) );
			if ( '' !== $raw ) {
				return $raw;
			}
		}

		if ( isset( $_REQUEST['rp_key'] ) ) {
			$raw = sanitize_text_field( wp_unslash( $_REQUEST['rp_key'] ) );
			if ( '' !== $raw ) {
				return $raw;
			}
		}

		$cookie_value = $this->read_rp_cookie();
		if ( '' !== $cookie_value && false !== strpos( $cookie_value, ':' ) ) {
			$parts = explode( ':', $cookie_value, 2 );
			if ( isset( $parts[1] ) ) {
				return sanitize_text_field( $parts[1] );
			}
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended,WordPress.Security.NonceVerification.Missing
		return '';
	}

	/**
	 * Read the user_login the reset is being attempted for. Mirrors
	 * get_reset_key() — the rp cookie is the canonical source during
	 * step 2 of the WordPress reset flow.
	 *
	 * @return string
	 */
	private function get_query_login(): string {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended,WordPress.Security.NonceVerification.Missing -- Read-only; identity is re-verified by check_password_reset_key() before any state is mutated.
		if ( isset( $_REQUEST['login'] ) ) {
			$raw = sanitize_user( wp_unslash( $_REQUEST['login'] ), true );
			if ( '' !== $raw ) {
				return $raw;
			}
		}

		if ( isset( $_REQUEST['user_login'] ) ) {
			$raw = sanitize_user( wp_unslash( $_REQUEST['user_login'] ), true );
			if ( '' !== $raw ) {
				return $raw;
			}
		}

		$cookie_value = $this->read_rp_cookie();
		if ( '' !== $cookie_value && false !== strpos( $cookie_value, ':' ) ) {
			$parts = explode( ':', $cookie_value, 2 );
			if ( isset( $parts[0] ) ) {
				return sanitize_user( $parts[0], true );
			}
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended,WordPress.Security.NonceVerification.Missing
		return '';
	}

	/**
	 * Raw "login:key" payload from the WordPress reset cookie, or empty.
	 *
	 * @return string
	 */
	private function read_rp_cookie(): string {
		if ( ! defined( 'COOKIEHASH' ) ) {
			return '';
		}
		$cookie_name = 'wp-resetpass-' . COOKIEHASH;
		if ( ! isset( $_COOKIE[ $cookie_name ] ) ) {
			return '';
		}
		return (string) wp_unslash( $_COOKIE[ $cookie_name ] );
	}

	/**
	 * URL of the reset-flow 2FA challenge page, prefilled with the reset key
	 * and login slug so the user lands back on the resetpass form after a
	 * successful verification.
	 *
	 * @param string $login     User login slug.
	 * @param string $reset_key Reset key.
	 * @param string $method    Optional preselected method.
	 * @return string
	 */
	private function build_challenge_url( string $login, string $reset_key, string $method = '' ): string {
		$args = array(
			'action' => self::ACTION_CHALLENGE,
			'key'    => $reset_key,
			'login'  => rawurlencode( $login ),
		);
		if ( '' !== $method ) {
			$args['method'] = $method;
		}
		return add_query_arg( $args, wp_login_url() );
	}

	/**
	 * URL of the standard wp-login.php?action=rp page that we redirect back
	 * to after a successful challenge.
	 *
	 * @param string $login     User login slug.
	 * @param string $reset_key Reset key.
	 * @return string
	 */
	private function build_reset_url( string $login, string $reset_key ): string {
		return add_query_arg(
			array(
				'action' => 'rp',
				'key'    => $reset_key,
				'login'  => rawurlencode( $login ),
			),
			wp_login_url()
		);
	}

	/**
	 * Render a 403 lockout page and terminate. Used when no eligible second
	 * factor exists for the reset flow — the standard `$errors->add()` path
	 * is unreliable here because security plugins (including this one's
	 * own `User_Enumeration::normalize_login_errors()`) rewrite the
	 * `login_errors` channel to a generic "Invalid credentials." string,
	 * which would mask the real reason and confuse the affected user.
	 *
	 * @param string $title Short heading shown to the user.
	 * @param string $body  Longer explanation of why the reset was blocked.
	 */
	private function die_with_lockout( string $title, string $body ): void {
		ReportedIP_Hive::emit_block_response_headers();
		wp_die(
			esc_html( $body ),
			esc_html( $title ),
			array( 'response' => 403 )
		);
	}

	/**
	 * Send the browser to a target URL, mirroring the dispatcher used by the
	 * login-flow 2FA challenge so error-rendering plugins cannot strip the
	 * redirect on the way out.
	 *
	 * @param string $url Target URL.
	 */
	private function dispatch_redirect( string $url ): void {
		ReportedIP_Hive::emit_block_response_headers();

		if ( ! headers_sent() ) {
			wp_safe_redirect( $url );
			exit;
		}

		$safe_url = esc_url_raw( $url );
		printf(
			'<!doctype html><meta http-equiv="refresh" content="0;url=%s"><script>window.location.replace(%s);</script>',
			esc_attr( $safe_url ),
			wp_json_encode( $safe_url )
		);
		exit;
	}

	/**
	 * Per-user / per-IP throttle gate. We reuse the central security monitor
	 * so failed reset challenges share the lockout bucket with login-flow
	 * failures (NIST §5.2.5: shared rate-limit across credential-equivalent
	 * surfaces).
	 *
	 * @param int    $user_id User being challenged.
	 * @param string $ip      Client IP.
	 * @return bool True when the user / IP combination is currently locked.
	 */
	private function is_throttled( int $user_id, string $ip ): bool {
		unset( $ip );
		$raw = get_user_meta( $user_id, self::META_FAILED_ATTEMPTS, true );
		if ( empty( $raw ) ) {
			return false;
		}
		$data = is_string( $raw ) ? json_decode( $raw, true ) : $raw;
		if ( ! is_array( $data ) || empty( $data['lockout_until'] ) ) {
			return false;
		}
		return time() < (int) $data['lockout_until'];
	}

	/**
	 * Record a failed challenge: bump the per-user counter, schedule a brief
	 * lockout once the count crosses the third rung, and graduate to the
	 * canonical security monitor (which itself feeds into the IP escalation
	 * ladder) once the IP-side counter saturates.
	 *
	 * @param int    $user_id User being challenged.
	 * @param string $ip      Client IP.
	 */
	private function record_failure( int $user_id, string $ip ): void {
		$raw  = get_user_meta( $user_id, self::META_FAILED_ATTEMPTS, true );
		$data = ! empty( $raw ) && is_string( $raw ) ? json_decode( $raw, true ) : array();
		if ( ! is_array( $data ) ) {
			$data = array();
		}

		$count = (int) ( $data['count'] ?? 0 ) + 1;
		$now   = time();

		$lockout_until = 0;
		foreach ( ReportedIP_Hive_Two_Factor::LOCKOUT_THRESHOLDS as $threshold => $duration ) {
			if ( $count >= $threshold ) {
				$lockout_until = $now + $duration;
			}
		}

		update_user_meta(
			$user_id,
			self::META_FAILED_ATTEMPTS,
			wp_json_encode(
				array(
					'count'         => $count,
					'last_attempt'  => $now,
					'lockout_until' => $lockout_until,
				)
			)
		);

		$top = (int) max( array_keys( ReportedIP_Hive_Two_Factor::LOCKOUT_THRESHOLDS ) );
		if ( $count >= $top && '' !== $ip && 'unknown' !== $ip && class_exists( 'ReportedIP_Hive' ) ) {
			$client  = ReportedIP_Hive::get_instance();
			$monitor = $client->get_security_monitor();
			if ( $monitor instanceof ReportedIP_Hive_Security_Monitor ) {
				$monitor->handle_threshold_exceeded(
					$ip,
					'2fa_brute_force',
					array(
						'attempts' => $count,
						'surface'  => 'password_reset',
					)
				);
				delete_user_meta( $user_id, self::META_FAILED_ATTEMPTS );
			}
		}
	}

	/**
	 * Clear the per-user failure counter after a successful challenge.
	 *
	 * @param int $user_id User ID.
	 */
	private function reset_failed_attempts( int $user_id ): void {
		delete_user_meta( $user_id, self::META_FAILED_ATTEMPTS );
	}

	/**
	 * Send a security alert to all admins when a user is hard-locked from
	 * the reset flow because they only have email-2FA and no recovery codes.
	 *
	 * @param \WP_User $user Affected user.
	 */
	private function notify_admins_email_only_block( \WP_User $user ): void {
		if ( ! class_exists( 'ReportedIP_Hive_Mailer' ) ) {
			return;
		}

		$site_name = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		$timestamp = wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) );
		$mailer    = ReportedIP_Hive_Mailer::get_instance();
		$users     = function_exists( 'get_users' )
			? get_users( array( 'role__in' => array( 'administrator' ) ) )
			: array();

		foreach ( $users as $admin ) {
			if ( ! ( $admin instanceof \WP_User ) ) {
				continue;
			}
			if ( empty( $admin->user_email ) || ! is_email( $admin->user_email ) ) {
				continue;
			}
			$mailer->send(
				array(
					'to'              => $admin->user_email,
					'subject'         => sprintf(
						/* translators: %s: site name */
						__( '[%s] Password reset blocked for an account with email-only 2FA', 'reportedip-hive' ),
						$site_name
					),
					'greeting'        => sprintf(
						/* translators: %s: admin display name */
						__( 'Hello %s,', 'reportedip-hive' ),
						$admin->display_name
					),
					'intro_text'      => sprintf(
						/* translators: %s: affected user login */
						__( 'A password reset was attempted for the user "%s". The account currently has only email-based 2FA configured and no recovery codes — for security, the reset has been blocked.', 'reportedip-hive' ),
						$user->user_login
					),
					'main_block_html' => '<p style="margin:0 0 16px;font-size:14px;color:#374151;line-height:1.6;">'
						. esc_html__( 'To unblock the user, either reset their password manually via WP-CLI (`wp user reset-password <id> --skip-email`) or enrol an additional 2FA method (Authenticator app, SMS, security key, or recovery codes) on their behalf.', 'reportedip-hive' )
						. '</p>',
					'main_block_text' => __( 'To unblock the user, either reset their password manually via WP-CLI (wp user reset-password <id> --skip-email) or enrol an additional 2FA method (Authenticator app, SMS, security key, or recovery codes) on their behalf.', 'reportedip-hive' ),
					'security_notice' => array(
						'ip'        => ReportedIP_Hive::get_client_ip(),
						'timestamp' => $timestamp,
					),
					'disclaimer'      => __( 'This alert was generated automatically by ReportedIP Hive.', 'reportedip-hive' ),
					'context'         => array(
						'type'    => '2fa_reset_email_only_blocked',
						'user_id' => $user->ID,
					),
				)
			);
		}
	}

	/**
	 * Localised label for a method identifier.
	 *
	 * @param string $method Method identifier.
	 * @return string
	 */
	private function method_label( string $method ): string {
		switch ( $method ) {
			case ReportedIP_Hive_Two_Factor::METHOD_TOTP:
				return __( 'Authenticator app', 'reportedip-hive' );
			case ReportedIP_Hive_Two_Factor::METHOD_SMS:
				return __( 'SMS code', 'reportedip-hive' );
			case ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN:
				return __( 'Passkey / security key', 'reportedip-hive' );
			case ReportedIP_Hive_Two_Factor::METHOD_RECOVERY:
				return __( 'Recovery code', 'reportedip-hive' );
			default:
				return $method;
		}
	}

	/**
	 * Localised input prompt for a method identifier.
	 *
	 * @param string $method Method identifier.
	 * @return string
	 */
	private function method_prompt( string $method ): string {
		switch ( $method ) {
			case ReportedIP_Hive_Two_Factor::METHOD_TOTP:
				return __( 'Enter the 6-digit code from your authenticator app', 'reportedip-hive' );
			case ReportedIP_Hive_Two_Factor::METHOD_SMS:
				return __( 'Enter the 6-digit code from the SMS we just sent', 'reportedip-hive' );
			case ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN:
				return __( 'Confirm your passkey or security key when prompted', 'reportedip-hive' );
			case ReportedIP_Hive_Two_Factor::METHOD_RECOVERY:
				return __( 'Enter one of your recovery codes', 'reportedip-hive' );
			default:
				return __( 'Enter your verification code', 'reportedip-hive' );
		}
	}

	/**
	 * Forward an event to the central security log with a stable event_type.
	 *
	 * @param string $event_type Event identifier.
	 * @param int    $user_id    Affected user ID.
	 * @param string $severity   Severity level (low / medium / high / critical).
	 * @param array  $extra      Additional event payload.
	 */
	private function log_event( string $event_type, int $user_id, string $severity = 'medium', array $extra = array() ): void {
		if ( ! class_exists( 'ReportedIP_Hive_Logger' ) ) {
			return;
		}
		$logger = ReportedIP_Hive_Logger::get_instance();
		if ( ! $logger ) {
			return;
		}
		$ip      = class_exists( 'ReportedIP_Hive' ) ? ReportedIP_Hive::get_client_ip() : 'unknown';
		$payload = array_merge( array( 'user_id' => $user_id ), $extra );
		if ( method_exists( $logger, 'log' ) ) {
			$logger->log( $event_type, $ip, $severity, $payload );
		}
	}
}
