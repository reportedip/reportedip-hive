<?php
/**
 * Password Strength Enforcement.
 *
 * Two layered checks for users in roles listed under
 * `reportedip_hive_2fa_enforce_roles` (re-using the same enforce list
 * as 2FA, admins / privileged roles need both):
 *
 *  1. Local heuristic: minimum length, character-class diversity, blocklist
 *     of the most common 1k passwords (kept inline to avoid filesystem reads
 *     during password change). PHP 8.1+, no deps.
 *  2. Optional HaveIBeenPwned k-anonymity range check. Only the first 5
 *     SHA-1 hex chars of the password leave the server, so even the API
 *     provider cannot reconstruct the password, same protocol the major
 *     password managers use.
 *
 * Errors surface through the standard `user_profile_update_errors` and
 * `validate_password_reset` hooks so they appear in the admin UI / reset
 * form without any extra rendering work. Since 3.0.1 the same policy runs
 * on the WooCommerce account details and registration forms and on the
 * Ultimate Member account and registration forms, each through the error
 * hook of that form.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ReportedIP_Hive_Password_Strength {

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Password_Strength|null
	 */
	private static $instance = null;

	/**
	 * Tiny, deliberately small blocklist, the 30 passwords that account for
	 * the majority of breach hits in published corpuses. The HIBP check
	 * covers the long tail; this list catches the most common attempts
	 * without a network round-trip.
	 *
	 * @var string[]
	 */
	private const COMMON_PASSWORDS = array(
		'password',
		'password1',
		'password123',
		'pass1234',
		'12345678',
		'123456789',
		'qwerty',
		'qwerty123',
		'qwertyuiop',
		'1q2w3e4r',
		'1qaz2wsx',
		'admin',
		'admin123',
		'administrator',
		'welcome',
		'welcome1',
		'letmein',
		'letmein1',
		'monkey',
		'dragon',
		'iloveyou',
		'football',
		'baseball',
		'sunshine',
		'master',
		'shadow',
		'superman',
		'batman',
		'trustno1',
		'starwars',
	);

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'user_profile_update_errors', array( $this, 'on_profile_update' ), 10, 3 );
		add_action( 'validate_password_reset', array( $this, 'on_password_reset' ), 10, 2 );
		add_action( 'woocommerce_save_account_details_errors', array( $this, 'on_wc_account_details' ), 10, 2 );
		add_filter( 'woocommerce_process_registration_errors', array( $this, 'on_wc_registration' ), 10, 4 );
		add_action( 'um_submit_account_errors_hook', array( $this, 'on_um_account' ), 20 );
		add_action( 'um_submit_form_errors_hook__registration', array( $this, 'on_um_registration' ), 20, 2 );
	}

	/**
	 * WooCommerce My Account, account details. WooCommerce sets
	 * `user_pass` on the user object only for a password change it is about
	 * to save (current password correct, both new fields equal), and has
	 * verified its own nonce before the hook fires.
	 *
	 * @param WP_Error $errors Errors collected so far.
	 * @param object   $user   User data being saved.
	 * @return void
	 * @since  3.0.1
	 */
	public function on_wc_account_details( $errors, $user ): void {
		if ( ! ( $errors instanceof WP_Error ) || ! is_object( $user ) || empty( $user->user_pass ) ) {
			return;
		}
		$wp_user = isset( $user->ID ) ? get_userdata( (int) $user->ID ) : false;
		if ( ! ( $wp_user instanceof WP_User ) ) {
			$wp_user = wp_get_current_user();
		}
		$violation = $this->validate_password( (string) wp_unslash( (string) $user->user_pass ), $wp_user );
		if ( null !== $violation ) {
			$errors->add( 'pass', $violation );
		}
	}

	/**
	 * WooCommerce registration with a password the customer chose.
	 * WooCommerce passes an empty password when it generates one itself, so
	 * that case is left alone. The new account gets the `customer` role,
	 * which decides the scope.
	 *
	 * @param WP_Error $validation_error Errors collected so far.
	 * @param string   $username         Requested user name.
	 * @param string   $password         Chosen password, empty when generated.
	 * @param string   $email            Mail address.
	 * @return WP_Error
	 * @since  3.0.1
	 */
	public function on_wc_registration( $validation_error, $username, $password, $email ) {
		unset( $username, $email );
		if ( ! ( $validation_error instanceof WP_Error ) || ! is_string( $password ) || '' === $password ) {
			return $validation_error;
		}
		$violation = $this->validate_password( (string) wp_unslash( $password ), null, array( 'customer' ) );
		if ( null !== $violation ) {
			$validation_error->add( 'registration-error-invalid-password', $violation );
		}
		return $validation_error;
	}

	/**
	 * Ultimate Member account page, password tab. Ultimate Member has checked
	 * its nonce and the current password in its own callback on priority 10.
	 *
	 * @param array $args Submitted account form data.
	 * @return void
	 * @since  3.0.1
	 */
	public function on_um_account( $args ): void {
		if ( ! is_array( $args ) || empty( $args['user_password'] ) || ! function_exists( 'UM' ) ) {
			return;
		}
		$violation = $this->validate_password( trim( (string) $args['user_password'] ), wp_get_current_user() );
		if ( null !== $violation ) {
			UM()->form()->add_error( 'user_password', $violation );
		}
	}

	/**
	 * Ultimate Member registration form. The scope follows the role the form
	 * assigns, else the site's default role.
	 *
	 * @param array $submitted_data Submitted form data.
	 * @param array $form_data      Ultimate Member form settings.
	 * @return void
	 * @since  3.0.1
	 */
	public function on_um_registration( $submitted_data, $form_data = array() ): void {
		if ( ! is_array( $submitted_data ) || empty( $submitted_data['user_password'] ) || ! function_exists( 'UM' ) ) {
			return;
		}
		$role      = is_array( $form_data ) && ! empty( $form_data['role'] ) ? (string) $form_data['role'] : (string) get_option( 'default_role', 'subscriber' );
		$violation = $this->validate_password( trim( (string) $submitted_data['user_password'] ), null, array( $role ) );
		if ( null !== $violation ) {
			UM()->form()->add_error( 'user_password', $violation );
		}
	}

	/**
	 * Profile update handler. Fires on /wp-admin/profile.php and the user
	 * edit screen. We surface any policy violation as a hard error so WP
	 * blocks the save.
	 *
	 * @param WP_Error $errors Errors collected so far.
	 * @param bool     $update Whether this is an update (vs new user).
	 * @param object   $user   User data being saved.
	 */
	public function on_profile_update( $errors, $update, $user ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		unset( $update );

		if ( empty( $user->user_pass ) ) {
			return;
		}

		$wp_user = isset( $user->ID ) ? get_user_by( 'id', (int) $user->ID ) : null;
		if ( ! ( $wp_user instanceof WP_User ) ) {
			$wp_user = wp_get_current_user();
		}

		$violation = $this->validate_password( (string) $user->user_pass, $wp_user );
		if ( null === $violation ) {
			return;
		}
		$errors->add( 'pass', $violation );
	}

	/**
	 * Password reset handler. Same logic as the profile update path.
	 * keeping these as separate WP hooks because that is how core spreads
	 * the password change surface.
	 *
	 * @param WP_Error         $errors Existing errors.
	 * @param WP_User|WP_Error $user   Target user.
	 */
	public function on_password_reset( $errors, $user ): void {
		if ( ! ( $user instanceof WP_User ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- WP core verifies the reset key upstream; passwords must NOT be sanitized, the raw string is required to validate length, classes and HIBP hash.
		$pass = isset( $_POST['pass1'] ) ? (string) wp_unslash( $_POST['pass1'] ) : '';
		if ( '' === $pass ) {
			return;
		}

		$violation = $this->validate_password( $pass, $user );
		if ( null === $violation ) {
			return;
		}
		$errors->add( 'pass', $violation );
	}

	/**
	 * Run the configured policy checks against a candidate password.
	 *
	 * @param string        $password Candidate password.
	 * @param WP_User|null  $user     Existing user, null for a new one.
	 * @param string[]|null $roles    Roles of an account still to be created; decides the scope instead of `$user`.
	 * @return string|null Violation message or null if the password passes.
	 */
	private function validate_password( string $password, ?WP_User $user, ?array $roles = null ): ?string {
		if ( ! ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_password_policy_enabled', true ) ) {
			return null;
		}
		$in_scope = null !== $roles ? $this->roles_subject_to_policy( $roles ) : $this->user_subject_to_policy( $user );
		if ( ! $in_scope ) {
			return null;
		}

		$min_length = max( 8, (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_password_min_length', 12 ) );
		if ( strlen( $password ) < $min_length ) {
			return sprintf(
				/* translators: %d: minimum required length */
				__( 'Password must be at least %d characters long.', 'reportedip-hive' ),
				$min_length
			);
		}

		$classes = 0;
		if ( preg_match( '/[a-z]/', $password ) ) {
			++$classes;
		}
		if ( preg_match( '/[A-Z]/', $password ) ) {
			++$classes;
		}
		if ( preg_match( '/[0-9]/', $password ) ) {
			++$classes;
		}
		if ( preg_match( '/[^A-Za-z0-9]/', $password ) ) {
			++$classes;
		}

		$min_classes = max( 1, min( 4, (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_password_min_classes', 3 ) ) );
		if ( $classes < $min_classes ) {
			return sprintf(
				/* translators: %d: required character classes */
				__( 'Password must contain characters from at least %d of: lowercase, uppercase, digits, symbols.', 'reportedip-hive' ),
				$min_classes
			);
		}

		if ( in_array( strtolower( $password ), self::COMMON_PASSWORDS, true ) ) {
			return __( 'Password is too common and is on a public breach list.', 'reportedip-hive' );
		}

		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_password_check_hibp', false ) ) {
			$hibp = $this->is_password_pwned( $password );
			if ( true === $hibp ) {
				return __( 'Password appears in a public data breach. Choose a different password.', 'reportedip-hive' );
			}
		}

		return null;
	}

	/**
	 * Whether this user is in scope for the policy. With "all users" on,
	 * everyone is; otherwise the roles of the
	 * `reportedip_hive_2fa_enforce_roles` list are, and an empty list covers
	 * nobody (since 3.0.1; before, the switch only counted while the list
	 * was empty, so it did nothing next to the default administrator role).
	 */
	private function user_subject_to_policy( ?WP_User $user ): bool {
		if ( ! ( $user instanceof WP_User ) ) {
			return true;
		}
		return $this->roles_subject_to_policy( (array) $user->roles );
	}

	/**
	 * The scope rule of {@see self::user_subject_to_policy()} for a list of
	 * roles, so an account that does not exist yet is judged by its role.
	 *
	 * @param string[] $roles Role slugs.
	 * @return bool
	 * @since  3.0.1
	 */
	private function roles_subject_to_policy( array $roles ): bool {
		if ( (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_password_policy_all_users', false ) ) {
			return true;
		}

		$enforce_roles = ReportedIP_Hive_Option_Routing::resolve_2fa_enforce_roles();
		foreach ( $roles as $role ) {
			if ( in_array( $role, $enforce_roles, true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * HaveIBeenPwned k-anonymity range check. Sends only the first 5 hex
	 * characters of the SHA-1 hash, scans the response for the remaining
	 * 35 chars, and tracks the count.
	 *
	 * Soft-fail: any network error returns null so the password change is
	 * allowed (we never lock users out because of a third-party outage).
	 *
	 * @return bool|null True = pwned, false = clean, null = lookup failed.
	 */
	private function is_password_pwned( string $password ): ?bool {
		$hash   = strtoupper( sha1( $password ) );
		$prefix = substr( $hash, 0, 5 );
		$suffix = substr( $hash, 5 );
		$cache  = 'rip_hibp_' . $prefix;
		$cached = get_transient( $cache );

		if ( false === $cached ) {
			$response = wp_remote_get(
				'https://api.pwnedpasswords.com/range/' . $prefix,
				array(
					'timeout'    => 3,
					'user-agent' => 'ReportedIP-Hive/' . ( defined( 'REPORTEDIP_HIVE_VERSION' ) ? REPORTEDIP_HIVE_VERSION : 'dev' ),
					'headers'    => array( 'Add-Padding' => 'true' ),
				)
			);
			if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
				return null;
			}
			$cached = (string) wp_remote_retrieve_body( $response );
			set_transient( $cache, $cached, HOUR_IN_SECONDS );
		}

		if ( ! is_string( $cached ) || '' === $cached ) {
			return null;
		}

		return self::range_lists_suffix( $cached, $suffix );
	}

	/**
	 * Whether a range response lists the hash suffix with a count above 0.
	 *
	 * With `Add-Padding: true` the service adds several hundred made-up
	 * suffixes with the count 0, so a line `SUFFIX:0` is padding and no hit.
	 *
	 * @param string $body   Response body, one `SUFFIX:COUNT` per line.
	 * @param string $suffix The 35 hex characters after the prefix.
	 * @return bool
	 * @since  3.0.1
	 */
	public static function range_lists_suffix( string $body, string $suffix ): bool {
		$suffix = strtoupper( $suffix );
		foreach ( explode( "\n", $body ) as $line ) {
			$parts = explode( ':', trim( $line ), 2 );
			if ( strtoupper( $parts[0] ) === $suffix && isset( $parts[1] ) && (int) $parts[1] > 0 ) {
				return true;
			}
		}
		return false;
	}
}
