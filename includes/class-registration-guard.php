<?php
/**
 * Registration protection: prohibited usernames, e-mail allow/block rules, a
 * registration rate limit, allowlist-only registration and the opt-in instant
 * block for logins with a non-existent username.
 *
 * This class owns every registration-time hook. The disposable-mail classifier
 * {@see ReportedIP_Hive_Disposable_Email} used to hook the same two surfaces
 * itself; it is now the last step of one ordered pipeline so an operator's own
 * allow rule can overrule the throwaway list and a denial is logged once.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.51
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registration-time rule engine.
 *
 * @since 2.1.51
 */
final class ReportedIP_Hive_Registration_Guard {

	/**
	 * Prohibited-username list (one entry per line).
	 */
	const OPT_USERNAMES = 'reportedip_hive_prohibited_usernames';

	/**
	 * Whether the bundled baseline names are prohibited as well.
	 */
	const OPT_USERNAMES_BASELINE = 'reportedip_hive_prohibited_usernames_baseline';

	/**
	 * E-mail rule mode: off | block | allow.
	 */
	const OPT_EMAIL_MODE = 'reportedip_hive_email_rule_mode';

	/**
	 * E-mail rule list (one entry per line).
	 */
	const OPT_EMAIL_RULES = 'reportedip_hive_email_rules';

	/**
	 * Registration rate-limit master toggle.
	 */
	const OPT_LIMIT_ENABLED = 'reportedip_hive_registration_limit_enabled';

	/**
	 * Registrations allowed per window and source IP.
	 */
	const OPT_LIMIT_COUNT = 'reportedip_hive_registration_limit_count';

	/**
	 * Rate-limit window in minutes, capped at 60. This is not a sliding window.
	 * {@see ReportedIP_Hive_Database::track_attempt()} keeps a single counter
	 * row per address, so the number compared against the limit is the
	 * address's current run of registrations: it starts over once a whole
	 * window passed without one ({@see count_source_ip()} drops the stale row)
	 * and otherwise keeps adding up. A steady drip can therefore reach the
	 * limit over a longer span than the configured window. The window cannot
	 * exceed 60 minutes because the counter row restarts itself after an hour
	 * without a registration, which a longer window could never observe.
	 */
	const OPT_LIMIT_TIMEFRAME = 'reportedip_hive_registration_limit_timeframe';

	/**
	 * IP/CIDR list registration is restricted to (empty = everyone).
	 */
	const OPT_ALLOWLIST = 'reportedip_hive_registration_allowlist';

	/**
	 * Opt-in instant block for logins with a non-existent username.
	 */
	const OPT_BLOCK_UNKNOWN_USERNAME = 'reportedip_hive_block_unknown_username_login';

	/**
	 * Every option key this feature owns, in registry order.
	 *
	 * @var string[]
	 */
	const OPTION_KEYS = array(
		self::OPT_USERNAMES,
		self::OPT_USERNAMES_BASELINE,
		self::OPT_EMAIL_MODE,
		self::OPT_EMAIL_RULES,
		self::OPT_LIMIT_ENABLED,
		self::OPT_LIMIT_COUNT,
		self::OPT_LIMIT_TIMEFRAME,
		self::OPT_ALLOWLIST,
		self::OPT_BLOCK_UNKNOWN_USERNAME,
	);

	/**
	 * Entries per list a plan without `registration_rules_unlimited` may use.
	 */
	const FREE_MAX_ENTRIES = 10;

	/**
	 * Attempt-tracker key counting successful registrations per source IP.
	 */
	const ATTEMPT_TYPE = 'registration';

	/**
	 * Bundled prohibited logins. These are the names credential-stuffing lists
	 * try first; they do not count towards the free entry cap and are switched
	 * off with a single toggle.
	 *
	 * @var string[]
	 */
	const BASELINE_USERNAMES = array(
		'admin',
		'administrator',
		'root',
		'sysadmin',
		'superadmin',
		'webmaster',
		'hostmaster',
		'postmaster',
		'support',
		'moderator',
	);

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Registration_Guard|null
	 */
	private static $instance = null;

	/**
	 * Identities the pipeline already judged in this request, keyed by
	 * {@see subject_key()}. A form surface is followed by `wp_insert_user()`
	 * in the same request, and judging the same registration twice would log
	 * the throwaway-mail classifier's monitor verdict a second time.
	 *
	 * @var array<string,bool>
	 */
	private $judged = array();

	/**
	 * Get the singleton instance.
	 *
	 * @return ReportedIP_Hive_Registration_Guard
	 * @since  2.1.51
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Register every registration-time surface.
	 *
	 * @since 2.1.51
	 */
	private function __construct() {
		add_filter( 'registration_errors', array( $this, 'on_registration_errors' ), 10, 3 );
		add_action( 'woocommerce_register_post', array( $this, 'on_woocommerce_register' ), 10, 3 );
		add_filter( 'wpmu_validate_user_signup', array( $this, 'on_wpmu_validate_user_signup' ), 10, 1 );
		add_filter( 'wp_pre_insert_user_data', array( $this, 'on_pre_insert_user_data' ), 10, 2 );
		add_action( 'user_register', array( $this, 'count_registration' ), 10, 0 );
		add_action( 'after_signup_user', array( $this, 'count_signup' ), 10, 0 );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 10, 1 );
	}

	/**
	 * Validate a core WordPress registration.
	 *
	 * @param WP_Error $errors Existing registration errors.
	 * @param string   $login  Submitted user login.
	 * @param string   $email  Submitted e-mail address.
	 * @return WP_Error
	 * @since  2.1.51
	 */
	public function on_registration_errors( $errors, $login, $email ) {
		if ( $errors instanceof WP_Error ) {
			$this->validate( (string) $login, (string) $email, $errors, 'wp' );
		}
		return $errors;
	}

	/**
	 * Validate a WooCommerce registration (My Account and checkout account
	 * creation). WooCommerce fires `woocommerce_registration_errors` on the
	 * very next line with the same errors object, so hooking both surfaces
	 * would evaluate and log every submission twice.
	 *
	 * @param string   $username Submitted username.
	 * @param string   $email    Submitted e-mail address.
	 * @param WP_Error $errors   WooCommerce validation errors.
	 * @return void
	 * @since  2.1.51
	 */
	public function on_woocommerce_register( $username, $email, $errors ) {
		if ( $errors instanceof WP_Error ) {
			$this->validate( (string) $username, (string) $email, $errors, 'woocommerce' );
		}
	}

	/**
	 * Validate a Multisite signup (wp-signup.php, user and user+site forms).
	 *
	 * @param array<string,mixed> $result Signup validation result.
	 * @return array<string,mixed>
	 * @since  2.1.51
	 */
	public function on_wpmu_validate_user_signup( $result ) {
		if ( is_array( $result ) && isset( $result['errors'] ) && $result['errors'] instanceof WP_Error ) {
			$this->validate(
				isset( $result['user_name'] ) ? (string) $result['user_name'] : '',
				isset( $result['user_email'] ) ? (string) $result['user_email'] : '',
				$result['errors'],
				'multisite'
			);
			self::mirror_signup_errors( $result['errors'] );
		}
		return $result;
	}

	/**
	 * Which part of a form a denial belongs to, keyed by error code.
	 *
	 * Two surfaces ask this question. `wp-signup.php` renders three fixed
	 * codes, and a registration form this plugin does not own hangs the message
	 * on one of its own fields. One table means a new denial reason cannot
	 * reach one of them and stay silent on the other.
	 *
	 * @var array<string, string>
	 */
	const ERROR_TARGETS = array(
		'reportedip_hive_prohibited_username' => 'login',
		'reportedip_hive_email_rule'          => 'email',
		'reportedip_hive_disposable_email'    => 'email',
		'reportedip_hive_registration_ip'     => 'generic',
		'reportedip_hive_registration_limit'  => 'generic',
		'reportedip_hive_reputation'          => 'generic',
		'reportedip_hive_form_proof'          => 'generic',
	);

	/**
	 * Where a denial belongs, as `login`, `email` or `generic`.
	 *
	 * @param string $code Error code from this class or from the disposable
	 *                     e-mail check.
	 * @return string
	 * @since  2.1.61
	 */
	public static function error_target( $code ) {
		$code = (string) $code;

		return isset( self::ERROR_TARGETS[ $code ] ) ? self::ERROR_TARGETS[ $code ] : 'generic';
	}

	/**
	 * Repeat a denial under the error codes the signup form renders.
	 *
	 * `wp-signup.php` prints exactly three codes, `user_name`, `user_email`
	 * and `generic`. A denial that only carries one of this class's own codes
	 * would hand the visitor the form back with no reason at all, so each
	 * message is copied onto the code that belongs to the field it is about.
	 * An existing core message is never overwritten.
	 *
	 * @param WP_Error $errors Signup validation errors.
	 * @return void
	 * @since  2.1.51
	 */
	private static function mirror_signup_errors( WP_Error $errors ) {
		$fields = array(
			'login'   => 'user_name',
			'email'   => 'user_email',
			'generic' => 'generic',
		);

		foreach ( self::ERROR_TARGETS as $code => $target ) {
			$field   = $fields[ $target ];
			$message = (string) $errors->get_error_message( $code );
			if ( '' !== $message && '' === (string) $errors->get_error_message( $field ) ) {
				$errors->add( $field, $message );
			}
		}
	}

	/**
	 * Safety net for programmatic account creation (REST, WooCommerce REST,
	 * membership plugins, importers) that never reaches a registration form.
	 * Aborting by returning an empty data set makes core answer with its
	 * generic `empty_data` error, the friendly wording belongs to the three
	 * form surfaces above.
	 *
	 * The whole pipeline runs: WooCommerce creates the account for a checkout
	 * without firing `woocommerce_register_post`, so this is the only place a
	 * rate limit or an allowlist can still refuse it. The one carve-out is the
	 * second half of a Multisite signup, `wp-activate.php` creates the user
	 * long after the visitor passed the form and from the activation link's
	 * request, not the registration's.
	 *
	 * @param array<string,mixed> $data   Sanitised user row about to be written.
	 * @param bool                $update Whether this is an update of an existing user.
	 * @return array<string,mixed>
	 * @since  2.1.51
	 */
	public function on_pre_insert_user_data( $data, $update ) {
		if ( ! self::applies() || $update || ! is_array( $data ) ) {
			return $data;
		}
		if ( is_multisite() && 'wp-activate.php' === self::current_page() ) {
			return $data;
		}

		$login = isset( $data['user_login'] ) ? (string) $data['user_login'] : '';
		$email = isset( $data['user_email'] ) ? (string) $data['user_email'] : '';
		if ( isset( $this->judged[ self::subject_key( $login, $email ) ] ) ) {
			return $data;
		}

		$errors = new WP_Error();
		$this->validate( $login, $email, $errors, 'programmatic' );

		return $errors->has_errors() ? array() : $data;
	}

	/**
	 * Count a completed registration against the source IP.
	 *
	 * On Multisite the signup row was already counted on `after_signup_user`;
	 * the activation request that finally creates the user must not count a
	 * second time.
	 *
	 * The new user id is not part of the count: the limit is keyed on the
	 * address the request came from, so the hook is registered without
	 * arguments.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public function count_registration() {
		if ( ! self::applies() ) {
			return;
		}
		if ( is_multisite() && 'wp-activate.php' === self::current_page() ) {
			return;
		}
		$this->count_source_ip();
	}

	/**
	 * Count a Multisite user signup against the source IP. Only the user form
	 * is counted; `after_signup_site` also fires for a signed-in member adding
	 * another site, which is not a registration.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public function count_signup() {
		if ( ! self::applies() ) {
			return;
		}
		$this->count_source_ip();
	}

	/**
	 * Block the source IP of a failed login that named a username no account
	 * uses. Adds nothing to the response: the login error was already unified
	 * to `Invalid credentials.` upstream, and the block itself is the only
	 * signal the operator opted into.
	 *
	 * The login error is deliberately not accepted as an argument: by the
	 * time this runs, every login failure carries the same unified code, so
	 * the account has to be looked up explicitly.
	 *
	 * The salted fingerprint of the submitted name is only logged while
	 * `reportedip_hive_detailed_logging` is on, and it uses the same formula
	 * as every other `username_hash` in the log so an operator can line a
	 * probe up with the failed logins around it.
	 *
	 * @param string $username Submitted username.
	 * @return void
	 * @since  2.1.51
	 */
	public function on_login_failed( $username ) {
		if ( ! self::applies() ) {
			return;
		}
		if ( ! ReportedIP_Hive_Option_Routing::get( self::OPT_BLOCK_UNKNOWN_USERNAME, false ) ) {
			return;
		}

		$username = trim( (string) $username );
		if ( '' === $username ) {
			return;
		}

		$ip = ReportedIP_Hive::get_client_ip();
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return;
		}

		$database = ReportedIP_Hive_Database::get_instance();
		if ( $database->is_whitelisted( $ip ) || $database->is_blocked( $ip ) ) {
			return;
		}
		if ( self::username_exists_anywhere( $username ) ) {
			return;
		}

		$details = array(
			'attempts'  => 1,
			'threshold' => 1,
			'timeframe' => 0,
		);
		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_detailed_logging', false ) ) {
			$details['username_hash'] = hash( 'sha256', $username . wp_salt() );
		}

		$monitor = ReportedIP_Hive::get_instance()->get_security_monitor();
		if ( $monitor instanceof ReportedIP_Hive_Security_Monitor ) {
			$monitor->handle_threshold_exceeded( $ip, 'unknown_username_probe', $details );
		}
	}

	/**
	 * Run the registration pipeline. The first denial wins, so a denied
	 * attempt produces exactly one error and one log row.
	 *
	 * This is also the entry point for a registration form this plugin does not
	 * own. A membership plugin that writes the account itself instead of going
	 * through `register_new_user()` never fires `registration_errors`, so it
	 * calls this from its own validation hook with its own surface name and
	 * translates the codes through {@see error_target()}. The `judged` memo
	 * then keeps the `wp_pre_insert_user_data` safety net from judging the same
	 * sign-up a second time.
	 *
	 * @param string   $login   Submitted username.
	 * @param string   $email   Submitted e-mail address.
	 * @param WP_Error $errors  Errors object to add to.
	 * @param string   $surface Surface identifier for the log.
	 * @return void
	 * @since  2.1.51
	 */
	public function validate( $login, $email, WP_Error $errors, $surface ) {
		if ( ! self::applies() ) {
			return;
		}
		$this->judged[ self::subject_key( $login, $email ) ] = true;

		if ( $this->deny_by_allowlist( $errors, $surface ) ) {
			return;
		}
		if ( $this->deny_by_missing_form_proof( $errors, $surface ) ) {
			return;
		}
		if ( $this->deny_by_reputation( $errors, $surface ) ) {
			return;
		}
		if ( $this->deny_by_rate_limit( $errors, $surface ) ) {
			return;
		}
		if ( $this->deny_by_username( $login, $errors, $surface ) ) {
			return;
		}
		if ( $this->deny_by_email( $email, $errors, $surface ) ) {
			return;
		}
		ReportedIP_Hive_Disposable_Email::get_instance()->evaluate( (string) $email, $errors );
	}

	/**
	 * Refuse a sign-up from an address the community network knows as abusive.
	 *
	 * Same threshold, same floor and same consequence the sign-in path uses:
	 * a visitor the site would refuse a login to must not be able to open an
	 * account instead.
	 *
	 * @param WP_Error $errors  Errors object.
	 * @param string   $surface Surface identifier.
	 * @return bool True when the pipeline must stop.
	 * @since  2.1.53
	 */
	private function deny_by_reputation( WP_Error $errors, $surface ) {
		if ( ! class_exists( 'ReportedIP_Hive_Reputation_Gate' ) ) {
			return false;
		}

		$message = ReportedIP_Hive_Reputation_Gate::get_instance()->check( 'register', ReportedIP_Hive::get_client_ip() );

		if ( '' === $message ) {
			return false;
		}

		$errors->add( 'reportedip_hive_reputation', $message );

		$logger = self::logger();
		if ( $logger instanceof ReportedIP_Hive_Logger ) {
			$logger->log_security_event(
				'registration_denied',
				ReportedIP_Hive::get_client_ip(),
				array(
					'reason'  => 'community_reputation',
					'surface' => $surface,
				),
				'low'
			);
		}

		return true;
	}

	/**
	 * Refuse a sign-up that reached a form we rendered without ever running its
	 * script.
	 *
	 * Only the WordPress registration form plants an anchor, so every other
	 * surface reports `absent` and passes through untouched. `absent` never
	 * denies: it means we did not render here, not that the sender failed.
	 *
	 * @param WP_Error $errors  Errors object.
	 * @param string   $surface Surface identifier.
	 * @return bool True when the pipeline must stop.
	 * @since  2.1.53
	 */
	private function deny_by_missing_form_proof( WP_Error $errors, $surface ) {
		if ( 'wp' !== $surface || ! class_exists( 'ReportedIP_Hive_Form_Proof' ) ) {
			return false;
		}

		$proof = ReportedIP_Hive_Form_Proof::get_instance();

		/*
		 * The lenient reading: a sign-up form served from a cache filled
		 * before the anchor existed must not lock anyone out. A filled decoy
		 * and a failed proof are refused, which is what every other surface
		 * does and what this path did not do until 2.1.66.
		 */
		$message = $proof->enforce( 'register', false );

		if ( '' === $message ) {
			return false;
		}

		$errors->add( 'reportedip_hive_form_proof', $message );

		/*
		 * A second row next to the shared `form_proof_failed` one, because the
		 * registration view is where an operator looks when a sign-up did not
		 * arrive, and it filters on this event.
		 */
		$logger = self::logger();
		if ( $logger instanceof ReportedIP_Hive_Logger ) {
			$logger->log_security_event(
				'registration_denied',
				ReportedIP_Hive::get_client_ip(),
				array(
					'reason'  => 'form_proof',
					'surface' => $surface,
					'verdict' => (string) $proof->last_verdict(),
				),
				'low'
			);
		}

		return true;
	}

	/**
	 * Refuse registration from outside the operator's IP allowlist.
	 *
	 * @param WP_Error $errors  Errors object.
	 * @param string   $surface Surface identifier.
	 * @return bool True when the pipeline must stop.
	 * @since  2.1.51
	 */
	private function deny_by_allowlist( WP_Error $errors, $surface ) {
		if ( ! self::unlimited() ) {
			return false;
		}

		$ranges = ReportedIP_Hive_Proxy_Trust::parse_ranges( (string) ReportedIP_Hive_Option_Routing::get( self::OPT_ALLOWLIST, '' ) );
		if ( empty( $ranges ) ) {
			return false;
		}

		$ip = ReportedIP_Hive::get_client_ip();
		if ( ReportedIP_Hive_Proxy_Trust::source_is_trusted( $ip, $ranges ) ) {
			return false;
		}

		$errors->add(
			'reportedip_hive_registration_ip',
			__( 'Registration is not available from your network.', 'reportedip-hive' )
		);

		$logger = self::logger();
		if ( $logger instanceof ReportedIP_Hive_Logger ) {
			$logger->log_security_event(
				'registration_denied',
				$ip,
				array(
					'reason'  => 'ip_not_allowlisted',
					'surface' => $surface,
				),
				'low'
			);
		}

		return true;
	}

	/**
	 * Refuse a registration once the source IP passed the configured number of
	 * registrations inside the window. The refusal is deliberately the whole
	 * consequence: a shared office or campus address creating a handful of
	 * accounts is not an attacker, so no escalation ladder and no community
	 * report run from here.
	 *
	 * @param WP_Error $errors  Errors object.
	 * @param string   $surface Surface identifier.
	 * @return bool True when the pipeline must stop.
	 * @since  2.1.51
	 */
	private function deny_by_rate_limit( WP_Error $errors, $surface ) {
		if ( ! ReportedIP_Hive_Option_Routing::get( self::OPT_LIMIT_ENABLED, true ) ) {
			return false;
		}

		$ip = ReportedIP_Hive::get_client_ip();
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		$database = ReportedIP_Hive_Database::get_instance();
		if ( $database->is_whitelisted( $ip ) ) {
			return false;
		}

		$limit     = (int) ReportedIP_Hive_Option_Routing::get( self::OPT_LIMIT_COUNT, 3 );
		$timeframe = (int) ReportedIP_Hive_Option_Routing::get( self::OPT_LIMIT_TIMEFRAME, 60 );
		$attempts  = (int) $database->get_attempt_count( $ip, self::ATTEMPT_TYPE, $timeframe );
		if ( $attempts < $limit ) {
			return false;
		}

		$errors->add(
			'reportedip_hive_registration_limit',
			__( 'Too many registrations from your network. Please try again later.', 'reportedip-hive' )
		);

		$logger = self::logger();
		if ( $logger instanceof ReportedIP_Hive_Logger ) {
			$logger->log_security_event(
				'registration_limit',
				$ip,
				array(
					'attempts'  => $attempts,
					'threshold' => $limit,
					'timeframe' => $timeframe,
					'surface'   => $surface,
				),
				'medium'
			);
		}

		return true;
	}

	/**
	 * Refuse a prohibited username.
	 *
	 * @param string   $login   Submitted username.
	 * @param WP_Error $errors  Errors object.
	 * @param string   $surface Surface identifier.
	 * @return bool True when the pipeline must stop.
	 * @since  2.1.51
	 */
	private function deny_by_username( $login, WP_Error $errors, $surface ) {
		$hit = self::matches_any( $login, $this->username_rules() );
		if ( null === $hit ) {
			return false;
		}

		$errors->add(
			'reportedip_hive_prohibited_username',
			__( 'This username is not allowed. Please choose another one.', 'reportedip-hive' )
		);

		$logger = self::logger();
		if ( $logger instanceof ReportedIP_Hive_Logger ) {
			$logger->log_security_event(
				'prohibited_username',
				ReportedIP_Hive::get_client_ip(),
				array(
					'username' => ReportedIP_Hive_Logger::truncate( $login, 60 ),
					'rule'     => ReportedIP_Hive_Logger::truncate( $hit, 80 ),
					'surface'  => $surface,
				),
				'medium'
			);
		}

		return true;
	}

	/**
	 * Apply the e-mail rule list. In `allow` mode an empty effective list
	 * behaves like `off`, otherwise a plan downgrade that drops every entry
	 * would silently close registration for everybody.
	 *
	 * @param string   $email   Submitted e-mail address.
	 * @param WP_Error $errors  Errors object.
	 * @param string   $surface Surface identifier.
	 * @return bool True when the pipeline must stop (denied, or explicitly allowed).
	 * @since  2.1.51
	 */
	private function deny_by_email( $email, WP_Error $errors, $surface ) {
		$mode = (string) ReportedIP_Hive_Option_Routing::get( self::OPT_EMAIL_MODE, 'off' );
		if ( 'block' !== $mode && 'allow' !== $mode ) {
			return false;
		}

		$rules = $this->email_rules();
		if ( 'allow' === $mode && empty( $rules ) ) {
			return false;
		}

		$hit = self::matches_any( $email, $rules );
		if ( 'allow' === $mode && null !== $hit ) {
			return true;
		}
		if ( 'block' === $mode && null === $hit ) {
			return false;
		}

		$errors->add(
			'reportedip_hive_email_rule',
			__( 'This e-mail address cannot be used for registration.', 'reportedip-hive' )
		);

		$logger = self::logger();
		if ( $logger instanceof ReportedIP_Hive_Logger ) {
			$logger->log_security_event(
				'registration_denied',
				ReportedIP_Hive::get_client_ip(),
				array(
					'reason'  => 'block' === $mode ? 'email_blocked' : 'email_not_allowed',
					'domain'  => ReportedIP_Hive_Disposable_Email::domain_of( $email ),
					'rule'    => null === $hit ? '' : ReportedIP_Hive_Logger::truncate( $hit, 80 ),
					'surface' => $surface,
				),
				'low'
			);
		}

		return true;
	}

	/**
	 * Count the current request's source IP as one registration.
	 *
	 * A row the window no longer covers is dropped first. The shared attempt
	 * counter only restarts on its own after a full idle hour, so without this
	 * a window shorter than that would keep the count of a long-finished burst
	 * alive and refuse the address after a single further registration.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	private function count_source_ip() {
		$ip = ReportedIP_Hive::get_client_ip();
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return;
		}

		$database = ReportedIP_Hive_Database::get_instance();
		if ( $database->is_whitelisted( $ip ) ) {
			return;
		}

		$timeframe = (int) ReportedIP_Hive_Option_Routing::get( self::OPT_LIMIT_TIMEFRAME, 60 );
		if ( 0 === (int) $database->get_attempt_count( $ip, self::ATTEMPT_TYPE, $timeframe ) ) {
			$database->reset_attempt_counter( $ip, self::ATTEMPT_TYPE );
		}

		$database->track_attempt( $ip, self::ATTEMPT_TYPE );
	}

	/**
	 * Whether the rules apply to the current actor. Anyone who may create
	 * accounts is creating them deliberately, and neither WP-CLI nor cron is a
	 * visitor filling in a form.
	 *
	 * @return bool
	 * @since  2.1.51
	 */
	private static function applies() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return false;
		}
		if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
			return false;
		}
		if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in()
			&& ( current_user_can( 'create_users' ) || current_user_can( 'promote_users' ) ) ) {
			return false;
		}
		return true;
	}

	/**
	 * The script actually executing this request, or an empty string.
	 *
	 * Deliberately not `$GLOBALS['pagenow']`: WordPress derives that from
	 * `PHP_SELF`, which carries `PATH_INFO`, so a request to
	 * `/index.php/wp-activate.php` would report `wp-activate.php` and let a
	 * visitor skip the checks keyed on it. `SCRIPT_NAME` names the resolved
	 * file and cannot be steered that way.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	private static function current_page() {
		if ( ! isset( $_SERVER['SCRIPT_NAME'] ) ) {
			return '';
		}

		return basename( sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) );
	}

	/**
	 * Request-scoped key for one submitted identity.
	 *
	 * @param string $login Submitted username.
	 * @param string $email Submitted e-mail address.
	 * @return string
	 * @since  2.1.51
	 */
	private static function subject_key( $login, $email ) {
		return strtolower( trim( (string) $login ) . '|' . trim( (string) $email ) );
	}

	/**
	 * Whether the plan lifts the entry cap, allows regular expressions and
	 * enables allowlist-only registration.
	 *
	 * @return bool
	 * @since  2.1.51
	 */
	private static function unlimited() {
		if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			return false;
		}
		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'registration_rules_unlimited' );
		return ! empty( $status['available'] );
	}

	/**
	 * Active prohibited-username rules, baseline included when enabled.
	 *
	 * @return string[]
	 * @since  2.1.51
	 */
	private function username_rules() {
		$rules = self::active_entries(
			(string) ReportedIP_Hive_Option_Routing::get( self::OPT_USERNAMES, '' ),
			self::unlimited()
		);

		if ( ReportedIP_Hive_Option_Routing::get( self::OPT_USERNAMES_BASELINE, true ) ) {
			$rules = array_merge( self::BASELINE_USERNAMES, $rules );
		}

		return $rules;
	}

	/**
	 * Active e-mail rules.
	 *
	 * @return string[]
	 * @since  2.1.51
	 */
	private function email_rules() {
		return self::active_entries(
			(string) ReportedIP_Hive_Option_Routing::get( self::OPT_EMAIL_RULES, '' ),
			self::unlimited()
		);
	}

	/**
	 * The plugin logger, or null when the bootstrap has not run.
	 *
	 * @return ReportedIP_Hive_Logger|null
	 * @since  2.1.51
	 */
	private static function logger() {
		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return null;
		}
		$logger = ReportedIP_Hive::get_instance()->get_logger();
		return $logger instanceof ReportedIP_Hive_Logger ? $logger : null;
	}

	/**
	 * Split a stored list value into its entries. Stored values are canonical
	 * (one entry per line, comments already dropped by the sanitizer); the
	 * comment and blank-line handling stays so a hand-edited option or an
	 * older transport payload cannot inject an empty rule that matches
	 * everything.
	 *
	 * @param string $raw Stored option value.
	 * @return string[] Entries, de-duplicated, order preserved.
	 * @since  2.1.51
	 */
	public static function stored_entries( $raw ) {
		$entries = array();

		foreach ( preg_split( '/\r\n|\r|\n/', (string) $raw ) as $line ) {
			$line = trim( (string) $line );
			if ( '' === $line || 0 === strpos( $line, '#' ) ) {
				continue;
			}
			if ( ! in_array( $line, $entries, true ) ) {
				$entries[] = $line;
			}
		}

		return $entries;
	}

	/**
	 * The entries a plan actually enforces: everything on Professional and
	 * above, the first {@see FREE_MAX_ENTRIES} plain entries otherwise.
	 * Regular expressions are dropped rather than treated as literals so a
	 * downgrade cannot turn a pattern into a rule that matches nothing.
	 *
	 * @param string $raw       Stored option value.
	 * @param bool   $unlimited Whether the plan lifts the cap.
	 * @return string[]
	 * @since  2.1.51
	 */
	public static function active_entries( $raw, $unlimited ) {
		$entries = self::stored_entries( $raw );
		if ( $unlimited ) {
			return $entries;
		}

		$active = array();
		foreach ( $entries as $entry ) {
			if ( 'regex' === self::entry_kind( $entry ) ) {
				continue;
			}
			$active[] = $entry;
			if ( count( $active ) >= self::FREE_MAX_ENTRIES ) {
				break;
			}
		}

		return $active;
	}

	/**
	 * Classify one entry: `/.../` is a regular expression, an entry containing
	 * `*` is a wildcard, everything else is compared literally.
	 *
	 * @param string $entry List entry.
	 * @return string `exact` | `wildcard` | `regex`
	 * @since  2.1.51
	 */
	public static function entry_kind( $entry ) {
		$entry = (string) $entry;
		if ( strlen( $entry ) >= 3 && 0 === strpos( $entry, '/' ) && '/' === substr( $entry, -1 ) ) {
			return 'regex';
		}
		if ( false !== strpos( $entry, '*' ) ) {
			return 'wildcard';
		}
		return 'exact';
	}

	/**
	 * The PCRE body an entry executes as, or null for a literal entry.
	 * Case-insensitivity travels inline so the pattern keeps its meaning
	 * through {@see ReportedIP_Hive_WAF::compile_pattern()}, which owns the
	 * delimiter.
	 *
	 * @param string $entry List entry.
	 * @return string|null PCRE body, or null when the entry is compared literally.
	 * @since  2.1.51
	 */
	public static function entry_pattern( $entry ) {
		$entry = (string) $entry;
		$kind  = self::entry_kind( $entry );

		if ( 'regex' === $kind ) {
			return '(?i)' . substr( $entry, 1, -1 );
		}
		if ( 'wildcard' === $kind ) {
			return '(?i)^' . str_replace( '\*', '.*', preg_quote( strtolower( $entry ) ) ) . '$'; // phpcs:ignore WordPress.PHP.PregQuoteDelimiter.Missing -- The delimiter is added by WAF::compile_pattern(), which escapes it itself; quoting it here too would double-escape.
		}

		return null;
	}

	/**
	 * The first entry matching the subject, or null.
	 *
	 * @param string   $subject Username or e-mail address.
	 * @param string[] $entries Active entries.
	 * @return string|null The matching entry, for the log.
	 * @since  2.1.51
	 */
	public static function matches_any( $subject, array $entries ) {
		$subject = trim( (string) $subject );
		if ( '' === $subject ) {
			return null;
		}
		$lowered = strtolower( $subject );

		foreach ( $entries as $entry ) {
			$entry = (string) $entry;
			if ( 'exact' === self::entry_kind( $entry ) ) {
				if ( strtolower( $entry ) === $lowered ) {
					return $entry;
				}
				continue;
			}

			$pattern = self::entry_pattern( $entry );
			if ( null === $pattern ) {
				continue;
			}
			if ( null !== ReportedIP_Hive_WAF::match_fragment( $pattern, $subject ) ) {
				return $entry;
			}
		}

		return null;
	}

	/**
	 * Whether any account uses this login or e-mail address.
	 *
	 * @param string $username Submitted username.
	 * @return bool
	 * @since  2.1.51
	 */
	public static function username_exists_anywhere( $username ) {
		$username = (string) $username;
		if ( false !== get_user_by( 'login', $username ) ) {
			return true;
		}
		return is_email( $username ) && false !== get_user_by( 'email', $username );
	}

	/**
	 * Sanitize the prohibited-username list. WordPress logins may contain
	 * spaces, so only newlines and commas separate entries here.
	 *
	 * @param mixed $value Raw textarea value.
	 * @return string Canonical newline-joined list.
	 * @since  2.1.51
	 */
	public static function sanitize_username_list( $value ) {
		return self::sanitize_list( $value, '/,+/', false );
	}

	/**
	 * Sanitize the e-mail rule list. A bare hostname is stored as `*@hostname`
	 * so the obvious input matches the way an operator expects.
	 *
	 * @param mixed $value Raw textarea value.
	 * @return string Canonical newline-joined list.
	 * @since  2.1.51
	 */
	public static function sanitize_email_rule_list( $value ) {
		return self::sanitize_list( $value, '/[\s,]+/', true );
	}

	/**
	 * Sanitize the registration IP allowlist through the shared trusted-proxy
	 * parser, so one validator decides what a valid IP or CIDR entry is.
	 *
	 * @param mixed $value Raw textarea value.
	 * @return string Canonical newline-joined list.
	 * @since  2.1.51
	 */
	public static function sanitize_ip_list( $value ) {
		$lines = array();
		foreach ( preg_split( '/\r\n|\r|\n/', (string) ( is_scalar( $value ) ? $value : '' ) ) as $line ) {
			$line = trim( (string) $line );
			if ( '' === $line || 0 === strpos( $line, '#' ) ) {
				continue;
			}
			$lines[] = (string) preg_replace( '/[\s,]+/', "\n", $line );
		}

		return implode( "\n", ReportedIP_Hive_Proxy_Trust::parse_ranges( implode( "\n", $lines ) ) );
	}

	/**
	 * Whether a sanitized list value needs the Professional entry allowance:
	 * more than {@see FREE_MAX_ENTRIES} entries, or any regular expression.
	 *
	 * @param mixed $value Sanitized list value.
	 * @return bool
	 * @since  2.1.51
	 */
	public static function list_needs_tier( $value ) {
		$entries = self::stored_entries( (string) ( is_scalar( $value ) ? $value : '' ) );
		if ( count( $entries ) > self::FREE_MAX_ENTRIES ) {
			return true;
		}
		foreach ( $entries as $entry ) {
			if ( 'regex' === self::entry_kind( $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Shared list sanitizer.
	 *
	 * Regular-expression entries bypass `sanitize_text_field()`: it strips
	 * percent-encoded octets and angle brackets, which silently rewrites a
	 * pattern before it is ever compiled. They are checked for valid UTF-8,
	 * stripped of control characters and dropped when they do not compile.
	 *
	 * @param mixed  $value           Raw textarea value.
	 * @param string $separator       PCRE splitting entries inside one line.
	 * @param bool   $normalise_hosts Whether a bare hostname becomes `*@hostname`.
	 * @return string Canonical newline-joined list.
	 * @since  2.1.51
	 */
	private static function sanitize_list( $value, $separator, $normalise_hosts ) {
		$entries = array();

		foreach ( preg_split( '/\r\n|\r|\n/', (string) ( is_scalar( $value ) ? $value : '' ) ) as $line ) {
			$line = trim( (string) $line );
			if ( '' === $line || 0 === strpos( $line, '#' ) ) {
				continue;
			}

			$parts = 'regex' === self::entry_kind( $line ) ? array( $line ) : (array) preg_split( $separator, $line );

			foreach ( $parts as $part ) {
				$part = trim( (string) $part );
				if ( '' === $part ) {
					continue;
				}

				if ( 'regex' === self::entry_kind( $part ) ) {
					$part = self::sanitize_regex_entry( $part );
				} else {
					$part = strtolower( sanitize_text_field( $part ) );
					if ( $normalise_hosts && '' !== $part && false === strpos( $part, '@' ) && false === strpos( $part, '*' ) ) {
						$part = '*@' . $part;
					}
				}

				if ( '' === $part || in_array( $part, $entries, true ) ) {
					continue;
				}
				$entries[] = $part;
			}
		}

		return implode( "\n", $entries );
	}

	/**
	 * Validate one regular-expression entry, or drop it.
	 *
	 * @param string $entry Raw `/.../` entry.
	 * @return string The entry, or an empty string when it is unusable.
	 * @since  2.1.51
	 */
	private static function sanitize_regex_entry( $entry ) {
		$entry = function_exists( 'wp_check_invalid_utf8' ) ? (string) wp_check_invalid_utf8( $entry ) : (string) $entry;
		$entry = (string) preg_replace( '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $entry );
		if ( 'regex' !== self::entry_kind( $entry ) ) {
			return '';
		}

		return self::pattern_compiles( (string) self::entry_pattern( $entry ) ) ? $entry : '';
	}

	/**
	 * Whether a PCRE body compiles. Uses the firewall's delimiter so the
	 * check and the later execution agree on what the pattern is.
	 *
	 * @param string $pattern PCRE body.
	 * @return bool
	 * @since  2.1.51
	 */
	private static function pattern_compiles( $pattern ) {
		if ( '' === $pattern ) {
			return false;
		}

		return false !== @preg_match( ReportedIP_Hive_WAF::compile_pattern( $pattern ), '' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- An operator typo must be reported as a rejected entry, not as a PHP warning in the admin response.
	}
}
