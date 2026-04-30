<?php
/**
 * Login-time 2FA reminder for users without an active method.
 *
 * Counts how many times a user has logged in without configuring 2FA, renders
 * a soft banner on every admin page until they set it up, and — once a
 * site-configurable threshold is reached — flips a transient that the existing
 * onboarding wizard ({@see ReportedIP_Hive_Two_Factor_Onboarding}) picks up to
 * hard-block privileged roles. Customer / Subscriber / Author roles only ever
 * see the soft banner so a missing phone never locks anyone out of WooCommerce.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.6.1
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hooks the login-reminder lifecycle. Public API is fully static — the class
 * has no per-request state. Counter and last-seen timestamp live in user-meta;
 * the dismiss flag is a short-lived transient that re-arms on the next login.
 *
 * @since 1.6.1
 */
class ReportedIP_Hive_Two_Factor_Recommend {

	/**
	 * User-meta key for the per-user reminder counter.
	 */
	const META_COUNT = 'reportedip_hive_2fa_reminder_count';

	/**
	 * User-meta key for the last `wp_login` timestamp that incremented the counter.
	 */
	const META_LAST_SEEN = 'reportedip_hive_2fa_reminder_last_seen';

	/**
	 * Minimum seconds between two counter increments. Protects against
	 * a logout/login loop inflating the count to the hard threshold.
	 */
	const SPAM_GUARD_SECS = 60;

	/**
	 * Hardcap so the counter never overflows or grows unbounded.
	 */
	const HARD_CAP = 99;

	/**
	 * Transient prefix used by the "Remind me later" button to suppress the
	 * banner inside the current admin session.
	 */
	const DISMISS_TRANSIENT_PREFIX = 'rip_hive_2fa_dismiss_';

	/**
	 * TTL for the dismiss transient — long enough for one work session,
	 * short enough that a fresh login re-shows the banner.
	 */
	const DISMISS_TTL = 1800;

	/**
	 * Site-wide options.
	 */
	const OPT_ENABLED        = 'reportedip_hive_2fa_reminder_enabled';
	const OPT_HARD_THRESHOLD = 'reportedip_hive_2fa_reminder_hard_threshold';
	const OPT_HARD_ROLES     = 'reportedip_hive_2fa_reminder_hard_roles';

	/**
	 * Defaults if the options were never written.
	 */
	const DEFAULT_THRESHOLD  = 5;
	const DEFAULT_HARD_ROLES = array( 'administrator', 'editor', 'shop_manager' );

	/**
	 * Wire the WordPress hooks. Idempotent — calling twice is safe.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'wp_login', array( __CLASS__, 'on_login' ), 30, 2 );
		add_action( 'reportedip_hive_2fa_method_enabled', array( __CLASS__, 'reset' ), 10, 2 );
		add_action( 'admin_notices', array( __CLASS__, 'maybe_render_soft_banner' ) );
		add_action( 'admin_post_reportedip_hive_2fa_remind_later', array( __CLASS__, 'handle_remind_later' ) );
	}

	/**
	 * Whether the reminder feature is enabled site-wide.
	 *
	 * @return bool
	 */
	public static function is_enabled() {
		return (bool) get_option( self::OPT_ENABLED, true );
	}

	/**
	 * `wp_login` callback — increment the counter and, if the threshold is
	 * crossed for a privileged role, set the onboarding-wizard transient so
	 * the existing redirect logic kicks the user into the hard-block flow.
	 *
	 * @param string  $user_login Login name (unused).
	 * @param mixed   $user       WP_User on success, anything else is a no-op.
	 * @return void
	 */
	public static function on_login( $user_login, $user ) {
		unset( $user_login );
		if ( ! ( $user instanceof \WP_User ) ) {
			return;
		}
		if ( ! self::is_enabled() ) {
			return;
		}
		if ( ! self::is_site_method_available() ) {
			return;
		}
		if ( self::has_any_2fa( $user->ID ) ) {
			self::reset( $user->ID, '' );
			return;
		}

		$last_seen = (int) get_user_meta( $user->ID, self::META_LAST_SEEN, true );
		if ( $last_seen > 0 && ( time() - $last_seen ) < self::SPAM_GUARD_SECS ) {
			return;
		}

		$count = (int) get_user_meta( $user->ID, self::META_COUNT, true );
		$count = min( self::HARD_CAP, $count + 1 );
		update_user_meta( $user->ID, self::META_COUNT, $count );
		update_user_meta( $user->ID, self::META_LAST_SEEN, time() );

		if ( self::should_hard_block( $user ) && class_exists( 'ReportedIP_Hive_Two_Factor_Onboarding' ) ) {
			$ttl = defined( 'ReportedIP_Hive_Two_Factor_Onboarding::TRANSIENT_TTL' )
				? ReportedIP_Hive_Two_Factor_Onboarding::TRANSIENT_TTL
				: 30 * MINUTE_IN_SECONDS;
			set_transient(
				ReportedIP_Hive_Two_Factor_Onboarding::TRANSIENT_PREFIX . $user->ID,
				1,
				$ttl
			);
		}
	}

	/**
	 * Reset the counter — fired by `reportedip_hive_2fa_method_enabled` when
	 * the user activates any method. The signature matches the action so we
	 * can hook it directly.
	 *
	 * @param int    $user_id User whose 2FA just went live.
	 * @param string $method  Method id (unused; reset is method-agnostic).
	 * @return void
	 */
	public static function reset( $user_id, $method = '' ) {
		unset( $method );
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return;
		}
		delete_user_meta( $user_id, self::META_COUNT );
		delete_user_meta( $user_id, self::META_LAST_SEEN );
	}

	/**
	 * Whether the user has at least one active 2FA method.
	 *
	 * @param int $user_id
	 * @return bool
	 */
	public static function has_any_2fa( $user_id ) {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return false;
		}
		if ( ! class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
			return false;
		}
		$methods = ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user_id );
		return ! empty( $methods );
	}

	/**
	 * Whether at least one 2FA method is enabled for the whole site.
	 * If the operator has nothing in the allow list there is nothing for the
	 * end-user to activate, so the reminder stays silent.
	 *
	 * @return bool
	 */
	public static function is_site_method_available() {
		if ( ! class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
			return false;
		}
		$allowed = ReportedIP_Hive_Two_Factor::get_allowed_methods();
		return ! empty( $allowed );
	}

	/**
	 * Whether this user should be hard-blocked at the next admin page render.
	 *
	 * @param int|\WP_User $user
	 * @return bool
	 */
	public static function should_hard_block( $user ) {
		$user_obj = ( $user instanceof \WP_User ) ? $user : get_userdata( (int) $user );
		if ( ! ( $user_obj instanceof \WP_User ) ) {
			return false;
		}
		if ( ! self::is_enabled() ) {
			return false;
		}
		if ( self::has_any_2fa( $user_obj->ID ) ) {
			return false;
		}

		$threshold = (int) get_option( self::OPT_HARD_THRESHOLD, self::DEFAULT_THRESHOLD );
		if ( $threshold <= 0 ) {
			return false;
		}
		$count = (int) get_user_meta( $user_obj->ID, self::META_COUNT, true );
		if ( $count < $threshold ) {
			return false;
		}

		return self::user_in_hard_roles( $user_obj );
	}

	/**
	 * Whether the soft banner should render for the given user.
	 *
	 * @param int $user_id
	 * @return bool
	 */
	public static function should_show_soft( $user_id ) {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return false;
		}
		if ( ! self::is_enabled() ) {
			return false;
		}
		if ( self::has_any_2fa( $user_id ) ) {
			return false;
		}

		$user = get_userdata( $user_id );
		if ( $user instanceof \WP_User && self::should_hard_block( $user ) ) {
			return false;
		}

		$count = (int) get_user_meta( $user_id, self::META_COUNT, true );
		if ( $count <= 0 ) {
			return false;
		}

		if ( get_transient( self::DISMISS_TRANSIENT_PREFIX . $user_id ) ) {
			return false;
		}
		return true;
	}

	/**
	 * `admin_notices` callback — render the soft reminder banner.
	 *
	 * @return void
	 */
	public static function maybe_render_soft_banner() {
		$user_id = get_current_user_id();
		if ( ! $user_id || ! self::should_show_soft( $user_id ) ) {
			return;
		}

		$user         = get_userdata( $user_id );
		$count        = (int) get_user_meta( $user_id, self::META_COUNT, true );
		$threshold    = (int) get_option( self::OPT_HARD_THRESHOLD, self::DEFAULT_THRESHOLD );
		$is_hard_role = self::user_in_hard_roles( $user );

		$profile_url = admin_url( 'profile.php#reportedip-hive-2fa' );
		$dismiss_url = admin_url( 'admin-post.php' );
		?>
		<div class="notice rip-alert rip-alert--warning rip-2fa-recommend">
			<p style="font-size: var(--rip-text-base); font-weight: 600; margin: 0 0 var(--rip-space-2);">
				<?php esc_html_e( 'Two-factor authentication is recommended for your account', 'reportedip-hive' ); ?>
			</p>
			<p style="margin: 0 0 var(--rip-space-2);">
				<?php
				if ( $is_hard_role && $threshold > 0 ) {
					printf(
						/* translators: 1: current reminder count, 2: hard-block threshold */
						esc_html__( 'A second factor (authenticator app, email or SMS) keeps your login safe even if your password leaks. Reminder %1$d of %2$d — after that you will need to set 2FA up before continuing.', 'reportedip-hive' ),
						(int) $count,
						(int) $threshold
					);
				} else {
					esc_html_e( 'A second factor (authenticator app, email or SMS) keeps your login safe even if your password leaks.', 'reportedip-hive' );
				}
				?>
			</p>
			<p style="margin: 0;">
				<a class="rip-button rip-button--primary" href="<?php echo esc_url( $profile_url ); ?>">
					<?php esc_html_e( 'Set up now', 'reportedip-hive' ); ?>
				</a>
				<form method="post" action="<?php echo esc_url( $dismiss_url ); ?>" style="display: inline-block; margin-left: var(--rip-space-2);">
					<input type="hidden" name="action" value="reportedip_hive_2fa_remind_later" />
					<?php wp_nonce_field( 'reportedip_hive_2fa_remind_later' ); ?>
					<button type="submit" class="rip-button rip-button--ghost">
						<?php esc_html_e( 'Remind me later', 'reportedip-hive' ); ?>
					</button>
				</form>
			</p>
		</div>
		<?php
	}

	/**
	 * `admin-post.php?action=reportedip_hive_2fa_remind_later` handler.
	 *
	 * @return void
	 */
	public static function handle_remind_later() {
		$user_id = get_current_user_id();
		if ( ! $user_id ) {
			wp_die( esc_html__( 'Permission denied.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'reportedip_hive_2fa_remind_later' );

		set_transient( self::DISMISS_TRANSIENT_PREFIX . $user_id, 1, self::DISMISS_TTL );

		$redirect = wp_get_referer();
		if ( ! $redirect ) {
			$redirect = admin_url();
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Resolve the configured hard-block roles, sanitising the option value
	 * (which may be a JSON string or a plain array depending on saved state).
	 *
	 * @return string[]
	 */
	private static function get_hard_roles() {
		$raw = get_option( self::OPT_HARD_ROLES, self::DEFAULT_HARD_ROLES );
		if ( is_string( $raw ) ) {
			$decoded = json_decode( $raw, true );
			$raw     = is_array( $decoded ) ? $decoded : self::DEFAULT_HARD_ROLES;
		}
		if ( ! is_array( $raw ) || empty( $raw ) ) {
			return self::DEFAULT_HARD_ROLES;
		}
		$clean = array_values(
			array_filter(
				array_map( 'sanitize_key', $raw ),
				static function ( $role ) {
					return '' !== (string) $role;
				}
			)
		);
		return ! empty( $clean ) ? $clean : self::DEFAULT_HARD_ROLES;
	}

	/**
	 * Whether the user has any role configured for hard-block.
	 *
	 * @param mixed $user
	 * @return bool
	 */
	private static function user_in_hard_roles( $user ) {
		if ( ! ( $user instanceof \WP_User ) ) {
			return false;
		}
		$user_roles = is_array( $user->roles ) ? $user->roles : array();
		$hard_roles = self::get_hard_roles();
		return ! empty( array_intersect( $user_roles, $hard_roles ) );
	}
}
