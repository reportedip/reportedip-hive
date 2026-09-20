<?php
/**
 * User account blocking, the identity-based counterpart to the IP block list.
 *
 * A blocked account keeps its password and its content but cannot sign in,
 * cannot authenticate an application password and cannot complete a password
 * reset. Blocking writes one user-meta record, destroys every WordPress
 * session and revokes every trusted 2FA device, so the offboarded account is
 * out of the site within the same request.
 *
 * Writing a block is a Business feature. Enforcing an existing one and lifting
 * it are deliberately never tier-gated: a lapsed licence must not hand a
 * released employee their access back.
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
 * Account block state machine and login/reset/API enforcement.
 *
 * @since 2.1.51
 */
final class ReportedIP_Hive_User_Block {

	/**
	 * User-meta key holding the block record. Its existence means "blocked".
	 */
	const META = '_reportedip_hive_blocked';

	/**
	 * Tier feature key gating the write side.
	 */
	const FEATURE = 'user_management';

	/**
	 * Maximum length of the message shown to the blocked user.
	 */
	const MESSAGE_MAX = 500;

	/**
	 * Maximum length of the internal administrator note.
	 */
	const NOTE_MAX = 1000;

	/**
	 * Error code returned from the `authenticate` chain.
	 */
	const ERROR_CODE = 'reportedip_user_blocked';

	/**
	 * Security-log event written when a blocked account is turned away.
	 */
	const EVENT_DENIED = 'blocked_user_denied';

	/**
	 * Per-request memo for {@see count_blocked()}, keyed by blog id.
	 *
	 * @var array<int,int>
	 */
	private static $count_memo = array();

	/**
	 * Register the enforcement hooks.
	 *
	 * `authenticate` @ 30 runs after core's credential validators (20) and
	 * before the 2FA challenge (99), and acts only on a `WP_User`, so the
	 * block message is only ever shown to someone who already proved the
	 * password. `determine_current_user` @ 99 runs after core's cookie (10)
	 * and application-password (20) validators; without it a blocked account
	 * would keep working over REST and XML-RPC, because
	 * `wp_validate_application_password()` bypasses the `authenticate` chain
	 * entirely. `validate_password_reset` @ 4 runs before the 2FA reset gate
	 * at 5.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public static function register_hooks() {
		add_filter( 'authenticate', array( __CLASS__, 'deny_authenticate' ), 30, 3 );
		add_filter( 'determine_current_user', array( __CLASS__, 'deny_current_user' ), 99 );
		add_action( 'validate_password_reset', array( __CLASS__, 'deny_password_reset' ), 4, 2 );
	}

	/**
	 * Whether the current plan may create new blocks.
	 *
	 * @return bool
	 * @since  2.1.51
	 */
	public static function is_available() {
		if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			return false;
		}
		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( self::FEATURE );
		return ! empty( $status['available'] );
	}

	/**
	 * Whether an account is currently blocked.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 * @since  2.1.51
	 */
	public static function is_blocked( $user_id ) {
		return null !== self::get( (int) $user_id );
	}

	/**
	 * Read and normalise the block record.
	 *
	 * @param int $user_id User id.
	 * @return array{blocked_at:string,blocked_by:int,message:string,note:string}|null
	 * @since  2.1.51
	 */
	public static function get( $user_id ) {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return null;
		}
		return self::normalize( get_user_meta( $user_id, self::META, true ) );
	}

	/**
	 * Pad a stored record into the canonical shape. Pure.
	 *
	 * @param mixed $raw Raw meta value.
	 * @return array{blocked_at:string,blocked_by:int,message:string,note:string}|null
	 * @since  2.1.51
	 */
	public static function normalize( $raw ) {
		if ( ! is_array( $raw ) || empty( $raw['blocked_at'] ) ) {
			return null;
		}
		return array(
			'blocked_at' => (string) $raw['blocked_at'],
			'blocked_by' => isset( $raw['blocked_by'] ) ? (int) $raw['blocked_by'] : 0,
			'message'    => isset( $raw['message'] ) ? (string) $raw['message'] : '',
			'note'       => isset( $raw['note'] ) ? (string) $raw['note'] : '',
		);
	}

	/**
	 * Clean and cap the two free-text fields. Pure.
	 *
	 * @param string $message Message shown to the blocked user.
	 * @param string $note    Internal administrator note.
	 * @return array{message:string,note:string}
	 * @since  2.1.51
	 */
	public static function sanitize_texts( $message, $note ) {
		$message = sanitize_textarea_field( (string) $message );
		$note    = sanitize_textarea_field( (string) $note );

		return array(
			'message' => (string) mb_substr( $message, 0, self::MESSAGE_MAX ),
			'note'    => (string) mb_substr( $note, 0, self::NOTE_MAX ),
		);
	}

	/**
	 * Decide whether a block must be refused, from gathered inputs. Pure.
	 *
	 * @param int      $actor_id             Administrator performing the block.
	 * @param int      $target_id            Account to block.
	 * @param bool     $target_is_super      Whether the target is a network super admin.
	 * @param int|null $other_active_admins  Number of other unblocked administrators,
	 *                                       or null when the target is not an administrator.
	 * @return string '' | 'self' | 'super_admin' | 'last_admin'
	 * @since  2.1.51
	 */
	public static function refusal_reason( $actor_id, $target_id, $target_is_super, $other_active_admins ) {
		if ( (int) $actor_id > 0 && (int) $actor_id === (int) $target_id ) {
			return 'self';
		}
		if ( $target_is_super ) {
			return 'super_admin';
		}
		if ( null !== $other_active_admins && (int) $other_active_admins < 1 ) {
			return 'last_admin';
		}
		return '';
	}

	/**
	 * Gather the environment and evaluate {@see refusal_reason()}.
	 *
	 * The last-unblocked-administrator guard is single-site only. It exists to
	 * keep a site from locking itself out for good, and on a network that
	 * outcome cannot happen: super administrators are refused outright, so at
	 * least one account always keeps its way in and can lift the block. A
	 * network count would also be wrong: roles and `get_users()` answer for
	 * whichever blog the current screen sits on, which is the main site while
	 * an administrator of some other site is being blocked from Network Admin.
	 *
	 * @param int $target_id Account to block.
	 * @return string Refusal token, '' when the block may proceed.
	 * @since  2.1.51
	 */
	public static function refusal( $target_id ) {
		$target_id       = (int) $target_id;
		$target_is_super = is_multisite() && is_super_admin( $target_id );
		$other_admins    = null;

		$target       = get_userdata( $target_id );
		$target_roles = $target ? (array) $target->roles : array();

		if ( ! is_multisite() && in_array( 'administrator', $target_roles, true ) ) {
			$other_admins = 0;
			foreach ( (array) get_users(
				array(
					'role'   => 'administrator',
					'fields' => 'ID',
				)
			) as $admin_id ) {
				if ( (int) $admin_id !== $target_id && ! self::is_blocked( (int) $admin_id ) ) {
					++$other_admins;
				}
			}
		}

		return self::refusal_reason( get_current_user_id(), $target_id, $target_is_super, $other_admins );
	}

	/**
	 * Human-readable explanation for a refusal token.
	 *
	 * @param string $reason Refusal token.
	 * @return string
	 * @since  2.1.51
	 */
	public static function refusal_message( $reason ) {
		switch ( $reason ) {
			case 'self':
				return __( 'You cannot block your own account.', 'reportedip-hive' );
			case 'super_admin':
				return __( 'Network super administrators cannot be blocked.', 'reportedip-hive' );
			case 'last_admin':
				return __( 'This is the last administrator who can still sign in.', 'reportedip-hive' );
			default:
				return '';
		}
	}

	/**
	 * Block an account: record, sessions, trusted devices, audit trail.
	 *
	 * @param int    $user_id User id.
	 * @param string $message Message shown to the user on the login form.
	 * @param string $note    Internal administrator note.
	 * @return true|WP_Error
	 * @since  2.1.51
	 */
	public static function block( $user_id, $message = '', $note = '' ) {
		$user_id = (int) $user_id;
		$user    = get_userdata( $user_id );
		if ( ! $user ) {
			return new WP_Error( 'not_found', __( 'That user does not exist.', 'reportedip-hive' ) );
		}

		if ( ! self::is_available() ) {
			return new WP_Error( 'tier_locked', self::tier_locked_message() );
		}

		$refusal = self::refusal( $user_id );
		if ( '' !== $refusal ) {
			return new WP_Error( $refusal, self::refusal_message( $refusal ) );
		}

		$texts = self::sanitize_texts( $message, $note );
		update_user_meta(
			$user_id,
			self::META,
			array(
				'blocked_at' => current_time( 'mysql', true ),
				'blocked_by' => get_current_user_id(),
				'message'    => $texts['message'],
				'note'       => $texts['note'],
			)
		);
		self::$count_memo = array();

		WP_Session_Tokens::get_instance( $user_id )->destroy_all();
		ReportedIP_Hive_Two_Factor::revoke_all_trusted_devices( $user_id );

		ReportedIP_Hive_Audit_Logger::get_instance()->record(
			'user_block',
			'blocked',
			array(
				'by'          => get_current_user_id(),
				'has_message' => '' !== $texts['message'] ? 1 : 0,
				'has_note'    => '' !== $texts['note'] ? 1 : 0,
			),
			get_current_user_id(),
			(string) wp_get_current_user()->user_login,
			ReportedIP_Hive_Audit_Logger::user_object( $user, $user_id )
		);

		return true;
	}

	/**
	 * Update the two free-text fields without touching the block itself.
	 *
	 * @param int    $user_id User id.
	 * @param string $message Message shown to the user.
	 * @param string $note    Internal administrator note.
	 * @return void
	 * @since  2.1.51
	 */
	public static function update_texts( $user_id, $message, $note ) {
		$record = self::get( $user_id );
		if ( null === $record ) {
			return;
		}
		$texts             = self::sanitize_texts( $message, $note );
		$record['message'] = $texts['message'];
		$record['note']    = $texts['note'];
		update_user_meta( (int) $user_id, self::META, $record );
	}

	/**
	 * Lift a block. Never tier-gated.
	 *
	 * @param int $user_id User id.
	 * @return true|WP_Error
	 * @since  2.1.51
	 */
	public static function unblock( $user_id ) {
		$user_id = (int) $user_id;
		$user    = get_userdata( $user_id );
		if ( ! $user ) {
			return new WP_Error( 'not_found', __( 'That user does not exist.', 'reportedip-hive' ) );
		}

		if ( ! self::is_blocked( $user_id ) ) {
			return true;
		}

		delete_user_meta( $user_id, self::META );
		self::$count_memo = array();

		ReportedIP_Hive_Audit_Logger::get_instance()->record(
			'user_block',
			'unblocked',
			array( 'by' => get_current_user_id() ),
			get_current_user_id(),
			(string) wp_get_current_user()->user_login,
			ReportedIP_Hive_Audit_Logger::user_object( $user, $user_id )
		);

		return true;
	}

	/**
	 * The default sentence shown to a blocked user.
	 *
	 * Contains the word "blocked" on purpose: the anti-enumeration filter in
	 * {@see ReportedIP_Hive_User_Enumeration::normalize_login_errors()} only
	 * lets a login message through unmasked when it carries one of its
	 * passthrough needles.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	public static function default_message() {
		return __( 'This account has been blocked. Please contact the site administrator.', 'reportedip-hive' );
	}

	/**
	 * The message a blocked user sees, operator text appended to the default.
	 *
	 * @param int $user_id User id.
	 * @return string
	 * @since  2.1.51
	 */
	public static function message_for( $user_id ) {
		$record = self::get( $user_id );
		$custom = ( null !== $record ) ? trim( $record['message'] ) : '';

		return '' !== $custom
			? self::default_message() . ' ' . $custom
			: self::default_message();
	}

	/**
	 * Display label for the administrator who created a block.
	 *
	 * @param int $blocked_by Actor user id (0 = WP-CLI or system).
	 * @return string
	 * @since  2.1.51
	 */
	public static function blocked_by_label( $blocked_by ) {
		$blocked_by = (int) $blocked_by;
		if ( $blocked_by <= 0 ) {
			return __( 'WP-CLI', 'reportedip-hive' );
		}
		$actor = get_userdata( $blocked_by );
		return $actor ? (string) $actor->user_login : '#' . $blocked_by;
	}

	/**
	 * Refuse the sign-in of a blocked account.
	 *
	 * Acts only once the password has been validated, so nothing about the
	 * account state leaks to someone who does not hold the credentials.
	 *
	 * @param WP_User|WP_Error|null $user     Result so far.
	 * @param string                $username Submitted username.
	 * @param string                $password Submitted password.
	 * @return WP_User|WP_Error|null
	 * @since  2.1.51
	 */
	public static function deny_authenticate( $user, $username = '', $password = '' ) {
		unset( $username, $password );

		if ( ! ( $user instanceof WP_User ) || ! self::is_blocked( $user->ID ) ) {
			return $user;
		}

		self::log_denial( $user->ID, 'login' );

		return new WP_Error( self::ERROR_CODE, self::message_for( $user->ID ) );
	}

	/**
	 * Treat a blocked account as anonymous for every already-authenticated
	 * surface: cookies, application passwords, REST and XML-RPC.
	 *
	 * Deliberately silent, application-password clients poll, and one log row
	 * per poll would drown the event log.
	 *
	 * @param int|false $user_id Resolved user id.
	 * @return int|false
	 * @since  2.1.51
	 */
	public static function deny_current_user( $user_id ) {
		if ( (int) $user_id > 0 && self::is_blocked( (int) $user_id ) ) {
			return 0;
		}
		return $user_id;
	}

	/**
	 * Refuse a password reset for a blocked account.
	 *
	 * The lost-password form itself stays untouched (it would otherwise leak
	 * which addresses belong to blocked accounts); only the holder of the
	 * mailbox ever reaches this 403.
	 *
	 * @param WP_Error         $errors Reset errors (unused).
	 * @param WP_User|WP_Error $user   Reset target.
	 * @return void
	 * @since  2.1.51
	 */
	public static function deny_password_reset( $errors, $user = null ) {
		unset( $errors );

		if ( ! ( $user instanceof WP_User ) || ! self::is_blocked( $user->ID ) ) {
			return;
		}

		self::log_denial( $user->ID, 'password_reset' );

		ReportedIP_Hive_Two_Factor_Reset_Gate::die_with_lockout(
			__( 'Password reset blocked', 'reportedip-hive' ),
			self::message_for( $user->ID )
		);
	}

	/**
	 * Number of blocked accounts in scope.
	 *
	 * @param int $blog_id Blog id, 0 for the whole network.
	 * @return int
	 * @since  2.1.51
	 */
	public static function count_blocked( $blog_id = 0 ) {
		$blog_id = (int) $blog_id;
		if ( isset( self::$count_memo[ $blog_id ] ) ) {
			return self::$count_memo[ $blog_id ];
		}

		$query = new WP_User_Query(
			array(
				'blog_id'      => $blog_id,
				'meta_key'     => self::META, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Existence probe over a rare meta key; the alternative is a full user scan.
				'meta_compare' => 'EXISTS',
				'fields'       => 'ID',
				'number'       => 1,
				'count_total'  => true,
			)
		);

		self::$count_memo[ $blog_id ] = (int) $query->get_total();
		return self::$count_memo[ $blog_id ];
	}

	/**
	 * Drop the per-request blocked-account counter memo.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public static function flush_count_memo() {
		self::$count_memo = array();
	}

	/**
	 * Tier-lock wording, mirroring the settings registry.
	 *
	 * The single source for every surface that gates on {@see self::FEATURE}.
	 * account blocking and the session manager alike, so the plan name comes
	 * from `feature_status()` instead of being spelled out three times.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	public static function tier_locked_message() {
		$min_tier = 'business';
		if ( class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			$manager  = ReportedIP_Hive_Mode_Manager::get_instance();
			$status   = $manager->feature_status( self::FEATURE );
			$slug     = ! empty( $status['min_tier'] ) ? (string) $status['min_tier'] : $min_tier;
			$min_tier = (string) $manager->get_tier_info( $slug )['label'];
		}

		return sprintf(
			/* translators: %s: minimum plan name required for the feature */
			__( 'User management requires the %s plan.', 'reportedip-hive' ),
			$min_tier
		);
	}

	/**
	 * Write the security-log row for a refused sign-in or reset.
	 *
	 * @param int    $user_id Blocked account.
	 * @param string $surface `login` or `password_reset`.
	 * @return void
	 * @since  2.1.51
	 */
	private static function log_denial( $user_id, $surface ) {
		if ( ! class_exists( 'ReportedIP_Hive_Logger' ) ) {
			return;
		}
		ReportedIP_Hive_Logger::get_instance()->log_security_event(
			self::EVENT_DENIED,
			ReportedIP_Hive::get_client_ip(),
			array(
				'user_id' => (int) $user_id,
				'surface' => (string) $surface,
			),
			'medium'
		);
	}
}
