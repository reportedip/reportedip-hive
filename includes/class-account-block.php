<?php
/**
 * Account block enforcement, the identity-based counterpart to the IP block
 * list.
 *
 * A blocked account keeps its password and its content but cannot sign in,
 * cannot authenticate an application password and cannot complete a password
 * reset. The block is one user-meta record. This class reads it, enforces it
 * and lifts it; writing a new block belongs to the add-on.
 *
 * Enforcing an existing block and lifting it never depend on the add-on or
 * the plan: an account blocked under an earlier release, or while the
 * add-on ran, stays blocked when only this plugin is left, so a lapsed plan
 * or a removed add-on never hands a released employee their access back.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     3.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Account block record and login/reset/API enforcement.
 *
 * @since 3.0.0
 */
final class ReportedIP_Hive_Account_Block {

	/**
	 * User-meta key holding the block record. Its existence means "blocked".
	 */
	const META = '_reportedip_hive_blocked';

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
	 * Register the profile card of a blocked account on the user edit
	 * screen. Admin requests only.
	 *
	 * @return void
	 * @since  3.0.0
	 */
	public static function register_admin_hooks() {
		add_action( 'edit_user_profile', array( __CLASS__, 'render_profile_card' ) );
		add_action( 'edit_user_profile_update', array( __CLASS__, 'save_profile_card' ) );
	}

	/**
	 * Whether this plugin draws the profile card for a user. The add-on
	 * answers false and draws its own, complete card.
	 *
	 * @param WP_User $user Edited user.
	 * @return bool
	 * @since  3.0.0
	 */
	private static function owns_profile_card( $user ) {
		/**
		 * Whether the free plugin shows its card for a blocked account
		 * (state and an unblock button) on the user edit screen.
		 *
		 * @param bool    $show Default true.
		 * @param WP_User $user Edited user.
		 * @since 3.0.0
		 */
		return (bool) apply_filters( 'reportedip_hive_account_block_card', true, $user );
	}

	/**
	 * The card of a blocked account on the user edit screen: since when,
	 * by whom, the message the user sees, and a button that lifts the
	 * block. Nothing for an account that is not blocked.
	 *
	 * @param WP_User $user Edited user.
	 * @return void
	 * @since  3.0.0
	 */
	public static function render_profile_card( $user ) {
		if ( ! ( $user instanceof WP_User ) || ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}
		$record = self::get( $user->ID );
		if ( null === $record || ! self::owns_profile_card( $user ) ) {
			return;
		}

		wp_enqueue_style( 'reportedip-hive-design-system', REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/design-system.css', array(), REPORTEDIP_HIVE_VERSION );
		?>
		<h2 id="reportedip-hive-account-access"><?php esc_html_e( 'Account access', 'reportedip-hive' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<td colspan="2">
					<div class="rip-card">
						<div class="rip-card__body">
							<p>
								<span class="rip-badge rip-badge--danger"><?php esc_html_e( 'Blocked', 'reportedip-hive' ); ?></span>
								<span class="rip-text-muted">
									<?php
									printf(
										/* translators: 1: local date and time, 2: administrator name */
										esc_html__( 'since %1$s by %2$s', 'reportedip-hive' ),
										esc_html( ReportedIP_Hive::format_local_datetime( $record['blocked_at'] ) ),
										esc_html( self::blocked_by_label( $record['blocked_by'] ) )
									);
									?>
								</span>
							</p>
							<p class="rip-field-hint"><?php echo esc_html( self::message_for( $user->ID ) ); ?></p>
							<?php if ( '' !== $record['note'] ) : ?>
								<p class="rip-field-hint">
									<?php
									/* translators: %s: internal administrator note */
									echo esc_html( sprintf( __( 'Administrator note: %s', 'reportedip-hive' ), $record['note'] ) );
									?>
								</p>
							<?php endif; ?>
							<p>
								<button type="submit" class="rip-button rip-button--secondary" name="rip_account_unblock" value="1"><?php esc_html_e( 'Unblock this account', 'reportedip-hive' ); ?></button>
							</p>
							<p class="rip-field-hint"><?php esc_html_e( 'The account can sign in again right away. Its password and its content were never touched.', 'reportedip-hive' ); ?></p>
						</div>
					</div>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Lift the block when the unblock button of the card was pressed. The
	 * user edit form carries the nonce WordPress checks for every profile
	 * save; it is checked here again before anything changes.
	 *
	 * @param int $user_id Edited user.
	 * @return void
	 * @since  3.0.0
	 */
	public static function save_profile_card( $user_id ) {
		$user_id = (int) $user_id;
		if ( empty( $_POST['rip_account_unblock'] ) || ! current_user_can( 'edit_user', $user_id ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Presence check only; the nonce is verified on the next line before anything changes.
			return;
		}
		check_admin_referer( 'update-user_' . $user_id );
		$user = get_userdata( $user_id );
		if ( ! $user || ! self::owns_profile_card( $user ) ) {
			return;
		}
		self::unblock( $user_id );
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
	 * Lift a block. Never depends on the plan or on the add-on.
	 *
	 * Fires `reportedip_hive_user_unblocked` after the record is gone, so
	 * the add-on writes its audit row.
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

		/**
		 * Fires after the block of an account was lifted.
		 *
		 * @param int     $user_id Account that was unblocked.
		 * @param WP_User $user    The account.
		 * @since 3.0.0
		 */
		do_action( 'reportedip_hive_user_unblocked', $user_id, $user );

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
