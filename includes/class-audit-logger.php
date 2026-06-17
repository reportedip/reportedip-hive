<?php
/**
 * User-lifecycle audit event trail (Business+).
 *
 * Records login, logout, failed login, password-reset, profile, role-change
 * and registration events into the dedicated `audit_log` table for compliance
 * and forensics — most notably a role change carries the actor (`changed_by`)
 * for privilege-escalation review, and a login from an address the user has
 * not used before is flagged as `new_ip`. Capture only happens while the
 * `audit_log` feature is available (Business+); on lower tiers the hooks are
 * never registered, so there is no database load and the existing security
 * logs remain the record for everyone. The table is treated as append-only;
 * secrets (passwords, tokens, 2FA codes) are never written.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.2
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Captures and stores user-lifecycle audit events.
 *
 * @since 2.1.2
 */
class ReportedIP_Hive_Audit_Logger {

	/**
	 * Audit table suffix (without prefix).
	 */
	const TABLE = 'reportedip_hive_audit_log';

	/**
	 * Feature key gating capture.
	 */
	const FEATURE = 'audit_log';

	/**
	 * User-meta key holding the per-user known-IP LRU list.
	 */
	const KNOWN_IPS_META = '_reportedip_hive_known_ips';

	/**
	 * Maximum remembered IPs per user (LRU).
	 */
	const KNOWN_IPS_MAX = 50;

	/**
	 * Substrings that mark a data key as sensitive and force redaction.
	 *
	 * @var string[]
	 */
	const REDACT_KEYS = array( 'password', 'pass', 'pwd', 'secret', 'token', 'otp', 'nonce', 'apikey', 'api_key' );

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Audit_Logger|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return ReportedIP_Hive_Audit_Logger
	 * @since  2.1.2
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Private constructor — wiring happens in register_hooks().
	 *
	 * @since 2.1.2
	 */
	private function __construct() {}

	/**
	 * Whether audit capture is available for the current tier/mode.
	 *
	 * @return bool
	 * @since  2.1.2
	 */
	public static function is_available() {
		if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			return false;
		}
		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( self::FEATURE );
		return ! empty( $status['available'] );
	}

	/**
	 * Register the lifecycle hooks — only when capture is available and enabled.
	 *
	 * The tier gate resolves translated feature labels, so checking it before
	 * `init` would trigger WordPress 6.7's too-early textdomain notice (and
	 * break cookie headers on debug installs). When called from the plugin
	 * bootstrap the registration therefore defers itself to `init`; every
	 * captured event (logins, profile updates, role changes) fires after
	 * `init`, so nothing is missed.
	 *
	 * @return void
	 * @since  2.1.2
	 */
	public function register_hooks() {
		if ( ! did_action( 'init' ) && ! doing_action( 'init' ) ) {
			add_action( 'init', array( $this, 'register_hooks' ), 1 );
			return;
		}
		if ( ! self::is_available() ) {
			return;
		}
		if ( ! (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_audit_enabled', true ) ) {
			return;
		}

		add_action( 'wp_login', array( $this, 'on_login' ), 10, 2 );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 10, 1 );
		add_action( 'wp_logout', array( $this, 'on_logout' ), 10, 1 );
		add_action( 'retrieve_password', array( $this, 'on_retrieve_password' ), 10, 1 );
		add_action( 'after_password_reset', array( $this, 'on_password_reset' ), 10, 2 );
		add_action( 'profile_update', array( $this, 'on_profile_update' ), 10, 2 );
		add_action( 'set_user_role', array( $this, 'on_role_change' ), 10, 3 );
		add_action( 'user_register', array( $this, 'on_register' ), 10, 1 );
	}

	/**
	 * Successful login — flagged `new_ip` when the address is unfamiliar.
	 *
	 * @param string  $user_login Login name.
	 * @param WP_User $user       Authenticated user.
	 * @return void
	 * @since  2.1.2
	 */
	public function on_login( $user_login, $user ) {
		$user_id = ( $user instanceof WP_User ) ? (int) $user->ID : 0;
		$ip      = self::client_ip();
		$action  = $this->note_ip( $user_id, $ip ) ? 'new_ip' : 'success';
		$this->log_event( 'login', $action, array(), $user_id, (string) $user_login );
	}

	/**
	 * Failed login attempt.
	 *
	 * @param string $username Submitted login name.
	 * @return void
	 * @since  2.1.2
	 */
	public function on_login_failed( $username ) {
		$this->log_event( 'login', 'failed', array(), 0, (string) $username );
	}

	/**
	 * Logout.
	 *
	 * @param int $user_id Logging-out user id (WP 5.5+).
	 * @return void
	 * @since  2.1.2
	 */
	public function on_logout( $user_id = 0 ) {
		$this->log_event( 'logout', 'success', array(), (int) $user_id );
	}

	/**
	 * Password-reset request.
	 *
	 * @param string $user_login Login name the reset was requested for.
	 * @return void
	 * @since  2.1.2
	 */
	public function on_retrieve_password( $user_login ) {
		$this->log_event( 'password_reset', 'requested', array(), 0, (string) $user_login );
	}

	/**
	 * Password-reset completion. The new password is never recorded.
	 *
	 * @param WP_User $user     User whose password was reset.
	 * @param string  $new_pass New password (ignored).
	 * @return void
	 * @since  2.1.2
	 */
	public function on_password_reset( $user, $new_pass ) {
		unset( $new_pass );
		$user_id = (int) $user->ID;
		$login   = (string) $user->user_login;
		$this->log_event( 'password_reset', 'completed', array(), $user_id, $login );
	}

	/**
	 * Profile update — records an e-mail change explicitly.
	 *
	 * @param int     $user_id       Updated user id.
	 * @param WP_User $old_user_data Pre-update user object.
	 * @return void
	 * @since  2.1.2
	 */
	public function on_profile_update( $user_id, $old_user_data ) {
		$user_id = (int) $user_id;
		$new     = get_userdata( $user_id );
		$action  = 'updated';
		$data    = array();
		if ( $new && isset( $old_user_data->user_email ) && $new->user_email !== $old_user_data->user_email ) {
			$action = 'email_changed';
		}
		$login = $new ? (string) $new->user_login : '';
		$this->log_event( 'profile_change', $action, $data, $user_id, $login );
	}

	/**
	 * Role change — captures the actor as `changed_by`.
	 *
	 * @param int      $user_id   User whose role changed.
	 * @param string   $role      New primary role.
	 * @param string[] $old_roles Previous roles.
	 * @return void
	 * @since  2.1.2
	 */
	public function on_role_change( $user_id, $role, $old_roles ) {
		$data  = array(
			'new_role'   => (string) $role,
			'old_roles'  => is_array( $old_roles ) ? array_values( $old_roles ) : array(),
			'changed_by' => (int) get_current_user_id(),
		);
		$user  = get_userdata( (int) $user_id );
		$login = $user ? (string) $user->user_login : '';
		$this->log_event( 'profile_change', 'role_changed', $data, (int) $user_id, $login );
	}

	/**
	 * New user registration.
	 *
	 * @param int $user_id Registered user id.
	 * @return void
	 * @since  2.1.2
	 */
	public function on_register( $user_id ) {
		$user  = get_userdata( (int) $user_id );
		$login = $user ? (string) $user->user_login : '';
		$this->log_event( 'registration', 'success', array(), (int) $user_id, $login );
	}

	/**
	 * Persist one audit row from gathered context.
	 *
	 * @param string               $type     Event type.
	 * @param string               $action   Event action.
	 * @param array<string,mixed>  $data     Structured event data (redacted before storage).
	 * @param int                  $user_id  Subject user id (0 for none).
	 * @param string               $username Subject username.
	 * @return void
	 * @since  2.1.2
	 */
	private function log_event( $type, $action, array $data, $user_id = 0, $username = '' ) {
		global $wpdb;

		$user_agent = '';
		if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
			$user_agent = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) );
		}

		$row = self::build_row(
			array(
				'blog_id'      => get_current_blog_id(),
				'created_at'   => current_time( 'mysql', true ),
				'ip'           => self::client_ip(),
				'user_id'      => $user_id,
				'username'     => $username,
				'event_type'   => $type,
				'event_action' => $action,
				'data'         => $data,
				'user_agent'   => $user_agent,
			)
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Append-only audit write; caching is not applicable.
		$wpdb->insert( $wpdb->base_prefix . self::TABLE, $row );
	}

	/**
	 * Build a storage-ready audit row from a context array. Pure — no WP calls.
	 *
	 * Redacts sensitive keys, JSON-encodes the data blob and clamps every
	 * field to its column width. Unit-testable without a database.
	 *
	 * @param array<string,mixed> $ctx Context (blog_id, created_at, ip, user_id, username, event_type, event_action, data, risk_score, country_code, user_agent).
	 * @return array<string,mixed>
	 * @since  2.1.2
	 */
	public static function build_row( array $ctx ) {
		$data = isset( $ctx['data'] ) && is_array( $ctx['data'] ) ? self::redact( $ctx['data'] ) : array();

		return array(
			'blog_id'      => (int) ( $ctx['blog_id'] ?? 0 ),
			'created_at'   => (string) ( $ctx['created_at'] ?? '' ),
			'ip'           => substr( (string) ( $ctx['ip'] ?? '' ), 0, 64 ),
			'user_id'      => empty( $ctx['user_id'] ) ? null : (int) $ctx['user_id'],
			'username'     => substr( (string) ( $ctx['username'] ?? '' ), 0, 60 ),
			'event_type'   => substr( (string) ( $ctx['event_type'] ?? '' ), 0, 32 ),
			'event_action' => substr( (string) ( $ctx['event_action'] ?? '' ), 0, 64 ),
			'event_data'   => empty( $data ) ? null : wp_json_encode( $data ),
			'risk_score'   => isset( $ctx['risk_score'] ) ? (int) $ctx['risk_score'] : null,
			'country_code' => empty( $ctx['country_code'] ) ? null : substr( (string) $ctx['country_code'], 0, 8 ),
			'user_agent'   => empty( $ctx['user_agent'] ) ? null : substr( (string) $ctx['user_agent'], 0, 255 ),
		);
	}

	/**
	 * Recursively replace the value of any sensitive key with a redaction marker.
	 *
	 * @param array<string,mixed> $data Raw data.
	 * @return array<string,mixed>
	 * @since  2.1.2
	 */
	public static function redact( array $data ) {
		$out = array();
		foreach ( $data as $key => $value ) {
			$lower = strtolower( (string) $key );
			$hit   = false;
			foreach ( self::REDACT_KEYS as $needle ) {
				if ( false !== strpos( $lower, $needle ) ) {
					$hit = true;
					break;
				}
			}
			if ( $hit ) {
				$out[ $key ] = '[redacted]';
			} elseif ( is_array( $value ) ) {
				$out[ $key ] = self::redact( $value );
			} else {
				$out[ $key ] = $value;
			}
		}
		return $out;
	}

	/**
	 * Whether an IP is new for a user given their known-IP list.
	 *
	 * @param string   $ip    Candidate IP.
	 * @param string[] $known Known IPs.
	 * @return bool
	 * @since  2.1.2
	 */
	public static function is_new_ip( $ip, array $known ) {
		return '' !== $ip && ! in_array( $ip, $known, true );
	}

	/**
	 * Record an IP against a user's LRU list, returning whether it was new.
	 *
	 * @param int    $user_id User id.
	 * @param string $ip      Client IP.
	 * @return bool True when the IP had not been seen for this user.
	 * @since  2.1.2
	 */
	private function note_ip( $user_id, $ip ) {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 || '' === $ip ) {
			return false;
		}
		$known = get_user_meta( $user_id, self::KNOWN_IPS_META, true );
		$known = is_array( $known ) ? $known : array();
		if ( ! self::is_new_ip( $ip, $known ) ) {
			return false;
		}
		$known[] = $ip;
		if ( count( $known ) > self::KNOWN_IPS_MAX ) {
			$known = array_slice( $known, -self::KNOWN_IPS_MAX );
		}
		update_user_meta( $user_id, self::KNOWN_IPS_META, $known );
		return true;
	}

	/**
	 * Delete audit rows older than the retention window, in one bounded batch.
	 *
	 * @param int $retention_days Days to keep.
	 * @return int Rows deleted.
	 * @since  2.1.2
	 */
	public static function cleanup( $retention_days ) {
		global $wpdb;
		$days   = max( 1, (int) $retention_days );
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
		$table  = $wpdb->base_prefix . self::TABLE;
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- $table from base_prefix + class constant; date bound is prepared; retention sweep needs no cache.
		return (int) $wpdb->query( $wpdb->prepare( "DELETE FROM $table WHERE created_at < %s LIMIT 1000", $cutoff ) );
	}

	/**
	 * Resolve the client IP through the plugin's central helper.
	 *
	 * @return string
	 * @since  2.1.2
	 */
	private static function client_ip() {
		if ( class_exists( 'ReportedIP_Hive' ) ) {
			return (string) ReportedIP_Hive::get_client_ip();
		}
		return '';
	}
}
