<?php
/**
 * Audit event trail (Business+): the one writer of the `audit_log` table.
 *
 * Records who did what on the site into a dedicated, append-only table:
 * account events (sign-ins, resets, role changes with the acting user,
 * blocks, sessions) are captured here, everything else by the connectors
 * in `includes/audit/`, one per trigger group of
 * {@see ReportedIP_Hive_Audit_Registry}. Capture only happens while the
 * `audit_log` feature is available (Business+) and the trail is switched
 * on; on lower tiers no hook is registered, so there is no database load
 * and the security log remains the record for everyone. Every row names
 * the acting user in `user_id`/`username` and the affected object in
 * `object_type`/`object_id`/`object_label`. Secrets (passwords, tokens,
 * codes) are never written.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.2
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Captures and stores audit events.
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
	 * Schema version that added the object columns.
	 */
	const OBJECT_COLUMNS_VERSION = 17;

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
	 * Drop the host part of every logged address.
	 */
	const OPT_ANONYMIZE_IP = 'reportedip_hive_audit_anonymize_ip';

	/**
	 * Mail the notification recipients when an account signs in from an
	 * address it has not used before.
	 */
	const OPT_NEW_IP_ALERT = 'reportedip_hive_audit_new_ip_alert';

	/**
	 * Cooldown between two new-IP alerts for the same account, in seconds.
	 */
	const NEW_IP_ALERT_COOLDOWN = 900;

	/**
	 * Connector class per trigger group, loaded from `includes/audit/`.
	 *
	 * @var array<string, string>
	 */
	const CONNECTORS = array(
		'content'       => 'ReportedIP_Hive_Audit_Connector_Content',
		'installer'     => 'ReportedIP_Hive_Audit_Connector_Installer',
		'settings'      => 'ReportedIP_Hive_Audit_Connector_Settings',
		'menus_widgets' => 'ReportedIP_Hive_Audit_Connector_Menus',
		'editor'        => 'ReportedIP_Hive_Audit_Connector_Editor',
		'multisite'     => 'ReportedIP_Hive_Audit_Connector_Multisite',
	);

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Audit_Logger|null
	 */
	private static $instance = null;

	/**
	 * Whether the object columns exist, resolved once per request.
	 *
	 * @var bool|null
	 */
	private static $has_object_columns = null;

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
	 * Private constructor, wiring happens in register_hooks().
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
	 * Whether the trail is available and switched on.
	 *
	 * @return bool
	 * @since  2.1.62
	 */
	public static function is_enabled() {
		if ( ! self::is_available() ) {
			return false;
		}
		return (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_audit_enabled', true );
	}

	/**
	 * Register the capture hooks of every enabled trigger group.
	 *
	 * The tier gate resolves translated feature labels, so checking it before
	 * `init` would trigger WordPress 6.7's too-early textdomain notice (and
	 * break cookie headers on debug installs). When called from the plugin
	 * bootstrap the registration therefore defers itself to `init`; every
	 * captured event fires after `init`, so nothing is missed.
	 *
	 * @return void
	 * @since  2.1.2
	 */
	public function register_hooks() {
		if ( ! did_action( 'init' ) && ! doing_action( 'init' ) ) {
			add_action( 'init', array( $this, 'register_hooks' ), 1 );
			return;
		}
		if ( ! self::is_enabled() ) {
			return;
		}

		$groups = ReportedIP_Hive_Audit_Registry::enabled_groups();

		if ( in_array( 'logins', $groups, true ) ) {
			add_action( 'wp_login', array( $this, 'on_login' ), 10, 2 );
			add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 10, 1 );
			add_action( 'wp_logout', array( $this, 'on_logout' ), 10, 1 );
		}

		if ( in_array( 'users', $groups, true ) ) {
			self::load_connectors();
			add_action( 'retrieve_password', array( $this, 'on_retrieve_password' ), 10, 1 );
			add_action( 'after_password_reset', array( $this, 'on_password_reset' ), 10, 2 );
			add_action( 'profile_update', array( $this, 'on_profile_update' ), 10, 2 );
			add_action( 'set_user_role', array( $this, 'on_role_change' ), 10, 3 );
			add_action( 'user_register', array( $this, 'on_register' ), 10, 1 );
			add_action( 'deleted_user', array( $this, 'on_user_deleted' ), 10, 3 );
			add_action( 'wpmu_delete_user', array( $this, 'on_network_user_deleted' ), 10, 2 );
		}

		foreach ( self::CONNECTORS as $group => $class ) {
			if ( ! in_array( $group, $groups, true ) ) {
				continue;
			}
			self::load_connectors();
			( new $class() )->register();
		}
	}

	/**
	 * Require the connector base class and every connector file once.
	 *
	 * @return void
	 * @since  2.1.62
	 */
	public static function load_connectors() {
		if ( class_exists( 'ReportedIP_Hive_Audit_Connector', false ) ) {
			return;
		}
		$dir = REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/audit/';
		require_once $dir . 'class-audit-connector.php';
		foreach ( array( 'content', 'installer', 'settings', 'menus', 'editor', 'multisite' ) as $name ) {
			require_once $dir . 'class-audit-connector-' . $name . '.php';
		}
	}

	/**
	 * Successful login, flagged `new_ip` when the address is unfamiliar.
	 *
	 * @param string  $user_login Login name.
	 * @param WP_User $user       Authenticated user.
	 * @return void
	 * @since  2.1.2
	 */
	public function on_login( $user_login, $user ) {
		$user_id = ( $user instanceof WP_User ) ? (int) $user->ID : 0;
		$ip      = self::client_ip();
		$is_new  = self::note_ip( $user_id, $ip );
		$action  = $is_new ? 'new_ip' : 'success';
		$this->log_event( 'login', $action, array(), $user_id, (string) $user_login );

		if ( $is_new ) {
			$this->alert_new_ip( $user_id, (string) $user_login, $ip );
		}
	}

	/**
	 * Mail the notification recipients about a sign-in from an unfamiliar
	 * address.
	 *
	 * Deliberately quiet by default and rate-limited per account: the trail
	 * already records every one of these, and an alert that fires on each
	 * dynamic-IP change trains its readers to ignore it.
	 *
	 * @param int    $user_id    Signing-in user.
	 * @param string $user_login Login name.
	 * @param string $ip         Client address.
	 * @return void
	 * @since  2.1.51
	 */
	private function alert_new_ip( $user_id, $user_login, $ip ) {
		if ( ! ReportedIP_Hive_Option_Routing::get( self::OPT_NEW_IP_ALERT, false ) ) {
			return;
		}
		if ( ! class_exists( 'ReportedIP_Hive_Mailer' ) || ! class_exists( 'ReportedIP_Hive_Defaults' ) ) {
			return;
		}

		$recipients = ReportedIP_Hive_Defaults::notify_recipients();
		if ( empty( $recipients ) ) {
			return;
		}

		$throttle = 'rip_audit_newip_' . $user_id;
		if ( get_transient( $throttle ) ) {
			return;
		}
		set_transient( $throttle, 1, self::NEW_IP_ALERT_COOLDOWN );

		if ( ReportedIP_Hive_Option_Routing::get( self::OPT_ANONYMIZE_IP, false ) ) {
			$ip = self::anonymize_ip( $ip );
		}

		$body = sprintf(
			/* translators: 1: login name, 2: IP address, 3: site name */
			__( 'The account %1$s signed in from %2$s on %3$s. This address has not been used by that account before. If this was expected, no action is needed.', 'reportedip-hive' ),
			$user_login,
			$ip,
			wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES )
		);

		ReportedIP_Hive_Mailer::get_instance()->send(
			array(
				'to'              => implode( ', ', $recipients ),
				/* translators: %s: login name */
				'subject'         => sprintf( __( 'New sign-in location for %s', 'reportedip-hive' ), $user_login ),
				'intro_text'      => __( 'An account signed in from an address it has not used before.', 'reportedip-hive' ),
				'main_block_html' => '<p>' . esc_html( $body ) . '</p>',
				'main_block_text' => $body,
				'security_notice' => array(
					'ip'        => $ip,
					'timestamp' => ReportedIP_Hive::format_local_datetime( current_time( 'mysql', true ) ),
				),
				'context'         => array( 'source' => 'audit_new_ip' ),
			)
		);
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
		$user = get_userdata( (int) $user_id );
		$this->log_event( 'logout', 'success', array(), (int) $user_id, $user ? (string) $user->user_login : '' );
	}

	/**
	 * Password-reset request. Nobody is signed in, so the requested account
	 * is the object.
	 *
	 * @param string $user_login Login name the reset was requested for.
	 * @return void
	 * @since  2.1.2
	 */
	public function on_retrieve_password( $user_login ) {
		$user = get_user_by( 'login', (string) $user_login );
		$this->log_event( 'password_reset', 'requested', array(), 0, '', self::user_object( $user, 0, (string) $user_login ) );
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
		$this->log_event( 'password_reset', 'completed', array(), 0, '', self::user_object( $user, (int) $user->ID ) );
	}

	/**
	 * Profile update; an e-mail or password change is named explicitly.
	 *
	 * The password is detected by comparing the stored hashes; neither hash
	 * is written anywhere. In the request that registered the account, or
	 * changed its role or e-mail, a second generic or password row is
	 * noise: WP-CLI and the network sign-up write the password in a
	 * follow-up update, and every role change comes with a profile update.
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
		if ( $new && isset( $old_user_data->user_email ) && $new->user_email !== $old_user_data->user_email ) {
			$action = 'email_changed';
		} elseif ( $new && isset( $old_user_data->user_pass ) && (string) $new->user_pass !== (string) $old_user_data->user_pass ) {
			$action = 'password_changed';
		}
		if ( ReportedIP_Hive_Audit_Connector::seen( 'user:' . $user_id . ':specific' ) && in_array( $action, array( 'updated', 'password_changed' ), true ) ) {
			return;
		}
		if ( 'email_changed' === $action ) {
			ReportedIP_Hive_Audit_Connector::seen( 'user:' . $user_id . ':specific' );
		}
		$this->record_actor_event( 'profile_change', $action, array(), self::user_object( $new, $user_id ) );
	}

	/**
	 * Role change, with the actor in the user column and `changed_by` in the data.
	 *
	 * @param int      $user_id   User whose role changed.
	 * @param string   $role      New primary role.
	 * @param string[] $old_roles Previous roles.
	 * @return void
	 * @since  2.1.2
	 */
	public function on_role_change( $user_id, $role, $old_roles ) {
		if ( ReportedIP_Hive_Audit_Connector::suppressed( 'set_user_role' ) ) {
			return;
		}
		if ( empty( $old_roles ) ) {
			return;
		}
		ReportedIP_Hive_Audit_Connector::seen( 'user:' . (int) $user_id . ':specific' );
		$data = array(
			'new_role'   => (string) $role,
			'old_roles'  => is_array( $old_roles ) ? array_values( $old_roles ) : array(),
			'changed_by' => (int) get_current_user_id(),
		);
		$this->record_actor_event( 'profile_change', 'role_changed', $data, self::user_object( get_userdata( (int) $user_id ), (int) $user_id ) );
	}

	/**
	 * New user registration. Self-registrations have no actor.
	 *
	 * @param int $user_id Registered user id.
	 * @return void
	 * @since  2.1.2
	 */
	public function on_register( $user_id ) {
		ReportedIP_Hive_Audit_Connector::seen( 'user:' . (int) $user_id . ':specific' );
		$this->record_actor_event( 'registration', 'success', array(), self::user_object( get_userdata( (int) $user_id ), (int) $user_id ) );
	}

	/**
	 * User deleted on a single site, or removed from the network as a whole.
	 *
	 * @param int          $user_id  Deleted user id.
	 * @param int|null     $reassign User the content went to.
	 * @param WP_User|null $user     Deleted user (WP 5.5+).
	 * @return void
	 * @since  2.1.62
	 */
	public function on_user_deleted( $user_id, $reassign = null, $user = null ) {
		if ( ReportedIP_Hive_Audit_Connector::suppressed( 'deleted_user' ) ) {
			return;
		}
		$this->record_actor_event(
			'user',
			'deleted',
			array( 'reassign' => (int) $reassign ),
			self::user_object( $user, (int) $user_id )
		);
	}

	/**
	 * Network-wide user deletion; the embedded per-site `deleted_user` and the
	 * `remove_user_from_blog` core fires for every site are silenced.
	 *
	 * @param int          $user_id Deleted user id.
	 * @param WP_User|null $user    Deleted user (WP 5.5+).
	 * @return void
	 * @since  2.1.62
	 */
	public function on_network_user_deleted( $user_id, $user = null ) {
		self::load_connectors();
		ReportedIP_Hive_Audit_Connector::suppress( 'deleted_user' );
		ReportedIP_Hive_Audit_Connector::suppress( 'remove_user_from_blog' );
		$this->record_actor_event( 'user', 'deleted', array( 'network' => 1 ), self::user_object( $user, (int) $user_id ), 0 );
	}

	/**
	 * Public entry point for callers outside the lifecycle listeners.
	 *
	 * Honours the same tier and opt-out gate as the automatic listeners, plus
	 * the trigger group of the event, so a site that switched a group off
	 * does not gain rows through another surface.
	 *
	 * @param string              $type     Event type.
	 * @param string              $action   Event action.
	 * @param array<string,mixed> $data     Structured event data.
	 * @param int                 $user_id  Acting user id (0 for none).
	 * @param string              $username Acting user's login.
	 * @param array<string,mixed> $object   `type`, `id`, `label` of the affected object.
	 * @param int|null            $blog_id  Explicit scope, 0 for network rows, null for the current site.
	 * @return void
	 * @since  2.1.51
	 */
	public function record( $type, $action, array $data, $user_id = 0, $username = '', array $object = array(), $blog_id = null ) {
		if ( ! self::is_enabled() ) {
			return;
		}
		$event = ReportedIP_Hive_Audit_Registry::event( (string) $type, (string) $action );
		if ( $event && ! ReportedIP_Hive_Audit_Registry::group_enabled( $event['group'] ) ) {
			return;
		}
		$this->log_event( (string) $type, (string) $action, $data, (int) $user_id, (string) $username, $object, $blog_id );
	}

	/**
	 * Row with the signed-in user as the actor.
	 *
	 * @param string              $type    Event type.
	 * @param string              $action  Event action.
	 * @param array<string,mixed> $data    Structured data.
	 * @param array<string,mixed> $object  Affected object.
	 * @param int|null            $blog_id Scope.
	 * @return void
	 * @since  2.1.62
	 */
	private function record_actor_event( $type, $action, array $data, array $object, $blog_id = null ) {
		$actor = wp_get_current_user();
		$this->log_event( $type, $action, $data, (int) $actor->ID, (string) $actor->user_login, $object, $blog_id );
	}

	/**
	 * How the current request reached WordPress.
	 *
	 * @return string One of `cli`, `cron`, `xmlrpc`, `rest`, `ajax`, `web`.
	 * @since  2.1.62
	 */
	public static function agent() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'cli';
		}
		if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
			return 'cron';
		}
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return 'xmlrpc';
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'rest';
		}
		if ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) {
			return 'ajax';
		}
		return 'web';
	}

	/**
	 * Object descriptor of a user account.
	 *
	 * @param WP_User|false|null $user     User, when still resolvable.
	 * @param int                $user_id  Id fallback.
	 * @param string             $login    Login fallback.
	 * @return array{type:string, id:int, label:string}
	 * @since  2.1.62
	 */
	public static function user_object( $user, $user_id, $login = '' ) {
		if ( $user instanceof WP_User ) {
			$user_id = (int) $user->ID;
			$login   = (string) $user->user_login;
		}
		return array(
			'type'  => 'user',
			'id'    => (int) $user_id,
			'label' => '' !== $login ? $login : '#' . (int) $user_id,
		);
	}

	/**
	 * Persist one audit row from gathered context.
	 *
	 * @param string              $type     Event type.
	 * @param string              $action   Event action.
	 * @param array<string,mixed> $data     Structured event data (redacted before storage).
	 * @param int                 $user_id  Acting user id (0 for none).
	 * @param string              $username Acting user's login.
	 * @param array<string,mixed> $object   Affected object.
	 * @param int|null            $blog_id  Scope; null means the current site.
	 * @return void
	 * @since  2.1.2
	 */
	private function log_event( $type, $action, array $data, $user_id = 0, $username = '', array $object = array(), $blog_id = null ) {
		global $wpdb;

		$user_agent = '';
		if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
			$user_agent = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) );
		}
		if ( ! isset( $data['agent'] ) ) {
			$data['agent'] = self::agent();
		}

		$row = self::build_row(
			array(
				'blog_id'      => null === $blog_id ? get_current_blog_id() : (int) $blog_id,
				'created_at'   => current_time( 'mysql', true ),
				'ip'           => self::client_ip(),
				'user_id'      => $user_id,
				'username'     => $username,
				'event_type'   => $type,
				'event_action' => $action,
				'data'         => $data,
				'user_agent'   => $user_agent,
				'anonymize_ip' => (bool) ReportedIP_Hive_Option_Routing::get( self::OPT_ANONYMIZE_IP, false ),
				'object'       => $object,
			)
		);

		if ( ! self::has_object_columns() ) {
			unset( $row['object_type'], $row['object_id'], $row['object_label'] );
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Append-only audit write; caching is not applicable.
		$wpdb->insert( $wpdb->base_prefix . self::TABLE, $row );
	}

	/**
	 * Whether schema v17 has run. The migration runs on `admin_init`, so a
	 * plugin update followed by a front-end sign-in would otherwise insert
	 * with columns the table does not have yet.
	 *
	 * @return bool
	 * @since  2.1.62
	 */
	private static function has_object_columns() {
		if ( null === self::$has_object_columns ) {
			$version                  = class_exists( 'ReportedIP_Hive_Migration_Manager' ) ? ReportedIP_Hive_Migration_Manager::VERSION_OPTION : 'reportedip_hive_db_version';
			self::$has_object_columns = (int) get_site_option( $version, 0 ) >= self::OBJECT_COLUMNS_VERSION;
		}
		return self::$has_object_columns;
	}

	/**
	 * Build a storage-ready audit row from a context array. Pure, no WP calls.
	 *
	 * Redacts sensitive keys, JSON-encodes the data blob and clamps every
	 * field to its column width. Unit-testable without a database.
	 *
	 * @param array<string,mixed> $ctx Context (blog_id, created_at, ip, user_id, username, event_type, event_action, data, risk_score, country_code, user_agent, object).
	 * @return array<string,mixed>
	 * @since  2.1.2
	 */
	public static function build_row( array $ctx ) {
		$data   = isset( $ctx['data'] ) && is_array( $ctx['data'] ) ? self::redact( $ctx['data'] ) : array();
		$ip     = (string) ( $ctx['ip'] ?? '' );
		$object = isset( $ctx['object'] ) && is_array( $ctx['object'] ) ? $ctx['object'] : array();

		if ( ! empty( $ctx['anonymize_ip'] ) ) {
			$ip = self::anonymize_ip( $ip );
		}

		$object_type  = substr( (string) ( $object['type'] ?? '' ), 0, 32 );
		$object_label = (string) ( $object['label'] ?? '' );
		if ( function_exists( 'mb_substr' ) ) {
			$object_label = mb_substr( $object_label, 0, 200 );
		} else {
			$object_label = substr( $object_label, 0, 200 );
		}

		return array(
			'blog_id'      => (int) ( $ctx['blog_id'] ?? 0 ),
			'created_at'   => (string) ( $ctx['created_at'] ?? '' ),
			'ip'           => substr( $ip, 0, 64 ),
			'user_id'      => empty( $ctx['user_id'] ) ? null : (int) $ctx['user_id'],
			'username'     => substr( (string) ( $ctx['username'] ?? '' ), 0, 60 ),
			'event_type'   => substr( (string) ( $ctx['event_type'] ?? '' ), 0, 32 ),
			'event_action' => substr( (string) ( $ctx['event_action'] ?? '' ), 0, 64 ),
			'event_data'   => empty( $data ) ? null : wp_json_encode( $data ),
			'risk_score'   => isset( $ctx['risk_score'] ) ? (int) $ctx['risk_score'] : null,
			'country_code' => empty( $ctx['country_code'] ) ? null : substr( (string) $ctx['country_code'], 0, 8 ),
			'user_agent'   => empty( $ctx['user_agent'] ) ? null : substr( (string) $ctx['user_agent'], 0, 255 ),
			'object_type'  => '' === $object_type ? null : $object_type,
			'object_id'    => empty( $object['id'] ) ? null : (int) $object['id'],
			'object_label' => '' === $object_label ? null : $object_label,
		);
	}

	/**
	 * Drop the host part of an address so the row keeps its network but
	 * stops identifying a person.
	 *
	 * IPv4 loses the last octet, IPv6 keeps the /64 prefix. Anything that is
	 * not an address is returned untouched, because an unparsable value is
	 * not personal data to begin with and silently blanking it would hide a
	 * bug in whatever produced it.
	 *
	 * @param string $ip Raw address.
	 * @return string
	 * @since  2.1.51
	 */
	public static function anonymize_ip( $ip ) {
		$ip = trim( (string) $ip );

		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts    = explode( '.', $ip );
			$parts[3] = '0';
			return implode( '.', $parts );
		}

		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$packed = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Validated as IPv6 above; the silence guards against platform builds without IPv6 support.
			if ( false === $packed ) {
				return $ip;
			}
			return (string) inet_ntop( substr( $packed, 0, 8 ) . str_repeat( "\0", 8 ) );
		}

		return $ip;
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
	 * Shared with {@see ReportedIP_Hive_Login_Context}: the list itself is
	 * plain sign-in history, so it is written on every login. The Business
	 * gate applies to the audit row this method's return value flags, not to
	 * the list.
	 *
	 * @param int    $user_id User id.
	 * @param string $ip      Client IP.
	 * @return bool True when the IP had not been seen for this user.
	 * @since  2.1.2
	 */
	public static function note_ip( $user_id, $ip ) {
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
	 * Delete audit rows older than the retention window, chunked under the
	 * shared cleanup time budget like the other tables.
	 *
	 * @param int $retention_days Days to keep.
	 * @return int Rows deleted.
	 * @since  2.1.2
	 */
	public static function cleanup( $retention_days ) {
		global $wpdb;
		return ReportedIP_Hive_Database::delete_older_than(
			$wpdb->base_prefix . self::TABLE,
			'created_at',
			max( 1, (int) $retention_days ),
			time() + ReportedIP_Hive_Database::CLEANUP_TIME_BUDGET
		);
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
