<?php
/**
 * System-readiness issue register.
 *
 * Collects the operational faults that are already detectable somewhere in
 * the plugin, an unwritable guard queue, a stalled WP-Cron, a client-IP
 * header trusted from any peer, a stuck schema migration, a degraded API
 * window, a relay cap, failing outgoing mail, a missing encryption backend
 * and the report-queue backlog, into one persistent list with a severity,
 * a first-seen timestamp and a site-wide seven-day dismissal.
 *
 * The detectors are pure static predicates that take their inputs as
 * arguments; {@see self::compute()} is the only impure gatherer. Nothing
 * here enforces anything: the register only reads and reports.
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
 * Static-only readiness register.
 *
 * @since 2.1.51
 */
final class ReportedIP_Hive_Readiness {

	/**
	 * Network option holding `{key => {first_seen, dismissed_until}}`.
	 *
	 * Runtime state: deliberately absent from {@see ReportedIP_Hive_Defaults}
	 * and from the settings import/export, and removed by the uninstall
	 * prefix sweep like every other plugin option.
	 */
	const OPT_STATE = 'reportedip_hive_readiness_state';

	/**
	 * Site transient holding the computed open-issue list.
	 */
	const CACHE_KEY = 'reportedip_hive_readiness_cache';

	/**
	 * Cache lifetime in seconds.
	 */
	const CACHE_TTL = 300;

	/**
	 * Plugin options that ordinary front-end traffic rewrites, so a cache
	 * flush on them would leave the register recomputing on every hit.
	 */
	const HOT_OPTIONS = array(
		'reportedip_hive_api_stats',
		'reportedip_hive_cache_stats',
		'reportedip_hive_hide_login_enabled',
		'reportedip_hive_2fa_frontend_enabled',
		'reportedip_hive_auto_footer_enabled',
		'reportedip_hive_operation_mode',
		'reportedip_hive_wizard_completed',
		'reportedip_hive_waf_dropin_enabled',
	);

	/**
	 * Site transient holding `{count, last_error, last_at}` for `wp_mail_failed`.
	 */
	const MAIL_FAIL_TRANSIENT = 'reportedip_hive_mail_failures';

	/**
	 * Mail-failure record lifetime; refreshed on every recorded failure so the
	 * issue disappears a day after the last one.
	 */
	const MAIL_FAIL_TTL = 86400;

	/**
	 * Minimum seconds between two mail-failure writes. A broken contact form
	 * otherwise costs one network write plus a cache flush per visitor.
	 */
	const MAIL_FAIL_THROTTLE = 60;

	/**
	 * How long a dismissal hides an issue, in seconds.
	 */
	const DISMISS_SECS = 604800;

	/**
	 * How long every cron hook has to be overdue before cron counts as stalled.
	 */
	const CRON_STALL_SECS = 86400;

	/**
	 * How long a hook has to be overdue before a disabled WP-Cron counts as stale.
	 */
	const CRON_STALE_SECS = 3600;

	/**
	 * `admin-post.php` action that dismisses one issue.
	 */
	const ACTION_DISMISS = 'reportedip_hive_readiness_dismiss';

	/**
	 * Severity: needs action now, never dismissable.
	 */
	const SEV_CRITICAL = 'critical';

	/**
	 * Severity: degraded, dismissable.
	 */
	const SEV_WARNING = 'warning';

	/**
	 * Severity: informational, dismissable.
	 */
	const SEV_ADVISORY = 'advisory';

	/**
	 * Wire the WordPress hooks. Idempotent.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public static function init() {
		add_action( 'wp_mail_failed', array( __CLASS__, 'record_mail_failure' ) );
		add_action( 'admin_post_' . self::ACTION_DISMISS, array( __CLASS__, 'handle_dismiss' ) );

		$flush = array( __CLASS__, 'flush_on_option_change' );
		add_action( 'updated_option', $flush );
		add_action( 'added_option', $flush );
		add_action( 'deleted_option', $flush );
		add_action( 'update_site_option', $flush );
		add_action( 'add_site_option', $flush );
	}

	/**
	 * The open (non-dismissed) issues, newest state persisted along the way.
	 *
	 * Both the cache and the reconciled state are written on the main site
	 * only. A sub-site skips the guard and cron detectors, so persisting its
	 * result would prune those keys as resolved and drop their `first_seen`
	 * and dismissal from the network-wide option. Reading is not restricted:
	 * the cache is network-wide, so a sub-site reusing the main site's list
	 * saves three queries per render and sees the complete picture.
	 *
	 * @param bool $fresh Bypass the cache (System Status page and WP-CLI).
	 * @return array<int,array<string,mixed>>
	 * @since  2.1.51
	 */
	public static function open_issues( $fresh = false ) {
		if ( ! $fresh ) {
			$cached = get_site_transient( self::CACHE_KEY );
			if ( is_array( $cached ) ) {
				return self::with_links( $cached );
			}
		}

		$cacheable = ! is_multisite() || is_main_site();

		$state  = self::get_state();
		$result = self::reconcile( self::compute(), $state, time() );

		if ( $cacheable && $result['state'] !== $state ) {
			ReportedIP_Hive_Option_Routing::set( self::OPT_STATE, $result['state'] );
		}

		$open = array();
		foreach ( $result['issues'] as $issue ) {
			if ( ! empty( $issue['dismissed'] ) ) {
				continue;
			}
			unset( $issue['dismissed'] );
			$open[] = $issue;
		}

		if ( $cacheable ) {
			set_site_transient( self::CACHE_KEY, $open, self::CACHE_TTL );
		}

		return self::with_links( $open );
	}

	/**
	 * Advisory issues that depend on the signed-in user.
	 *
	 * Not part of the cached register: the answer differs per user, and the
	 * dismissal lives in user meta for the same reason.
	 *
	 * @param int $user_id User id.
	 * @return array<int,array<string,mixed>>
	 * @since  2.1.57
	 */
	public static function user_issues( $user_id ) {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 || ! ReportedIP_Hive_Mode_Manager::get_instance()->is_wizard_completed() ) {
			return array();
		}
		$dismissed_until = (int) get_user_meta( $user_id, 'reportedip_hive_next_step_dismissed_own_2fa_missing', true );
		if ( $dismissed_until > time() ) {
			return array();
		}
		$issue = self::own_2fa_missing(
			(bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_enabled_global', false ),
			(array) ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user_id )
		);
		if ( null === $issue ) {
			return array();
		}
		$issue['dismissable'] = true;
		return self::with_links( array( $issue ) );
	}

	/**
	 * Advisory: Hide Login is off.
	 *
	 * @param bool $enabled Option state.
	 * @return array<string,mixed>|null
	 * @since  2.1.57
	 */
	public static function hide_login_off( $enabled ) {
		if ( $enabled ) {
			return null;
		}
		return self::issue(
			'hide_login_off',
			self::SEV_ADVISORY,
			__( 'Hide the sign-in page', 'reportedip-hive' ),
			__( 'Bots look for wp-login.php first. A custom slug takes the page off that list; the normal address answers with the block page.', 'reportedip-hive' )
		);
	}

	/**
	 * Advisory: storefront 2FA is included in the plan but switched off.
	 *
	 * @param bool $woocommerce WooCommerce active.
	 * @param bool $available   `feature_status('frontend_2fa')['available']`.
	 * @param bool $enabled     Option state.
	 * @return array<string,mixed>|null
	 * @since  2.1.57
	 */
	public static function frontend_2fa_available( $woocommerce, $available, $enabled ) {
		if ( ! $woocommerce || ! $available || $enabled ) {
			return null;
		}
		return self::issue(
			'frontend_2fa_available',
			self::SEV_ADVISORY,
			__( 'Storefront 2FA is included in your plan', 'reportedip-hive' ),
			__( 'Customers and staff who sign in through My Account get the second factor inside your theme. Nothing changes for visitors who never sign in.', 'reportedip-hive' )
		);
	}

	/**
	 * Advisory: the footer badge is off.
	 *
	 * @param bool $enabled Option state.
	 * @return array<string,mixed>|null
	 * @since  2.1.57
	 */
	public static function badge_off( $enabled ) {
		if ( $enabled ) {
			return null;
		}
		return self::issue(
			'badge_off',
			self::SEV_ADVISORY,
			__( 'Show the protection badge', 'reportedip-hive' ),
			__( 'A small footer badge tells visitors the site is protected and links to the community network. It is a text line, no tracking.', 'reportedip-hive' )
		);
	}

	/**
	 * Advisory: the pre-WordPress guard could run here but does not.
	 *
	 * @param bool $supported Server can take the drop-in (Apache/FPM).
	 * @param bool $running   Guard answers requests.
	 * @return array<string,mixed>|null
	 * @since  2.1.57
	 */
	public static function dropin_not_running( $supported, $running ) {
		if ( ! $supported || $running ) {
			return null;
		}
		return self::issue(
			'dropin_not_running',
			self::SEV_ADVISORY,
			__( 'Switch on Extended Protection', 'reportedip-hive' ),
			__( 'The guard rejects known-bad requests before WordPress loads. Your server supports it; one click writes the directive.', 'reportedip-hive' )
		);
	}

	/**
	 * Advisory: the site runs Local Shield.
	 *
	 * @param string $mode Operation mode.
	 * @return array<string,mixed>|null
	 * @since  2.1.57
	 */
	public static function community_pending( $mode ) {
		if ( 'community' === (string) $mode ) {
			return null;
		}
		return self::issue(
			'community_pending',
			self::SEV_ADVISORY,
			__( 'Join the community network', 'reportedip-hive' ),
			__( 'Local Shield blocks what it sees itself. With a free Community Access Key the site also refuses addresses the network already knows.', 'reportedip-hive' )
		);
	}

	/**
	 * Per-user advisory: 2FA is on for the site, the admin has no method.
	 *
	 * Not part of the cached register: the answer differs per user.
	 *
	 * @param bool     $twofa_enabled Global 2FA switch.
	 * @param string[] $methods       The user's enabled methods.
	 * @return array<string,mixed>|null
	 * @since  2.1.57
	 */
	public static function own_2fa_missing( $twofa_enabled, array $methods ) {
		if ( ! $twofa_enabled || array() !== $methods ) {
			return null;
		}
		return self::issue(
			'own_2fa_missing',
			self::SEV_ADVISORY,
			__( 'Set up your own second factor', 'reportedip-hive' ),
			__( 'Two-factor authentication is on for this site, but your account has no method yet. An authenticator app takes two minutes.', 'reportedip-hive' )
		);
	}

	/**
	 * Attach the deep links to a list of issues.
	 *
	 * Resolved on read rather than baked into the cache: the cache is
	 * network-wide, while `get_admin_page_url()` answers differently in the
	 * Network Admin, on a sub-site and under WP-CLI. Whoever filled the cache
	 * would otherwise decide everyone else's links for five minutes.
	 *
	 * @param array<int,array<string,mixed>> $issues Issues without URLs.
	 * @return array<int,array<string,mixed>>
	 * @since  2.1.51
	 */
	private static function with_links( array $issues ) {
		$links  = self::links();
		$linked = array();

		foreach ( $issues as $issue ) {
			$key                   = (string) $issue['key'];
			$target                = $links[ $key ] ?? array( 'reportedip-hive-debug', '' );
			$issue['settings_url'] = 'profile' === $target[0]
				? admin_url( 'profile.php#reportedip-hive-2fa' )
				: ReportedIP_Hive_Score::url( $target[0], $target[1] );
			$issue['doc_url']      = self::doc_url( $key );
			$linked[]              = $issue;
		}

		return $linked;
	}

	/**
	 * How many open issues are worth interrupting an operator for.
	 *
	 * @param array<int,array<string,mixed>>|null $issues Pre-fetched list, or null to read the cache.
	 * @return int
	 * @since  2.1.51
	 */
	public static function attention_count( $issues = null ) {
		$issues = is_array( $issues ) ? $issues : self::open_issues();
		$count  = 0;
		foreach ( $issues as $issue ) {
			if ( self::SEV_ADVISORY !== (string) $issue['severity'] ) {
				++$count;
			}
		}
		return $count;
	}

	/**
	 * Gather every detector input and return the raised issues, sorted
	 * critical first. Deep links are attached later by {@see self::with_links()}.
	 *
	 * The guard and cron detectors are skipped on Multisite sub-sites: the
	 * guard queue lives in the network's main upload directory and cron is
	 * scheduled on the main site only, so a sub-site view would raise false
	 * positives. A super admin therefore sees fewer issues on a sub-site
	 * page than in the Network Admin.
	 *
	 * @return array<int,array<string,mixed>>
	 * @since  2.1.51
	 */
	public static function compute() {
		$now       = time();
		$main_site = ! is_multisite() || is_main_site();
		$raised    = array();

		if ( $main_site ) {
			$dropin     = ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
			$queue_path = (string) $dropin->queue_path();
			$raised[]   = self::guard_queue(
				(bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false ),
				(bool) $dropin->queue_is_writable(),
				'' === $queue_path ? '' : dirname( $queue_path )
			);

			$next_runs = array();
			foreach ( ReportedIP_Hive_Cron_Handler::get_hook_names() as $hook ) {
				$next_runs[ $hook ] = wp_next_scheduled( $hook );
			}
			$raised[] = self::cron_stalled( $next_runs, $now );
			$raised[] = self::cron_disabled_stale(
				defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON,
				defined( 'ALTERNATE_WP_CRON' ) && ALTERNATE_WP_CRON,
				$next_runs,
				$now
			);
		}

		$raised[] = self::trusted_header(
			(string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_trusted_ip_header', '' ),
			ReportedIP_Hive_Proxy_Trust::parse_ranges(
				(string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_trusted_proxy_ranges', '' )
			)
		);

		$raised[] = self::schema_outdated(
			(int) get_site_option( ReportedIP_Hive_Migration_Manager::VERSION_OPTION, 0 ),
			ReportedIP_Hive_Migration_Manager::CURRENT_VERSION
		);

		$mode = ReportedIP_Hive_Mode_Manager::get_instance();
		if ( $mode->is_community_mode() && ReportedIP_Hive_API::get_instance()->is_configured() ) {
			$stats    = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_stats', array() );
			$stats    = is_array( $stats ) ? $stats : array();
			$raised[] = self::api_degraded(
				ReportedIP_Hive_API::window_is_degraded( $stats ),
				(float) ( $stats['recent_success_rate'] ?? 0 ),
				(int) ( $stats['recent_total'] ?? 0 )
			);
		}

		$raised[] = self::relay_cap( 'mail', ReportedIP_Hive_Mode_Manager::get_cap_state( 'mail' ) );
		$raised[] = self::relay_cap( 'sms', ReportedIP_Hive_Mode_Manager::get_cap_state( 'sms' ) );
		$raised[] = self::mail_failures( self::get_mail_failures() );
		$raised[] = self::crypto_missing( ReportedIP_Hive_Two_Factor_Crypto::get_active_method() );

		if ( ReportedIP_Hive_Schema::tables_exist() ) {
			$queue      = ReportedIP_Hive_Database::get_instance()->get_queue_statistics();
			$api_usable = $mode->is_community_mode() && ReportedIP_Hive_API::get_instance()->is_configured();
			$raised[]   = self::queue_failed( (int) $queue['failed'], $api_usable );
			$raised[]   = self::queue_backlog(
				(int) $queue['pending'],
				(int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_queue_warning_threshold', 50 ),
				(int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_queue_critical_threshold', 200 ),
				$api_usable
			);
		}

		if ( $mode->is_wizard_completed() ) {
			$raised[] = self::hide_login_off( (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_enabled', false ) );
			$raised[] = self::frontend_2fa_available(
				class_exists( 'WooCommerce' ),
				! empty( $mode->feature_status( 'frontend_2fa' )['available'] ),
				(bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_frontend_enabled', false )
			);
			$raised[] = self::badge_off( (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_footer_enabled', false ) );
			if ( $main_site ) {
				$guard    = ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
				$raised[] = self::dropin_not_running( (bool) $guard->supports_htaccess(), (bool) $guard->is_running() );
			}
			$raised[] = self::community_pending( (string) $mode->get_mode() );
		}

		$issues = array();
		foreach ( $raised as $issue ) {
			if ( is_array( $issue ) ) {
				$issues[] = $issue;
			}
		}

		usort(
			$issues,
			static function ( $a, $b ) {
				return self::severity_rank( $a['severity'] ) <=> self::severity_rank( $b['severity'] );
			}
		);

		return $issues;
	}

	/**
	 * Merge the freshly computed issues with the persisted state.
	 *
	 * Pure: sets `first_seen` once per continuous occurrence, prunes state
	 * for conditions that resolved (so a returning condition re-raises with a
	 * fresh timestamp and no lingering dismissal) and marks issues that are
	 * inside their dismissal window. Critical issues are never dismissable.
	 *
	 * @param array<int,array<string,mixed>>            $issues Computed issues.
	 * @param array<string,array<string,int>>           $state  Persisted state.
	 * @param int                                       $now    Current UNIX time.
	 * @return array{issues:array<int,array<string,mixed>>,state:array<string,array<string,int>>}
	 * @since  2.1.51
	 */
	public static function reconcile( array $issues, array $state, $now ) {
		$now       = (int) $now;
		$next      = array();
		$decorated = array();

		foreach ( $issues as $issue ) {
			$key         = (string) $issue['key'];
			$previous    = isset( $state[ $key ] ) && is_array( $state[ $key ] ) ? $state[ $key ] : array();
			$first_seen  = isset( $previous['first_seen'] ) ? (int) $previous['first_seen'] : $now;
			$until       = isset( $previous['dismissed_until'] ) ? (int) $previous['dismissed_until'] : 0;
			$dismissable = self::SEV_CRITICAL !== (string) $issue['severity'];

			$next[ $key ] = array(
				'first_seen'      => $first_seen,
				'dismissed_until' => $until,
			);

			$issue['first_seen']  = $first_seen;
			$issue['dismissable'] = $dismissable;
			$issue['dismissed']   = $dismissable && $until > $now;
			$decorated[]          = $issue;
		}

		return array(
			'issues' => $decorated,
			'state'  => $next,
		);
	}

	/**
	 * Hide one issue for {@see self::DISMISS_SECS} seconds, site-wide.
	 *
	 * @param string $key Issue key.
	 * @param int    $now Current UNIX time.
	 * @return void
	 * @since  2.1.51
	 */
	public static function dismiss( $key, $now ) {
		$key   = (string) $key;
		$now   = (int) $now;
		$state = self::get_state();
		$entry = isset( $state[ $key ] ) && is_array( $state[ $key ] )
			? $state[ $key ]
			: array( 'first_seen' => $now );

		$entry['dismissed_until'] = $now + self::DISMISS_SECS;
		$state[ $key ]            = $entry;

		ReportedIP_Hive_Option_Routing::set( self::OPT_STATE, $state );
		self::flush_cache();
	}

	/**
	 * `admin-post.php?action=reportedip_hive_readiness_dismiss` handler.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public static function handle_dismiss() {
		if ( ! ReportedIP_Hive_Option_Routing::current_user_can_manage() ) {
			wp_die( esc_html__( 'Permission denied.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION_DISMISS );

		$key = isset( $_GET['issue'] ) ? sanitize_key( wp_unslash( $_GET['issue'] ) ) : '';
		if ( '' !== $key ) {
			foreach ( self::open_issues( true ) as $issue ) {
				if ( $key === (string) $issue['key'] && ! empty( $issue['dismissable'] ) ) {
					self::dismiss( $key, time() );
					break;
				}
			}
		}

		$redirect = wp_get_referer();
		if ( ! $redirect ) {
			$page     = 'admin.php?page=reportedip-hive-debug';
			$redirect = is_multisite() ? network_admin_url( $page ) : admin_url( $page );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * `wp_mail_failed` listener: keep a rolling 24 h failure counter.
	 *
	 * Throttled to one write per {@see self::MAIL_FAIL_THROTTLE} seconds so a
	 * broken front-end form cannot turn every visitor submission into a
	 * network write, and stripped of e-mail addresses because PHPMailer puts
	 * the recipients into its error messages and the message is shown on the
	 * System Status page.
	 *
	 * @param mixed $error `WP_Error` handed over by `wp_mail()`.
	 * @return void
	 * @since  2.1.51
	 */
	public static function record_mail_failure( $error ) {
		if ( ! is_wp_error( $error ) ) {
			return;
		}

		$now     = time();
		$record  = self::get_mail_failures();
		$last_at = null === $record ? 0 : $record['last_at'];
		if ( null !== $record && ( $now - $last_at ) < self::MAIL_FAIL_THROTTLE ) {
			return;
		}

		set_site_transient(
			self::MAIL_FAIL_TRANSIENT,
			array(
				'count'      => ( null === $record ? 0 : $record['count'] ) + 1,
				'last_error' => self::strip_addresses( (string) $error->get_error_message() ),
				'last_at'    => $now,
			),
			self::MAIL_FAIL_TTL
		);

		self::flush_cache();
	}

	/**
	 * Drop the cached issue list.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public static function flush_cache() {
		delete_site_transient( self::CACHE_KEY );
	}

	/**
	 * Flush the cache when a plugin-prefixed option changes.
	 *
	 * {@see self::HOT_OPTIONS} is excluded: those two counters are rewritten
	 * on ordinary front-end traffic, `api_stats` on every API call,
	 * `cache_stats` at shutdown of every request that touched the reputation
	 * cache, so watching them would keep the cache permanently cold.
	 *
	 * @param string $option Option name being written.
	 * @return void
	 * @since  2.1.51
	 */
	public static function flush_on_option_change( $option ) {
		if ( ! is_string( $option ) || 0 !== strpos( $option, 'reportedip_hive_' ) ) {
			return;
		}
		if ( in_array( $option, self::HOT_OPTIONS, true ) ) {
			return;
		}
		self::flush_cache();
	}

	/**
	 * Extended protection is on but cannot record what it blocked.
	 *
	 * @param bool   $enabled  Whether the pre-WordPress guard is enabled.
	 * @param bool   $writable Whether the hit queue directory is writable.
	 * @param string $dir      Absolute queue directory path.
	 * @return array<string,string>|null
	 * @since  2.1.51
	 */
	public static function guard_queue( $enabled, $writable, $dir ) {
		if ( ! $enabled || $writable ) {
			return null;
		}

		return self::issue(
			'guard_queue_unwritable',
			self::SEV_CRITICAL,
			__( 'Extended protection cannot record hits', 'reportedip-hive' ),
			sprintf(
				/* translators: %s: absolute path of the queue directory. */
				__( 'The guard cannot write to %s, so blocked requests are stopped but never reach the log, the counters or the escalation ladder. Give the web-server user write access to that directory.', 'reportedip-hive' ),
				$dir
			)
		);
	}

	/**
	 * No plugin cron hook has run for a day.
	 *
	 * A hook without a schedule is not overdue, that is a different fault
	 * and the Cron status panel below already names it.
	 *
	 * @param array<string,int|false> $next_runs Hook => next run timestamp or false.
	 * @param int                     $now       Current UNIX time.
	 * @return array<string,string>|null
	 * @since  2.1.51
	 */
	public static function cron_stalled( array $next_runs, $now ) {
		if ( empty( $next_runs ) ) {
			return null;
		}

		foreach ( $next_runs as $next ) {
			if ( false === $next || ( (int) $now - (int) $next ) < self::CRON_STALL_SECS ) {
				return null;
			}
		}

		return self::issue(
			'cron_stalled',
			self::SEV_CRITICAL,
			__( 'WP-Cron is not running', 'reportedip-hive' ),
			__( 'WP-Cron has not fired any ReportedIP Hive hook in the last 24 h.', 'reportedip-hive' )
				. ' '
				. __( 'Likely causes: the site cannot call its own wp-cron.php (a failing loopback request, listed under Tools, Site Health), or another plugin\'s cron jobs use up the per-run time limit (WP_CRON_LOCK_TIMEOUT) before our jobs run. Set up a dedicated server cron using the snippet below.', 'reportedip-hive' )
		);
	}

	/**
	 * WP-Cron is switched off and nothing external is triggering it.
	 *
	 * @param bool                    $disabled  Whether `DISABLE_WP_CRON` is truthy.
	 * @param bool                    $alternate Whether `ALTERNATE_WP_CRON` is truthy.
	 * @param array<string,int|false> $next_runs Hook => next run timestamp or false.
	 * @param int                     $now       Current UNIX time.
	 * @return array<string,string>|null
	 * @since  2.1.51
	 */
	public static function cron_disabled_stale( $disabled, $alternate, array $next_runs, $now ) {
		if ( ! $disabled || $alternate ) {
			return null;
		}

		$overdue = 0;
		foreach ( $next_runs as $next ) {
			if ( false === $next ) {
				continue;
			}
			$overdue = max( $overdue, (int) $now - (int) $next );
		}

		if ( $overdue <= self::CRON_STALE_SECS ) {
			return null;
		}

		return self::issue(
			'cron_disabled_stale',
			self::SEV_WARNING,
			__( 'WP-Cron is disabled and overdue', 'reportedip-hive' ),
			__( 'DISABLE_WP_CRON is set, ALTERNATE_WP_CRON is off and the next scheduled run is more than an hour late. Without a server cron calling wp-cron.php the report queue, the quota refresh and the ruleset sync stop running.', 'reportedip-hive' )
		);
	}

	/**
	 * A client-IP header is honoured from every peer.
	 *
	 * @param string        $header Configured header name, '' when off.
	 * @param array<int,mixed> $ranges Parsed trusted proxy ranges.
	 * @return array<string,string>|null
	 * @since  2.1.51
	 */
	public static function trusted_header( $header, array $ranges ) {
		if ( '' === (string) $header || ! empty( $ranges ) ) {
			return null;
		}

		return self::issue(
			'trusted_header_open',
			self::SEV_WARNING,
			__( 'Client-IP header trusted from any source', 'reportedip-hive' ),
			__( 'The client-IP header is currently accepted from any source. Anyone able to reach this site directly can forge their IP address. Add the CIDR ranges of your proxy or CDN under Trusted proxy sources.', 'reportedip-hive' )
		);
	}

	/**
	 * A database migration did not complete.
	 *
	 * @param int $db_version Stored schema version.
	 * @param int $current    Version this build expects.
	 * @return array<string,string>|null
	 * @since  2.1.51
	 */
	public static function schema_outdated( $db_version, $current ) {
		if ( (int) $db_version >= (int) $current ) {
			return null;
		}

		return self::issue(
			'schema_outdated',
			self::SEV_CRITICAL,
			__( 'Database schema is out of date', 'reportedip-hive' ),
			sprintf(
				/* translators: 1: stored schema version, 2: schema version this build expects. */
				__( 'The plugin tables are at schema version %1$d but this build expects %2$d. Sensors that rely on the newer columns or indexes can behave incorrectly. Open the System Status page to let the migration run again.', 'reportedip-hive' ),
				(int) $db_version,
				(int) $current
			)
		);
	}

	/**
	 * The rolling API window is degraded.
	 *
	 * @param bool  $degraded Result of {@see ReportedIP_Hive_API::window_is_degraded()}.
	 * @param float $rate     Recent success rate in percent.
	 * @param int   $total    Number of calls in the window.
	 * @return array<string,string>|null
	 * @since  2.1.51
	 */
	public static function api_degraded( $degraded, $rate, $total ) {
		if ( ! $degraded ) {
			return null;
		}

		return self::issue(
			'api_degraded',
			self::SEV_WARNING,
			__( 'Community threat checks are failing', 'reportedip-hive' ),
			sprintf(
				/* translators: 1: success rate in percent, 2: number of calls in the rolling window. */
				__( 'Only %1$s%% of the last %2$d calls to the community network succeeded. Local protection is unaffected; reputation lookups and report submissions are unreliable until the connection recovers.', 'reportedip-hive' ),
				number_format_i18n( (float) $rate, 1 ),
				(int) $total
			)
		);
	}

	/**
	 * A managed relay channel has hit its cap.
	 *
	 * @param string                   $channel 'mail' | 'sms'.
	 * @param array<string,mixed>|null $state   Cap state, or null when the channel is fine.
	 * @return array<string,string>|null
	 * @since  2.1.51
	 */
	public static function relay_cap( $channel, $state ) {
		if ( ! is_array( $state ) ) {
			return null;
		}

		if ( 'sms' === $channel ) {
			return self::issue(
				'relay_cap_sms',
				self::SEV_WARNING,
				__( 'SMS relay capacity reached', 'reportedip-hive' ),
				__( 'SMS-based 2FA codes are paused until the relay accepts again, users can still choose TOTP, Email or Passkey.', 'reportedip-hive' )
			);
		}

		return self::issue(
			'relay_cap_mail',
			self::SEV_WARNING,
			__( 'Mail relay capacity reached', 'reportedip-hive' ),
			__( 'Mails are temporarily routed through your local wp_mail() until the relay accepts again.', 'reportedip-hive' )
		);
	}

	/**
	 * Outgoing mail failed within the last 24 hours.
	 *
	 * @param array{count:int,last_error:string,last_at:int}|null $record Rolling failure record.
	 * @return array<string,string>|null
	 * @since  2.1.51
	 */
	public static function mail_failures( $record ) {
		if ( ! is_array( $record ) || (int) $record['count'] < 1 ) {
			return null;
		}

		return self::issue(
			'mail_failures',
			self::SEV_WARNING,
			__( 'Outgoing mail is failing', 'reportedip-hive' ),
			sprintf(
				/* translators: 1: number of failed mails, 2: last error message reported by wp_mail(). */
				__( '%1$d outgoing mails failed in the last 24 hours. Two-factor codes, lockout alerts and quota warnings may not arrive. Last error: %2$s', 'reportedip-hive' ),
				(int) $record['count'],
				(string) $record['last_error']
			)
		);
	}

	/**
	 * No encryption backend for secrets at rest.
	 *
	 * @param string|false $active_method Result of {@see ReportedIP_Hive_Two_Factor_Crypto::get_active_method()}.
	 * @return array<string,string>|null
	 * @since  2.1.51
	 */
	public static function crypto_missing( $active_method ) {
		if ( false !== $active_method ) {
			return null;
		}

		return self::issue(
			'crypto_missing',
			self::SEV_WARNING,
			__( 'No encryption backend available', 'reportedip-hive' ),
			__( 'Neither libsodium nor OpenSSL is available on this server, so two-factor secrets and phone numbers cannot be encrypted at rest. Ask your host to enable one of the two PHP extensions.', 'reportedip-hive' )
		);
	}

	/**
	 * Reports that could not be submitted.
	 *
	 * Silent while the API cannot drain the queue (Local Shield, or no
	 * Community Access Key): the rows are leftovers nothing will submit, and
	 * the remediation the message names does not exist in that state.
	 *
	 * @param int  $failed     Number of failed queue rows.
	 * @param bool $api_usable Whether reports can currently be submitted.
	 * @return array<string,string>|null
	 * @since  2.1.51
	 */
	public static function queue_failed( $failed, $api_usable = true ) {
		if ( ! $api_usable || (int) $failed < 1 ) {
			return null;
		}

		return self::issue(
			'queue_failed',
			self::SEV_WARNING,
			__( 'Reports failed to reach the community', 'reportedip-hive' ),
			sprintf(
				/* translators: %d: number of failed queue entries. */
				__( '%d queued reports could not be submitted. Retry or clear them on the API queue tab.', 'reportedip-hive' ),
				(int) $failed
			)
		);
	}

	/**
	 * The pending report queue has grown past its thresholds.
	 *
	 * @param int  $pending    Pending queue rows.
	 * @param int  $warn       Warning threshold.
	 * @param int  $crit       Critical threshold.
	 * @param bool $api_usable Whether reports can currently be submitted.
	 * @return array<string,string>|null
	 * @since  2.1.51
	 */
	public static function queue_backlog( $pending, $warn, $crit, $api_usable = true ) {
		$pending = (int) $pending;
		if ( ! $api_usable || $pending < (int) $warn ) {
			return null;
		}

		return self::issue(
			'queue_backlog',
			$pending >= (int) $crit ? self::SEV_CRITICAL : self::SEV_WARNING,
			__( 'Report queue backlog', 'reportedip-hive' ),
			sprintf(
				/* translators: %d: number of pending queue entries. */
				__( '%d reports are waiting to be submitted. The queue drains faster on a higher tier, or you can process it manually from the API queue tab.', 'reportedip-hive' ),
				$pending
			)
		);
	}

	/**
	 * Build one issue descriptor.
	 *
	 * @param string $key      Stable issue key.
	 * @param string $severity One of the SEV_* constants.
	 * @param string $label    Short human-readable title.
	 * @param string $message  Full explanation including the remediation.
	 * @return array<string,string>
	 * @since  2.1.51
	 */
	private static function issue( $key, $severity, $label, $message ) {
		return array(
			'key'      => $key,
			'severity' => $severity,
			'label'    => $label,
			'message'  => $message,
		);
	}

	/**
	 * Deep-link target per issue key: `[page slug, tab slug]`.
	 *
	 * @return array<string,array{0:string,1:string}>
	 * @since  2.1.51
	 */
	private static function links() {
		return array(
			'guard_queue_unwritable' => array( 'reportedip-hive-tools', 'server' ),
			'cron_stalled'           => array( 'reportedip-hive-debug', '' ),
			'cron_disabled_stale'    => array( 'reportedip-hive-debug', '' ),
			'trusted_header_open'    => array( 'reportedip-hive-protection', 'detection' ),
			'schema_outdated'        => array( 'reportedip-hive-debug', '' ),
			'api_degraded'           => array( 'reportedip-hive-community', 'community' ),
			'relay_cap_mail'         => array( 'reportedip-hive-community', 'community' ),
			'relay_cap_sms'          => array( 'reportedip-hive-community', 'community' ),
			'mail_failures'          => array( 'reportedip-hive-protection', 'notifications' ),
			'crypto_missing'         => array( 'reportedip-hive-protection', 'account_security' ),
			'queue_failed'           => array( 'reportedip-hive-security', 'api_queue' ),
			'queue_backlog'          => array( 'reportedip-hive-security', 'api_queue' ),
			'hide_login_off'         => array( 'reportedip-hive-protection', 'hide_login' ),
			'frontend_2fa_available' => array( 'reportedip-hive-protection', 'account_security' ),
			'badge_off'              => array( 'reportedip-hive-community', 'badges' ),
			'dropin_not_running'     => array( 'reportedip-hive-tools', 'server' ),
			'community_pending'      => array( 'reportedip-hive-community', 'community' ),
			'own_2fa_missing'        => array( 'profile', '' ),
		);
	}

	/**
	 * Documentation anchor for one issue key.
	 *
	 * @param string $key Issue key.
	 * @return string
	 * @since  2.1.51
	 */
	private static function doc_url( $key ) {
		return REPORTEDIP_HIVE_SITE_URL . '/docs/integrations/wordpress-hive/#readiness-' . $key;
	}

	/**
	 * Sort weight of a severity: critical first, advisory last.
	 *
	 * @param string $severity Severity token.
	 * @return int
	 * @since  2.1.51
	 */
	private static function severity_rank( $severity ) {
		if ( self::SEV_CRITICAL === $severity ) {
			return 0;
		}
		if ( self::SEV_WARNING === $severity ) {
			return 1;
		}
		return 2;
	}

	/**
	 * Persisted per-issue state.
	 *
	 * @return array<string,array<string,int>>
	 * @since  2.1.51
	 */
	private static function get_state() {
		$raw = ReportedIP_Hive_Option_Routing::get( self::OPT_STATE, array() );
		return is_array( $raw ) ? $raw : array();
	}

	/**
	 * The rolling mail-failure record, or null when there is none.
	 *
	 * @return array{count:int,last_error:string,last_at:int}|null
	 * @since  2.1.51
	 */
	private static function get_mail_failures() {
		$raw = get_site_transient( self::MAIL_FAIL_TRANSIENT );
		if ( ! is_array( $raw ) || empty( $raw['count'] ) ) {
			return null;
		}

		return array(
			'count'      => (int) $raw['count'],
			'last_error' => (string) ( $raw['last_error'] ?? '' ),
			'last_at'    => (int) ( $raw['last_at'] ?? 0 ),
		);
	}

	/**
	 * Remove e-mail addresses from a mailer error before it is stored.
	 *
	 * @param string $message Raw error message.
	 * @return string
	 * @since  2.1.51
	 */
	private static function strip_addresses( $message ) {
		$clean = preg_replace( '/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/', '[redacted]', $message );
		if ( ! is_string( $clean ) ) {
			$clean = $message;
		}
		return sanitize_text_field( substr( $clean, 0, 300 ) );
	}
}
