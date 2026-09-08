<?php
/**
 * Per-user sign-in history feeding the adaptive 2FA step-up triggers.
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
 * Records where and how a user signs in, and when they last passed a second
 * factor.
 *
 * One JSON user-meta row per user ({@see ReportedIP_Hive_Two_Factor::META_LOGIN_CONTEXT})
 * plus the known-IP list shared with {@see ReportedIP_Hive_Audit_Logger}. The
 * lists are LRU-capped, so the row stays small no matter how long an account
 * lives.
 *
 * Nothing is written while `2fa_policies` is unavailable: a site that cannot
 * use the triggers must not accumulate movement profiles for its users. The
 * consequence is that the baseline starts when a site upgrades to
 * Professional — the `new_*` triggers stay quiet until the first sign-in
 * after the upgrade has been recorded.
 *
 * @since 2.1.51
 */
final class ReportedIP_Hive_Login_Context {

	/**
	 * LRU caps for the three history lists.
	 */
	const MAX_NETS      = 50;
	const MAX_UAS       = 20;
	const MAX_COUNTRIES = 12;

	/**
	 * Runtime latch: unix timestamp of the first second-factor verification by
	 * a user who may manage the site. Not a setting — never in the registry,
	 * never exported.
	 */
	const OPT_ADMIN_VERIFIED = 'reportedip_hive_2fa_policy_admin_verified';

	/**
	 * Users already recorded in this request, so a `wp_login` fired twice for
	 * the same sign-in counts once.
	 *
	 * @var array<int, bool>
	 */
	private static $recorded = array();

	/**
	 * Users who passed a second factor in this request.
	 *
	 * @var array<int, bool>
	 */
	private static $verified = array();

	/**
	 * Register the two login listeners.
	 *
	 * `wp_login` runs at 60, after the audit logger has decided whether the
	 * address was new for this user.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public static function init() {
		add_action( 'wp_login', array( __CLASS__, 'on_login' ), 60, 2 );
		add_action( 'reportedip_hive_2fa_verified', array( __CLASS__, 'on_verified' ), 10, 3 );
	}

	/**
	 * Every sign-in, verified or not — the only place that records.
	 *
	 * Both challenge surfaces fire `reportedip_hive_2fa_verified` immediately
	 * before `wp_login`, so the flag {@see self::on_verified()} left behind is
	 * available here. Recording from the earlier hook instead would put this
	 * request's address into the known-IP list before
	 * {@see ReportedIP_Hive_Audit_Logger::on_login()} (priority 10) reads it,
	 * and a sign-in from an unfamiliar address would be audited as `success`
	 * rather than `new_ip`.
	 *
	 * @param string        $user_login Login name (unused — hook signature).
	 * @param \WP_User|null $user       Authenticated user.
	 * @return void
	 * @since  2.1.51
	 */
	public static function on_login( $user_login, $user = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		unset( $user_login );

		$user_id = ( $user instanceof WP_User ) ? (int) $user->ID : 0;
		self::record( $user, isset( self::$verified[ $user_id ] ) );
	}

	/**
	 * Sign-in that passed a second factor.
	 *
	 * Only remembers the verification for the `wp_login` listener and opens
	 * the administrator latch: policies may only name the administrator role
	 * once somebody who can manage the site has proven a second factor works
	 * for them.
	 *
	 * @param int    $user_id User id.
	 * @param string $method  Verified method (unused — hook signature).
	 * @param string $context Verification surface (unused — hook signature).
	 * @return void
	 * @since  2.1.51
	 */
	public static function on_verified( $user_id, $method = '', $context = '' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		unset( $method, $context );

		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return;
		}

		self::$verified[ $user_id ] = true;

		if ( ! self::admin_latch_open() && self::may_manage_site( $user_id ) ) {
			ReportedIP_Hive_Option_Routing::set( self::OPT_ADMIN_VERIFIED, time() );
		}
	}

	/**
	 * Sign-in history of one user, padded to the full shape.
	 *
	 * @param int $user_id User id.
	 * @return array<string, mixed>
	 * @since  2.1.51
	 */
	public static function get( $user_id ) {
		$skeleton = array(
			'last'                => array(
				'ip'       => '',
				'net'      => '',
				'ua'       => '',
				'ua_short' => '',
				'country'  => '',
				'ts'       => 0,
			),
			'verified_at'         => 0,
			'logins_since_verify' => 0,
			'nets'                => array(),
			'uas'                 => array(),
			'countries'           => array(),
		);

		$raw     = get_user_meta( (int) $user_id, ReportedIP_Hive_Two_Factor::META_LOGIN_CONTEXT, true );
		$decoded = is_string( $raw ) ? json_decode( $raw, true ) : $raw;
		if ( ! is_array( $decoded ) ) {
			return $skeleton;
		}

		$context         = array_merge( $skeleton, $decoded );
		$context['last'] = array_merge( $skeleton['last'], is_array( $context['last'] ) ? $context['last'] : array() );
		foreach ( array( 'nets', 'uas', 'countries' ) as $list ) {
			$context[ $list ] = is_array( $context[ $list ] ) ? array_values( $context[ $list ] ) : array();
		}
		$context['verified_at']         = (int) $context['verified_at'];
		$context['logins_since_verify'] = (int) $context['logins_since_verify'];

		return $context;
	}

	/**
	 * Record one sign-in.
	 *
	 * Adds the address to the known-IP list as its last step, so callers must
	 * run after {@see ReportedIP_Hive_Audit_Logger::on_login()}.
	 *
	 * @param \WP_User|null $user     Authenticated user.
	 * @param bool          $verified Whether a second factor was passed.
	 * @return void
	 * @since  2.1.51
	 */
	public static function record( $user, $verified ) {
		$user_id = ( $user instanceof WP_User ) ? (int) $user->ID : 0;
		if ( $user_id <= 0 || isset( self::$recorded[ $user_id ] ) ) {
			return;
		}
		if ( ! ReportedIP_Hive_Two_Factor_Policies::is_available() ) {
			return;
		}
		self::$recorded[ $user_id ] = true;

		$signals = self::current_signals();
		$context = self::get( $user_id );
		$now     = time();

		$context['last'] = array(
			'ip'       => $signals['ip'],
			'net'      => $signals['net'],
			'ua'       => $signals['ua'],
			'ua_short' => $signals['ua_short'],
			'country'  => $signals['country'],
			'ts'       => $now,
		);

		$context['nets']      = self::push( $context['nets'], $signals['net'], self::MAX_NETS );
		$context['uas']       = self::push( $context['uas'], $signals['ua'], self::MAX_UAS );
		$context['countries'] = self::push( $context['countries'], $signals['country'], self::MAX_COUNTRIES );

		if ( $verified ) {
			$context['verified_at']         = $now;
			$context['logins_since_verify'] = 0;
		} else {
			++$context['logins_since_verify'];
		}

		update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_LOGIN_CONTEXT, (string) wp_json_encode( $context ) );
		ReportedIP_Hive_Audit_Logger::note_ip( $user_id, $signals['ip'] );
	}

	/**
	 * Signals of the current request.
	 *
	 * The User-Agent is stored as a bare SHA-256 hash: it is only ever
	 * compared against earlier hashes in the same user row, so a salt would
	 * add nothing. `country` is empty outside Community mode and for
	 * addresses the reputation cache has not seen — the `new_country` trigger
	 * treats that as "no signal" rather than as a new country.
	 *
	 * @return array{ip:string,net:string,ua:string,ua_short:string,country:string}
	 * @since  2.1.51
	 */
	public static function current_signals() {
		$ip = ReportedIP_Hive::get_client_ip();
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

		return array(
			'ip'       => (string) $ip,
			'net'      => ReportedIP_Hive_Two_Factor_Notifications::ip_to_network( (string) $ip ),
			'ua'       => '' === $ua ? '' : hash( 'sha256', $ua ),
			'ua_short' => ReportedIP_Hive_Two_Factor_Notifications::short_ua( $ua ),
			'country'  => ReportedIP_Hive_Geo_Anomaly::extract_country( ReportedIP_Hive_Geo_Anomaly::fetch_reputation( (string) $ip ) ),
		);
	}

	/**
	 * Whether an administrator has already completed a second-factor sign-in.
	 *
	 * @return bool
	 * @since  2.1.51
	 */
	public static function admin_latch_open() {
		return (int) ReportedIP_Hive_Option_Routing::get( self::OPT_ADMIN_VERIFIED, 0 ) > 0;
	}

	/**
	 * Known IPs of one user, shared with the audit logger.
	 *
	 * @param int $user_id User id.
	 * @return string[]
	 * @since  2.1.51
	 */
	public static function known_ips( $user_id ) {
		$known = get_user_meta( (int) $user_id, ReportedIP_Hive_Audit_Logger::KNOWN_IPS_META, true );
		return is_array( $known ) ? array_values( $known ) : array();
	}

	/**
	 * Whether a user may manage this site or network.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 * @since  2.1.51
	 */
	private static function may_manage_site( $user_id ) {
		if ( function_exists( 'is_super_admin' ) && is_super_admin( $user_id ) ) {
			return true;
		}
		return user_can( $user_id, 'manage_options' );
	}

	/**
	 * Append a value to an LRU list, keeping it unique and capped.
	 *
	 * @param array<int, string> $list  Existing list.
	 * @param string             $value Value to remember; empty values are ignored.
	 * @param int                $max   Cap.
	 * @return array<int, string>
	 * @since  2.1.51
	 */
	private static function push( array $list, $value, $max ) {
		$value = (string) $value;
		if ( '' === $value ) {
			return array_values( $list );
		}
		$list = array_values( array_diff( $list, array( $value ) ) );
		$list[] = $value;

		return count( $list ) > $max ? array_slice( $list, -$max ) : $list;
	}
}
