<?php
/**
 * Adaptive per-role step-up rules for two-factor authentication.
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
 * Decides whether a sign-in needs the second factor again.
 *
 * Each trigger owns one role list. A user matched by one of those lists is
 * challenged again — even on a trusted device — as soon as the trigger's
 * condition holds. Users whose role is required to use 2FA
 * ({@see ReportedIP_Hive_Two_Factor::is_enforced_for_user()}) are excluded:
 * they are challenged on every sign-in anyway.
 *
 * The evaluator never locks anybody out. A user without a second factor is
 * reported through `2fa_stepup_skipped_no_method` and signs in as before.
 *
 * @since 2.1.51
 */
final class ReportedIP_Hive_Two_Factor_Policies {

	/**
	 * Feature key in the mode-manager matrix.
	 */
	const FEATURE = '2fa_policies';

	/**
	 * Shared prefix of the ten policy options.
	 */
	const OPTION_PREFIX = 'reportedip_hive_2fa_policy_';

	/**
	 * Prefix of the "would have challenged, but the user has no method"
	 * verdict returned by {@see evaluate()}.
	 */
	const NO_METHOD_PREFIX = 'no_method:';

	/**
	 * Triggers in display order.
	 *
	 * @var string[]
	 */
	const TRIGGERS = array(
		'new_country',
		'new_ip',
		'new_subnet',
		'new_device',
		'every_n_days',
		'every_n_logins',
		'sessions_above_n',
	);

	/**
	 * Triggers in evaluation order — cheapest first, the session count last
	 * because it is the only one that reads a second meta row. First match
	 * wins; the reason is only used for the log row.
	 *
	 * @var string[]
	 */
	const EVAL_ORDER = array(
		'every_n_logins',
		'every_n_days',
		'new_ip',
		'new_subnet',
		'new_device',
		'new_country',
		'sessions_above_n',
	);

	/**
	 * Option key of one trigger's role list.
	 *
	 * @param string $trigger Trigger slug.
	 * @return string
	 * @since  2.1.51
	 */
	public static function option_key( $trigger ) {
		return self::OPTION_PREFIX . (string) $trigger;
	}

	/**
	 * Roles a trigger is configured for.
	 *
	 * @param string $trigger Trigger slug.
	 * @return string[]
	 * @since  2.1.51
	 */
	public static function roles_for( $trigger ) {
		if ( ! in_array( (string) $trigger, self::TRIGGERS, true ) ) {
			return array();
		}

		$stored = ReportedIP_Hive_Option_Routing::to_array(
			ReportedIP_Hive_Option_Routing::get( self::option_key( $trigger ), '[]' )
		);

		return ReportedIP_Hive_Two_Factor::filter_valid_roles( $stored );
	}

	/**
	 * The whole matrix, trigger slug => role slugs.
	 *
	 * @return array<string, string[]>
	 * @since  2.1.51
	 */
	public static function matrix() {
		$matrix = array();
		foreach ( self::TRIGGERS as $trigger ) {
			$matrix[ $trigger ] = self::roles_for( $trigger );
		}

		return $matrix;
	}

	/**
	 * Whether the current plan includes adaptive triggers.
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
	 * Triggers configured for at least one of a user's roles.
	 *
	 * @param \WP_User $user Authenticated user.
	 * @return string[] Trigger slugs in display order.
	 * @since  2.1.51
	 */
	public static function applies_to( $user ) {
		$roles = ( $user instanceof WP_User ) ? array_map( 'strval', (array) $user->roles ) : array();
		if ( empty( $roles ) ) {
			return array();
		}

		$hits = array();
		foreach ( self::TRIGGERS as $trigger ) {
			if ( array_intersect( $roles, self::roles_for( $trigger ) ) ) {
				$hits[] = $trigger;
			}
		}

		return $hits;
	}

	/**
	 * Verdict for one sign-in.
	 *
	 * @param \WP_User $user           Authenticated user.
	 * @param bool     $has_any_method Whether the user has an active second factor.
	 * @param bool     $is_enforced    Whether the user's role requires 2FA anyway.
	 * @return string Trigger slug, `no_method:<trigger>` when the user has no
	 *                second factor, or an empty string for "no step-up".
	 * @since  2.1.51
	 */
	public static function evaluate( $user, $has_any_method, $is_enforced ) {
		if ( $is_enforced || ! $user instanceof WP_User ) {
			return '';
		}
		if ( ! self::is_available() ) {
			return '';
		}

		$triggers = self::applies_to( $user );
		if ( empty( $triggers ) ) {
			return '';
		}
		if ( ! $has_any_method ) {
			return self::NO_METHOD_PREFIX . $triggers[0];
		}

		$context = ReportedIP_Hive_Login_Context::get( (int) $user->ID );
		$signals = ReportedIP_Hive_Login_Context::current_signals();

		foreach ( self::EVAL_ORDER as $trigger ) {
			if ( in_array( $trigger, $triggers, true ) && self::fires( $trigger, (int) $user->ID, $context, $signals ) ) {
				return $trigger;
			}
		}

		return '';
	}

	/**
	 * Sanitizer for every policy role list.
	 *
	 * Strips `administrator` until an administrator has completed one
	 * second-factor sign-in, so a policy written through the settings form,
	 * an import, MainWP or the cloud can never be the reason nobody can get
	 * back into the site.
	 *
	 * @param array<int, mixed> $roles Candidate role slugs.
	 * @return string[]
	 * @since  2.1.51
	 */
	public static function filter_policy_roles( array $roles ) {
		$roles = ReportedIP_Hive_Two_Factor::filter_valid_roles( $roles );
		if ( ReportedIP_Hive_Login_Context::admin_latch_open() ) {
			return $roles;
		}

		return array_values( array_diff( $roles, array( 'administrator' ) ) );
	}

	/**
	 * Trigger labels and one-line descriptions for the settings matrix.
	 *
	 * @return array<string, array{label:string, description:string}>
	 * @since  2.1.51
	 */
	public static function trigger_texts() {
		return array(
			'new_country'      => array(
				'label'       => __( 'New country', 'reportedip-hive' ),
				'description' => __( 'The sign-in comes from a country this account has not used before.', 'reportedip-hive' ),
			),
			'new_ip'           => array(
				'label'       => __( 'New IP address', 'reportedip-hive' ),
				'description' => __( 'The exact address is not in the account\'s recent history.', 'reportedip-hive' ),
			),
			'new_subnet'       => array(
				'label'       => __( 'New network', 'reportedip-hive' ),
				'description' => __( 'The address block (IPv4 /24, IPv6 /64) is new, so a normal dynamic-IP change does not trigger it.', 'reportedip-hive' ),
			),
			'new_device'       => array(
				'label'       => __( 'New browser or device', 'reportedip-hive' ),
				'description' => __( 'The browser fingerprint has not signed this account in before.', 'reportedip-hive' ),
			),
			'every_n_days'     => array(
				'label'       => __( 'Every few days', 'reportedip-hive' ),
				'description' => __( 'The last second-factor verification is older than the number of days below. The clock starts with the first sign-in after this feature is switched on, so nobody is challenged all at once on the day you configure it.', 'reportedip-hive' ),
			),
			'every_n_logins'   => array(
				'label'       => __( 'Every few sign-ins', 'reportedip-hive' ),
				'description' => __( 'That many sign-ins have happened since the last second-factor verification.', 'reportedip-hive' ),
			),
			'sessions_above_n' => array(
				'label'       => __( 'Too many open sessions', 'reportedip-hive' ),
				'description' => __( 'The account already has that many active sessions on other devices.', 'reportedip-hive' ),
			),
		);
	}

	/**
	 * Whether one trigger's condition holds.
	 *
	 * The `new_*` triggers stay quiet while their baseline list is empty:
	 * without history everything looks new, and a first sign-in must not be
	 * treated as an anomaly.
	 *
	 * @param string               $trigger Trigger slug.
	 * @param int                  $user_id User id.
	 * @param array<string, mixed> $context Stored sign-in history.
	 * @param array<string, mixed> $signals Signals of the current request.
	 * @return bool
	 * @since  2.1.51
	 */
	private static function fires( $trigger, $user_id, array $context, array $signals ) {
		switch ( $trigger ) {
			case 'every_n_logins':
				$logins = max( 1, (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_policy_logins', 10 ) );
				return (int) $context['logins_since_verify'] >= $logins;

			case 'every_n_days':
				$verified_at = (int) $context['verified_at'];
				$days        = max( 1, (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_policy_days', 30 ) );
				return $verified_at > 0 && ( time() - $verified_at ) >= $days * DAY_IN_SECONDS;

			case 'new_ip':
				$known = ReportedIP_Hive_Login_Context::known_ips( $user_id );
				return ! empty( $known ) && ReportedIP_Hive_Audit_Logger::is_new_ip( (string) $signals['ip'], $known );

			case 'new_subnet':
				return self::is_unseen( (string) $signals['net'], $context['nets'] );

			case 'new_device':
				return self::is_unseen( (string) $signals['ua'], $context['uas'] );

			case 'new_country':
				return self::is_unseen( (string) $signals['country'], $context['countries'] );

			case 'sessions_above_n':
				$sessions = max( 1, (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_policy_sessions', 3 ) );
				return count( ReportedIP_Hive_User_Sessions::for_user( $user_id ) ) >= $sessions;
		}

		return false;
	}

	/**
	 * Whether a signal is present and missing from its baseline list.
	 *
	 * @param string             $value Current signal, empty when unavailable.
	 * @param array<int, string> $known Baseline list.
	 * @return bool
	 * @since  2.1.51
	 */
	private static function is_unseen( $value, $known ) {
		$known = is_array( $known ) ? $known : array();

		return '' !== $value && ! empty( $known ) && ! in_array( $value, $known, true );
	}
}
