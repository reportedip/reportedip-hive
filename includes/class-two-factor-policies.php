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
 * challenged again, even on a trusted device, as soon as the trigger's
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
	 * Triggers in evaluation order, cheapest first, the session count last
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
	 * Listener on `reportedip_hive_2fa_stepup`: an earlier listener's
	 * verdict stands, otherwise {@see self::evaluate()} decides.
	 *
	 * @param string   $stepup         Verdict so far.
	 * @param \WP_User $user           Authenticated user.
	 * @param bool     $has_any_method Whether the user has an active second factor.
	 * @param bool     $is_enforced    Whether the user's role requires 2FA anyway.
	 * @return string
	 * @since  3.0.0
	 */
	public static function filter_stepup( $stepup, $user, $has_any_method, $is_enforced ) {
		if ( '' !== (string) $stepup ) {
			return (string) $stepup;
		}
		return self::evaluate( $user, (bool) $has_any_method, (bool) $is_enforced );
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
	 * Role choices the settings form cannot offer right now: the
	 * administrator role until an administrator has passed one challenge
	 * (the same rule {@see self::filter_policy_roles()} enforces on write).
	 *
	 * @return string[]
	 * @since  3.0.0
	 */
	public static function locked_choices() {
		return ReportedIP_Hive_Login_Context::admin_latch_open() ? array() : array( 'administrator' );
	}

	/**
	 * Note under a policy role list on the settings form.
	 *
	 * @param string $key Registry key.
	 * @return string
	 * @since  3.0.0
	 */
	public static function choices_note( $key ) {
		$notes = array();
		if ( ! ReportedIP_Hive_Login_Context::admin_latch_open() ) {
			$notes[] = __( 'Triggers for administrators become available once an administrator has completed one second-factor sign-in on this site.', 'reportedip-hive' );
		}
		if ( self::option_key( 'new_country' ) === (string) $key && empty( ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'api_reputation_check' )['available'] ) ) {
			$notes[] = __( 'Country data comes from the Community Network. In Local Shield the country trigger never fires.', 'reportedip-hive' );
		}
		return implode( ' ', $notes );
	}

	/**
	 * Listener on `reportedip_hive_section_state`: the number of armed
	 * triggers in the head of the policy section.
	 *
	 * @param array{text:string,tone:string} $state   State so far.
	 * @param string                         $section Section id.
	 * @param array<string,mixed>            $current Current values.
	 * @return array{text:string,tone:string}
	 * @since  3.0.0
	 */
	public static function section_state( $state, $section, $current ) {
		if ( 'twofa_policies' !== $section ) {
			return $state;
		}
		$active = 0;
		foreach ( (array) $current as $key => $value ) {
			if ( 0 === strpos( (string) $key, self::OPTION_PREFIX ) && is_array( $value ) && array() !== $value ) {
				++$active;
			}
		}
		return array(
			/* translators: %d: number of triggers */
			'text' => sprintf( __( '%d triggers', 'reportedip-hive' ), $active ),
			'tone' => 'neutral',
		);
	}

	/**
	 * Listener on `reportedip_hive_site_2fa_settings_after`: the network's
	 * trigger matrix, read-only, on a sub-site's 2FA page.
	 *
	 * @param array<string,string> $all_roles Role slug => display name.
	 * @return void
	 * @since  3.0.0
	 */
	public static function render_site_policy_block( $all_roles ) {
		$all_roles     = (array) $all_roles;
		$policy_status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( self::FEATURE );
		$policy_matrix = self::matrix();
		$policy_texts  = self::trigger_texts();
		?>
		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
				<?php esc_html_e( 'Adaptive 2FA triggers (network policy)', 'reportedip-hive' ); ?>
				&nbsp;<?php ReportedIP_Hive_Admin_Settings::render_tier_marker( $policy_status ); ?>
			</h2>
			<p class="rip-settings-section__desc">
				<?php esc_html_e( 'The Super Admin decides which roles are asked for their second factor again when something about a sign-in changes. The rules apply on this site too and cannot be overridden here.', 'reportedip-hive' ); ?>
			</p>

			<ul class="rip-network-state">
				<?php foreach ( self::TRIGGERS as $policy_trigger ) : ?>
					<li>
						<?php echo esc_html( $policy_texts[ $policy_trigger ]['label'] ); ?>:
						<?php if ( empty( $policy_matrix[ $policy_trigger ] ) ) : ?>
							<span class="rip-badge rip-badge--neutral"><?php esc_html_e( 'off', 'reportedip-hive' ); ?></span>
						<?php else : ?>
							<?php foreach ( $policy_matrix[ $policy_trigger ] as $policy_role ) : ?>
								<span class="rip-badge rip-badge--info"><?php echo esc_html( $all_roles[ $policy_role ] ?? $policy_role ); ?></span>
							<?php endforeach; ?>
						<?php endif; ?>
					</li>
				<?php endforeach; ?>
			</ul>
		</div>
		<?php
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
