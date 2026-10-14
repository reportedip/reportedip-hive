<?php
/**
 * One notice on the plugin pages when the account's plan covers the add-on
 * but the add-on does not run on this site.
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
 * Add-on hint for a paid account.
 *
 * The plan comes from the cached account state ({@see ReportedIP_Hive_Mode_Manager::get_current_tier()}),
 * so the hint appears after a plan change as well as on a site that came
 * from a 2.x release with a paid plan. Whether the add-on runs is read from
 * the documented extension point it uses on every boot: an add-on that
 * booted registers its rows on `reportedip_hive_feature_matrix`. The free
 * plugin names no add-on class or constant.
 *
 * The notice is rendered by {@see ReportedIP_Hive_Admin_Settings::render_inline_notices()},
 * so it appears on the plugin pages only, never on the WordPress dashboard,
 * and each user can dismiss it once per plan.
 *
 * @since 3.0.0
 */
final class ReportedIP_Hive_Addon_Notice {

	/**
	 * Notice id prefix; the plan slug is appended, so a later change to a
	 * higher plan shows the hint again.
	 *
	 * @var string
	 */
	const NOTICE_ID = 'reportedip_hive_addon_available';

	/**
	 * Plans whose account covers the add-on.
	 *
	 * @var string[]
	 */
	const PAID_TIERS = array( 'professional', 'business', 'enterprise' );

	/**
	 * Whether an add-on booted on this site.
	 *
	 * @return bool
	 */
	public static function addon_running() {
		return (bool) has_filter( 'reportedip_hive_feature_matrix' );
	}

	/**
	 * Notice id for a plan.
	 *
	 * @param string $tier Tier slug.
	 * @return string
	 */
	public static function notice_id( $tier ) {
		return self::NOTICE_ID . '_' . sanitize_key( (string) $tier );
	}

	/**
	 * Notice text for a plan, or empty when no hint is due.
	 *
	 * Pure apart from the translation: the caller supplies the plan, the
	 * add-on state and the dismissal.
	 *
	 * @param string $tier      Tier slug of the account.
	 * @param bool   $running   Whether the add-on runs.
	 * @param bool   $dismissed Whether the user dismissed the hint for this plan.
	 * @return string HTML, safe to print.
	 */
	public static function message_for( $tier, $running, $dismissed ) {
		$tier = (string) $tier;
		if ( $running || $dismissed || ! in_array( $tier, self::PAID_TIERS, true ) ) {
			return '';
		}
		return sprintf(
			/* translators: 1: plan name, 2: link to the account dashboard on reportedip.com */
			esc_html__( 'Your reportedip.com account is on the %1$s plan. Download the ReportedIP Hive Pro add-on from %2$s to use it on this site.', 'reportedip-hive' ),
			esc_html( (string) ReportedIP_Hive_Mode_Manager::get_instance()->get_tier_info( $tier )['label'] ),
			'<a href="' . esc_url( REPORTEDIP_HIVE_SITE_URL . '/dashboard/' ) . '" target="_blank" rel="noopener noreferrer">reportedip.com/dashboard</a>'
		);
	}

	/**
	 * Print the notice for the current user, if due.
	 *
	 * @return void
	 */
	public static function render() {
		if ( ! ReportedIP_Hive_Option_Routing::current_user_can_manage() ) {
			return;
		}
		$tier = (string) ReportedIP_Hive_Mode_Manager::get_instance()->get_current_tier();
		$id   = self::notice_id( $tier );
		$body = self::message_for( $tier, self::addon_running(), (bool) get_user_meta( get_current_user_id(), 'reportedip_dismissed_' . $id, true ) );
		if ( '' === $body ) {
			return;
		}
		ReportedIP_Hive_Admin_Notice::render(
			array(
				'variant'        => 'info',
				'dismissible'    => true,
				'data_notice_id' => $id,
				'body'           => $body,
			)
		);
	}
}
