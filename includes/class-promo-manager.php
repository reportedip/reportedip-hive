<?php
/**
 * Central frequency-cap and killswitch for all Pro/Upgrade promo surfaces.
 *
 * Single source of truth for the question "may this promo show now?". Every
 * promo surface (admin notice, inline upsell card) calls {@see can_show()}
 * before rendering and {@see mark_shown()} immediately after. Explicit dismiss
 * buttons route through {@see mark_dismissed()}; a dedicated permanent opt-out
 * link routes through {@see mark_permanently_dismissed()}.
 *
 * Three guards stack:
 *  1. Site-wide killswitch (option {@see OPT_ENABLED}, default true).
 *  2. Per-user global frequency cap (90 days between any two promo renders).
 *  3. Per-user per-feature cooldown (60 days after a dismiss for that key).
 *
 * Status notices (cap reached, community-layer degraded) are deliberately
 * outside this system — they are operational information, not marketing, and
 * must stay visible regardless of the cap.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.16
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Static-only class. State lives in user-meta (per admin) and a single site
 * option (the killswitch).
 *
 * @since 2.0.16
 */
class ReportedIP_Hive_Promo_Manager {

	/**
	 * Site-wide killswitch. Default true. Settings → Notifications exposes it.
	 */
	const OPT_ENABLED = 'reportedip_hive_promo_enabled';

	/**
	 * User-meta key: Unix timestamp of the most recent promo render across all
	 * features. Drives the 90-day global cap so a single admin never sees more
	 * than ~4 promo touches per year.
	 */
	const META_LAST_SHOWN = 'reportedip_hive_promo_last_shown_at';

	/**
	 * User-meta key: map `feature_key => unix_timestamp` of the most recent
	 * dismiss for that key (explicit or implicit by render). Drives the
	 * 60-day per-feature cooldown.
	 */
	const META_DISMISSED_MAP = 'reportedip_hive_promo_dismissed_at';

	/**
	 * User-meta key: map `feature_key => 1` for permanent per-user opt-out
	 * ("don't show this again, ever"). Cleared on tier upgrade so a returning
	 * paid customer can see relevant post-upgrade surfaces.
	 */
	const META_OPTOUT_MAP = 'reportedip_hive_promo_optout';

	/**
	 * Global frequency cap: minimum seconds between any two promo renders
	 * for the same user, regardless of feature. 90 days.
	 */
	const GLOBAL_FREQUENCY_CAP_SECS = 7776000;

	/**
	 * Per-feature cooldown after dismissal. 60 days.
	 */
	const PER_FEATURE_COOLDOWN_SECS = 5184000;

	/**
	 * Promo key — WooCommerce Frontend-2FA banner shown on dashboard / plugins
	 * to admins of Free / Contributor WooCommerce stores.
	 */
	const KEY_WC_FRONTEND_2FA = 'wc_frontend_2fa';

	/**
	 * Promo key — inline upsell card on the Frontend-2FA settings tab.
	 */
	const KEY_FRONTEND_2FA_INLINE = 'frontend_2fa_inline';

	/**
	 * Promo key — Mail / SMS managed-relay card on the Security Dashboard.
	 */
	const KEY_MAIL_SMS_RELAY = 'mail_sms_relay';

	/**
	 * Promo key — Hardening Mode upsell on the Hardening tab.
	 */
	const KEY_HARDENING_MODE = 'hardening_mode';

	/**
	 * Promo key — advanced threat-analytics card on the Security Dashboard.
	 */
	const KEY_ADVANCED_ANALYTICS = 'advanced_analytics';

	/**
	 * Whether a promo surface keyed `$key` is allowed to render now for `$user_id`.
	 *
	 * @param string $key     One of the KEY_* constants.
	 * @param int    $user_id User id; 0 means current user.
	 * @return bool
	 * @since  2.0.16
	 */
	public static function can_show( $key, $user_id = 0 ) {
		$key = (string) $key;
		if ( '' === $key ) {
			return false;
		}
		if ( ! self::is_enabled() ) {
			return false;
		}

		$user_id = self::resolve_user_id( $user_id );
		if ( $user_id <= 0 ) {
			return false;
		}

		if ( self::is_permanently_dismissed( $key, $user_id ) ) {
			return false;
		}

		$now        = time();
		$last_shown = (int) get_user_meta( $user_id, self::META_LAST_SHOWN, true );
		if ( $last_shown > 0 && ( $now - $last_shown ) < self::GLOBAL_FREQUENCY_CAP_SECS ) {
			return false;
		}

		$map      = self::dismissed_map( $user_id );
		$per_feat = isset( $map[ $key ] ) ? (int) $map[ $key ] : 0;
		if ( $per_feat > 0 && ( $now - $per_feat ) < self::PER_FEATURE_COOLDOWN_SECS ) {
			return false;
		}

		return true;
	}

	/**
	 * Record that a promo surface keyed `$key` actually rendered. Bumps both
	 * the global and the per-feature timestamps.
	 *
	 * Must be called AFTER the surface renders, not before — an eager check
	 * followed by a no-render bug would otherwise silently consume a slot.
	 *
	 * @param string $key
	 * @param int    $user_id 0 = current user.
	 * @return void
	 * @since  2.0.16
	 */
	public static function mark_shown( $key, $user_id = 0 ) {
		$user_id = self::resolve_user_id( $user_id );
		if ( $user_id <= 0 ) {
			return;
		}
		$now = time();
		update_user_meta( $user_id, self::META_LAST_SHOWN, $now );

		$map                  = self::dismissed_map( $user_id );
		$map[ (string) $key ] = $now;
		update_user_meta( $user_id, self::META_DISMISSED_MAP, $map );
	}

	/**
	 * Record an explicit user dismissal. Functionally identical to
	 * {@see mark_shown()} but exists so the call site reads as intent.
	 *
	 * @param string $key
	 * @param int    $user_id
	 * @return void
	 * @since  2.0.16
	 */
	public static function mark_dismissed( $key, $user_id = 0 ) {
		self::mark_shown( $key, $user_id );
	}

	/**
	 * Permanent opt-out for this user and this feature.
	 *
	 * @param string $key
	 * @param int    $user_id
	 * @return void
	 * @since  2.0.16
	 */
	public static function mark_permanently_dismissed( $key, $user_id = 0 ) {
		$user_id = self::resolve_user_id( $user_id );
		if ( $user_id <= 0 ) {
			return;
		}
		$map                  = self::optout_map( $user_id );
		$map[ (string) $key ] = 1;
		update_user_meta( $user_id, self::META_OPTOUT_MAP, $map );
	}

	/**
	 * Reset per-user promo state. Called from {@see ReportedIP_Hive_Tier_Upgrade}
	 * when the customer upgrades so the post-upgrade banner is not blocked by
	 * a stale global cap and old per-feature timestamps from a previous
	 * lifecycle no longer apply. Permanent opt-outs (META_OPTOUT_MAP) are
	 * preserved — those are explicit user choices, not lifecycle state.
	 *
	 * @param int $user_id
	 * @return void
	 * @since  2.0.16
	 */
	public static function reset_for_user( $user_id ) {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return;
		}
		delete_user_meta( $user_id, self::META_LAST_SHOWN );
		delete_user_meta( $user_id, self::META_DISMISSED_MAP );
	}

	/**
	 * Whether the site-wide killswitch is on.
	 *
	 * @return bool
	 * @since  2.0.16
	 */
	public static function is_enabled() {
		return (bool) ReportedIP_Hive_Option_Routing::get( self::OPT_ENABLED, true );
	}

	/**
	 * Whether the user has permanently opted out of this promo key.
	 *
	 * @param string $key
	 * @param int    $user_id
	 * @return bool
	 * @since  2.0.16
	 */
	public static function is_permanently_dismissed( $key, $user_id ) {
		$map = self::optout_map( (int) $user_id );
		return ! empty( $map[ (string) $key ] );
	}

	/**
	 * Resolve a user id, falling back to the current user when 0 is passed.
	 *
	 * @param int $user_id
	 * @return int
	 */
	private static function resolve_user_id( $user_id ) {
		if ( 0 === (int) $user_id ) {
			return (int) get_current_user_id();
		}
		return (int) $user_id;
	}

	/**
	 * @param int $user_id
	 * @return array<string,int>
	 */
	private static function dismissed_map( $user_id ) {
		$raw = get_user_meta( (int) $user_id, self::META_DISMISSED_MAP, true );
		return is_array( $raw ) ? $raw : array();
	}

	/**
	 * @param int $user_id
	 * @return array<string,int>
	 */
	private static function optout_map( $user_id ) {
		$raw = get_user_meta( (int) $user_id, self::META_OPTOUT_MAP, true );
		return is_array( $raw ) ? $raw : array();
	}
}
