<?php
/**
 * Promo banner that nudges Free / Contributor admins of WooCommerce
 * stores to consider the Frontend-2FA feature included with the
 * Professional tier.
 *
 * Modelled on {@see ReportedIP_Hive_Two_Factor_Recommend} but with two
 * key differences: the dismiss is a 14-day cooldown (per user), and the
 * gating condition is `Mode_Manager::feature_status('frontend_2fa')`
 * returning `reason=tier`. When the operator upgrades, the gate flips
 * to `available` and the banner stays silent without manual cleanup.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.7.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Static-only class. The dismiss state lives in user-meta so each
 * admin gets their own 14-day window — a single dismiss does not
 * silence the promo for the whole team.
 *
 * @since 1.7.0
 */
class ReportedIP_Hive_Two_Factor_WC_Notice {

	/**
	 * User-meta key that stores the Unix timestamp of the most recent
	 * dismissal. Zero / missing means "never dismissed".
	 */
	const META_DISMISSED_AT = 'reportedip_hive_wc2fa_promo_dismissed_at';

	/**
	 * User-meta key holding the cumulative dismiss count for telemetry.
	 */
	const META_DISMISS_COUNT = 'reportedip_hive_wc2fa_promo_dismiss_count';

	/**
	 * Site-wide killswitch. Default true; flipping it to false hides
	 * the banner for every admin without touching their dismiss state.
	 */
	const OPT_ENABLED = 'reportedip_hive_wc2fa_promo_enabled';

	/**
	 * Cooldown between two banner renderings for the same user.
	 */
	const COOLDOWN_SECS = 1209600;

	/**
	 * Bind hooks. Idempotent.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'admin_notices', array( __CLASS__, 'maybe_render' ), 20 );
		add_action( 'admin_post_reportedip_hive_wc2fa_promo_dismiss', array( __CLASS__, 'handle_dismiss' ) );
	}

	/**
	 * Whether the banner should show on the current request.
	 *
	 * Six conditions, all must hold:
	 *  - WooCommerce active (otherwise the pitch is irrelevant);
	 *  - frontend_2fa feature locked specifically by tier (not by mode
	 *    — a local-mode site is gated for a different reason and gets
	 *    a different message in the operation-mode card);
	 *  - the killswitch option is on;
	 *  - the user has manage_options;
	 *  - last dismiss is older than 14 days;
	 *  - we are on a Hive page or the dashboard, not on every random
	 *    admin screen.
	 *
	 * @param int $user_id User ID to evaluate. 0 = current user.
	 * @return bool
	 */
	public static function should_show( $user_id = 0 ) {
		if ( ! class_exists( 'WooCommerce' ) ) {
			return false;
		}
		if ( ! get_option( self::OPT_ENABLED, true ) ) {
			return false;
		}
		if ( 0 === (int) $user_id ) {
			$user_id = (int) get_current_user_id();
		}
		if ( $user_id <= 0 ) {
			return false;
		}
		if ( ! user_can( $user_id, 'manage_options' ) ) {
			return false;
		}
		if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			return false;
		}
		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'frontend_2fa' );
		if ( ! empty( $status['available'] ) ) {
			return false;
		}
		if ( 'tier' !== ( $status['reason'] ?? '' ) ) {
			return false;
		}
		$last = (int) get_user_meta( $user_id, self::META_DISMISSED_AT, true );
		if ( $last > 0 && ( time() - $last ) < self::COOLDOWN_SECS ) {
			return false;
		}
		return self::is_eligible_screen();
	}

	/**
	 * Limit the banner to admin screens that admins genuinely visit
	 * with intent (Hive admin pages and the dashboard). Keeps
	 * customize.php / profile.php / network screens free of friction.
	 *
	 * @return bool
	 */
	private static function is_eligible_screen() {
		if ( ! function_exists( 'get_current_screen' ) ) {
			return true;
		}
		$screen = get_current_screen();
		if ( ! $screen ) {
			return true;
		}
		$id = (string) $screen->id;
		if ( 'dashboard' === $id ) {
			return true;
		}
		if ( false !== strpos( $id, 'reportedip-hive' ) ) {
			return true;
		}
		if ( 'plugins' === $id ) {
			return true;
		}
		return false;
	}

	/**
	 * `admin_notices` callback. Renders the promo with the standard
	 * `rip-alert--info` design-system class so the look is consistent
	 * with every other Hive notice.
	 *
	 * @return void
	 */
	public static function maybe_render() {
		$user_id = (int) get_current_user_id();
		if ( ! self::should_show( $user_id ) ) {
			return;
		}

		$dismiss_action = wp_nonce_url(
			admin_url( 'admin-post.php?action=reportedip_hive_wc2fa_promo_dismiss' ),
			'reportedip_hive_wc2fa_promo_dismiss'
		);
		$pricing_url    = defined( 'REPORTEDIP_UPGRADE_URL' )
			? REPORTEDIP_UPGRADE_URL
			: 'https://reportedip.de/pricing/';

		?>
		<div class="notice rip-alert rip-alert--info rip-wc2fa-promo">
			<h3 class="rip-alert__title" style="margin:0 0 0.5rem;">
				<?php esc_html_e( 'Protect your WooCommerce customers with 2FA', 'reportedip-hive' ); ?>
			</h3>
			<p style="margin:0 0 0.75rem;">
				<?php esc_html_e( 'Hive Professional extends the second factor to My Account and Checkout — the only WordPress security plugin that keeps customers inside the storefront theme during sign-in. Solid Security and the WordPress Two-Factor plugin only cover the wp-admin login.', 'reportedip-hive' ); ?>
			</p>
			<p style="margin:0;">
				<a class="rip-button rip-button--primary" href="<?php echo esc_url( $pricing_url ); ?>" target="_blank" rel="noopener">
					<?php esc_html_e( 'Compare plans', 'reportedip-hive' ); ?>
				</a>
				<a class="rip-button rip-button--ghost" href="<?php echo esc_url( $dismiss_action ); ?>" style="margin-left:0.5rem;">
					<?php esc_html_e( 'Remind me in 14 days', 'reportedip-hive' ); ?>
				</a>
			</p>
		</div>
		<?php
	}

	/**
	 * `admin_post` handler — record the dismiss timestamp on the
	 * current user, bump the counter for telemetry, redirect back.
	 *
	 * @return void
	 */
	public static function handle_dismiss() {
		check_admin_referer( 'reportedip_hive_wc2fa_promo_dismiss' );

		$user_id = (int) get_current_user_id();
		if ( $user_id > 0 ) {
			update_user_meta( $user_id, self::META_DISMISSED_AT, time() );
			$count = (int) get_user_meta( $user_id, self::META_DISMISS_COUNT, true );
			update_user_meta( $user_id, self::META_DISMISS_COUNT, $count + 1 );
		}

		$redirect = wp_get_referer();
		if ( ! $redirect ) {
			$redirect = admin_url();
		}
		wp_safe_redirect( $redirect );
		exit;
	}
}
