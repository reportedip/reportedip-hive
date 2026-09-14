<?php
/**
 * Dashboard: status banner, next steps, area rows and the one upsell card.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.57
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The "done, and now?" part of the Security Dashboard.
 *
 * @since 2.1.57
 */
class ReportedIP_Hive_Dashboard_Next_Steps {

	/**
	 * admin-post action of an inline step.
	 *
	 * @var string
	 */
	const ACTION_STEP = 'reportedip_hive_next_step';

	/**
	 * Users above this count are a Business signal.
	 *
	 * @var int
	 */
	const BUSINESS_USER_THRESHOLD = 25;

	/**
	 * Transient prefix carrying a step result back to the dashboard.
	 *
	 * @var string
	 */
	const RESULT_TRANSIENT = 'reportedip_hive_next_step_result_';

	/**
	 * User meta holding the dismissal deadline of the per-user card.
	 *
	 * @var string
	 */
	const META_DISMISSED_OWN_2FA = 'reportedip_hive_next_step_dismissed_own_2fa_missing';

	/**
	 * Wire hooks.
	 */
	public function __construct() {
		add_action( 'admin_post_' . self::ACTION_STEP, array( $this, 'handle_next_step' ) );
	}

	/**
	 * Recommended keys whose stored value differs.
	 *
	 * @param array<string,mixed> $recommended `Defaults::recommended()`.
	 * @param array<string,mixed> $current     Registry values.
	 * @return string[]
	 */
	public static function deviations( array $recommended, array $current ) {
		$diff = array();
		foreach ( $recommended as $key => $value ) {
			if ( ! array_key_exists( $key, $current ) ) {
				continue;
			}
			if ( self::norm( $value ) !== self::norm( $current[ $key ] ) ) {
				$diff[] = $key;
			}
		}
		return $diff;
	}

	/**
	 * Comparable scalar form of an option value.
	 *
	 * @param mixed $value Value.
	 * @return string
	 */
	private static function norm( $value ) {
		if ( is_bool( $value ) ) {
			return $value ? '1' : '0';
		}
		if ( is_array( $value ) ) {
			$copy = array_map( 'strval', $value );
			sort( $copy );
			return implode( ',', $copy );
		}
		return (string) $value;
	}

	/**
	 * Timestamp of the quickstart completion, from either storage form.
	 *
	 * `Mode_Manager::mark_wizard_completed()` stores a UTC MySQL datetime; an
	 * epoch number is accepted too. Anything else yields 0.
	 *
	 * @param mixed $raw Stored option value.
	 * @return int
	 */
	public static function completed_at_timestamp( $raw ) {
		if ( is_numeric( $raw ) ) {
			return max( 0, (int) $raw );
		}
		$raw = trim( (string) $raw );
		if ( '' === $raw ) {
			return 0;
		}
		$ts = strtotime( $raw . ' UTC' );
		return false === $ts ? 0 : max( 0, $ts );
	}

	/**
	 * Points the scores gain per Protection-page section once the section's
	 * switched-off items are enabled.
	 *
	 * Only present, available and disabled items count; plan-locked items and
	 * items linking elsewhere (the Community page) are ignored.
	 *
	 * @param array<int,array<string,mixed>> $items Score item descriptors.
	 * @return array<string,int> Section id => points.
	 */
	public static function score_potential( array $items ) {
		$potential = array();
		foreach ( $items as $item ) {
			if ( empty( $item['present'] ) || empty( $item['available'] ) || ! empty( $item['enabled'] ) ) {
				continue;
			}
			$url = (string) ( $item['settings_url'] ?? '' );
			$pos = strpos( $url, '#' );
			if ( false === $pos || false === strpos( $url, 'page=reportedip-hive-protection' ) ) {
				continue;
			}
			$section               = substr( $url, $pos + 1 );
			$potential[ $section ] = ( $potential[ $section ] ?? 0 ) + (int) ( $item['weight'] ?? 0 );
		}
		return $potential;
	}

	/**
	 * Whether the site shows a Business signal.
	 *
	 * @param array{woocommerce:bool,multisite:bool,users:int} $signals Signals.
	 * @return bool
	 */
	public static function business_signal( array $signals ) {
		return ! empty( $signals['woocommerce'] ) || ! empty( $signals['multisite'] ) || (int) ( $signals['users'] ?? 0 ) > self::BUSINESS_USER_THRESHOLD;
	}

	/**
	 * The one upsell card for a plan, or null.
	 *
	 * @param string                                          $tier    Tier key.
	 * @param array{woocommerce:bool,multisite:bool,users:int} $signals Signals.
	 * @return string|null Promo key.
	 */
	public static function choose_upsell( $tier, array $signals ) {
		switch ( (string) $tier ) {
			case 'free':
			case 'contributor':
				return ! empty( $signals['woocommerce'] ) ? ReportedIP_Hive_Promo_Manager::KEY_WC_FRONTEND_2FA : ReportedIP_Hive_Promo_Manager::KEY_MAIL_SMS_RELAY;
			case 'professional':
				return self::business_signal( $signals ) ? ReportedIP_Hive_Promo_Manager::KEY_BUSINESS_SIGNAL : null;
			default:
				return ReportedIP_Hive_Promo_Manager::KEY_REFERRAL;
		}
	}

	/**
	 * Per-step action definition: button label and whether the step writes.
	 *
	 * @return array<string,array{label:string,write:bool,field?:string}>
	 */
	public static function step_actions() {
		return array(
			'hide_login_off'         => array(
				'label' => __( 'Switch on', 'reportedip-hive' ),
				'write' => true,
				'field' => 'slug',
			),
			'frontend_2fa_available' => array(
				'label' => __( 'Switch on', 'reportedip-hive' ),
				'write' => true,
			),
			'badge_off'              => array(
				'label' => __( 'Show badge', 'reportedip-hive' ),
				'write' => true,
			),
			'dropin_not_running'     => array(
				'label' => __( 'Open server setup', 'reportedip-hive' ),
				'write' => false,
			),
			'community_pending'      => array(
				'label' => __( 'Enter a key', 'reportedip-hive' ),
				'write' => false,
			),
			'own_2fa_missing'        => array(
				'label' => __( 'Set up now', 'reportedip-hive' ),
				'write' => false,
			),
		);
	}

	/**
	 * Registry values a step writes.
	 *
	 * @param string              $step  Issue key.
	 * @param array<string,mixed> $input Posted fields.
	 * @return array<string,mixed>
	 */
	public static function step_values( $step, array $input ) {
		switch ( (string) $step ) {
			case 'badge_off':
				return array( 'reportedip_hive_auto_footer_enabled' => 1 );
			case 'frontend_2fa_available':
				return array( 'reportedip_hive_2fa_frontend_enabled' => 1 );
			case 'hide_login_off':
				return array(
					'reportedip_hive_hide_login_slug'    => (string) ( $input['slug'] ?? '' ),
					'reportedip_hive_hide_login_enabled' => 1,
				);
		}
		return array();
	}

	/**
	 * Site signals for the upsell chooser.
	 *
	 * @return array{woocommerce:bool,multisite:bool,users:int}
	 */
	public static function signals() {
		$counts = count_users();
		return array(
			'woocommerce' => class_exists( 'WooCommerce' ),
			'multisite'   => is_multisite(),
			'users'       => (int) ( $counts['total_users'] ?? 0 ),
		);
	}

	/**
	 * The one status line of the dashboard, rendered above the stat cards.
	 *
	 * Green while the site runs on its recommendation. In Community Network
	 * it turns into a warning when no key is stored or the daily report
	 * quota is used up; the rate-limit state is already covered by the
	 * page-wide inline notice. All state comes from cached or local sources,
	 * nothing here performs an HTTP request.
	 *
	 * @param ReportedIP_Hive_API $api API client.
	 * @return void
	 */
	public static function render_banner( $api ) {
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		if ( ! $mode_manager->is_wizard_completed() ) {
			return;
		}
		$info           = $mode_manager->get_tier_info();
		$tier           = (string) ( $info['key'] ?? 'free' );
		$label          = (string) ( $info['label'] ?? $tier );
		$mode           = (string) $mode_manager->get_mode();
		$current        = ReportedIP_Hive_Settings_Registry::current_values();
		$diff           = self::deviations( ReportedIP_Hive_Defaults::recommended( $tier, $mode ), $current );
		$set_at         = self::completed_at_timestamp( ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_Mode_Manager::OPTION_WIZARD_COMPLETED_AT, '' ) );
		$community      = $mode_manager->is_community_mode();
		$protection_url = ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-protection' );
		$community_url  = ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-community' );

		if ( $community && ! $api->is_configured() ) {
			?>
			<div class="rip-alert rip-alert--warning rip-status-banner">
				<div class="rip-alert__content rip-alert__content--row">
					<div class="rip-alert__message"><?php esc_html_e( 'Community protection is not connected.', 'reportedip-hive' ); ?></div>
					<a href="<?php echo esc_url( $community_url ); ?>" class="rip-button rip-button--primary rip-button--sm"><?php esc_html_e( 'Connect now', 'reportedip-hive' ); ?></a>
				</div>
			</div>
			<?php
			return;
		}

		$quota = $community ? $api->get_quota_status() : array();
		if ( ! empty( $quota['exhausted'] ) ) {
			$countdown = '';
			$reset_ts  = empty( $quota['reset_time'] ) ? false : strtotime( (string) $quota['reset_time'] );
			if ( $reset_ts && $reset_ts > time() ) {
				/* translators: %s: human-readable time span until the daily quota resets */
				$countdown = sprintf( __( 'Resets in %s.', 'reportedip-hive' ), human_time_diff( time(), $reset_ts ) );
			}
			?>
			<div class="rip-alert rip-alert--warning rip-status-banner">
				<?php
				echo esc_html( trim( (string) ( $quota['message'] ?? '' ) . ' ' . $countdown ) );
				printf( ' <a href="%1$s">%2$s</a>', esc_url( $community_url ), esc_html__( 'Open the Community page', 'reportedip-hive' ) );
				?>
			</div>
			<?php
			return;
		}
		?>
		<div class="rip-alert rip-alert--success rip-status-banner">
			<?php
			if ( $set_at > 0 ) {
				/* translators: 1: plan name, 2: date */
				echo esc_html( sprintf( __( 'Protection active since %2$s on the %1$s recommendation.', 'reportedip-hive' ), $label, wp_date( (string) get_option( 'date_format' ), $set_at ) ) );
			} else {
				/* translators: %s: plan name */
				echo esc_html( sprintf( __( 'Protection active on the %s recommendation.', 'reportedip-hive' ), $label ) );
			}
			if ( $community ) {
				printf( ' <a href="%1$s">%2$s</a>', esc_url( $community_url ), esc_html__( 'Community Network connected.', 'reportedip-hive' ) );
			}
			if ( array() !== $diff ) {
				printf(
					' <a href="%1$s">%2$s</a>',
					esc_url( $protection_url ),
					/* translators: %d: number of settings that differ from the recommendation */
					esc_html( sprintf( _n( 'Adjusted (%d setting).', 'Adjusted (%d settings).', count( $diff ), 'reportedip-hive' ), count( $diff ) ) )
				);
			}
			if ( in_array( $tier, array( 'free', 'contributor' ), true ) ) {
				printf( ' <a href="%1$s">%2$s</a>', esc_url( ReportedIP_Hive_Admin_Settings::pricing_url() ), esc_html__( 'See plans', 'reportedip-hive' ) );
			}
			?>
		</div>
		<?php
	}

	/**
	 * Render the step result, next steps, area rows and the upsell card.
	 *
	 * @return void
	 */
	public static function render() {
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		if ( ! $mode_manager->is_wizard_completed() ) {
			return;
		}
		$tier           = (string) ( $mode_manager->get_tier_info()['key'] ?? 'free' );
		$current        = ReportedIP_Hive_Settings_Registry::current_values();
		$user_id        = get_current_user_id();
		$protection_url = ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-protection' );

		$result = get_transient( self::RESULT_TRANSIENT . $user_id );
		delete_transient( self::RESULT_TRANSIENT . $user_id );
		?>
		<?php if ( is_array( $result ) && ! empty( $result['message'] ) ) : ?>
			<div class="rip-alert <?php echo ! empty( $result['ok'] ) ? 'rip-alert--success' : 'rip-alert--error'; ?>"><?php echo esc_html( (string) $result['message'] ); ?></div>
		<?php endif; ?>
		<?php
		self::render_next_steps( $current, $user_id );
		self::render_area_rows( $current, $protection_url );
		self::render_upsell( $tier );
	}

	/**
	 * The next-step cards.
	 *
	 * @param array<string,mixed> $current Registry values.
	 * @param int                 $user_id Current user.
	 * @return void
	 */
	private static function render_next_steps( array $current, $user_id ) {
		$actions = self::step_actions();
		$issues  = ReportedIP_Hive_Readiness::user_issues( $user_id );
		foreach ( ReportedIP_Hive_Readiness::open_issues() as $issue ) {
			if ( ReportedIP_Hive_Readiness::SEV_ADVISORY === (string) $issue['severity'] && isset( $actions[ (string) $issue['key'] ] ) ) {
				$issues[] = $issue;
			}
		}
		if ( array() === $issues ) {
			return;
		}
		?>
		<div class="rip-card rip-next-steps">
			<div class="rip-card__header"><h2><?php esc_html_e( 'Next steps', 'reportedip-hive' ); ?></h2></div>
			<div class="rip-card__body rip-next-steps__grid">
				<?php foreach ( $issues as $issue ) : ?>
					<?php
					$key         = (string) $issue['key'];
					$action      = $actions[ $key ];
					$dismiss_url = wp_nonce_url(
						add_query_arg(
							array(
								'action'  => self::ACTION_STEP,
								'step'    => $key,
								'dismiss' => '1',
							),
							admin_url( 'admin-post.php' )
						),
						self::ACTION_STEP
					);
					?>
					<div class="rip-next-steps__card" data-step="<?php echo esc_attr( $key ); ?>">
						<h3 class="rip-next-steps__title"><?php echo esc_html( (string) $issue['label'] ); ?></h3>
						<p class="rip-next-steps__text"><?php echo esc_html( (string) $issue['message'] ); ?></p>
						<?php if ( $action['write'] ) : ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="rip-next-steps__form">
								<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_STEP ); ?>" />
								<input type="hidden" name="step" value="<?php echo esc_attr( $key ); ?>" />
								<?php wp_nonce_field( self::ACTION_STEP ); ?>
								<?php if ( 'slug' === ( $action['field'] ?? '' ) ) : ?>
									<input type="text" name="slug" class="rip-input rip-input--sm" placeholder="<?php esc_attr_e( 'my-secret-door', 'reportedip-hive' ); ?>" value="<?php echo esc_attr( (string) ( $current['reportedip_hive_hide_login_slug'] ?? '' ) ); ?>" required />
								<?php endif; ?>
								<button type="submit" class="rip-button rip-button--primary rip-button--sm"><?php echo esc_html( $action['label'] ); ?></button>
							</form>
						<?php else : ?>
							<a class="rip-button rip-button--primary rip-button--sm" href="<?php echo esc_url( (string) $issue['settings_url'] ); ?>"><?php echo esc_html( $action['label'] ); ?></a>
						<?php endif; ?>
						<?php if ( ! empty( $issue['dismissable'] ) ) : ?>
							<a class="rip-next-steps__dismiss" href="<?php echo esc_url( $dismiss_url ); ?>"><?php esc_html_e( 'Not now', 'reportedip-hive' ); ?></a>
						<?php endif; ?>
					</div>
				<?php endforeach; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * One row per registry section with the short status.
	 *
	 * @param array<string,mixed> $current        Registry values.
	 * @param string              $protection_url Protection page URL.
	 * @return void
	 */
	private static function render_area_rows( array $current, $protection_url ) {
		$potential = self::score_potential(
			array_merge(
				(array) ( ReportedIP_Hive_Score::detection_score()['items'] ?? array() ),
				(array) ( ReportedIP_Hive_Score::hardening_score()['items'] ?? array() )
			)
		);
		?>
		<details class="rip-card rip-areas">
			<summary class="rip-areas__summary">
				<span class="rip-areas__title"><?php esc_html_e( 'Protection areas', 'reportedip-hive' ); ?></span>
				<span class="rip-areas__intro"><?php esc_html_e( 'Every area of the Protection page with its current state. The points show what the scores gain once an area is switched on.', 'reportedip-hive' ); ?></span>
			</summary>
			<ul class="rip-areas__list">
				<?php foreach ( ReportedIP_Hive_Settings_Registry::sections() as $section => $meta ) : ?>
					<?php
					$url  = $protection_url . '#' . $section;
					$gain = empty( $potential[ $section ] )
						? ''
						/* translators: %d: score points the area adds once switched on */
						: sprintf( __( '+%d pts', 'reportedip-hive' ), (int) $potential[ $section ] );
					?>
					<li class="rip-areas__row">
						<div class="rip-areas__text">
							<a href="<?php echo esc_url( $url ); ?>" class="rip-areas__label"><?php echo esc_html( (string) $meta['label'] ); ?></a>
							<span class="rip-areas__desc"><?php echo esc_html( (string) ( $meta['description'] ?? '' ) ); ?></span>
						</div>
						<span class="rip-areas__state">
							<?php if ( '' !== $gain ) : ?>
								<a class="rip-badge rip-badge--info rip-areas__gain" href="<?php echo esc_url( $url ); ?>"><?php echo esc_html( $gain ); ?></a>
							<?php endif; ?>
							<span class="rip-badge rip-badge--neutral"><?php echo esc_html( ReportedIP_Hive_Protection_Page::section_status( $section, $current ) ); ?></span>
						</span>
					</li>
				<?php endforeach; ?>
			</ul>
		</details>
		<?php
	}

	/**
	 * At most one upsell card, gated by the promo manager.
	 *
	 * @param string $tier Tier key.
	 * @return void
	 */
	private static function render_upsell( $tier ) {
		$key = self::choose_upsell( $tier, self::signals() );
		if ( null === $key || ! ReportedIP_Hive_Promo_Manager::can_show( $key ) ) {
			return;
		}
		$cards = array(
			ReportedIP_Hive_Promo_Manager::KEY_MAIL_SMS_RELAY => array(
				'tier'  => 'professional',
				'title' => __( '2FA codes that arrive', 'reportedip-hive' ),
				'text'  => __( 'Professional sends the e-mail and SMS codes through the managed relay: 500 mails and 25 SMS a month, no Twilio account, and a sender reputation we maintain. From 4.97 € per domain for three sites.', 'reportedip-hive' ),
			),
			ReportedIP_Hive_Promo_Manager::KEY_WC_FRONTEND_2FA => array(
				'tier'  => 'professional',
				'title' => __( 'Second factor inside your storefront', 'reportedip-hive' ),
				'text'  => __( 'Professional puts the 2FA challenge on a themed page in My Account and checkout, so customers never see wp-login.php. Codes travel through the managed relay.', 'reportedip-hive' ),
			),
			ReportedIP_Hive_Promo_Manager::KEY_BUSINESS_SIGNAL => array(
				'tier'  => 'business',
				'title' => __( 'Built for shops, networks and teams', 'reportedip-hive' ),
				'text'  => __( 'Business adds the audit trail, account blocking with session control, white-label 2FA pages and mails, and 15 domains under one licence.', 'reportedip-hive' ),
			),
			ReportedIP_Hive_Promo_Manager::KEY_REFERRAL => array(
				'tier'  => '',
				'title' => __( 'Recommend Hive, get a month back', 'reportedip-hive' ),
				'text'  => __( 'Every customer you refer credits your account with one monthly fee of your plan. The link is on the Community page.', 'reportedip-hive' ),
			),
		);
		$card  = $cards[ $key ];
		$href  = ReportedIP_Hive_Promo_Manager::KEY_REFERRAL === $key
			? ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-community&tab=community' )
			: add_query_arg(
				array(
					'utm_source' => 'hive',
					'utm_medium' => 'dashboard',
				),
				ReportedIP_Hive_Admin_Settings::pricing_url()
			);
		?>
		<div class="rip-card rip-tier-card rip-upsell" data-promo="<?php echo esc_attr( $key ); ?>">
			<div class="rip-card__body">
				<?php if ( '' !== $card['tier'] ) : ?>
					<?php ReportedIP_Hive_Admin_Settings::render_tier_badge( $card['tier'], array( 'small' => true ) ); ?>
				<?php endif; ?>
				<h3><?php echo esc_html( $card['title'] ); ?></h3>
				<p><?php echo esc_html( $card['text'] ); ?></p>
				<a class="rip-button rip-button--primary rip-button--sm" href="<?php echo esc_url( $href ); ?>" target="_blank" rel="noopener"><?php echo ReportedIP_Hive_Promo_Manager::KEY_REFERRAL === $key ? esc_html__( 'Open the referral programme', 'reportedip-hive' ) : esc_html__( 'See plans', 'reportedip-hive' ); ?></a>
			</div>
		</div>
		<?php
		ReportedIP_Hive_Promo_Manager::mark_shown( $key );
	}

	/**
	 * admin-post handler: run or dismiss one step.
	 *
	 * @return void
	 */
	public function handle_next_step() {
		if ( ! ReportedIP_Hive_Option_Routing::current_user_can_manage() ) {
			wp_die( esc_html__( 'Permission denied.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION_STEP );
		$step    = isset( $_REQUEST['step'] ) ? sanitize_key( wp_unslash( $_REQUEST['step'] ) ) : '';
		$dismiss = ! empty( $_REQUEST['dismiss'] );
		$actions = self::step_actions();
		$message = '';
		$ok      = false;
		if ( isset( $actions[ $step ] ) ) {
			if ( $dismiss ) {
				if ( 'own_2fa_missing' === $step ) {
					update_user_meta( get_current_user_id(), self::META_DISMISSED_OWN_2FA, time() + ReportedIP_Hive_Readiness::DISMISS_SECS );
				} else {
					ReportedIP_Hive_Readiness::dismiss( $step, time() );
				}
				$ok = true;
			} elseif ( $actions[ $step ]['write'] ) {
				$input  = array( 'slug' => isset( $_POST['slug'] ) ? sanitize_text_field( wp_unslash( $_POST['slug'] ) ) : '' );
				$result = ReportedIP_Hive_Settings_Apply::apply( self::step_values( $step, $input ), 'admin' );
				foreach ( $result['results'] as $row ) {
					if ( in_array( $row['status'], array( ReportedIP_Hive_Settings_Apply::STATUS_INVALID, ReportedIP_Hive_Settings_Apply::STATUS_SKIPPED_TIER ), true ) ) {
						$message = (string) ( $row['message'] ?? __( 'Rejected.', 'reportedip-hive' ) );
					}
				}
				$ok = '' === $message;
				if ( $ok ) {
					$message = __( 'Done.', 'reportedip-hive' );
					ReportedIP_Hive_Readiness::flush_cache();
				}
			}
		}
		if ( '' !== $message ) {
			set_transient(
				self::RESULT_TRANSIENT . get_current_user_id(),
				array(
					'ok'      => $ok,
					'message' => $message,
				),
				60
			);
		}
		wp_safe_redirect( ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive' ) );
		exit;
	}
}
