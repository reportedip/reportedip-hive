<?php
/**
 * Admin Settings Class for ReportedIP Hive.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ReportedIP_Hive_Admin_Settings {

	private $database;
	private $api_client;
	private $logger;

	public function __construct() {
		$this->database   = ReportedIP_Hive_Database::get_instance();
		$this->api_client = ReportedIP_Hive_API::get_instance();
		$this->logger     = ReportedIP_Hive_Logger::get_instance();

		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
		add_action( 'network_admin_menu', array( $this, 'add_network_admin_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_init', array( 'ReportedIP_Hive_Two_Factor_Admin', 'register_settings' ) );
		add_action( 'admin_notices', array( $this, 'render_tier_upgrade_banner' ) );
		add_action( 'admin_notices', array( $this, 'render_cap_status_notice' ), 5 );
		add_action( 'admin_post_reportedip_hive_cap_notice_dismiss', array( $this, 'handle_cap_notice_dismiss' ) );
		add_action( 'admin_post_reportedip_hive_audit_export', array( $this, 'handle_audit_export' ) );
		add_action( 'updated_option', array( $this, 'maybe_sync_notifications_to_api' ), 10, 1 );
		add_action( 'network_admin_edit_reportedip_hive_save_settings', array( $this, 'handle_network_admin_save' ) );
	}

	/**
	 * Form action URL for Settings-API forms.
	 *
	 * On the network admin context, options.php cannot persist sitemeta —
	 * we route through edit.php?action=reportedip_hive_save_settings instead,
	 * which is dispatched to {@see handle_network_admin_save()}. Outside
	 * network admin we keep the WordPress core options.php endpoint.
	 *
	 * @return string Absolute URL for use in `<form action="">`.
	 * @since  2.0.0
	 */
	public static function settings_form_action() {
		if ( is_network_admin() ) {
			return network_admin_url( 'edit.php?action=reportedip_hive_save_settings' );
		}
		return admin_url( 'options.php' );
	}

	/**
	 * Get the correct admin URL for a plugin page.
	 *
	 * Handles Multisite network admin screens properly by routing to
	 * network_admin_url() when is_network_admin() is true.
	 *
	 * @param string $path Target path, e.g. admin.php?page=...
	 * @return string Absolute admin URL.
	 * @since  2.0.26
	 */
	public static function get_admin_page_url( $path ) {
		if ( is_network_admin() ) {
			return network_admin_url( $path );
		}
		return admin_url( $path );
	}

	/**
	 * Handle Settings-API submissions on the network admin.
	 *
	 * Mirrors WordPress core's options.php whitelist + sanitize-callback
	 * loop, but persists via {@see ReportedIP_Hive_Option_Routing::set()}
	 * so network-scoped values land in sitemeta. Per-site overrides
	 * (the three keys in `Option_Routing::SITE_OPTION_LOOKUP`) are not
	 * editable from network admin tabs and are filtered out here as a
	 * defence in depth.
	 *
	 * Posted via `<form action="<?php echo self::settings_form_action(); ?>">`.
	 * The form keeps `settings_fields( $option_group )` so the standard
	 * `<option_group>-options` nonce action is still used here.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	public function handle_network_admin_save() {
		if ( ! current_user_can( 'manage_network_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to perform this action.', 'reportedip-hive' ) );
		}

		$option_page = isset( $_POST['option_page'] )
			? sanitize_key( wp_unslash( $_POST['option_page'] ) )
			: '';

		if ( '' === $option_page ) {
			wp_die( esc_html__( 'Missing option group.', 'reportedip-hive' ) );
		}

		check_admin_referer( $option_page . '-options' );

		global $new_whitelist_options;

		$whitelisted = isset( $new_whitelist_options[ $option_page ] )
			? (array) $new_whitelist_options[ $option_page ]
			: array();

		foreach ( $whitelisted as $option_name ) {
			if ( 0 !== strpos( $option_name, 'reportedip_hive_' ) ) {
				continue;
			}
			if ( ReportedIP_Hive_Option_Routing::is_site_option( $option_name ) ) {
				continue;
			}

			// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Per-option sanitization is delegated to the registered sanitize_callback that update_site_option runs via the sanitize_option_<key> filter; pre-sanitizing here would double-apply the callback and collapse complex array values.
			$raw   = $_POST[ $option_name ] ?? null;
			$value = is_string( $raw ) ? wp_unslash( $raw ) : $raw;
			// phpcs:enable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash

			ReportedIP_Hive_Option_Routing::set( $option_name, $value );
		}

		add_settings_error(
			$option_page,
			'settings_updated',
			__( 'Settings saved.', 'reportedip-hive' ),
			'success'
		);
		set_transient( 'settings_errors', get_settings_errors(), 30 );

		$referer = wp_get_referer();
		if ( ! $referer ) {
			$referer = network_admin_url( 'admin.php?page=reportedip-hive-settings' );
		}
		$referer = add_query_arg( 'settings-updated', 'true', $referer );
		wp_safe_redirect( $referer );
		exit;
	}

	/**
	 * Trigger an opportunistic API sync when any notification setting changes.
	 *
	 * Listens on the four notification keys and fires once per request via a
	 * static flag, so saving the whole tab still produces a single POST. Skips
	 * silently when the sync toggle is off or the API client cannot be used.
	 *
	 * @param string $option Option name being updated.
	 * @since 1.5.3
	 */
	public function maybe_sync_notifications_to_api( $option ) {
		static $already_synced = false;

		$watched = array(
			'reportedip_hive_notify_recipients',
			'reportedip_hive_notify_from_name',
			'reportedip_hive_notify_from_email',
			'reportedip_hive_notify_sync_to_api',
		);
		if ( $already_synced || ! in_array( $option, $watched, true ) ) {
			return;
		}
		if ( ! ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_notify_sync_to_api', false ) ) {
			return;
		}

		$already_synced = true;

		if ( ! method_exists( $this->api_client, 'sync_notification_config' ) ) {
			return;
		}

		$this->api_client->sync_notification_config(
			array(
				'recipients' => ReportedIP_Hive_Defaults::notify_recipients(),
				'from_name'  => (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_notify_from_name', '' ),
				'from_email' => (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_notify_from_email', '' ),
			)
		);
	}

	/**
	 * Render unified page header for all plugin pages
	 *
	 * @param string $title   Page title
	 * @param string $subtitle Page subtitle/description
	 */
	public static function render_page_header( $title, $subtitle ) {
		?>
		<div class="wrap rip-wrap">
			<div class="rip-header">
				<div class="rip-header__brand">
					<div class="rip-header__logo">
						<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
							<path d="M24 4L8 12v12c0 11 7.7 21.3 16 24 8.3-2.7 16-13 16-24V12L24 4z" fill="currentColor" opacity="0.15"/>
							<path d="M24 4L8 12v12c0 11 7.7 21.3 16 24 8.3-2.7 16-13 16-24V12L24 4zm0 4.2l12 6v10c0 8.4-6 16.3-12 18.5-6-2.2-12-10.1-12-18.5v-10l12-6z" fill="currentColor"/>
							<path d="M21 28l-5-5 1.8-1.8 3.2 3.2 7.2-7.2L30 19l-9 9z" fill="currentColor"/>
						</svg>
					</div>
					<div>
						<h1 class="rip-header__title"><?php echo esc_html( $title ); ?></h1>
						<p class="rip-header__subtitle"><?php echo esc_html( $subtitle ); ?></p>
					</div>
				</div>
				<?php self::render_header_actions(); ?>
			</div>

			<?php self::render_inline_notices(); ?>
			<?php self::render_settings_saved_notice(); ?>
		<?php
	}

	/**
	 * Render the "Settings saved." notice after a Network-admin save.
	 *
	 * The Settings API normally renders this notice automatically on
	 * `wp-admin/options-*.php` screens via core, but custom admin pages
	 * (and our network-admin save handler) need to opt in. We read the
	 * `settings_errors` transient that {@see handle_network_admin_save()}
	 * stores right before its redirect, then delegate rendering to
	 * `settings_errors()` which honours the standard `notice-success`
	 * styling expected by WordPress admins.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	public static function render_settings_saved_notice() {
		$transient = get_transient( 'settings_errors' );
		if ( is_array( $transient ) ) {
			foreach ( $transient as $error ) {
				if ( ! is_array( $error ) ) {
					continue;
				}
				add_settings_error(
					(string) ( $error['setting'] ?? 'general' ),
					(string) ( $error['code'] ?? 'settings_updated' ),
					(string) ( $error['message'] ?? '' ),
					(string) ( $error['type'] ?? 'success' )
				);
			}
			delete_transient( 'settings_errors' );
		}

		$errors = get_settings_errors();
		if ( ! empty( $errors ) ) {
			foreach ( $errors as $error ) {
				$type    = (string) ( $error['type'] ?? 'success' );
				$variant = 'info';
				if ( 'error' === $type ) {
					$variant = 'error';
				} elseif ( 'warning' === $type ) {
					$variant = 'warning';
				} elseif ( 'success' === $type || 'updated' === $type ) {
					$variant = 'success';
				}

				ReportedIP_Hive_Admin_Notice::render(
					array(
						'variant'     => $variant,
						'body'        => $error['message'] ?? '',
						'dismissible' => true,
					)
				);
			}
			// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Custom notice rendering requires clearing settings errors to prevent double-rendering.
			$GLOBALS['wp_settings_errors'] = array();
		}
	}

	/**
	 * Render the header actions cluster: mode badge + tier badge.
	 *
	 * @param array $opts Optional flags: 'show_mode' (bool), 'show_tier' (bool).
	 * @return void
	 * @since 1.5.3
	 */
	public static function render_header_actions( $opts = array() ) {
		$opts = wp_parse_args(
			$opts,
			array(
				'show_mode' => true,
				'show_tier' => true,
			)
		);
		?>
		<div class="rip-header__actions">
			<?php if ( ! empty( $opts['show_mode'] ) ) : ?>
				<?php self::render_mode_badge(); ?>
			<?php endif; ?>
			<?php
			if ( ! empty( $opts['show_tier'] ) ) {
				$tier_key  = ReportedIP_Hive_Mode_Manager::get_instance()->get_tier_info()['key'];
				$tier_opts = array();
				if ( in_array( $tier_key, array( 'free', 'contributor' ), true ) && current_user_can( 'manage_options' ) ) {
					$tier_opts = array(
						'href'  => self::pricing_url(),
						'title' => __( 'Compare plans — unlock PRO protection, managed 2FA delivery and priority rulesets', 'reportedip-hive' ),
					);
				}
				self::render_tier_badge( null, $tier_opts );
			}
			?>
		</div>
		<?php
	}

	/**
	 * Render the operation-mode badge (Local Shield / Community Network).
	 *
	 * @param string|null $mode Optional explicit mode (defaults to current mode).
	 * @return void
	 * @since 1.5.3
	 */
	public static function render_mode_badge( $mode = null ) {
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$info         = $mode_manager->get_mode_info( $mode );
		?>
		<span class="rip-mode-badge <?php echo esc_attr( $info['badge_class'] ); ?>">
			<?php if ( $info['key'] === 'local' ) : ?>
				<svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
			<?php else : ?>
				<svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><circle cx="10" cy="10" r="8" stroke="currentColor" stroke-width="2" fill="none"/><path d="M2 10h16M10 2c2.8 2.8 4.4 6.5 4.4 8s-1.6 5.2-4.4 8c-2.8-2.8-4.4-6.5-4.4-8s1.6-5.2 4.4-8z" stroke="currentColor" stroke-width="1.5" fill="none"/></svg>
			<?php endif; ?>
			<?php echo esc_html( $info['label'] ); ?>
		</span>
		<?php
	}

	/**
	 * Render the tier badge.
	 *
	 * @param string|null $tier Optional explicit tier (defaults to current tier).
	 * @param array       $opts {
	 *     Optional. Render flags.
	 *     @type bool   $small  Compact variant for inline placement (default false).
	 *     @type bool   $locked Render a lock glyph instead of the tier icon (default false).
	 *     @type string $href   When non-empty the badge renders as an external link.
	 *     @type string $title  Tooltip override (defaults to the tier description).
	 * }
	 * @return void
	 * @since 1.5.3
	 */
	public static function render_tier_badge( $tier = null, $opts = array() ) {
		$opts = wp_parse_args(
			$opts,
			array(
				'small'  => false,
				'locked' => false,
				'href'   => '',
				'title'  => '',
			)
		);

		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$info         = $mode_manager->get_tier_info( $tier );

		$classes = 'rip-tier-badge ' . $info['badge_class'];
		if ( ! empty( $opts['small'] ) ) {
			$classes .= ' rip-tier-badge--sm';
		}

		$title = '' !== $opts['title'] ? $opts['title'] : $info['description'];

		if ( '' !== $opts['href'] ) {
			printf(
				'<a class="%1$s" title="%2$s" href="%3$s" target="_blank" rel="noopener noreferrer">',
				esc_attr( $classes ),
				esc_attr( $title ),
				esc_url( $opts['href'] )
			);
		} else {
			printf(
				'<span class="%1$s" title="%2$s">',
				esc_attr( $classes ),
				esc_attr( $title )
			);
		}

		if ( ! empty( $opts['locked'] ) ) {
			echo '<svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2h.5A1.5 1.5 0 0117 10.5v6A1.5 1.5 0 0115.5 18h-11A1.5 1.5 0 013 16.5v-6A1.5 1.5 0 014.5 9H5zm2 0V7a3 3 0 116 0v2H7z" clip-rule="evenodd"/></svg>';
		} else {
			echo self::kses_inline_svg( $info['icon'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- kses_inline_svg() applies wp_kses internally; the SVG is whitelisted by the helper.
		}

		echo esc_html( $info['short_label'] );

		echo '' !== $opts['href'] ? '</a>' : '</span>';
	}

	/**
	 * Render the canonical tier marker for a tier-gated feature.
	 *
	 * Single entry point that keeps the tier story visible in both directions:
	 *
	 *  - feature locked by tier  — compact tier badge with a lock glyph,
	 *    linked to the pricing page so the upgrade path is one click away
	 *  - feature locked by mode  — delegates to the mode tier-lock chip
	 *  - feature available       — the same compact tier badge without the
	 *    lock, so paying customers keep seeing what their plan includes
	 *  - feature has no tier gate — renders nothing
	 *
	 * @param array $status Output of Mode_Manager::feature_status().
	 * @param array $opts {
	 *     Optional. Render flags.
	 *     @type bool   $link Whether the locked badge links out (default true);
	 *                        set false when the marker sits inside another link.
	 *     @type string $href Override the locked-badge link target.
	 * }
	 * @return void
	 * @since 2.1.7
	 */
	public static function render_tier_marker( $status, $opts = array() ) {
		if ( empty( $status ) || ! is_array( $status ) || empty( $status['min_tier'] ) ) {
			return;
		}

		$opts = wp_parse_args(
			$opts,
			array(
				'link' => true,
				'href' => '',
			)
		);

		$min_tier = (string) $status['min_tier'];

		if ( ! empty( $status['available'] ) ) {
			self::render_tier_badge(
				$min_tier,
				array(
					'small' => true,
					'title' => __( 'Included in your plan', 'reportedip-hive' ),
				)
			);
			return;
		}

		$reason = $status['reason'] ?? '';

		if ( 'mode' === $reason ) {
			self::render_tier_lock( $status, '' !== $opts['href'] ? array( 'href' => $opts['href'] ) : array() );
			return;
		}

		if ( 'tier' !== $reason ) {
			return;
		}

		$tier_label = ReportedIP_Hive_Mode_Manager::get_instance()->get_tier_info( $min_tier )['label'];
		$href       = '';
		if ( ! empty( $opts['link'] ) ) {
			$href = '' !== $opts['href'] ? $opts['href'] : self::pricing_url();
		}

		self::render_tier_badge(
			$min_tier,
			array(
				'small'  => true,
				'locked' => true,
				'href'   => $href,
				/* translators: %s = plan name (e.g. "Professional") */
				'title'  => sprintf( __( 'Available with the %s plan and higher — compare plans', 'reportedip-hive' ), $tier_label ),
			)
		);
	}

	/**
	 * Canonical target for upgrade affordances (locked tier markers, header
	 * badge): the public pricing page where plans can be compared and booked.
	 *
	 * @return string
	 * @since 2.1.7
	 */
	public static function pricing_url() {
		return 'https://reportedip.de/pricing/';
	}

	/**
	 * Sanitize inline SVG markup against a permissive allowlist suitable for
	 * decorative icons. Returns escaped HTML — safe to echo directly.
	 *
	 * @param string $svg_html Raw SVG markup (typically from a constants table).
	 * @return string
	 * @since 1.5.3
	 */
	public static function kses_inline_svg( $svg_html ) {
		static $allowed = null;
		if ( null === $allowed ) {
			$shape_attrs = array(
				'd'            => true,
				'cx'           => true,
				'cy'           => true,
				'r'            => true,
				'x'            => true,
				'y'            => true,
				'x1'           => true,
				'x2'           => true,
				'y1'           => true,
				'y2'           => true,
				'width'        => true,
				'height'       => true,
				'rx'           => true,
				'ry'           => true,
				'points'       => true,
				'fill'         => true,
				'fill-rule'    => true,
				'clip-rule'    => true,
				'stroke'       => true,
				'stroke-width' => true,
				'opacity'      => true,
			);
			$allowed     = array(
				'svg'      => array(
					'viewbox'      => true,
					'fill'         => true,
					'stroke'       => true,
					'stroke-width' => true,
					'xmlns'        => true,
					'aria-hidden'  => true,
					'width'        => true,
					'height'       => true,
				),
				'path'     => $shape_attrs,
				'circle'   => $shape_attrs,
				'rect'     => $shape_attrs,
				'line'     => $shape_attrs,
				'polyline' => $shape_attrs,
				'polygon'  => $shape_attrs,
			);
		}
		return wp_kses( (string) $svg_html, $allowed );
	}

	/**
	 * Render an upgrade-affordance chip for tier-gated controls.
	 *
	 * @param array $status Output of Mode_Manager::feature_status().
	 * @param array $opts   Optional: 'href' (override URL), 'label' (override text).
	 * @return void
	 * @since 1.5.3
	 */
	public static function render_tier_lock( $status, $opts = array() ) {
		if ( empty( $status ) ) {
			return;
		}
		if ( ! empty( $status['available'] ) ) {
			return;
		}

		$reason = $status['reason'] ?? 'unknown';

		if ( 'mode' === $reason ) {
			$mode_required = (string) ( $status['mode_required'] ?? '' );
			$label_default = ( 'community' === $mode_required )
				? __( 'Community only', 'reportedip-hive' )
				: __( 'Mode required', 'reportedip-hive' );
			$label         = $opts['label'] ?? $label_default;
			$href          = $opts['href'] ?? self::get_admin_page_url( 'admin.php?page=reportedip-hive-settings&tab=general' );
			?>
			<a href="<?php echo esc_url( $href ); ?>" class="rip-tier-lock rip-tier-lock--mode">
				<svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2h.5A1.5 1.5 0 0117 10.5v6A1.5 1.5 0 0115.5 18h-11A1.5 1.5 0 013 16.5v-6A1.5 1.5 0 014.5 9H5zm2 0V7a3 3 0 116 0v2H7z" clip-rule="evenodd"/></svg>
				<?php echo esc_html( $label ); ?>
			</a>
			<?php
			return;
		}

		if ( 'tier' === $reason ) {
			$min_tier   = (string) ( $status['min_tier'] ?? 'professional' );
			$mm         = ReportedIP_Hive_Mode_Manager::get_instance();
			$tier_label = $mm->get_tier_info( $min_tier )['short_label'];
			$variant    = ( 'business' === $min_tier || 'enterprise' === $min_tier )
				? 'rip-tier-lock--business'
				: '';
			$href       = $opts['href'] ?? self::pricing_url();
			$label      = $opts['label'] ?? sprintf(
				/* translators: %s = tier name (e.g. "PRO", "Business") */
				__( '%s+', 'reportedip-hive' ),
				$tier_label
			);
			?>
			<a
				href="<?php echo esc_url( $href ); ?>"
				class="rip-tier-lock <?php echo esc_attr( $variant ); ?>"
				target="_blank"
				rel="noopener noreferrer"
			>
				<svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2h.5A1.5 1.5 0 0117 10.5v6A1.5 1.5 0 0115.5 18h-11A1.5 1.5 0 013 16.5v-6A1.5 1.5 0 014.5 9H5zm2 0V7a3 3 0 116 0v2H7z" clip-rule="evenodd"/></svg>
				<?php echo esc_html( $label ); ?>
			</a>
			<?php
		}
	}

	/**
	 * Render the "Available with Professional plan" upsell card for the
	 * Frontend-2FA section. Shared between the network-admin 2FA tab and
	 * the per-site 2FA settings page so feature copy stays in one place.
	 *
	 * Renders nothing when the feature is available or when the gate is not
	 * a tier gate (e.g. mode mismatch — handled by the inline tier-lock chip).
	 *
	 * @param array $status Output of Mode_Manager::feature_status('frontend_2fa').
	 * @return void
	 * @since 2.0.0
	 */
	public static function render_frontend_2fa_pro_upsell( $status ) {
		if ( empty( $status ) ) {
			return;
		}
		if ( ! empty( $status['available'] ) ) {
			return;
		}
		if ( 'tier' !== ( $status['reason'] ?? '' ) ) {
			return;
		}
		if ( class_exists( 'ReportedIP_Hive_Promo_Manager' )
			&& ! ReportedIP_Hive_Promo_Manager::can_show( ReportedIP_Hive_Promo_Manager::KEY_FRONTEND_2FA_INLINE )
		) {
			return;
		}

		$upgrade_url = self::pricing_url();
		?>
		<div class="rip-alert rip-alert--info rip-pro-upsell">
			<p class="rip-pro-upsell__title">
				<?php esc_html_e( 'Available with the Professional plan and higher', 'reportedip-hive' ); ?>
			</p>
			<ul class="rip-pro-upsell__features">
				<li><?php esc_html_e( 'Themed challenge page on the My Account / Checkout slug', 'reportedip-hive' ); ?></li>
				<li><?php esc_html_e( 'Themed onboarding wizard for Customer / Subscriber roles', 'reportedip-hive' ); ?></li>
				<li><?php esc_html_e( 'Cart and checkout state survive the redirect roundtrip', 'reportedip-hive' ); ?></li>
				<li><?php esc_html_e( 'WC Blocks Cart / Checkout error redirect listener', 'reportedip-hive' ); ?></li>
				<li><?php esc_html_e( 'Trusted-device cookie shared with the wp-login flow', 'reportedip-hive' ); ?></li>
				<li><?php esc_html_e( 'Hide-Login bypass + cache-plugin-safe headers', 'reportedip-hive' ); ?></li>
			</ul>
			<p class="rip-pro-upsell__cta">
				<a class="rip-button rip-button--primary" href="<?php echo esc_url( $upgrade_url ); ?>" target="_blank" rel="noopener noreferrer">
					<?php esc_html_e( 'Compare plans', 'reportedip-hive' ); ?>
				</a>
			</p>
		</div>
		<?php

		if ( class_exists( 'ReportedIP_Hive_Promo_Manager' ) ) {
			ReportedIP_Hive_Promo_Manager::mark_shown( ReportedIP_Hive_Promo_Manager::KEY_FRONTEND_2FA_INLINE );
		}
	}

	/**
	 * Render the Local-vs-Community comparison cards.
	 *
	 * Reused by the Settings General tab (interactive radio cards) and the
	 * setup wizard step 1 (read-only value-proposition view).
	 *
	 * @param array $opts {
	 *     Optional. Render flags.
	 *     @type bool        $interactive Whether to render radio inputs (default true).
	 *     @type string|null $selected    Pre-selected mode key (default current mode).
	 *     @type string|null $highlight   Optional mode key to visually highlight even when not selected.
	 * }
	 * @return void
	 * @since 1.5.3
	 */
	public static function render_mode_comparison( $opts = array() ) {
		$opts = wp_parse_args(
			$opts,
			array(
				'interactive' => true,
				'selected'    => null,
				'highlight'   => null,
			)
		);

		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$selected     = $opts['selected'] ?? $mode_manager->get_mode();
		$interactive  = ! empty( $opts['interactive'] );
		$highlight    = $opts['highlight'];
		$wrapper_tag  = $interactive ? 'label' : 'div';
		?>
		<div class="rip-mode-cards">
			<<?php echo esc_html( $wrapper_tag ); ?>
				class="rip-mode-card <?php echo $selected === 'local' ? 'rip-mode-card--selected' : ''; ?> <?php echo $highlight === 'local' ? 'rip-mode-card--highlight' : ''; ?>"
			>
				<?php if ( $interactive ) : ?>
					<input type="radio" name="reportedip_hive_operation_mode" value="local" <?php checked( $selected, 'local' ); ?> class="rip-mode-card__input" />
				<?php endif; ?>
				<div class="rip-mode-card__icon">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
				</div>
				<div class="rip-mode-card__content">
					<h3 class="rip-mode-card__title"><?php esc_html_e( 'Local Protection', 'reportedip-hive' ); ?></h3>
					<p class="rip-mode-card__desc"><?php esc_html_e( 'Standalone protection without API connection. Perfect for privacy-focused sites.', 'reportedip-hive' ); ?></p>
					<ul class="rip-mode-card__features">
						<li><?php esc_html_e( 'Works offline', 'reportedip-hive' ); ?></li>
						<li><?php esc_html_e( 'No account required', 'reportedip-hive' ); ?></li>
						<li><?php esc_html_e( 'Local blocking only', 'reportedip-hive' ); ?></li>
					</ul>
				</div>
				<?php if ( $interactive ) : ?>
					<span class="rip-mode-card__check">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>
					</span>
				<?php endif; ?>
			</<?php echo esc_html( $wrapper_tag ); ?>>

			<<?php echo esc_html( $wrapper_tag ); ?>
				class="rip-mode-card <?php echo $selected === 'community' ? 'rip-mode-card--selected' : ''; ?> <?php echo $highlight === 'community' ? 'rip-mode-card--highlight' : ''; ?>"
			>
				<?php if ( $interactive ) : ?>
					<input type="radio" name="reportedip_hive_operation_mode" value="community" <?php checked( $selected, 'community' ); ?> class="rip-mode-card__input" />
				<?php endif; ?>
				<div class="rip-mode-card__icon rip-mode-card__icon--community">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2c3 3.6 4.7 7.4 4.7 10s-1.7 6.4-4.7 10c-3-3.6-4.7-7.4-4.7-10s1.7-6.4 4.7-10z"/></svg>
				</div>
				<div class="rip-mode-card__content">
					<h3 class="rip-mode-card__title"><?php esc_html_e( 'Community Network', 'reportedip-hive' ); ?></h3>
					<p class="rip-mode-card__desc"><?php esc_html_e( 'Join thousands of sites sharing threat intelligence. Collective protection powered by community.', 'reportedip-hive' ); ?></p>
					<ul class="rip-mode-card__features">
						<li><?php esc_html_e( 'Real-time threat data', 'reportedip-hive' ); ?></li>
						<li><?php esc_html_e( 'Community blocklists', 'reportedip-hive' ); ?></li>
						<li><?php esc_html_e( 'GDPR compliant', 'reportedip-hive' ); ?></li>
					</ul>
				</div>
				<?php if ( $interactive ) : ?>
					<span class="rip-mode-card__check">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>
				</span>
				<?php endif; ?>
			</<?php echo esc_html( $wrapper_tag ); ?>>
		</div>
		<?php
	}

	/**
	 * Render the dashboard "Relay Quota" section for PRO+ Community sites.
	 *
	 * Shows mail and SMS monthly usage, optional bundle balance for Business+,
	 * and a stale-data hint when the snapshot is older than 24h.
	 *
	 * @param ReportedIP_Hive_Mode_Manager $mode_manager Singleton.
	 * @return void
	 * @since 1.5.3
	 */
	/**
	 * Render the Mail/SMS upgrade CTA card for Free-tier Community sites.
	 *
	 * @param ReportedIP_Hive_Mode_Manager $mode_manager Singleton.
	 * @return void
	 * @since 1.6.0
	 */
	private function render_mail_sms_promo_card( $mode_manager ) {
		if ( class_exists( 'ReportedIP_Hive_Promo_Manager' )
			&& ! ReportedIP_Hive_Promo_Manager::can_show( ReportedIP_Hive_Promo_Manager::KEY_MAIL_SMS_RELAY )
		) {
			return;
		}

		$mail_status = $mode_manager->feature_status( 'mail_relay_via_api' );
		$sms_status  = $mode_manager->feature_status( 'sms_relay_via_api' );
		unset( $sms_status );
		?>
		<div class="rip-card rip-mb-6 rip-promo-card">
			<div class="rip-card__header">
				<h2 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
					<?php esc_html_e( 'Reliable mail & SMS delivery', 'reportedip-hive' ); ?>
				</h2>
			</div>
			<div class="rip-card__body">
				<p><?php esc_html_e( 'Upgrade to Professional to route 2FA codes and security alerts through the reportedip.de relay — verified SPF/DKIM/DMARC, anti-fraud routing, no spam folder.', 'reportedip-hive' ); ?></p>
				<ul class="rip-promo-card__benefits">
					<li><?php esc_html_e( '500 mails / month included (Business: 2,500)', 'reportedip-hive' ); ?></li>
					<li><?php esc_html_e( '25 SMS / month included (Business: 75 + add-on bundles)', 'reportedip-hive' ); ?></li>
					<li><?php esc_html_e( 'No SMTP/SMS provider contract needed — managed by reportedip.de', 'reportedip-hive' ); ?></li>
				</ul>
				<div class="rip-flex rip-gap-2 rip-mt-3">
					<?php self::render_tier_lock( $mail_status, array( 'label' => __( 'Unlock with Professional', 'reportedip-hive' ) ) ); ?>
				</div>
			</div>
		</div>
		<?php

		if ( class_exists( 'ReportedIP_Hive_Promo_Manager' ) ) {
			ReportedIP_Hive_Promo_Manager::mark_shown( ReportedIP_Hive_Promo_Manager::KEY_MAIL_SMS_RELAY );
		}
	}

	/**
	 * Render the API call usage card on the dashboard. Renders nothing
	 * when the plugin has never made an API call.
	 *
	 * @return void
	 * @since 1.6.0
	 */
	private function render_api_usage_card() {
		$stats_raw = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_stats', array() );
		if ( ! is_array( $stats_raw ) || empty( $stats_raw['total_calls'] ) ) {
			return;
		}
		$total   = (int) $stats_raw['total_calls'];
		$success = (float) ( $stats_raw['success_rate'] ?? 0 );
		$avg_ms  = (float) ( $stats_raw['avg_response_time'] ?? 0 );

		$snapshot     = ReportedIP_Hive_Mode_Manager::get_instance()->get_api_rate_limit_snapshot();
		$source_label = 'manual' === $snapshot['source']
			? esc_html__( 'manual override', 'reportedip-hive' )
			: sprintf(
				/* translators: %s: tier slug. */
				esc_html__( 'auto · %s tier', 'reportedip-hive' ),
				esc_html( $snapshot['tier'] )
			);

		$bucket_labels = array(
			'reputation' => esc_html__( 'This hour — reputation', 'reportedip-hive' ),
			'submission' => esc_html__( 'This hour — submission', 'reportedip-hive' ),
			'meta'       => esc_html__( 'This hour — meta', 'reportedip-hive' ),
		);
		?>
		<div class="rip-card rip-mb-6">
			<div class="rip-card__header">
				<h2 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
					<?php esc_html_e( 'API call usage', 'reportedip-hive' ); ?>
				</h2>
				<span class="rip-badge rip-badge--neutral"><?php echo $source_label; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pre-escaped above. ?></span>
			</div>
			<div class="rip-card__body">
				<div class="rip-stat-cards">
					<div class="rip-stat-card">
						<div class="rip-stat-card__icon rip-stat-card__icon--info">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
						</div>
						<div class="rip-stat-card__content">
							<div class="rip-stat-card__value"><?php echo esc_html( number_format_i18n( $total ) ); ?></div>
							<div class="rip-stat-card__label"><?php esc_html_e( 'Total API calls', 'reportedip-hive' ); ?></div>
						</div>
					</div>
					<div class="rip-stat-card">
						<div class="rip-stat-card__icon rip-stat-card__icon--success">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
						</div>
						<div class="rip-stat-card__content">
							<div class="rip-stat-card__value"><?php echo esc_html( number_format_i18n( $success ) ); ?>%</div>
							<div class="rip-stat-card__label"><?php esc_html_e( 'Success rate', 'reportedip-hive' ); ?></div>
						</div>
					</div>
					<div class="rip-stat-card">
						<div class="rip-stat-card__icon rip-stat-card__icon--info">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
						</div>
						<div class="rip-stat-card__content">
							<div class="rip-stat-card__value"><?php echo esc_html( number_format_i18n( $avg_ms ) ); ?> ms</div>
							<div class="rip-stat-card__label"><?php esc_html_e( 'Avg response', 'reportedip-hive' ); ?></div>
						</div>
					</div>
					<?php
					foreach ( array( 'reputation', 'submission', 'meta' ) as $bucket ) :
						$used      = (int) ( $snapshot['used'][ $bucket ] ?? 0 );
						$limit     = $snapshot['limits'][ $bucket ] ?? null;
						$limit_lbl = null === $limit ? '∞' : number_format_i18n( (int) $limit );
						$icon      = ( null !== $limit && $limit > 0 && $used >= (int) ceil( $limit * 0.8 ) ) ? 'warning' : 'info';
						?>
						<div class="rip-stat-card">
							<div class="rip-stat-card__icon rip-stat-card__icon--<?php echo esc_attr( $icon ); ?>">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
							</div>
							<div class="rip-stat-card__content">
								<div class="rip-stat-card__value"><?php echo esc_html( number_format_i18n( $used ) . ' / ' . $limit_lbl ); ?></div>
								<div class="rip-stat-card__label"><?php echo esc_html( $bucket_labels[ $bucket ] ); ?></div>
							</div>
						</div>
					<?php endforeach; ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Count how many protection layers are currently switched on.
	 *
	 * Reads the canonical sensor/feature toggles through the option router so the
	 * "N/M layers active" hero KPI reflects the real configuration network-wide.
	 *
	 * @return array{active:int,total:int}
	 * @since  2.1.13
	 */
	private function get_active_protection_layers() {
		$layers = array(
			'reportedip_hive_monitor_failed_logins'    => true,
			'reportedip_hive_monitor_comments'         => true,
			'reportedip_hive_monitor_xmlrpc'           => true,
			'reportedip_hive_monitor_app_passwords'    => true,
			'reportedip_hive_monitor_rest_api'         => true,
			'reportedip_hive_block_user_enumeration'   => true,
			'reportedip_hive_monitor_404_scans'        => true,
			'reportedip_hive_monitor_geo_anomaly'      => true,
			'reportedip_hive_monitor_woocommerce'      => true,
			'reportedip_hive_waf_enabled'              => true,
			'reportedip_hive_monitor_bot_verification' => true,
			'reportedip_hive_comment_honeypot_enabled' => true,
			'reportedip_hive_decoy_pathblock_enabled'  => true,
			'reportedip_hive_auto_block'               => true,
			'reportedip_hive_block_escalation_enabled' => true,
			'reportedip_hive_password_policy_enabled'  => true,
			'reportedip_hive_2fa_enabled_global'       => false,
			'reportedip_hive_hide_login_enabled'       => false,
			'reportedip_hive_headers_enabled'          => false,
			'reportedip_hive_audit_enabled'            => true,
		);

		$active = 0;
		foreach ( $layers as $key => $default ) {
			if ( ReportedIP_Hive_Option_Routing::get( $key, $default ) ) {
				++$active;
			}
		}

		return array(
			'active' => $active,
			'total'  => count( $layers ),
		);
	}

	/**
	 * Render the most active attacker IPs over the last 30 days.
	 *
	 * @param array<int,array{ip:string,count:int,last_seen:string,blocked:bool}> $top_ips Rows from get_threat_analytics().
	 * @return void
	 * @since  2.1.13
	 */
	private function render_top_attackers_table( $top_ips ) {
		?>
		<div class="rip-dashboard__section">
			<div class="rip-dashboard__section-title">
				<h2>
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>
					<?php esc_html_e( 'Top Attackers (30 days)', 'reportedip-hive' ); ?>
				</h2>
				<a href="<?php echo esc_url( self::get_admin_page_url( 'admin.php?page=reportedip-hive-security&tab=blocked' ) ); ?>" class="rip-button rip-button--ghost rip-button--sm">
					<?php esc_html_e( 'Manage Blocks', 'reportedip-hive' ); ?>
				</a>
			</div>

			<div class="rip-card">
				<?php if ( empty( $top_ips ) ) : ?>
					<div class="rip-empty-state rip-empty-state--compact">
						<svg class="rip-empty-state__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
							<path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
						</svg>
						<p class="rip-empty-state__text"><?php esc_html_e( 'No attacker activity recorded in the last 30 days.', 'reportedip-hive' ); ?></p>
					</div>
				<?php else : ?>
					<table class="rip-table">
						<thead>
							<tr>
								<th><?php esc_html_e( 'IP Address', 'reportedip-hive' ); ?></th>
								<th><?php esc_html_e( 'Attacks', 'reportedip-hive' ); ?></th>
								<th><?php esc_html_e( 'Last Seen', 'reportedip-hive' ); ?></th>
								<th><?php esc_html_e( 'Status', 'reportedip-hive' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $top_ips as $row ) : ?>
								<tr>
									<td><code><?php echo esc_html( $row['ip'] ); ?></code></td>
									<td><?php echo esc_html( number_format_i18n( $row['count'] ) ); ?></td>
									<td>
										<?php
										/* translators: %s = human-readable time difference, e.g. "3 hours". */
										echo esc_html( sprintf( __( '%s ago', 'reportedip-hive' ), human_time_diff( strtotime( $row['last_seen'] ), time() ) ) );
										?>
									</td>
									<td>
										<?php if ( $row['blocked'] ) : ?>
											<span class="rip-badge rip-badge--danger"><?php esc_html_e( 'Blocked', 'reportedip-hive' ); ?></span>
										<?php else : ?>
											<span class="rip-badge rip-badge--neutral"><?php esc_html_e( 'Monitored', 'reportedip-hive' ); ?></span>
										<?php endif; ?>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the advanced-analytics upsell card for non-Professional tiers.
	 *
	 * Deliberately understated: a single frequency-capped card that previews the
	 * deeper analytics unlocked by higher plans. Falls silent for Professional
	 * and above, and respects the global promo cap.
	 *
	 * @return void
	 * @since  2.1.13
	 */
	private function render_analytics_pro_card() {
		if ( class_exists( 'ReportedIP_Hive_Promo_Manager' )
			&& ! ReportedIP_Hive_Promo_Manager::can_show( ReportedIP_Hive_Promo_Manager::KEY_ADVANCED_ANALYTICS )
		) {
			return;
		}

		$status = array(
			'available' => false,
			'reason'    => 'tier',
			'min_tier'  => 'professional',
		);
		?>
		<div class="rip-card rip-mb-6 rip-promo-card">
			<div class="rip-card__header">
				<h2 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3v18h18"/><path d="M7 16l4-4 4 4 5-5"/></svg>
					<?php esc_html_e( 'Go deeper with advanced analytics', 'reportedip-hive' ); ?>
				</h2>
			</div>
			<div class="rip-card__body">
				<p><?php esc_html_e( 'Professional and Business plans unlock the full picture behind these charts — longer history, attacker geography and a tamper-evident audit trail.', 'reportedip-hive' ); ?></p>
				<ul class="rip-promo-card__benefits">
					<li><?php esc_html_e( 'Extended history and longer log retention', 'reportedip-hive' ); ?></li>
					<li><?php esc_html_e( 'Priority rulesets — broader WAF signatures and live bot / disposable feeds', 'reportedip-hive' ); ?></li>
					<li><?php esc_html_e( 'Audit event trail with CSV / JSON export (Business)', 'reportedip-hive' ); ?></li>
				</ul>
				<div class="rip-flex rip-gap-2 rip-mt-3">
					<?php self::render_tier_lock( $status, array( 'label' => __( 'Unlock with Professional', 'reportedip-hive' ) ) ); ?>
				</div>
			</div>
		</div>
		<?php

		if ( class_exists( 'ReportedIP_Hive_Promo_Manager' ) ) {
			ReportedIP_Hive_Promo_Manager::mark_shown( ReportedIP_Hive_Promo_Manager::KEY_ADVANCED_ANALYTICS );
		}
	}

	private function render_relay_quota_section( $mode_manager ) {
		$snapshot = $mode_manager->get_relay_quota_snapshot();
		$tier     = $mode_manager->get_tier_info( $snapshot['tier'] );

		$mail_used   = (int) $snapshot['mail']['used'];
		$mail_limit  = $snapshot['mail']['limit'];
		$mail_bundle = (int) $snapshot['mail_bundle_balance'];
		$sms_used    = (int) $snapshot['sms']['used'];
		$sms_limit   = $snapshot['sms']['limit'];
		$sms_bundle  = (int) $snapshot['sms_bundle_balance'];
		$reset_label = $snapshot['period_end']
			? date_i18n( get_option( 'date_format' ), (int) $snapshot['period_end'] )
			: __( 'next billing cycle', 'reportedip-hive' );
		?>
		<div class="rip-settings-section rip-relay-quota">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 8v4l3 3M3 12a9 9 0 1018 0 9 9 0 00-18 0z"/></svg>
				<?php esc_html_e( 'Relay Quota', 'reportedip-hive' ); ?>
				<?php self::render_tier_badge( $snapshot['tier'] ); ?>
			</h2>
			<p class="rip-settings-section__desc">
				<?php
				printf(
					/* translators: 1: tier short label (e.g. PRO), 2: human-readable reset date */
					esc_html__( 'Your %1$s plan includes managed mail and SMS delivery via reportedip.de. Counters reset on %2$s.', 'reportedip-hive' ),
					esc_html( $tier['short_label'] ),
					esc_html( $reset_label )
				);
				?>
			</p>

			<div class="rip-stat-cards">
				<?php $this->render_quota_card( 'mail', $mail_used, $mail_limit, $reset_label, $snapshot['is_stale'], $mail_bundle ); ?>
				<?php $this->render_quota_card( 'sms', $sms_used, $sms_limit, $reset_label, $snapshot['is_stale'], $sms_bundle ); ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render a single relay quota stat card with progress bar.
	 *
	 * @param string   $type        'mail' or 'sms'.
	 * @param int      $used        Number consumed in current period.
	 * @param int|null $limit       Period limit (null = unlimited).
	 * @param string   $reset_label Human-readable reset date.
	 * @param bool     $is_stale    Whether the snapshot is older than 24h.
	 * @param int      $bundle      Prepaid bundle balance for this type. Signed: a
	 *                              negative value means a Stripe refund clawed credits
	 *                              back below zero — sending stays blocked until a new
	 *                              bundle is purchased (PRICING-PLAN.md §3d).
	 * @return void
	 * @since 1.5.3
	 */
	private function render_quota_card( $type, $used, $limit, $reset_label, $is_stale, $bundle = 0 ) {
		$is_mail   = ( 'mail' === $type );
		$label     = $is_mail ? __( 'Mail relay', 'reportedip-hive' ) : __( 'SMS relay', 'reportedip-hive' );
		$icon      = $is_mail
			? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>'
			: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>';
		$icon_kind = $is_mail ? 'rip-stat-card__icon--info' : 'rip-stat-card__icon--primary';

		$pct = 0;
		if ( null !== $limit && $limit > 0 ) {
			$pct = (int) min( 100, round( $used / $limit * 100 ) );
		}

		$progress_class = '';
		if ( $pct >= 90 ) {
			$progress_class = 'rip-stat-card__progress--crit';
		} elseif ( $pct >= 70 ) {
			$progress_class = 'rip-stat-card__progress--warn';
		}

		$value_text = (string) $used;
		$limit_text = ( null === $limit )
			? __( 'unlimited', 'reportedip-hive' )
			: sprintf( '/ %s', number_format_i18n( (int) $limit ) );

		$bundle_unit_singular = $is_mail
			? __( 'Mail credit', 'reportedip-hive' )
			: __( 'SMS credit', 'reportedip-hive' );
		$bundle_unit_plural   = $is_mail
			? __( 'Mail credits', 'reportedip-hive' )
			: __( 'SMS credits', 'reportedip-hive' );
		$bundle_unit          = ( 1 === abs( (int) $bundle ) ) ? $bundle_unit_singular : $bundle_unit_plural;
		?>
		<div class="rip-stat-card rip-stat-card--quota">
			<div class="rip-stat-card__head">
				<div class="rip-stat-card__icon <?php echo esc_attr( $icon_kind ); ?>">
					<?php echo self::kses_inline_svg( $icon ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- kses_inline_svg() applies wp_kses internally; the SVG is whitelisted by the helper. ?>
				</div>
				<div class="rip-stat-card__content">
					<div class="rip-stat-card__value">
						<?php echo esc_html( $value_text ); ?>
						<span class="rip-stat-card__value-limit"><?php echo esc_html( $limit_text ); ?></span>
					</div>
					<div class="rip-stat-card__label"><?php echo esc_html( $label ); ?></div>
				</div>
			</div>

			<?php if ( null !== $limit && $limit > 0 ) : ?>
				<div class="rip-stat-card__progress <?php echo esc_attr( $progress_class ); ?>" style="--quota-pct: <?php echo (int) $pct; ?>;">
					<div class="rip-stat-card__progress-bar"></div>
				</div>
			<?php endif; ?>

			<?php if ( $bundle > 0 ) : ?>
				<div class="rip-stat-card__hint rip-stat-card__hint--bundle">
					<?php
					printf(
						/* translators: 1: bundle balance count, 2: unit (Mail credits / SMS credits) */
						esc_html__( '+ %1$s %2$s in your bundle balance', 'reportedip-hive' ),
						esc_html( number_format_i18n( (int) $bundle ) ),
						esc_html( $bundle_unit )
					);
					?>
				</div>
			<?php elseif ( $bundle < 0 ) : ?>
				<div class="rip-stat-card__hint rip-stat-card__hint--bundle-negative">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
					<?php
					printf(
						/* translators: 1: negative balance (already includes the minus sign), 2: unit (Mail credits / SMS credits) */
						esc_html__( 'Bundle balance is %1$s %2$s after refund — purchase a new bundle to resume sending once the inclusive quota is exhausted.', 'reportedip-hive' ),
						esc_html( number_format_i18n( (int) $bundle ) ),
						esc_html( $bundle_unit )
					);
					?>
				</div>
			<?php endif; ?>

			<div class="rip-stat-card__hint">
				<?php
				printf(
					/* translators: %s = next reset date */
					esc_html__( 'Resets on %s', 'reportedip-hive' ),
					esc_html( $reset_label )
				);
				?>
			</div>

			<?php if ( $is_stale ) : ?>
				<div class="rip-stat-card__hint rip-stat-card__hint--stale">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
					<?php esc_html_e( 'Awaiting fresh quota data — refreshes every 6 hours.', 'reportedip-hive' ); ?>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Render unified page footer with trust badges
	 */
	public static function render_page_footer() {
		?>
			<div class="rip-trust-badges">
				<div class="rip-trust-badge">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
					<?php esc_html_e( 'Security Focused', 'reportedip-hive' ); ?>
				</div>
				<div class="rip-trust-badge">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
					<?php esc_html_e( 'GDPR Compliant', 'reportedip-hive' ); ?>
				</div>
				<div class="rip-trust-badge">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
					<?php esc_html_e( 'Made in Germany', 'reportedip-hive' ); ?>
				</div>
			</div>
		</div><!-- /.wrap.rip-wrap -->
		<?php
	}

	/**
	 * Render the post-tier-upgrade welcome banner on every Hive admin page.
	 *
	 * Hooked on `admin_notices`. Visible only on screens whose id contains
	 * `reportedip-hive` and only while {@see ReportedIP_Hive_Tier_Upgrade::should_show_notice()}
	 * returns true. Shows a three-step checklist plus a dismiss button.
	 */
	public function render_tier_upgrade_banner() {
		if ( ! class_exists( 'ReportedIP_Hive_Tier_Upgrade' ) ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || strpos( (string) $screen->id, 'reportedip-hive' ) === false ) {
			return;
		}
		if ( ! ReportedIP_Hive_Tier_Upgrade::should_show_notice() ) {
			return;
		}
		$notice = ReportedIP_Hive_Tier_Upgrade::get_notice();
		if ( ! $notice ) {
			return;
		}

		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$tier_info    = $mode_manager->get_tier_info( (string) $notice['to'] );
		$tier_label   = '' !== (string) $tier_info['label']
			? (string) $tier_info['label']
			: __( 'paid', 'reportedip-hive' );

		$two_factor_url = self::get_admin_page_url( 'admin.php?page=reportedip-hive-settings&tab=two_factor' );
		$checklist      = ReportedIP_Hive_Tier_Upgrade::get_setup_checklist();

		$title = sprintf(
			/* translators: %s = tier label, e.g. Professional */
			__( 'Your %s plan is active — finish 2FA setup', 'reportedip-hive' ),
			$tier_label
		);

		ReportedIP_Hive_Admin_Notice::render(
			array(
				'variant'           => 'info',
				'extra_classes'     => 'rip-tier-upgrade-banner',
				'title'             => $title,
				'body'              => __( 'Two-factor authentication via the managed reportedip.de relay is now included with your plan. SMS is ready to use — enable it as a method to roll it out:', 'reportedip-hive' ),
				'checklist'         => $checklist,
				'primary_action'    => array(
					'label' => __( 'Open 2FA settings', 'reportedip-hive' ),
					'url'   => $two_factor_url,
				),
				'secondary_actions' => array(
					array(
						'type'        => 'form',
						'label'       => __( 'Dismiss', 'reportedip-hive' ),
						'form_action' => 'reportedip_hive_dismiss_tier_notice',
						'nonce'       => 'reportedip_hive_dismiss_tier_notice',
					),
				),
			)
		);
	}

	/**
	 * Render a status notice when the Mail or SMS relay has hit its cap and
	 * is silently in fallback (mail → wp_mail) or paused (SMS → other 2FA
	 * method).
	 *
	 * This is operational information, not a promo — it does NOT participate
	 * in {@see ReportedIP_Hive_Promo_Manager}'s frequency cap. The notice
	 * stays visible until either the underlying transient expires (relay
	 * accepts again) or the operator dismisses it for the configured cooldown.
	 *
	 * Hook: `admin_notices` priority 5 so it sits at the top of the page,
	 * above the standard-priority Hive banners.
	 *
	 * @return void
	 * @since  2.0.16
	 */
	public function render_cap_status_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			return;
		}

		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen ) {
			return;
		}
		$screen_id = (string) $screen->id;
		if ( false === strpos( $screen_id, 'reportedip-hive' ) && 'dashboard' !== $screen_id ) {
			return;
		}

		$mail_state = ReportedIP_Hive_Mode_Manager::get_cap_state( 'mail' );
		$sms_state  = ReportedIP_Hive_Mode_Manager::get_cap_state( 'sms' );
		if ( ! $mail_state && ! $sms_state ) {
			return;
		}

		$user_id         = (int) get_current_user_id();
		$dismissed_until = (int) get_user_meta( $user_id, 'reportedip_hive_cap_notice_dismissed_until', true );
		if ( $dismissed_until > 0 && $dismissed_until > time() ) {
			return;
		}

		$lines = array();
		if ( $mail_state ) {
			$lines[] = self::format_cap_state_line(
				__( 'Mail relay', 'reportedip-hive' ),
				$mail_state,
				__( 'Mails are temporarily routed through your local wp_mail() until the relay accepts again.', 'reportedip-hive' )
			);
		}
		if ( $sms_state ) {
			$lines[] = self::format_cap_state_line(
				__( 'SMS relay', 'reportedip-hive' ),
				$sms_state,
				__( 'SMS-based 2FA codes are paused until the relay accepts again — users can still choose TOTP, Email or Passkey.', 'reportedip-hive' )
			);
		}

		$dashboard_url   = self::get_admin_page_url( 'admin.php?page=reportedip-hive-community' );
		$cap_dismiss_url = wp_nonce_url(
			self::get_admin_page_url( 'admin-post.php?action=reportedip_hive_cap_notice_dismiss' ),
			'reportedip_hive_cap_notice_dismiss'
		);
		ReportedIP_Hive_Admin_Notice::render(
			array(
				'variant'           => 'warning',
				'extra_classes'     => 'rip-cap-status-notice',
				'title'             => __( 'Managed relay capacity reached', 'reportedip-hive' ),
				'list_items'        => $lines,
				'primary_action'    => array(
					'label'   => __( 'View quota details', 'reportedip-hive' ),
					'url'     => $dashboard_url,
					'variant' => 'secondary',
				),
				'secondary_actions' => array(
					array(
						'type'  => 'link',
						'label' => __( 'Hide for 24 hours', 'reportedip-hive' ),
						'url'   => $cap_dismiss_url,
					),
				),
			)
		);
	}

	/**
	 * Format one line of the cap-status notice for a single channel.
	 *
	 * @param string $channel_label Localised channel label.
	 * @param array  $state         Output of {@see ReportedIP_Hive_Mode_Manager::get_cap_state()}.
	 * @param string $fallback_hint Localised hint about the fallback behaviour.
	 * @return string Sentence ready for {@see wp_kses_post()}.
	 */
	private static function format_cap_state_line( $channel_label, array $state, $fallback_hint ) {
		$hit_at  = (int) ( $state['hit_at'] ?? 0 );
		$retry   = (int) ( $state['retry_after'] ?? 0 );
		$resumes = $retry > 0 ? ( $hit_at > 0 ? $hit_at + $retry : time() + $retry ) : 0;

		$when = '';
		if ( $resumes > 0 ) {
			$when = ' ' . sprintf(
				/* translators: %s = human-readable time difference (e.g. "in 4 hours"). */
				esc_html__( 'Relay accepts again %s.', 'reportedip-hive' ),
				esc_html( human_time_diff( time(), $resumes ) )
			);
		}

		return sprintf(
			'<strong>%s:</strong> %s%s',
			esc_html( $channel_label ),
			esc_html( $fallback_hint ),
			$when
		);
	}

	/**
	 * `admin-post.php?action=reportedip_hive_cap_notice_dismiss` handler.
	 *
	 * Hides the cap-status notice for 24 hours on the current user. The
	 * underlying transient is untouched — when it expires naturally the
	 * notice can return, which is intentional (it is operational information
	 * that the relay is still in fallback).
	 *
	 * @return void
	 * @since  2.0.16
	 */
	public function handle_cap_notice_dismiss() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'reportedip_hive_cap_notice_dismiss' );

		$user_id = (int) get_current_user_id();
		if ( $user_id > 0 ) {
			update_user_meta(
				$user_id,
				'reportedip_hive_cap_notice_dismissed_until',
				time() + DAY_IN_SECONDS
			);
		}

		$redirect = wp_get_referer();
		if ( ! $redirect ) {
			$redirect = self::get_admin_page_url( '' );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * `admin-post.php?action=reportedip_hive_audit_export` handler.
	 *
	 * Streams the audit log as CSV or JSON. Business+ only; on Multisite a site
	 * administrator exports only their own blog's rows.
	 *
	 * @return void
	 * @since  2.1.2
	 */
	public function handle_audit_export() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'reportedip_hive_audit_export' );

		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'audit_log' );
		if ( empty( $status['available'] ) ) {
			wp_die( esc_html__( 'The audit log is not available on your plan.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Verified by check_admin_referer() above.
		$format = ( isset( $_GET['format'] ) && 'json' === sanitize_key( wp_unslash( $_GET['format'] ) ) ) ? 'json' : 'csv';

		global $wpdb;
		$table = $wpdb->base_prefix . ReportedIP_Hive_Audit_Logger::TABLE;
		$cols  = 'created_at, ip, user_id, username, event_type, event_action, event_data, country_code';
		if ( is_multisite() && ! is_network_admin() ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Table name from base_prefix; column list literal; blog id bound.
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT $cols FROM $table WHERE blog_id = %d ORDER BY created_at DESC LIMIT 10000", get_current_blog_id() ), ARRAY_A );
		} else {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Table name from base_prefix; column list literal.
			$rows = $wpdb->get_results( "SELECT $cols FROM $table ORDER BY created_at DESC LIMIT 10000", ARRAY_A );
		}
		$rows = (array) $rows;

		nocache_headers();
		if ( 'json' === $format ) {
			header( 'Content-Type: application/json; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="reportedip-hive-audit-' . gmdate( 'Y-m-d' ) . '.json"' );
			echo wp_json_encode( $rows, JSON_PRETTY_PRINT );
			exit;
		}

		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="reportedip-hive-audit-' . gmdate( 'Y-m-d' ) . '.csv"' );
		$output = fopen( 'php://output', 'w' );
		fputcsv( $output, array( 'created_at', 'ip', 'user_id', 'username', 'event_type', 'event_action', 'event_data', 'country_code' ) );
		foreach ( $rows as $row ) {
			fputcsv( $output, $row );
		}
		fclose( $output ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- php://output stream
		exit;
	}

	/**
	 * Render inline notices within plugin pages (replaces admin_notices)
	 */
	public static function render_inline_notices() {
		global $wpdb;

		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		if ( $mode_manager->is_community_layer_degraded() ) {
			$upgrade_url = self::get_admin_page_url( 'admin.php?page=reportedip-hive-community' );
			$body        = sprintf(
				'<strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a>',
				esc_html__( 'Community threat-check rate-limited.', 'reportedip-hive' ),
				esc_html__( 'The local firewall (sensors, blocks, logs, queue) remains fully active. Reputation lookups for new IPs and outgoing report submissions are paused until the hourly counter resets.', 'reportedip-hive' ),
				esc_url( $upgrade_url ),
				esc_html__( 'Upgrade tier for higher caps.', 'reportedip-hive' )
			);
			ReportedIP_Hive_Admin_Notice::render(
				array(
					'variant' => 'warning',
					'body'    => $body,
				)
			);
		}

		$table = $wpdb->prefix . 'reportedip_hive_api_queue';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Safe table name composed from $wpdb->prefix and a hardcoded suffix.
		$table_exists = $wpdb->get_var( "SHOW TABLES LIKE '$table'" ) === $table;

		if ( ! $table_exists ) {
			return;
		}

		// phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name built from $wpdb->prefix and a hardcoded constant; safe.
		$counts = $wpdb->get_row(
			"SELECT
				SUM( CASE WHEN status = 'failed' THEN 1 ELSE 0 END ) AS failed_count,
				SUM( CASE WHEN status = 'pending' THEN 1 ELSE 0 END ) AS pending_count
			FROM $table"
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$failed_count  = (int) ( $counts->failed_count ?? 0 );
		$pending_count = (int) ( $counts->pending_count ?? 0 );

		if ( $failed_count > 0 ) {
			$queue_url = self::get_admin_page_url( 'admin.php?page=reportedip-hive-security&tab=api_queue' );
			$body      = sprintf(
				'<strong>%1$s</strong> %2$s',
				esc_html__( 'ReportedIP Hive:', 'reportedip-hive' ),
				sprintf(
					/* translators: %1$d: number of failed reports, %2$s: link to queue page */
					esc_html__( '%1$d API reports failed. %2$s', 'reportedip-hive' ),
					intval( $failed_count ),
					'<a href="' . esc_url( $queue_url ) . '">' . esc_html__( 'View queue', 'reportedip-hive' ) . '</a>'
				)
			);
			ReportedIP_Hive_Admin_Notice::render(
				array(
					'variant'           => 'error',
					'body'              => $body,
					'secondary_actions' => array(
						array(
							'type'    => 'button',
							'label'   => __( 'Retry all', 'reportedip-hive' ),
							'class'   => 'rip-retry-all-failed',
							'variant' => 'secondary',
						),
					),
				)
			);
		}

		$warning_threshold  = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_queue_warning_threshold', 50 );
		$critical_threshold = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_queue_critical_threshold', 200 );

		if ( $pending_count >= $critical_threshold ) {
			$queue_url     = self::get_admin_page_url( 'admin.php?page=reportedip-hive-security&tab=api_queue' );
			$community_url = self::get_admin_page_url( 'admin.php?page=reportedip-hive-community' );
			$body          = sprintf(
				'<strong>%1$s</strong> %2$s',
				esc_html__( 'Queue Critical:', 'reportedip-hive' ),
				sprintf(
					/* translators: 1: pending count, 2: upgrade link, 3: queue link */
					esc_html__( '%1$d reports pending processing. %2$s or %3$s.', 'reportedip-hive' ),
					intval( $pending_count ),
					'<a href="' . esc_url( $community_url ) . '">' . esc_html__( 'Upgrade API tier', 'reportedip-hive' ) . '</a>',
					'<a href="' . esc_url( $queue_url ) . '">' . esc_html__( 'Manage queue', 'reportedip-hive' ) . '</a>'
				)
			);
			ReportedIP_Hive_Admin_Notice::render(
				array(
					'variant' => 'error',
					'body'    => $body,
				)
			);
		} elseif ( $pending_count >= $warning_threshold ) {
			$community_url = self::get_admin_page_url( 'admin.php?page=reportedip-hive-community' );
			$body          = sprintf(
				'<strong>%1$s</strong> %2$s',
				esc_html__( 'ReportedIP Hive:', 'reportedip-hive' ),
				sprintf(
					/* translators: 1: pending count, 2: upgrade link */
					esc_html__( '%1$d reports pending processing. %2$s for higher limits.', 'reportedip-hive' ),
					intval( $pending_count ),
					'<a href="' . esc_url( $community_url ) . '">' . esc_html__( 'Upgrade API tier', 'reportedip-hive' ) . '</a>'
				)
			);
			ReportedIP_Hive_Admin_Notice::render(
				array(
					'variant' => 'warning',
					'body'    => $body,
				)
			);
		}
	}

	/**
	 * Per-site admin menu entry point.
	 *
	 * Multisite: registers a read-only menu (Status, own-site Logs, 2FA Site
	 * Settings — the only writable section).
	 * Single-site: registers the full admin menu, identical to v1.x.
	 *
	 * @since 1.0.0
	 */
	public function add_admin_menu() {
		if ( is_multisite() ) {
			$this->register_site_readonly_menu();
			return;
		}
		$this->register_full_menu( 'manage_options' );
	}

	/**
	 * Network admin menu entry point.
	 *
	 * Mounts the full settings UI under the network admin with the
	 * `manage_network_options` capability — Multisite Super Admins manage
	 * the whole network's protection in one place.
	 *
	 * @since 2.0.0
	 */
	public function add_network_admin_menu() {
		$this->register_full_menu( 'manage_network_options' );
	}

	/**
	 * Registers the full admin menu (dashboard, security, settings,
	 * system status, community) under the given capability. Shared
	 * between single-site `admin_menu` and multisite `network_admin_menu`.
	 *
	 * @param string $cap Capability gating every menu item.
	 * @since 1.0.0
	 */
	private function register_full_menu( $cap ) {
		add_menu_page(
			__( 'ReportedIP Hive', 'reportedip-hive' ),
			__( 'ReportedIP Hive', 'reportedip-hive' ),
			$cap,
			'reportedip-hive',
			array( $this, 'dashboard_page' ),
			'dashicons-shield-alt',
			30
		);

		add_submenu_page(
			'reportedip-hive',
			__( 'Dashboard', 'reportedip-hive' ),
			__( 'Dashboard', 'reportedip-hive' ),
			$cap,
			'reportedip-hive',
			array( $this, 'dashboard_page' )
		);

		add_submenu_page(
			'reportedip-hive',
			__( 'Security', 'reportedip-hive' ),
			__( 'Security', 'reportedip-hive' ),
			$cap,
			'reportedip-hive-security',
			array( $this, 'security_page' )
		);

		add_submenu_page(
			'reportedip-hive',
			__( 'Firewall', 'reportedip-hive' ),
			__( 'Firewall', 'reportedip-hive' ),
			$cap,
			'reportedip-hive-firewall',
			array( ReportedIP_Hive_Admin_Firewall::get_instance(), 'firewall_page' )
		);

		add_submenu_page(
			'reportedip-hive',
			__( 'Settings', 'reportedip-hive' ),
			__( 'Settings', 'reportedip-hive' ),
			$cap,
			'reportedip-hive-settings',
			array( $this, 'settings_page' )
		);

		add_submenu_page(
			'reportedip-hive',
			__( 'System Status', 'reportedip-hive' ),
			__( 'System Status', 'reportedip-hive' ),
			$cap,
			'reportedip-hive-debug',
			array( $this, 'debug_page' )
		);

		add_submenu_page(
			'reportedip-hive',
			__( 'Community & Quota', 'reportedip-hive' ),
			__( 'Community', 'reportedip-hive' ),
			$cap,
			'reportedip-hive-community',
			array( $this, 'community_page' )
		);
	}

	/**
	 * Render the Audit sub-tab inside the Security page — user-lifecycle audit
	 * trail. Business+ tier-locked scaffold; the event trail lands in a later
	 * phase.
	 *
	 * @since 2.1.2
	 * @return void
	 */
	private function render_audit_tab() {
		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'audit_log' );
		if ( empty( $status['available'] ) ) {
			self::render_tier_marker( $status );
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'The user-lifecycle audit trail — logins, role changes with the actor, new-IP alerts — unlocks with Business. Your standard security events stay available in the Event Log.', 'reportedip-hive' ) . '</div>';
			return;
		}

		if ( ! class_exists( 'ReportedIP_Hive_Audit_Log_Table' ) ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-audit-log-table.php';
		}
		$table = new ReportedIP_Hive_Audit_Log_Table();
		$table->prepare_items();

		$csv_url  = wp_nonce_url( admin_url( 'admin-post.php?action=reportedip_hive_audit_export&format=csv' ), 'reportedip_hive_audit_export' );
		$json_url = wp_nonce_url( admin_url( 'admin-post.php?action=reportedip_hive_audit_export&format=json' ), 'reportedip_hive_audit_export' );
		echo '<p>';
		printf(
			'<a class="rip-button rip-button--secondary" href="%s">%s</a> <a class="rip-button rip-button--secondary" href="%s">%s</a> ',
			esc_url( $csv_url ),
			esc_html__( 'Export CSV', 'reportedip-hive' ),
			esc_url( $json_url ),
			esc_html__( 'Export JSON', 'reportedip-hive' )
		);
		self::render_tier_marker( $status );
		echo '</p>';

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only page slug echoed back into the filter form.
		$page = isset( $_REQUEST['page'] ) ? sanitize_key( wp_unslash( $_REQUEST['page'] ) ) : 'reportedip-hive-security';
		echo '<form method="get">';
		printf( '<input type="hidden" name="page" value="%s" />', esc_attr( $page ) );
		echo '<input type="hidden" name="tab" value="activity" /><input type="hidden" name="sub" value="audit" />';
		$table->display();
		echo '</form>';
	}

	/**
	 * Site Admin menu on Multisite — read-only with two writable overrides.
	 *
	 * The Site Admin gets a status page (read-only summary), a logs view
	 * automatically scoped to the current `blog_id`, and a "Site Settings"
	 * page where they can override the WooCommerce Frontend-2FA slug and
	 * extend the 2FA enforcement role list (additive only — they cannot
	 * remove network-required roles).
	 *
	 * @since 2.0.0
	 */
	private function register_site_readonly_menu() {
		add_menu_page(
			__( 'ReportedIP Hive', 'reportedip-hive' ),
			__( 'ReportedIP Hive', 'reportedip-hive' ),
			'manage_options',
			'reportedip-hive-site',
			array( $this, 'render_site_status_page' ),
			'dashicons-shield-alt',
			30
		);

		add_submenu_page(
			'reportedip-hive-site',
			__( 'Status', 'reportedip-hive' ),
			__( 'Status', 'reportedip-hive' ),
			'manage_options',
			'reportedip-hive-site',
			array( $this, 'render_site_status_page' )
		);

		add_submenu_page(
			'reportedip-hive-site',
			__( 'Logs (this site)', 'reportedip-hive' ),
			__( 'Logs', 'reportedip-hive' ),
			'manage_options',
			'reportedip-hive-site-logs',
			array( $this, 'render_site_logs_page' )
		);

		add_submenu_page(
			'reportedip-hive-site',
			__( '2FA Site Settings', 'reportedip-hive' ),
			__( '2FA Site Settings', 'reportedip-hive' ),
			'manage_options',
			'reportedip-hive-site-2fa',
			array( $this, 'render_site_2fa_settings_page' )
		);
	}

	/**
	 * Site-Admin Status page — read-only with per-site stat cards.
	 *
	 * @since 2.0.0
	 */
	public function render_site_status_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'reportedip-hive' ) );
		}

		$stats = $this->get_site_admin_stats();

		$this->render_site_admin_header(
			__( 'ReportedIP Hive', 'reportedip-hive' ),
			__( 'Site security overview', 'reportedip-hive' )
		);
		$this->render_site_readonly_banner();
		?>
		<div class="rip-content">
			<div class="rip-stat-cards">
				<div class="rip-stat-card">
					<div class="rip-stat-card__icon rip-stat-card__icon--info">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
					</div>
					<div class="rip-stat-card__content">
						<div class="rip-stat-card__value"><?php echo esc_html( number_format_i18n( $stats['events_24h'] ) ); ?></div>
						<div class="rip-stat-card__label"><?php esc_html_e( 'Events (24h)', 'reportedip-hive' ); ?></div>
					</div>
				</div>
				<div class="rip-stat-card">
					<div class="rip-stat-card__icon rip-stat-card__icon--warning">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/></svg>
					</div>
					<div class="rip-stat-card__content">
						<div class="rip-stat-card__value"><?php echo esc_html( number_format_i18n( $stats['failed_logins_24h'] ) ); ?></div>
						<div class="rip-stat-card__label"><?php esc_html_e( 'Failed logins (24h)', 'reportedip-hive' ); ?></div>
					</div>
				</div>
				<div class="rip-stat-card">
					<div class="rip-stat-card__icon rip-stat-card__icon--danger">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M4.93 4.93l14.14 14.14"/></svg>
					</div>
					<div class="rip-stat-card__content">
						<div class="rip-stat-card__value"><?php echo esc_html( number_format_i18n( $stats['blocked_active'] ) ); ?></div>
						<div class="rip-stat-card__label"><?php esc_html_e( 'Active IP blocks (network-wide)', 'reportedip-hive' ); ?></div>
					</div>
				</div>
				<div class="rip-stat-card">
					<div class="rip-stat-card__icon rip-stat-card__icon--success">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>
					</div>
					<div class="rip-stat-card__content">
						<div class="rip-stat-card__value"><?php echo esc_html( number_format_i18n( $stats['whitelisted'] ) ); ?></div>
						<div class="rip-stat-card__label"><?php esc_html_e( 'Whitelisted IPs (network-wide)', 'reportedip-hive' ); ?></div>
					</div>
				</div>
			</div>

			<div class="rip-card">
				<h2 class="rip-card__title"><?php esc_html_e( 'Recent activity on this site', 'reportedip-hive' ); ?></h2>
				<?php if ( empty( $stats['recent_events'] ) ) : ?>
					<div class="rip-empty-state">
						<p><?php esc_html_e( 'No events recorded yet.', 'reportedip-hive' ); ?></p>
					</div>
				<?php else : ?>
					<table class="rip-table widefat striped">
						<thead><tr>
							<th><?php esc_html_e( 'When', 'reportedip-hive' ); ?></th>
							<th><?php esc_html_e( 'Event', 'reportedip-hive' ); ?></th>
							<th><?php esc_html_e( 'IP', 'reportedip-hive' ); ?></th>
							<th><?php esc_html_e( 'Severity', 'reportedip-hive' ); ?></th>
						</tr></thead>
						<tbody>
						<?php foreach ( $stats['recent_events'] as $row ) : ?>
							<tr>
								<td><?php echo esc_html( (string) $row->created_at ); ?></td>
								<td><?php echo esc_html( (string) $row->event_type ); ?></td>
								<td><code><?php echo esc_html( (string) $row->ip_address ); ?></code></td>
								<td><span class="rip-badge rip-badge--<?php echo esc_attr( $this->severity_badge_class( (string) $row->severity ) ); ?>"><?php echo esc_html( (string) $row->severity ); ?></span></td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
				<p>
					<a class="rip-button rip-button--secondary" href="<?php echo esc_url( self::get_admin_page_url( 'admin.php?page=reportedip-hive-site-logs' ) ); ?>"><?php esc_html_e( 'View all logs for this site', 'reportedip-hive' ); ?></a>
				</p>
			</div>
		</div>
		<?php
		$this->render_site_admin_footer();
	}

	/**
	 * Site-Admin Logs page — auto-scoped to the current blog_id.
	 *
	 * @since 2.0.0
	 */
	public function render_site_logs_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'reportedip-hive' ) );
		}

		global $wpdb;
		$table   = ReportedIP_Hive_Schema::table( ReportedIP_Hive_Schema::TABLE_LOGS );
		$blog_id = (int) get_current_blog_id();
		// phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is a constant table name from Schema::table(); admin-only paginated read with no caching value.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, event_type, ip_address, severity, created_at
				 FROM $table
				 WHERE blog_id = %d
				 ORDER BY created_at DESC
				 LIMIT 100",
				$blog_id
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		$this->render_site_admin_header(
			__( 'Security Logs', 'reportedip-hive' ),
			__( 'Showing security events recorded for this site only', 'reportedip-hive' )
		);
		$this->render_site_readonly_banner();
		?>
		<div class="rip-content">
			<div class="rip-card">
				<?php if ( empty( $rows ) ) : ?>
					<div class="rip-empty-state">
						<p><?php esc_html_e( 'No events recorded yet.', 'reportedip-hive' ); ?></p>
					</div>
				<?php else : ?>
					<table class="rip-table widefat striped">
						<thead><tr>
							<th><?php esc_html_e( 'When', 'reportedip-hive' ); ?></th>
							<th><?php esc_html_e( 'Event', 'reportedip-hive' ); ?></th>
							<th><?php esc_html_e( 'IP', 'reportedip-hive' ); ?></th>
							<th><?php esc_html_e( 'Severity', 'reportedip-hive' ); ?></th>
						</tr></thead>
						<tbody>
						<?php foreach ( $rows as $row ) : ?>
							<tr>
								<td><?php echo esc_html( (string) $row->created_at ); ?></td>
								<td><?php echo esc_html( (string) $row->event_type ); ?></td>
								<td><code><?php echo esc_html( (string) $row->ip_address ); ?></code></td>
								<td><span class="rip-badge rip-badge--<?php echo esc_attr( $this->severity_badge_class( (string) $row->severity ) ); ?>"><?php echo esc_html( (string) $row->severity ); ?></span></td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			</div>
		</div>
		<?php
		$this->render_site_admin_footer();
	}

	/**
	 * Site-Admin 2FA Site Settings page — the only writable section.
	 *
	 * Two fields:
	 *   - reportedip_hive_2fa_frontend_slug_site_override (URL-safe slug)
	 *   - reportedip_hive_2fa_enforce_roles_extra (additive role list)
	 *
	 * @since 2.0.0
	 */
	public function render_site_2fa_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'reportedip-hive' ) );
		}

		$saved = $this->maybe_handle_site_2fa_save();

		$slug_default        = (string) get_site_option( 'reportedip_hive_2fa_frontend_slug', ReportedIP_Hive_Option_Routing::DEFAULT_FRONTEND_SLUG );
		$slug_override       = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_frontend_slug_site_override', '' );
		$setup_slug_default  = (string) get_site_option( 'reportedip_hive_2fa_frontend_setup_slug', 'reportedip-hive-2fa-setup' );
		$setup_slug_override = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_frontend_setup_slug_site_override', '' );

		$network_roles = ReportedIP_Hive_Option_Routing::get_network_enforce_roles();
		$site_extra    = ReportedIP_Hive_Option_Routing::get_site_enforce_roles_extra();
		$all_roles     = function_exists( 'wp_roles' ) ? wp_roles()->get_names() : array();

		$has_wc        = class_exists( 'WooCommerce' );
		$home_prefix   = trailingslashit( home_url( '/' ) );
		$challenge_url = $home_prefix . sanitize_title( '' !== $slug_override ? $slug_override : $slug_default ) . '/';
		$setup_url     = $home_prefix . sanitize_title( '' !== $setup_slug_override ? $setup_slug_override : $setup_slug_default ) . '/';

		$frontend_status         = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'frontend_2fa' );
		$frontend_locked         = empty( $frontend_status['available'] );
		$frontend_locked_by_tier = $frontend_locked && 'tier' === $frontend_status['reason'];
		$frontend_enabled        = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_frontend_enabled', false );
		$customer_optional       = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_frontend_customer_optional', true );

		$this->render_site_admin_header(
			__( '2FA Site Settings', 'reportedip-hive' ),
			__( 'Per-site overrides for the WooCommerce-style frontend 2FA flow', 'reportedip-hive' )
		);
		$this->render_site_readonly_banner();
		?>
		<div class="rip-content">
			<?php if ( $saved ) : ?>
				<div class="rip-alert rip-alert--success rip-alert--banner"><strong><?php esc_html_e( 'Saved.', 'reportedip-hive' ); ?></strong> <?php esc_html_e( 'Site overrides updated.', 'reportedip-hive' ); ?></div>
			<?php endif; ?>

			<form method="post">
				<?php wp_nonce_field( 'reportedip_hive_site_2fa_save', '_rip_site_2fa_nonce' ); ?>

				<div class="rip-settings-section <?php echo $frontend_locked ? 'rip-settings-section--locked' : ''; ?>">
					<h2 class="rip-settings-section__title">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
						<?php esc_html_e( 'Frontend login for WooCommerce', 'reportedip-hive' ); ?>
						&nbsp;<?php self::render_tier_marker( $frontend_status ); ?>
					</h2>
					<p class="rip-settings-section__desc">
						<?php esc_html_e( 'Renders the second factor inside the active storefront theme when customers sign in via My Account, classic checkout or the WooCommerce blocks — instead of bouncing them to wp-login.php.', 'reportedip-hive' ); ?>
					</p>

					<?php self::render_frontend_2fa_pro_upsell( $frontend_status ); ?>

					<?php if ( ! $has_wc ) : ?>
						<div class="rip-alert rip-alert--info">
							<?php esc_html_e( 'WooCommerce is not active on this site. Activate WooCommerce to use frontend login 2FA — these slug overrides take effect once it is.', 'reportedip-hive' ); ?>
						</div>
					<?php endif; ?>

					<div class="rip-form-group">
						<span class="rip-label"><?php esc_html_e( 'Network configuration (managed by Super Admin)', 'reportedip-hive' ); ?></span>
						<ul class="rip-network-state">
							<li>
								<?php esc_html_e( 'Themed challenge page', 'reportedip-hive' ); ?>:
								<?php if ( $frontend_enabled && ! $frontend_locked ) : ?>
									<span class="rip-badge rip-badge--success"><?php esc_html_e( 'enabled', 'reportedip-hive' ); ?></span>
								<?php elseif ( $frontend_locked_by_tier ) : ?>
									<span class="rip-badge rip-badge--neutral"><?php esc_html_e( 'locked by tier', 'reportedip-hive' ); ?></span>
								<?php else : ?>
									<span class="rip-badge rip-badge--neutral"><?php esc_html_e( 'disabled', 'reportedip-hive' ); ?></span>
								<?php endif; ?>
							</li>
							<li>
								<?php esc_html_e( 'Customer self-service opt-in', 'reportedip-hive' ); ?>:
								<span class="rip-badge rip-badge--<?php echo $customer_optional ? 'success' : 'neutral'; ?>"><?php echo $customer_optional ? esc_html__( 'allowed', 'reportedip-hive' ) : esc_html__( 'not allowed', 'reportedip-hive' ); ?></span>
							</li>
						</ul>
					</div>

					<fieldset class="rip-fieldset" <?php echo $frontend_locked ? 'disabled' : ''; ?>>
						<legend class="screen-reader-text"><?php esc_html_e( 'Per-site slug overrides', 'reportedip-hive' ); ?></legend>

						<div class="rip-form-group">
							<label class="rip-label" for="rip_2fa_frontend_slug_site_override">
								<?php esc_html_e( 'Challenge page slug — site override', 'reportedip-hive' ); ?>
							</label>
							<div class="rip-input-prefix">
								<span class="rip-input-prefix__prefix"><?php echo esc_html( $home_prefix ); ?></span>
								<input type="text"
									id="rip_2fa_frontend_slug_site_override"
									name="rip_2fa_frontend_slug_site_override"
									class="rip-input"
									value="<?php echo esc_attr( $slug_override ); ?>"
									placeholder="<?php echo esc_attr( $slug_default ); ?>"
									pattern="[a-z0-9][a-z0-9-]{1,48}[a-z0-9]"
									maxlength="50"
									spellcheck="false"
									autocomplete="off" />
								<span class="rip-input-prefix__suffix">/</span>
							</div>
							<p class="rip-help-text">
								<?php
								printf(
									/* translators: 1: network-default slug, 2: effective URL on this site */
									esc_html__( 'Network default: %1$s. Leave empty to inherit. Effective URL on this site: %2$s', 'reportedip-hive' ),
									'<code>' . esc_html( $slug_default ) . '</code>',
									'<code>' . esc_html( $challenge_url ) . '</code>'
								);
								?>
							</p>
						</div>

						<div class="rip-form-group">
							<label class="rip-label" for="rip_2fa_frontend_setup_slug_site_override">
								<?php esc_html_e( 'Setup page slug (onboarding) — site override', 'reportedip-hive' ); ?>
							</label>
							<div class="rip-input-prefix">
								<span class="rip-input-prefix__prefix"><?php echo esc_html( $home_prefix ); ?></span>
								<input type="text"
									id="rip_2fa_frontend_setup_slug_site_override"
									name="rip_2fa_frontend_setup_slug_site_override"
									class="rip-input"
									value="<?php echo esc_attr( $setup_slug_override ); ?>"
									placeholder="<?php echo esc_attr( $setup_slug_default ); ?>"
									pattern="[a-z0-9][a-z0-9-]{1,48}[a-z0-9]"
									maxlength="50"
									spellcheck="false"
									autocomplete="off" />
								<span class="rip-input-prefix__suffix">/</span>
							</div>
							<p class="rip-help-text">
								<?php
								printf(
									/* translators: 1: network-default setup slug, 2: effective URL on this site */
									esc_html__( 'Network default: %1$s. Leave empty to inherit. Effective URL on this site: %2$s', 'reportedip-hive' ),
									'<code>' . esc_html( $setup_slug_default ) . '</code>',
									'<code>' . esc_html( $setup_url ) . '</code>'
								);
								?>
							</p>
						</div>
					</fieldset>
				</div>

				<div class="rip-settings-section">
					<h2 class="rip-settings-section__title">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 11h-6"/></svg>
						<?php esc_html_e( '2FA enforcement — role overrides for this site', 'reportedip-hive' ); ?>
					</h2>
					<p class="rip-settings-section__desc">
						<?php esc_html_e( 'The Super Admin enforces 2FA on certain roles network-wide. You can add roles on top of that list for this site only — but you cannot remove network-required roles here.', 'reportedip-hive' ); ?>
					</p>

					<div class="rip-form-group">
						<span class="rip-label"><?php esc_html_e( 'Network-required roles (always enforced on this site)', 'reportedip-hive' ); ?></span>
						<?php if ( empty( $network_roles ) ) : ?>
							<p class="rip-help-text"><em><?php esc_html_e( 'The Super Admin has not enforced 2FA on any role network-wide.', 'reportedip-hive' ); ?></em></p>
						<?php else : ?>
							<ul class="rip-network-state">
								<?php foreach ( $network_roles as $role_slug ) : ?>
									<li>
										<span class="rip-badge rip-badge--info"><?php esc_html_e( 'network', 'reportedip-hive' ); ?></span>
										<?php echo esc_html( $all_roles[ $role_slug ] ?? $role_slug ); ?>
										<code><?php echo esc_html( $role_slug ); ?></code>
									</li>
								<?php endforeach; ?>
							</ul>
						<?php endif; ?>
					</div>

					<fieldset class="rip-fieldset">
						<legend class="rip-label">
							<?php esc_html_e( 'Additional roles to enforce on THIS site', 'reportedip-hive' ); ?>
						</legend>
						<p class="rip-help-text">
							<?php esc_html_e( 'Pick roles that should require 2FA on this sub-site in addition to the network-required ones above. Network-required roles stay enforced regardless of the boxes here.', 'reportedip-hive' ); ?>
						</p>
						<div class="rip-form-group rip-form-checklist">
							<?php foreach ( $all_roles as $slug => $label ) : ?>
								<?php
								$is_network = in_array( $slug, $network_roles, true );
								$is_extra   = in_array( $slug, $site_extra, true );
								?>
								<label class="rip-toggle">
									<input type="checkbox"
										class="rip-toggle__input"
										name="rip_2fa_enforce_roles_extra[]"
										value="<?php echo esc_attr( $slug ); ?>"
										<?php checked( $is_extra || $is_network ); ?>
										<?php disabled( $is_network ); ?> />
									<span class="rip-toggle__slider"></span>
									<span class="rip-toggle__label">
										<?php echo esc_html( $label ); ?>
										<?php if ( $is_network ) : ?>
											<span class="rip-badge rip-badge--info rip-badge--inline"><?php esc_html_e( 'enforced by network', 'reportedip-hive' ); ?></span>
										<?php endif; ?>
									</span>
								</label>
							<?php endforeach; ?>
						</div>
					</fieldset>
				</div>

				<p class="rip-actions">
					<?php submit_button( __( 'Save site overrides', 'reportedip-hive' ), 'primary rip-button rip-button--primary', 'submit', false ); ?>
				</p>
			</form>
		</div>
		<?php
		$this->render_site_admin_footer();
	}

	/**
	 * Render the standard rip-header for sub-site admin pages.
	 *
	 * Mirrors {@see render_page_header()} but replaces the network-only
	 * Mode + Tier badge cluster with a "Centrally managed" badge plus a
	 * deep link into the Network Admin so site admins always have a way
	 * back to the controlling super admin.
	 *
	 * @param string $title    Page title.
	 * @param string $subtitle Page subtitle.
	 * @return void
	 * @since  2.0.0
	 */
	private function render_site_admin_header( $title, $subtitle ) {
		?>
		<div class="wrap rip-wrap">
			<div class="rip-header">
				<div class="rip-header__brand">
					<div class="rip-header__logo">
						<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
							<path d="M24 4L8 12v12c0 11 7.7 21.3 16 24 8.3-2.7 16-13 16-24V12L24 4z" fill="currentColor" opacity="0.15"/>
							<path d="M24 4L8 12v12c0 11 7.7 21.3 16 24 8.3-2.7 16-13 16-24V12L24 4zm0 4.2l12 6v10c0 8.4-6 16.3-12 18.5-6-2.2-12-10.1-12-18.5v-10l12-6z" fill="currentColor"/>
							<path d="M21 28l-5-5 1.8-1.8 3.2 3.2 7.2-7.2L30 19l-9 9z" fill="currentColor"/>
						</svg>
					</div>
					<div>
						<h1 class="rip-header__title"><?php echo esc_html( $title ); ?></h1>
						<p class="rip-header__subtitle"><?php echo esc_html( $subtitle ); ?></p>
					</div>
				</div>
				<div class="rip-header__actions">
					<span class="rip-mode-badge rip-mode-badge--neutral"><?php esc_html_e( 'Site view', 'reportedip-hive' ); ?></span>
					<a class="rip-button rip-button--secondary" href="<?php echo esc_url( network_admin_url( 'admin.php?page=reportedip-hive' ) ); ?>"><?php esc_html_e( 'Open Network Admin', 'reportedip-hive' ); ?></a>
				</div>
			</div>
		<?php
	}

	/**
	 * Render the trust-badges footer + close the rip-wrap div on
	 * sub-site admin pages. Counterpart to
	 * {@see render_site_admin_header()}.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	private function render_site_admin_footer() {
		self::render_page_footer();
	}

	/**
	 * Aggregate the per-site stat counters for the Site Status page.
	 *
	 * - events_24h: number of events recorded for this `blog_id` in the last 24 h.
	 * - failed_logins_24h: subset filtered to login-related event types.
	 * - blocked_active: total active blocks in the network-wide blocked table.
	 * - whitelisted: total active whitelist entries (network-wide).
	 * - recent_events: 10 most recent events for this site.
	 *
	 * @return array<string, mixed>
	 * @since  2.0.0
	 */
	private function get_site_admin_stats() {
		global $wpdb;
		$logs    = ReportedIP_Hive_Schema::table( ReportedIP_Hive_Schema::TABLE_LOGS );
		$blog_id = (int) get_current_blog_id();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $logs is a constant table name from Schema::table(); per-site admin dashboard widget with naturally fresh data, caching would only delay incident visibility.
		$events_24h        = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $logs WHERE blog_id = %d AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)",
				$blog_id
			)
		);
		$failed_logins_24h = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $logs WHERE blog_id = %d AND event_type LIKE %s AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)",
				$blog_id,
				'%failed_login%'
			)
		);
		$recent_events     = (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT event_type, ip_address, severity, created_at FROM $logs WHERE blog_id = %d ORDER BY created_at DESC LIMIT 10",
				$blog_id
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		return array(
			'events_24h'        => $events_24h,
			'failed_logins_24h' => $failed_logins_24h,
			'blocked_active'    => $this->database->count_blocked_ips(),
			'whitelisted'       => $this->database->count_whitelisted_ips(),
			'recent_events'     => $recent_events,
		);
	}

	/**
	 * Map a log severity to the matching `rip-badge--*` modifier class.
	 *
	 * @param string $severity Severity slug from the logs table.
	 * @return string Badge variant slug.
	 * @since  2.0.0
	 */
	private function severity_badge_class( $severity ) {
		switch ( $severity ) {
			case 'critical':
			case 'high':
				return 'danger';
			case 'medium':
				return 'warning';
			case 'low':
				return 'info';
			default:
				return 'neutral';
		}
	}

	/**
	 * Renders the read-only banner shown atop every Site Admin page on Multisite.
	 *
	 * @since 2.0.0
	 */
	private function render_site_readonly_banner() {
		printf(
			'<div class="rip-alert rip-alert--info rip-alert--banner"><strong>%s</strong> %s</div>',
			esc_html__( 'Centrally managed:', 'reportedip-hive' ),
			esc_html__( 'this site is part of a managed ReportedIP Hive network. For Whitelist or mode changes, contact your Network Admin.', 'reportedip-hive' )
		);
	}

	/**
	 * Handle the Site-2FA-Settings POST. Validates nonce, sanitises input,
	 * intersects roles against the actual `wp_roles()` whitelist (so a
	 * crafted POST cannot smuggle non-existent role slugs into the
	 * enforcement list), persists both override keys.
	 *
	 * @return bool True when a save happened on this request.
	 * @since  2.0.0
	 */
	private function maybe_handle_site_2fa_save() {
		if ( ! isset( $_POST['_rip_site_2fa_nonce'] ) ) {
			return false;
		}

		$nonce = sanitize_text_field( wp_unslash( $_POST['_rip_site_2fa_nonce'] ) );
		if ( ! wp_verify_nonce( $nonce, 'reportedip_hive_site_2fa_save' ) ) {
			wp_die( esc_html__( 'Security check failed. Please reload and try again.', 'reportedip-hive' ) );
		}

		$slug_raw = isset( $_POST['rip_2fa_frontend_slug_site_override'] )
			? sanitize_text_field( wp_unslash( $_POST['rip_2fa_frontend_slug_site_override'] ) )
			: '';
		ReportedIP_Hive_Option_Routing::set(
			'reportedip_hive_2fa_frontend_slug_site_override',
			sanitize_title( $slug_raw )
		);

		$setup_slug_raw = isset( $_POST['rip_2fa_frontend_setup_slug_site_override'] )
			? sanitize_text_field( wp_unslash( $_POST['rip_2fa_frontend_setup_slug_site_override'] ) )
			: '';
		ReportedIP_Hive_Option_Routing::set(
			'reportedip_hive_2fa_frontend_setup_slug_site_override',
			sanitize_title( $setup_slug_raw )
		);

		$roles_raw     = isset( $_POST['rip_2fa_enforce_roles_extra'] ) && is_array( $_POST['rip_2fa_enforce_roles_extra'] )
			? array_map( 'sanitize_text_field', wp_unslash( $_POST['rip_2fa_enforce_roles_extra'] ) )
			: array();
		$valid_roles   = function_exists( 'wp_roles' ) ? array_keys( wp_roles()->get_names() ) : array();
		$network_roles = ReportedIP_Hive_Option_Routing::get_network_enforce_roles();
		$roles         = array_values(
			array_diff(
				array_intersect(
					array_unique( array_map( 'sanitize_key', array_map( 'strval', $roles_raw ) ) ),
					$valid_roles
				),
				$network_roles
			)
		);
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_2fa_enforce_roles_extra', $roles );

		return true;
	}

	/**
	 * Register settings
	 */
	public function register_settings() {
		register_setting(
			'reportedip_hive_general',
			'reportedip_hive_operation_mode',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_operation_mode' ),
				'default'           => 'local',
			)
		);

		register_setting(
			'reportedip_hive_api',
			'reportedip_hive_api_key',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_api_key' ),
			)
		);
		register_setting(
			'reportedip_hive_api',
			'reportedip_hive_api_endpoint',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_api_endpoint' ),
			)
		);

		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_failed_login_threshold',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_failed_login_threshold' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_failed_login_timeframe',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_timeframe' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_comment_spam_threshold',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_spam_threshold' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_xmlrpc_threshold',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_xmlrpc_threshold' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_comment_spam_timeframe',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_timeframe' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_xmlrpc_timeframe',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_timeframe' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_monitor_failed_logins',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_monitor_comments',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_monitor_xmlrpc',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);

		foreach ( array(
			'reportedip_hive_password_spray_threshold',
			'reportedip_hive_app_password_threshold',
			'reportedip_hive_rest_threshold',
			'reportedip_hive_rest_sensitive_threshold',
			'reportedip_hive_user_enum_threshold',
			'reportedip_hive_scan_404_threshold',
		) as $threshold_option ) {
			register_setting(
				'reportedip_hive_protection_detection',
				$threshold_option,
				array(
					'type'              => 'integer',
					'sanitize_callback' => array( $this, 'sanitize_failed_login_threshold' ),
				)
			);
		}
		foreach ( array(
			'reportedip_hive_password_spray_timeframe',
			'reportedip_hive_app_password_timeframe',
			'reportedip_hive_rest_timeframe',
			'reportedip_hive_rest_sensitive_timeframe',
			'reportedip_hive_user_enum_timeframe',
			'reportedip_hive_scan_404_timeframe',
			'reportedip_hive_geo_window_days',
			'reportedip_hive_password_min_length',
			'reportedip_hive_password_min_classes',
		) as $integer_option ) {
			register_setting(
				'reportedip_hive_protection_detection',
				$integer_option,
				array(
					'type'              => 'integer',
					'sanitize_callback' => array( $this, 'sanitize_timeframe' ),
				)
			);
		}
		foreach ( array(
			'reportedip_hive_monitor_app_passwords',
			'reportedip_hive_app_password_require_2fa',
			'reportedip_hive_monitor_rest_api',
			'reportedip_hive_block_user_enumeration',
			'reportedip_hive_monitor_404_scans',
			'reportedip_hive_bot_allowlist_enabled',
			'reportedip_hive_monitor_woocommerce',
			'reportedip_hive_monitor_geo_anomaly',
			'reportedip_hive_geo_revoke_trusted_devices',
			'reportedip_hive_geo_report_to_api',
			'reportedip_hive_password_policy_enabled',
			'reportedip_hive_password_check_hibp',
			'reportedip_hive_password_policy_all_users',
		) as $boolean_option ) {
			register_setting(
				'reportedip_hive_protection_detection',
				$boolean_option,
				array(
					'type'              => 'boolean',
					'sanitize_callback' => array( $this, 'sanitize_boolean' ),
				)
			);
		}

		register_setting(
			'reportedip_hive_protection_blocking',
			'reportedip_hive_auto_block',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_blocking',
			'reportedip_hive_block_duration',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_block_duration' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_blocking',
			'reportedip_hive_block_threshold',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_block_threshold' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_notifications',
			'reportedip_hive_notify_admin',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_notifications',
			'reportedip_hive_2fa_notify_new_device',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_notifications',
			'reportedip_hive_notify_recipients',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_notify_recipients' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_notifications',
			'reportedip_hive_promo_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_notifications',
			'reportedip_hive_quota_notif_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_notifications',
			'reportedip_hive_tier_change_mail_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_notifications',
			'reportedip_hive_notify_from_name',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
			)
		);
		register_setting(
			'reportedip_hive_protection_notifications',
			'reportedip_hive_notify_from_email',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_notify_from_email' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_notifications',
			'reportedip_hive_notify_sync_to_api',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_blocking',
			'reportedip_hive_report_only_mode',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_blocking',
			'reportedip_hive_block_escalation_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_blocking',
			'reportedip_hive_block_ladder_minutes',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_block_ladder' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_blocking',
			'reportedip_hive_block_ladder_reset_days',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_ladder_reset_days' ),
			)
		);

		register_setting(
			'reportedip_hive_hide_login',
			'reportedip_hive_hide_login_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_hide_login_enabled' ),
			)
		);
		register_setting(
			'reportedip_hive_hide_login',
			'reportedip_hive_hide_login_slug',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_hide_login_slug' ),
			)
		);
		register_setting(
			'reportedip_hive_hide_login',
			'reportedip_hive_hide_login_response_mode',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_hide_login_response_mode' ),
			)
		);
		register_setting(
			'reportedip_hive_hide_login',
			'reportedip_hive_hide_login_token_in_urls',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_hide_login',
			'reportedip_hive_monitor_hide_login_probe',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_hide_login',
			'reportedip_hive_hide_login_probe_threshold',
			array(
				'type'              => 'integer',
				'sanitize_callback' => 'absint',
			)
		);
		register_setting(
			'reportedip_hive_hide_login',
			'reportedip_hive_hide_login_probe_timeframe',
			array(
				'type'              => 'integer',
				'sanitize_callback' => 'absint',
			)
		);

		register_setting(
			'reportedip_hive_advanced_privacy',
			'reportedip_hive_log_level',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_log_level' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_privacy',
			'reportedip_hive_detailed_logging',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_privacy',
			'reportedip_hive_log_user_agents',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_privacy',
			'reportedip_hive_minimal_logging',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_privacy',
			'reportedip_hive_log_referer_domains',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_privacy',
			'reportedip_hive_data_retention_days',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_retention_days' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_privacy',
			'reportedip_hive_auto_anonymize_days',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_anonymize_days' ),
			)
		);

		register_setting(
			'reportedip_hive_advanced_performance',
			'reportedip_hive_enable_caching',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_performance',
			'reportedip_hive_delete_data_on_uninstall',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_performance',
			'reportedip_hive_cache_duration',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_cache_duration' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_performance',
			'reportedip_hive_negative_cache_duration',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_negative_cache_duration' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_performance',
			'reportedip_hive_max_api_calls_per_hour',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_max_api_calls' ),
			)
		);
		register_setting(
			'reportedip_hive_api',
			'reportedip_hive_trusted_ip_header',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_trusted_ip_header' ),
			)
		);

		register_setting(
			'reportedip_hive_protection_blocking',
			'reportedip_hive_blocked_page_contact_url',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_url_nullsafe' ),
			)
		);

		register_setting(
			'reportedip_hive_protection_blocking',
			'reportedip_hive_report_cooldown_hours',
			array(
				'type'              => 'integer',
				'sanitize_callback' => 'absint',
			)
		);

		register_setting(
			'reportedip_hive_promote',
			'reportedip_hive_auto_footer_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => false,
			)
		);

		register_setting(
			'reportedip_hive_promote',
			'reportedip_hive_auto_footer_variant',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_auto_footer_variant' ),
				'default'           => 'badge',
			)
		);

		register_setting(
			'reportedip_hive_promote',
			'reportedip_hive_auto_footer_align',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_auto_footer_align' ),
				'default'           => 'center',
			)
		);

		register_setting(
			'reportedip_hive_hardening_mode',
			'reportedip_hive_hardening_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
				'default'           => false,
			)
		);
		register_setting(
			'reportedip_hive_hardening_mode',
			'reportedip_hive_hardening_realtime_detection',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
				'default'           => true,
			)
		);
		register_setting(
			'reportedip_hive_hardening_mode',
			'reportedip_hive_hardening_duration_minutes',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_hardening_duration' ),
				'default'           => 60,
			)
		);
		register_setting(
			'reportedip_hive_hardening_mode',
			'reportedip_hive_hardening_login_threshold',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_hardening_login_threshold' ),
				'default'           => 2,
			)
		);
		register_setting(
			'reportedip_hive_hardening_mode',
			'reportedip_hive_hardening_login_timeframe',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_hardening_login_timeframe' ),
				'default'           => 5,
			)
		);
		register_setting(
			'reportedip_hive_hardening_mode',
			'reportedip_hive_hardening_block_threshold',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_hardening_block_threshold' ),
				'default'           => 60,
			)
		);
		register_setting(
			'reportedip_hive_hardening_mode',
			'reportedip_hive_hardening_detect_window_minutes',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_hardening_detect_window' ),
				'default'           => 10,
			)
		);
		register_setting(
			'reportedip_hive_hardening_mode',
			'reportedip_hive_hardening_detect_min_ips',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_hardening_detect_min_ips' ),
				'default'           => 5,
			)
		);
		register_setting(
			'reportedip_hive_hardening_mode',
			'reportedip_hive_hardening_detect_min_attempts',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_hardening_detect_min_attempts' ),
				'default'           => 20,
			)
		);

		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_decoy_pathblock_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
				'default'           => true,
			)
		);
	}

	/**
	 * Sanitiser: hardening-mode duration in minutes (5–360).
	 *
	 * @param mixed $value
	 * @return int
	 * @since  2.0.8
	 */
	public function sanitize_hardening_duration( $value ) {
		$value = absint( $value );
		return max( 5, min( 360, $value > 0 ? $value : 60 ) );
	}

	/**
	 * Sanitiser: hardening login-failure threshold (1–10).
	 *
	 * @param mixed $value
	 * @return int
	 * @since  2.0.8
	 */
	public function sanitize_hardening_login_threshold( $value ) {
		$value = absint( $value );
		return max( 1, min( 10, $value > 0 ? $value : 2 ) );
	}

	/**
	 * Sanitiser: hardening login-failure timeframe in minutes (1–60).
	 *
	 * @param mixed $value
	 * @return int
	 * @since  2.0.8
	 */
	public function sanitize_hardening_login_timeframe( $value ) {
		$value = absint( $value );
		return max( 1, min( 60, $value > 0 ? $value : 5 ) );
	}

	/**
	 * Sanitiser: hardening reputation block threshold percentage (10–100).
	 *
	 * @param mixed $value
	 * @return int
	 * @since  2.0.8
	 */
	public function sanitize_hardening_block_threshold( $value ) {
		$value = absint( $value );
		return max( 10, min( 100, $value > 0 ? $value : 60 ) );
	}

	/**
	 * Sanitiser: distributed-detection window in minutes (1–120).
	 *
	 * @param mixed $value
	 * @return int
	 * @since  2.0.29
	 */
	public function sanitize_hardening_detect_window( $value ) {
		$value = absint( $value );
		return max( 1, min( 120, $value > 0 ? $value : 10 ) );
	}

	/**
	 * Sanitiser: distributed-detection minimum distinct IPs (2–100).
	 *
	 * @param mixed $value
	 * @return int
	 * @since  2.0.29
	 */
	public function sanitize_hardening_detect_min_ips( $value ) {
		$value = absint( $value );
		return max( 2, min( 100, $value > 0 ? $value : 5 ) );
	}

	/**
	 * Sanitiser: distributed-detection minimum total attempts (3–1000).
	 *
	 * @param mixed $value
	 * @return int
	 * @since  2.0.29
	 */
	public function sanitize_hardening_detect_min_attempts( $value ) {
		$value = absint( $value );
		return max( 3, min( 1000, $value > 0 ? $value : 20 ) );
	}

	/**
	 * Sanitiser: auto-footer variant must be one of the supported values.
	 *
	 * Delegates to the canonical allowlist on `ReportedIP_Hive_Frontend_Shortcodes`
	 * so the wizard, the Promote tab, and Settings API all share one source of truth.
	 *
	 * @param mixed $value Raw value from $_POST.
	 * @return string Sanitised variant key (`badge` or `shield`).
	 * @since  1.3.0
	 */
	public function sanitize_auto_footer_variant( $value ) {
		return ReportedIP_Hive_Frontend_Shortcodes::sanitize_footer_variant( $value );
	}

	/**
	 * Sanitiser: auto-footer alignment must be left, center, or right.
	 *
	 * @param mixed $value Raw value from $_POST.
	 * @return string Sanitised alignment key.
	 * @since  1.3.1
	 */
	public function sanitize_auto_footer_align( $value ) {
		$value = sanitize_key( (string) $value );
		return in_array( $value, array( 'left', 'center', 'right', 'below' ), true ) ? $value : 'center';
	}

	/**
	 * Null-safe URL sanitiser for settings that point to an external URL.
	 *
	 * Coerces null to an empty string before handing off to esc_url_raw(),
	 * which in turn calls esc_url() — that function's first op is ltrim(),
	 * and PHP 8.1+ deprecates passing null there. The deprecation output
	 * breaks the Settings API redirect because headers have already been
	 * emitted by the time wp_redirect fires.
	 *
	 * @param mixed $value Raw option value from $_POST (may be null).
	 * @return string Sanitised URL or empty string.
	 */
	public function sanitize_url_nullsafe( $value ) {
		return esc_url_raw( (string) ( $value ?? '' ) );
	}

	/**
	 * Sanitize API key - validates format
	 */
	public function sanitize_api_key( $value ) {
		$value = sanitize_text_field( $value ?? '' );

		if ( empty( $value ) ) {
			return '';
		}

		if ( strlen( $value ) < 32 || strlen( $value ) > 64 ) {
			add_settings_error(
				'reportedip_hive_api_key',
				'invalid_api_key_length',
				__( 'API key must be between 32 and 64 characters.', 'reportedip-hive' ),
				'error'
			);
			return ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' );
		}

		if ( ! preg_match( '/^[a-zA-Z0-9]+$/', $value ) ) {
			add_settings_error(
				'reportedip_hive_api_key',
				'invalid_api_key_format',
				__( 'API key must contain only alphanumeric characters.', 'reportedip-hive' ),
				'error'
			);
			return ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' );
		}

		return $value;
	}

	/**
	 * Sanitize API endpoint - validates URL and enforces HTTPS
	 */
	public function sanitize_api_endpoint( $value ) {
		$value = esc_url_raw( $value ?? '' );

		if ( empty( $value ) ) {
			return 'https://reportedip.de/wp-json/reportedip/v2/';
		}

		if ( ! filter_var( $value, FILTER_VALIDATE_URL ) ) {
			add_settings_error(
				'reportedip_hive_api_endpoint',
				'invalid_api_endpoint',
				__( 'API endpoint must be a valid URL.', 'reportedip-hive' ),
				'error'
			);
			return ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_endpoint', 'https://reportedip.de/wp-json/reportedip/v2/' );
		}

		if ( strpos( $value, 'https://' ) !== 0 ) {
			add_settings_error(
				'reportedip_hive_api_endpoint',
				'insecure_api_endpoint',
				__( 'API endpoint must use HTTPS for security.', 'reportedip-hive' ),
				'error'
			);
			return ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_endpoint', 'https://reportedip.de/wp-json/reportedip/v2/' );
		}

		return trailingslashit( $value );
	}

	/**
	 * Sanitize boolean values
	 */
	public function sanitize_boolean( $value ) {
		return $value ? 1 : 0;
	}

	/**
	 * Sanitize the operation-mode option. Anything that isn't `local` or
	 * `community` falls back to the previously stored value (or `local` on
	 * first install). Side effects (cache invalidation, action hook, audit
	 * log) are handled by `Mode_Manager::on_mode_option_updated()` listening
	 * on `update_option_<OPTION_MODE>`.
	 *
	 * @param mixed $value Raw POST value.
	 * @return string Either `local` or `community`.
	 * @since 1.6.0
	 */
	public function sanitize_operation_mode( $value ) {
		$value = is_string( $value ) ? trim( $value ) : '';
		if ( ReportedIP_Hive_Mode_Manager::is_valid_mode( $value ) ) {
			return $value;
		}
		$current = (string) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_Mode_Manager::OPTION_MODE, ReportedIP_Hive_Mode_Manager::MODE_LOCAL );
		return ReportedIP_Hive_Mode_Manager::is_valid_mode( $current ) ? $current : ReportedIP_Hive_Mode_Manager::MODE_LOCAL;
	}

	/**
	 * Sanitize the comma/whitespace-separated notification recipient list.
	 *
	 * Drops invalid addresses, dedupes, and re-emits a comma+space joined
	 * string so the saved option round-trips cleanly.
	 *
	 * @param string $value Raw textarea content.
	 * @return string
	 */
	public function sanitize_notify_recipients( $value ) {
		$candidates = array_filter( array_map( 'trim', preg_split( '/[\s,;]+/', (string) $value ) ) );
		$valid      = array();
		foreach ( $candidates as $candidate ) {
			$clean = sanitize_email( $candidate );
			if ( '' !== $clean && is_email( $clean ) ) {
				$valid[] = $clean;
			}
		}
		return implode( ', ', array_values( array_unique( $valid ) ) );
	}

	/**
	 * Sanitize the configurable From-email; empty when invalid.
	 *
	 * @param string $value Raw input.
	 * @return string
	 */
	public function sanitize_notify_from_email( $value ) {
		$clean = sanitize_email( (string) $value );
		return ( '' !== $clean && is_email( $clean ) ) ? $clean : '';
	}

	/**
	 * Sanitize failed login threshold (1-100)
	 */
	public function sanitize_failed_login_threshold( $value ) {
		$value  = absint( $value );
		$min    = 1;
		$max    = 100;
		$result = max( $min, min( $max, $value ) );

		if ( $value !== $result ) {
			add_settings_error(
				'reportedip_hive_failed_login_threshold',
				'value_adjusted',
				sprintf(
					/* translators: 1: adjusted threshold value, 2: minimum allowed value, 3: maximum allowed value */
					__( 'Failed login threshold was adjusted to %1$d (must be between %2$d and %3$d).', 'reportedip-hive' ),
					$result,
					$min,
					$max
				),
				'warning'
			);
		}
		return $result;
	}

	/**
	 * Sanitize timeframe (1-1440 minutes = 24 hours)
	 */
	public function sanitize_timeframe( $value ) {
		$value  = absint( $value );
		$min    = 1;
		$max    = 1440;
		$result = max( $min, min( $max, $value ) );

		if ( $value !== $result ) {
			add_settings_error(
				'reportedip_hive_timeframe',
				'value_adjusted',
				sprintf(
					/* translators: 1: adjusted value in minutes, 2: minimum allowed value, 3: maximum allowed value */
					__( 'Time window was adjusted to %1$d minutes (must be between %2$d and %3$d).', 'reportedip-hive' ),
					$result,
					$min,
					$max
				),
				'warning'
			);
		}
		return $result;
	}

	/**
	 * Sanitize spam threshold (1-50)
	 */
	public function sanitize_spam_threshold( $value ) {
		$value  = absint( $value );
		$min    = 1;
		$max    = 50;
		$result = max( $min, min( $max, $value ) );

		if ( $value !== $result ) {
			add_settings_error(
				'reportedip_hive_spam_threshold',
				'value_adjusted',
				sprintf(
					/* translators: 1: adjusted threshold value, 2: minimum allowed value, 3: maximum allowed value */
					__( 'Comment spam threshold was adjusted to %1$d (must be between %2$d and %3$d).', 'reportedip-hive' ),
					$result,
					$min,
					$max
				),
				'warning'
			);
		}
		return $result;
	}

	/**
	 * Sanitize XMLRPC threshold (1-100)
	 */
	public function sanitize_xmlrpc_threshold( $value ) {
		$value  = absint( $value );
		$min    = 1;
		$max    = 100;
		$result = max( $min, min( $max, $value ) );

		if ( $value !== $result ) {
			add_settings_error(
				'reportedip_hive_xmlrpc_threshold',
				'value_adjusted',
				sprintf(
					/* translators: 1: adjusted threshold value, 2: minimum allowed value, 3: maximum allowed value */
					__( 'XMLRPC threshold was adjusted to %1$d (must be between %2$d and %3$d).', 'reportedip-hive' ),
					$result,
					$min,
					$max
				),
				'warning'
			);
		}
		return $result;
	}

	/**
	 * Sanitize block duration (0-8760 hours = 1 year, 0 = permanent)
	 */
	public function sanitize_block_duration( $value ) {
		$value = absint( $value );
		return min( 8760, $value );
	}

	/**
	 * Sanitize the progressive-block ladder.
	 *
	 * Accepts a comma-separated list of minute values. Drops blanks, clamps
	 * negatives to 1, caps each step at one year (525 600 min), preserves
	 * order. Empty input falls back to the documented default ladder.
	 *
	 * @param mixed $value Raw value from the settings form.
	 * @return string Cleaned CSV ready for storage.
	 * @since  1.5.0
	 */
	public function sanitize_block_ladder( $value ) {
		$value = is_string( $value ) ? $value : '';
		$parts = array_filter(
			array_map( 'trim', explode( ',', $value ) ),
			static fn( string $part ): bool => '' !== $part
		);

		$ladder = array();
		foreach ( $parts as $part ) {
			$minutes  = max( 1, min( 525600, (int) $part ) );
			$ladder[] = $minutes;
		}

		if ( empty( $ladder ) && class_exists( 'ReportedIP_Hive_Block_Escalation' ) ) {
			$ladder = ReportedIP_Hive_Block_Escalation::DEFAULT_LADDER_MINUTES;
		}

		return implode( ',', $ladder );
	}

	/**
	 * Sanitize the ladder reset window in days (1-365).
	 *
	 * @param mixed $value Raw value.
	 * @return int Clamped days.
	 * @since  1.5.0
	 */
	public function sanitize_ladder_reset_days( $value ) {
		$value = absint( $value );
		return max( 1, min( 365, $value ) );
	}

	/**
	 * Sanitize block threshold (0-100 percent)
	 */
	public function sanitize_block_threshold( $value ) {
		$value  = absint( $value );
		$min    = 0;
		$max    = 100;
		$result = max( $min, min( $max, $value ) );

		if ( $value !== $result ) {
			add_settings_error(
				'reportedip_hive_block_threshold',
				'value_adjusted',
				sprintf(
					/* translators: 1: adjusted threshold percentage, 2: minimum allowed value, 3: maximum allowed value */
					__( 'Block threshold was adjusted to %1$d%% (must be between %2$d and %3$d).', 'reportedip-hive' ),
					$result,
					$min,
					$max
				),
				'warning'
			);
		}
		return $result;
	}

	/**
	 * Sanitize log level
	 */
	public function sanitize_log_level( $value ) {
		$valid_levels = array( 'debug', 'info', 'warning', 'error', 'critical' );
		$value        = sanitize_text_field( $value ?? '' );
		return in_array( $value, $valid_levels ) ? $value : 'info';
	}

	/**
	 * Sanitize Hide-Login enable toggle.
	 *
	 * Refuses to enable when no slug has been configured yet — protects users
	 * from locking themselves out by toggling the feature on without setting
	 * a slug first.
	 *
	 * @param mixed $value Raw posted value.
	 * @return bool Effective enabled state.
	 * @since  1.2.0
	 */
	public function sanitize_hide_login_enabled( $value ) {
		$wants_enabled = $this->sanitize_boolean( $value );
		if ( ! $wants_enabled ) {
			return false;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Nonce verified by Settings API options.php handler before sanitize callbacks fire.
		$slug_option = isset( $_POST['reportedip_hive_hide_login_slug'] )
			? sanitize_text_field( wp_unslash( (string) $_POST['reportedip_hive_hide_login_slug'] ) )
			: (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_slug', '' );
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		if ( '' === trim( $slug_option ) ) {
			add_settings_error(
				'reportedip_hive_hide_login_enabled',
				'reportedip_hive_hide_login_no_slug',
				__( 'Set a custom login slug before enabling Hide Login — otherwise the feature has nowhere to send admins.', 'reportedip-hive' )
			);
			return false;
		}

		flush_rewrite_rules( false );
		return true;
	}

	/**
	 * Sanitize the hidden-login slug. Delegates to the Hide_Login class which
	 * owns the validation rules (reserved slugs, permalink collisions, format).
	 *
	 * @param mixed $value Raw posted value.
	 * @return string Validated slug or the previously-stored value.
	 * @since  1.2.0
	 */
	public function sanitize_hide_login_slug( $value ) {
		if ( ! class_exists( 'ReportedIP_Hive_Hide_Login' ) ) {
			return is_string( $value ) ? sanitize_title( $value ) : '';
		}
		return ReportedIP_Hive_Hide_Login::get_instance()->sanitize_slug( $value );
	}

	/**
	 * Sanitize the hidden-login response mode (block_page | 404).
	 *
	 * @param mixed $value Raw posted value.
	 * @return string A valid response mode.
	 * @since  1.2.0
	 */
	public function sanitize_hide_login_response_mode( $value ) {
		if ( ! class_exists( 'ReportedIP_Hive_Hide_Login' ) ) {
			return 'block_page';
		}
		return ReportedIP_Hive_Hide_Login::get_instance()->sanitize_response_mode( $value );
	}

	/**
	 * Sanitize data retention days (1-365)
	 */
	public function sanitize_retention_days( $value ) {
		$value = absint( $value );
		return max( 1, min( 365, $value ) );
	}

	/**
	 * Sanitize auto anonymize days (1-365, must be <= retention days)
	 */
	public function sanitize_anonymize_days( $value ) {
		$value          = absint( $value );
		$retention_days = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_data_retention_days', 30 );
		return max( 1, min( $retention_days, min( 365, $value ) ) );
	}

	/**
	 * Sanitize cache duration (1-168 hours = 1 week)
	 */
	public function sanitize_cache_duration( $value ) {
		$value = absint( $value );
		return max( 1, min( 168, $value ) );
	}

	/**
	 * Sanitize negative cache duration (1-24 hours)
	 */
	public function sanitize_negative_cache_duration( $value ) {
		$value = absint( $value );
		return max( 1, min( 24, $value ) );
	}

	/**
	 * Sanitize max API calls per hour (0 = auto/tier-bound, otherwise 10–100000).
	 *
	 * @param mixed $value Raw input.
	 * @return int
	 */
	public function sanitize_max_api_calls( $value ) {
		$value = absint( $value );
		if ( 0 === $value ) {
			return 0;
		}
		return max( 10, min( 100000, $value ) );
	}

	/**
	 * Sanitize trusted IP header - only allow known safe values
	 */
	public function sanitize_trusted_ip_header( $value ) {
		$allowed = array( '', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP' );
		$value   = sanitize_text_field( $value ?? '' );
		return in_array( $value, $allowed, true ) ? $value : '';
	}

	/**
	 * Render the protection- and hardening-score section on the dashboard.
	 *
	 * Two SVG ring gauges (detection / hardening) followed by per-group item
	 * breakdowns with activate-direct-links and tier/mode-lock CTAs, plus
	 * independent-verification deep links for the site host.
	 *
	 * @return void
	 * @since  2.1.2
	 */
	private function render_score_section() {
		if ( ! class_exists( 'ReportedIP_Hive_Score' ) ) {
			return;
		}

		$detection = ReportedIP_Hive_Score::detection_score();
		$hardening = ReportedIP_Hive_Score::hardening_score();
		$host      = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		?>
		<section class="rip-score-section">
			<div class="rip-score-gauges">
				<?php
				$this->render_score_gauge( $detection, __( 'Detection Score', 'reportedip-hive' ) );
				$this->render_score_gauge( $hardening, __( 'Hardening Score', 'reportedip-hive' ) );
				?>
			</div>
			<div class="rip-score-breakdowns">
				<?php
				$this->render_score_items( $detection, __( 'Detection sensors', 'reportedip-hive' ) );
				$this->render_score_items( $hardening, __( 'Hardening features', 'reportedip-hive' ) );
				?>
			</div>
			<?php if ( '' !== $host ) : ?>
			<div class="rip-score-verify">
				<span class="rip-score-verify__label"><?php esc_html_e( 'Verify independently:', 'reportedip-hive' ); ?></span>
				<a class="rip-button rip-button--secondary" target="_blank" rel="noopener noreferrer" href="<?php echo esc_url( 'https://developer.mozilla.org/en-US/observatory/analyze?host=' . rawurlencode( $host ) ); ?>">
					<?php esc_html_e( 'Mozilla Observatory', 'reportedip-hive' ); ?>
				</a>
				<a class="rip-button rip-button--secondary" target="_blank" rel="noopener noreferrer" href="<?php echo esc_url( 'https://securityheaders.com/?followRedirects=on&q=' . rawurlencode( $host ) ); ?>">
					<?php esc_html_e( 'securityheaders.com', 'reportedip-hive' ); ?>
				</a>
			</div>
			<?php endif; ?>
		</section>
		<?php
	}

	/**
	 * Render a single SVG ring gauge with its score, grade and caption.
	 *
	 * @param array<string,mixed> $summary One group summary from ReportedIP_Hive_Score.
	 * @param string              $title   Group title.
	 * @return void
	 * @since  2.1.2
	 */
	private function render_score_gauge( array $summary, $title ) {
		$score  = (int) ( $summary['score'] ?? 0 );
		$grade  = (string) ( $summary['grade'] ?? 'F' );
		$earned = (int) ( $summary['earned'] ?? 0 );
		$max    = (int) ( $summary['max'] ?? 0 );
		$locked = (int) ( $summary['locked_potential'] ?? 0 );
		$band   = $score < 40 ? 'danger' : ( $score < 70 ? 'warning' : 'success' );
		$circ   = 2 * M_PI * 52;
		$offset = $circ * ( 1 - $score / 100 );

		/* translators: 1: score group title, 2: numeric score out of 100 */
		$aria = sprintf( __( '%1$s: %2$d out of 100', 'reportedip-hive' ), $title, $score );
		/* translators: 1: earned points, 2: maximum points */
		$caption = sprintf( __( '%1$d of %2$d points', 'reportedip-hive' ), $earned, $max );
		?>
		<div class="rip-stat-card rip-gauge-card">
			<div class="rip-gauge">
				<svg class="rip-gauge__svg" viewBox="0 0 120 120" role="img" aria-label="<?php echo esc_attr( $aria ); ?>">
					<circle class="rip-gauge__track" cx="60" cy="60" r="52" fill="none" stroke-width="10" />
					<circle class="rip-gauge__value rip-gauge__value--<?php echo esc_attr( $band ); ?>" cx="60" cy="60" r="52" fill="none" stroke-width="10" stroke-linecap="round" stroke-dasharray="<?php echo esc_attr( (string) round( $circ, 2 ) ); ?>" stroke-dashoffset="<?php echo esc_attr( (string) round( $offset, 2 ) ); ?>" transform="rotate(-90 60 60)" />
				</svg>
				<div class="rip-gauge__center">
					<span class="rip-gauge__score"><?php echo esc_html( (string) $score ); ?></span>
					<span class="rip-gauge__grade rip-gauge__grade--<?php echo esc_attr( $band ); ?>"><?php echo esc_html( $grade ); ?></span>
				</div>
			</div>
			<div class="rip-gauge-card__meta">
				<h3 class="rip-gauge-card__title"><?php echo esc_html( $title ); ?></h3>
				<p class="rip-gauge-card__caption">
					<?php
					echo esc_html( $caption );
					if ( $locked > 0 ) {
						/* translators: %d: points unlockable through an upgrade or mode switch */
						echo ' · ' . esc_html( sprintf( __( '+%d unlockable', 'reportedip-hive' ), $locked ) );
					}
					?>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the collapsible per-item breakdown for one score group.
	 *
	 * @param array<string,mixed> $summary One group summary from ReportedIP_Hive_Score.
	 * @param string              $title   Group title.
	 * @return void
	 * @since  2.1.2
	 */
	private function render_score_items( array $summary, $title ) {
		$items = isset( $summary['items'] ) && is_array( $summary['items'] ) ? $summary['items'] : array();
		if ( empty( $items ) ) {
			return;
		}
		?>
		<details class="rip-score-list">
			<summary class="rip-score-list__summary"><?php echo esc_html( $title ); ?></summary>
			<ul class="rip-score-items">
				<?php
				foreach ( $items as $item ) :
					$weight    = (int) ( $item['weight'] ?? 0 );
					$available = ! empty( $item['available'] );
					$enabled   = ! empty( $item['enabled'] );
					/* translators: %d: weight of the security item in points */
					$weight_label = sprintf( __( '%d pts', 'reportedip-hive' ), $weight );
					?>
					<li class="rip-score-item">
						<span class="rip-score-item__label"><?php echo esc_html( (string) ( $item['label'] ?? '' ) ); ?></span>
						<span class="rip-score-item__weight"><?php echo esc_html( $weight_label ); ?></span>
						<span class="rip-score-item__state">
							<?php
							if ( ! $available && ! empty( $item['status'] ) ) {
								/* translators: %d: points unlockable by upgrading or switching mode */
								$lock_label = sprintf( __( '+%d pts', 'reportedip-hive' ), $weight );
								self::render_tier_lock( $item['status'], array( 'label' => $lock_label ) );
							} elseif ( $enabled ) {
								?>
								<span class="rip-score-item__on">
									<svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M16.7 5.3a1 1 0 010 1.4l-7.5 7.5a1 1 0 01-1.4 0L3.3 9.7a1 1 0 011.4-1.4l3.1 3.1 6.8-6.8a1 1 0 011.4 0z" clip-rule="evenodd"/></svg>
									<?php esc_html_e( 'Active', 'reportedip-hive' ); ?>
								</span>
								<?php
							} else {
								?>
								<a class="rip-score-item__enable" href="<?php echo esc_url( (string) ( $item['settings_url'] ?? '' ) ); ?>"><?php esc_html_e( 'Enable', 'reportedip-hive' ); ?></a>
								<?php
							}
							?>
						</span>
					</li>
				<?php endforeach; ?>
			</ul>
		</details>
		<?php
	}

	/**
	 * Dashboard page
	 */
	public function dashboard_page() {
		$ip_stats      = $this->database->get_ip_management_stats();
		$recent_events = $this->database->get_recent_events( 24, 10 );

		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();

		self::render_page_header( __( 'ReportedIP Hive', 'reportedip-hive' ), __( 'Security Dashboard', 'reportedip-hive' ) );
		?>

			<div class="rip-dashboard">
				<?php
				$analytics = $this->database->get_threat_analytics( 30 );
				$layers    = $this->get_active_protection_layers();
				?>

				<div class="rip-stat-cards">
					<div class="rip-stat-card rip-stat-card--accent">
						<div class="rip-stat-card__icon rip-stat-card__icon--success">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
						</div>
						<div class="rip-stat-card__content">
							<div class="rip-stat-card__value"><?php echo esc_html( number_format_i18n( $analytics['totals']['period'] ) ); ?></div>
							<div class="rip-stat-card__label"><?php esc_html_e( 'Attacks blocked (30 days)', 'reportedip-hive' ); ?></div>
						</div>
					</div>

					<div class="rip-stat-card">
						<div class="rip-stat-card__icon rip-stat-card__icon--danger">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
						</div>
						<div class="rip-stat-card__content">
							<div class="rip-stat-card__value"><?php echo esc_html( number_format_i18n( $analytics['totals']['today'] ) ); ?></div>
							<div class="rip-stat-card__label"><?php esc_html_e( 'Blocked today', 'reportedip-hive' ); ?></div>
						</div>
					</div>

					<div class="rip-stat-card">
						<div class="rip-stat-card__icon rip-stat-card__icon--warning">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
						</div>
						<div class="rip-stat-card__content">
							<div class="rip-stat-card__value"><?php echo esc_html( number_format_i18n( $ip_stats['active_blocked'] ?? 0 ) ); ?></div>
							<div class="rip-stat-card__label"><?php esc_html_e( 'IPs currently blocked', 'reportedip-hive' ); ?></div>
						</div>
					</div>

					<div class="rip-stat-card">
						<div class="rip-stat-card__icon rip-stat-card__icon--primary">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
						</div>
						<div class="rip-stat-card__content">
							<div class="rip-stat-card__value"><?php echo esc_html( number_format_i18n( $layers['active'] ) . '/' . number_format_i18n( $layers['total'] ) ); ?></div>
							<div class="rip-stat-card__label"><?php esc_html_e( 'Protection layers active', 'reportedip-hive' ); ?></div>
						</div>
					</div>
				</div>

				<?php $this->render_score_section(); ?>

				<?php
				if ( $mode_manager->is_community_mode() && $mode_manager->tier_at_least( 'professional' ) ) {
					$this->render_relay_quota_section( $mode_manager );
				} elseif ( $mode_manager->is_community_mode() ) {
					$this->render_mail_sms_promo_card( $mode_manager );
				}
				?>

				<?php $this->render_api_usage_card(); ?>

				<div class="rip-charts-grid">
					<div class="rip-chart-card">
						<div class="rip-chart-card__header">
							<h3 class="rip-chart-card__title"><?php esc_html_e( 'Security Events', 'reportedip-hive' ); ?></h3>
							<div class="rip-time-selector">
								<button type="button" class="rip-time-selector__btn rip-time-selector__btn--active" data-period="7"><?php esc_html_e( '7 Days', 'reportedip-hive' ); ?></button>
								<button type="button" class="rip-time-selector__btn" data-period="30"><?php esc_html_e( '30 Days', 'reportedip-hive' ); ?></button>
								<button type="button" class="rip-time-selector__btn" data-period="90"><?php esc_html_e( '90 Days', 'reportedip-hive' ); ?></button>
							</div>
						</div>
						<div class="rip-chart-card__body">
							<canvas id="rip-security-events-chart" class="rip-chart-card__canvas"></canvas>
							<?php if ( (int) $analytics['totals']['period'] === 0 ) : ?>
								<div id="rip-security-events-empty" class="rip-chart-card__empty">
									<svg class="rip-chart-card__empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
										<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
										<polyline points="9 12 11 14 15 10"/>
									</svg>
									<h4><?php esc_html_e( 'No threats detected yet — protection is active.', 'reportedip-hive' ); ?></h4>
									<p><?php esc_html_e( 'Your dashboard will fill up automatically as ReportedIP Hive blocks attempts. We watch:', 'reportedip-hive' ); ?></p>
									<ul>
										<li><?php esc_html_e( 'Login brute-force, credential spray and 2FA attacks', 'reportedip-hive' ); ?></li>
										<li><?php esc_html_e( 'Firewall (WAF) hits: SQL injection, XSS, path traversal', 'reportedip-hive' ); ?></li>
										<li><?php esc_html_e( 'Scanners, fake bots, enumeration and spam floods', 'reportedip-hive' ); ?></li>
									</ul>
								</div>
							<?php endif; ?>
						</div>
					</div>

					<div class="rip-chart-card">
						<div class="rip-chart-card__header">
							<h3 class="rip-chart-card__title"><?php esc_html_e( 'Threat Distribution', 'reportedip-hive' ); ?></h3>
						</div>
						<div class="rip-chart-card__body">
							<canvas id="rip-threat-distribution-chart" class="rip-chart-card__canvas"></canvas>
						</div>
					</div>
				</div>

				<div class="rip-charts-grid rip-charts-grid--even">
					<div class="rip-chart-card">
						<div class="rip-chart-card__header">
							<h3 class="rip-chart-card__title"><?php esc_html_e( 'Firewall — Top Attack Types', 'reportedip-hive' ); ?></h3>
						</div>
						<div class="rip-chart-card__body">
							<canvas id="rip-waf-groups-chart" class="rip-chart-card__canvas"></canvas>
						</div>
					</div>

					<div class="rip-chart-card">
						<div class="rip-chart-card__header">
							<h3 class="rip-chart-card__title"><?php esc_html_e( 'Severity Breakdown', 'reportedip-hive' ); ?></h3>
						</div>
						<div class="rip-chart-card__body">
							<canvas id="rip-severity-chart" class="rip-chart-card__canvas"></canvas>
						</div>
					</div>
				</div>

				<?php $this->render_top_attackers_table( $analytics['top_ips'] ); ?>

				<?php
				if ( ! $mode_manager->tier_at_least( 'professional' ) ) {
					$this->render_analytics_pro_card();
				}
				?>

				<!-- Recent Activity Section -->
				<div class="rip-dashboard__section">
					<div class="rip-dashboard__section-title">
						<h2>
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
							<?php esc_html_e( 'Recent Activity', 'reportedip-hive' ); ?>
						</h2>
						<a href="<?php echo esc_url( self::get_admin_page_url( 'admin.php?page=reportedip-hive-security&tab=logs' ) ); ?>" class="rip-button rip-button--ghost rip-button--sm">
							<?php esc_html_e( 'View All', 'reportedip-hive' ); ?>
						</a>
					</div>

					<div class="rip-card">
						<?php if ( empty( $recent_events ) ) : ?>
							<div class="rip-empty-state rip-empty-state--compact">
								<svg class="rip-empty-state__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
									<path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
								</svg>
								<p class="rip-empty-state__text"><?php esc_html_e( 'No critical events in the last 24 hours. Your site is secure!', 'reportedip-hive' ); ?></p>
							</div>
						<?php else : ?>
							<ul class="rip-activity-list">
								<?php
								$severity_labels = array(
									'critical' => __( 'Critical', 'reportedip-hive' ),
									'high'     => __( 'High', 'reportedip-hive' ),
									'medium'   => __( 'Medium', 'reportedip-hive' ),
									'low'      => __( 'Low', 'reportedip-hive' ),
								);
								$family_labels = ReportedIP_Hive_Event_Taxonomy::labels();
								foreach ( $recent_events as $event ) :
									$icon_class   = $this->severity_badge_class( $event->severity );
									$badge_label  = $severity_labels[ $event->severity ] ?? ucfirst( (string) $event->severity );
									$family_key   = ReportedIP_Hive_Event_Taxonomy::classify( $event->event_type );
									$family_name  = null !== $family_key ? ( $family_labels[ $family_key ] ?? $family_key ) : '';
									$time_ago     = human_time_diff( strtotime( $event->created_at ), time() );
									?>
								<li class="rip-activity-item">
									<div class="rip-activity-item__icon rip-activity-item__icon--<?php echo esc_attr( $icon_class ); ?>">
										<?php if ( $icon_class === 'danger' ) : ?>
											<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
										<?php elseif ( $icon_class === 'warning' ) : ?>
											<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
										<?php else : ?>
											<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
										<?php endif; ?>
									</div>
									<div class="rip-activity-item__content">
										<div class="rip-activity-item__title">
											<span class="rip-badge rip-badge--<?php echo esc_attr( $icon_class ); ?>"><?php echo esc_html( $badge_label ); ?></span>
											<?php echo esc_html( ucwords( str_replace( '_', ' ', $event->event_type ) ) ); ?>
											<?php if ( '' !== $family_name ) : ?>
												<span class="rip-activity-item__family"><?php echo esc_html( $family_name ); ?></span>
											<?php endif; ?>
											<span class="rip-activity-item__ip"><?php echo esc_html( $event->ip_address ); ?></span>
										</div>
										<div class="rip-activity-item__desc">
											<?php echo wp_kses_post( $this->logger->format_details( $event->details ) ); ?>
										</div>
									</div>
									<span class="rip-activity-item__time"><?php echo esc_html( $time_ago ); ?> <?php esc_html_e( 'ago', 'reportedip-hive' ); ?></span>
								</li>
								<?php endforeach; ?>
							</ul>
						<?php endif; ?>
					</div>
				</div>

				<!-- Quick Actions Section -->
				<div class="rip-dashboard__section">
					<div class="rip-dashboard__section-title">
						<h2>
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
							<?php esc_html_e( 'Quick Actions', 'reportedip-hive' ); ?>
						</h2>
					</div>

					<div class="rip-quick-actions">
						<a href="<?php echo esc_url( self::get_admin_page_url( 'admin.php?page=reportedip-hive-settings' ) ); ?>" class="rip-quick-action">
							<div class="rip-quick-action__icon">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
							</div>
							<span class="rip-quick-action__label"><?php esc_html_e( 'Settings', 'reportedip-hive' ); ?></span>
						</a>

						<a href="<?php echo esc_url( self::get_admin_page_url( 'admin.php?page=reportedip-hive-security&tab=blocked' ) ); ?>" class="rip-quick-action">
							<div class="rip-quick-action__icon">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
							</div>
							<span class="rip-quick-action__label"><?php esc_html_e( 'Blocked IPs', 'reportedip-hive' ); ?></span>
						</a>

						<a href="<?php echo esc_url( self::get_admin_page_url( 'admin.php?page=reportedip-hive-security&tab=whitelist' ) ); ?>" class="rip-quick-action">
							<div class="rip-quick-action__icon">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
							</div>
							<span class="rip-quick-action__label"><?php esc_html_e( 'Whitelist', 'reportedip-hive' ); ?></span>
						</a>

						<a href="<?php echo esc_url( self::get_admin_page_url( 'admin.php?page=reportedip-hive-security&tab=logs' ) ); ?>" class="rip-quick-action">
							<div class="rip-quick-action__icon">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
							</div>
							<span class="rip-quick-action__label"><?php esc_html_e( 'View Logs', 'reportedip-hive' ); ?></span>
						</a>

						<?php if ( $mode_manager->is_community_mode() ) : ?>
						<a href="<?php echo esc_url( self::get_admin_page_url( 'admin.php?page=reportedip-hive-security&tab=lookup' ) ); ?>" class="rip-quick-action">
							<div class="rip-quick-action__icon">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
							</div>
							<span class="rip-quick-action__label"><?php esc_html_e( 'IP Lookup', 'reportedip-hive' ); ?></span>
						</a>
						<?php endif; ?>
					</div>
				</div>

			</div><!-- /.rip-dashboard -->

		<?php self::render_page_footer(); ?>
		<?php
	}

	/**
	 * Security page - Combined IP Management and Security Logs
	 * Consolidated navigation: IP Lists | Activity | Advanced (Community only)
	 */
	public function security_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Tab navigation only, no data modification
		$active_tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'ip_lists';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Tab navigation only, no data modification
		$sub_tab = isset( $_GET['sub'] ) ? sanitize_key( wp_unslash( $_GET['sub'] ) ) : '';

		if ( $active_tab === 'blocked' || $active_tab === 'whitelist' ) {
			$sub_tab    = $active_tab;
			$active_tab = 'ip_lists';
		}
		if ( $active_tab === 'logs' || $active_tab === 'lookup' ) {
			$sub_tab    = $active_tab;
			$active_tab = 'activity';
		}
		if ( $active_tab === 'api_queue' ) {
			$active_tab = 'advanced';
		}
		if ( ! in_array( $active_tab, array( 'ip_lists', 'activity', 'advanced' ), true ) ) {
			$active_tab = 'ip_lists';
		}
		if ( ! in_array( $sub_tab, array( '', 'blocked', 'whitelist', 'logs', 'lookup', 'audit' ), true ) ) {
			$sub_tab = '';
		}

		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();

		$database    = ReportedIP_Hive_Database::get_instance();
		$queue_stats = $database->get_queue_statistics();

		self::render_page_header( __( 'Security', 'reportedip-hive' ), __( 'Manage blocked IPs, whitelist, and security logs', 'reportedip-hive' ) );
		?>

			<!-- Main Navigation Tabs -->
			<nav class="rip-nav-tabs">
				<a href="?page=reportedip-hive-security&tab=ip_lists" class="rip-nav-tabs__tab <?php echo $active_tab === 'ip_lists' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
					<?php esc_html_e( 'IP Lists', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-security&tab=activity" class="rip-nav-tabs__tab <?php echo $active_tab === 'activity' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
					<?php esc_html_e( 'Activity', 'reportedip-hive' ); ?>
				</a>
				<?php if ( $mode_manager->is_community_mode() || $queue_stats['failed'] > 0 || $queue_stats['pending'] > 0 ) : ?>
				<a href="?page=reportedip-hive-security&tab=advanced" class="rip-nav-tabs__tab <?php echo $active_tab === 'advanced' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
					<?php esc_html_e( 'Advanced', 'reportedip-hive' ); ?>
					<?php if ( $queue_stats['failed'] > 0 ) : ?>
						<span class="rip-nav-tabs__badge rip-nav-tabs__badge--danger"><?php echo (int) $queue_stats['failed']; ?></span>
					<?php endif; ?>
				</a>
				<?php endif; ?>
			</nav>

			<div class="rip-content">
				<?php
				switch ( $active_tab ) {
					case 'ip_lists':
						$this->render_ip_lists_tab( $sub_tab );
						break;
					case 'activity':
						$this->render_activity_tab( $sub_tab );
						break;
					case 'advanced':
						if ( $mode_manager->is_community_mode() || $queue_stats['failed'] > 0 || $queue_stats['pending'] > 0 ) {
							$this->render_advanced_tab();
						} else {
							$this->render_ip_lists_tab( $sub_tab );
						}
						break;
					default:
						$this->render_ip_lists_tab( $sub_tab );
				}
				?>
			</div>

		<?php self::render_page_footer(); ?>
		<?php
	}

	/**
	 * Render consolidated IP Lists tab (Blocked + Whitelist)
	 */
	private function render_ip_lists_tab( $sub_tab = '' ) {
		if ( empty( $sub_tab ) ) {
			$sub_tab = 'blocked';
		}
		?>
		<div class="rip-sub-tabs">
			<a href="?page=reportedip-hive-security&tab=ip_lists&sub=blocked" class="rip-sub-tabs__tab <?php echo $sub_tab === 'blocked' ? 'rip-sub-tabs__tab--active' : ''; ?>">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
				<?php esc_html_e( 'Blocked', 'reportedip-hive' ); ?>
				<span class="rip-sub-tabs__count"><?php echo (int) $this->database->count_blocked_ips(); ?></span>
			</a>
			<a href="?page=reportedip-hive-security&tab=ip_lists&sub=whitelist" class="rip-sub-tabs__tab <?php echo $sub_tab === 'whitelist' ? 'rip-sub-tabs__tab--active' : ''; ?>">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
				<?php esc_html_e( 'Whitelist', 'reportedip-hive' ); ?>
				<span class="rip-sub-tabs__count"><?php echo (int) $this->database->count_whitelisted_ips(); ?></span>
			</a>
		</div>

		<?php
		if ( $sub_tab === 'whitelist' ) {
			$this->render_whitelist_tab();
		} else {
			$this->render_blocked_tab();
		}
	}

	/**
	 * Render consolidated Activity tab (Logs + Lookup)
	 */
	private function render_activity_tab( $sub_tab = '' ) {
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();

		if ( empty( $sub_tab ) ) {
			$sub_tab = 'logs';
		}
		?>
		<div class="rip-sub-tabs">
			<a href="?page=reportedip-hive-security&tab=activity&sub=logs" class="rip-sub-tabs__tab <?php echo $sub_tab === 'logs' ? 'rip-sub-tabs__tab--active' : ''; ?>">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
				<?php esc_html_e( 'Event Log', 'reportedip-hive' ); ?>
			</a>
			<?php if ( $mode_manager->is_community_mode() ) : ?>
			<a href="?page=reportedip-hive-security&tab=activity&sub=lookup" class="rip-sub-tabs__tab <?php echo $sub_tab === 'lookup' ? 'rip-sub-tabs__tab--active' : ''; ?>">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
				<?php esc_html_e( 'IP Lookup', 'reportedip-hive' ); ?>
			</a>
			<?php endif; ?>
			<a href="?page=reportedip-hive-security&tab=activity&sub=audit" class="rip-sub-tabs__tab <?php echo $sub_tab === 'audit' ? 'rip-sub-tabs__tab--active' : ''; ?>">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><path d="M9 15l2 2 4-4"/></svg>
				<?php esc_html_e( 'Audit Trail', 'reportedip-hive' ); ?>
			</a>
		</div>

		<?php
		if ( $sub_tab === 'lookup' && $mode_manager->is_community_mode() ) {
			$this->render_lookup_tab();
		} elseif ( $sub_tab === 'audit' ) {
			$this->render_audit_tab();
		} else {
			$this->render_logs_tab();
		}
	}

	/**
	 * Render Advanced tab (API Queue - Community mode only)
	 */
	private function render_advanced_tab() {
		$this->render_api_queue_tab();
	}

	/**
	 * Render logs tab using WP_List_Table
	 */
	private function render_logs_tab() {
		$logs_table = new ReportedIP_Hive_Logs_Table();
		$logs_table->process_bulk_action();
		$logs_table->prepare_items();

		?>
		<form method="post">
			<input type="hidden" name="page" value="reportedip-hive-security" />
			<input type="hidden" name="tab" value="logs" />
			<?php
			$logs_table->search_box( __( 'Search', 'reportedip-hive' ), 'log-search' );
			$logs_table->display();
			?>
		</form>

		<div class="tablenav bottom">
			<a href="<?php echo esc_url( admin_url( 'admin-ajax.php?action=reportedip_hive_export_logs&format=csv&nonce=' . wp_create_nonce( 'reportedip_hive_nonce' ) ) ); ?>" class="button">
				<?php esc_html_e( 'Export CSV', 'reportedip-hive' ); ?>
			</a>
			<a href="<?php echo esc_url( admin_url( 'admin-ajax.php?action=reportedip_hive_export_logs&format=json&nonce=' . wp_create_nonce( 'reportedip_hive_nonce' ) ) ); ?>" class="button">
				<?php esc_html_e( 'Export JSON', 'reportedip-hive' ); ?>
			</a>
		</div>
		<?php
	}

	/**
	 * Render API Queue tab using WP_List_Table
	 */
	private function render_api_queue_tab() {
		$queue_table = new ReportedIP_Hive_API_Queue_Table();
		$queue_table->process_bulk_action();
		$queue_table->prepare_items();

		?>

		<div class="rip-alert rip-alert--info rip-mb-4">
			<p><?php esc_html_e( 'This page shows all pending API reports that will be sent to the ReportedIP service. Reports are processed automatically via cron (hourly). Failed reports will be retried up to 3 times.', 'reportedip-hive' ); ?></p>
		</div>

		<?php $queue_table->display_statistics(); ?>

		<form method="post">
			<input type="hidden" name="page" value="reportedip-hive-security" />
			<input type="hidden" name="tab" value="api_queue" />
			<?php
			$queue_table->search_box( __( 'Search IP', 'reportedip-hive' ), 'queue-search' );
			$queue_table->display();
			?>
		</form>

		<script type="text/javascript">
		jQuery(document).ready(function($) {
			$(document).on('click', '.retry-report', function(e) {
				e.preventDefault();
				var $button = $(this);
				var reportId = $button.data('id');

				$button.prop('disabled', true).text('<?php esc_html_e( 'Retrying...', 'reportedip-hive' ); ?>');

				$.post(ajaxurl, {
					action: 'reportedip_hive_retry_report',
					nonce: reportedip_hive_ajax.nonce,
					report_id: reportId
				}, function(response) {
					if (response.success) {
						location.reload();
					} else {
						alert(response.data || '<?php esc_html_e( 'Error retrying report', 'reportedip-hive' ); ?>');
						$button.prop('disabled', false).text('<?php esc_html_e( 'Retry', 'reportedip-hive' ); ?>');
					}
				});
			});

			$(document).on('click', '.delete-report', function(e) {
				e.preventDefault();
				var $button = $(this);
				var reportId = $button.data('id');

				if (!confirm('<?php esc_html_e( 'Are you sure you want to delete this queue item?', 'reportedip-hive' ); ?>')) {
					return;
				}

				$button.prop('disabled', true).text('<?php esc_html_e( 'Deleting...', 'reportedip-hive' ); ?>');

				$.post(ajaxurl, {
					action: 'reportedip_hive_delete_report',
					nonce: reportedip_hive_ajax.nonce,
					report_id: reportId
				}, function(response) {
					if (response.success) {
						location.reload();
					} else {
						alert(response.data || '<?php esc_html_e( 'Error deleting report', 'reportedip-hive' ); ?>');
						$button.prop('disabled', false).text('<?php esc_html_e( 'Delete', 'reportedip-hive' ); ?>');
					}
				});
			});
		});
		</script>

		<?php
	}

	/**
	 * Render blocked IPs tab using WP_List_Table
	 */
	private function render_blocked_tab() {
		$blocked_table = new ReportedIP_Hive_Blocked_IPs_Table();
		$blocked_table->process_bulk_action();
		$blocked_table->prepare_items();

		?>
		<div class="rip-card rip-mb-4">
			<div class="rip-card__header">
				<h3 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
					<?php esc_html_e( 'Block an IP Address', 'reportedip-hive' ); ?>
				</h3>
			</div>
			<div class="rip-card__body">
				<form id="block-ip-form" method="post" class="rip-form-inline">
					<div class="rip-form-group">
						<input type="text" id="block-ip-address" name="ip_address" class="rip-input" placeholder="<?php esc_html_e( 'IP Address', 'reportedip-hive' ); ?>" required />
					</div>
					<div class="rip-form-group">
						<input type="text" id="block-ip-reason" name="reason" class="rip-input" placeholder="<?php esc_html_e( 'Reason', 'reportedip-hive' ); ?>" required />
					</div>
					<div class="rip-form-group">
						<select id="block-ip-duration" name="duration" class="rip-select">
							<option value="24"><?php esc_html_e( '24 Hours', 'reportedip-hive' ); ?></option>
							<option value="72"><?php esc_html_e( '3 Days', 'reportedip-hive' ); ?></option>
							<option value="168"><?php esc_html_e( '1 Week', 'reportedip-hive' ); ?></option>
							<option value="720"><?php esc_html_e( '30 Days', 'reportedip-hive' ); ?></option>
							<option value="0"><?php esc_html_e( 'Permanent', 'reportedip-hive' ); ?></option>
						</select>
					</div>
					<button type="submit" class="rip-button rip-button--danger"><?php esc_html_e( 'Block IP', 'reportedip-hive' ); ?></button>
				</form>
			</div>
		</div>

		<div class="rip-card rip-mb-4">
			<div class="rip-card__header">
				<h3 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
					<?php esc_html_e( 'Import Blocked IPs from CSV', 'reportedip-hive' ); ?>
				</h3>
			</div>
			<div class="rip-card__body">
				<form id="import-blocked-csv-form" method="post" enctype="multipart/form-data" class="rip-form-inline">
					<div class="rip-form-group">
						<input type="file" id="blocked-csv-file" name="csv_file" class="rip-input" accept=".csv,.txt" required />
					</div>
					<div class="rip-form-group">
						<select id="blocked-import-duration" name="duration" class="rip-select">
							<option value="24"><?php esc_html_e( '24 Hours', 'reportedip-hive' ); ?></option>
							<option value="72"><?php esc_html_e( '3 Days', 'reportedip-hive' ); ?></option>
							<option value="168"><?php esc_html_e( '1 Week', 'reportedip-hive' ); ?></option>
							<option value="720" selected><?php esc_html_e( '30 Days', 'reportedip-hive' ); ?></option>
							<option value="0"><?php esc_html_e( 'Permanent', 'reportedip-hive' ); ?></option>
						</select>
					</div>
					<button type="submit" class="rip-button rip-button--secondary"><?php esc_html_e( 'Import CSV', 'reportedip-hive' ); ?></button>
				</form>
				<p class="rip-help-text rip-mt-2"><?php esc_html_e( 'CSV format: One IP address per line, or columns: ip_address, reason (optional)', 'reportedip-hive' ); ?></p>
			</div>
		</div>

		<form method="post">
			<input type="hidden" name="page" value="reportedip-hive-security" />
			<input type="hidden" name="tab" value="blocked" />
			<?php
			$blocked_table->search_box( __( 'Search', 'reportedip-hive' ), 'blocked-search' );
			$blocked_table->display();
			?>
		</form>
		<?php
	}

	/**
	 * Render whitelist tab using WP_List_Table
	 */
	private function render_whitelist_tab() {
		$whitelist_table = new ReportedIP_Hive_Whitelist_Table();
		$whitelist_table->process_bulk_action();
		$whitelist_table->prepare_items();

		?>
		<div class="rip-card rip-mb-4">
			<div class="rip-card__header">
				<h3 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
					<?php esc_html_e( 'Add to Whitelist', 'reportedip-hive' ); ?>
				</h3>
			</div>
			<div class="rip-card__body">
				<form id="add-whitelist-form" method="post" class="rip-form-inline">
					<div class="rip-form-group">
						<input type="text" id="whitelist-ip-address" name="ip_address" class="rip-input" placeholder="<?php esc_html_e( 'IP Address or CIDR', 'reportedip-hive' ); ?>" required />
					</div>
					<div class="rip-form-group">
						<input type="text" id="whitelist-reason" name="reason" class="rip-input" placeholder="<?php esc_html_e( 'Reason', 'reportedip-hive' ); ?>" />
					</div>
					<div class="rip-form-group">
						<input type="date" id="whitelist-expires" name="expires_at" class="rip-input" placeholder="<?php esc_html_e( 'Expires (optional)', 'reportedip-hive' ); ?>" />
					</div>
					<button type="submit" class="rip-button rip-button--success"><?php esc_html_e( 'Add to Whitelist', 'reportedip-hive' ); ?></button>
				</form>
			</div>
		</div>

		<div class="rip-card rip-mb-4">
			<div class="rip-card__header">
				<h3 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
					<?php esc_html_e( 'Import Whitelist from CSV', 'reportedip-hive' ); ?>
				</h3>
			</div>
			<div class="rip-card__body">
				<form id="import-whitelist-csv-form" method="post" enctype="multipart/form-data" class="rip-form-inline">
					<div class="rip-form-group">
						<input type="file" id="whitelist-csv-file" name="csv_file" class="rip-input" accept=".csv,.txt" required />
					</div>
					<button type="submit" class="rip-button rip-button--secondary"><?php esc_html_e( 'Import CSV', 'reportedip-hive' ); ?></button>
				</form>
				<p class="rip-help-text rip-mt-2"><?php esc_html_e( 'CSV format: One IP address per line, or columns: ip_address, reason (optional)', 'reportedip-hive' ); ?></p>
			</div>
		</div>

		<form method="post">
			<input type="hidden" name="page" value="reportedip-hive-security" />
			<input type="hidden" name="tab" value="whitelist" />
			<?php
			$whitelist_table->search_box( __( 'Search', 'reportedip-hive' ), 'whitelist-search' );
			$whitelist_table->display();
			?>
		</form>
		<?php
	}

	/**
	 * Render IP lookup tab
	 */
	private function render_lookup_tab() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-fill lookup field from URL, no data modification
		$lookup_ip = isset( $_GET['lookup_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['lookup_ip'] ) ) : '';
		?>
		<div class="rip-card">
			<div class="rip-card__header">
				<h3 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
					<?php esc_html_e( 'IP Address Lookup', 'reportedip-hive' ); ?>
				</h3>
			</div>
			<div class="rip-card__body">
				<p class="rip-help-text rip-mb-4"><?php esc_html_e( 'Check the reputation of any IP address using the ReportedIP.de service.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-inline rip-mb-4">
					<div class="rip-form-group">
						<input type="text" id="lookup-ip-address" class="rip-input" placeholder="<?php esc_html_e( 'Enter IP address...', 'reportedip-hive' ); ?>" value="<?php echo esc_attr( $lookup_ip ); ?>" />
					</div>
					<button type="button" class="rip-button rip-button--primary" id="lookup-ip-button">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
						<?php esc_html_e( 'Lookup', 'reportedip-hive' ); ?>
					</button>
				</div>

				<div id="lookup-results" class="rip-lookup-results rip-hidden">
					<h4 class="rip-mb-2"><?php esc_html_e( 'Lookup Results', 'reportedip-hive' ); ?></h4>
					<div id="lookup-results-content"></div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Settings page entrypoint with seven-tab navigation.
	 *
	 * Old slugs (api, security, actions, protection, logging, caching, advanced)
	 * are aliased to their new home so external links keep working.
	 */
	public function settings_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Tab navigation only, no data modification
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'general';

		$tab_aliases = array(
			'api'        => 'general',
			'security'   => 'detection',
			'protection' => 'detection',
			'actions'    => 'blocking',
			'logging'    => 'privacy_logs',
			'advanced'   => 'performance',
			'caching'    => 'performance',
			'login'      => 'hide_login',
			'hide-login' => 'hide_login',
		);
		if ( isset( $tab_aliases[ $active_tab ] ) ) {
			$active_tab = $tab_aliases[ $active_tab ];
		}

		self::render_page_header(
			__( 'Settings', 'reportedip-hive' ),
			__( 'Configure how ReportedIP Hive protects your site — grouped by topic so you can find what you need quickly.', 'reportedip-hive' )
		);
		?>

			<nav class="rip-nav-tabs">
				<a href="?page=reportedip-hive-settings&tab=general" class="rip-nav-tabs__tab <?php echo $active_tab === 'general' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
					<?php esc_html_e( 'General', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-settings&tab=detection" class="rip-nav-tabs__tab <?php echo $active_tab === 'detection' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
					<?php esc_html_e( 'Detection', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-settings&tab=blocking" class="rip-nav-tabs__tab <?php echo $active_tab === 'blocking' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
					<?php esc_html_e( 'Blocking', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-settings&tab=hide_login" class="rip-nav-tabs__tab <?php echo $active_tab === 'hide_login' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/><line x1="4" y1="20" x2="20" y2="4"/></svg>
					<?php esc_html_e( 'Hide Login', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-settings&tab=notifications" class="rip-nav-tabs__tab <?php echo $active_tab === 'notifications' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
					<?php esc_html_e( 'Notifications', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-settings&tab=privacy_logs" class="rip-nav-tabs__tab <?php echo $active_tab === 'privacy_logs' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="15" y2="17"/></svg>
					<?php esc_html_e( 'Privacy & Logs', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-settings&tab=performance" class="rip-nav-tabs__tab <?php echo $active_tab === 'performance' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
					<?php esc_html_e( 'Performance & Tools', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-settings&tab=two_factor" class="rip-nav-tabs__tab <?php echo $active_tab === 'two_factor' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
					<?php esc_html_e( 'Two-Factor Auth', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-settings&tab=hardening_mode" class="rip-nav-tabs__tab <?php echo $active_tab === 'hardening_mode' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L3 6v6c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V6l-9-4z"/><polyline points="9 12 11 14 15 10"/></svg>
					<?php esc_html_e( 'Hardening Mode', 'reportedip-hive' ); ?>
					<?php
					$hm_status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'hardening_mode' );
					echo ' ';
					self::render_tier_marker( $hm_status, array( 'link' => false ) );
					?>
				</a>
			</nav>

			<div class="rip-content">
				<?php
				switch ( $active_tab ) {
					case 'general':
						$this->render_general_settings_tab();
						break;
					case 'detection':
						$this->render_detection_tab();
						break;
					case 'blocking':
						$this->render_blocking_tab();
						break;
					case 'hide_login':
						$this->render_hide_login_tab();
						break;
					case 'notifications':
						$this->render_notifications_tab();
						break;
					case 'privacy_logs':
						$this->render_privacy_logs_tab();
						break;
					case 'performance':
						$this->render_performance_advanced_tab();
						break;
					case 'two_factor':
						ReportedIP_Hive_Two_Factor_Admin::render_global_settings();
						break;
					case 'hardening_mode':
						$this->render_hardening_mode_tab();
						break;
					default:
						$this->render_general_settings_tab();
				}
				?>
			</div>

		<?php self::render_page_footer(); ?>
		<?php
	}

	/**
	 * Render General settings tab (Mode + API Configuration)
	 */
	private function render_general_settings_tab() {
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		?>
		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="8" stroke="currentColor" stroke-width="2" fill="none"/><path d="M2 10h16M10 2c2.8 2.8 4.4 6.5 4.4 8s-1.6 5.2-4.4 8" stroke="currentColor" stroke-width="1.5" fill="none"/></svg>
				<?php esc_html_e( 'Operation Mode', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc"><?php esc_html_e( 'Choose how ReportedIP Hive should operate. You can switch modes at any time.', 'reportedip-hive' ); ?></p>

			<form method="post" action="<?php echo esc_url( self::settings_form_action() ); ?>" class="rip-form rip-form--mode">
				<?php settings_fields( 'reportedip_hive_general' ); ?>
				<?php self::render_mode_comparison( array( 'interactive' => true ) ); ?>
				<p class="rip-help-text"><?php esc_html_e( 'Mode changes take effect immediately after saving.', 'reportedip-hive' ); ?></p>
				<div class="rip-form-actions">
					<?php submit_button( __( 'Save Mode', 'reportedip-hive' ), 'rip-button rip-button--primary', 'submit', false ); ?>
				</div>
			</form>
		</div>

		<?php if ( $mode_manager->is_community_mode() ) : ?>
		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
				<?php esc_html_e( 'API Configuration', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc"><?php esc_html_e( 'Connect to the ReportedIP community network for enhanced protection.', 'reportedip-hive' ); ?></p>

			<form method="post" action="<?php echo esc_url( self::settings_form_action() ); ?>" class="rip-form">
				<?php settings_fields( 'reportedip_hive_api' ); ?>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_api_key"><?php esc_html_e( 'API Key', 'reportedip-hive' ); ?></label>
					<input type="password" id="reportedip_hive_api_key" name="reportedip_hive_api_key" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' ) ); ?>" class="rip-input" />
					<p class="rip-help-text">
						<?php esc_html_e( 'Your ReportedIP.de API key.', 'reportedip-hive' ); ?>
						<a href="https://reportedip.de/dashboard/api-keys" target="_blank"><?php esc_html_e( 'Get API Key', 'reportedip-hive' ); ?></a>
					</p>
				</div>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_api_endpoint"><?php esc_html_e( 'API Endpoint', 'reportedip-hive' ); ?></label>
					<input type="url" id="reportedip_hive_api_endpoint" name="reportedip_hive_api_endpoint" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_endpoint', 'https://reportedip.de/wp-json/reportedip/v2/' ) ); ?>" class="rip-input" />
					<p class="rip-help-text"><?php esc_html_e( 'The ReportedIP.de API endpoint URL.', 'reportedip-hive' ); ?></p>
				</div>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_trusted_ip_header">
						<?php esc_html_e( 'Trusted IP Header', 'reportedip-hive' ); ?>
					</label>
					<select name="reportedip_hive_trusted_ip_header" id="reportedip_hive_trusted_ip_header" class="rip-input">
						<option value="" <?php selected( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_trusted_ip_header', '' ), '' ); ?>>
							<?php esc_html_e( 'None (REMOTE_ADDR only)', 'reportedip-hive' ); ?>
						</option>
						<option value="HTTP_CF_CONNECTING_IP" <?php selected( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_trusted_ip_header', '' ), 'HTTP_CF_CONNECTING_IP' ); ?>>
							<?php esc_html_e( 'Cloudflare (CF-Connecting-IP)', 'reportedip-hive' ); ?>
						</option>
						<option value="HTTP_X_REAL_IP" <?php selected( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_trusted_ip_header', '' ), 'HTTP_X_REAL_IP' ); ?>>
							<?php esc_html_e( 'Nginx (X-Real-IP)', 'reportedip-hive' ); ?>
						</option>
						<option value="HTTP_X_FORWARDED_FOR" <?php selected( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_trusted_ip_header', '' ), 'HTTP_X_FORWARDED_FOR' ); ?>>
							<?php esc_html_e( 'Generic Proxy (X-Forwarded-For)', 'reportedip-hive' ); ?>
						</option>
						<option value="HTTP_CLIENT_IP" <?php selected( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_trusted_ip_header', '' ), 'HTTP_CLIENT_IP' ); ?>>
							<?php esc_html_e( 'Client-IP Header', 'reportedip-hive' ); ?>
						</option>
					</select>
					<p class="rip-help-text">
						<?php esc_html_e( 'Select which HTTP header to trust for determining the client IP. Use "None" unless your site is behind a reverse proxy.', 'reportedip-hive' ); ?>
					</p>
				</div>

				<div class="rip-form-actions">
					<button type="button" class="rip-button rip-button--secondary" id="test-api-connection-general">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
						<?php esc_html_e( 'Test Connection', 'reportedip-hive' ); ?>
					</button>
					<?php submit_button( __( 'Save Changes', 'reportedip-hive' ), 'rip-button rip-button--primary', 'submit', false ); ?>
				</div>
				<div id="api-test-result" class="rip-api-result"></div>
			</form>
		</div>
		<?php endif; ?>
		<?php
	}

	/**
	 * Tab: Detection — what is monitored and at which thresholds.
	 *
	 * Plain-language framing: every section answers "what triggers an
	 * incident, and how many tries within how much time".
	 *
	 * @since 1.2.0
	 */
	private function render_detection_tab() {
		?>
		<form method="post" action="<?php echo esc_url( self::settings_form_action() ); ?>" class="rip-form">
			<?php settings_fields( 'reportedip_hive_protection_detection' ); ?>

			<?php /* Checkbox-off fallbacks — see render_global_settings() in class-two-factor-admin.php for context. */ ?>
			<input type="hidden" name="reportedip_hive_monitor_failed_logins" value="0" />
			<input type="hidden" name="reportedip_hive_monitor_comments" value="0" />
			<input type="hidden" name="reportedip_hive_monitor_xmlrpc" value="0" />
			<input type="hidden" name="reportedip_hive_monitor_app_passwords" value="0" />
			<input type="hidden" name="reportedip_hive_app_password_require_2fa" value="0" />
			<input type="hidden" name="reportedip_hive_monitor_rest_api" value="0" />
			<input type="hidden" name="reportedip_hive_block_user_enumeration" value="0" />
			<input type="hidden" name="reportedip_hive_monitor_404_scans" value="0" />
			<input type="hidden" name="reportedip_hive_bot_allowlist_enabled" value="0" />
			<input type="hidden" name="reportedip_hive_monitor_woocommerce" value="0" />
			<input type="hidden" name="reportedip_hive_monitor_geo_anomaly" value="0" />
			<input type="hidden" name="reportedip_hive_geo_revoke_trusted_devices" value="0" />
			<input type="hidden" name="reportedip_hive_geo_report_to_api" value="0" />
			<input type="hidden" name="reportedip_hive_password_policy_enabled" value="0" />
			<input type="hidden" name="reportedip_hive_password_check_hibp" value="0" />
			<input type="hidden" name="reportedip_hive_password_policy_all_users" value="0" />

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
					<?php esc_html_e( 'Failed login attempts', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Catches password-guessing attacks. We count wrong passwords per IP. Once an IP exceeds the limit within the window, it is treated as a threat. A second layer also fires if one IP probes many different usernames in a short window (password-spray / credential-stuffing).', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_failed_logins" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_failed_logins', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch failed logins', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_failed_login_threshold"><?php esc_html_e( 'How many wrong passwords?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_failed_login_threshold" name="reportedip_hive_failed_login_threshold" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_failed_login_threshold', 5 ) ); ?>" min="1" max="100" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Trigger after this many failed attempts from one IP. 5 is a good starting point.', 'reportedip-hive' ); ?></p>
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_failed_login_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_failed_login_timeframe" name="reportedip_hive_failed_login_timeframe" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_failed_login_timeframe', 15 ) ); ?>" min="1" max="1440" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Counters reset after this window. Shorter = stricter, but more sensitive to legitimate users mistyping their password.', 'reportedip-hive' ); ?></p>
					</div>
				</div>

				<h3 class="rip-settings-subsection__title"><?php esc_html_e( 'Password-spray detection', 'reportedip-hive' ); ?></h3>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Triggers when one IP tries many different usernames quickly — a stronger signal than the per-IP attempt count above.', 'reportedip-hive' ); ?></p>
				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_password_spray_threshold"><?php esc_html_e( 'How many distinct usernames?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_password_spray_threshold" name="reportedip_hive_password_spray_threshold" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_password_spray_threshold', 5 ) ); ?>" min="2" max="100" class="rip-input" />
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_password_spray_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_password_spray_timeframe" name="reportedip_hive_password_spray_timeframe" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_password_spray_timeframe', 10 ) ); ?>" min="1" max="1440" class="rip-input" />
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
					<?php esc_html_e( 'Comment spam', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'When the same IP submits comments that WordPress flags as spam in rapid succession, treat that IP as a threat.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_comments" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_comments', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch comment spam', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_comment_spam_threshold"><?php esc_html_e( 'How many spam comments?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_comment_spam_threshold" name="reportedip_hive_comment_spam_threshold" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_spam_threshold', 5 ) ); ?>" min="1" max="50" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Counts comments WordPress already marked as spam. 3 catches most bots.', 'reportedip-hive' ); ?></p>
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_comment_spam_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_comment_spam_timeframe" name="reportedip_hive_comment_spam_timeframe" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_spam_timeframe', 60 ) ); ?>" min="1" max="1440" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Counter window. Real spammers post quickly — 60 minutes is generous.', 'reportedip-hive' ); ?></p>
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
					<?php esc_html_e( 'XML-RPC abuse', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'XML-RPC is an older WordPress remote-control interface that bots often hammer to brute-force passwords. Most modern sites do not actively use it.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_xmlrpc" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_xmlrpc', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch XML-RPC requests', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_xmlrpc_threshold"><?php esc_html_e( 'How many requests?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_xmlrpc_threshold" name="reportedip_hive_xmlrpc_threshold" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_xmlrpc_threshold', 10 ) ); ?>" min="1" max="100" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Trigger after this many XML-RPC calls from one IP.', 'reportedip-hive' ); ?></p>
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_xmlrpc_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_xmlrpc_timeframe" name="reportedip_hive_xmlrpc_timeframe" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_xmlrpc_timeframe', 60 ) ); ?>" min="1" max="1440" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Counter window for XML-RPC requests.', 'reportedip-hive' ); ?></p>
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 1v6m0 6v6"/><path d="m4.22 4.22 4.24 4.24m6.36 6.36 4.24 4.24"/><path d="M1 12h6m6 0h6"/><path d="m4.22 19.78 4.24-4.24m6.36-6.36 4.24-4.24"/></svg>
					<?php esc_html_e( 'Application password abuse', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Application passwords authenticate over REST and XML-RPC and skip the normal login 2FA prompt. We rate-limit failed app-password sign-ins and can optionally block new app passwords for 2FA-enforced roles until enrolment is finished.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_app_passwords" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_app_passwords', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch application-password authentications', 'reportedip-hive' ); ?></span>
					</label>
				</div>
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_app_password_require_2fa" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_app_password_require_2fa', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Block app-password creation until 2FA enrolment is finished (for enforced roles)', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_app_password_threshold"><?php esc_html_e( 'How many failed auths?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_app_password_threshold" name="reportedip_hive_app_password_threshold" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_app_password_threshold', 5 ) ); ?>" min="1" max="100" class="rip-input" />
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_app_password_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_app_password_timeframe" name="reportedip_hive_app_password_timeframe" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_app_password_timeframe', 15 ) ); ?>" min="1" max="1440" class="rip-input" />
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
					<?php esc_html_e( 'REST API abuse', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Per-IP rate limit on /wp-json/* requests. Catches scrapers and vulnerability scanners that hammer the REST surface. Sensitive routes (/wp/v2/users, /wp/v2/comments) use a tighter threshold by default.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_rest_api" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_rest_api', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch REST API requests', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_rest_threshold"><?php esc_html_e( 'Global requests threshold', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_rest_threshold" name="reportedip_hive_rest_threshold" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_rest_threshold', 240 ) ); ?>" min="1" max="1000" class="rip-input" />
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_rest_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_rest_timeframe" name="reportedip_hive_rest_timeframe" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_rest_timeframe', 5 ) ); ?>" min="1" max="1440" class="rip-input" />
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_rest_sensitive_threshold"><?php esc_html_e( 'Sensitive-route threshold', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_rest_sensitive_threshold" name="reportedip_hive_rest_sensitive_threshold" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_rest_sensitive_threshold', 20 ) ); ?>" min="1" max="500" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Tighter limit for /wp/v2/users and /wp/v2/comments.', 'reportedip-hive' ); ?></p>
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_rest_sensitive_timeframe"><?php esc_html_e( 'Sensitive timeframe (min)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_rest_sensitive_timeframe" name="reportedip_hive_rest_sensitive_timeframe" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_rest_sensitive_timeframe', 5 ) ); ?>" min="1" max="1440" class="rip-input" />
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
					<?php esc_html_e( 'User enumeration defence', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Closes the four classic username-leak vectors: ?author= probes, /wp-json/wp/v2/users, oEmbed author leaks, and the verbose "user does not exist" login error. Repeated probes from one IP also trip the auto-block.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_block_user_enumeration" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_user_enumeration', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Block username discovery and unify login errors', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_user_enum_threshold"><?php esc_html_e( 'How many probes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_user_enum_threshold" name="reportedip_hive_user_enum_threshold" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_user_enum_threshold', 5 ) ); ?>" min="1" max="100" class="rip-input" />
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_user_enum_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_user_enum_timeframe" name="reportedip_hive_user_enum_timeframe" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_user_enum_timeframe', 5 ) ); ?>" min="1" max="1440" class="rip-input" />
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
					<?php esc_html_e( '404 / Scanner detection', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Catches vulnerability scanners. A single hit on a known-bad path (.env, wp-config.php.bak, /.git/config, /phpmyadmin, …) triggers immediately; bursts of regular 404s also count.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_404_scans" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_404_scans', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch suspicious 404s and known scanner paths', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_scan_404_threshold"><?php esc_html_e( '404 burst threshold', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_scan_404_threshold" name="reportedip_hive_scan_404_threshold" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_scan_404_threshold', 12 ) ); ?>" min="1" max="100" class="rip-input" />
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_scan_404_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_scan_404_timeframe" name="reportedip_hive_scan_404_timeframe" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_scan_404_timeframe', 2 ) ); ?>" min="1" max="1440" class="rip-input" />
					</div>
				</div>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_bot_allowlist_enabled" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_bot_allowlist_enabled', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Skip burst triggers for verified search engines and AI crawlers (User-Agent based)', 'reportedip-hive' ); ?></span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'Googlebot, Bingbot, DuckDuckBot, GPTBot, ClaudeBot, PerplexityBot, Amazonbot and similar crawlers are exempt from the 404 burst trigger and the REST burst trigger. Pattern-based detection (.env, wp-config.php.bak, /phpmyadmin/, …) stays active for all visitors, including spoofed bot User-Agents.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"/><line x1="3" y1="6" x2="21" y2="6"/><path d="M16 10a4 4 0 0 1-8 0"/></svg>
					<?php esc_html_e( 'WooCommerce login', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Hooks into WooCommerce-specific login failures (my-account form, checkout AJAX login). Uses the same threshold as Failed login attempts.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_woocommerce" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_woocommerce', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch WooCommerce login attempts', 'reportedip-hive' ); ?></span>
					</label>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
					<?php esc_html_e( 'Geographic anomaly', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Watches successful logins. When a user signs in from a country or network (ASN) not seen in the recent look-back window, the event is logged and trusted-device cookies can be revoked to force a fresh 2FA challenge. Location data reuses the cached community lookup, so no extra request is made.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_geo_anomaly" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_geo_anomaly', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch logins from new countries / networks', 'reportedip-hive' ); ?></span>
					</label>
				</div>
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_geo_revoke_trusted_devices" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_geo_revoke_trusted_devices', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Revoke trusted-device cookies on geo anomaly (forces 2FA on next login)', 'reportedip-hive' ); ?></span>
					</label>
				</div>
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_geo_report_to_api" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_geo_report_to_api', false ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Also share anomalies with the community network (off by default — informational)', 'reportedip-hive' ); ?></span>
					</label>
				</div>
				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_geo_window_days"><?php esc_html_e( 'Look-back window (days)', 'reportedip-hive' ); ?></label>
					<input type="number" id="reportedip_hive_geo_window_days" name="reportedip_hive_geo_window_days" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_geo_window_days', 90 ) ); ?>" min="1" max="365" class="rip-input" style="max-width: 180px;" />
					<p class="rip-help-text"><?php esc_html_e( 'How long a country/ASN stays "known" for a user.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><line x1="12" y1="15" x2="12" y2="18"/></svg>
					<?php esc_html_e( 'Password strength policy', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Enforces a minimum length, character-class diversity and an optional public-breach check (HaveIBeenPwned k-anonymity — only the first 5 SHA-1 hex characters of the password leave the server). Applies to users in the 2FA-enforced roles by default.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_password_policy_enabled" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_password_policy_enabled', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Enforce password policy', 'reportedip-hive' ); ?></span>
					</label>
				</div>
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_password_check_hibp" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_password_check_hibp', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Reject passwords that appear in public breaches (HaveIBeenPwned, k-anonymity protocol)', 'reportedip-hive' ); ?></span>
					</label>
				</div>
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_password_policy_all_users" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_password_policy_all_users', false ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Apply to all users (default: only 2FA-enforced roles)', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_password_min_length"><?php esc_html_e( 'Minimum length', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_password_min_length" name="reportedip_hive_password_min_length" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_password_min_length', 12 ) ); ?>" min="8" max="128" class="rip-input" />
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_password_min_classes"><?php esc_html_e( 'Required character classes (lower / upper / digit / symbol)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_password_min_classes" name="reportedip_hive_password_min_classes" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_password_min_classes', 3 ) ); ?>" min="1" max="4" class="rip-input" />
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L3 7v6c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V7l-9-5z"/></svg>
					<?php esc_html_e( 'Decoy Path Block', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc">
					<?php
					printf(
						/* translators: 1: opening link tag to the Firewall Scan & Decoy tab, 2: closing link tag. */
						esc_html__( 'The decoy-path trap, its auto-managed .htaccess block and the server-config snippets now live on the %1$sFirewall › Scan & Decoy%2$s tab, next to the scan detector.', 'reportedip-hive' ),
						'<a href="' . esc_url( admin_url( 'admin.php?page=reportedip-hive-firewall&tab=scan' ) ) . '">',
						'</a>'
					);
					?>
				</p>
			</div>

			<div class="rip-form-actions">
				<?php submit_button( __( 'Save detection settings', 'reportedip-hive' ), 'rip-button rip-button--primary', 'submit', false ); ?>
			</div>
		</form>
		<?php
	}

	/**
	 * Tab: Blocking — what to do once an incident has been detected.
	 *
	 * Plain-language framing: "do we block, for how long, and at what
	 * community-confidence level."
	 *
	 * @since 1.2.0
	 */
	private function render_blocking_tab() {
		?>
		<form method="post" action="<?php echo esc_url( self::settings_form_action() ); ?>" class="rip-form">
			<?php settings_fields( 'reportedip_hive_protection_blocking' ); ?>

			<?php /* Checkbox-off fallbacks. */ ?>
			<input type="hidden" name="reportedip_hive_auto_block" value="0" />
			<input type="hidden" name="reportedip_hive_report_only_mode" value="0" />
			<input type="hidden" name="reportedip_hive_block_escalation_enabled" value="0" />

			<div class="rip-card rip-decision-flow rip-mb-4">
				<h3 class="rip-decision-flow__title"><?php esc_html_e( 'How blocking decides', 'reportedip-hive' ); ?></h3>
				<ol class="rip-decision-flow__steps">
					<li>
						<span class="rip-decision-flow__num">1</span>
						<div>
							<strong><?php esc_html_e( 'Report-only mode wins above everything.', 'reportedip-hive' ); ?></strong>
							<p><?php esc_html_e( 'If on, the plugin only logs and never blocks. Step 2 and 3 are bypassed.', 'reportedip-hive' ); ?></p>
						</div>
					</li>
					<li>
						<span class="rip-decision-flow__num">2</span>
						<div>
							<strong><?php esc_html_e( 'Auto-blocking must be on for any block to happen.', 'reportedip-hive' ); ?></strong>
							<p><?php esc_html_e( 'Off = the plugin watches but never inserts an IP into the block list.', 'reportedip-hive' ); ?></p>
						</div>
					</li>
					<li>
						<span class="rip-decision-flow__num">3</span>
						<div>
							<strong><?php esc_html_e( 'Progressive blocking controls the duration.', 'reportedip-hive' ); ?></strong>
							<p><?php esc_html_e( 'On = ladder (5 min → … → 7 d). Off = the fixed "Block length" below. Whitelist entries always win.', 'reportedip-hive' ); ?></p>
						</div>
					</li>
				</ol>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
					<?php esc_html_e( 'Auto-blocking', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'When detection triggers, automatically block the offender. Disable this if you only want to monitor — none of the duration settings below take effect when this is off.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_auto_block" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_block', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Block IPs automatically when a threshold is crossed', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div id="rip-blocking-dependent-fields">
					<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
						<div class="rip-form-group">
							<label class="rip-label" for="reportedip_hive_block_threshold"><?php esc_html_e( 'Community confidence to block', 'reportedip-hive' ); ?></label>
							<input type="number" id="reportedip_hive_block_threshold" name="reportedip_hive_block_threshold" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_threshold', 75 ) ); ?>" min="0" max="100" class="rip-input" />
							<p class="rip-help-text"><?php esc_html_e( 'When community-mode is on, only block IPs the network is at least this confident about (0–100). Lower = more aggressive but more false positives.', 'reportedip-hive' ); ?></p>
						</div>
					</div>

					<h3 class="rip-settings-subsection__title">
						<?php esc_html_e( 'Block duration strategy', 'reportedip-hive' ); ?>
						<span class="rip-required" aria-hidden="true">*</span>
					</h3>
					<p class="rip-help-text rip-mb-3"><?php esc_html_e( 'Pick one: a fixed length, or the progressive ladder. The ladder is recommended — legitimate visitors who trip once recover in minutes, repeat offenders still pay full price.', 'reportedip-hive' ); ?></p>

					<div class="rip-form-group">
						<label class="rip-toggle">
							<input type="checkbox" id="rip-block-escalation-toggle" name="reportedip_hive_block_escalation_enabled" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_escalation_enabled', true ) ); ?> />
							<span class="rip-toggle__slider"></span>
							<span class="rip-toggle__label"><?php esc_html_e( 'Use a progressive ladder (recommended)', 'reportedip-hive' ); ?></span>
						</label>
					</div>

					<div id="rip-blocking-fixed-fields" class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_block_duration"><?php esc_html_e( 'Block length (hours)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_block_duration" name="reportedip_hive_block_duration" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_duration', 24 ) ); ?>" min="0" max="8760" class="rip-input" style="max-width:200px;" />
						<p class="rip-help-text"><?php esc_html_e( 'Used when the progressive ladder is OFF. 0 = permanent.', 'reportedip-hive' ); ?></p>
					</div>

					<div id="rip-blocking-ladder-fields" class="rip-grid rip-grid-cols-2 rip-gap-4">
						<div class="rip-form-group">
							<label class="rip-label" for="reportedip_hive_block_ladder_minutes"><?php esc_html_e( 'Ladder (minutes, comma-separated)', 'reportedip-hive' ); ?></label>
							<?php
							$ladder_value = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_ladder_minutes', '' );
							if ( '' === trim( $ladder_value ) ) {
								$ladder_value = implode( ',', ReportedIP_Hive_Block_Escalation::DEFAULT_LADDER_MINUTES );
							}
							?>
							<input type="text" id="reportedip_hive_block_ladder_minutes" name="reportedip_hive_block_ladder_minutes" value="<?php echo esc_attr( $ladder_value ); ?>" class="rip-input" placeholder="5,15,30,1440,2880,10080" />
							<p class="rip-help-text"><?php esc_html_e( 'Default: 5,15,30,1440,2880,10080 — 5 min, 15 min, 30 min, 24 h, 48 h, 7 d. The last entry caps the ladder; further offences keep getting that duration.', 'reportedip-hive' ); ?></p>
						</div>
						<div class="rip-form-group">
							<label class="rip-label" for="reportedip_hive_block_ladder_reset_days"><?php esc_html_e( 'Reset window (days)', 'reportedip-hive' ); ?></label>
							<input type="number" id="reportedip_hive_block_ladder_reset_days" name="reportedip_hive_block_ladder_reset_days" value="<?php echo esc_attr( (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_ladder_reset_days', ReportedIP_Hive_Block_Escalation::DEFAULT_RESET_DAYS ) ); ?>" min="1" max="365" class="rip-input" style="max-width: 200px;" />
							<p class="rip-help-text"><?php esc_html_e( 'After this many days without a new block, the IP starts again at ladder step 1.', 'reportedip-hive' ); ?></p>
						</div>
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
					<?php esc_html_e( 'Report-only mode', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Audit mode: detect and log incidents but do not block anyone. Useful before flipping enforcement on.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_report_only_mode" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch and report only — never block', 'reportedip-hive' ); ?></span>
					</label>
					<div class="rip-alert rip-alert--warning rip-mt-2">
						<strong><?php esc_html_e( 'Heads up:', 'reportedip-hive' ); ?></strong>
						<?php esc_html_e( 'When this is on, no IP is blocked even if Auto-blocking is enabled.', 'reportedip-hive' ); ?>
					</div>
				</div>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_report_cooldown_hours"><?php esc_html_e( 'Report cool-down (hours)', 'reportedip-hive' ); ?></label>
					<input type="number" id="reportedip_hive_report_cooldown_hours" name="reportedip_hive_report_cooldown_hours" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_cooldown_hours', 24 ) ); ?>" min="0" max="168" class="rip-input" style="max-width: 180px;" />
					<p class="rip-help-text"><?php esc_html_e( 'Wait at least this long before re-reporting the same IP to the community network. Prevents duplicate reports.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
					<?php esc_html_e( 'Blocked-page contact link', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Optional URL shown to blocked visitors if they think the block is a mistake. Accepts a full https:// URL (e.g. your contact form) or a "mailto:" link. Leave empty to hide the link.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-label rip-sr-only" for="reportedip_hive_blocked_page_contact_url"><?php esc_html_e( 'Contact URL', 'reportedip-hive' ); ?></label>
					<input type="text" id="reportedip_hive_blocked_page_contact_url" name="reportedip_hive_blocked_page_contact_url" value="<?php echo esc_attr( (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_blocked_page_contact_url', '' ) ); ?>" class="rip-input" placeholder="<?php echo esc_attr( 'mailto:' . get_option( 'admin_email', '' ) ); ?>" inputmode="url" />
					<p class="rip-help-text">
						<?php esc_html_e( 'Quick option:', 'reportedip-hive' ); ?>
						<button type="button" class="rip-button rip-button--ghost rip-button--sm" id="rip-use-admin-email" data-value="<?php echo esc_attr( 'mailto:' . get_option( 'admin_email', '' ) ); ?>">
							<?php
							/* translators: %s: site admin email address */
							echo esc_html( sprintf( __( 'Use site admin email (%s)', 'reportedip-hive' ), (string) get_option( 'admin_email', '' ) ) );
							?>
						</button>
					</p>
					<script>
					(function () {
						var btn = document.getElementById('rip-use-admin-email');
						var inp = document.getElementById('reportedip_hive_blocked_page_contact_url');
						if (!btn || !inp) { return; }
						btn.addEventListener('click', function () {
							inp.value = btn.getAttribute('data-value') || '';
							inp.focus();
						});
					})();
					</script>
				</div>
			</div>

			<div class="rip-form-actions">
				<?php submit_button( __( 'Save blocking settings', 'reportedip-hive' ), 'rip-button rip-button--primary', 'submit', false ); ?>
			</div>

			<script>
			(function () {
				var autoBlock   = document.querySelector('input[name="reportedip_hive_auto_block"][type="checkbox"]');
				var escalation  = document.getElementById('rip-block-escalation-toggle');
				var dependent   = document.getElementById('rip-blocking-dependent-fields');
				var fixedFields = document.getElementById('rip-blocking-fixed-fields');
				var ladderRow   = document.getElementById('rip-blocking-ladder-fields');
				if (!dependent || !fixedFields || !ladderRow) { return; }

				var sync = function () {
					var blocking = autoBlock ? autoBlock.checked : true;
					dependent.classList.toggle('rip-is-disabled', !blocking);
					var ladder = escalation ? escalation.checked : true;
					fixedFields.style.display = ladder ? 'none' : '';
					ladderRow.style.display   = ladder ? '' : 'none';
				};

				if (autoBlock)  { autoBlock.addEventListener('change', sync); }
				if (escalation) { escalation.addEventListener('change', sync); }
				sync();
			})();
			</script>
		</form>
		<?php
	}

	/**
	 * Tab: Hide Login — moves wp-login.php behind a custom slug.
	 *
	 * @since 1.2.0
	 */
	private function render_hide_login_tab() {
		$hide_login = class_exists( 'ReportedIP_Hive_Hide_Login' )
			? ReportedIP_Hive_Hide_Login::get_instance()
			: null;

		$enabled         = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_enabled', false );
		$slug            = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_slug', '' );
		$response_mode   = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_response_mode', ReportedIP_Hive_Hide_Login::RESPONSE_MODE_BLOCK_PAGE );
		$token_in_urls   = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_token_in_urls', true );
		$probe_enabled   = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_hide_login_probe', true );
		$probe_threshold = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_probe_threshold', 5 );
		$probe_timeframe = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_probe_timeframe', 10 );
		$preview_url     = $hide_login && $hide_login->is_active() ? $hide_login->get_login_url() : '';
		$kill_switch     = defined( 'REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN' ) && REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN;
		?>
		<form method="post" action="<?php echo esc_url( self::settings_form_action() ); ?>" class="rip-form">
			<?php settings_fields( 'reportedip_hive_hide_login' ); ?>

			<?php /* Checkbox-off fallbacks. */ ?>
			<input type="hidden" name="reportedip_hive_hide_login_enabled" value="0" />
			<input type="hidden" name="reportedip_hive_hide_login_token_in_urls" value="0" />

			<?php if ( $kill_switch ) : ?>
				<div class="rip-alert rip-alert--warning rip-mb-4">
					<strong><?php esc_html_e( 'Kill switch is active.', 'reportedip-hive' ); ?></strong>
					<?php esc_html_e( 'The constant REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN is defined as true in wp-config.php — Hide Login is disabled until you remove it. This is the recovery path: if you ever lose your custom slug, drop the constant in and the original wp-login.php is reachable again.', 'reportedip-hive' ); ?>
				</div>
			<?php endif; ?>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
					<?php esc_html_e( 'Hide WordPress login', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Move wp-login.php behind a custom slug. Bots that scan default WordPress paths will no longer find a login form to brute-force.', 'reportedip-hive' ); ?></p>

				<div class="rip-alert rip-alert--info rip-mb-4">
					<strong><?php esc_html_e( 'Heads up — this is security through obscurity.', 'reportedip-hive' ); ?></strong>
					<?php esc_html_e( 'Hiding the login URL stops automated scanners but does not replace strong passwords, 2FA or rate limiting. Use it as one layer of a defense-in-depth setup.', 'reportedip-hive' ); ?>
				</div>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" id="rip-hide-login-enabled" name="reportedip_hive_hide_login_enabled" value="1" class="rip-toggle__input" <?php checked( $enabled ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Enable Hide Login', 'reportedip-hive' ); ?></span>
					</label>
				</div>
			</div>

			<div id="rip-hide-login-dependent-fields"<?php echo $enabled ? '' : ' class="rip-is-disabled"'; ?>>
				<div class="rip-settings-section">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_hide_login_slug"><?php esc_html_e( 'Custom login slug', 'reportedip-hive' ); ?></label>
						<div class="rip-input-row" style="display:flex; align-items:center; gap:.5rem;">
							<span class="rip-help-text" style="white-space:nowrap;"><?php echo esc_html( trailingslashit( home_url() ) ); ?></span>
							<input type="text" id="reportedip_hive_hide_login_slug" name="reportedip_hive_hide_login_slug" value="<?php echo esc_attr( $slug ); ?>" class="rip-input" placeholder="welcome" autocomplete="off" spellcheck="false" <?php disabled( ! $enabled ); ?> />
						</div>
						<p class="rip-help-text">
							<?php esc_html_e( '3–50 characters: lowercase letters, digits, dashes or underscores. Reserved WordPress paths and existing post/page/author slugs are rejected.', 'reportedip-hive' ); ?>
						</p>
						<?php if ( '' !== $preview_url ) : ?>
							<p class="rip-help-text">
								<strong><?php esc_html_e( 'Active login URL:', 'reportedip-hive' ); ?></strong>
								<code><?php echo esc_html( $preview_url ); ?></code>
							</p>
						<?php endif; ?>
					</div>
				</div>

				<div class="rip-settings-section">
					<h2 class="rip-settings-section__title">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
						<?php esc_html_e( 'What visitors see at the old URL', 'reportedip-hive' ); ?>
					</h2>
					<p class="rip-settings-section__desc"><?php esc_html_e( 'Choose the response when someone hits wp-login.php or wp-admin without being logged in.', 'reportedip-hive' ); ?></p>

					<div class="rip-form-group">
						<label class="rip-radio">
							<input type="radio" name="reportedip_hive_hide_login_response_mode" value="block_page" <?php checked( $response_mode, 'block_page' ); ?> <?php disabled( ! $enabled ); ?> />
							<span><strong><?php esc_html_e( 'Hive block page (recommended)', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'shows the same 403 page as a blocked IP. Branded and friendly to legitimate users who got there by accident.', 'reportedip-hive' ); ?></span>
						</label>
						<label class="rip-radio">
							<input type="radio" name="reportedip_hive_hide_login_response_mode" value="404" <?php checked( $response_mode, '404' ); ?> <?php disabled( ! $enabled ); ?> />
							<span><strong><?php esc_html_e( 'Soft 404', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'serves the theme’s 404 page. Hides that the plugin exists at all — better against fingerprinting, less helpful to humans.', 'reportedip-hive' ); ?></span>
						</label>
					</div>

					<div class="rip-form-group">
						<label class="rip-toggle">
							<input type="checkbox" name="reportedip_hive_hide_login_token_in_urls" value="1" class="rip-toggle__input" <?php checked( $token_in_urls ); ?> <?php disabled( ! $enabled ); ?> />
							<span class="rip-toggle__slider"></span>
							<span class="rip-toggle__label"><?php esc_html_e( 'Append the slug as a marker query argument to all generated login URLs', 'reportedip-hive' ); ?></span>
						</label>
						<p class="rip-help-text"><?php esc_html_e( 'Off by default — the slug already lives in the URL path, the extra query argument is redundant and can collide with plugins that use the same name. Enable only if you have a specific integration that expects the marker.', 'reportedip-hive' ); ?></p>
					</div>
				</div>

				<div class="rip-settings-section">
					<h2 class="rip-settings-section__title">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
						<?php esc_html_e( 'Block scanners probing the old login URL', 'reportedip-hive' ); ?>
					</h2>
					<p class="rip-settings-section__desc"><?php esc_html_e( 'A single accidental hit on the old URL is harmless and only logged. A repeated pattern from one IP is almost always a scanner — block it on the same escalating ladder as other threats and share it with the community.', 'reportedip-hive' ); ?></p>

					<div class="rip-form-group">
						<label class="rip-toggle">
							<input type="checkbox" name="reportedip_hive_monitor_hide_login_probe" value="1" class="rip-toggle__input" <?php checked( $probe_enabled ); ?> <?php disabled( ! $enabled ); ?> />
							<span class="rip-toggle__slider"></span>
							<span class="rip-toggle__label"><?php esc_html_e( 'Block IPs that repeatedly probe the hidden login URL', 'reportedip-hive' ); ?></span>
						</label>
						<p class="rip-help-text"><?php esc_html_e( 'On by default. The passive recon log stays regardless of this setting — turning it off only disables the IP block and community report.', 'reportedip-hive' ); ?></p>
					</div>

					<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
						<div class="rip-form-group">
							<label class="rip-label" for="reportedip_hive_hide_login_probe_threshold"><?php esc_html_e( 'How many hits?', 'reportedip-hive' ); ?></label>
							<input type="number" id="reportedip_hive_hide_login_probe_threshold" name="reportedip_hive_hide_login_probe_threshold" value="<?php echo esc_attr( (string) $probe_threshold ); ?>" min="1" max="100" class="rip-input" <?php disabled( ! $enabled ); ?> />
							<p class="rip-help-text"><?php esc_html_e( 'Block after this many direct hits from one IP. 5 is a good starting point.', 'reportedip-hive' ); ?></p>
						</div>
						<div class="rip-form-group">
							<label class="rip-label" for="reportedip_hive_hide_login_probe_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
							<input type="number" id="reportedip_hive_hide_login_probe_timeframe" name="reportedip_hive_hide_login_probe_timeframe" value="<?php echo esc_attr( (string) $probe_timeframe ); ?>" min="1" max="1440" class="rip-input" <?php disabled( ! $enabled ); ?> />
							<p class="rip-help-text"><?php esc_html_e( 'Counter window. A real user rarely hits the old URL twice — 10 minutes is forgiving.', 'reportedip-hive' ); ?></p>
						</div>
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
					<?php esc_html_e( 'Locked out? Recovery via wp-config.php', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'If you forget the slug, add this constant to wp-config.php (above the line that says “That’s all, stop editing!”). The original wp-login.php becomes reachable again — Hide Login stays inactive until you remove the constant.', 'reportedip-hive' ); ?></p>

				<div class="rip-alert rip-alert--warning">
					<pre style="margin:0; white-space:pre-wrap; word-break:break-all;"><code>define( 'REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN', true );</code></pre>
				</div>
			</div>

			<div class="rip-form-actions">
				<?php submit_button( __( 'Save Hide Login settings', 'reportedip-hive' ), 'rip-button rip-button--primary', 'submit', false ); ?>
			</div>
		</form>

		<script>
		(function () {
			var toggle = document.getElementById('rip-hide-login-enabled');
			var deps   = document.getElementById('rip-hide-login-dependent-fields');
			if (!toggle || !deps) { return; }
			toggle.addEventListener('change', function () {
				deps.classList.toggle('rip-is-disabled', !toggle.checked);
				var inputs = deps.querySelectorAll('input, select, textarea, button');
				inputs.forEach(function (input) {
					input.disabled = !toggle.checked;
				});
			});
		})();
		</script>
		<?php
	}

	/**
	 * Tab: Notifications — admin emails when incidents happen.
	 *
	 * @since 1.2.0
	 */
	private function render_notifications_tab() {
		$default_from_name = ReportedIP_Hive_Defaults::notify_from_name_default();
		$default_from_mail = (string) get_option( 'admin_email', '' );

		$tier_pro_or_higher = false;
		if ( class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			$mgr                = ReportedIP_Hive_Mode_Manager::get_instance();
			$tier_pro_or_higher = (bool) $mgr->tier_at_least( 'professional' );
		}

		$recipients_value = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_notify_recipients', '' );
		if ( '' === trim( $recipients_value ) ) {
			$recipients_value = $default_from_mail;
		}

		// Keep the stored value empty when the user hasn't overridden — that way
		// notify_from() resolves the default dynamically (e.g. follows
		// bloginfo('name') if the site is renamed later). The placeholder on
		// the input still shows the active fallback so the UI isn't blank.
		$from_name_value  = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_notify_from_name', '' );
		$from_email_value = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_notify_from_email', '' );

		$sync_option       = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_notify_sync_to_api', null );
		$sync_to_api_value = null === $sync_option ? $tier_pro_or_higher : (bool) $sync_option;

		$is_community_mode = class_exists( 'ReportedIP_Hive_Mode_Manager' )
			&& 'community' === ReportedIP_Hive_Mode_Manager::get_instance()->get_mode();
		?>
		<?php if ( $tier_pro_or_higher ) : ?>
		<div class="rip-alert rip-alert--success">
			<strong><?php esc_html_e( 'PRO mail relay active.', 'reportedip-hive' ); ?></strong>
			<?php esc_html_e( 'All plugin mails go through the reportedip.de relay so they pass authentication checks and stay out of spam folders. Your "From email" below is used as Reply-To, so replies still reach your inbox.', 'reportedip-hive' ); ?>
		</div>
		<?php else : ?>
		<div class="rip-alert rip-alert--info">
			<strong><?php esc_html_e( 'Free tier — mails leave your server directly.', 'reportedip-hive' ); ?></strong>
			<?php esc_html_e( 'Upgrade to PRO to route mails through the EU-based reportedip.de relay, which handles SPF/DKIM/DMARC so mails are less likely to land in spam.', 'reportedip-hive' ); ?>
			<a href="<?php echo esc_url( REPORTEDIP_HIVE_UPGRADE_URL ); ?>" target="_blank" rel="noopener noreferrer" class="rip-alert__cta"><?php esc_html_e( 'Learn more', 'reportedip-hive' ); ?> &rarr;</a>
		</div>
		<?php endif; ?>

		<form method="post" action="<?php echo esc_url( self::settings_form_action() ); ?>" class="rip-form">
			<?php settings_fields( 'reportedip_hive_protection_notifications' ); ?>

			<?php /* Checkbox-off fallbacks. */ ?>
			<input type="hidden" name="reportedip_hive_notify_admin" value="0" />
			<input type="hidden" name="reportedip_hive_notify_sync_to_api" value="0" />
			<input type="hidden" name="reportedip_hive_2fa_notify_new_device" value="0" />
			<input type="hidden" name="reportedip_hive_promo_enabled" value="0" />
			<input type="hidden" name="reportedip_hive_quota_notif_enabled" value="0" />
			<input type="hidden" name="reportedip_hive_tier_change_mail_enabled" value="0" />

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
					<?php esc_html_e( 'Alert recipients', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Send an email when something significant happens — repeated brute-force attempts, new blocks, etc. The recipient list also receives 2FA-related operational mails.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_notify_admin" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_notify_admin', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Send admin notifications when security events occur', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_notify_recipients"><?php esc_html_e( 'Recipients', 'reportedip-hive' ); ?></label>
					<textarea
						id="reportedip_hive_notify_recipients"
						name="reportedip_hive_notify_recipients"
						class="rip-input rip-input--textarea"
						rows="3"
						placeholder="security@example.com, ops@example.com"
					><?php echo esc_textarea( $recipients_value ); ?></textarea>
					<p class="rip-help-text"><?php esc_html_e( 'One or more email addresses, separated by commas, spaces or new lines. Invalid entries are dropped on save.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16v16H4z"/><path d="M22 6 12 13 2 6"/></svg>
					<?php esc_html_e( 'Sender (used for all plugin mails)', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Applies to every plugin mail — security alerts AND 2FA login codes — so both arrive from the same address. Leave both fields empty to use the recommended defaults: your site name and the WordPress admin email.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_notify_from_name"><?php esc_html_e( 'From name', 'reportedip-hive' ); ?></label>
					<input
						type="text"
						id="reportedip_hive_notify_from_name"
						name="reportedip_hive_notify_from_name"
						class="rip-input"
						value="<?php echo esc_attr( $from_name_value ); ?>"
						placeholder="<?php echo esc_attr( $default_from_name ); ?>"
						maxlength="120"
					/>
					<p class="rip-help-text">
						<?php
						printf(
							/* translators: 1: site name wrapped in <code>, 2: same site name in plain text */
							wp_kses(
								/* translators: 1: HTML-wrapped site name, 2: plain site name (Tip example) */
								__( 'Display name shown in the recipient\'s inbox. Leave empty to use your site name (currently: %1$s). Tip: include "Security" or "Alerts" to make it instantly recognizable, e.g. "%2$s Security".', 'reportedip-hive' ),
								array( 'code' => array() )
							),
							'<code>' . esc_html( $default_from_name ) . '</code>',
							esc_html( $default_from_name )
						);
						?>
					</p>
				</div>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_notify_from_email"><?php esc_html_e( 'From email', 'reportedip-hive' ); ?></label>
					<input
						type="email"
						id="reportedip_hive_notify_from_email"
						name="reportedip_hive_notify_from_email"
						class="rip-input"
						value="<?php echo esc_attr( $from_email_value ); ?>"
						placeholder="<?php echo esc_attr( $default_from_mail ); ?>"
					/>
					<p class="rip-help-text">
						<?php
						if ( $tier_pro_or_higher ) {
							esc_html_e( 'Used as Reply-To so replies reach your inbox directly. With the PRO mail relay, mails are sent from noreply@reportedip.de, so any address you enter here is safe to use.', 'reportedip-hive' );
						} else {
							esc_html_e( 'Should match a domain you own, so mail-server checks (SPF/DKIM) do not reject the message.', 'reportedip-hive' );
						}
						?>
					</p>
				</div>
			</div>

			<?php if ( $is_community_mode ) : ?>
			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
					<?php esc_html_e( 'Sync with reportedip.de', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc">
					<?php esc_html_e( 'Mirrors the contact set above to your reportedip.de account dashboard so the relay sees the same configuration.', 'reportedip-hive' ); ?>
					<?php if ( $tier_pro_or_higher ) : ?>
						<strong><?php esc_html_e( 'Recommended on for PRO accounts.', 'reportedip-hive' ); ?></strong>
					<?php endif; ?>
				</p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_notify_sync_to_api" value="1" class="rip-toggle__input" <?php checked( $sync_to_api_value ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Mirror this contact set to my reportedip.de account', 'reportedip-hive' ); ?></span>
					</label>
				</div>
			</div>
			<?php endif; ?>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 17H2a3 3 0 0 0 3-3V9a7 7 0 0 1 14 0v5a3 3 0 0 0 3 3z"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
					<?php esc_html_e( 'Sign-in notifications', 'reportedip-hive' ); ?>
				</h2>
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_2fa_notify_new_device" value="1" class="rip-toggle__input" <?php checked( (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_notify_new_device', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Email on sign-in from a new device', 'reportedip-hive' ); ?></span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'Notifies the user when a sign-in comes from a previously unseen browser/IP combination. Uses the unified mail provider configured above.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
					<?php esc_html_e( 'Service notices & upgrade hints', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc">
					<?php esc_html_e( 'Controls operational mails (quota warnings, plan changes) and in-admin upgrade hints. Security recommendations and status notices are always shown; these toggles only affect promotional content.', 'reportedip-hive' ); ?>
				</p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_promo_enabled" value="1" class="rip-toggle__input" <?php checked( (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_promo_enabled', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Show upgrade hints in the admin', 'reportedip-hive' ); ?></span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'When off, all PRO-feature promotion (dashboard cards, inline upsells, WooCommerce 2FA banner) is hidden site-wide. Status notices and security recommendations remain unaffected.', 'reportedip-hive' ); ?></p>
				</div>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_quota_notif_enabled" value="1" class="rip-toggle__input" <?php checked( (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_quota_notif_enabled', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Email when the managed-relay quota reaches 80% or 100%', 'reportedip-hive' ); ?></span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'Sent at most once per month per channel and stage. Recipients are the alert list configured above.', 'reportedip-hive' ); ?></p>
				</div>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_tier_change_mail_enabled" value="1" class="rip-toggle__input" <?php checked( (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_tier_change_mail_enabled', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Email when the plan changes (upgrade or downgrade)', 'reportedip-hive' ); ?></span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'One factual mail per tier change with a short summary of what becomes available or pauses. No marketing copy.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-form-actions">
				<?php submit_button( __( 'Save notification settings', 'reportedip-hive' ), 'rip-button rip-button--primary', 'submit', false ); ?>
			</div>
		</form>

		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
				<?php esc_html_e( 'Test the email pipeline', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc"><?php esc_html_e( 'Sends a sample mail through the unified branded template and your active mail provider. Useful before flipping notifications on, or after changing SMTP settings.', 'reportedip-hive' ); ?></p>

			<div class="rip-form-group">
				<button type="button" class="rip-button rip-button--secondary" id="reportedip-send-test-mail">
					<?php esc_html_e( 'Send test email', 'reportedip-hive' ); ?>
				</button>
				<span id="reportedip-send-test-mail-status" class="rip-help-text rip-ml-3 rip-hidden"></span>
				<script>
				(function(){
					var btn = document.getElementById('reportedip-send-test-mail');
					if (!btn || !window.jQuery || !window.reportedip_hive_ajax) return;
					var $ = window.jQuery, $btn = $(btn), $status = $('#reportedip-send-test-mail-status');
					var labelIdle = <?php echo wp_json_encode( __( 'Send test email', 'reportedip-hive' ) ); ?>;
					var labelBusy = <?php echo wp_json_encode( __( 'Sending…', 'reportedip-hive' ) ); ?>;
					$btn.on('click', function(e){
						e.preventDefault();
						$btn.prop('disabled', true).text(labelBusy);
						$status.removeClass('rip-hidden').text('').css('color', '');
						$.post(window.reportedip_hive_ajax.ajax_url, {
							action: 'reportedip_hive_send_test_mail',
							nonce:  window.reportedip_hive_ajax.nonce
						}).done(function(resp){
							if (resp && resp.success) {
								$status.text(resp.data && resp.data.message ? resp.data.message : '').css('color', 'var(--rip-success)');
							} else {
								$status.text(resp && resp.data && resp.data.message ? resp.data.message : <?php echo wp_json_encode( __( 'Test email failed.', 'reportedip-hive' ) ); ?>).css('color', 'var(--rip-danger)');
							}
						}).fail(function(){
							$status.text(<?php echo wp_json_encode( __( 'Request failed. Check server logs.', 'reportedip-hive' ) ); ?>).css('color', 'var(--rip-danger)');
						}).always(function(){
							$btn.prop('disabled', false).text(labelIdle);
						});
					});
				})();
				</script>
			</div>
		</div>
		<?php
	}

	/**
	 * Tab: Privacy & Logs — what the plugin records and how long it keeps it.
	 *
	 * Plain-language framing: a logging-profile radio (Minimal / Standard /
	 * Detailed) writes the underlying minimal_logging + detailed_logging
	 * toggles, so users do not have to reason about both.
	 *
	 * @since 1.2.0
	 */
	private function render_privacy_logs_tab() {
		$minimal  = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_minimal_logging', false );
		$detailed = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_detailed_logging', false );
		$profile  = $minimal ? 'minimal' : ( $detailed ? 'detailed' : 'standard' );
		?>
		<form method="post" action="<?php echo esc_url( self::settings_form_action() ); ?>" class="rip-form" id="rip-privacy-logs-form">
			<?php settings_fields( 'reportedip_hive_advanced_privacy' ); ?>

			<?php /* Checkbox-off fallbacks. (minimal_/detailed_logging are JS-driven hidden fields, see below.) */ ?>
			<input type="hidden" name="reportedip_hive_log_user_agents" value="0" />
			<input type="hidden" name="reportedip_hive_log_referer_domains" value="0" />

			<div class="rip-alert rip-alert--info">
				<svg class="rip-alert__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
					<circle cx="12" cy="12" r="10"></circle>
					<line x1="12" y1="16" x2="12" y2="12"></line>
					<line x1="12" y1="8" x2="12.01" y2="8"></line>
				</svg>
				<div class="rip-alert__content">
					<div class="rip-alert__message">
						<?php
						printf(
							wp_kses(
								/* translators: %s = privacy-text generator URL */
								__( 'Need a privacy policy statement for this site? Generate a custom-tailored text (German or English) based on your configuration at <a href="%s" target="_blank" rel="noopener">reportedip.de/dashboard/dsgvo</a>. A draft text is also registered under <strong>Tools &rarr; Privacy</strong>.', 'reportedip-hive' ),
								array(
									'a'      => array(
										'href'   => array(),
										'target' => array(),
										'rel'    => array(),
									),
									'strong' => array(),
								)
							),
							'https://reportedip.de/dashboard/dsgvo'
						);
						?>
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
					<?php esc_html_e( 'Logging profile', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Pick how much detail to keep about security events. Minimal is the privacy-first choice; Detailed helps when investigating attacks.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-radio">
						<input type="radio" name="rip_logging_profile" value="minimal" data-min="1" data-det="0" <?php checked( $profile, 'minimal' ); ?> />
						<span class="rip-radio__label"><strong><?php esc_html_e( 'Minimal', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'Essential security events only. Recommended for strict GDPR setups.', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-radio rip-mt-2">
						<input type="radio" name="rip_logging_profile" value="standard" data-min="0" data-det="0" <?php checked( $profile, 'standard' ); ?> />
						<span class="rip-radio__label"><strong><?php esc_html_e( 'Standard', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'Default. Enough context to spot patterns without storing personal data.', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-radio rip-mt-2">
						<input type="radio" name="rip_logging_profile" value="detailed" data-min="0" data-det="1" <?php checked( $profile, 'detailed' ); ?> />
						<span class="rip-radio__label"><strong><?php esc_html_e( 'Detailed', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'Adds hashed usernames so repeat-offender analysis is possible. Disable if you do not need it.', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<input type="hidden" name="reportedip_hive_minimal_logging" id="rip-minimal-logging" value="<?php echo $minimal ? '1' : '0'; ?>" />
				<input type="hidden" name="reportedip_hive_detailed_logging" id="rip-detailed-logging" value="<?php echo $detailed ? '1' : '0'; ?>" />

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_log_level"><?php esc_html_e( 'Log severity threshold', 'reportedip-hive' ); ?></label>
					<select id="reportedip_hive_log_level" name="reportedip_hive_log_level" class="rip-select">
						<option value="debug" <?php selected( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_level', 'info' ), 'debug' ); ?>><?php esc_html_e( 'Debug — everything (verbose, dev only)', 'reportedip-hive' ); ?></option>
						<option value="info" <?php selected( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_level', 'info' ), 'info' ); ?>><?php esc_html_e( 'Info — normal events (recommended)', 'reportedip-hive' ); ?></option>
						<option value="warning" <?php selected( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_level', 'info' ), 'warning' ); ?>><?php esc_html_e( 'Warning — only important events', 'reportedip-hive' ); ?></option>
						<option value="error" <?php selected( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_level', 'info' ), 'error' ); ?>><?php esc_html_e( 'Error — critical events only', 'reportedip-hive' ); ?></option>
					</select>
				</div>

				<script>
				(function(){
					if (!window.jQuery) return;
					var $ = window.jQuery;
					$(document).on('change', 'input[name="rip_logging_profile"]', function(){
						$('#rip-minimal-logging').val($(this).data('min'));
						$('#rip-detailed-logging').val($(this).data('det'));
					});
				})();
				</script>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="7" r="4"/><path d="M5 21v-2a4 4 0 0 1 4-4h6a4 4 0 0 1 4 4v2"/></svg>
					<?php esc_html_e( 'What we record about visitors', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Both options below are off by default for privacy. Enable only what you need for incident analysis.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_log_user_agents" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_user_agents', false ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Log browser user-agent strings (truncated to 50 chars to limit fingerprinting)', 'reportedip-hive' ); ?></span>
					</label>
				</div>
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_log_referer_domains" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_referer_domains', false ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Log referrer domain only (e.g. "example.com" — never the full URL)', 'reportedip-hive' ); ?></span>
					</label>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
					<?php esc_html_e( 'How long we keep data', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Old log entries are removed automatically. Anonymisation strips personal data even earlier without losing the security signal.', 'reportedip-hive' ); ?></p>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_data_retention_days"><?php esc_html_e( 'Delete logs after (days)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_data_retention_days" name="reportedip_hive_data_retention_days" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_data_retention_days', 30 ) ); ?>" min="7" max="365" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( '30 days is plenty for security analysis. Longer retention may require a privacy-policy update.', 'reportedip-hive' ); ?></p>
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_auto_anonymize_days"><?php esc_html_e( 'Anonymise older entries after (days)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_auto_anonymize_days" name="reportedip_hive_auto_anonymize_days" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_anonymize_days', 7 ) ); ?>" min="1" max="90" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Removes IP last-octet, user-agent strings, etc. while keeping aggregate counts.', 'reportedip-hive' ); ?></p>
					</div>
				</div>
				<p class="rip-help-text"><?php esc_html_e( 'The "Delete plugin data on uninstall" toggle moved to Performance & Tools. Maintenance buttons (cleanup / anonymise / export) live on the System Status page.', 'reportedip-hive' ); ?></p>
			</div>

			<div class="rip-alert rip-alert--info">
				<strong><?php esc_html_e( 'GDPR note:', 'reportedip-hive' ); ?></strong>
				<?php esc_html_e( 'IP-based blocking has a legitimate-interest legal basis under GDPR. Mention security monitoring in your privacy policy.', 'reportedip-hive' ); ?>
			</div>

			<div class="rip-form-actions">
				<?php submit_button( __( 'Save privacy & logs settings', 'reportedip-hive' ), 'rip-button rip-button--primary', 'submit', false ); ?>
			</div>
		</form>
		<?php
	}

	/**
	 * Render the maintenance / exports panel (cleanup, anonymise, export).
	 *
	 * @since 1.6.0
	 */
	private function render_maintenance_panel() {
		?>
		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
				<?php esc_html_e( 'Maintenance & exports', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc"><?php esc_html_e( 'These actions run immediately. Retention and anonymisation thresholds are configured on the Privacy & Logs tab.', 'reportedip-hive' ); ?></p>

			<div class="rip-card">
				<div class="rip-card__body">
					<div class="rip-grid rip-grid-cols-3 rip-gap-4">
						<div>
							<p class="rip-label rip-mb-2"><?php esc_html_e( 'Database cleanup', 'reportedip-hive' ); ?></p>
							<button type="button" class="rip-button rip-button--secondary" id="cleanup-old-logs">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
								<?php esc_html_e( 'Clean up logs', 'reportedip-hive' ); ?>
							</button>
							<p class="rip-help-text">
								<?php
								/* translators: %d: number of days after which log entries are removed */
								echo esc_html( sprintf( __( 'Removes logs older than %d days right now.', 'reportedip-hive' ), (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_data_retention_days', 30 ) ) );
								?>
							</p>
						</div>
						<div>
							<p class="rip-label rip-mb-2"><?php esc_html_e( 'Anonymise old data', 'reportedip-hive' ); ?></p>
							<button type="button" class="rip-button rip-button--secondary" id="anonymize-old-data">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
								<?php esc_html_e( 'Anonymise', 'reportedip-hive' ); ?>
							</button>
							<p class="rip-help-text">
								<?php
								/* translators: %d: number of days after which personal data is anonymized */
								echo esc_html( sprintf( __( 'Strips personal data older than %d days right now.', 'reportedip-hive' ), (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_anonymize_days', 7 ) ) );
								?>
							</p>
						</div>
						<div>
							<p class="rip-label rip-mb-2"><?php esc_html_e( 'Export logs', 'reportedip-hive' ); ?></p>
							<div class="rip-flex rip-gap-2">
								<button type="button" class="rip-button rip-button--secondary" id="export-logs-csv">CSV</button>
								<button type="button" class="rip-button rip-button--secondary" id="export-logs-json">JSON</button>
							</div>
							<p class="rip-help-text"><?php esc_html_e( 'Download log entries for offline analysis.', 'reportedip-hive' ); ?></p>
						</div>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Cron status panel on the System Status page.
	 *
	 * Surfaces the next scheduled run for each plugin cron hook plus the
	 * current queue-lock state, and exposes manual escape hatches for
	 * environments where WP-Cron is not firing reliably (CDN/cache plugin
	 * blocking the loopback to wp-cron.php).
	 *
	 * @return void
	 * @since 1.6.7
	 */
	private function render_cron_status_panel() {
		$hooks = array(
			'reportedip_hive_process_queue'   => __( 'Process API queue', 'reportedip-hive' ),
			'reportedip_hive_refresh_quota'   => __( 'Refresh API & relay quota', 'reportedip-hive' ),
			'reportedip_hive_sync_reputation' => __( 'Reputation sync', 'reportedip-hive' ),
			'reportedip_hive_cleanup'         => __( 'Daily cleanup', 'reportedip-hive' ),
		);

		$now             = time();
		$lock_held       = (bool) get_transient( ReportedIP_Hive_Cron_Handler::QUEUE_LOCK_TRANSIENT );
		$nonce           = wp_create_nonce( 'reportedip_hive_nonce' );
		$datetime_fmt    = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		$all_overdue_24h = true;
		foreach ( array_keys( $hooks ) as $hook ) {
			$next = wp_next_scheduled( $hook );
			if ( false === $next || ( $now - $next ) < DAY_IN_SECONDS ) {
				$all_overdue_24h = false;
				break;
			}
		}
		?>
		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
				<?php esc_html_e( 'Cron status', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc">
				<?php esc_html_e( 'WP-Cron processes the report queue and refreshes quota counters. If the next-run times below stay in the past, WP-Cron is not firing — set up a server cron (snippet below) or check your CDN/cache plugin.', 'reportedip-hive' ); ?>
			</p>

			<?php if ( $all_overdue_24h ) : ?>
				<div class="rip-alert rip-alert--error" style="margin-bottom: var(--rip-space-3);">
					<strong><?php esc_html_e( 'WP-Cron has not fired any ReportedIP Hive hook in the last 24 h.', 'reportedip-hive' ); ?></strong>
					<?php esc_html_e( 'Likely cause: another plugin\'s cron jobs use up the per-run time limit (WP_CRON_LOCK_TIMEOUT) before our jobs run. Set up a dedicated server cron using the snippet below.', 'reportedip-hive' ); ?>
				</div>
			<?php endif; ?>

			<div class="rip-card">
				<div class="rip-card__body">
					<table class="rip-table">
						<thead>
							<tr>
								<th><?php esc_html_e( 'Hook', 'reportedip-hive' ); ?></th>
								<th><?php esc_html_e( 'Next run', 'reportedip-hive' ); ?></th>
								<th><?php esc_html_e( 'Status', 'reportedip-hive' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php
							foreach ( $hooks as $hook => $label ) :
								$next = wp_next_scheduled( $hook );
								if ( false === $next ) {
									$status_class = 'danger';
									$status_text  = __( 'Not scheduled', 'reportedip-hive' );
									$next_label   = __( '—', 'reportedip-hive' );
								} else {
									$delta = $next - $now;
									if ( $delta < -300 ) {
										$status_class = 'danger';
										$status_text  = __( 'Overdue', 'reportedip-hive' );
									} elseif ( $delta < 0 ) {
										$status_class = 'warning';
										$status_text  = __( 'Pending', 'reportedip-hive' );
									} else {
										$status_class = 'success';
										$status_text  = __( 'Scheduled', 'reportedip-hive' );
									}
									$next_label = sprintf(
										'%s (%s)',
										esc_html( wp_date( $datetime_fmt, $next ) ),
										esc_html( human_time_diff( $now, $next ) )
									);
								}
								?>
								<tr>
									<td><code><?php echo esc_html( $hook ); ?></code><br><span class="rip-help-text"><?php echo esc_html( $label ); ?></span></td>
									<td><?php echo wp_kses_post( $next_label ); ?></td>
									<td><span class="rip-badge rip-badge--<?php echo esc_attr( $status_class ); ?>"><?php echo esc_html( $status_text ); ?></span></td>
								</tr>
							<?php endforeach; ?>
							<tr>
								<td><?php esc_html_e( 'Queue lock', 'reportedip-hive' ); ?><br><span class="rip-help-text"><?php esc_html_e( 'Prevents two queue workers from colliding (5 min TTL).', 'reportedip-hive' ); ?></span></td>
								<td><code><?php echo esc_html( ReportedIP_Hive_Cron_Handler::QUEUE_LOCK_TRANSIENT ); ?></code></td>
								<td>
									<?php if ( $lock_held ) : ?>
										<span class="rip-badge rip-badge--warning"><?php esc_html_e( 'Held', 'reportedip-hive' ); ?></span>
									<?php else : ?>
										<span class="rip-badge rip-badge--neutral"><?php esc_html_e( 'Free', 'reportedip-hive' ); ?></span>
									<?php endif; ?>
								</td>
							</tr>
						</tbody>
					</table>

					<div class="rip-flex rip-gap-2 rip-mt-3">
						<button type="button" class="rip-button rip-button--primary" id="rip-run-queue-now">
							<?php esc_html_e( 'Run queue now', 'reportedip-hive' ); ?>
						</button>
						<button type="button" class="rip-button rip-button--secondary" id="rip-clear-queue-lock">
							<?php esc_html_e( 'Clear queue lock', 'reportedip-hive' ); ?>
						</button>
					</div>
					<div id="rip-cron-status-result" class="rip-test-results"></div>
				</div>
			</div>

			<?php $this->render_cron_setup_snippet(); ?>
		</div>

		<script>
			jQuery(function ($) {
				const nonce = <?php echo wp_json_encode( $nonce ); ?>;
				const $out  = $('#rip-cron-status-result');

				function renderResult(html, kind) {
					$out.html('<div class="rip-alert rip-alert--' + kind + '">' + html + '</div>');
				}

				$('#rip-run-queue-now').on('click', function () {
					const $btn = $(this);
					$btn.prop('disabled', true);
					$out.html('<p>' + <?php echo wp_json_encode( __( 'Processing queue…', 'reportedip-hive' ) ); ?> + '</p>');
					$.post(ajaxurl, { action: 'reportedip_hive_run_queue_now', nonce: nonce })
						.done(function (resp) {
							if (resp.success) {
								renderResult(resp.data.message + ' <strong>(' + resp.data.remaining + ' pending)</strong>', 'success');
							} else {
								renderResult((resp.data && resp.data.message) || 'Error', 'error');
							}
						})
						.fail(function () { renderResult('Request failed', 'error'); })
						.always(function () { $btn.prop('disabled', false); });
				});

				$('#rip-clear-queue-lock').on('click', function () {
					const $btn = $(this);
					$btn.prop('disabled', true);
					$.post(ajaxurl, { action: 'reportedip_hive_clear_queue_lock', nonce: nonce })
						.done(function (resp) {
							if (resp.success) {
								renderResult(resp.data.message, resp.data.was_locked ? 'success' : 'info');
								setTimeout(function () { location.reload(); }, 800);
							} else {
								renderResult((resp.data && resp.data.message) || 'Error', 'error');
							}
						})
						.fail(function () { renderResult('Request failed', 'error'); })
						.always(function () { $btn.prop('disabled', false); });
				});
			});
		</script>
		<?php
	}

	/**
	 * Render the dedicated server-cron setup snippet card.
	 *
	 * Shows a copy-pasteable crontab line that runs ReportedIP Hive's hooks
	 * via WP-CLI on a fixed schedule, bypassing the per-spawn time budget of
	 * wp-cron.php (`WP_CRON_LOCK_TIMEOUT`). Needed when another plugin's
	 * heavy cron workers consume the budget before our hooks fire.
	 *
	 * @return void
	 * @since 1.6.8
	 */
	private function render_cron_setup_snippet() {
		$hooks_arg = 'reportedip_hive_process_queue reportedip_hive_refresh_quota reportedip_hive_sync_reputation reportedip_hive_cleanup';
		$abspath   = defined( 'ABSPATH' ) ? rtrim( ABSPATH, '/\\' ) : '/path/to/wordpress';
		$wp_cli    = file_exists( $abspath . '/wp-cli.phar' ) ? $abspath . '/wp-cli.phar' : '/usr/local/bin/wp';
		$snippet   = sprintf(
			'*/5 * * * * php %s cron event run --due-now %s --path=%s --quiet',
			esc_html( $wp_cli ),
			esc_html( $hooks_arg ),
			esc_html( $abspath )
		);
		$ispconfig = sprintf(
			'*/5 * * * * {SITE_PHP} %s cron event run --due-now %s --path={DOCROOT_CLIENT} --quiet',
			esc_html( basename( $wp_cli ) ),
			esc_html( $hooks_arg )
		);
		?>
		<div class="rip-card rip-mt-4">
			<div class="rip-card__header">
				<h3 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
					<?php esc_html_e( 'Recommended: dedicated server cron', 'reportedip-hive' ); ?>
				</h3>
			</div>
			<div class="rip-card__body">
				<p>
					<?php esc_html_e( 'wp-cron.php has a per-spawn time budget (WP_CRON_LOCK_TIMEOUT, 60–90 s on most setups). When other plugins schedule heavy workers, the budget can be consumed before ReportedIP Hive\'s hooks are reached. A dedicated cron line that targets only our hooks via WP-CLI bypasses the shared budget completely.', 'reportedip-hive' ); ?>
				</p>

				<p class="rip-label rip-mt-3"><?php esc_html_e( 'Standard crontab', 'reportedip-hive' ); ?></p>
				<pre class="rip-code-block" style="overflow-x:auto;padding:var(--rip-space-3);background:var(--rip-gray-50);font-size:var(--rip-text-xs);line-height:1.4;"><?php echo esc_html( $snippet ); ?></pre>

				<p class="rip-label rip-mt-3"><?php esc_html_e( 'ISPConfig template (uses {SITE_PHP} and {DOCROOT_CLIENT} variables)', 'reportedip-hive' ); ?></p>
				<pre class="rip-code-block" style="overflow-x:auto;padding:var(--rip-space-3);background:var(--rip-gray-50);font-size:var(--rip-text-xs);line-height:1.4;"><?php echo esc_html( $ispconfig ); ?></pre>

				<p class="rip-help-text rip-mt-3">
					<strong><?php esc_html_e( 'Optional:', 'reportedip-hive' ); ?></strong>
					<?php esc_html_e( 'after the dedicated cron is in place and verified, you can disable WordPress\' built-in cron loopback to avoid duplicate runs by adding to wp-config.php:', 'reportedip-hive' ); ?>
					<code>define('DISABLE_WP_CRON', true);</code>
				</p>
				<p class="rip-help-text">
					<?php esc_html_e( 'Adjust the WP-CLI path if it differs on your host. The plugin auto-detected the path shown above.', 'reportedip-hive' ); ?>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Tab: Performance & Tools — caching, rate-limiting, settings import/export.
	 *
	 * @since 1.2.0
	 */
	private function render_performance_advanced_tab() {
		$cache         = ReportedIP_Hive_Cache::get_instance();
		$cache_stats   = $cache->get_cache_statistics();
		$cache_info    = $cache->get_cache_info();
		$cache_savings = $cache->estimate_monthly_savings();
		$api_health    = $this->api_client->get_api_health_status();
		$api_usage     = $this->api_client->estimate_monthly_usage();
		?>
		<form method="post" action="<?php echo esc_url( self::settings_form_action() ); ?>" class="rip-form">
			<?php settings_fields( 'reportedip_hive_advanced_performance' ); ?>

			<?php /* Checkbox-off fallbacks. */ ?>
			<input type="hidden" name="reportedip_hive_enable_caching" value="0" />
			<input type="hidden" name="reportedip_hive_delete_data_on_uninstall" value="0" />

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
					<?php esc_html_e( 'Caching — saves API credits', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Caching reuses the result of past IP lookups instead of asking the community network again. Typically saves 70–90% of API calls.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_enable_caching" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_enable_caching', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Cache IP-reputation results (recommended)', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_cache_duration"><?php esc_html_e( 'Cache results for (hours)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_cache_duration" name="reportedip_hive_cache_duration" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_cache_duration', 24 ) ); ?>" min="1" max="168" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'How long to keep a "known IP" answer. 24–48 hours fits most sites.', 'reportedip-hive' ); ?></p>
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_negative_cache_duration"><?php esc_html_e( 'Cache "unknown IP" for (hours)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_negative_cache_duration" name="reportedip_hive_negative_cache_duration" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_negative_cache_duration', 2 ) ); ?>" min="1" max="24" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Shorter than the regular cache so a freshly-reported IP gets re-checked sooner.', 'reportedip-hive' ); ?></p>
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
					<?php esc_html_e( 'API rate limit', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Hourly ceiling on outgoing API calls. Counted in three independent buckets — reputation lookups, report submissions, and meta/quota sync — so a bot scan can no longer freeze the report queue.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_max_api_calls_per_hour"><?php esc_html_e( 'Max API calls per hour', 'reportedip-hive' ); ?></label>
					<input type="number" id="reportedip_hive_max_api_calls_per_hour" name="reportedip_hive_max_api_calls_per_hour" value="<?php echo esc_attr( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_max_api_calls_per_hour', 0 ) ); ?>" min="0" max="100000" class="rip-input" style="max-width: 180px;" />
					<p class="rip-help-text"><?php esc_html_e( '0 = auto (tier-bound caps scale with your subscription — Free 150/h reputation, Professional 3 000/h, Business 12 000/h, Enterprise unlimited). A positive number overrides all three buckets uniformly.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
					<?php esc_html_e( 'Uninstall behaviour', 'reportedip-hive' ); ?>
				</h2>
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_delete_data_on_uninstall" value="1" class="rip-toggle__input" <?php checked( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_delete_data_on_uninstall', false ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Delete all plugin data on uninstall (logs, settings, IP lists)', 'reportedip-hive' ); ?></span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'Off by default — uninstalling normally keeps your configuration so reinstalling restores it.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-form-actions">
				<?php submit_button( __( 'Save performance settings', 'reportedip-hive' ), 'rip-button rip-button--primary', 'submit', false ); ?>
			</div>
		</form>

		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 20V10"/><path d="M12 20V4"/><path d="M6 20v-6"/></svg>
				<?php esc_html_e( 'Live usage stats', 'reportedip-hive' ); ?>
			</h2>
			<div class="rip-stat-cards">
				<div class="rip-stat-card rip-stat-card--centered">
					<div class="rip-stat-card__content">
						<div class="rip-stat-card__title"><?php esc_html_e( 'Estimated monthly API calls', 'reportedip-hive' ); ?></div>
						<div class="rip-stat-card__value"><?php echo esc_html( $api_usage['estimated_monthly_calls'] ); ?></div>
						<div class="rip-stat-card__detail">
						<?php
							/* translators: %1$s: confidence level, %2$s: daily average */
							echo esc_html( sprintf( __( 'Confidence: %1$s · Daily avg: %2$s', 'reportedip-hive' ), ucfirst( (string) $api_usage['confidence'] ), (string) $api_usage['current_daily_average'] ) );
						?>
						</div>
					</div>
				</div>
				<div class="rip-stat-card rip-stat-card--centered">
					<div class="rip-stat-card__content">
						<div class="rip-stat-card__title"><?php esc_html_e( 'Cache efficiency', 'reportedip-hive' ); ?></div>
						<div class="rip-stat-card__value"><?php echo esc_html( $cache_stats['hit_rate'] ); ?>%</div>
						<div class="rip-stat-card__detail">
						<?php
							/* translators: %1$s: cache hits, %2$s: cache misses */
							echo esc_html( sprintf( __( 'Hits: %1$s · Misses: %2$s', 'reportedip-hive' ), (string) $cache_stats['hits'], (string) $cache_stats['misses'] ) );
						?>
						</div>
					</div>
				</div>
				<div class="rip-stat-card rip-stat-card--centered">
					<div class="rip-stat-card__content">
						<div class="rip-stat-card__title"><?php esc_html_e( 'Credits saved this month', 'reportedip-hive' ); ?></div>
						<div class="rip-stat-card__value"><?php echo esc_html( $cache_savings['estimated_monthly_calls_saved'] ); ?></div>
					</div>
				</div>
				<div class="rip-stat-card rip-stat-card--centered">
					<div class="rip-stat-card__content">
						<div class="rip-stat-card__title"><?php esc_html_e( 'API health', 'reportedip-hive' ); ?></div>
						<div class="rip-stat-card__value"><?php echo esc_html( $api_health['health_score'] ); ?>%</div>
					</div>
				</div>
			</div>
		</div>

		<div class="rip-alert rip-alert--info">
			<strong><?php esc_html_e( 'Cache management, setup wizard restart, settings import/export and maintenance/exports', 'reportedip-hive' ); ?></strong>
			—
			<?php
			printf(
				/* translators: %s: link to the System Status page */
				esc_html__( 'are now on the %s page.', 'reportedip-hive' ),
				'<a href="' . esc_url( self::get_admin_page_url( 'admin.php?page=reportedip-hive-debug' ) ) . '">' . esc_html__( 'System Status', 'reportedip-hive' ) . '</a>'
			);
			?>
		</div>
		<?php
	}

	/**
	 * Debug & Health page
	 */
	public function debug_page() {
		$current_user_ip = $this->get_current_user_ip();
		$plugin_health   = $this->get_plugin_health_status();

		$plugin_data    = get_plugin_data( REPORTEDIP_HIVE_PLUGIN_FILE );
		$plugin_version = $plugin_data['Version'];

		$cache      = ReportedIP_Hive_Cache::get_instance();
		$cache_info = $cache->get_cache_info();

		self::render_page_header( __( 'System Status', 'reportedip-hive' ), __( 'Health, maintenance and tools', 'reportedip-hive' ) );
		?>

			<!-- Health Status Cards -->
			<div class="rip-health-grid">
				<?php
				$health_items = array(
					'logging'  => array(
						'icon'  => '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
						'title' => __( 'Logging', 'reportedip-hive' ),
					),
					'database' => array(
						'icon'  => '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
						'title' => __( 'Database', 'reportedip-hive' ),
					),
					'api'      => array(
						'icon'  => '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
						'title' => __( 'API', 'reportedip-hive' ),
					),
				);
				$pill_icons   = array(
					'success' => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" width="14" height="14" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>',
					'warning' => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" aria-hidden="true"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
					'danger'  => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
				);
				foreach ( $health_items as $key => $item ) :
					$status       = $plugin_health[ $key ]['status'];
					$status_class = $status === 'healthy' ? 'success' : ( $status === 'warning' ? 'warning' : 'danger' );
					?>
				<div class="rip-health-card rip-health-card--<?php echo esc_attr( $status_class ); ?>">
					<div class="rip-health-card-icon">
						<?php echo wp_kses_post( $item['icon'] ); ?>
					</div>
					<div class="rip-health-card-content">
						<h3><?php echo esc_html( $item['title'] ); ?></h3>
						<span class="rip-status-pill rip-status-pill--<?php echo esc_attr( $status_class ); ?>">
							<?php echo wp_kses_post( $pill_icons[ $status_class ] ); ?>
							<?php echo esc_html( $plugin_health[ $key ]['message'] ); ?>
						</span>
					</div>
				</div>
				<?php endforeach; ?>
			</div>

			<!-- System Info Section -->
			<div class="rip-card">
				<div class="rip-card__header">
					<h2><?php esc_html_e( 'System Information', 'reportedip-hive' ); ?></h2>
				</div>
				<div class="rip-card__body">
					<div class="rip-info-grid">
						<div class="rip-info-item">
							<span class="rip-info-label"><?php esc_html_e( 'Plugin Version', 'reportedip-hive' ); ?></span>
							<span class="rip-info-value"><code><?php echo esc_html( $plugin_version ); ?></code></span>
						</div>
						<div class="rip-info-item">
							<span class="rip-info-label"><?php esc_html_e( 'PHP Version', 'reportedip-hive' ); ?></span>
							<span class="rip-info-value"><code><?php echo esc_html( PHP_VERSION ); ?></code></span>
						</div>
						<div class="rip-info-item">
							<span class="rip-info-label"><?php esc_html_e( 'WordPress Version', 'reportedip-hive' ); ?></span>
							<span class="rip-info-value"><code><?php echo esc_html( get_bloginfo( 'version' ) ); ?></code></span>
						</div>
						<div class="rip-info-item">
							<span class="rip-info-label"><?php esc_html_e( 'Your IP Address', 'reportedip-hive' ); ?></span>
							<span class="rip-info-value">
								<code><?php echo esc_html( $current_user_ip ); ?></code>
								<?php
								if ( $this->database->is_whitelisted( $current_user_ip ) ) {
									echo '<span class="rip-badge rip-badge--success">' . esc_html__( 'Whitelisted', 'reportedip-hive' ) . '</span>';
								} elseif ( $this->database->is_blocked( $current_user_ip ) ) {
									echo '<span class="rip-badge rip-badge--danger">' . esc_html__( 'Blocked', 'reportedip-hive' ) . '</span>';
								}
								?>
							</span>
						</div>
						<div class="rip-info-item">
							<span class="rip-info-label"><?php esc_html_e( 'Protection Mode', 'reportedip-hive' ); ?></span>
							<span class="rip-info-value">
								<?php if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false ) ) : ?>
									<span class="rip-badge rip-badge--warning"><?php esc_html_e( 'Report Only', 'reportedip-hive' ); ?></span>
								<?php else : ?>
									<span class="rip-badge rip-badge--success"><?php esc_html_e( 'Full Protection', 'reportedip-hive' ); ?></span>
								<?php endif; ?>
							</span>
						</div>
						<div class="rip-info-item">
							<span class="rip-info-label"><?php esc_html_e( 'Log Level', 'reportedip-hive' ); ?></span>
							<span class="rip-info-value"><code><?php echo esc_html( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_level', 'info' ) ); ?></code></span>
						</div>
						<?php
						$rule_sync_last = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_rule_sync_last_run', 0 );
						$rule_sync_obj  = ReportedIP_Hive_Rule_Sync::get_instance();
						$ruleset_parts  = array();
						foreach ( ReportedIP_Hive_Rule_Store::VALID_KEYS as $rule_key ) {
							$rule_row        = $rule_sync_obj->get_ruleset( $rule_key );
							$rule_version    = isset( $rule_row['version'] ) ? (int) $rule_row['version'] : 0;
							$ruleset_parts[] = $rule_key . ' v' . $rule_version . ( $rule_version > 0 ? '' : ' (baseline)' );
						}
						?>
						<div class="rip-info-item">
							<span class="rip-info-label"><?php esc_html_e( 'Last Rule Sync', 'reportedip-hive' ); ?></span>
							<span class="rip-info-value">
								<?php echo $rule_sync_last ? esc_html( wp_date( 'Y-m-d H:i:s', $rule_sync_last ) ) : esc_html__( 'never (baseline only)', 'reportedip-hive' ); ?>
							</span>
						</div>
						<div class="rip-info-item">
							<span class="rip-info-label"><?php esc_html_e( 'Ruleset Versions', 'reportedip-hive' ); ?></span>
							<span class="rip-info-value"><code><?php echo esc_html( implode( ', ', $ruleset_parts ) ); ?></code></span>
						</div>
						<?php
						$dropin_mgr      = ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
						$dropin_enabled  = (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false );
						$dropin_server   = $dropin_mgr->detect_server();
						$dropin_writable = $dropin_mgr->is_writable_target();
						?>
						<div class="rip-info-item">
							<span class="rip-info-label"><?php esc_html_e( 'WAF Drop-in', 'reportedip-hive' ); ?></span>
							<span class="rip-info-value">
								<?php if ( $dropin_mgr->is_active() ) : ?>
									<span class="rip-badge rip-badge--success"><?php esc_html_e( 'Active', 'reportedip-hive' ); ?></span>
								<?php elseif ( $dropin_enabled && 'nginx' === $dropin_server ) : ?>
									<span class="rip-badge rip-badge--info"><?php esc_html_e( 'Enabled (manual nginx config)', 'reportedip-hive' ); ?></span>
								<?php elseif ( $dropin_enabled ) : ?>
									<span class="rip-badge rip-badge--warning"><?php esc_html_e( 'Enabled, directive missing', 'reportedip-hive' ); ?></span>
								<?php else : ?>
									<span class="rip-badge rip-badge--neutral"><?php esc_html_e( 'Disabled', 'reportedip-hive' ); ?></span>
								<?php endif; ?>
								<code><?php echo esc_html( $dropin_server ); ?></code>
								<?php if ( $dropin_enabled && ! $dropin_writable ) : ?>
									<span class="rip-badge rip-badge--warning"><?php esc_html_e( 'Target not writable', 'reportedip-hive' ); ?></span>
								<?php endif; ?>
							</span>
						</div>
					</div>
				</div>
			</div>

			<!-- Cache Management -->
			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
					<?php esc_html_e( 'Cache management', 'reportedip-hive' ); ?>
				</h2>
				<div class="rip-card">
					<div class="rip-card__body">
						<div class="rip-cache-info rip-mb-3">
							<div class="rip-cache-info__item">
								<span class="rip-cache-info__label"><?php esc_html_e( 'Entries', 'reportedip-hive' ); ?></span>
								<span class="rip-cache-info__value">
								<?php
									/* translators: %1$s: active entries, %2$s: expired entries */
									echo esc_html( sprintf( __( '%1$s active, %2$s expired', 'reportedip-hive' ), (string) $cache_info['active_count'], (string) $cache_info['expired_count'] ) );
								?>
								</span>
							</div>
							<div class="rip-cache-info__item">
								<span class="rip-cache-info__label"><?php esc_html_e( 'Size', 'reportedip-hive' ); ?></span>
								<span class="rip-cache-info__value"><?php echo esc_html( $cache_info['total_size_mb'] ); ?> MB</span>
							</div>
						</div>
						<div class="rip-flex rip-gap-2">
							<button type="button" class="rip-button rip-button--secondary" id="clear-cache">
								<?php esc_html_e( 'Clear all cache', 'reportedip-hive' ); ?>
							</button>
							<button type="button" class="rip-button rip-button--ghost" id="cleanup-expired-cache">
								<?php esc_html_e( 'Clean expired entries', 'reportedip-hive' ); ?>
							</button>
						</div>
					</div>
				</div>
			</div>

			<!-- Setup wizard restart -->
			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>
					<?php esc_html_e( 'Setup wizard', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Re-run the guided setup to reconfigure mode, API access, detection thresholds and notifications. Existing settings are pre-filled — you can review and confirm each step.', 'reportedip-hive' ); ?></p>
				<div class="rip-flex rip-gap-2">
					<a href="<?php echo esc_url( self::get_admin_page_url( 'admin.php?page=reportedip-hive-wizard&step=1' ) ); ?>" class="rip-button rip-button--secondary">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>
						<?php esc_html_e( 'Restart setup wizard', 'reportedip-hive' ); ?>
					</a>
				</div>
			</div>

			<?php $this->render_cron_status_panel(); ?>

			<?php $this->render_maintenance_panel(); ?>

			<?php
			if ( class_exists( 'ReportedIP_Hive_Settings_Import_Export' ) ) {
				ReportedIP_Hive_Settings_Import_Export::get_instance()->render_panel();
			}
			?>

			<!-- Quick Actions -->
			<div class="rip-card">
				<div class="rip-card__header">
					<h2><?php esc_html_e( 'Quick Actions', 'reportedip-hive' ); ?></h2>
				</div>
				<div class="rip-card__body">
					<div class="rip-actions-grid">
						<div class="rip-action-group">
							<h3><?php esc_html_e( 'Connection Tests', 'reportedip-hive' ); ?></h3>
							<div class="rip-action-buttons">
								<?php if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) : ?>
								<button type="button" class="rip-button rip-button--secondary" id="test-database-connection">
									<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
									<?php esc_html_e( 'Test Database', 'reportedip-hive' ); ?>
								</button>
								<?php endif; ?>
								<button type="button" class="rip-button rip-button--secondary" id="test-api-connection-debug">
									<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
									<?php esc_html_e( 'Test API', 'reportedip-hive' ); ?>
								</button>
							</div>
							<?php if ( ! ( defined( 'WP_DEBUG' ) && WP_DEBUG ) ) : ?>
							<p class="rip-help-text"><?php esc_html_e( 'Enable WP_DEBUG for additional diagnostic tests.', 'reportedip-hive' ); ?></p>
							<?php endif; ?>
							<div id="system-test-results" class="rip-test-results"></div>
						</div>

						<div class="rip-action-group rip-action-group--danger">
							<h3><?php esc_html_e( 'Reset Plugin', 'reportedip-hive' ); ?></h3>
							<p class="rip-action-description"><?php esc_html_e( 'Reset all plugin settings to defaults. This will not delete your blocked IPs or logs.', 'reportedip-hive' ); ?></p>
							<div class="rip-action-buttons">
								<button type="button" class="rip-button rip-button--warning" id="reset-settings">
									<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2.5 2v6h6M21.5 22v-6h-6"/><path d="M22 11.5A10 10 0 0 0 3.2 7.2M2 12.5a10 10 0 0 0 18.8 4.2"/></svg>
									<?php esc_html_e( 'Reset Settings', 'reportedip-hive' ); ?>
								</button>
								<button type="button" class="rip-button rip-button--danger" id="reset-all-data">
									<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
									<?php esc_html_e( 'Reset All Data', 'reportedip-hive' ); ?>
								</button>
							</div>
							<div id="reset-results" class="rip-test-results"></div>
						</div>
					</div>
				</div>
			</div>

		<?php self::render_page_footer(); ?>
		<?php
	}

	/**
	 * Get current user IP - delegates to main plugin class
	 */
	private function get_current_user_ip() {
		return ReportedIP_Hive::get_client_ip();
	}

	/**
	 * Get plugin health status
	 */
	private function get_plugin_health_status() {
		$health = array(
			'logging'  => array(
				'status'  => 'healthy',
				'message' => '',
				'details' => array(),
			),
			'database' => array(
				'status'  => 'healthy',
				'message' => '',
				'details' => array(),
			),
			'api'      => array(
				'status'  => 'healthy',
				'message' => '',
				'details' => array(),
			),
		);

		try {
			$recent_logs = $this->logger->get_logs( 1, 1 );
			if ( empty( $recent_logs ) ) {
				$health['logging']['status']    = 'warning';
				$health['logging']['message']   = __( 'No recent logs found', 'reportedip-hive' );
				$health['logging']['details'][] = __( 'No logs in the last 24 hours. This might indicate a logging problem.', 'reportedip-hive' );
			} else {
				$health['logging']['message'] = __( 'Logging system operational', 'reportedip-hive' );
				/* translators: %s: timestamp of the most recent log entry */
				$health['logging']['details'][] = sprintf( __( 'Last log entry: %s', 'reportedip-hive' ), $recent_logs[0]->created_at );
			}

			$log_level = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_level', 'info' );
			if ( $log_level === 'error' ) {
				$health['logging']['status']    = 'warning';
				$health['logging']['details'][] = __( 'Log level is set to "error" - many events may not be logged.', 'reportedip-hive' );
			}
		} catch ( Exception $e ) {
			$health['logging']['status']    = 'error';
			$health['logging']['message']   = __( 'Logging system error', 'reportedip-hive' );
			$health['logging']['details'][] = $e->getMessage();
		}

		try {
			global $wpdb;
			$table_name = $wpdb->prefix . 'reportedip_hive_logs';
			// phpcs:disable WordPress.DB.DirectDatabaseQuery -- One-time health probe on a plugin table; name from $wpdb->prefix plus a hardcoded suffix.
			$table_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) ) === $table_name;
			// phpcs:enable WordPress.DB.DirectDatabaseQuery

			if ( ! $table_exists ) {
				$health['database']['status']    = 'error';
				$health['database']['message']   = __( 'Database tables missing', 'reportedip-hive' );
				$health['database']['details'][] = __( 'Plugin tables not found. Try deactivating and reactivating the plugin.', 'reportedip-hive' );
			} else {
				$health['database']['message'] = __( 'Database operational', 'reportedip-hive' );

				// phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Safe table name composed from $wpdb->prefix and a hardcoded suffix.
				$log_count = $wpdb->get_var( "SELECT COUNT(*) FROM $table_name" );
				// phpcs:enable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
				/* translators: %d: total number of log entries in the database */
				$health['database']['details'][] = sprintf( __( 'Total log entries: %d', 'reportedip-hive' ), $log_count );
			}
		} catch ( Exception $e ) {
			$health['database']['status']    = 'error';
			$health['database']['message']   = __( 'Database error', 'reportedip-hive' );
			$health['database']['details'][] = $e->getMessage();
		}

		try {
			if ( ! $this->api_client->is_configured() ) {
				$health['api']['status']    = 'warning';
				$health['api']['message']   = __( 'API not configured', 'reportedip-hive' );
				$health['api']['details'][] = __( 'API key not set. Some features will not work.', 'reportedip-hive' );
			} else {
				$test_result = get_transient( 'reportedip_hive_api_health' );
				if ( false === $test_result ) {
					$test_result = $this->api_client->test_connection();
					set_transient( 'reportedip_hive_api_health', $test_result, 300 );
				}
				if ( $test_result['success'] ) {
					$health['api']['message']   = __( 'API connection operational', 'reportedip-hive' );
					$health['api']['details'][] = __( 'API connection test successful.', 'reportedip-hive' );
				} else {
					$health['api']['status']    = 'error';
					$health['api']['message']   = __( 'API connection failed', 'reportedip-hive' );
					$health['api']['details'][] = $test_result['message'] ?? __( 'Unknown API error', 'reportedip-hive' );
				}
			}
		} catch ( Exception $e ) {
			$health['api']['status']    = 'error';
			$health['api']['message']   = __( 'API system error', 'reportedip-hive' );
			$health['api']['details'][] = $e->getMessage();
		}

		return $health;
	}

	/**
	 * Get dashboard statistics
	 */
	public function get_dashboard_stats() {
		global $wpdb;

		$ip_stats   = $this->database->get_ip_management_stats();
		$logs_table = $wpdb->prefix . 'reportedip_hive_logs';

		$cutoff_utc = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name built from $wpdb->prefix and a hardcoded constant; safe.
		$events_24h = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $logs_table
				 WHERE created_at >= %s OR created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)",
				$cutoff_utc
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter

		$queue_table = $wpdb->prefix . 'reportedip_hive_api_queue';
		// phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name built from $wpdb->prefix and a hardcoded constant; safe.
		$queue_count = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM $queue_table WHERE status IN ('pending', 'failed')"
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter

		return array(
			'events_24h'      => $events_24h,
			'blocked_ips'     => $ip_stats['active_blocked'] ?? 0,
			'whitelisted_ips' => $ip_stats['active_whitelist'] ?? 0,
			'queue_count'     => $queue_count,
		);
	}

	/**
	 * Tier definitions — single source of truth for the Community page.
	 *
	 * Mirrors the constants in reportedip-service/includes/class-constants.php.
	 * Update only this table when the service side changes.
	 *
	 * @return array<string, array{label:string,reports_day:int,checks_day:int,features:array<int,string>,cta_type:string,in_pricing:bool,price?:string,mail_per_mo?:int,sms_per_mo?:int,domains?:int}>
	 */
	private function get_tier_definitions() {
		return array(
			'free'         => array(
				'label'       => 'Free',
				'reports_day' => 50,
				'checks_day'  => 1000,
				'features'    => array(
					__( 'Local protection included', 'reportedip-hive' ),
					__( 'Community threat checks', 'reportedip-hive' ),
					__( 'Limited reports', 'reportedip-hive' ),
				),
				'cta_type'    => 'upgrade',
				'in_pricing'  => true,
			),
			'contributor'  => array(
				'label'       => 'Contributor',
				'reports_day' => 200,
				'checks_day'  => 5000,
				'features'    => array(
					__( 'Full report permission', 'reportedip-hive' ),
					__( 'Community recognition', 'reportedip-hive' ),
					__( 'Email support', 'reportedip-hive' ),
				),
				'cta_type'    => 'upgrade',
				'in_pricing'  => true,
			),
			'professional' => array(
				'label'       => 'Professional',
				'price'       => '€14.90 / mo · €149 / yr',
				'reports_day' => 1000,
				'checks_day'  => 25000,
				'mail_per_mo' => 500,
				'sms_per_mo'  => 25,
				'domains'     => 3,
				'features'    => array(
					__( '500 2FA mails / month via reportedip.de SMTP', 'reportedip-hive' ),
					__( '25 included 2FA SMS per month — managed via reportedip.de', 'reportedip-hive' ),
					__( 'Multi-site licence (3 domains)', 'reportedip-hive' ),
					__( 'Priority sync (daily blacklist download)', 'reportedip-hive' ),
					__( '2FA usage reports & per-role policies', 'reportedip-hive' ),
					__( 'Bulk operations & analytics', 'reportedip-hive' ),
					__( 'Email support', 'reportedip-hive' ),
				),
				'cta_type'    => 'upgrade',
				'in_pricing'  => true,
			),
			'business'     => array(
				'label'       => 'Business',
				'price'       => '€39 / mo · €389 / yr',
				'reports_day' => 5000,
				'checks_day'  => 100000,
				'mail_per_mo' => 2500,
				'sms_per_mo'  => 75,
				'domains'     => 15,
				'features'    => array(
					__( '2,500 2FA mails / month', 'reportedip-hive' ),
					__( '75 2FA SMS / month + prepaid bundles', 'reportedip-hive' ),
					__( 'Multi-site licence (15 domains per licence)', 'reportedip-hive' ),
					__( 'Bookable x2–x20: domains, API quota and 2FA mail/SMS scale with the licence count (volume discount)', 'reportedip-hive' ),
					__( 'Whitelabel (wizards, 2FA page, all texts & email templates)', 'reportedip-hive' ),
					__( 'WooCommerce integration', 'reportedip-hive' ),
					__( 'Full WP-CLI automation', 'reportedip-hive' ),
					__( 'Restrict user login times', 'reportedip-hive' ),
					__( 'GDPR export tool', 'reportedip-hive' ),
					__( 'Priority support', 'reportedip-hive' ),
				),
				'cta_type'    => 'upgrade',
				'in_pricing'  => true,
			),
			'enterprise'   => array(
				'label'       => 'Enterprise',
				'price'       => 'On request',
				'reports_day' => -1,
				'checks_day'  => -1,
				'mail_per_mo' => -1,
				'sms_per_mo'  => -1,
				'domains'     => -1,
				'features'    => array(
					__( 'Unlimited API calls and reports', 'reportedip-hive' ),
					__( 'Custom SMS volume + dedicated sender', 'reportedip-hive' ),
					__( 'Phone support with 4 h SLA', 'reportedip-hive' ),
					__( 'Tailored DPA / AVV adjustments', 'reportedip-hive' ),
					__( 'Dedicated onboarding', 'reportedip-hive' ),
				),
				'cta_type'    => 'contact',
				'in_pricing'  => true,
			),
			'honeypot'     => array(
				'label'       => 'Honeypot',
				'reports_day' => -1,
				'checks_day'  => -1,
				'features'    => array(),
				'cta_type'    => 'none',
				'in_pricing'  => false,
			),
		);
	}

	/**
	 * Normalize a service role to a tier slug plus metadata.
	 *
	 * @param string $user_role   Role from the verify-key response (e.g. "reportedip_free").
	 * @param bool   $is_honeypot Whether the key is flagged as honeypot.
	 * @return array Definition including an additional `slug` field.
	 */
	private function get_tier_info( $user_role, $is_honeypot = false ) {
		static $role_map = array(
			'reportedip_free'         => 'free',
			'reportedip_contributor'  => 'contributor',
			'reportedip_professional' => 'professional',
			'reportedip_business'     => 'business',
			'reportedip_enterprise'   => 'enterprise',
			'reportedip_honeypot'     => 'honeypot',
			'subscriber'              => 'free',
			'contributor'             => 'free',
			'author'                  => 'contributor',
			'editor'                  => 'professional',
			'administrator'           => 'enterprise',
		);

		if ( $is_honeypot ) {
			$slug = 'honeypot';
		} else {
			$key  = strtolower( (string) $user_role );
			$slug = $role_map[ $key ] ?? 'free';
		}

		$tiers        = $this->get_tier_definitions();
		$tier         = $tiers[ $slug ];
		$tier['slug'] = $slug;

		return $tier;
	}

	/**
	 * Return an external URL, optionally with a filter override.
	 *
	 * @param string $key          Identifier (upgrade|honeypot|faq|register|contact_mail).
	 * @param string $fallback_url Default URL used when no filter overrides it.
	 * @return string
	 */
	private function get_external_url( $key, $fallback_url ) {
		$url = apply_filters( 'reportedip_hive_external_url', $fallback_url, $key );

		return is_string( $url ) && $url !== '' ? $url : $fallback_url;
	}

	/**
	 * Community & Quota page
	 */
	public function community_page() {
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();

		if ( isset( $_GET['rip_refresh'] ) && check_admin_referer( 'reportedip_hive_refresh_quota' ) ) {
			delete_transient( 'reportedip_hive_api_quota' );
			delete_transient( 'reportedip_hive_api_status' );
			if ( $this->api_client->is_configured() && $mode_manager->is_community_mode() ) {
				$this->api_client->refresh_api_quota();
			}
			wp_safe_redirect( self::get_admin_page_url( 'admin.php?page=reportedip-hive-community&refreshed=1' ) );
			exit;
		}

		$is_community_mode = $mode_manager->is_community_mode();
		$is_configured     = $this->api_client->is_configured();

		$cached_quota = $this->api_client->get_cached_quota();
		if ( false === $cached_quota && $is_community_mode && $is_configured ) {
			$fresh = $this->api_client->refresh_api_quota();
			if ( is_array( $fresh ) ) {
				$cached_quota = $fresh;
			}
		}

		$has_quota        = is_array( $cached_quota );
		$quota            = $has_quota ? $cached_quota : array();
		$quota_status     = $this->api_client->get_quota_status();
		$queue_summary    = $this->database->get_queue_summary();
		$security_summary = $this->database->get_security_summary( 30 );

		$user_role         = (string) ( $quota['user_role'] ?? '' );
		$is_honeypot       = ! empty( $quota['is_honeypot'] );
		$daily_limit       = (int) ( $quota['daily_report_limit'] ?? 0 );
		$remaining_reports = (int) ( $quota['remaining_reports'] ?? 0 );
		$reset_time        = $quota['reset_time'] ?? null;

		$tier = $this->get_tier_info( $user_role, $is_honeypot );

		$daily_limit_display = $daily_limit < 0 ? __( 'Unbegrenzt', 'reportedip-hive' ) : number_format_i18n( $daily_limit );
		$remaining_display   = $daily_limit < 0 ? __( 'Unbegrenzt', 'reportedip-hive' ) : number_format_i18n( $remaining_reports );

		$queue_size    = (int) ( $queue_summary['total_pending'] ?? 0 );
		$days_to_clear = $daily_limit > 0 ? (int) ceil( $queue_size / $daily_limit ) : null;

		$reset_formatted = '';
		if ( ! empty( $reset_time ) ) {
			$ts = strtotime( $reset_time );
			if ( $ts ) {
				$reset_formatted = wp_date( 'd.m.Y H:i', $ts );
			}
		}

		$refresh_url = wp_nonce_url(
			self::get_admin_page_url( 'admin.php?page=reportedip-hive-community&rip_refresh=1' ),
			'reportedip_hive_refresh_quota'
		);

		$upgrade_url = add_query_arg(
			array(
				'utm_source'   => 'plugin',
				'utm_medium'   => 'community-page',
				'utm_campaign' => 'upgrade',
			),
			$this->get_external_url( 'upgrade', REPORTEDIP_HIVE_UPGRADE_URL )
		);

		$contact_mail = $this->get_external_url( 'contact_mail', REPORTEDIP_HIVE_CONTACT_MAIL );
		$contact_url  = 'mailto:' . rawurlencode( $contact_mail ) . '?subject=' . rawurlencode( 'ReportedIP Enterprise-Anfrage' );

		$honeypot_url = add_query_arg(
			array(
				'utm_source'   => 'plugin',
				'utm_medium'   => 'community-page',
				'utm_campaign' => 'honeypot',
			),
			$this->get_external_url( 'honeypot', REPORTEDIP_HIVE_HONEYPOT_URL )
		);

		$subtab = isset( $_GET['subtab'] ) ? sanitize_key( wp_unslash( $_GET['subtab'] ) ) : 'main';
		$subtab = in_array( $subtab, array( 'main', 'promote' ), true ) ? $subtab : 'main';

		$main_tab_url    = self::get_admin_page_url( 'admin.php?page=reportedip-hive-community' );
		$promote_tab_url = self::get_admin_page_url( 'admin.php?page=reportedip-hive-community&subtab=promote' );

		self::render_page_header( __( 'Community & Quota', 'reportedip-hive' ), __( 'Manage your API quota and community participation', 'reportedip-hive' ) );
		?>

			<div class="rip-content">

				<nav class="nav-tab-wrapper rip-mb-6" aria-label="<?php esc_attr_e( 'Community sections', 'reportedip-hive' ); ?>">
					<a href="<?php echo esc_url( $main_tab_url ); ?>" class="nav-tab <?php echo 'main' === $subtab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Community & Quota', 'reportedip-hive' ); ?></a>
					<a href="<?php echo esc_url( $promote_tab_url ); ?>" class="nav-tab <?php echo 'promote' === $subtab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Promote', 'reportedip-hive' ); ?></a>
				</nav>

				<?php if ( 'main' === $subtab ) : ?>

					<?php if ( isset( $_GET['refreshed'] ) ) : ?>
					<div class="rip-alert rip-alert--success rip-mb-6">
						<?php esc_html_e( 'Status has been refreshed.', 'reportedip-hive' ); ?>
					</div>
				<?php endif; ?>

					<?php if ( ! $is_community_mode ) : ?>
					<div class="rip-alert rip-alert--info rip-mb-6">
						<strong><?php esc_html_e( 'Local Shield mode active', 'reportedip-hive' ); ?></strong><br>
						<?php esc_html_e( 'The plugin is currently running in local mode. Community features like shared reports, quota management and tier upgrades are disabled. Switch to community mode to benefit from the community threat intelligence.', 'reportedip-hive' ); ?>
						<br><br>
						<a href="<?php echo esc_url( self::get_admin_page_url( 'admin.php?page=reportedip-hive-settings&tab=general' ) ); ?>" class="rip-button rip-button--primary">
							<?php esc_html_e( 'Switch to Community', 'reportedip-hive' ); ?>
						</a>
					</div>
				<?php elseif ( ! $is_configured ) : ?>
					<div class="rip-alert rip-alert--warning rip-mb-6">
						<svg class="rip-alert__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
							<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
							<line x1="12" y1="9" x2="12" y2="13"></line>
							<line x1="12" y1="17" x2="12.01" y2="17"></line>
						</svg>
						<div class="rip-alert__content">
							<div class="rip-alert__title"><?php esc_html_e( 'API key is missing', 'reportedip-hive' ); ?></div>
							<div class="rip-alert__message">
								<?php esc_html_e( 'Community mode is active, but no API key is configured. Without a key, neither reports can be sent nor quota/tier can be queried.', 'reportedip-hive' ); ?>
							</div>
							<div style="margin-top:12px; display:flex; gap:8px;">
								<a href="<?php echo esc_url( self::get_admin_page_url( 'admin.php?page=reportedip-hive-settings&tab=general' ) ); ?>" class="rip-button rip-button--primary">
									<?php esc_html_e( 'Add API key', 'reportedip-hive' ); ?>
								</a>
								<a href="<?php echo esc_url( REPORTEDIP_HIVE_REGISTER_URL ); ?>" target="_blank" rel="noopener" class="rip-button rip-button--secondary">
									<?php esc_html_e( 'Create account', 'reportedip-hive' ); ?>
								</a>
							</div>
						</div>
					</div>
				<?php endif; ?>

				<!-- Current Status -->
				<div class="rip-card rip-mb-6">
					<div class="rip-card__header">
						<h2 class="rip-card__title">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
								<path d="M12 2L2 7l10 5 10-5-10-5z"/>
								<path d="M2 17l10 5 10-5"/>
								<path d="M2 12l10 5 10-5"/>
							</svg>
							<?php esc_html_e( 'Your current status', 'reportedip-hive' ); ?>
						</h2>
						<?php if ( $is_community_mode && $is_configured ) : ?>
							<a href="<?php echo esc_url( $refresh_url ); ?>" class="rip-button rip-button--ghost rip-button--sm" title="<?php esc_attr_e( 'Refresh status now', 'reportedip-hive' ); ?>">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
									<polyline points="23 4 23 10 17 10"/>
									<polyline points="1 20 1 14 7 14"/>
									<path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
								</svg>
								<?php esc_html_e( 'Refresh', 'reportedip-hive' ); ?>
							</a>
						<?php endif; ?>
					</div>
					<div class="rip-card__body">
						<?php if ( $is_community_mode && $is_configured && ! $has_quota ) : ?>
							<div class="rip-alert rip-alert--warning">
								<?php esc_html_e( 'The status could not be fetched from the service right now. Please check your API key and internet connection, then try again.', 'reportedip-hive' ); ?>
							</div>
						<?php else : ?>
							<div class="rip-stat-cards">
								<!-- Tier Card -->
								<div class="rip-stat-card">
									<div class="rip-stat-card__icon rip-stat-card__icon--info">
										<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
											<path d="M12 15l-2-2m0 0l-2-2m2 2l2-2m-2 2v6"/>
											<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
											<circle cx="12" cy="7" r="4"/>
										</svg>
									</div>
									<div class="rip-stat-card__content">
										<div class="rip-stat-card__value"><?php echo esc_html( $tier['label'] ); ?></div>
										<div class="rip-stat-card__label">
											<?php
											if ( $is_honeypot ) {
												esc_html_e( 'Honeypot-Tier (unbegrenzt)', 'reportedip-hive' );
											} else {
												esc_html_e( 'API Tier', 'reportedip-hive' );
											}
											?>
										</div>
									</div>
								</div>

								<!-- Daily Reports Card -->
								<div class="rip-stat-card">
									<div class="rip-stat-card__icon <?php echo ( $daily_limit < 0 || $remaining_reports > 0 ) ? 'rip-stat-card__icon--success' : 'rip-stat-card__icon--warning'; ?>">
										<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
											<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
											<polyline points="14 2 14 8 20 8"/>
										</svg>
									</div>
									<div class="rip-stat-card__content">
										<div class="rip-stat-card__value">
											<?php
											if ( $daily_limit < 0 ) {
												echo esc_html__( '∞', 'reportedip-hive' );
											} else {
												echo esc_html( $remaining_display . ' / ' . $daily_limit_display );
											}
											?>
										</div>
										<div class="rip-stat-card__label"><?php esc_html_e( 'Reports available today', 'reportedip-hive' ); ?></div>
									</div>
								</div>

								<!-- Queue Card -->
								<div class="rip-stat-card">
									<div class="rip-stat-card__icon <?php echo $queue_size > 50 ? 'rip-stat-card__icon--warning' : 'rip-stat-card__icon--success'; ?>">
										<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
											<line x1="8" y1="6" x2="21" y2="6"/>
											<line x1="8" y1="12" x2="21" y2="12"/>
											<line x1="8" y1="18" x2="21" y2="18"/>
											<line x1="3" y1="6" x2="3.01" y2="6"/>
											<line x1="3" y1="12" x2="3.01" y2="12"/>
											<line x1="3" y1="18" x2="3.01" y2="18"/>
										</svg>
									</div>
									<div class="rip-stat-card__content">
										<div class="rip-stat-card__value"><?php echo esc_html( number_format_i18n( $queue_size ) ); ?></div>
										<div class="rip-stat-card__label"><?php esc_html_e( 'Reports in queue', 'reportedip-hive' ); ?></div>
									</div>
								</div>

								<!-- Queue Age Card -->
								<div class="rip-stat-card">
									<div class="rip-stat-card__icon <?php echo ( isset( $queue_summary['age_days'] ) && $queue_summary['age_days'] > 3 ) ? 'rip-stat-card__icon--warning' : 'rip-stat-card__icon--info'; ?>">
										<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
											<circle cx="12" cy="12" r="10"/>
											<polyline points="12 6 12 12 16 14"/>
										</svg>
									</div>
									<div class="rip-stat-card__content">
										<div class="rip-stat-card__value">
											<?php
											if ( isset( $queue_summary['age_days'] ) ) {
												echo esc_html( sprintf( /* translators: %d: number of days */ _n( '%d day', '%d days', (int) $queue_summary['age_days'], 'reportedip-hive' ), (int) $queue_summary['age_days'] ) );
											} else {
												echo '—';
											}
											?>
										</div>
										<div class="rip-stat-card__label"><?php esc_html_e( 'Oldest report', 'reportedip-hive' ); ?></div>
									</div>
								</div>
							</div>

							<?php if ( ! empty( $quota_status['exhausted'] ) ) : ?>
								<div class="rip-alert rip-alert--warning rip-mt-4">
									<strong><?php esc_html_e( 'Notice:', 'reportedip-hive' ); ?></strong>
									<?php echo esc_html( $quota_status['message'] ); ?>
									<?php if ( $reset_formatted ) : ?>
										<br>
										<small>
											<?php
											echo esc_html(
												sprintf(
													/* translators: %s: reset date/time */
													__( 'Reset: %s', 'reportedip-hive' ),
													$reset_formatted
												)
											);
											?>
										</small>
									<?php endif; ?>
								</div>
							<?php endif; ?>

							<?php if ( $queue_size > 0 && $daily_limit > 0 && $days_to_clear > 1 ) : ?>
								<div class="rip-alert rip-alert--info rip-mt-4">
									<?php
									echo esc_html(
										sprintf(
											/* translators: %d: days to clear queue */
											__( 'At current quota, the queue will clear in about %d days.', 'reportedip-hive' ),
											$days_to_clear
										)
									);
									?>
								</div>
							<?php endif; ?>
						<?php endif; ?>
					</div>
				</div>

				<!-- Upgrade Options -->
				<div class="rip-card rip-mb-6">
					<div class="rip-card__header">
						<h2 class="rip-card__title">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
								<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
							</svg>
							<?php esc_html_e( 'Tier overview', 'reportedip-hive' ); ?>
						</h2>
					</div>
					<div class="rip-card__body">
						<?php
						$active_slug = $tier['slug'];
						$plans       = array_filter(
							$this->get_tier_definitions(),
							static function ( $plan ) {
								return ! empty( $plan['in_pricing'] );
							}
						);
						$unlimited   = __( 'Unlimited', 'reportedip-hive' );
						?>
						<?php
						$mode_manager_for_relay = ReportedIP_Hive_Mode_Manager::get_instance();
						$mail_relay_status      = $mode_manager_for_relay->feature_status( 'mail_relay_via_api' );
						$sms_relay_status       = $mode_manager_for_relay->feature_status( 'sms_relay_via_api' );
						?>
						<div class="rip-relay-highlights" style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px;">
							<div class="rip-card rip-relay-highlight rip-relay-highlight--mail">
								<h3 style="margin:0 0 8px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
									<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
									<?php esc_html_e( '100% mail delivery via reportedip.de', 'reportedip-hive' ); ?>
									<?php self::render_tier_marker( $mail_relay_status ); ?>
								</h3>
								<ul style="margin:8px 0 0 18px;padding:0;color:var(--rip-gray-700,#374151);">
									<li><?php esc_html_e( 'Clean SPF / DKIM / DMARC reputation — no more spam folders', 'reportedip-hive' ); ?></li>
									<li><?php esc_html_e( 'No SMTP setup on your server, no own credentials to rotate', 'reportedip-hive' ); ?></li>
									<li><?php esc_html_e( 'Branded sender, optional reply-to override', 'reportedip-hive' ); ?></li>
								</ul>
								<p style="margin-top:10px;font-size:0.875rem;color:var(--rip-gray-500,#6B7280);">
									<?php esc_html_e( 'Included with Professional (500/mo) and Business (2,500/mo).', 'reportedip-hive' ); ?>
								</p>
							</div>
							<div class="rip-card rip-relay-highlight rip-relay-highlight--sms">
								<h3 style="margin:0 0 8px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
									<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12" y2="18"/></svg>
									<?php esc_html_e( 'Managed SMS-2FA delivery (Professional and above)', 'reportedip-hive' ); ?>
									<?php self::render_tier_marker( $sms_relay_status ); ?>
								</h3>
								<ul style="margin:8px 0 0 18px;padding:0;color:var(--rip-gray-700,#374151);">
									<li><?php esc_html_e( 'No third-party SMS contract, no top-up management', 'reportedip-hive' ); ?></li>
									<li><?php esc_html_e( 'Anti-fraud routing — high-risk destinations blocked, GDPR-friendly', 'reportedip-hive' ); ?></li>
									<li><?php esc_html_e( 'Server-side anti-spam: per-recipient backoff (2/5/15/30/60 min)', 'reportedip-hive' ); ?></li>
								</ul>
								<p style="margin-top:10px;font-size:0.875rem;color:var(--rip-gray-500,#6B7280);">
									<?php esc_html_e( 'Included with Professional (25/mo) and Business (75/mo + bundles).', 'reportedip-hive' ); ?>
								</p>
							</div>
						</div>

						<div class="rip-pricing-grid">
							<?php foreach ( $plans as $slug => $plan ) : ?>
								<?php
								$is_active   = ( $active_slug === $slug );
								$reports_txt = $plan['reports_day'] < 0 ? $unlimited : number_format_i18n( $plan['reports_day'] );
								$checks_txt  = $plan['checks_day'] < 0 ? $unlimited : number_format_i18n( $plan['checks_day'] );
								$mail_txt    = isset( $plan['mail_per_mo'] ) ? ( $plan['mail_per_mo'] < 0 ? $unlimited : ( $plan['mail_per_mo'] > 0 ? number_format_i18n( $plan['mail_per_mo'] ) . '/mo' : '—' ) ) : '—';
								$sms_txt     = isset( $plan['sms_per_mo'] ) ? ( $plan['sms_per_mo'] < 0 ? $unlimited : ( $plan['sms_per_mo'] > 0 ? number_format_i18n( $plan['sms_per_mo'] ) . '/mo' : '—' ) ) : '—';
								$domains_txt = isset( $plan['domains'] ) ? ( $plan['domains'] < 0 ? $unlimited : (string) $plan['domains'] ) : '1';
								$price_txt   = isset( $plan['price'] ) ? (string) $plan['price'] : '';
								?>
								<div class="rip-pricing-card <?php echo $is_active ? 'rip-pricing-card--active' : ''; ?>">
									<?php if ( $is_active ) : ?>
										<span class="rip-pricing-card__badge"><?php esc_html_e( 'Current tier', 'reportedip-hive' ); ?></span>
									<?php endif; ?>
									<h3 class="rip-pricing-card__title"><?php echo esc_html( $plan['label'] ); ?></h3>
									<?php if ( '' !== $price_txt ) : ?>
										<p class="rip-pricing-card__price-tag" style="font-weight:600;color:var(--rip-primary,#4F46E5);margin:4px 0;">
											<?php echo esc_html( $price_txt ); ?>
										</p>
									<?php endif; ?>
									<p class="rip-pricing-card__price">
										<?php echo esc_html( $reports_txt ); ?>
										<small><?php esc_html_e( 'Reports/day', 'reportedip-hive' ); ?></small>
									</p>
									<p class="rip-pricing-card__subprice">
										<?php
										echo esc_html(
											sprintf(
												/* translators: %s: number of API checks */
												__( '%s API checks/day', 'reportedip-hive' ),
												$checks_txt
											)
										);
										?>
									</p>
									<p class="rip-pricing-card__subprice" style="font-size:0.8125rem;color:var(--rip-gray-600,#4B5563);">
										<?php
										/* translators: %s: monthly mail relay allowance, e.g. "500 / month" or "unlimited". */
										echo esc_html( sprintf( __( 'Mail relay: %s', 'reportedip-hive' ), $mail_txt ) );
										?>
										&nbsp;·&nbsp;
										<?php
										/* translators: %s: monthly SMS relay allowance, e.g. "25 / month" or "unlimited". */
										echo esc_html( sprintf( __( 'SMS relay: %s', 'reportedip-hive' ), $sms_txt ) );
										?>
										&nbsp;·&nbsp;
										<?php
										/* translators: %s: number of domains the plan covers, e.g. "3" or "unlimited". */
										echo esc_html( sprintf( __( 'Domains: %s', 'reportedip-hive' ), $domains_txt ) );
										?>
									</p>
									<ul class="rip-pricing-card__features">
										<?php foreach ( $plan['features'] as $feature ) : ?>
											<li><?php echo esc_html( $feature ); ?></li>
										<?php endforeach; ?>
									</ul>
									<?php if ( $is_active ) : ?>
										<span class="rip-button rip-button--secondary rip-button--full-width rip-button--disabled">
											<?php esc_html_e( 'Current plan', 'reportedip-hive' ); ?>
										</span>
									<?php elseif ( 'contact' === $plan['cta_type'] ) : ?>
										<a href="<?php echo esc_url( $contact_url ); ?>" class="rip-button rip-button--primary rip-button--full-width">
											<?php esc_html_e( 'Kontakt aufnehmen', 'reportedip-hive' ); ?>
										</a>
									<?php else : ?>
										<a href="<?php echo esc_url( $upgrade_url ); ?>" target="_blank" rel="noopener" class="rip-button rip-button--primary rip-button--full-width">
											<?php esc_html_e( 'Upgrade', 'reportedip-hive' ); ?>
										</a>
									<?php endif; ?>
								</div>
							<?php endforeach; ?>
						</div>

						<?php if ( $is_honeypot ) : ?>
							<div class="rip-alert rip-alert--success rip-mt-4">
								<strong><?php esc_html_e( 'Honeypot status detected', 'reportedip-hive' ); ?></strong> —
								<?php esc_html_e( 'Your key has honeypot privileges: unlimited reports, unlimited API checks, higher weighting.', 'reportedip-hive' ); ?>
							</div>
						<?php endif; ?>
					</div>
				</div>

				<!-- Honeypot Program -->
				<div class="rip-highlight-card rip-mb-6">
					<h2 class="rip-highlight-card__title">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
							<path d="M12 2a10 10 0 0 1 10 10c0 5.52-4.48 10-10 10S2 17.52 2 12 6.48 2 12 2z"/>
							<path d="M12 6v6l4 2"/>
						</svg>
						<?php esc_html_e( 'Honeypot program (free!)', 'reportedip-hive' ); ?>
					</h2>

					<p>
						<?php esc_html_e( 'Running a honeypot server? Join our honeypot network and enjoy special benefits:', 'reportedip-hive' ); ?>
					</p>

					<ul>
						<li><strong><?php esc_html_e( 'Unlimited reports', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'No daily limits', 'reportedip-hive' ); ?></li>
						<li><strong><?php esc_html_e( 'Higher weighting', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'Your reports count more', 'reportedip-hive' ); ?></li>
						<li><strong><?php esc_html_e( 'Special API keys', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'Optimised for automated systems', 'reportedip-hive' ); ?></li>
						<li><strong><?php esc_html_e( 'Community recognition', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'Visible as an active contributor', 'reportedip-hive' ); ?></li>
					</ul>

					<a href="<?php echo esc_url( $honeypot_url ); ?>" target="_blank" rel="noopener" class="rip-button rip-button--primary rip-mt-3">
						<?php esc_html_e( 'Learn more about the honeypot program', 'reportedip-hive' ); ?>
					</a>
				</div>

				<!-- Activity Summary -->
				<div class="rip-card">
					<div class="rip-card__header">
						<h2 class="rip-card__title">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
								<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
							</svg>
							<?php esc_html_e( 'Your activity (last 30 days)', 'reportedip-hive' ); ?>
						</h2>
					</div>
					<div class="rip-card__body">
						<?php
						$failed_logins     = (int) ( $security_summary['summary']->total_failed_logins ?? 0 );
						$comment_spam      = (int) ( $security_summary['summary']->total_comment_spam ?? 0 );
						$xmlrpc_calls      = (int) ( $security_summary['summary']->total_xmlrpc_calls ?? 0 );
						$reputation_blocks = (int) ( $security_summary['summary']->total_reputation_blocks ?? 0 );
						$total_events      = $failed_logins + $comment_spam + $xmlrpc_calls;
						$total_blocked     = (int) ( $security_summary['summary']->total_blocked_ips ?? 0 );
						$total_api_reports = (int) ( $security_summary['summary']->total_api_reports ?? 0 );

						$api_stats_raw = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_stats', array() );
						$api_stats     = is_array( $api_stats_raw ) ? $api_stats_raw : array();
						$api_total     = (int) ( $api_stats['total_calls'] ?? 0 );
						$api_success   = (float) ( $api_stats['success_rate'] ?? 0 );
						?>

						<div class="rip-activity-stats">
							<div class="rip-activity-stat">
								<div class="rip-activity-stat__value rip-activity-stat__value--danger"><?php echo esc_html( number_format_i18n( $total_events ) ); ?></div>
								<div class="rip-activity-stat__label"><?php esc_html_e( 'Security events', 'reportedip-hive' ); ?></div>
							</div>
							<div class="rip-activity-stat">
								<div class="rip-activity-stat__value rip-activity-stat__value--warning"><?php echo esc_html( number_format_i18n( $total_blocked ) ); ?></div>
								<div class="rip-activity-stat__label"><?php esc_html_e( 'IPs blocked', 'reportedip-hive' ); ?></div>
							</div>
							<div class="rip-activity-stat">
								<div class="rip-activity-stat__value rip-activity-stat__value--success"><?php echo esc_html( number_format_i18n( $total_api_reports ) ); ?></div>
								<div class="rip-activity-stat__label"><?php esc_html_e( 'Reported to community', 'reportedip-hive' ); ?></div>
							</div>
							<div class="rip-activity-stat">
								<div class="rip-activity-stat__value rip-activity-stat__value--danger"><?php echo esc_html( number_format_i18n( $failed_logins ) ); ?></div>
								<div class="rip-activity-stat__label"><?php esc_html_e( 'Failed logins', 'reportedip-hive' ); ?></div>
							</div>
							<div class="rip-activity-stat">
								<div class="rip-activity-stat__value rip-activity-stat__value--warning"><?php echo esc_html( number_format_i18n( $comment_spam ) ); ?></div>
								<div class="rip-activity-stat__label"><?php esc_html_e( 'Comment spam', 'reportedip-hive' ); ?></div>
							</div>
							<div class="rip-activity-stat">
								<div class="rip-activity-stat__value rip-activity-stat__value--info"><?php echo esc_html( number_format_i18n( $reputation_blocks ) ); ?></div>
								<div class="rip-activity-stat__label"><?php esc_html_e( 'Reputation blocks', 'reportedip-hive' ); ?></div>
							</div>
							<?php if ( $api_total > 0 ) : ?>
							<div class="rip-activity-stat">
								<div class="rip-activity-stat__value rip-activity-stat__value--info"><?php echo esc_html( number_format_i18n( $api_total ) ); ?></div>
								<div class="rip-activity-stat__label"><?php esc_html_e( 'API calls (lifetime)', 'reportedip-hive' ); ?></div>
							</div>
							<div class="rip-activity-stat">
								<div class="rip-activity-stat__value rip-activity-stat__value--success"><?php echo esc_html( number_format_i18n( $api_success ) ); ?>%</div>
								<div class="rip-activity-stat__label"><?php esc_html_e( 'API success rate', 'reportedip-hive' ); ?></div>
							</div>
							<?php endif; ?>
						</div>

						<?php if ( $total_events > 0 && $total_api_reports === 0 && 'free' === $tier['slug'] ) : ?>
							<div class="rip-alert rip-alert--info rip-mt-4">
								<strong><?php esc_html_e( 'Recommendation:', 'reportedip-hive' ); ?></strong>
								<?php
								echo esc_html(
									sprintf(
										/* translators: %d: number of events */
										__( 'You have detected %d security events but have not reported anything to the community yet. A Contributor upgrade lets you share up to 200 reports per day and strengthens threat intelligence for everyone.', 'reportedip-hive' ),
										$total_events
									)
								);
								?>
								<br><br>
								<a href="<?php echo esc_url( $upgrade_url ); ?>" target="_blank" rel="noopener" class="rip-button rip-button--primary rip-button--sm">
									<?php esc_html_e( 'Upgrade now', 'reportedip-hive' ); ?>
								</a>
							</div>
						<?php endif; ?>
					</div>
				</div>

				<?php endif; ?>

				<?php if ( 'promote' === $subtab ) : ?>
					<?php $this->render_promote_tab(); ?>
				<?php endif; ?>

			</div>

		<?php self::render_page_footer(); ?>
		<?php
	}

	/**
	 * Render the "Promote" sub-tab inside the Community page.
	 *
	 * Surfaces the auto-footer toggle plus copy-to-clipboard previews for the
	 * four public shortcodes that drive backlinks to reportedip.de.
	 *
	 * @since 1.3.0
	 */
	private function render_promote_tab() {
		$auto_enabled = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_footer_enabled', false );
		$auto_variant = ReportedIP_Hive_Frontend_Shortcodes::sanitize_footer_variant( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_footer_variant', 'badge' ) );
		$auto_align   = $this->sanitize_auto_footer_align( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_footer_align', 'center' ) );

		$shortcodes = ReportedIP_Hive_Frontend_Shortcodes::get_instance();

		$showcase = array(
			array(
				'variant'   => 'badge',
				'title'     => __( 'Footer Badge', 'reportedip-hive' ),
				'desc'      => __( 'Compact "Protected by ReportedIP Hive" badge — fits any footer or sidebar.', 'reportedip-hive' ),
				'shortcode' => '[reportedip_badge]',
				'args'      => array(),
			),
			array(
				'variant'   => 'stat',
				'title'     => __( 'Stat Card — All-Time', 'reportedip-hive' ),
				'desc'      => __( 'Cumulative threat count since installation — animates up on first scroll into view, with a live indicator dot.', 'reportedip-hive' ),
				'shortcode' => '[reportedip_stat type="attacks_total" tone="trust"]',
				'args'      => array(
					'type' => 'attacks_total',
					'tone' => 'trust',
				),
			),
			array(
				'variant'   => 'banner',
				'title'     => __( 'Community Banner', 'reportedip-hive' ),
				'desc'      => __( 'Wider banner that pitches community participation — perfect for landing pages or "About" sections.', 'reportedip-hive' ),
				'shortcode' => '[reportedip_banner type="reports_total" tone="community"]',
				'args'      => array(
					'type' => 'reports_total',
					'tone' => 'community',
				),
			),
			array(
				'variant'   => 'shield',
				'title'     => __( 'Shield Icon', 'reportedip-hive' ),
				'desc'      => __( 'Discreet icon-only shield — pair with a footer line or a fixed corner widget.', 'reportedip-hive' ),
				'shortcode' => '[reportedip_shield]',
				'args'      => array(),
			),
			array(
				'variant'   => 'stat',
				'title'     => __( 'Login Activity', 'reportedip-hive' ),
				'desc'      => __( 'Live successful-login counter (30 days) — a quiet confidence signal in a customer dashboard or "About" footer.', 'reportedip-hive' ),
				'shortcode' => '[reportedip_stat type="logins_30d" tone="trust"]',
				'args'      => array(
					'type' => 'logins_30d',
					'tone' => 'trust',
				),
			),
		);

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- WordPress sets `settings-updated` on its own redirect after the Settings API form save; not user-mutable.
		if ( isset( $_GET['settings-updated'] ) ) :
			?>
			<div class="rip-alert rip-alert--success rip-mb-6">
				<?php esc_html_e( 'Settings saved.', 'reportedip-hive' ); ?>
			</div>
			<?php
		endif;
		?>

		<div class="rip-card rip-mb-6">
			<div class="rip-card__header">
				<h2 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
					<?php esc_html_e( 'Help grow the ReportedIP community', 'reportedip-hive' ); ?>
				</h2>
			</div>
			<div class="rip-card__body">
				<p>
					<?php esc_html_e( 'Add a small badge to your site that links back to ReportedIP. Every link strengthens the community network and helps more sites stay protected.', 'reportedip-hive' ); ?>
				</p>
				<p style="color:var(--rip-gray-600);">
					<?php esc_html_e( 'Banners render inside Shadow DOM, so your theme cannot override the design. The link itself stays in regular HTML — search engines will find it and credit your site.', 'reportedip-hive' ); ?>
				</p>
			</div>
		</div>

		<?php
		$preview_align_map = array(
			'left'   => 'flex-start',
			'center' => 'center',
			'right'  => 'flex-end',
			'below'  => 'center',
		);
		$preview_justify   = $preview_align_map[ $auto_align ] ?? 'center';
		?>
		<div class="rip-card rip-mb-6">
			<div class="rip-card__header">
				<h2 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
					<?php esc_html_e( 'Auto-footer badge', 'reportedip-hive' ); ?>
				</h2>
			</div>
			<div class="rip-card__body">
				<div id="rip-auto-footer-preview" style="background:var(--rip-gray-50);border:1px dashed var(--rip-gray-300);border-radius:var(--rip-radius-lg);padding:1.5em;min-height:90px;display:flex;align-items:center;justify-content:<?php echo esc_attr( $preview_justify ); ?>;margin-bottom:.6em;">
					<?php
					echo $shortcodes->build_element( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- build_element() escapes its own attributes; the custom-element wrapper would be stripped by wp_kses.
						$auto_variant,
						array(
							'utm_medium' => 'admin-preview',
							'theme'      => 'dark',
							'align'      => 'center',
						)
					);
					?>
				</div>
				<p style="margin:0 0 1.25em;font-size:.85em;color:var(--rip-gray-600);">
					<?php esc_html_e( 'Live preview — updates as you change the variant and position below.', 'reportedip-hive' ); ?>
				</p>
				<form method="post" action="<?php echo esc_url( self::settings_form_action() ); ?>">
					<?php settings_fields( 'reportedip_hive_promote' ); ?>
					<input type="hidden" name="_wp_http_referer" value="<?php echo esc_attr( self::get_admin_page_url( 'admin.php?page=reportedip-hive-community&subtab=promote' ) ); ?>">

					<p style="margin-top:0;">
						<label style="display:flex;align-items:center;gap:.5em;cursor:pointer;">
							<input type="checkbox" name="reportedip_hive_auto_footer_enabled" value="1" <?php checked( $auto_enabled ); ?>>
							<strong><?php esc_html_e( 'Show a "Protected by ReportedIP Hive" badge in the site footer', 'reportedip-hive' ); ?></strong>
						</label>
						<span style="display:block;margin-left:1.65em;color:var(--rip-gray-600);font-size:.9em;">
							<?php esc_html_e( 'Renders automatically at the bottom of every front-end page. No shortcode placement needed.', 'reportedip-hive' ); ?>
						</span>
					</p>

					<fieldset style="margin-top:1.25em;">
						<legend style="font-weight:600;margin-bottom:.5em;"><?php esc_html_e( 'Variant', 'reportedip-hive' ); ?></legend>
						<label style="display:inline-flex;align-items:center;gap:.4em;margin-right:1.5em;">
							<input type="radio" name="reportedip_hive_auto_footer_variant" value="badge" <?php checked( $auto_variant, 'badge' ); ?>>
							<?php esc_html_e( 'Footer badge', 'reportedip-hive' ); ?>
						</label>
						<label style="display:inline-flex;align-items:center;gap:.4em;">
							<input type="radio" name="reportedip_hive_auto_footer_variant" value="shield" <?php checked( $auto_variant, 'shield' ); ?>>
							<?php esc_html_e( 'Shield icon', 'reportedip-hive' ); ?>
						</label>
					</fieldset>

					<fieldset style="margin-top:1.25em;">
						<legend style="font-weight:600;margin-bottom:.5em;"><?php esc_html_e( 'Position', 'reportedip-hive' ); ?></legend>
						<label style="display:inline-flex;align-items:center;gap:.4em;margin-right:1.5em;">
							<input type="radio" name="reportedip_hive_auto_footer_align" value="left" <?php checked( $auto_align, 'left' ); ?>>
							<?php esc_html_e( 'Left', 'reportedip-hive' ); ?>
						</label>
						<label style="display:inline-flex;align-items:center;gap:.4em;margin-right:1.5em;">
							<input type="radio" name="reportedip_hive_auto_footer_align" value="center" <?php checked( $auto_align, 'center' ); ?>>
							<?php esc_html_e( 'Center', 'reportedip-hive' ); ?>
						</label>
						<label style="display:inline-flex;align-items:center;gap:.4em;margin-right:1.5em;">
							<input type="radio" name="reportedip_hive_auto_footer_align" value="right" <?php checked( $auto_align, 'right' ); ?>>
							<?php esc_html_e( 'Right', 'reportedip-hive' ); ?>
						</label>
						<label style="display:inline-flex;align-items:center;gap:.4em;">
							<input type="radio" name="reportedip_hive_auto_footer_align" value="below" <?php checked( $auto_align, 'below' ); ?>>
							<?php esc_html_e( 'Below content', 'reportedip-hive' ); ?>
						</label>
						<span style="display:block;margin-top:.5em;color:var(--rip-gray-600);font-size:.9em;">
							<?php esc_html_e( 'Below content renders the badge as a full-width row directly below your theme footer — works across classic and block themes.', 'reportedip-hive' ); ?>
						</span>
					</fieldset>

					<p style="margin-top:1.5em;">
						<button type="submit" class="rip-button rip-button--primary"><?php esc_html_e( 'Save', 'reportedip-hive' ); ?></button>
					</p>
				</form>
				<script>
				(function(){
					var wrap = document.getElementById('rip-auto-footer-preview');
					if (!wrap) return;
					var initial = wrap.querySelector('rip-hive-banner');
					if (!initial) return;
					var blueprint = initial.cloneNode(true);
					var alignMap = {left:'flex-start', center:'center', right:'flex-end', below:'center'};
					function getRadio(name){
						var el = document.querySelector('input[name="' + name + '"]:checked');
						return el ? el.value : '';
					}
					function rerender(){
						var variant = getRadio('reportedip_hive_auto_footer_variant') || 'badge';
						var align   = getRadio('reportedip_hive_auto_footer_align') || 'center';
						var fresh   = blueprint.cloneNode(true);
						fresh.setAttribute('data-variant', variant);
						wrap.replaceChildren(fresh);
						wrap.style.justifyContent = alignMap[align] || 'center';
					}
					document.querySelectorAll('input[name="reportedip_hive_auto_footer_variant"], input[name="reportedip_hive_auto_footer_align"]').forEach(function(r){
						r.addEventListener('change', rerender);
					});
				})();
				</script>
			</div>
		</div>

		<div class="rip-card">
			<div class="rip-card__header">
				<h2 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
					<?php esc_html_e( 'Manual shortcodes', 'reportedip-hive' ); ?>
				</h2>
			</div>
			<div class="rip-card__body">
				<p style="margin-top:0;">
					<?php esc_html_e( 'Drop any of these shortcodes into a post, page, widget, or theme template. Each one renders a self-contained banner that links back to reportedip.de with UTM tracking.', 'reportedip-hive' ); ?>
				</p>

				<div style="margin:1em 0 1.5em;padding:1em 1.25em;background:linear-gradient(135deg, rgba(79, 70, 229, 0.08), rgba(124, 58, 237, 0.08));border:1px solid rgba(79, 70, 229, 0.18);border-radius:var(--rip-radius-lg);">
					<strong style="display:block;margin-bottom:.25em;color:var(--rip-gray-900);"><?php esc_html_e( 'Featured: show your contribution to the community', 'reportedip-hive' ); ?></strong>
					<p style="margin:0 0 .5em;color:var(--rip-gray-700);font-size:.9em;">
						<?php esc_html_e( 'A "contributor" tone reads as "ReportedIP Contributor" with a count of API reports your site has shared with the community in the last 30 days.', 'reportedip-hive' ); ?>
					</p>
					<code style="display:inline-block;background:#fff;padding:.4em .75em;border-radius:var(--rip-radius-sm);font-size:.85em;border:1px solid var(--rip-gray-200);">[reportedip_stat type="api_reports_30d" tone="contributor"]</code>
				</div>

				<div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:1.25em;margin-top:1.25em;">
					<?php foreach ( $showcase as $info ) : ?>
						<div style="border:1px solid var(--rip-gray-200);border-radius:var(--rip-radius-lg);padding:1.25em;background:var(--rip-gray-50);">
							<h3 style="margin-top:0;margin-bottom:.5em;font-size:1em;"><?php echo esc_html( $info['title'] ); ?></h3>
							<p style="color:var(--rip-gray-600);font-size:.9em;margin-top:0;margin-bottom:1em;"><?php echo esc_html( $info['desc'] ); ?></p>
							<div style="background:#fff;border:1px dashed var(--rip-gray-300);border-radius:var(--rip-radius-md);padding:1em;margin-bottom:1em;min-height:80px;display:flex;align-items:center;justify-content:center;">
								<?php
								// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- build_element() escapes its own attributes; the custom-element wrapper would be stripped by wp_kses.
								echo $shortcodes->build_element(
									$info['variant'],
									array_merge(
										array(
											'utm_medium' => 'admin-preview',
											'theme'      => 'dark',
											'align'      => 'center',
										),
										$info['args']
									)
								);
								// phpcs:enable WordPress.Security.EscapeOutput.OutputNotEscaped
								?>
							</div>
							<div style="display:flex;gap:.5em;align-items:center;">
								<code style="flex:1;background:#fff;padding:.5em .75em;border-radius:var(--rip-radius-sm);font-size:.85em;border:1px solid var(--rip-gray-200);overflow-x:auto;white-space:nowrap;"><?php echo esc_html( $info['shortcode'] ); ?></code>
								<button type="button" class="rip-button rip-button--secondary rip-button--sm rip-copy-shortcode" data-shortcode="<?php echo esc_attr( $info['shortcode'] ); ?>"><?php esc_html_e( 'Copy', 'reportedip-hive' ); ?></button>
							</div>
						</div>
					<?php endforeach; ?>
				</div>

				<details style="margin-top:1.5em;">
					<summary style="cursor:pointer;font-weight:600;color:var(--rip-gray-700);"><?php esc_html_e( 'All available attributes', 'reportedip-hive' ); ?></summary>
					<div style="margin-top:1em;color:var(--rip-gray-600);font-size:.9em;line-height:1.6;">
						<p><strong><?php esc_html_e( 'type', 'reportedip-hive' ); ?></strong> — <code>attacks_total</code> (lifetime), <code>attacks_30d</code>, <code>reports_total</code>, <code>api_reports_30d</code>, <code>blocked_active</code>, <code>whitelist_active</code>, <code>logins_30d</code>, <code>spam_30d</code></p>
						<p><strong><?php esc_html_e( 'tone', 'reportedip-hive' ); ?></strong> — <code>protect</code> (default), <code>trust</code> (<em>"Secured by…"</em>), <code>community</code> (<em>"Part of the ReportedIP Hive"</em>), <code>contributor</code> (<em>"ReportedIP Contributor"</em>)</p>
						<p><strong><?php esc_html_e( 'bg', 'reportedip-hive' ); ?></strong> — Hex colour <code>#RRGGBB</code> or two stops for a gradient: <code>#FF6B00,#FFB800</code></p>
						<p><strong><?php esc_html_e( 'color', 'reportedip-hive' ); ?></strong> — Foreground hex colour</p>
						<p><strong><?php esc_html_e( 'border', 'reportedip-hive' ); ?></strong> — Hex colour or <code>none</code> (default)</p>
						<p><strong><?php esc_html_e( 'intro', 'reportedip-hive' ); ?></strong> — Override the headline text (max 80 chars)</p>
						<p><strong><?php esc_html_e( 'label', 'reportedip-hive' ); ?></strong> — Override the metric label / noun (max 80 chars)</p>
						<p><strong><?php esc_html_e( 'live', 'reportedip-hive' ); ?></strong> — <code>true</code> (default) shows a pulsing live dot, <code>false</code> hides it</p>
						<p><strong><?php esc_html_e( 'theme', 'reportedip-hive' ); ?></strong> — <code>dark</code> (default Indigo) or <code>light</code> (white card)</p>
						<p><strong><?php esc_html_e( 'align', 'reportedip-hive' ); ?></strong> — <code>left</code>, <code>center</code>, <code>right</code></p>
					</div>
				</details>
			</div>
		</div>

		<?php
		$customizer_payload = array(
			'tones'        => ReportedIP_Hive_Frontend_Shortcodes::tone_definitions(),
			'sampleValues' => $shortcodes->get_cached_stats(),
			'statLabels'   => array(
				'attacks_total'    => array(
					'label'    => __( 'attacks blocked', 'reportedip-hive' ),
					'fallback' => __( 'Active threat protection', 'reportedip-hive' ),
				),
				'attacks_30d'      => array(
					'label'    => __( 'attacks blocked (30 days)', 'reportedip-hive' ),
					'fallback' => __( 'Active threat protection', 'reportedip-hive' ),
				),
				'blocked_active'   => array(
					'label'    => __( 'IPs currently blocked', 'reportedip-hive' ),
					'fallback' => __( 'Active IP protection', 'reportedip-hive' ),
				),
				'whitelist_active' => array(
					'label'    => __( 'Trusted IPs', 'reportedip-hive' ),
					'fallback' => __( 'Trust-aware filtering', 'reportedip-hive' ),
				),
				'logins_30d'       => array(
					'label'    => __( 'Failed logins blocked (30 days)', 'reportedip-hive' ),
					'fallback' => __( 'Brute-force protection', 'reportedip-hive' ),
				),
				'spam_30d'         => array(
					'label'    => __( 'Spam comments stopped (30 days)', 'reportedip-hive' ),
					'fallback' => __( 'Comment spam protection', 'reportedip-hive' ),
				),
				'api_reports_30d'  => array(
					'label'    => __( 'reports shared this month', 'reportedip-hive' ),
					'fallback' => __( 'Community contributor', 'reportedip-hive' ),
				),
				'reports_total'    => array(
					'label'    => __( 'IPs reported to the community', 'reportedip-hive' ),
					'fallback' => __( 'Active community member', 'reportedip-hive' ),
				),
			),
			'variantTones' => array(
				'badge'  => 'protect',
				'stat'   => 'trust',
				'banner' => 'community',
				'shield' => 'protect',
			),
			'siteUrl'      => defined( 'REPORTEDIP_HIVE_SITE_URL' ) ? REPORTEDIP_HIVE_SITE_URL : 'https://reportedip.de',
		);
		?>

		<div class="rip-card rip-mt-6">
			<div class="rip-card__header">
				<h2 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 1 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
					<?php esc_html_e( 'Build your own banner', 'reportedip-hive' ); ?>
				</h2>
			</div>
			<div class="rip-card__body">
				<p style="margin-top:0;color:var(--rip-gray-600);">
					<?php esc_html_e( 'Configure every attribute. The preview updates as you change values, and the matching shortcode is generated on the right — just copy it into your post or template.', 'reportedip-hive' ); ?>
				</p>

				<div id="rip-customizer" style="display:grid;grid-template-columns:minmax(0, 1fr) minmax(0, 1fr);gap:1.5em;margin-top:1em;">
					<div>
						<div class="rip-form-group">
							<label class="rip-label" for="rip-cust-variant"><?php esc_html_e( 'Variant', 'reportedip-hive' ); ?></label>
							<select id="rip-cust-variant" class="rip-input">
								<option value="badge"><?php esc_html_e( 'Badge — compact pill', 'reportedip-hive' ); ?></option>
								<option value="stat"><?php esc_html_e( 'Stat — single big number', 'reportedip-hive' ); ?></option>
								<option value="banner" selected><?php esc_html_e( 'Banner — full marketing block', 'reportedip-hive' ); ?></option>
								<option value="shield"><?php esc_html_e( 'Shield — icon only', 'reportedip-hive' ); ?></option>
							</select>
						</div>

						<div class="rip-form-group rip-mt-3">
							<label class="rip-label" for="rip-cust-type"><?php esc_html_e( 'Stat type', 'reportedip-hive' ); ?></label>
							<select id="rip-cust-type" class="rip-input">
								<option value="attacks_total" selected><?php esc_html_e( 'attacks_total — Lifetime attacks', 'reportedip-hive' ); ?></option>
								<option value="attacks_30d"><?php esc_html_e( 'attacks_30d — Last 30 days', 'reportedip-hive' ); ?></option>
								<option value="reports_total"><?php esc_html_e( 'reports_total — Lifetime reports', 'reportedip-hive' ); ?></option>
								<option value="api_reports_30d"><?php esc_html_e( 'api_reports_30d — Reports this month', 'reportedip-hive' ); ?></option>
								<option value="blocked_active"><?php esc_html_e( 'blocked_active — Currently blocked', 'reportedip-hive' ); ?></option>
								<option value="whitelist_active"><?php esc_html_e( 'whitelist_active — Trusted IPs', 'reportedip-hive' ); ?></option>
								<option value="logins_30d"><?php esc_html_e( 'logins_30d — Failed logins (30 days)', 'reportedip-hive' ); ?></option>
								<option value="spam_30d"><?php esc_html_e( 'spam_30d — Spam (30 days)', 'reportedip-hive' ); ?></option>
							</select>
						</div>

						<div class="rip-form-group rip-mt-3">
							<label class="rip-label" for="rip-cust-tone"><?php esc_html_e( 'Tone', 'reportedip-hive' ); ?></label>
							<select id="rip-cust-tone" class="rip-input">
								<option value="protect"><?php esc_html_e( 'protect — "Protected by ReportedIP Hive"', 'reportedip-hive' ); ?></option>
								<option value="trust"><?php esc_html_e( 'trust — "Secured by ReportedIP Hive"', 'reportedip-hive' ); ?></option>
								<option value="community" selected><?php esc_html_e( 'community — "Part of the ReportedIP Hive"', 'reportedip-hive' ); ?></option>
								<option value="contributor"><?php esc_html_e( 'contributor — "ReportedIP Contributor"', 'reportedip-hive' ); ?></option>
							</select>
						</div>

						<fieldset style="margin-top:1em;">
							<legend style="font-weight:600;font-size:.9em;margin-bottom:.4em;color:var(--rip-gray-700);"><?php esc_html_e( 'Theme', 'reportedip-hive' ); ?></legend>
							<label style="display:inline-flex;align-items:center;gap:.4em;margin-right:1.25em;">
								<input type="radio" name="rip-cust-theme" value="dark" checked> <?php esc_html_e( 'Dark', 'reportedip-hive' ); ?>
							</label>
							<label style="display:inline-flex;align-items:center;gap:.4em;">
								<input type="radio" name="rip-cust-theme" value="light"> <?php esc_html_e( 'Light', 'reportedip-hive' ); ?>
							</label>
						</fieldset>

						<fieldset style="margin-top:1em;">
							<legend style="font-weight:600;font-size:.9em;margin-bottom:.4em;color:var(--rip-gray-700);"><?php esc_html_e( 'Alignment', 'reportedip-hive' ); ?></legend>
							<label style="display:inline-flex;align-items:center;gap:.4em;margin-right:1em;">
								<input type="radio" name="rip-cust-align" value="left"> <?php esc_html_e( 'Left', 'reportedip-hive' ); ?>
							</label>
							<label style="display:inline-flex;align-items:center;gap:.4em;margin-right:1em;">
								<input type="radio" name="rip-cust-align" value="center" checked> <?php esc_html_e( 'Center', 'reportedip-hive' ); ?>
							</label>
							<label style="display:inline-flex;align-items:center;gap:.4em;">
								<input type="radio" name="rip-cust-align" value="right"> <?php esc_html_e( 'Right', 'reportedip-hive' ); ?>
							</label>
						</fieldset>

						<div class="rip-form-group rip-mt-3" style="display:grid;grid-template-columns:1fr 1fr;gap:.75em;">
							<div>
								<label class="rip-label" for="rip-cust-bg1" style="display:flex;align-items:center;justify-content:space-between;gap:.4em;">
									<span><?php esc_html_e( 'Background', 'reportedip-hive' ); ?></span>
									<button type="button" class="rip-cust-clear" data-target="rip-cust-bg1" style="background:none;border:none;color:var(--rip-gray-500);cursor:pointer;font-size:.8em;text-decoration:underline;"><?php esc_html_e( 'reset', 'reportedip-hive' ); ?></button>
								</label>
								<input type="color" id="rip-cust-bg1" class="rip-input" value="#4F46E5" data-empty="1" style="height:38px;padding:2px;">
							</div>
							<div>
								<label class="rip-label" for="rip-cust-bg2" style="display:flex;align-items:center;justify-content:space-between;gap:.4em;">
									<span><?php esc_html_e( 'Gradient stop', 'reportedip-hive' ); ?></span>
									<button type="button" class="rip-cust-clear" data-target="rip-cust-bg2" style="background:none;border:none;color:var(--rip-gray-500);cursor:pointer;font-size:.8em;text-decoration:underline;"><?php esc_html_e( 'reset', 'reportedip-hive' ); ?></button>
								</label>
								<input type="color" id="rip-cust-bg2" class="rip-input" value="#7C3AED" data-empty="1" style="height:38px;padding:2px;">
							</div>
						</div>

						<div class="rip-form-group rip-mt-3" style="display:grid;grid-template-columns:1fr 1fr;gap:.75em;">
							<div>
								<label class="rip-label" for="rip-cust-color" style="display:flex;align-items:center;justify-content:space-between;gap:.4em;">
									<span><?php esc_html_e( 'Foreground', 'reportedip-hive' ); ?></span>
									<button type="button" class="rip-cust-clear" data-target="rip-cust-color" style="background:none;border:none;color:var(--rip-gray-500);cursor:pointer;font-size:.8em;text-decoration:underline;"><?php esc_html_e( 'reset', 'reportedip-hive' ); ?></button>
								</label>
								<input type="color" id="rip-cust-color" class="rip-input" value="#ffffff" data-empty="1" style="height:38px;padding:2px;">
							</div>
							<div>
								<label class="rip-label" for="rip-cust-border" style="display:flex;align-items:center;justify-content:space-between;gap:.4em;">
									<span><?php esc_html_e( 'Border', 'reportedip-hive' ); ?></span>
									<button type="button" class="rip-cust-clear" data-target="rip-cust-border" style="background:none;border:none;color:var(--rip-gray-500);cursor:pointer;font-size:.8em;text-decoration:underline;"><?php esc_html_e( 'reset', 'reportedip-hive' ); ?></button>
								</label>
								<input type="color" id="rip-cust-border" class="rip-input" value="#ffffff" data-empty="1" style="height:38px;padding:2px;">
							</div>
						</div>

						<div class="rip-form-group rip-mt-3">
							<label class="rip-label" for="rip-cust-intro"><?php esc_html_e( 'Intro override', 'reportedip-hive' ); ?></label>
							<input type="text" id="rip-cust-intro" class="rip-input" maxlength="80" placeholder="<?php esc_attr_e( 'Leave empty to use tone default', 'reportedip-hive' ); ?>">
						</div>

						<div class="rip-form-group rip-mt-3">
							<label class="rip-label" for="rip-cust-label"><?php esc_html_e( 'Label override', 'reportedip-hive' ); ?></label>
							<input type="text" id="rip-cust-label" class="rip-input" maxlength="80" placeholder="<?php esc_attr_e( 'Leave empty to use tone default', 'reportedip-hive' ); ?>">
						</div>

						<label class="rip-mt-3" style="display:inline-flex;align-items:center;gap:.5em;cursor:pointer;">
							<input type="checkbox" id="rip-cust-live" checked>
							<?php esc_html_e( 'Show pulsing live indicator', 'reportedip-hive' ); ?>
						</label>
					</div>

					<div>
						<div id="rip-cust-preview" style="background:var(--rip-gray-50);border:1px dashed var(--rip-gray-300);border-radius:var(--rip-radius-lg);padding:2em 1em;min-height:140px;display:flex;align-items:center;justify-content:center;"></div>

						<div style="margin-top:1em;">
							<label class="rip-label" style="font-weight:600;"><?php esc_html_e( 'Generated shortcode', 'reportedip-hive' ); ?></label>
							<div style="display:flex;gap:.5em;align-items:stretch;margin-top:.4em;">
								<code id="rip-cust-shortcode" style="flex:1;background:#fff;padding:.6em .8em;border-radius:var(--rip-radius-sm);font-size:.85em;border:1px solid var(--rip-gray-200);overflow-x:auto;white-space:nowrap;line-height:1.4;">[reportedip_banner]</code>
								<button type="button" id="rip-cust-copy" class="rip-button rip-button--primary rip-button--sm"><?php esc_html_e( 'Copy', 'reportedip-hive' ); ?></button>
							</div>
						</div>

						<p style="margin-top:1em;font-size:.85em;color:var(--rip-gray-600);">
							<?php esc_html_e( 'Drop the shortcode into any post, page, widget, or template. The banner will render with these exact settings.', 'reportedip-hive' ); ?>
						</p>
					</div>
				</div>
			</div>
		</div>

		<script>
		window.ripCustomizerData = <?php echo wp_json_encode( $customizer_payload ); ?>;
		(function(){
			document.querySelectorAll('.rip-copy-shortcode').forEach(function(btn){
				btn.addEventListener('click', function(){
					var sc = btn.getAttribute('data-shortcode') || '';
					copyToClipboard(sc, btn);
				});
			});

			function copyToClipboard(text, btn){
				var orig = btn.textContent;
				var done = function(){
					btn.textContent = '<?php echo esc_js( __( 'Copied!', 'reportedip-hive' ) ); ?>';
					setTimeout(function(){ btn.textContent = orig; }, 1400);
				};
				if (navigator.clipboard && navigator.clipboard.writeText) {
					navigator.clipboard.writeText(text).then(done, function(){
						window.prompt('<?php echo esc_js( __( 'Copy this shortcode:', 'reportedip-hive' ) ); ?>', text);
					});
				} else {
					window.prompt('<?php echo esc_js( __( 'Copy this shortcode:', 'reportedip-hive' ) ); ?>', text);
				}
			}

			var data = window.ripCustomizerData || {tones:{},sampleValues:{},statLabels:{},variantTones:{}};
			var $ = function(id){ return document.getElementById(id); };

			var preview = $('rip-cust-preview');
			var shortcodeEl = $('rip-cust-shortcode');
			var copyBtn = $('rip-cust-copy');
			if (!preview || !shortcodeEl) return;

			var formatNumber = function(n){
				try { return new Intl.NumberFormat().format(n); } catch(e) { return String(n); }
			};

			var attrEscape = function(s){
				return String(s).replace(/"/g, '\\"');
			};

			var readState = function(){
				var bg1El = $('rip-cust-bg1');
				var bg2El = $('rip-cust-bg2');
				var colorEl = $('rip-cust-color');
				var borderEl = $('rip-cust-border');
				return {
					variant: $('rip-cust-variant').value,
					type: $('rip-cust-type').value,
					tone: $('rip-cust-tone').value,
					theme: document.querySelector('input[name="rip-cust-theme"]:checked').value,
					align: document.querySelector('input[name="rip-cust-align"]:checked').value,
					bg1: bg1El.dataset.empty === '1' ? '' : bg1El.value,
					bg2: bg2El.dataset.empty === '1' ? '' : bg2El.value,
					color: colorEl.dataset.empty === '1' ? '' : colorEl.value,
					border: borderEl.dataset.empty === '1' ? '' : borderEl.value,
					intro: $('rip-cust-intro').value.trim(),
					label: $('rip-cust-label').value.trim(),
					live: $('rip-cust-live').checked
				};
			};

			var resolveBg = function(state){
				if (!state.bg1) return '';
				return state.bg2 ? state.bg1 + ',' + state.bg2 : state.bg1;
			};

			var resolveHeadlineNoun = function(state){
				var tone = data.tones[state.tone] || {headline:'Protected by ReportedIP Hive', noun:null};
				var stat = data.statLabels[state.type] || {label:'', fallback:'Active threat protection'};
				return {
					headline: state.intro || tone.headline,
					noun: state.label || (tone.noun !== null ? tone.noun : stat.label),
					fallback: stat.fallback
				};
			};

			var renderBanner = function(state){
				var hn = resolveHeadlineNoun(state);
				var sample = (data.sampleValues && data.sampleValues[state.type]) || 0;
				var hasValue = sample > 0;
				var metricText = hasValue ? formatNumber(sample) + ' ' + hn.noun : hn.fallback;
				var bg = resolveBg(state);

				var wrap = document.createElement('span');
				wrap.style.cssText = 'display:block;text-align:' + state.align + ';margin:0;';

				var banner = document.createElement('rip-hive-banner');
				banner.setAttribute('data-variant', state.variant);
				banner.setAttribute('data-tone', state.tone);
				banner.setAttribute('data-stat', state.type);
				banner.setAttribute('data-value', hasValue ? String(sample) : '');
				banner.setAttribute('data-headline', hn.headline);
				banner.setAttribute('data-noun', hn.noun);
				banner.setAttribute('data-metric-text', metricText);
				banner.setAttribute('data-mode', 'community');
				banner.setAttribute('data-theme', state.theme);
				banner.setAttribute('data-bg', bg);
				banner.setAttribute('data-color', state.color);
				banner.setAttribute('data-border', state.border);
				banner.setAttribute('data-live', state.live ? 'true' : 'false');
				banner.setAttribute('data-href', (data.siteUrl || 'https://reportedip.de') + '/?utm_source=hive&utm_medium=admin-customizer&utm_campaign=protected&utm_content=' + state.variant);

				var fallback = document.createElement('a');
				fallback.href = banner.getAttribute('data-href');
				fallback.rel = 'noopener';
				fallback.className = 'rip-hive-fallback-link';
				fallback.textContent = hn.headline + ' — ' + metricText;
				banner.appendChild(fallback);

				wrap.appendChild(banner);
				preview.replaceChildren(wrap);
			};

			var buildShortcode = function(state){
				var tag = 'reportedip_' + state.variant;
				var defaultTone = (data.variantTones && data.variantTones[state.variant]) || 'protect';
				var bg = resolveBg(state);
				var attrs = [];
				if (state.type !== 'attacks_total') attrs.push('type="' + state.type + '"');
				if (state.tone !== defaultTone) attrs.push('tone="' + state.tone + '"');
				if (state.theme !== 'dark') attrs.push('theme="' + state.theme + '"');
				if (state.align !== 'left') attrs.push('align="' + state.align + '"');
				if (bg) attrs.push('bg="' + bg + '"');
				if (state.color) attrs.push('color="' + state.color + '"');
				if (state.border) attrs.push('border="' + state.border + '"');
				if (state.intro) attrs.push('intro="' + attrEscape(state.intro) + '"');
				if (state.label) attrs.push('label="' + attrEscape(state.label) + '"');
				if (!state.live) attrs.push('live="false"');
				return attrs.length ? '[' + tag + ' ' + attrs.join(' ') + ']' : '[' + tag + ']';
			};

			var update = function(){
				var state = readState();
				renderBanner(state);
				shortcodeEl.textContent = buildShortcode(state);
			};

			var inputs = document.querySelectorAll('#rip-customizer input, #rip-customizer select');
			inputs.forEach(function(el){
				el.addEventListener('input', function(e){
					if (e.target && e.target.type === 'color') {
						e.target.dataset.empty = '0';
					}
					update();
				});
				el.addEventListener('change', update);
			});

			document.querySelectorAll('.rip-cust-clear').forEach(function(btn){
				btn.addEventListener('click', function(){
					var input = $(btn.getAttribute('data-target'));
					if (input) {
						input.dataset.empty = '1';
						update();
					}
				});
			});

			if (copyBtn) {
				copyBtn.addEventListener('click', function(){
					copyToClipboard(shortcodeEl.textContent, copyBtn);
				});
			}

			update();
		})();
		</script>
		<?php
	}

	/**
	 * Render the "Hardening Mode" settings tab.
	 *
	 * Tab is visible to all tiers, but the master toggle + sub-fields are
	 * disabled on Free/Contributor with a PRO-Upsell card. PRO+ users see the
	 * master toggle as on/off; while off, the sub-fields are visually grayed
	 * out via {@see assets/js/admin.js} listener on the master toggle.
	 *
	 * @return void
	 * @since  2.0.8
	 */
	private function render_hardening_mode_tab() {
		$mode_manager        = ReportedIP_Hive_Mode_Manager::get_instance();
		$status              = $mode_manager->feature_status( 'hardening_mode' );
		$is_available        = ! empty( $status['available'] );
		$tier_gated          = isset( $status['reason'] ) && 'tier' === $status['reason'];
		$master_on           = ReportedIP_Hive_Hardening_Mode::is_master_enabled();
		$is_active           = ReportedIP_Hive_Hardening_Mode::is_active();
		$expires_at          = ReportedIP_Hive_Hardening_Mode::expires_at();
		$reason              = ReportedIP_Hive_Hardening_Mode::current_reason();
		$duration            = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hardening_duration_minutes', 60 );
		$login_thresh        = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hardening_login_threshold', 2 );
		$login_window        = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hardening_login_timeframe', 5 );
		$block_thresh        = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hardening_block_threshold', 60 );
		$realtime_on         = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hardening_realtime_detection', true );
		$detect_window       = ReportedIP_Hive_Hardening_Mode::detect_window_minutes();
		$detect_min_ips      = ReportedIP_Hive_Hardening_Mode::detect_min_ips();
		$detect_min_attempts = ReportedIP_Hive_Hardening_Mode::detect_min_attempts();
		?>
		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L3 6v6c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V6l-9-4z"/><polyline points="9 12 11 14 15 10"/></svg>
				<?php esc_html_e( 'Hardening Mode on Coordinated Attack', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc">
				<?php esc_html_e( 'When the plugin detects ≥ 3 IPs / ≥ 20 failed logins in the same minute (burst), or many distinct IPs across the rolling detection window below (distributed botnet), it tightens the failed-login and reputation thresholds network-wide for the configured duration. The attack stops mid-flight instead of slipping under the per-IP threshold.', 'reportedip-hive' ); ?>
			</p>

			<?php if ( $is_active ) : ?>
				<div class="rip-alert rip-alert--warning" style="margin-bottom: var(--rip-space-4);">
					<strong><?php esc_html_e( 'Hardening Mode is currently active.', 'reportedip-hive' ); ?></strong>
					<?php
					if ( $expires_at ) {
						printf(
							/* translators: %s: HH:MM expiry time in site timezone. */
							' ' . esc_html__( 'Active until %s site time.', 'reportedip-hive' ),
							esc_html( wp_date( 'Y-m-d H:i', (int) $expires_at ) )
						);
					}
					if ( is_array( $reason ) && ! empty( $reason['unique_ips'] ) ) {
						if ( ReportedIP_Hive_Hardening_Mode::is_rolling_window_label( (string) ( $reason['time_window'] ?? '' ) ) ) {
							printf(
								/* translators: 1: number of attacking IPs, 2: total attempts. */
								' ' . esc_html__( 'Trigger: %1$d IPs, %2$d attempts across the detection window (distributed).', 'reportedip-hive' ),
								(int) $reason['unique_ips'],
								(int) $reason['total_attempts']
							);
						} else {
							printf(
								/* translators: 1: number of attacking IPs, 2: total attempts, 3: time window. */
								' ' . esc_html__( 'Trigger: %1$d IPs, %2$d attempts in minute %3$s (burst).', 'reportedip-hive' ),
								(int) $reason['unique_ips'],
								(int) $reason['total_attempts'],
								esc_html( (string) ( $reason['time_window'] ?? '' ) )
							);
						}
					}
					?>
					<button type="button" class="button button-small" id="rip-hardening-deactivate" style="margin-left: var(--rip-space-3);">
						<?php esc_html_e( 'Deactivate now', 'reportedip-hive' ); ?>
					</button>
				</div>
				<script>
				jQuery(document).ready(function($){
					$('#rip-hardening-deactivate').on('click', function(e){
						e.preventDefault();
						var $btn = $(this).prop('disabled', true);
						$.post(ajaxurl, {
							action: 'reportedip_hive_hardening_deactivate',
							nonce: '<?php echo esc_js( wp_create_nonce( 'reportedip_hive_nonce' ) ); ?>'
						}, function(response){
							if (response && response.success) {
								location.reload();
							} else {
								$btn.prop('disabled', false);
							}
						});
					});
				});
				</script>
			<?php endif; ?>

			<?php
			$show_hardening_promo = $tier_gated
				&& class_exists( 'ReportedIP_Hive_Promo_Manager' )
				&& ReportedIP_Hive_Promo_Manager::can_show( ReportedIP_Hive_Promo_Manager::KEY_HARDENING_MODE );
			if ( $show_hardening_promo ) :
				?>
				<div class="rip-alert rip-alert--info" style="margin-bottom: var(--rip-space-4);">
					<?php esc_html_e( 'Hardening Mode is part of the Professional plan and above. Upgrade to switch automatic hardening on for coordinated-attack patterns.', 'reportedip-hive' ); ?>
				</div>
				<?php
				ReportedIP_Hive_Promo_Manager::mark_shown( ReportedIP_Hive_Promo_Manager::KEY_HARDENING_MODE );
				?>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( self::settings_form_action() ); ?>" class="rip-form">
				<?php settings_fields( 'reportedip_hive_hardening_mode' ); ?>

				<div class="rip-form-group">
					<input type="hidden" name="reportedip_hive_hardening_enabled" value="0" />
						<label class="rip-toggle">
						<input
							type="checkbox"
							name="reportedip_hive_hardening_enabled"
							value="1"
							id="rip-hardening-master"
							class="rip-toggle__input"
							<?php checked( $master_on ); ?>
							<?php disabled( ! $is_available && ! $master_on ); ?>
						/>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label">
							<?php esc_html_e( 'Enable automatic hardening on coordinated-attack detection', 'reportedip-hive' ); ?>
						</span>
					</label>
					&nbsp;<?php self::render_tier_marker( $status ); ?>
					<?php if ( ! $is_available ) : ?>
						<p class="rip-help-text"><?php esc_html_e( 'Available on Professional, Business and Enterprise plans. On by default; switch it off here if you prefer manual control.', 'reportedip-hive' ); ?></p>
					<?php else : ?>
						<p class="rip-help-text"><?php esc_html_e( 'On by default for your plan. Switch it off if you prefer to rely only on the per-IP thresholds.', 'reportedip-hive' ); ?></p>
					<?php endif; ?>
				</div>

				<fieldset id="rip-hardening-sub-fields" class="rip-fieldset" <?php disabled( ! $is_available || ! $master_on ); ?>>
					<div class="rip-form-group">
						<label class="rip-toggle">
							<input type="checkbox" name="reportedip_hive_hardening_realtime_detection" value="1" class="rip-toggle__input" <?php checked( $realtime_on ); ?> />
							<span class="rip-toggle__slider"></span>
							<span class="rip-toggle__label">
								<?php esc_html_e( 'Realtime detection (in addition to the hourly cron sweep)', 'reportedip-hive' ); ?>
							</span>
						</label>
						<p class="rip-help-text"><?php esc_html_e( 'Inspects every failed login at most once per minute (debounced). Cuts reaction time from up to 60 minutes down to under one minute.', 'reportedip-hive' ); ?></p>
					</div>

					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_hardening_duration_minutes"><?php esc_html_e( 'Hardening duration (minutes)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_hardening_duration_minutes" name="reportedip_hive_hardening_duration_minutes" value="<?php echo esc_attr( (string) $duration ); ?>" min="5" max="360" class="rip-input" style="max-width: 180px;" />
						<p class="rip-help-text"><?php esc_html_e( 'How long the hardening window stays in effect after a detection. Default 60 minutes.', 'reportedip-hive' ); ?></p>
					</div>

					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_hardening_login_threshold"><?php esc_html_e( 'Failed-login threshold during hardening', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_hardening_login_threshold" name="reportedip_hive_hardening_login_threshold" value="<?php echo esc_attr( (string) $login_thresh ); ?>" min="1" max="10" class="rip-input" style="max-width: 180px;" />
						<p class="rip-help-text"><?php esc_html_e( 'Normal default is 5. Hardening tightens to this value (default 2). Manual stricter settings outside hardening are never weakened.', 'reportedip-hive' ); ?></p>
					</div>

					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_hardening_login_timeframe"><?php esc_html_e( 'Failed-login timeframe during hardening (minutes)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_hardening_login_timeframe" name="reportedip_hive_hardening_login_timeframe" value="<?php echo esc_attr( (string) $login_window ); ?>" min="1" max="60" class="rip-input" style="max-width: 180px;" />
						<p class="rip-help-text"><?php esc_html_e( 'Normal default is 15 minutes. Hardening tightens to this value (default 5).', 'reportedip-hive' ); ?></p>
					</div>

					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_hardening_block_threshold"><?php esc_html_e( 'Reputation block threshold during hardening (%)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_hardening_block_threshold" name="reportedip_hive_hardening_block_threshold" value="<?php echo esc_attr( (string) $block_thresh ); ?>" min="10" max="100" class="rip-input" style="max-width: 180px;" />
						<p class="rip-help-text"><?php esc_html_e( 'Normal default is 75 %. Hardening tightens to this value (default 60 %). IPs with a community-confidence score above this threshold are blocked before authentication.', 'reportedip-hive' ); ?></p>
					</div>

					<h3 class="rip-settings-subsection__title" style="margin-top: var(--rip-space-5);"><?php esc_html_e( 'Distributed-attack detection', 'reportedip-hive' ); ?></h3>
					<p class="rip-help-text" style="margin-top: 0;"><?php esc_html_e( 'Catches botnets that rotate IPs over several minutes — each IP stays under the per-IP block threshold, but together they breach these limits across the rolling window. Defaults are conservative enough that a small site practically never reaches them legitimately.', 'reportedip-hive' ); ?></p>

					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_hardening_detect_window_minutes"><?php esc_html_e( 'Detection window (minutes)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_hardening_detect_window_minutes" name="reportedip_hive_hardening_detect_window_minutes" value="<?php echo esc_attr( (string) $detect_window ); ?>" min="1" max="120" class="rip-input" style="max-width: 180px;" />
						<p class="rip-help-text"><?php esc_html_e( 'Rolling window over which distinct IPs and failed logins are aggregated. Default 10 minutes.', 'reportedip-hive' ); ?></p>
					</div>

					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_hardening_detect_min_ips"><?php esc_html_e( 'Minimum distinct IPs', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_hardening_detect_min_ips" name="reportedip_hive_hardening_detect_min_ips" value="<?php echo esc_attr( (string) $detect_min_ips ); ?>" min="2" max="100" class="rip-input" style="max-width: 180px;" />
						<p class="rip-help-text"><?php esc_html_e( 'How many different IPs must fail login within the window to count as distributed. Default 5.', 'reportedip-hive' ); ?></p>
					</div>

					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_hardening_detect_min_attempts"><?php esc_html_e( 'Minimum total attempts', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_hardening_detect_min_attempts" name="reportedip_hive_hardening_detect_min_attempts" value="<?php echo esc_attr( (string) $detect_min_attempts ); ?>" min="3" max="1000" class="rip-input" style="max-width: 180px;" />
						<p class="rip-help-text"><?php esc_html_e( 'Total failed logins across all those IPs within the window. Default 20.', 'reportedip-hive' ); ?></p>
					</div>
				</fieldset>

				<?php submit_button( __( 'Save Hardening Settings', 'reportedip-hive' ) ); ?>
			</form>
		</div>
		<?php
	}
}
