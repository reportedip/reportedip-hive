<?php
/**
 * Quickstart: the one-page setup that replaced the ten-step wizard.
 *
 * Asks for mode and key, detects the tier from the key check, applies
 * `ReportedIP_Hive_Defaults::recommended()` through the settings registry
 * and sends the admin to the dashboard.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.54
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Renders the quickstart page and owns its AJAX handlers.
 *
 * @since 2.1.54
 */
class ReportedIP_Hive_Quickstart {

	/**
	 * Page slug.
	 *
	 * @var string
	 */
	const PAGE_SLUG = 'reportedip-hive-quickstart';

	/**
	 * Slug of the removed wizard; requests for it land on the quickstart.
	 *
	 * @var string
	 */
	const LEGACY_SLUG = 'reportedip-hive-wizard';

	/**
	 * Nonce action shared by every quickstart AJAX call.
	 *
	 * @var string
	 */
	const NONCE = 'reportedip_quickstart_nonce';

	/**
	 * Mode manager.
	 *
	 * @var ReportedIP_Hive_Mode_Manager
	 */
	private $mode_manager;

	/**
	 * Wire hooks.
	 *
	 * @param ReportedIP_Hive_Mode_Manager $mode_manager Mode manager instance.
	 */
	public function __construct( $mode_manager ) {
		$this->mode_manager = $mode_manager;

		add_action( 'admin_menu', array( $this, 'add_page' ) );
		add_action( 'network_admin_menu', array( $this, 'add_page' ) );
		add_action( 'admin_init', array( $this, 'maybe_redirect_legacy_slug' ), 5 );
		add_action( 'admin_init', array( $this, 'maybe_redirect_after_activation' ) );
		add_action( 'admin_init', array( $this, 'maybe_render_standalone' ) );

		add_action( 'wp_ajax_reportedip_quickstart_validate_key', array( $this, 'ajax_validate_api_key' ) );
		add_action( 'wp_ajax_reportedip_quickstart_activate', array( $this, 'ajax_activate' ) );
		add_action( 'wp_ajax_reportedip_quickstart_import', array( $this, 'ajax_import_settings' ) );
		add_action( 'wp_ajax_reportedip_quickstart_validate_login_slug', array( $this, 'ajax_validate_login_slug' ) );
	}

	/**
	 * Option-writing capability, network-aware.
	 *
	 * @return bool
	 */
	private function user_can_run_quickstart() {
		return ReportedIP_Hive_Option_Routing::current_user_can_manage();
	}

	/**
	 * Hidden menu entries so both slugs route; the page itself renders
	 * standalone. The legacy slug must stay registered because core's
	 * `user_can_access_admin_page()` dies with 403 before `admin_init`
	 * for any unregistered `page=` value, so the redirect would never run.
	 * On Multisite the quickstart exists in the network admin only, so a
	 * sub-site gets no entry and core answers with its 403 page.
	 *
	 * @return void
	 */
	public function add_page() {
		if ( is_multisite() && ! is_network_admin() ) {
			return;
		}
		foreach ( array( self::PAGE_SLUG, self::LEGACY_SLUG ) as $slug ) {
			add_submenu_page(
				'',
				__( 'Quickstart', 'reportedip-hive' ),
				__( 'Quickstart', 'reportedip-hive' ),
				ReportedIP_Hive_Option_Routing::manage_capability(),
				$slug,
				'__return_null'
			);
		}
	}

	/**
	 * `page=reportedip-hive-wizard` from old docs or bookmarks lands here.
	 *
	 * @return void
	 */
	public function maybe_redirect_legacy_slug() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only routing.
		if ( ! isset( $_GET['page'] ) || self::LEGACY_SLUG !== $_GET['page'] ) {
			return;
		}
		wp_safe_redirect( self::get_url() );
		exit;
	}

	/**
	 * Render the page on `admin_init` so no admin chrome loads around it.
	 *
	 * @return void
	 */
	public function maybe_render_standalone() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only routing.
		if ( ! isset( $_GET['page'] ) || self::PAGE_SLUG !== $_GET['page'] ) {
			return;
		}
		if ( is_multisite() && ! is_network_admin() ) {
			return;
		}
		if ( ! $this->user_can_run_quickstart() ) {
			return;
		}
		$this->render();
	}

	/**
	 * One-shot redirect after plugin activation.
	 *
	 * The activation marker is consumed only by a request a browser follows,
	 * see {@see request_can_redirect()}.
	 *
	 * @return void
	 */
	public function maybe_redirect_after_activation() {
		if ( ! $this->request_can_redirect() ) {
			return;
		}
		if ( ! get_site_transient( 'reportedip_hive_activation_redirect' ) ) {
			return;
		}
		delete_site_transient( 'reportedip_hive_activation_redirect' );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only routing.
		if ( is_network_admin() || isset( $_GET['activate-multi'] ) ) {
			return;
		}
		if ( $this->mode_manager->is_wizard_completed() ) {
			return;
		}
		wp_safe_redirect( self::get_url() );
		exit;
	}

	/**
	 * Whether the current request is one a redirect can actually reach.
	 *
	 * admin-ajax, cron, REST, XML-RPC, WP-CLI and non-GET requests would
	 * consume the one-shot marker without a browser ever following the 302.
	 *
	 * @return bool
	 */
	private function request_can_redirect() {
		if ( wp_doing_ajax() || wp_doing_cron() ) {
			return false;
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return false;
		}
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return false;
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return false;
		}
		$method = isset( $_SERVER['REQUEST_METHOD'] )
			? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) )
			: 'GET';
		return 'GET' === $method;
	}

	/**
	 * Feature rows shown under "What gets switched on", as label => tier.
	 *
	 * The dashboard reuses this list, so it lives here as a static.
	 *
	 * @return array<int, array{label:string, tier:string}>
	 */
	public static function feature_rows() {
		return array(
			array(
				'label' => __( 'Brute-force protection with automatic blocking (Balanced level)', 'reportedip-hive' ),
				'tier'  => 'free',
			),
			array(
				'label' => __( 'Firewall against injection and scanners', 'reportedip-hive' ),
				'tier'  => 'free',
			),
			array(
				'label' => __( 'Community reputation, block from 75 % confidence', 'reportedip-hive' ),
				'tier'  => 'free',
			),
			array(
				'label' => __( 'Bot verification, spam and registration protection', 'reportedip-hive' ),
				'tier'  => 'free',
			),
			array(
				'label' => __( 'Basic security headers', 'reportedip-hive' ),
				'tier'  => 'free',
			),
			array(
				'label' => __( 'Logs for 30 days, IP addresses anonymised after 7 days', 'reportedip-hive' ),
				'tier'  => 'free',
			),
			array(
				'label' => __( 'Hardening Mode during attack waves', 'reportedip-hive' ),
				'tier'  => 'professional',
			),
			array(
				'label' => __( 'Block Tor exit nodes', 'reportedip-hive' ),
				'tier'  => 'professional',
			),
			array(
				'label' => __( 'HSTS header', 'reportedip-hive' ),
				'tier'  => 'professional',
			),
			array(
				'label' => __( 'Storefront 2FA for WooCommerce customers', 'reportedip-hive' ),
				'tier'  => 'professional',
			),
			array(
				'label' => __( '2FA mails and SMS through the EU relay, logs for 90 days', 'reportedip-hive' ),
				'tier'  => 'professional',
			),
			array(
				'label' => __( 'Audit trail and account blocking, logs for one year', 'reportedip-hive' ),
				'tier'  => 'business',
			),
		);
	}

	/**
	 * Whether the Business teaser is worth showing to a Professional site.
	 *
	 * @return bool
	 */
	private function business_signal() {
		if ( class_exists( 'WooCommerce' ) || is_multisite() ) {
			return true;
		}
		$counts = count_users();
		return (int) ( $counts['total_users'] ?? 0 ) > 25;
	}

	/**
	 * Render the standalone page.
	 *
	 * @return void
	 */
	private function render() {
		show_admin_bar( false );
		ReportedIP_Hive::isolate_standalone_frontend_page();
		$this->enqueue_assets();
		?>
		<!DOCTYPE html>
		<html <?php language_attributes(); ?>>
		<head>
			<meta charset="<?php bloginfo( 'charset' ); ?>">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title><?php esc_html_e( 'ReportedIP Hive Quickstart', 'reportedip-hive' ); ?></title>
			<?php wp_head(); ?>
		</head>
		<body class="rip-wizard-page rip-setup-wizard rip-quickstart-page">
			<div class="rip-wizard">
				<?php $this->render_header(); ?>
				<div class="rip-wizard__content">
					<?php $this->render_body(); ?>
				</div>
				<?php $this->render_footer(); ?>
			</div>
			<?php wp_footer(); ?>
		</body>
		</html>
		<?php
		exit;
	}

	/**
	 * Styles, script and localisation.
	 *
	 * @return void
	 */
	private function enqueue_assets() {
		$ver  = REPORTEDIP_HIVE_VERSION;
		$base = REPORTEDIP_HIVE_PLUGIN_URL;

		wp_enqueue_style( 'reportedip-hive-design-system', $base . 'assets/css/design-system.css', array(), $ver );
		wp_enqueue_style( 'reportedip-hive-wizard', $base . 'assets/css/wizard.css', array( 'reportedip-hive-design-system' ), $ver );
		wp_enqueue_script( 'jquery-core' );
		wp_enqueue_script( 'reportedip-hive-quickstart', $base . 'assets/js/quickstart.js', array( 'jquery-core' ), $ver, true );

		$tier = $this->mode_manager->get_current_tier();
		wp_localize_script(
			'reportedip-hive-quickstart',
			'reportedipQuickstart',
			array(
				'ajaxUrl'     => admin_url( 'admin-ajax.php' ),
				'nonce'       => wp_create_nonce( self::NONCE ),
				'savedApiKey' => (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' ),
				'tier'        => $tier,
				'strings'     => array(
					'validating'  => __( 'Checking…', 'reportedip-hive' ),
					'valid'       => __( 'Key is valid.', 'reportedip-hive' ),
					'invalid'     => __( 'Invalid key.', 'reportedip-hive' ),
					'error'       => __( 'Check failed. Please try again.', 'reportedip-hive' ),
					'missingKey'  => __( 'Please enter your Community Access Key.', 'reportedip-hive' ),
					'activating'  => __( 'Switching protection on…', 'reportedip-hive' ),
					/* translators: %1$s: used domains, %2$s: domain limit */
					'domains'     => __( '%1$s of %2$s domains in use', 'reportedip-hive' ),
					'keyRequired' => __( 'Community Network needs a checked Community Access Key. Check the key above or choose Local Shield.', 'reportedip-hive' ),
				),
			)
		);
	}

	/**
	 * Logo, tier badge.
	 *
	 * @return void
	 */
	private function render_header() {
		?>
		<header class="rip-wizard__header">
			<div class="rip-wizard__logo">
				<svg class="rip-wizard__logo-icon" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
					<path d="M20 4L6 10v10c0 9.2 6.4 17.8 14 20 7.6-2.2 14-10.8 14-20V10L20 4z" fill="currentColor" opacity="0.2"/>
					<path d="M20 4L6 10v10c0 9.2 6.4 17.8 14 20 7.6-2.2 14-10.8 14-20V10L20 4zm0 3.5L31 12v8c0 7.5-5.2 14.5-11 16.5-5.8-2-11-9-11-16.5v-8L20 7.5z" fill="currentColor"/>
					<path d="M18 24l-4-4 1.4-1.4L18 21.2l6.6-6.6L26 16l-8 8z" fill="currentColor"/>
				</svg>
				<span class="rip-wizard__logo-text">ReportedIP Hive</span>
			</div>
			<div class="rip-wizard__header-actions" id="rip-quickstart-tier-badge">
				<?php ReportedIP_Hive_Admin_Settings::render_tier_badge(); ?>
			</div>
		</header>
		<?php
	}

	/**
	 * Mode cards, key, feature list, switches, teaser, actions, import.
	 *
	 * @return void
	 */
	private function render_body() {
		$mode = 'community';
		if ( $this->mode_manager->is_wizard_completed() && 'local' === $this->mode_manager->get_mode() ) {
			$mode = 'local';
		}
		$api_key      = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' );
		$tier         = $this->mode_manager->get_current_tier();
		$register_url = add_query_arg(
			array(
				'site'       => wp_parse_url( home_url(), PHP_URL_HOST ),
				'utm_source' => 'hive',
				'utm_medium' => 'quickstart',
			),
			REPORTEDIP_HIVE_REGISTER_URL
		);
		$check_icon   = '<svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>';
		?>
		<div class="rip-wizard__mode-select rip-quickstart">
			<h1 class="rip-wizard__title"><?php esc_html_e( 'Set up ReportedIP Hive', 'reportedip-hive' ); ?></h1>
			<p class="rip-wizard__subtitle"><?php esc_html_e( 'Two decisions and your site is protected. Everything else is preconfigured and can be changed later.', 'reportedip-hive' ); ?></p>

			<div class="rip-wizard__mode-cards">
				<div class="rip-mode-card rip-mode-card--recommended <?php echo 'community' === $mode ? 'rip-mode-card--selected' : ''; ?>" data-mode="community">
					<span class="rip-mode-card__check"></span>
					<div class="rip-mode-card__ribbon"><?php esc_html_e( 'Recommended', 'reportedip-hive' ); ?></div>
					<h3 class="rip-mode-card__title"><?php esc_html_e( 'Community Network', 'reportedip-hive' ); ?></h3>
					<p class="rip-mode-card__description"><?php esc_html_e( 'Reputation data from thousands of sites in real time. Free key.', 'reportedip-hive' ); ?></p>
				</div>
				<div class="rip-mode-card <?php echo 'local' === $mode ? 'rip-mode-card--selected' : ''; ?>" data-mode="local">
					<span class="rip-mode-card__check"></span>
					<h3 class="rip-mode-card__title"><?php esc_html_e( 'Local Shield', 'reportedip-hive' ); ?></h3>
					<p class="rip-mode-card__description"><?php esc_html_e( 'No external connection. Local detection only, no reputation.', 'reportedip-hive' ); ?></p>
				</div>
			</div>
			<input type="hidden" id="rip-selected-mode" value="<?php echo esc_attr( $mode ); ?>">

			<div class="rip-config-card <?php echo 'community' === $mode ? '' : 'rip-is-hidden'; ?>" id="rip-api-key-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
					<h3><?php esc_html_e( 'Community Access Key', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<div class="rip-input-group">
						<input type="text" id="rip-api-key" class="rip-input" placeholder="<?php esc_attr_e( 'Paste key…', 'reportedip-hive' ); ?>" value="<?php echo esc_attr( $api_key ); ?>" autocomplete="off">
						<button type="button" id="rip-validate-key" class="rip-button rip-button--secondary"><?php esc_html_e( 'Check', 'reportedip-hive' ); ?></button>
					</div>
					<div id="rip-api-key-status" class="rip-input-status"></div>
					<p class="rip-input-help">
						<?php esc_html_e( 'No key yet?', 'reportedip-hive' ); ?>
						<a href="<?php echo esc_url( $register_url ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Create a free account', 'reportedip-hive' ); ?> →</a>
					</p>
					<p class="rip-input-help"><?php esc_html_e( 'In Community mode every request identifies this installation by its address and plugin version. Visitor data stays limited to the IP address and event type of detected threats.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
					<h3><?php esc_html_e( 'What gets switched on', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<ul class="rip-quickstart__features" id="rip-quickstart-features" data-tier="<?php echo esc_attr( $tier ); ?>">
						<?php foreach ( self::feature_rows() as $row ) : ?>
							<?php $locked = ! $this->mode_manager->tier_at_least( $row['tier'] ); ?>
							<li class="rip-quickstart__feature <?php echo $locked ? 'rip-quickstart__feature--locked' : ''; ?>" data-tier="<?php echo esc_attr( $row['tier'] ); ?>">
								<?php echo $check_icon; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Static inline SVG. ?>
								<span><?php echo esc_html( $row['label'] ); ?></span>
								<?php if ( 'free' !== $row['tier'] ) : ?>
									<?php ReportedIP_Hive_Admin_Settings::render_tier_badge( $row['tier'], array( 'small' => true ) ); ?>
								<?php endif; ?>
							</li>
						<?php endforeach; ?>
					</ul>

					<label class="rip-toggle">
						<input type="checkbox" id="rip-quickstart-2fa" checked>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><strong><?php esc_html_e( '2FA for administrators', 'reportedip-hive' ); ?></strong> · <?php esc_html_e( '7-day grace period; code via app, e-mail, passkey or SMS. Your own setup starts right after this.', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-toggle">
						<input type="checkbox" id="rip-quickstart-badge" checked>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><strong><?php esc_html_e( '"Protected by ReportedIP" badge in the footer', 'reportedip-hive' ); ?></strong> · <?php esc_html_e( 'shows visitors the protection and helps the network grow.', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-toggle">
						<input type="checkbox" id="rip-quickstart-notify" checked>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label">
							<strong><?php esc_html_e( 'Alert mails', 'reportedip-hive' ); ?></strong> ·
							<?php
							/* translators: %s: site admin e-mail address */
							printf( esc_html__( 'to %s on critical events.', 'reportedip-hive' ), esc_html( (string) get_option( 'admin_email', '' ) ) );
							?>
						</span>
					</label>
				</div>
			</div>

			<?php $this->render_tier_teaser( $tier ); ?>

			<div class="rip-wizard__actions">
				<button type="button" id="rip-quickstart-activate" class="rip-button rip-button--primary rip-button--large">
					<?php esc_html_e( 'Switch protection on', 'reportedip-hive' ); ?>
				</button>
				<button type="button" id="rip-quickstart-expert" class="rip-button rip-button--ghost rip-button--sm"><?php esc_html_e( 'I will set everything up myself (expert mode)', 'reportedip-hive' ); ?></button>
			</div>
			<p class="rip-input-help rip-is-hidden" id="rip-quickstart-note"></p>

			<div class="rip-wizard__import-shortcut">
				<button type="button" class="rip-wizard__import-toggle" id="rip-quickstart-import-toggle"><?php esc_html_e( 'Already have an export file? Import settings from JSON →', 'reportedip-hive' ); ?></button>
				<form id="rip-quickstart-import-form" class="rip-wizard__import-form rip-hidden" method="post" enctype="multipart/form-data">
					<?php wp_nonce_field( 'reportedip_hive_settings_import', '_rip_ie_nonce' ); ?>
					<input type="file" name="settings_file" accept="application/json,.json" required>
					<button type="submit" class="rip-button rip-button--secondary"><?php esc_html_e( 'Import and finish', 'reportedip-hive' ); ?></button>
					<div id="rip-quickstart-import-status" class="rip-mt-3"></div>
				</form>
			</div>
		</div>
		<?php
	}

	/**
	 * One tier card at most: Professional for free tiers, Business for
	 * Professional sites with a signal, nothing above that.
	 *
	 * @param string $tier Current tier.
	 * @return void
	 */
	private function render_tier_teaser( $tier ) {
		$upgrade_url = add_query_arg(
			array(
				'utm_source' => 'hive',
				'utm_medium' => 'quickstart',
			),
			REPORTEDIP_HIVE_UPGRADE_URL
		);
		if ( in_array( $tier, array( 'free', 'contributor' ), true ) ) {
			$badge = 'professional';
			$title = __( '2FA codes that actually arrive', 'reportedip-hive' );
			$items = array(
				__( 'SMS 2FA without a Twilio account, 25 a month included', 'reportedip-hive' ),
				__( '500 2FA mails a month from our EU relay, not your shared host', 'reportedip-hive' ),
				__( 'Covers 3 sites at 4.97 EUR each per month, 90 days of logs', 'reportedip-hive' ),
			);
		} elseif ( 'professional' === $tier && $this->business_signal() ) {
			$badge = 'business';
			$title = __( 'One licence, every client site', 'reportedip-hive' );
			$items = array(
				__( '15 client sites at 2.60 EUR each, white-labelled with your name', 'reportedip-hive' ),
				__( 'Audit trail, account blocking and session manager', 'reportedip-hive' ),
				__( 'Mail-2FA: 2,500/month, SMS-2FA: 75/month, one year of logs', 'reportedip-hive' ),
			);
		} else {
			return;
		}
		?>
		<div class="rip-wizard__tier-teaser" id="rip-quickstart-teaser">
			<article class="rip-tier-card">
				<header class="rip-tier-card__header">
					<?php ReportedIP_Hive_Admin_Settings::render_tier_badge( $badge ); ?>
					<h3 class="rip-tier-card__title"><?php echo esc_html( $title ); ?></h3>
				</header>
				<ul class="rip-tier-card__list">
					<?php foreach ( $items as $item ) : ?>
						<li><?php echo esc_html( $item ); ?></li>
					<?php endforeach; ?>
				</ul>
				<a href="<?php echo esc_url( $upgrade_url ); ?>" target="_blank" rel="noopener noreferrer" class="rip-button rip-button--secondary rip-button--sm"><?php esc_html_e( 'See plans', 'reportedip-hive' ); ?> →</a>
			</article>
		</div>
		<?php
	}

	/**
	 * Trust badges and version.
	 *
	 * @return void
	 */
	private function render_footer() {
		?>
		<footer class="rip-wizard__footer">
			<div class="rip-wizard__footer-badges rip-trust-badges">
				<span class="rip-wizard__badge rip-trust-badge">
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
					<?php esc_html_e( 'Security Focused', 'reportedip-hive' ); ?>
				</span>
				<span class="rip-wizard__badge rip-trust-badge">
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
					<?php esc_html_e( 'GDPR Compliant', 'reportedip-hive' ); ?>
				</span>
				<span class="rip-wizard__badge rip-trust-badge">
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M3.172 5.172a4 4 0 015.656 0L10 6.343l1.172-1.171a4 4 0 115.656 5.656L10 17.657l-6.828-6.829a4 4 0 010-5.656z" clip-rule="evenodd"/></svg>
					<?php esc_html_e( 'Made in Germany', 'reportedip-hive' ); ?>
				</span>
			</div>
			<p class="rip-wizard__version">ReportedIP Hive v<?php echo esc_html( REPORTEDIP_HIVE_VERSION ); ?></p>
		</footer>
		<?php
	}

	/**
	 * AJAX: verify the key, persist it and report the tier.
	 *
	 * `persist_verified_status()` stores the known tier and the domain
	 * snapshot. The recommendation itself is applied in {@see ajax_activate()}
	 * from the full map, not from a tier-change delta. The option write runs
	 * through the registered settings sanitizer, which keeps the previous
	 * value on a format error; a key that did not land is reported instead
	 * of being announced as valid.
	 *
	 * @return void
	 */
	public function ajax_validate_api_key() {
		check_ajax_referer( self::NONCE, 'nonce' );
		if ( ! $this->user_can_run_quickstart() ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'reportedip-hive' ) ), 403 );
		}

		$api_key = isset( $_POST['api_key'] ) ? sanitize_text_field( wp_unslash( $_POST['api_key'] ) ) : '';
		if ( '' === $api_key ) {
			wp_send_json_error( array( 'message' => __( 'Please enter your Community Access Key.', 'reportedip-hive' ) ) );
		}

		$api_client = ReportedIP_Hive_API::get_instance();
		$api_client->set_api_key( $api_key );
		$result = $api_client->verify_api_key( $api_key );

		if ( ! $result || empty( $result['valid'] ) ) {
			wp_send_json_error(
				array(
					'valid'   => false,
					'message' => $result['message'] ?? __( 'Invalid key.', 'reportedip-hive' ),
				)
			);
		}

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_api_key', $api_key );
		if ( $api_key !== (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' ) ) {
			wp_send_json_error(
				array(
					'valid'   => false,
					'message' => __( 'The key was accepted by the service but has an unexpected format and could not be saved. Please paste it exactly as shown in your account.', 'reportedip-hive' ),
				)
			);
		}
		$api_client->persist_verified_status( $result );

		$tier = ReportedIP_Hive_Mode_Manager::tier_from_role( (string) ( $result['userRole'] ?? '' ) );

		ob_start();
		ReportedIP_Hive_Admin_Settings::render_tier_badge( $tier );
		$badge = trim( (string) ob_get_clean() );

		$domains = $this->mode_manager->get_domains_snapshot();

		wp_send_json_success(
			array(
				'valid'           => true,
				'key_name'        => (string) ( $result['keyName'] ?? '' ),
				'tier'            => $tier,
				'tier_label'      => $this->mode_manager->get_tier_info( $tier )['label'],
				'tier_badge_html' => $badge,
				'domains_used'    => $domains ? (int) $domains['used'] : null,
				'domains_limit'   => $domains ? (int) $domains['limit'] : null,
			)
		);
	}

	/**
	 * AJAX: apply the recommendation and finish setup.
	 *
	 * @return void
	 */
	public function ajax_activate() {
		check_ajax_referer( self::NONCE, 'nonce' );
		if ( ! $this->user_can_run_quickstart() ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'reportedip-hive' ) ), 403 );
		}

		$mode   = isset( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : 'community';
		$twofa  = ! empty( $_POST['twofa_admins'] );
		$badge  = ! empty( $_POST['badge'] );
		$notify = ! empty( $_POST['notify'] );
		$expert = ! empty( $_POST['expert'] );

		if ( 'community' === $mode ) {
			$has_key = '' !== (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' );
			if ( ! $has_key ) {
				wp_send_json_error(
					array( 'message' => __( 'Community Network needs a checked Community Access Key. Check the key above or choose Local Shield.', 'reportedip-hive' ) )
				);
			}
		} else {
			$mode = 'local';
		}
		$this->mode_manager->set_mode( $mode );

		ReportedIP_Hive_Defaults::seed_missing();

		$tier   = 'community' === $mode ? $this->mode_manager->get_current_tier() : 'free';
		$values = ReportedIP_Hive_Defaults::recommended( $tier, $mode );

		$values['reportedip_hive_2fa_enabled_global']  = $twofa ? 1 : 0;
		$values['reportedip_hive_2fa_enforce_roles']   = $twofa ? array( 'administrator' ) : array();
		$values['reportedip_hive_auto_footer_enabled'] = $badge ? 1 : 0;
		$values['reportedip_hive_auto_footer_variant'] = 'badge';
		$values['reportedip_hive_notify_admin']        = $notify ? 1 : 0;
		$values['reportedip_hive_notify_recipients']   = $notify ? (string) get_option( 'admin_email', '' ) : '';

		$result = ReportedIP_Hive_Settings_Apply::apply( $values, 'quickstart' );
		foreach ( $result['results'] as $key => $row ) {
			if ( in_array( $row['status'], array( ReportedIP_Hive_Settings_Apply::STATUS_INVALID, ReportedIP_Hive_Settings_Apply::STATUS_SKIPPED_TIER ), true ) ) {
				ReportedIP_Hive_Logger::get_instance()->log(
					'quickstart_value_rejected',
					'',
					'low',
					array(
						'option' => (string) $key,
						'status' => (string) $row['status'],
						'reason' => (string) ( $row['message'] ?? '' ),
					)
				);
			}
		}

		if ( $expert ) {
			update_user_meta( get_current_user_id(), 'reportedip_hive_expert_mode', 1 );
			$this->disarm_onboarding();
		} elseif ( $twofa ) {
			$this->arm_onboarding();
		}

		$this->mode_manager->mark_wizard_completed();

		wp_send_json_success(
			array(
				'redirect_url' => self::get_admin_page_url( $expert ? 'admin.php?page=reportedip-hive-settings' : 'admin.php?page=reportedip-hive' ),
				'applied'      => (int) $result['applied'],
			)
		);
	}

	/**
	 * Arm the 2FA onboarding for the current admin when the switch enforced
	 * them and they have no method yet.
	 *
	 * @return void
	 */
	private function arm_onboarding() {
		if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Onboarding' ) || ! class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
			return;
		}
		$user = wp_get_current_user();
		if ( ! ReportedIP_Hive_Two_Factor::is_enforced_for_user( $user ) ) {
			return;
		}
		if ( ! empty( ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user->ID ) ) ) {
			return;
		}
		set_transient(
			ReportedIP_Hive_Two_Factor_Onboarding::TRANSIENT_PREFIX . $user->ID,
			1,
			ReportedIP_Hive_Two_Factor_Onboarding::TRANSIENT_TTL
		);
	}

	/**
	 * Drop a pending onboarding flag so the expert lands in the settings.
	 *
	 * An admin who first pressed "switch protection on" and then chose the
	 * expert route still carries the onboarding transient from the first
	 * click; without this the settings redirect is hijacked by the 2FA
	 * onboarding. Enforcement stays as chosen, the login-side flag brings
	 * the onboarding back on the next sign-in, skip and grace period apply.
	 *
	 * @return void
	 */
	private function disarm_onboarding() {
		if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Onboarding' ) ) {
			return;
		}
		delete_transient( ReportedIP_Hive_Two_Factor_Onboarding::TRANSIENT_PREFIX . get_current_user_id() );
	}

	/**
	 * AJAX: import a settings JSON, mark setup complete, go to the dashboard.
	 *
	 * Reuses the same allowlist and sanitiser pipeline as the regular
	 * settings-import panel.
	 *
	 * @return void
	 */
	public function ajax_import_settings() {
		check_ajax_referer( 'reportedip_hive_settings_import', '_rip_ie_nonce' );
		if ( ! $this->user_can_run_quickstart() ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'reportedip-hive' ) ), 403 );
		}

		if ( ! class_exists( 'ReportedIP_Hive_Settings_Import_Export' ) ) {
			wp_send_json_error( array( 'message' => __( 'Settings import is unavailable.', 'reportedip-hive' ) ), 500 );
		}

		$service = ReportedIP_Hive_Settings_Import_Export::get_instance();
		$decoded = $service->read_uploaded_payload();
		if ( is_wp_error( $decoded ) ) {
			wp_send_json_error( array( 'message' => $decoded->get_error_message() ), 400 );
		}

		$apply_summary = $service->apply_payload( $decoded, array_keys( ReportedIP_Hive_Settings_Import_Export::sections() ) );

		$this->mode_manager->mark_wizard_completed();

		wp_send_json_success(
			array(
				'redirect_url' => self::get_admin_page_url( 'admin.php?page=reportedip-hive' ),
				'summary'      => $apply_summary,
			)
		);
	}

	/**
	 * AJAX: validate a candidate hide-login slug. Kept for the dashboard's
	 * "hide login" next-step card.
	 *
	 * Reuses Hide_Login::sanitize_slug which surfaces all error reasons via
	 * add_settings_error. The queue is read back, the first error returned
	 * to the client, otherwise the canonicalised slug plus final URL.
	 *
	 * @return void
	 */
	public function ajax_validate_login_slug() {
		check_ajax_referer( self::NONCE, 'nonce' );
		if ( ! $this->user_can_run_quickstart() ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'reportedip-hive' ) ), 403 );
		}

		if ( ! class_exists( 'ReportedIP_Hive_Hide_Login' ) ) {
			wp_send_json_error( array( 'message' => __( 'Hide Login is unavailable.', 'reportedip-hive' ) ), 500 );
		}

		$raw  = isset( $_POST['slug'] ) ? sanitize_title( wp_unslash( (string) $_POST['slug'] ) ) : '';
		$hide = ReportedIP_Hive_Hide_Login::get_instance();

		$errors_before = count( get_settings_errors( 'reportedip_hive_hide_login_slug' ) );
		$validated     = $hide->sanitize_slug( $raw );
		$all_errors    = get_settings_errors( 'reportedip_hive_hide_login_slug' );
		$new_errors    = array_slice( $all_errors, $errors_before );

		if ( ! empty( $new_errors ) ) {
			wp_send_json_error( array( 'message' => $new_errors[0]['message'] ), 400 );
		}

		if ( '' === $validated || $validated !== $raw ) {
			wp_send_json_error( array( 'message' => __( 'That slug cannot be used.', 'reportedip-hive' ) ), 400 );
		}

		wp_send_json_success(
			array(
				'slug'     => $validated,
				'full_url' => trailingslashit( home_url() ) . $validated,
			)
		);
	}

	/**
	 * Quickstart URL, network-aware.
	 *
	 * @return string
	 */
	public static function get_url() {
		return self::get_admin_page_url( 'admin.php?page=' . self::PAGE_SLUG );
	}

	/**
	 * Admin URL that resolves to the network admin on Multisite.
	 *
	 * @param string $path Relative admin path.
	 * @return string
	 */
	public static function get_admin_page_url( $path ) {
		return is_multisite() ? network_admin_url( $path ) : admin_url( $path );
	}
}
