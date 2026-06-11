<?php
/**
 * Firewall admin page — WAF, bot verification, spam defence, scan & decoy,
 * rule sync and hardening tabs.
 *
 * Extracted from ReportedIP_Hive_Admin_Settings so the firewall surface owns
 * its renderers. The shared page frame (branded header, trust-badge footer,
 * tier badges and tier locks) stays on the settings class and is consumed via
 * its public static helpers.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.2
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Renders the Firewall admin page and its tabs.
 *
 * @since 2.1.2
 */
class ReportedIP_Hive_Admin_Firewall {

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Admin_Firewall|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return ReportedIP_Hive_Admin_Firewall
	 * @since  2.1.2
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Render a single stat card (value or badge plus label).
	 *
	 * @param array<string,string> $args {value: string, label: string, badge?: badge modifier class}.
	 * @return void
	 * @since  2.1.2
	 */
	private static function render_stat_card( array $args ) {
		$badge = isset( $args['badge'] ) ? (string) $args['badge'] : '';
		echo '<div class="rip-stat-card"><div class="rip-stat-card__content"><div class="rip-stat-card__value">';
		if ( '' !== $badge ) {
			printf( '<span class="rip-badge %s">%s</span>', esc_attr( $badge ), esc_html( (string) $args['value'] ) );
		} else {
			echo esc_html( (string) $args['value'] );
		}
		echo '</div><div class="rip-stat-card__label">' . esc_html( (string) $args['label'] ) . '</div></div></div>';
	}

	/**
	 * Render a labelled select row whose options carry a `data-opt` attribute
	 * for the bulk-save handler.
	 *
	 * @param string                    $id      Element id.
	 * @param string                    $opt_key Option key emitted as data-opt.
	 * @param string                    $label   Field label.
	 * @param array<int|string,string>  $choices Value => label map (numeric string keys collapse to int).
	 * @param string                    $current Currently selected value.
	 * @return void
	 * @since  2.1.2
	 */
	private static function render_select_row( $id, $opt_key, $label, array $choices, $current ) {
		printf( '<div class="rip-form-row"><label class="rip-form-label" for="%s">%s</label>', esc_attr( $id ), esc_html( $label ) );
		printf( '<select id="%s" class="rip-select" data-opt="%s">', esc_attr( $id ), esc_attr( $opt_key ) );
		foreach ( $choices as $value => $choice_label ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( (string) $value ), selected( (string) $current, (string) $value, false ), esc_html( $choice_label ) );
		}
		echo '</select></div>';
	}

	/**
	 * Firewall admin page — request-inspecting defence and the server-delivered
	 * rule sync. Routes the tab strip (Overview / WAF / Bot / Spam / Rule Sync /
	 * Scan & Decoy / Hardening) to the per-tab renderers.
	 *
	 * @since 2.1.2
	 * @return void
	 */
	public function firewall_page() {
		$active_tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'overview'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only tab routing.
		ReportedIP_Hive_Admin_Settings::render_page_header( __( 'Firewall', 'reportedip-hive' ), __( 'Request-inspecting defence and server-delivered rules', 'reportedip-hive' ) );

		$tabs = array(
			'overview'  => __( 'Overview', 'reportedip-hive' ),
			'waf'       => __( 'WAF', 'reportedip-hive' ),
			'bot'       => __( 'Bot Verification', 'reportedip-hive' ),
			'spam'      => __( 'Spam Defence', 'reportedip-hive' ),
			'rule_sync' => __( 'Rule Sync', 'reportedip-hive' ),
			'scan'      => __( 'Scan & Decoy', 'reportedip-hive' ),
			'hardening' => __( 'Hardening', 'reportedip-hive' ),
		);
		if ( ! isset( $tabs[ $active_tab ] ) ) {
			$active_tab = 'overview';
		}
		echo '<nav class="rip-nav-tabs">';
		foreach ( $tabs as $slug => $label ) {
			$class = 'rip-nav-tabs__tab' . ( $active_tab === $slug ? ' rip-nav-tabs__tab--active' : '' );
			printf(
				'<a href="%s" class="%s">%s</a>',
				esc_url( ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-firewall&tab=' . $slug ) ),
				esc_attr( $class ),
				esc_html( $label )
			);
		}
		echo '</nav>';

		echo '<div class="rip-content">';
		switch ( $active_tab ) {
			case 'rule_sync':
				$this->render_rule_sync_tab();
				break;
			case 'waf':
				$this->render_waf_tab();
				break;
			case 'bot':
				$this->render_bot_tab();
				break;
			case 'spam':
				$this->render_spam_tab();
				break;
			case 'scan':
				$this->render_scan_tab();
				break;
			case 'hardening':
				$this->render_hardening_tab();
				break;
			case 'overview':
				echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'The firewall bundles request inspection, verified-bot detection and the server-delivered rule sync. Use the Rule Sync tab to review the active rulesets.', 'reportedip-hive' ) . '</div>';
				break;
			default:
				echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'This engine ships in a later release. The server-delivered rule sync that feeds it is already active — see the Rule Sync tab.', 'reportedip-hive' ) . '</div>';
		}
		echo '</div>';

		ReportedIP_Hive_Admin_Settings::render_page_footer();
	}

	/**
	 * Render the WAF tab: live engine status (state, mode, active rules,
	 * Paranoia ceiling) plus the enable and report-only toggles. The engine is
	 * free on every plan; deeper Paranoia Levels ride the Professional ruleset.
	 *
	 * @since 2.1.2
	 * @return void
	 */
	private function render_waf_tab() {
		if ( ! class_exists( 'ReportedIP_Hive_WAF' ) ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'The WAF engine is unavailable.', 'reportedip-hive' ) . '</div>';
			return;
		}

		$waf         = ReportedIP_Hive_WAF::get_instance();
		$enabled     = $waf->is_enabled();
		$report_only = $waf->is_report_only();
		$rule_count  = $waf->active_rule_count();
		$pl_cap      = $waf->paranoia_cap();

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Web Application Firewall', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';

		echo '<div class="rip-grid rip-grid-cols-4">';
		self::render_stat_card(
			array(
				'value' => $enabled ? __( 'Active', 'reportedip-hive' ) : __( 'Disabled', 'reportedip-hive' ),
				'badge' => $enabled ? 'rip-badge--success' : 'rip-badge--neutral',
				'label' => __( 'Engine', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => $report_only ? __( 'Report only', 'reportedip-hive' ) : __( 'Enforcing', 'reportedip-hive' ),
				'badge' => $report_only ? 'rip-badge--warning' : 'rip-badge--info',
				'label' => __( 'Mode', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => (string) absint( $rule_count ),
				'label' => __( 'Active rules', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => _x( 'PL', 'Paranoia Level abbreviation', 'reportedip-hive' ) . absint( $pl_cap ),
				'label' => __( 'Paranoia ceiling', 'reportedip-hive' ),
			)
		);
		echo '</div>';

		echo '<p class="rip-help-text">' . esc_html__( 'The WAF engine and the Paranoia-Level-1 baseline rules are free on every plan. Paranoia Level 2/3 ride the Professional ruleset.', 'reportedip-hive' ) . '</p>';

		$paranoia_status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'rule_sync_priority' );
		$paranoia_choice = (int) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_PARANOIA, 2 );
		$paranoia_levels = array(
			1 => __( 'Level 1 — baseline (OWASP Top 10, false-positive averse)', 'reportedip-hive' ),
			2 => __( 'Level 2 — recommended (adds blind SQLi, LFI wrappers, obfuscated XSS)', 'reportedip-hive' ),
			3 => __( 'Level 3 — strict (aggressive, may need tuning)', 'reportedip-hive' ),
		);
		echo '<div class="rip-form-row"><label class="rip-form-label" for="rip-waf-paranoia">' . esc_html__( 'Paranoia Level', 'reportedip-hive' ) . '</label>';
		if ( empty( $paranoia_status['available'] ) ) {
			echo '<p class="rip-help-text">' . esc_html__( 'Level 1 is active. Higher levels are delivered with the Professional ruleset.', 'reportedip-hive' ) . ' ';
			ReportedIP_Hive_Admin_Settings::render_tier_lock( $paranoia_status, array( 'label' => __( 'Unlock Level 2/3 with Professional', 'reportedip-hive' ) ) );
			echo '</p>';
		} else {
			echo '<select id="rip-waf-paranoia" class="rip-select">';
			foreach ( $paranoia_levels as $level => $label ) {
				printf(
					'<option value="%d"%s>%s</option>',
					absint( $level ),
					selected( $paranoia_choice, $level, false ),
					esc_html( $label )
				);
			}
			echo '</select>';
			echo <<<'RIPJS'
<script>jQuery(function($){$('#rip-waf-paranoia').on('change',function(){var s=$(this).prop('disabled',true);$.post(reportedip_hive_ajax.ajax_url,{action:'reportedip_hive_waf_set_paranoia',level:$(this).val(),nonce:reportedip_hive_ajax.nonce},function(r){s.prop('disabled',false);location.reload();});});});</script>
RIPJS;
		}
		echo '</div>';

		printf(
			'<button type="button" class="rip-button rip-button--secondary rip-waf-toggle" data-field="enabled">%s</button> ',
			esc_html( $enabled ? __( 'Disable engine', 'reportedip-hive' ) : __( 'Enable engine', 'reportedip-hive' ) )
		);
		printf(
			'<button type="button" class="rip-button rip-button--secondary rip-waf-toggle" data-field="report_only">%s</button>',
			esc_html( $report_only ? __( 'Switch to enforcing', 'reportedip-hive' ) : __( 'Switch to report-only', 'reportedip-hive' ) )
		);

		echo <<<'RIPJS'
<script>jQuery(function($){$('.rip-waf-toggle').on('click',function(e){e.preventDefault();var b=$(this).prop('disabled',true);$.post(reportedip_hive_ajax.ajax_url,{action:'reportedip_hive_waf_toggle',field:$(this).data('field'),nonce:reportedip_hive_ajax.nonce},function(r){b.prop('disabled',false);location.reload();});});});</script>
RIPJS;

		echo '</div></div>';

		$this->render_waf_dropin_box();
	}

	/**
	 * Render the "Extended Protection" box: the optional pre-WordPress drop-in
	 * that runs the WAF before WordPress loads. Shows the detected server, the
	 * write status, a toggle and — for nginx — the copy-paste config snippet.
	 *
	 * @since 2.1.2
	 * @return void
	 */
	private function render_waf_dropin_box() {
		if ( ! class_exists( 'ReportedIP_Hive_WAF_Dropin_Manager' ) ) {
			return;
		}
		$dropin     = ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
		$enabled    = (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false );
		$server     = $dropin->detect_server();
		$writable   = $dropin->is_writable_target();
		$active     = $dropin->is_active();
		$is_nginx   = ( 'nginx' === $server );
		$server_lbl = array(
			'apache'  => 'Apache (mod_php, .htaccess)',
			'fpm'     => 'PHP-FPM / CGI (.user.ini)',
			'nginx'   => 'nginx (manual snippet)',
			'unknown' => __( 'Unknown', 'reportedip-hive' ),
		);

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Extended Protection (pre-WordPress)', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Optionally run the firewall before WordPress loads, so a malicious request is rejected earlier and cheaper. Off by default — enable only after confirming your server can write the configuration.', 'reportedip-hive' ) . '</p>';

		echo '<div class="rip-grid rip-grid-cols-3">';
		self::render_stat_card(
			array(
				'value' => $active ? __( 'Installed', 'reportedip-hive' ) : __( 'Not installed', 'reportedip-hive' ),
				'badge' => $active ? 'rip-badge--success' : 'rip-badge--neutral',
				'label' => __( 'Drop-in', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => $server_lbl[ $server ] ?? $server,
				'label' => __( 'Detected server', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => $writable ? __( 'Writable', 'reportedip-hive' ) : __( 'Not writable', 'reportedip-hive' ),
				'badge' => $writable ? 'rip-badge--success' : 'rip-badge--warning',
				'label' => __( 'Config target', 'reportedip-hive' ),
			)
		);
		echo '</div>';

		if ( $is_nginx ) {
			echo '<div class="rip-alert rip-alert--warning">' . esc_html__( 'On nginx the directive cannot be written automatically. Enable the drop-in to generate the guard file, then paste this snippet into your server block and reload nginx. Remove it again before deactivating the plugin.', 'reportedip-hive' ) . '</div>';
			echo '<pre class="rip-code-block" id="rip-waf-nginx-snippet">' . esc_html( $dropin->nginx_snippet() ) . '</pre>';
			echo '<button type="button" class="rip-button rip-button--secondary" id="rip-waf-nginx-copy">' . esc_html__( 'Copy snippet', 'reportedip-hive' ) . '</button> ';
		}

		printf(
			'<button type="button" class="rip-button rip-button--primary rip-waf-dropin-toggle">%s</button>',
			esc_html( $enabled ? __( 'Disable extended protection', 'reportedip-hive' ) : __( 'Enable extended protection', 'reportedip-hive' ) )
		);

		echo <<<'RIPJS'
<script>jQuery(function($){$('.rip-waf-dropin-toggle').on('click',function(e){e.preventDefault();var b=$(this).prop('disabled',true);$.post(reportedip_hive_ajax.ajax_url,{action:'reportedip_hive_waf_dropin_toggle',nonce:reportedip_hive_ajax.nonce},function(r){b.prop('disabled',false);if(r&&r.data&&r.data.message){window.alert(r.data.message);}location.reload();});});$('#rip-waf-nginx-copy').on('click',function(e){e.preventDefault();var t=document.getElementById('rip-waf-nginx-snippet');if(t&&navigator.clipboard){navigator.clipboard.writeText(t.textContent);}});});</script>
RIPJS;

		echo '</div></div>';
	}

	/**
	 * Render the Bot Verification tab: the verified-bot sensor status, the action
	 * selector (off / flag / block) and the active bot-list version. Free on
	 * every plan; the official IP-range feeds ride the Professional ruleset.
	 *
	 * @since 2.1.2
	 * @return void
	 */
	private function render_bot_tab() {
		if ( ! class_exists( 'ReportedIP_Hive_Bot_Verifier' ) ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'The bot verifier is unavailable.', 'reportedip-hive' ) . '</div>';
			return;
		}

		$verifier = ReportedIP_Hive_Bot_Verifier::get_instance();
		$action   = $verifier->action();
		$enabled  = $verifier->is_enabled();
		$rules    = $verifier->get_bot_rules();
		$bot_ver  = 0;
		if ( class_exists( 'ReportedIP_Hive_Rule_Sync' ) ) {
			$ruleset = ReportedIP_Hive_Rule_Sync::get_instance()->get_ruleset( 'bot_signatures' );
			$bot_ver = isset( $ruleset['version'] ) ? (int) $ruleset['version'] : 0;
		}

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Verified Bot Detection', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';

		echo '<div class="rip-grid rip-grid-cols-3">';
		self::render_stat_card(
			array(
				'value' => $enabled ? __( 'Active', 'reportedip-hive' ) : __( 'Disabled', 'reportedip-hive' ),
				'badge' => $enabled ? 'rip-badge--success' : 'rip-badge--neutral',
				'label' => __( 'Sensor', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => (string) absint( count( $rules ) ),
				'label' => __( 'Known crawlers', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => $bot_ver > 0 ? 'v' . $bot_ver : __( 'Baseline', 'reportedip-hive' ),
				'label' => __( 'Bot list', 'reportedip-hive' ),
			)
		);
		echo '</div>';

		echo '<p class="rip-help-text">' . esc_html__( 'Confirms that a request claiming to be Googlebot, Bingbot or another crawler genuinely originates from that crawler (official IP ranges, then forward-confirmed reverse DNS). A spoofer is flagged or blocked; a genuine crawler is never blocked.', 'reportedip-hive' ) . '</p>';

		$actions = array(
			'off'   => __( 'Off — do not verify', 'reportedip-hive' ),
			'flag'  => __( 'Flag — log spoofers only (recommended)', 'reportedip-hive' ),
			'block' => __( 'Block — reject confirmed spoofers', 'reportedip-hive' ),
		);
		echo '<div class="rip-form-row"><label class="rip-form-label" for="rip-bot-action">' . esc_html__( 'Action on a confirmed spoofer', 'reportedip-hive' ) . '</label>';
		echo '<select id="rip-bot-action" class="rip-select">';
		foreach ( $actions as $value => $label ) {
			printf(
				'<option value="%s"%s>%s</option>',
				esc_attr( $value ),
				selected( $action, $value, false ),
				esc_html( $label )
			);
		}
		echo '</select></div>';

		echo <<<'RIPJS'
<script>jQuery(function($){$('#rip-bot-action').on('change',function(){var s=$(this).prop('disabled',true);$.post(reportedip_hive_ajax.ajax_url,{action:'reportedip_hive_bot_action',mode:$(this).val(),nonce:reportedip_hive_ajax.nonce},function(r){s.prop('disabled',false);location.reload();});});});</script>
RIPJS;

		echo '</div></div>';
	}

	/**
	 * Render the Spam Defence tab: the disposable-email action selector, the
	 * privacy-relay toggle (with an out-loud warning) and the comment-honeypot
	 * toggle. Free on every plan; the live disposable list rides Priority Sync.
	 *
	 * @since 2.1.2
	 * @return void
	 */
	private function render_spam_tab() {
		$disp_action = 'monitor';
		$disp_ver    = 0;
		if ( class_exists( 'ReportedIP_Hive_Disposable_Email' ) ) {
			$disp_action = ReportedIP_Hive_Disposable_Email::get_instance()->action();
		}
		if ( class_exists( 'ReportedIP_Hive_Rule_Sync' ) ) {
			$ruleset  = ReportedIP_Hive_Rule_Sync::get_instance()->get_ruleset( 'disposable_domains' );
			$disp_ver = isset( $ruleset['version'] ) ? (int) $ruleset['version'] : 0;
		}
		$block_relays = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_email_relays', false );
		$honeypot     = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_honeypot_enabled', true );

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Disposable Email', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Inspects the e-mail address at registration (WordPress and WooCommerce) against the throwaway-mail list. Monitor logs a match; Block rejects the registration. The live, frequently-updated list rides the Professional ruleset.', 'reportedip-hive' ) . '</p>';

		echo '<div class="rip-grid rip-grid-cols-2">';
		self::render_stat_card(
			array(
				'value' => ucfirst( $disp_action ),
				'label' => __( 'Mode', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => $disp_ver > 0 ? 'v' . $disp_ver : __( 'Baseline', 'reportedip-hive' ),
				'label' => __( 'Domain list', 'reportedip-hive' ),
			)
		);
		echo '</div>';

		$disp_actions = array(
			'off'     => __( 'Off', 'reportedip-hive' ),
			'monitor' => __( 'Monitor — log only (recommended)', 'reportedip-hive' ),
			'block'   => __( 'Block — reject registration', 'reportedip-hive' ),
		);
		echo '<div class="rip-form-row"><label class="rip-form-label" for="rip-disposable-action">' . esc_html__( 'Action on a throwaway address', 'reportedip-hive' ) . '</label>';
		echo '<select id="rip-disposable-action" class="rip-select">';
		foreach ( $disp_actions as $value => $label ) {
			printf(
				'<option value="%s"%s>%s</option>',
				esc_attr( $value ),
				selected( $disp_action, $value, false ),
				esc_html( $label )
			);
		}
		echo '</select></div>';

		echo '<div class="rip-alert rip-alert--warning">' . esc_html__( 'Blocking privacy relays also rejects legitimate Apple Hide My Email and Firefox Relay users. Leave this off unless you accept that trade-off.', 'reportedip-hive' ) . '</div>';
		printf(
			'<button type="button" class="rip-button rip-button--secondary rip-spam-toggle" data-field="block_relays">%s</button>',
			esc_html( $block_relays ? __( 'Stop blocking privacy relays', 'reportedip-hive' ) : __( 'Also block privacy relays', 'reportedip-hive' ) )
		);

		echo '</div></div>';

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Comment Honeypot', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Adds an invisible decoy field to the comment form. Spam bots that fill every field trip it and are rejected — no CAPTCHA, no friction for real visitors.', 'reportedip-hive' ) . '</p>';
		self::render_stat_card(
			array(
				'value' => $honeypot ? __( 'Active', 'reportedip-hive' ) : __( 'Disabled', 'reportedip-hive' ),
				'badge' => $honeypot ? 'rip-badge--success' : 'rip-badge--neutral',
				'label' => __( 'Honeypot', 'reportedip-hive' ),
			)
		);
		printf(
			'<p><button type="button" class="rip-button rip-button--secondary rip-spam-toggle" data-field="honeypot">%s</button></p>',
			esc_html( $honeypot ? __( 'Disable honeypot', 'reportedip-hive' ) : __( 'Enable honeypot', 'reportedip-hive' ) )
		);
		echo '</div></div>';

		echo <<<'RIPJS'
<script>jQuery(function($){$('.rip-spam-toggle').on('click',function(e){e.preventDefault();var b=$(this).prop('disabled',true);$.post(reportedip_hive_ajax.ajax_url,{action:'reportedip_hive_spam_toggle',field:$(this).data('field'),nonce:reportedip_hive_ajax.nonce},function(r){b.prop('disabled',false);location.reload();});});$('#rip-disposable-action').on('change',function(){var s=$(this).prop('disabled',true);$.post(reportedip_hive_ajax.ajax_url,{action:'reportedip_hive_disposable_action',mode:$(this).val(),nonce:reportedip_hive_ajax.nonce},function(r){s.prop('disabled',false);location.reload();});});});</script>
RIPJS;
	}

	/**
	 * Render the Scan & Decoy tab: the 404/honeypot scan detector status and
	 * toggle, followed by the full Decoy Path Block surface. Both sensors are
	 * free on every plan; the honeypot path list rides the server-delivered
	 * `scan_paths` ruleset and the numeric 404 thresholds live on Settings ›
	 * Protection.
	 *
	 * @since 2.1.2
	 * @return void
	 */
	private function render_scan_tab() {
		$scan_on   = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_404_scans', true );
		$threshold = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_scan_404_threshold', 8 );
		$timeframe = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_scan_404_timeframe', 1 );
		$path_ver  = 0;
		if ( class_exists( 'ReportedIP_Hive_Rule_Sync' ) ) {
			$ruleset  = ReportedIP_Hive_Rule_Sync::get_instance()->get_ruleset( 'scan_paths' );
			$path_ver = isset( $ruleset['version'] ) ? (int) $ruleset['version'] : 0;
		}

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Scan Detection', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Detects vulnerability scanners by high-rate 404s and instant hits on known-bad probe paths (.env, wp-config.bak, /.git/). The probe-path list is delivered through the scan_paths ruleset; the numeric thresholds live on Settings › Protection.', 'reportedip-hive' ) . '</p>';

		echo '<div class="rip-grid rip-grid-cols-3">';
		self::render_stat_card(
			array(
				'value' => $scan_on ? __( 'Active', 'reportedip-hive' ) : __( 'Disabled', 'reportedip-hive' ),
				'badge' => $scan_on ? 'rip-badge--success' : 'rip-badge--neutral',
				'label' => __( 'Scan detector', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => sprintf( '%1$d / %2$d %3$s', absint( $threshold ), absint( $timeframe ), _x( 'min', 'minutes abbreviation', 'reportedip-hive' ) ),
				'label' => __( '404 trigger', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => $path_ver > 0 ? 'v' . $path_ver : __( 'Baseline', 'reportedip-hive' ),
				'label' => __( 'Probe-path list', 'reportedip-hive' ),
			)
		);
		echo '</div>';

		printf(
			'<button type="button" class="rip-button rip-button--secondary rip-scan-toggle" data-field="scan">%s</button>',
			esc_html( $scan_on ? __( 'Disable scan detector', 'reportedip-hive' ) : __( 'Enable scan detector', 'reportedip-hive' ) )
		);

		echo '<p class="rip-help-text">';
		printf(
			/* translators: 1: opening Protection-settings link tag, 2: closing tag, 3: opening Rule-Sync link tag, 4: closing tag. */
			esc_html__( 'Tune the 404 thresholds on the %1$sProtection settings%2$s; review the active probe-path list on the %3$sRule Sync%4$s tab.', 'reportedip-hive' ),
			'<a href="' . esc_url( ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-settings&tab=protection' ) ) . '">',
			'</a>',
			'<a href="' . esc_url( ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-firewall&tab=rule_sync' ) ) . '">',
			'</a>'
		);
		echo '</p>';

		echo <<<'RIPJS'
<script>jQuery(function($){$('.rip-scan-toggle').on('click',function(e){e.preventDefault();var b=$(this).prop('disabled',true);$.post(reportedip_hive_ajax.ajax_url,{action:'reportedip_hive_scan_toggle',field:$(this).data('field'),nonce:reportedip_hive_ajax.nonce},function(r){b.prop('disabled',false);location.reload();});});});</script>
RIPJS;

		echo '</div></div>';

		$this->render_decoy_box();
	}

	/**
	 * Render the Decoy Path Block surface: the master toggle, the auto-managed
	 * .htaccess status and the copy-paste server-config snippets. A decoy hit is
	 * answered with a 403 and reported, but the IP is never added to the local
	 * block list, so a misbehaving backup plugin cannot lock the operator out.
	 *
	 * @since 2.1.2
	 * @return void
	 */
	private function render_decoy_box() {
		$decoy_on = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_decoy_pathblock_enabled', true );
		$writable = false;
		$present  = false;
		if ( class_exists( 'ReportedIP_Hive_Decoy_Htaccess_Writer' ) ) {
			$writer   = ReportedIP_Hive_Decoy_Htaccess_Writer::get_instance();
			$writable = $writer->is_writable_target();
			$present  = $writer->is_block_present();
		}
		$server     = class_exists( 'ReportedIP_Hive_WAF_Dropin_Manager' )
			? ReportedIP_Hive_WAF_Dropin_Manager::get_instance()->detect_server()
			: 'unknown';
		$is_apache  = ( 'apache' === $server || 'fpm' === $server );
		$server_lbl = array(
			'apache'  => 'Apache (.htaccess)',
			'fpm'     => 'PHP-FPM / Apache',
			'nginx'   => 'nginx',
			'unknown' => __( 'Unknown', 'reportedip-hive' ),
		);

		/**
		 * Resolve the .htaccess-block status badge: the empty marker skeleton
		 * that a disabled trap leaves behind must not read as "active", so the
		 * badge is gated on the trap actually being on.
		 */
		if ( ! $decoy_on ) {
			$block_class = 'rip-badge--neutral';
			$block_label = __( 'Inactive', 'reportedip-hive' );
		} elseif ( $present && $is_apache ) {
			$block_class = 'rip-badge--success';
			$block_label = __( 'Active', 'reportedip-hive' );
		} elseif ( $writable ) {
			$block_class = 'rip-badge--warning';
			$block_label = __( 'Pending', 'reportedip-hive' );
		} else {
			$block_class = 'rip-badge--info';
			$block_label = __( 'Manual', 'reportedip-hive' );
		}

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Decoy Path Block', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Detects requests to known bait paths (.env.backup, wp-config.old.php, db-dump-master.sql.php …) that legitimate visitors never request. Each hit is logged, shared with the community network, and answered with a 403, but the IP is not added to your local block list, so a misbehaving backup plugin cannot lock you out.', 'reportedip-hive' ) . '</p>';

		echo '<div class="rip-grid rip-grid-cols-3">';
		self::render_stat_card(
			array(
				'value' => $decoy_on ? __( 'Active', 'reportedip-hive' ) : __( 'Disabled', 'reportedip-hive' ),
				'badge' => $decoy_on ? 'rip-badge--success' : 'rip-badge--neutral',
				'label' => __( 'Decoy trap', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => $block_label,
				'badge' => $block_class,
				'label' => __( '.htaccess block', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => $server_lbl[ $server ] ?? $server,
				'label' => __( 'Detected server', 'reportedip-hive' ),
			)
		);
		echo '</div>';

		if ( ! $decoy_on ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'The decoy trap is off — no rewrite rules are active and no bait-path hits are reported.', 'reportedip-hive' ) . '</div>';
		} elseif ( $is_apache && $writable && $present ) {
			echo '<div class="rip-alert rip-alert--success">' . esc_html__( 'Auto-managed — Hive wrote the rewrite block to .htaccess. Real bait files on disk will no longer be served directly.', 'reportedip-hive' ) . '</div>';
		} elseif ( $is_apache && $writable ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( '.htaccess is writable but the block is not in place yet. Re-toggle the trap to trigger a sync.', 'reportedip-hive' ) . '</div>';
		} else {
			echo '<div class="rip-alert rip-alert--warning">' . esc_html__( 'This server is not auto-managed (nginx, or a read-only .htaccess). The PHP sensor still catches bait-path hits; paste the matching snippet below to also block them at the web-server layer.', 'reportedip-hive' ) . '</div>';
		}

		printf(
			'<button type="button" class="rip-button rip-button--secondary rip-scan-toggle" data-field="decoy">%s</button>',
			esc_html( $decoy_on ? __( 'Disable decoy trap', 'reportedip-hive' ) : __( 'Enable decoy trap', 'reportedip-hive' ) )
		);

		if ( class_exists( 'ReportedIP_Hive_Decoy_Path_Block' ) ) {
			$open = ( $decoy_on && ! $is_apache ) ? ' open' : '';
			echo '<details class="rip-form-group"' . esc_attr( $open ) . '><summary><strong>' . esc_html__( 'Server-config snippets (live preview / copy-paste)', 'reportedip-hive' ) . '</strong></summary>';
			echo '<p class="rip-help-text">' . esc_html__( 'On Apache the .htaccess block is auto-managed — the first snippet shows what Hive wrote (or would write) verbatim. On nginx, copy the matching snippet into your server { … } block and reload. Every snippet rewrites to /index.php so the Hive sensor still loads, logs the hit and reports it; a bare [F,L] / return 403 would skip detection entirely.', 'reportedip-hive' ) . '</p>';

			$snippets = array(
				array(
					'id'    => 'rip-decoy-snip-apache',
					'label' => __( 'Apache (.htaccess)', 'reportedip-hive' ),
					'note'  => '',
					'code'  => ReportedIP_Hive_Decoy_Path_Block::htaccess_snippet(),
				),
				array(
					'id'    => 'rip-decoy-snip-nginx',
					'label' => __( 'nginx (regex form — plain nginx)', 'reportedip-hive' ),
					'note'  => '',
					'code'  => ReportedIP_Hive_Decoy_Path_Block::nginx_snippet(),
				),
				array(
					'id'    => 'rip-decoy-snip-nginx-exact',
					'label' => __( 'nginx (exact-match form — ISPConfig & managed stacks)', 'reportedip-hive' ),
					'note'  => __( 'Use this variant when your host template ships a "location ~ /\\." dot-file deny rule before your custom directives — exact-match locations have higher priority than any regex location and survive that ordering.', 'reportedip-hive' ),
					'code'  => ReportedIP_Hive_Decoy_Path_Block::nginx_snippet_exact_match(),
				),
			);
			foreach ( $snippets as $snip ) {
				printf(
					'<p><strong>%1$s</strong> <button type="button" class="rip-button rip-button--secondary rip-snippet-copy" data-target="%2$s">%3$s</button></p>',
					esc_html( $snip['label'] ),
					esc_attr( $snip['id'] ),
					esc_html__( 'Copy snippet', 'reportedip-hive' )
				);
				if ( '' !== $snip['note'] ) {
					echo '<p class="rip-help-text">' . esc_html( $snip['note'] ) . '</p>';
				}
				echo '<pre class="rip-code-snippet" id="' . esc_attr( $snip['id'] ) . '"><code>' . esc_html( $snip['code'] ) . '</code></pre>';
			}
			echo '</details>';

			echo <<<'RIPJS'
<script>jQuery(function($){$('.rip-snippet-copy').on('click',function(e){e.preventDefault();var t=document.getElementById($(this).data('target'));if(t&&navigator.clipboard){navigator.clipboard.writeText(t.textContent);$(this).addClass('rip-button--copied');setTimeout(function(){},1200);}});});</script>
RIPJS;
		}

		echo '</div></div>';
	}

	/**
	 * Render the Rule Sync status surface: per-ruleset version and source, the
	 * last sync time and the operation-mode-aware state.
	 *
	 * @since 2.1.2
	 * @return void
	 */
	private function render_rule_sync_tab() {
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$sync         = ReportedIP_Hive_Rule_Sync::get_instance();
		$priority     = $mode_manager->feature_status( 'rule_sync_priority' );
		$last_run     = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_rule_sync_last_run', 0 );
		$enabled      = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_rule_sync_enabled', true );
		$has_priority = ! empty( $priority['available'] );

		$this->render_rule_sync_tiers( $has_priority );

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Active rulesets', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';

		if ( $mode_manager->is_local_mode() ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'Local Shield mode: the bundled baseline rulesets are active. Connect the Community Network to receive the richer, frequently-updated rulesets.', 'reportedip-hive' ) . '</div>';
		}

		echo '<table class="rip-table"><thead><tr><th>' . esc_html__( 'Ruleset', 'reportedip-hive' ) . '</th><th>' . esc_html__( 'Version', 'reportedip-hive' ) . '</th><th>' . esc_html__( 'Source', 'reportedip-hive' ) . '</th></tr></thead><tbody>';
		foreach ( ReportedIP_Hive_Rule_Store::VALID_KEYS as $key ) {
			$ruleset = $sync->get_ruleset( $key );
			$version = isset( $ruleset['version'] ) ? (int) $ruleset['version'] : 0;
			$synced  = $version > 0;
			$badge   = $synced ? 'rip-badge--success' : 'rip-badge--neutral';
			$source  = $synced
				? __( 'synced (Professional feed)', 'reportedip-hive' )
				: __( 'bundled baseline (Free)', 'reportedip-hive' );
			printf(
				'<tr><td><code>%s</code></td><td>%d</td><td><span class="rip-badge %s">%s</span></td></tr>',
				esc_html( $key ),
				absint( $version ),
				esc_attr( $badge ),
				esc_html( $source )
			);
		}
		echo '</tbody></table>';

		echo '<p class="rip-help-text">' . esc_html__( 'Master toggle:', 'reportedip-hive' ) . ' ' . ( $enabled ? esc_html__( 'enabled', 'reportedip-hive' ) : esc_html__( 'disabled', 'reportedip-hive' ) ) . ' &middot; ' . esc_html__( 'Last sync:', 'reportedip-hive' ) . ' ' . ( $last_run ? esc_html( wp_date( 'Y-m-d H:i:s', $last_run ) ) : esc_html__( 'never (baseline only)', 'reportedip-hive' ) ) . '</p>';

		if ( ! $has_priority ) {
			echo '<p class="rip-help-text">' . esc_html__( 'The bundled baseline rulesets stay active and free on every plan. Priority Sync — deeper coverage and frequent updates — is part of the Professional plan.', 'reportedip-hive' ) . '</p>';
			ReportedIP_Hive_Admin_Settings::render_tier_lock( $priority, array( 'label' => __( 'Unlock Priority Sync with Professional', 'reportedip-hive' ) ) );
		} else {
			echo '<button type="button" class="rip-button rip-button--primary" id="rip-rule-sync-now">' . esc_html__( 'Sync now', 'reportedip-hive' ) . '</button>';
			echo <<<'RIPJS'
<script>jQuery(function($){$('#rip-rule-sync-now').on('click',function(e){e.preventDefault();var b=$(this).prop('disabled',true);$.post(reportedip_hive_ajax.ajax_url,{action:'reportedip_hive_rule_sync_now',nonce:reportedip_hive_ajax.nonce},function(r){b.prop('disabled',false);if(r&&r.data&&r.data.message){window.alert(r.data.message);}location.reload();});});});</script>
RIPJS;
		}

		echo '</div></div>';
	}

	/**
	 * Render the two-column Free-vs-Professional coverage comparison for the
	 * Rule Sync tab so the plan boundary is explicit: the WAF engine and the
	 * baseline rulesets ship with every plan, Priority Sync is Professional.
	 *
	 * @param bool $has_priority Whether the current tier has Priority Sync.
	 * @return void
	 * @since 2.1.2
	 */
	private function render_rule_sync_tiers( $has_priority ) {
		$free_features = array(
			__( 'WAF engine — always on, every plan', 'reportedip-hive' ),
			__( 'Baseline rulesets (OWASP Top 10, Paranoia Level 1)', 'reportedip-hive' ),
			__( 'Bundled with the plugin — no connection required', 'reportedip-hive' ),
		);
		$pro_features  = array(
			__( 'Deeper coverage (Paranoia Level 2/3, obfuscation & bypass)', 'reportedip-hive' ),
			__( 'Server-delivered, Ed25519-signed rule updates', 'reportedip-hive' ),
			__( 'Frequent refresh via the Community Network', 'reportedip-hive' ),
		);

		echo '<div class="rip-grid rip-grid-cols-2">';

		echo '<div class="rip-card"><div class="rip-card__header rip-card__header--icon"><h3 class="rip-card__title">' . esc_html__( 'Included — every plan', 'reportedip-hive' ) . '</h3>';
		ReportedIP_Hive_Admin_Settings::render_tier_badge( 'free' );
		echo '</div><div class="rip-card__body"><ul class="rip-pricing-card__features">';
		foreach ( $free_features as $feature ) {
			echo '<li>' . esc_html( $feature ) . '</li>';
		}
		echo '</ul></div></div>';

		$pro_state = $has_priority
			? '<span class="rip-badge rip-badge--success">' . esc_html__( 'Active on your plan', 'reportedip-hive' ) . '</span>'
			: '<span class="rip-badge rip-badge--info">' . esc_html__( 'Professional and higher', 'reportedip-hive' ) . '</span>';
		echo '<div class="rip-card"><div class="rip-card__header rip-card__header--icon"><h3 class="rip-card__title">' . esc_html__( 'Priority Sync', 'reportedip-hive' ) . '</h3>';
		ReportedIP_Hive_Admin_Settings::render_tier_badge( 'professional' );
		echo '</div><div class="rip-card__body"><ul class="rip-pricing-card__features">';
		foreach ( $pro_features as $feature ) {
			echo '<li>' . esc_html( $feature ) . '</li>';
		}
		echo '</ul><p class="rip-help-text">' . $pro_state . '</p></div></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $pro_state is built from esc_html__ literals above.

		echo '</div>';
	}

	/**
	 * Render the Hardening tab inside the Firewall page — preventive hardening
	 * and security headers. Basic headers are free; HSTS, Permissions-Policy,
	 * CSP and the cross-origin trio are tier-locked to Professional.
	 *
	 * @since 2.1.2
	 * @return void
	 */
	private function render_hardening_tab() {
		if ( ! class_exists( 'ReportedIP_Hive_Security_Headers' ) ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'Security headers are unavailable.', 'reportedip-hive' ) . '</div>';
			return;
		}

		$h          = 'ReportedIP_Hive_Security_Headers';
		$adv_status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'security_headers_advanced' );
		$adv_ok     = ! empty( $adv_status['available'] );
		$enabled    = $h::is_enabled();
		$conflicts  = $h::conflicts();
		$get        = static function ( $key, $fallback ) {
			return ReportedIP_Hive_Option_Routing::get( $key, $fallback );
		};
		$on_off     = array(
			'1' => __( 'On', 'reportedip-hive' ),
			'0' => __( 'Off', 'reportedip-hive' ),
		);

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Security Headers', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Sends hardening response headers on every front-end request. The basic trio is free; HSTS, Permissions-Policy, the Content-Security-Policy and the Cross-Origin headers are part of advanced hardening. A header already set by your server or another plugin is detected and left untouched.', 'reportedip-hive' ) . '</p>';
		self::render_stat_card(
			array(
				'value' => $enabled ? __( 'Active', 'reportedip-hive' ) : __( 'Disabled', 'reportedip-hive' ),
				'badge' => $enabled ? 'rip-badge--success' : 'rip-badge--neutral',
				'label' => __( 'Header engine', 'reportedip-hive' ),
			)
		);
		if ( ! empty( $conflicts ) ) {
			printf(
				'<div class="rip-alert rip-alert--warning">%s <strong>%s</strong></div>',
				esc_html__( 'These headers are already set elsewhere and are left untouched:', 'reportedip-hive' ),
				esc_html( implode( ', ', $conflicts ) )
			);
		}
		self::render_select_row( 'rip-hdr-enabled', $h::OPT_ENABLED, __( 'Header engine', 'reportedip-hive' ), $on_off, $enabled ? '1' : '0' );
		echo '</div></div>';

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Basic Headers', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		self::render_select_row( 'rip-hdr-xcto', $h::OPT_XCTO, __( 'X-Content-Type-Options: nosniff', 'reportedip-hive' ), $on_off, (bool) $get( $h::OPT_XCTO, true ) ? '1' : '0' );
		self::render_select_row(
			'rip-hdr-xfo',
			$h::OPT_XFO,
			__( 'X-Frame-Options (clickjacking)', 'reportedip-hive' ),
			array(
				'SAMEORIGIN' => 'SAMEORIGIN',
				'DENY'       => 'DENY',
				'off'        => __( 'Off', 'reportedip-hive' ),
			),
			(string) $get( $h::OPT_XFO, 'SAMEORIGIN' )
		);
		self::render_select_row(
			'rip-hdr-referrer',
			$h::OPT_REFERRER,
			__( 'Referrer-Policy', 'reportedip-hive' ),
			array(
				'no-referrer'                     => 'no-referrer',
				'same-origin'                     => 'same-origin',
				'strict-origin'                   => 'strict-origin',
				'strict-origin-when-cross-origin' => 'strict-origin-when-cross-origin',
				'no-referrer-when-downgrade'      => 'no-referrer-when-downgrade',
			),
			(string) $get( $h::OPT_REFERRER, 'strict-origin-when-cross-origin' )
		);
		echo '</div></div>';

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Advanced Headers', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		if ( ! $adv_ok ) {
			ReportedIP_Hive_Admin_Settings::render_tier_lock( $adv_status, array( 'label' => __( 'Advanced headers — Professional', 'reportedip-hive' ) ) );
			echo '<p class="rip-help-text">' . esc_html__( 'HSTS, Permissions-Policy, the CSP builder and the Cross-Origin headers unlock with Professional. The basic headers above stay free.', 'reportedip-hive' ) . '</p>';
			echo '</div></div>';
			return;
		}

		self::render_select_row( 'rip-hdr-hsts', $h::OPT_HSTS_ENABLED, __( 'HTTP Strict Transport Security (HSTS)', 'reportedip-hive' ), $on_off, (bool) $get( $h::OPT_HSTS_ENABLED, false ) ? '1' : '0' );
		self::render_select_row(
			'rip-hdr-hsts-age',
			$h::OPT_HSTS_MAX_AGE,
			__( 'HSTS max-age', 'reportedip-hive' ),
			array(
				'15552000' => __( '6 months', 'reportedip-hive' ),
				'31536000' => __( '1 year', 'reportedip-hive' ),
				'63072000' => __( '2 years (preload-ready)', 'reportedip-hive' ),
			),
			(string) (int) $get( $h::OPT_HSTS_MAX_AGE, 63072000 )
		);
		self::render_select_row( 'rip-hdr-hsts-sub', $h::OPT_HSTS_SUBDOMAINS, __( 'HSTS includeSubDomains', 'reportedip-hive' ), $on_off, (bool) $get( $h::OPT_HSTS_SUBDOMAINS, false ) ? '1' : '0' );
		self::render_select_row( 'rip-hdr-hsts-preload', $h::OPT_HSTS_PRELOAD, __( 'HSTS preload', 'reportedip-hive' ), $on_off, (bool) $get( $h::OPT_HSTS_PRELOAD, false ) ? '1' : '0' );

		printf(
			'<div class="rip-form-row"><label class="rip-form-label" for="rip-hdr-perm">%s</label><input type="text" id="rip-hdr-perm" class="rip-input" data-opt="%s" value="%s" /></div>',
			esc_html__( 'Permissions-Policy', 'reportedip-hive' ),
			esc_attr( $h::OPT_PERMISSIONS ),
			esc_attr( (string) $get( $h::OPT_PERMISSIONS, '' ) )
		);

		self::render_select_row(
			'rip-hdr-csp-mode',
			$h::OPT_CSP_MODE,
			__( 'Content-Security-Policy mode', 'reportedip-hive' ),
			array(
				'off'         => __( 'Off', 'reportedip-hive' ),
				'report_only' => __( 'Report-Only (test first — recommended)', 'reportedip-hive' ),
				'enforce'     => __( 'Enforce', 'reportedip-hive' ),
			),
			(string) $get( $h::OPT_CSP_MODE, 'off' )
		);
		echo '<div class="rip-alert rip-alert--warning">' . esc_html__( 'Enforcing a CSP can break themes and plugins that rely on inline scripts. Always run Report-Only first and review the violations before you enforce.', 'reportedip-hive' ) . '</div>';
		$csp_policy = (string) $get( $h::OPT_CSP_POLICY, '' );
		if ( '' === $csp_policy ) {
			$csp_policy = $h::CSP_BASELINE;
		}
		printf(
			'<div class="rip-form-row"><label class="rip-form-label" for="rip-hdr-csp">%s</label><textarea id="rip-hdr-csp" class="rip-input rip-input--textarea" rows="4" data-opt="%s">%s</textarea></div>',
			esc_html__( 'CSP policy', 'reportedip-hive' ),
			esc_attr( $h::OPT_CSP_POLICY ),
			esc_textarea( $csp_policy )
		);
		printf(
			'<p><button type="button" class="rip-button rip-button--secondary rip-csp-preset" data-policy="%s">%s</button></p>',
			esc_attr( $h::CSP_BASELINE ),
			esc_html__( 'Insert OWASP baseline', 'reportedip-hive' )
		);
		printf(
			'<div class="rip-form-row"><label class="rip-form-label" for="rip-hdr-csp-uri">%s</label><input type="text" id="rip-hdr-csp-uri" class="rip-input" data-opt="%s" value="%s" /></div>',
			esc_html__( 'CSP report-uri (optional)', 'reportedip-hive' ),
			esc_attr( $h::OPT_CSP_REPORT_URI ),
			esc_attr( (string) $get( $h::OPT_CSP_REPORT_URI, '' ) )
		);

		self::render_select_row(
			'rip-hdr-coop',
			$h::OPT_COOP,
			__( 'Cross-Origin-Opener-Policy', 'reportedip-hive' ),
			array(
				'off'         => __( 'Off', 'reportedip-hive' ),
				'same-origin' => 'same-origin',
			),
			(string) $get( $h::OPT_COOP, 'off' )
		);
		self::render_select_row(
			'rip-hdr-corp',
			$h::OPT_CORP,
			__( 'Cross-Origin-Resource-Policy', 'reportedip-hive' ),
			array(
				'off'         => __( 'Off', 'reportedip-hive' ),
				'same-origin' => 'same-origin',
			),
			(string) $get( $h::OPT_CORP, 'off' )
		);
		self::render_select_row(
			'rip-hdr-coep',
			$h::OPT_COEP,
			__( 'Cross-Origin-Embedder-Policy', 'reportedip-hive' ),
			array(
				'off'          => __( 'Off', 'reportedip-hive' ),
				'require-corp' => 'require-corp',
			),
			(string) $get( $h::OPT_COEP, 'off' )
		);

		echo '</div></div>';

		printf(
			'<p><button type="button" class="rip-button rip-button--primary" id="rip-headers-save">%s</button> <span id="rip-headers-saved" class="rip-help-text"></span></p>',
			esc_html__( 'Save headers', 'reportedip-hive' )
		);

		echo <<<'RIPJS'
<script>jQuery(function($){
$('.rip-csp-preset').on('click',function(e){e.preventDefault();$('#rip-hdr-csp').val($(this).data('policy'));});
$('#rip-headers-save').on('click',function(e){e.preventDefault();var b=$(this).prop('disabled',true);var p={};$('[data-opt]').each(function(){p[$(this).data('opt')]=$(this).val();});$.post(reportedip_hive_ajax.ajax_url,{action:'reportedip_hive_headers_save',payload:JSON.stringify(p),nonce:reportedip_hive_ajax.nonce},function(r){b.prop('disabled',false);location.reload();});});
});</script>
RIPJS;
	}
}
