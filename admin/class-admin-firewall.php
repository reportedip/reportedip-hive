<?php
/**
 * Firewall admin page — overview dashboard, WAF, bot verification, spam
 * defence, scan & decoy, server setup, rule sync and hardening tabs.
 *
 * Extracted from ReportedIP_Hive_Admin_Settings so the firewall surface owns
 * its renderers. The shared page frame (branded header, trust-badge footer,
 * tier badges and tier locks) stays on the settings class and is consumed via
 * its public static helpers. Every server-level config snippet (WAF drop-in,
 * decoy rewrite rules, header export) lives on the Server Setup tab so the
 * operator configures the web server in exactly one place.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
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
	 * Event types the firewall surfaces own (overview feed + counters).
	 *
	 * The scan detector never writes a bare `scan_404` row: it funnels 404s
	 * through {@see ReportedIP_Hive_Security_Monitor::track_generic_attempt()},
	 * which only counts attempts and — once the burst threshold is crossed —
	 * logs the `_threshold_exceeded` variant. Listing the base type here made
	 * the counter and the feed permanently report zero even while scanners were
	 * being blocked.
	 *
	 * @var string[]
	 */
	const FIREWALL_EVENT_TYPES = array(
		'waf_block',
		'waf_would_block',
		'fake_bot',
		'fake_bot_blocked',
		'decoy_pathblock_hit',
		'scan_404_threshold_exceeded',
		'disposable_email',
		'prohibited_username',
		'registration_denied',
		'registration_limit',
		'unknown_username_probe_threshold_exceeded',
		'rule_sync_signature_fail',
	);

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
		echo '</select>';
		ReportedIP_Hive_Admin_Settings::render_field_help( $opt_key );
		echo '</div>';
	}

	/**
	 * Render the primary save button of a settings card. The Firewall page
	 * script posts every `[data-opt]` field of the surrounding `.rip-card`
	 * through the generic registry writer.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	private static function render_card_save_button() {
		printf(
			'<p><button type="button" class="rip-button rip-button--primary" data-rip-save="reportedip_hive_registry_save">%s</button></p>',
			esc_html__( 'Save', 'reportedip-hive' )
		);
	}

	/**
	 * Render an entry-list card: header with tier marker, help text, optional
	 * card-specific controls, the textarea, the entry counter and the save
	 * button.
	 *
	 * @param array{id:string,title:string,label:string,option:string,status:array<string,mixed>,help:string,placeholder:string,extra?:callable} $args Card definition.
	 * @return void
	 * @since  2.1.51
	 */
	private static function render_list_card( array $args ) {
		$option    = (string) $args['option'];
		$status    = (array) $args['status'];
		$unlimited = ! empty( $status['available'] );
		$raw       = (string) ReportedIP_Hive_Option_Routing::get( $option, '' );
		$stored    = ReportedIP_Hive_Registration_Guard::stored_entries( $raw );
		$active    = ReportedIP_Hive_Registration_Guard::active_entries( $raw, $unlimited );

		printf(
			'<div class="rip-card" id="%1$s"><div class="rip-card__header"><h2>%2$s</h2>',
			esc_attr( (string) $args['id'] ),
			esc_html( (string) $args['title'] )
		);
		ReportedIP_Hive_Admin_Settings::render_tier_marker( $status );
		echo '</div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html( (string) $args['help'] ) . '</p>';

		if ( isset( $args['extra'] ) && is_callable( $args['extra'] ) ) {
			call_user_func( $args['extra'] );
		}

		printf(
			'<div class="rip-form-row"><label class="rip-form-label" for="%1$s">%2$s</label><textarea id="%1$s" class="rip-textarea" rows="6" data-opt="%3$s" placeholder="%4$s">%5$s</textarea></div>',
			esc_attr( $args['id'] . '-input' ),
			esc_html( (string) $args['label'] ),
			esc_attr( $option ),
			esc_attr( (string) $args['placeholder'] ),
			esc_textarea( $raw )
		);

		echo '<p class="rip-help-text">' . esc_html(
			$unlimited
				/* translators: %d: number of active entries */
				? sprintf( __( '%d entries, no limit on your plan', 'reportedip-hive' ), count( $active ) )
				/* translators: 1: number of active entries, 2: entries allowed by the plan */
				: sprintf( __( '%1$d / %2$d entries', 'reportedip-hive' ), count( $active ), ReportedIP_Hive_Registration_Guard::FREE_MAX_ENTRIES )
		) . '</p>';

		if ( count( $stored ) > count( $active ) ) {
			echo '<div class="rip-alert rip-alert--warning">' . esc_html__( 'Only the first ten plain entries are in force on your plan. The remaining entries and every regular expression are kept but ignored.', 'reportedip-hive' ) . '</div>';
		}

		self::render_card_save_button();
		echo '</div></div>';
	}

	/**
	 * Admin URL of a firewall tab.
	 *
	 * @param string $slug Tab slug.
	 * @return string
	 * @since  2.1.3
	 */
	private static function tab_url( $slug ) {
		return ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-firewall&tab=' . $slug );
	}

	/**
	 * Render the one-paragraph "what does this tab do" intro under the tab strip.
	 *
	 * @param string $text Intro copy.
	 * @return void
	 * @since  2.1.3
	 */
	private static function render_tab_intro( $text ) {
		echo '<p class="rip-tab-intro">' . esc_html( $text ) . '</p>';
	}

	/**
	 * Render a labelled copy-paste snippet block (label, copy button, optional
	 * note, code).
	 *
	 * @param string $id    Element id for the copy target.
	 * @param string $label Snippet label.
	 * @param string $code  Snippet body.
	 * @param string $note  Optional help note rendered above the code.
	 * @return void
	 * @since  2.1.3
	 */
	private static function render_snippet( $id, $label, $code, $note = '' ) {
		printf(
			'<p><strong>%1$s</strong> <button type="button" class="rip-button rip-button--secondary" data-rip-copy="#%2$s">%3$s</button></p>',
			esc_html( $label ),
			esc_attr( $id ),
			esc_html__( 'Copy snippet', 'reportedip-hive' )
		);
		if ( '' !== $note ) {
			echo '<p class="rip-help-text">' . esc_html( $note ) . '</p>';
		}
		echo '<pre class="rip-code-snippet" id="' . esc_attr( $id ) . '"><code>' . esc_html( $code ) . '</code></pre>';
	}

	/**
	 * Display metadata for every server-delivered ruleset key. `url` wins over
	 * `tab` when the consuming feature lives outside the Firewall page.
	 *
	 * @return array<string,array{label:string,feeds:string,tab:string,url?:string}>
	 * @since  2.1.3
	 */
	private static function ruleset_meta() {
		return array(
			'waf'                => array(
				'label' => __( 'WAF signatures', 'reportedip-hive' ),
				'feeds' => __( 'Web Application Firewall', 'reportedip-hive' ),
				'tab'   => 'waf',
			),
			'bot_signatures'     => array(
				'label' => __( 'Verified-bot identities', 'reportedip-hive' ),
				'feeds' => __( 'Bot Verification', 'reportedip-hive' ),
				'tab'   => 'bot',
			),
			'disposable_domains' => array(
				'label' => __( 'Disposable e-mail domains', 'reportedip-hive' ),
				'feeds' => __( 'Registration & Spam', 'reportedip-hive' ),
				'tab'   => 'spam',
			),
			'scan_paths'         => array(
				'label' => __( 'Scanner probe paths', 'reportedip-hive' ),
				'feeds' => __( 'Scan Detection', 'reportedip-hive' ),
				'tab'   => 'scan',
			),
			'tor_exits'          => array(
				'label' => __( 'Tor exit nodes', 'reportedip-hive' ),
				'feeds' => __( 'Tor Exit Node Blocking', 'reportedip-hive' ),
				'tab'   => 'overview',
				'url'   => ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-settings&tab=blocking' ),
			),
		);
	}

	/**
	 * Human-readable label for a firewall event type.
	 *
	 * @param string $event_type Stored event type.
	 * @return string
	 * @since  2.1.3
	 */
	private static function event_label( $event_type ) {
		$labels = array(
			'waf_block'                                 => __( 'WAF blocked a request', 'reportedip-hive' ),
			'waf_would_block'                           => __( 'WAF match (report-only)', 'reportedip-hive' ),
			'fake_bot'                                  => __( 'Spoofed crawler flagged', 'reportedip-hive' ),
			'fake_bot_blocked'                          => __( 'Spoofed crawler blocked', 'reportedip-hive' ),
			'decoy_pathblock_hit'                       => __( 'Decoy path hit', 'reportedip-hive' ),
			'scan_404_threshold_exceeded'               => __( 'Scan detected', 'reportedip-hive' ),
			'disposable_email'                          => __( 'Disposable e-mail address detected', 'reportedip-hive' ),
			'prohibited_username'                       => __( 'Prohibited username at registration', 'reportedip-hive' ),
			'registration_denied'                       => __( 'Registration denied', 'reportedip-hive' ),
			'registration_limit'                        => __( 'Registration rate limit reached', 'reportedip-hive' ),
			'unknown_username_probe_threshold_exceeded' => __( 'Unknown-username login probe blocked', 'reportedip-hive' ),
			'rule_sync_signature_fail'                  => __( 'Ruleset signature rejected', 'reportedip-hive' ),
		);
		return isset( $labels[ $event_type ] ) ? $labels[ $event_type ] : ucwords( str_replace( '_', ' ', $event_type ) );
	}

	/**
	 * Firewall admin page — request-inspecting defence and the server-delivered
	 * rule sync. Routes the tab strip (Overview / WAF / Bot / Spam / Scan &
	 * Decoy / Server Setup / Rule Sync / Hardening) to the per-tab renderers.
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
			'spam'      => __( 'Registration & Spam', 'reportedip-hive' ),
			'scan'      => __( 'Scan & Decoy', 'reportedip-hive' ),
			'server'    => __( 'Server Setup', 'reportedip-hive' ),
			'rule_sync' => __( 'Rule Sync', 'reportedip-hive' ),
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
				esc_url( self::tab_url( $slug ) ),
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
			case 'server':
				$this->render_server_tab();
				break;
			case 'hardening':
				$this->render_hardening_tab();
				break;
			default:
				$this->render_overview_tab();
		}
		echo '</div>';

		ReportedIP_Hive_Admin_Settings::render_page_footer();
	}

	/**
	 * Render the Overview tab: a compact firewall dashboard — per-module status
	 * table, 7-day activity counters and the recent firewall event stream.
	 *
	 * @since 2.1.3
	 * @return void
	 */
	private function render_overview_tab() {
		self::render_tab_intro( __( 'Everything the firewall does at a glance: which modules are active, what they caught recently, and where to tune them. The detail tabs above configure each module; the Server Setup tab holds every web-server snippet in one place.', 'reportedip-hive' ) );

		$this->render_overview_status_table();
		$this->render_overview_activity();
		$this->render_overview_recent_events();
	}

	/**
	 * Render the per-module status table on the Overview tab.
	 *
	 * @since 2.1.3
	 * @return void
	 */
	private function render_overview_status_table() {
		$rows = $this->collect_module_status();

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Module status', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<table class="rip-table"><thead><tr><th>' . esc_html__( 'Module', 'reportedip-hive' ) . '</th><th>' . esc_html__( 'Status', 'reportedip-hive' ) . '</th><th>' . esc_html__( 'Details', 'reportedip-hive' ) . '</th><th></th></tr></thead><tbody>';
		foreach ( $rows as $row ) {
			printf(
				'<tr><td><strong>%1$s</strong></td><td><span class="rip-badge %2$s">%3$s</span></td><td>%4$s</td><td><a href="%5$s">%6$s</a></td></tr>',
				esc_html( $row['label'] ),
				esc_attr( $row['badge'] ),
				esc_html( $row['status'] ),
				esc_html( $row['detail'] ),
				esc_url( self::tab_url( $row['tab'] ) ),
				esc_html__( 'Configure', 'reportedip-hive' )
			);
		}
		echo '</tbody></table>';
		echo '</div></div>';
	}

	/**
	 * Collect the per-module status rows for the Overview table.
	 *
	 * @return array<int,array{label:string,status:string,badge:string,detail:string,tab:string}>
	 * @since  2.1.3
	 */
	private function collect_module_status() {
		$rows = array();

		if ( class_exists( 'ReportedIP_Hive_WAF' ) ) {
			$waf     = ReportedIP_Hive_WAF::get_instance();
			$enabled = $waf->is_enabled();
			$rows[]  = array(
				'label'  => __( 'WAF engine', 'reportedip-hive' ),
				'status' => $enabled ? __( 'Active', 'reportedip-hive' ) : __( 'Disabled', 'reportedip-hive' ),
				'badge'  => $enabled ? 'rip-badge--success' : 'rip-badge--neutral',
				'detail' => $enabled
					? sprintf(
						/* translators: 1: number of active rules, 2: paranoia level, 3: mode label. */
						__( '%1$d rules, Paranoia Level %2$d, %3$s', 'reportedip-hive' ),
						$waf->active_rule_count(),
						$waf->paranoia_cap(),
						$waf->is_report_only() ? __( 'report-only', 'reportedip-hive' ) : __( 'enforcing', 'reportedip-hive' )
					)
					: __( 'Requests are not inspected.', 'reportedip-hive' ),
				'tab'    => 'waf',
			);
		}

		if ( class_exists( 'ReportedIP_Hive_WAF_Dropin_Manager' ) ) {
			$dropin  = ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
			$enabled = (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false );
			$running = $dropin->is_running();
			if ( ! $enabled ) {
				$status = __( 'Off', 'reportedip-hive' );
				$badge  = 'rip-badge--neutral';
				$detail = __( 'Optional: run the WAF before WordPress loads.', 'reportedip-hive' );
			} elseif ( $running ) {
				$status = __( 'Running', 'reportedip-hive' );
				$badge  = 'rip-badge--success';
				$detail = __( 'Verified — the guard executed for this very request.', 'reportedip-hive' );
			} else {
				$status = __( 'Waiting', 'reportedip-hive' );
				$badge  = 'rip-badge--warning';
				$detail = __( 'Enabled, but the server directive is not active yet.', 'reportedip-hive' );
			}
			$rows[] = array(
				'label'  => __( 'Extended Protection (pre-WordPress)', 'reportedip-hive' ),
				'status' => $status,
				'badge'  => $badge,
				'detail' => $detail,
				'tab'    => $enabled && ! $running ? 'server' : 'waf',
			);
		}

		if ( class_exists( 'ReportedIP_Hive_Bot_Verifier' ) ) {
			$verifier = ReportedIP_Hive_Bot_Verifier::get_instance();
			$action   = $verifier->action();
			$active   = $verifier->is_enabled() && 'off' !== $action;
			$rows[]   = array(
				'label'  => __( 'Bot Verification', 'reportedip-hive' ),
				'status' => $active ? __( 'Active', 'reportedip-hive' ) : __( 'Off', 'reportedip-hive' ),
				'badge'  => $active ? 'rip-badge--success' : 'rip-badge--neutral',
				'detail' => $active
					? ( 'block' === $action ? __( 'Spoofed crawlers are blocked.', 'reportedip-hive' ) : __( 'Spoofed crawlers are flagged in the log.', 'reportedip-hive' ) )
					: __( 'Crawler identities are not verified.', 'reportedip-hive' ),
				'tab'    => 'bot',
			);
		}

		$disp_action   = class_exists( 'ReportedIP_Hive_Disposable_Email' )
			? ReportedIP_Hive_Disposable_Email::get_instance()->action()
			: 'off';
		$honeypot      = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_honeypot_enabled', true )
			&& ( ! class_exists( 'ReportedIP_Hive_Form_Proof' ) || ReportedIP_Hive_Form_Proof::get_instance()->is_enabled() );
		$filter_action = class_exists( 'ReportedIP_Hive_Comment_Spam_Filter' )
			? ReportedIP_Hive_Comment_Spam_Filter::get_instance()->action()
			: 'off';
		$spam_active   = ( 'off' !== $disp_action ) || $honeypot || ( 'off' !== $filter_action );
		$rows[]        = array(
			'label'  => __( 'Spam Defence', 'reportedip-hive' ),
			'status' => $spam_active ? __( 'Active', 'reportedip-hive' ) : __( 'Off', 'reportedip-hive' ),
			'badge'  => $spam_active ? 'rip-badge--success' : 'rip-badge--neutral',
			'detail' => sprintf(
				/* translators: 1: disposable-email mode, 2: form-protection state, 3: comment filter mode. */
				__( 'Disposable e-mail: %1$s · Form protection: %2$s · Comment filter: %3$s', 'reportedip-hive' ),
				ucfirst( $disp_action ),
				$honeypot ? __( 'on', 'reportedip-hive' ) : __( 'off', 'reportedip-hive' ),
				ucfirst( $filter_action )
			),
			'tab'    => 'spam',
		);

		$scan_on  = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_404_scans', true );
		$decoy_on = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_decoy_pathblock_enabled', true );
		$rows[]   = array(
			'label'  => __( 'Scan & Decoy', 'reportedip-hive' ),
			'status' => ( $scan_on || $decoy_on ) ? __( 'Active', 'reportedip-hive' ) : __( 'Off', 'reportedip-hive' ),
			'badge'  => ( $scan_on || $decoy_on ) ? 'rip-badge--success' : 'rip-badge--neutral',
			'detail' => sprintf(
				/* translators: 1: scan detector state, 2: decoy trap state. */
				__( 'Scan detector: %1$s · Decoy trap: %2$s', 'reportedip-hive' ),
				$scan_on ? __( 'on', 'reportedip-hive' ) : __( 'off', 'reportedip-hive' ),
				$decoy_on ? __( 'on', 'reportedip-hive' ) : __( 'off', 'reportedip-hive' )
			),
			'tab'    => 'scan',
		);

		if ( class_exists( 'ReportedIP_Hive_Security_Headers' ) ) {
			$hdr_on = ReportedIP_Hive_Security_Headers::is_enabled();
			$rows[] = array(
				'label'  => __( 'Security Headers', 'reportedip-hive' ),
				'status' => $hdr_on ? __( 'Active', 'reportedip-hive' ) : __( 'Off', 'reportedip-hive' ),
				'badge'  => $hdr_on ? 'rip-badge--success' : 'rip-badge--neutral',
				'detail' => $hdr_on
					? sprintf(
						/* translators: %d: number of headers currently emitted. */
						__( '%d headers are sent on every front-end response.', 'reportedip-hive' ),
						count( ReportedIP_Hive_Security_Headers::planned_headers() )
					)
					: __( 'No hardening headers are sent.', 'reportedip-hive' ),
				'tab'    => 'hardening',
			);
		}

		if ( class_exists( 'ReportedIP_Hive_Rule_Sync' ) && class_exists( 'ReportedIP_Hive_Rule_Store' ) ) {
			$sync   = ReportedIP_Hive_Rule_Sync::get_instance();
			$synced = 0;
			foreach ( ReportedIP_Hive_Rule_Store::VALID_KEYS as $key ) {
				$ruleset = $sync->get_ruleset( $key );
				if ( isset( $ruleset['version'] ) && (int) $ruleset['version'] > 0 ) {
					++$synced;
				}
			}
			$total  = count( ReportedIP_Hive_Rule_Store::VALID_KEYS );
			$rows[] = array(
				'label'  => __( 'Rule Sync', 'reportedip-hive' ),
				'status' => $synced > 0 ? __( 'Synced', 'reportedip-hive' ) : __( 'Baseline', 'reportedip-hive' ),
				'badge'  => $synced > 0 ? 'rip-badge--success' : 'rip-badge--info',
				'detail' => $synced > 0
					? sprintf(
						/* translators: 1: synced ruleset count, 2: total ruleset count. */
						__( '%1$d of %2$d rulesets delivered by the reportedip.com Rule API.', 'reportedip-hive' ),
						$synced,
						$total
					)
					: __( 'The bundled baseline rulesets are active.', 'reportedip-hive' ),
				'tab'    => 'rule_sync',
			);
		}

		return $rows;
	}

	/**
	 * Render the 7-day activity counters on the Overview tab.
	 *
	 * @since 2.1.3
	 * @return void
	 */
	private function render_overview_activity() {
		if ( ! class_exists( 'ReportedIP_Hive_Database' ) ) {
			return;
		}
		$counts = ReportedIP_Hive_Database::get_instance()->get_event_type_counts( self::FIREWALL_EVENT_TYPES, 7 * 24 );

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Activity (last 7 days)', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<div class="rip-grid rip-grid-cols-4">';
		self::render_stat_card(
			array(
				'value' => (string) ( $counts['waf_block'] + $counts['waf_would_block'] ),
				'label' => __( 'WAF matches', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => (string) ( $counts['fake_bot'] + $counts['fake_bot_blocked'] ),
				'label' => __( 'Spoofed crawlers', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => (string) ( $counts['decoy_pathblock_hit'] + $counts['scan_404_threshold_exceeded'] ),
				'label' => __( 'Scans & decoy hits', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => (string) $counts['disposable_email'],
				'label' => __( 'Disposable e-mails', 'reportedip-hive' ),
			)
		);
		echo '</div>';
		echo '</div></div>';
	}

	/**
	 * Render the recent firewall event stream on the Overview tab.
	 *
	 * @since 2.1.3
	 * @return void
	 */
	private function render_overview_recent_events() {
		if ( ! class_exists( 'ReportedIP_Hive_Database' ) ) {
			return;
		}
		$events = ReportedIP_Hive_Database::get_instance()->get_recent_events_by_types( self::FIREWALL_EVENT_TYPES, 7 * 24, 10 );
		$logger = class_exists( 'ReportedIP_Hive_Logger' ) ? ReportedIP_Hive_Logger::get_instance() : null;

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Recent firewall events', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';

		if ( empty( $events ) ) {
			echo '<div class="rip-empty-state rip-empty-state--compact">';
			echo '<svg class="rip-empty-state__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>';
			echo '<p class="rip-empty-state__text">' . esc_html__( 'No firewall events in the last 7 days. The modules are armed and will report here the moment something is caught.', 'reportedip-hive' ) . '</p>';
			echo '</div>';
		} else {
			echo '<ul class="rip-activity-list">';
			foreach ( $events as $event ) {
				$icon_class = 'info';
				if ( in_array( $event->severity, array( 'critical', 'high' ), true ) ) {
					$icon_class = 'danger';
				} elseif ( 'medium' === $event->severity ) {
					$icon_class = 'warning';
				} elseif ( 'low' === $event->severity ) {
					$icon_class = 'success';
				}
				$time_ago = human_time_diff( strtotime( $event->created_at ), time() );

				echo '<li class="rip-activity-item">';
				printf( '<div class="rip-activity-item__icon rip-activity-item__icon--%s">', esc_attr( $icon_class ) );
				if ( 'danger' === $icon_class ) {
					echo '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
				} elseif ( 'warning' === $icon_class ) {
					echo '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
				} else {
					echo '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>';
				}
				echo '</div>';
				echo '<div class="rip-activity-item__content">';
				echo '<div class="rip-activity-item__title">' . esc_html( self::event_label( (string) $event->event_type ) );
				echo ' <span class="rip-activity-item__ip">' . esc_html( $event->ip_address ) . '</span></div>';
				if ( $logger ) {
					echo '<div class="rip-activity-item__desc">' . wp_kses_post( $logger->format_details( $event->details ) ) . '</div>';
				}
				echo '</div>';
				/* translators: %s: human-readable time difference, e.g. "5 mins". */
				echo '<span class="rip-activity-item__time">' . esc_html( sprintf( __( '%s ago', 'reportedip-hive' ), $time_ago ) ) . '</span>';
				echo '</li>';
			}
			echo '</ul>';
		}

		echo '<p class="rip-help-text">';
		printf(
			/* translators: 1: opening link tag to the security logs, 2: closing tag. */
			esc_html__( 'The full event stream with filters lives on the %1$sSecurity › Logs%2$s page.', 'reportedip-hive' ),
			'<a href="' . esc_url( ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-security&tab=logs' ) ) . '">',
			'</a>'
		);
		echo '</p>';

		echo '</div></div>';
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

		self::render_tab_intro( __( 'The Web Application Firewall inspects every front-end request (URL, body, user-agent) against attack signatures — SQL injection, XSS, path traversal, command injection — and blocks the request before it reaches your site. Engine and baseline rules are free on every plan.', 'reportedip-hive' ) );

		echo '<nav class="rip-waf-jump" aria-label="' . esc_attr__( 'WAF sections', 'reportedip-hive' ) . '">';
		echo '<span class="rip-waf-jump__label">' . esc_html__( 'Jump to:', 'reportedip-hive' ) . '</span>';
		echo '<a class="rip-waf-jump__link" href="#rip-waf-engine">' . esc_html__( 'Engine & rules', 'reportedip-hive' ) . '</a>';
		echo '<a class="rip-waf-jump__link" href="#rip-waf-dropin">' . esc_html__( 'Extended protection', 'reportedip-hive' ) . '</a>';
		echo '<a class="rip-waf-jump__link" href="#rip-waf-exceptions">' . esc_html__( 'Exceptions', 'reportedip-hive' ) . '</a>';
		echo '</nav>';

		$waf         = ReportedIP_Hive_WAF::get_instance();
		$enabled     = $waf->is_enabled();
		$report_only = $waf->is_report_only();
		$rule_count  = $waf->active_rule_count();
		$pl_cap      = $waf->paranoia_cap();

		echo '<div class="rip-card" id="rip-waf-engine"><div class="rip-card__header"><h2>' . esc_html__( 'Web Application Firewall', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';

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
		echo '<div class="rip-form-row"><label class="rip-form-label" for="rip-waf-paranoia">' . esc_html__( 'Paranoia Level', 'reportedip-hive' ) . '</label> ';
		ReportedIP_Hive_Admin_Settings::render_tier_marker( $paranoia_status );
		if ( empty( $paranoia_status['available'] ) ) {
			echo '<p class="rip-help-text">' . esc_html__( 'Level 1 is active. Higher levels are delivered with the Professional ruleset.', 'reportedip-hive' ) . '</p>';
		} else {
			echo '<select id="rip-waf-paranoia" class="rip-select" data-rip-action="reportedip_hive_waf_set_paranoia" data-rip-param="level">';
			foreach ( $paranoia_levels as $level => $label ) {
				printf(
					'<option value="%d"%s>%s</option>',
					absint( $level ),
					selected( $paranoia_choice, $level, false ),
					esc_html( $label )
				);
			}
			echo '</select>';
		}
		echo '</div>';

		printf(
			'<button type="button" class="rip-button rip-button--secondary" data-rip-action="reportedip_hive_waf_toggle" data-rip-field="enabled">%s</button> ',
			esc_html( $enabled ? __( 'Disable engine', 'reportedip-hive' ) : __( 'Enable engine', 'reportedip-hive' ) )
		);
		printf(
			'<button type="button" class="rip-button rip-button--secondary" data-rip-action="reportedip_hive_waf_toggle" data-rip-field="report_only">%s</button>',
			esc_html( $report_only ? __( 'Switch to enforcing', 'reportedip-hive' ) : __( 'Switch to report-only', 'reportedip-hive' ) )
		);

		echo '</div></div>';

		echo '<div class="rip-card" id="rip-waf-scoring"><div class="rip-card__header"><h2>' . esc_html__( 'Scoring', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		self::render_select_row(
			'rip-waf-score',
			ReportedIP_Hive_WAF::OPT_BLOCK_THRESHOLD,
			__( 'Rule hits before a request is refused', 'reportedip-hive' ),
			array(
				'1'  => __( '1 — refuse on the first match', 'reportedip-hive' ),
				'2'  => __( '2', 'reportedip-hive' ),
				'3'  => __( '3 — default', 'reportedip-hive' ),
				'5'  => __( '5', 'reportedip-hive' ),
				'10' => __( '10 — only obvious attacks', 'reportedip-hive' ),
			),
			(string) (int) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_BLOCK_THRESHOLD, 3 )
		);
		self::render_card_save_button();
		echo '</div></div>';

		$this->render_waf_dropin_box();
		$this->render_waf_exceptions_box();
	}

	/**
	 * Render the backend-managed WAF exceptions (allowlist) box: a narrow
	 * add-form plus the list of active exceptions. Lets an operator relieve a
	 * false positive — a single rule on a path, or a whole-engine bypass for a
	 * first-party endpoint that legitimately carries attack-like payloads —
	 * without touching code. Mirrors how ModSecurity exclusions and the
	 * Wordfence allowlist work: exceptions are data, not shipped rules.
	 *
	 * @return void
	 * @since  2.1.9
	 */
	private function render_waf_exceptions_box() {
		if ( ! class_exists( 'ReportedIP_Hive_WAF_Exceptions_Table' ) ) {
			return;
		}

		echo '<div class="rip-card" id="rip-waf-exceptions"><div class="rip-card__header"><h2>' . esc_html__( 'WAF Exceptions', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Relieve a false positive without editing code. Scope an exception to a single rule (optionally on one path), a rule group, or — for a first-party endpoint that legitimately receives attack-like payloads — the whole engine on a path. A whole-engine exception must always carry a path or IP.', 'reportedip-hive' ) . '</p>';

		echo '<form id="add-waf-exception-form" class="rip-form">';

		echo '<div class="rip-form-row"><label class="rip-form-label" for="rip-waf-ex-scope">' . esc_html__( 'Scope', 'reportedip-hive' ) . '</label>';
		echo '<select id="rip-waf-ex-scope" name="scope" class="rip-select">';
		echo '<option value="rule">' . esc_html__( 'Single rule — exempt one specific rule', 'reportedip-hive' ) . '</option>';
		echo '<option value="group">' . esc_html__( 'Rule group — exempt a whole category', 'reportedip-hive' ) . '</option>';
		echo '<option value="all">' . esc_html__( 'Whole engine — only on a trusted path/IP', 'reportedip-hive' ) . '</option>';
		echo '</select>';
		echo '<p class="rip-field-hint">' . esc_html__( 'How broadly the exception applies. Start with "Single rule" — it is the narrowest and the right choice for almost every false positive.', 'reportedip-hive' ) . '</p></div>';

		echo '<div class="rip-form-row" data-rip-scope="rule"><label class="rip-form-label" for="rip-waf-ex-rule">' . esc_html__( 'Rule ID', 'reportedip-hive' ) . '</label>';
		echo '<input type="text" id="rip-waf-ex-rule" name="rule_id" class="rip-input" placeholder="waf_sqli_union" />';
		echo '<p class="rip-field-hint">' . wp_kses( __( 'The exact rule that fired. You will find it in the firewall log as <code>Rule:</code> (Security &rarr; Activity &rarr; WAF Block). Easiest of all: click the shield "Allow" button on the blocked event there and this is filled in for you.', 'reportedip-hive' ), array( 'code' => array() ) ) . '</p></div>';

		echo '<div class="rip-form-row rip-hidden" data-rip-scope="group"><label class="rip-form-label" for="rip-waf-ex-group">' . esc_html__( 'Rule group', 'reportedip-hive' ) . '</label>';
		echo '<select id="rip-waf-ex-group" name="rule_id" class="rip-select" disabled>';
		foreach ( self::waf_group_choices() as $group_key => $group_label ) {
			printf( '<option value="%s">%s</option>', esc_attr( $group_key ), esc_html( $group_label ) );
		}
		echo '</select>';
		echo '<p class="rip-field-hint">' . esc_html__( 'Exempts every rule in this category at once — shown in the log as "Group:". Broader than a single rule, so use it only when several rules of the same kind keep misfiring.', 'reportedip-hive' ) . '</p></div>';

		echo '<div class="rip-form-row rip-hidden" data-rip-scope="all"><p class="rip-field-hint">' . esc_html__( 'No rule needed — the WAF skips the path and/or IP below entirely. Use this only for a first-party endpoint you fully trust (e.g. your own API that receives attack samples). A path or IP is required.', 'reportedip-hive' ) . '</p></div>';

		echo '<div class="rip-form-row"><label class="rip-form-label" for="rip-waf-ex-path">' . esc_html__( 'Path prefix', 'reportedip-hive' ) . '</label>';
		echo '<input type="text" id="rip-waf-ex-path" name="path_prefix" class="rip-input" placeholder="/wp-json/my-api/v1" />';
		echo '<p class="rip-field-hint">' . esc_html__( 'Optional. Limits the exception to URLs that start with this path. Leave empty to apply everywhere (single-rule and group scope only).', 'reportedip-hive' ) . '</p></div>';

		echo '<div class="rip-form-row"><label class="rip-form-label" for="rip-waf-ex-ip">' . esc_html__( 'IP or CIDR', 'reportedip-hive' ) . '</label>';
		echo '<input type="text" id="rip-waf-ex-ip" name="ip_address" class="rip-input" placeholder="203.0.113.7" />';
		echo '<p class="rip-field-hint">' . esc_html__( 'Optional. Limits the exception to this client IP or range, e.g. 203.0.113.0/24.', 'reportedip-hive' ) . '</p></div>';

		echo '<div class="rip-form-row"><label class="rip-form-label" for="rip-waf-ex-reason">' . esc_html__( 'Reason', 'reportedip-hive' ) . '</label>';
		echo '<input type="text" id="rip-waf-ex-reason" name="reason" class="rip-input" placeholder="' . esc_attr__( 'e.g. report ingest endpoint', 'reportedip-hive' ) . '" />';
		echo '<p class="rip-field-hint">' . esc_html__( 'Optional. Shown in the list below so you remember later why this exception exists.', 'reportedip-hive' ) . '</p></div>';

		echo '<button type="submit" class="rip-button rip-button--primary">' . esc_html__( 'Add exception', 'reportedip-hive' ) . '</button>';
		echo '</form>';

		$table = new ReportedIP_Hive_WAF_Exceptions_Table();
		$table->prepare_items();
		$table->process_bulk_action();

		echo '<form method="post">';
		printf( '<input type="hidden" name="page" value="%s" />', esc_attr( 'reportedip-hive-firewall' ) );
		printf( '<input type="hidden" name="tab" value="%s" />', esc_attr( 'waf' ) );
		$table->display();
		echo '</form>';

		echo '<div class="rip-faq">';
		echo '<h3 class="rip-faq__title">' . esc_html__( 'Understanding WAF exceptions', 'reportedip-hive' ) . '</h3>';

		echo '<details class="rip-faq__item"><summary class="rip-faq__q">' . esc_html__( 'What is this for, and do I need it?', 'reportedip-hive' ) . '</summary>';
		echo '<p class="rip-faq__a">' . esc_html__( 'The WAF matches every front-end request against attack signatures (SQL injection, XSS, and so on). Occasionally a legitimate request looks like an attack — for example an API endpoint that receives reported attack samples, or a form that contains code. The rule fires even though nothing malicious is happening: a false positive. An exception tells the WAF to let that specific case through. Most sites never need one — only add an exception when you have confirmed a real false positive in the log.', 'reportedip-hive' ) . '</p></details>';

		echo '<details class="rip-faq__item"><summary class="rip-faq__q">' . esc_html__( 'Where do I get the Rule ID or group? I do not know what to type.', 'reportedip-hive' ) . '</summary>';
		echo '<p class="rip-faq__a">' . wp_kses(
			__( 'You normally do not type it at all. Every block is recorded under <strong>Security &rarr; Activity &rarr; WAF Block</strong>, and each entry names the rule that fired (<code>Rule: waf_sqli_union</code>) and its category (<code>Group: sql_injection</code>). The quickest path is the shield <strong>"Allow"</strong> button on that log row: it creates a single-rule exception for exactly that rule and path in one click, so you never have to know rule IDs. The form above is only for adding one by hand — copy the value after <code>Rule:</code> into the Rule ID field, or pick the category in the Rule group dropdown.', 'reportedip-hive' ),
			array(
				'code'   => array(),
				'strong' => array(),
			)
		) . '</p></details>';

		echo '<details class="rip-faq__item"><summary class="rip-faq__q">' . esc_html__( 'Which scope should I choose — rule, group or whole engine?', 'reportedip-hive' ) . '</summary>';
		echo '<p class="rip-faq__a">' . esc_html__( 'Single rule is the narrowest and the right default: it exempts exactly one rule, optionally only on one path. Rule group exempts a whole category (every XSS rule, say) — broader, only when several related rules keep misfiring. Whole engine skips all inspection and is reserved for a first-party endpoint you fully trust; it always requires a path or IP, so protection is never switched off everywhere by accident. Rule of thumb: pick the smallest scope that stops the false positive.', 'reportedip-hive' ) . '</p></details>';

		echo '<details class="rip-faq__item"><summary class="rip-faq__q">' . esc_html__( 'How do the path and IP fields work?', 'reportedip-hive' ) . '</summary>';
		echo '<p class="rip-faq__a">' . esc_html__( 'Both are optional narrowing filters. Path prefix limits the exception to URLs that start with the value you enter (for example /wp-json/my-api/v1, matching every route below it). IP or CIDR limits it to one client address or range. Leave them empty and a single-rule or group exception applies site-wide; set them to make it as tight as possible. For a whole-engine exception at least one of the two is mandatory.', 'reportedip-hive' ) . '</p></details>';

		echo '<details class="rip-faq__item"><summary class="rip-faq__q">' . esc_html__( 'Does this weaken my security, and does it apply to Extended Protection?', 'reportedip-hive' ) . '</summary>';
		echo '<p class="rip-faq__a">' . esc_html__( 'Only within the scope you pick — a rule-on-path exception leaves every other rule and every other path fully protected, which is why tight scoping matters. Exceptions apply everywhere the engine runs: they are also baked into the pre-WordPress guard, so the in-WordPress engine and the Extended-Protection layer honour the same allowlist.', 'reportedip-hive' ) . '</p></details>';

		echo '</div>';

		echo '</div></div>';
	}

	/**
	 * The selectable WAF rule groups for the exception form, keyed by the
	 * canonical group token (as it appears in the firewall log) and labelled
	 * "Human name (token)" so the value matches what the operator sees there.
	 * Derived from {@see ReportedIP_Hive_WAF::GROUP_REASON} so the list tracks
	 * the engine's known categories.
	 *
	 * @return array<string,string> Group token => option label.
	 * @since  2.1.11
	 */
	private static function waf_group_choices() {
		$labels = class_exists( 'ReportedIP_Hive_WAF' ) ? ReportedIP_Hive_WAF::group_labels() : array();
		$groups = class_exists( 'ReportedIP_Hive_WAF' ) ? array_keys( ReportedIP_Hive_WAF::GROUP_REASON ) : array_keys( $labels );

		$choices = array();
		foreach ( $groups as $group_key ) {
			$name = isset( $labels[ $group_key ] ) ? $labels[ $group_key ] : $group_key;
			/* translators: 1: human-readable group name, 2: raw group token shown in the log. */
			$choices[ $group_key ] = sprintf( __( '%1$s (%2$s)', 'reportedip-hive' ), $name, $group_key );
		}

		return $choices;
	}

	/**
	 * Render the "Extended Protection" box on the WAF tab: live setup state of
	 * the optional pre-WordPress drop-in. The definitive signal is whether the
	 * guard executed for the current request; the actual config snippets live on
	 * the Server Setup tab so the operator configures the server in one place.
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
		$running    = $dropin->is_running();
		$auto       = in_array( $server, array( 'apache', 'fpm' ), true );
		$server_lbl = array(
			'apache'  => 'Apache (mod_php, .htaccess)',
			'fpm'     => 'PHP-FPM / CGI (.user.ini)',
			'nginx'   => 'nginx (manual setup)',
			'unknown' => __( 'Unknown', 'reportedip-hive' ),
		);

		if ( ! $enabled ) {
			$status_value = __( 'Off', 'reportedip-hive' );
			$status_badge = 'rip-badge--neutral';
		} elseif ( $running ) {
			$status_value = __( 'Running', 'reportedip-hive' );
			$status_badge = 'rip-badge--success';
		} else {
			$status_value = __( 'Waiting for server config', 'reportedip-hive' );
			$status_badge = 'rip-badge--warning';
		}

		echo '<div class="rip-card" id="rip-waf-dropin"><div class="rip-card__header"><h2>' . esc_html__( 'Extended Protection (pre-WordPress)', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Optionally run the firewall before WordPress loads, so a malicious request is rejected earlier and cheaper. Off by default and free on every plan. Turning it on brings a few extra settings with it: Hive generates a guard file, a server-config directive is added on the Server Setup tab (written automatically on Apache and PHP-FPM; one manual step on nginx or via php.ini), and the guard then applies the same rule exceptions and paranoia level as the in-WordPress engine.', 'reportedip-hive' ) . '</p>';

		echo '<div class="rip-grid rip-grid-cols-3">';
		self::render_stat_card(
			array(
				'value' => $status_value,
				'badge' => $status_badge,
				'label' => __( 'Status', 'reportedip-hive' ),
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
				'value' => $dropin->guard_exists() ? __( 'Generated', 'reportedip-hive' ) : __( 'Not generated', 'reportedip-hive' ),
				'badge' => $dropin->guard_exists() ? 'rip-badge--success' : 'rip-badge--neutral',
				'label' => __( 'Guard file', 'reportedip-hive' ),
			)
		);
		$queue_ok = $dropin->queue_is_writable();
		self::render_stat_card(
			array(
				'value' => $queue_ok ? __( 'Recording', 'reportedip-hive' ) : __( 'Not writable', 'reportedip-hive' ),
				'badge' => $queue_ok ? 'rip-badge--success' : 'rip-badge--warning',
				'label' => __( 'Hit logging', 'reportedip-hive' ),
			)
		);
		echo '</div>';

		if ( $enabled && ! $queue_ok ) {
			echo '<div class="rip-alert rip-alert--warning">';
			printf(
				/* translators: %s: absolute path of the queue directory. */
				esc_html__( 'The guard cannot write to %s, so blocked requests are stopped but never reach the log, the counters or the escalation ladder. Give the web-server user write access to that directory.', 'reportedip-hive' ),
				'<code>' . esc_html( dirname( $dropin->queue_path() ) ) . '</code>'
			);
			echo '</div>';
		}

		if ( $enabled && $running ) {
			echo '<div class="rip-alert rip-alert--success">' . esc_html__( 'Setup complete — the guard executed for this very request, so every request to this site passes the firewall before WordPress loads.', 'reportedip-hive' ) . '</div>';
		} elseif ( $enabled && $auto ) {
			echo '<div class="rip-alert rip-alert--info">';
			printf(
				/* translators: 1: opening link tag to the Server Setup tab, 2: closing tag. */
				esc_html__( 'The directive was written automatically. PHP-FPM caches .user.ini for up to five minutes — reload this page shortly. If the status never flips to Running (common on nginx + PHP-FPM), the %1$sServer Setup tab%2$s carries a manual nginx / php.ini option you can apply instead.', 'reportedip-hive' ),
				'<a href="' . esc_url( self::tab_url( 'server' ) ) . '">',
				'</a>'
			);
			echo '</div>';
		} elseif ( $enabled ) {
			echo '<div class="rip-alert rip-alert--warning">';
			printf(
				/* translators: 1: opening link tag to the Server Setup tab, 2: closing tag. */
				esc_html__( 'One manual step left: add the directive to your server. The %1$sServer Setup tab%2$s shows both options (nginx snippet or php.ini line) with your live paths — this status flips to Running automatically once it works.', 'reportedip-hive' ),
				'<a href="' . esc_url( self::tab_url( 'server' ) ) . '">',
				'</a>'
			);
			echo '</div>';
		}

		printf(
			'<label class="rip-toggle"><input type="checkbox" class="rip-toggle__input" data-opt="%1$s" value="1"%2$s /><span class="rip-toggle__slider"></span><span class="rip-toggle__label">%3$s</span></label>',
			esc_attr( ReportedIP_Hive_WAF::OPT_DROPIN_SKIP_AUTHENTICATED ),
			checked( (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_SKIP_AUTHENTICATED, true ), true, false ),
			esc_html__( 'Leave the request body of signed-in users alone', 'reportedip-hive' )
		);
		ReportedIP_Hive_Admin_Settings::render_field_help( ReportedIP_Hive_WAF::OPT_DROPIN_SKIP_AUTHENTICATED );
		self::render_card_save_button();

		printf(
			'<p><button type="button" class="rip-button rip-button--primary" data-rip-action="reportedip_hive_waf_dropin_toggle">%s</button> ',
			esc_html( $enabled ? __( 'Disable extended protection', 'reportedip-hive' ) : __( 'Enable extended protection', 'reportedip-hive' ) )
		);
		printf(
			'<a href="%s" class="rip-button rip-button--secondary">%s</a></p>',
			esc_url( self::tab_url( 'server' ) ),
			esc_html__( 'Open Server Setup', 'reportedip-hive' )
		);

		echo '</div></div>';
	}

	/**
	 * Render the Bot Verification tab: what the sensor does, the verified
	 * crawler list, recent spoofer activity and the action selector. Free on
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

		self::render_tab_intro( __( 'Many attackers disguise themselves as Googlebot to slip past rate limits. This sensor checks whether a request claiming to be a known crawler really comes from that crawler — first against the official IP ranges, then via forward-confirmed reverse DNS. Genuine crawlers are never blocked, so it is SEO-safe by design.', 'reportedip-hive' ) );

		$verifier = ReportedIP_Hive_Bot_Verifier::get_instance();
		$action   = $verifier->action();
		$enabled  = $verifier->is_enabled();
		$rules    = $verifier->get_bot_rules();
		$bot_ver  = 0;
		if ( class_exists( 'ReportedIP_Hive_Rule_Sync' ) ) {
			$ruleset = ReportedIP_Hive_Rule_Sync::get_instance()->get_ruleset( 'bot_signatures' );
			$bot_ver = isset( $ruleset['version'] ) ? (int) $ruleset['version'] : 0;
		}
		$with_ranges = 0;
		foreach ( $rules as $rule ) {
			if ( is_array( $rule ) && ! empty( $rule['ranges'] ) ) {
				++$with_ranges;
			}
		}
		$spoof_counts = array(
			'fake_bot'         => 0,
			'fake_bot_blocked' => 0,
		);
		if ( class_exists( 'ReportedIP_Hive_Database' ) ) {
			$spoof_counts = ReportedIP_Hive_Database::get_instance()->get_event_type_counts( array( 'fake_bot', 'fake_bot_blocked' ), 7 * 24 );
		}

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Verified Bot Detection', 'reportedip-hive' ) . '</h2>';
		ReportedIP_Hive_Admin_Settings::render_tier_marker( ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'rule_sync_priority' ) );
		echo '</div><div class="rip-card__body">';

		echo '<div class="rip-grid rip-grid-cols-4">';
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
				'value' => (string) absint( $with_ranges ),
				'label' => __( 'With official IP ranges', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => (string) absint( $spoof_counts['fake_bot'] + $spoof_counts['fake_bot_blocked'] ),
				'label' => __( 'Spoofers caught (7 days)', 'reportedip-hive' ),
			)
		);
		echo '</div>';

		if ( ! empty( $rules ) ) {
			echo '<p class="rip-help-text">' . esc_html__( 'Crawlers currently verified:', 'reportedip-hive' ) . '</p>';
			echo '<p>';
			foreach ( $rules as $rule ) {
				$ua = is_array( $rule ) && isset( $rule['ua'] ) ? (string) $rule['ua'] : '';
				if ( '' === $ua ) {
					continue;
				}
				$has_ranges = is_array( $rule ) && ! empty( $rule['ranges'] );
				printf(
					'<span class="rip-badge %1$s">%2$s</span> ',
					esc_attr( $has_ranges ? 'rip-badge--success' : 'rip-badge--neutral' ),
					esc_html( ucfirst( $ua ) )
				);
			}
			echo '</p>';
			echo '<p class="rip-help-text">' . esc_html__( 'Green: verified DNS-free against the official IP ranges. Grey: verified via forward-confirmed reverse DNS. The frequently-refreshed range feeds (Google, Bing) arrive with the Professional ruleset.', 'reportedip-hive' ) . '</p>';
		}

		echo '<p class="rip-help-text">' . ( $bot_ver > 0
			? esc_html__( 'The crawler list is delivered and signed by the reportedip.com Rule API.', 'reportedip-hive' ) . ' (v' . absint( $bot_ver ) . ')'
			: esc_html__( 'The bundled baseline crawler list is active. Connect the Community Network for the server-delivered list.', 'reportedip-hive' ) ) . '</p>';

		$actions = array(
			'off'   => __( 'Off — do not verify', 'reportedip-hive' ),
			'flag'  => __( 'Flag — log spoofers only (recommended)', 'reportedip-hive' ),
			'block' => __( 'Block — reject confirmed spoofers', 'reportedip-hive' ),
		);
		self::render_select_row(
			'rip-bot-monitor',
			ReportedIP_Hive_Bot_Verifier::OPT_MONITOR,
			__( 'Crawler verification sensor', 'reportedip-hive' ),
			array(
				'1' => __( 'On', 'reportedip-hive' ),
				'0' => __( 'Off — do not check crawler identities at all', 'reportedip-hive' ),
			),
			ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_Bot_Verifier::OPT_MONITOR, true ) ? '1' : '0'
		);
		self::render_card_save_button();

		echo '<div class="rip-form-row"><label class="rip-form-label" for="rip-bot-action">' . esc_html__( 'Action on a confirmed spoofer', 'reportedip-hive' ) . '</label>';
		echo '<select id="rip-bot-action" class="rip-select" data-rip-action="reportedip_hive_bot_action" data-rip-param="mode">';
		foreach ( $actions as $value => $label ) {
			printf(
				'<option value="%s"%s>%s</option>',
				esc_attr( $value ),
				selected( $action, $value, false ),
				esc_html( $label )
			);
		}
		echo '</select></div>';

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
		self::render_tab_intro( __( 'Decides who may open an account here. Registrations run through one ordered check: allowlisted networks, the rate limit per address, prohibited usernames, your e-mail rules and finally the throwaway-mail list. The comment honeypot at the bottom rejects comment bots without a CAPTCHA.', 'reportedip-hive' ) );

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

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Disposable Email', 'reportedip-hive' ) . '</h2>';
		ReportedIP_Hive_Admin_Settings::render_tier_marker( ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'rule_sync_priority' ) );
		echo '</div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Inspects the e-mail address at registration (WordPress and WooCommerce) against the throwaway-mail list. Monitor logs a match; Block rejects the registration. The live, frequently-updated list rides the Professional ruleset.', 'reportedip-hive' ) . '</p>';
		echo '<p class="rip-help-text">' . esc_html__( 'An e-mail allow rule below overrules this list: an address matching an allow rule is accepted even when its domain is a known throwaway provider.', 'reportedip-hive' ) . '</p>';

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
		echo '<select id="rip-disposable-action" class="rip-select" data-rip-action="reportedip_hive_disposable_action" data-rip-param="mode">';
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
			'<button type="button" class="rip-button rip-button--secondary" data-rip-action="reportedip_hive_spam_toggle" data-rip-field="block_relays">%s</button>',
			esc_html( $block_relays ? __( 'Stop blocking privacy relays', 'reportedip-hive' ) : __( 'Also block privacy relays', 'reportedip-hive' ) )
		);

		echo '</div></div>';

		$status    = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'registration_rules_unlimited' );
		$unlimited = ! empty( $status['available'] );

		self::render_list_card(
			array(
				'id'          => 'rip-reg-usernames',
				'title'       => __( 'Prohibited usernames', 'reportedip-hive' ),
				'label'       => __( 'Prohibited usernames', 'reportedip-hive' ),
				'option'      => ReportedIP_Hive_Registration_Guard::OPT_USERNAMES,
				'status'      => $status,
				'help'        => __( 'One entry per line. An entry is compared literally, as a wildcard when it contains an asterisk (admin*), or as a case-insensitive regular expression when it is written between slashes (/^adm[i1]n$/). Regular expressions need the Professional plan. Lines starting with # are notes.', 'reportedip-hive' ),
				'placeholder' => "shop-admin\nadmin*",
				'extra'       => static function () {
					$baseline = (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_Registration_Guard::OPT_USERNAMES_BASELINE, true );
					printf(
						'<label class="rip-toggle"><input type="checkbox" class="rip-toggle__input" data-opt="%1$s" value="1"%2$s /><span class="rip-toggle__slider"></span><span class="rip-toggle__label">%3$s</span></label>',
						esc_attr( ReportedIP_Hive_Registration_Guard::OPT_USERNAMES_BASELINE ),
						checked( $baseline, true, false ),
						esc_html__( 'Also reject the built-in list (admin, administrator, root, support and six more). It does not count towards the entry allowance.', 'reportedip-hive' )
					);
				},
			)
		);

		$email_mode = (string) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_Registration_Guard::OPT_EMAIL_MODE, 'off' );

		self::render_list_card(
			array(
				'id'          => 'rip-reg-emails',
				'title'       => __( 'E-mail rules', 'reportedip-hive' ),
				'label'       => __( 'E-mail rules', 'reportedip-hive' ),
				'option'      => ReportedIP_Hive_Registration_Guard::OPT_EMAIL_RULES,
				'status'      => $status,
				'help'        => __( 'One entry per line, compared against the whole address. A bare host name is stored as *@host. Wildcards such as *@*.example.com and, on the Professional plan, regular expressions between slashes are allowed.', 'reportedip-hive' ),
				'placeholder' => "example.com\n*@*.example.org",
				'extra'       => static function () use ( $email_mode ) {
					self::render_select_row(
						'rip-reg-email-mode',
						ReportedIP_Hive_Registration_Guard::OPT_EMAIL_MODE,
						__( 'Rule mode', 'reportedip-hive' ),
						array(
							'off'   => __( 'Off — do not check addresses against this list', 'reportedip-hive' ),
							'block' => __( 'Block list — reject addresses that match', 'reportedip-hive' ),
							'allow' => __( 'Allow list — accept only addresses that match', 'reportedip-hive' ),
						),
						$email_mode
					);
					if ( 'allow' === $email_mode ) {
						echo '<div class="rip-alert rip-alert--warning">' . esc_html__( 'Allow-list mode rejects every address that does not match an entry. An empty list is treated as Off, so a plan change cannot close registration by accident.', 'reportedip-hive' ) . '</div>';
					}
				},
			)
		);

		$limit_on  = (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_Registration_Guard::OPT_LIMIT_ENABLED, true );
		$limit_max = (int) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_Registration_Guard::OPT_LIMIT_COUNT, 3 );
		$limit_win = (int) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_Registration_Guard::OPT_LIMIT_TIMEFRAME, 60 );

		echo '<div class="rip-card" id="rip-reg-limit"><div class="rip-card__header"><h2>' . esc_html__( 'Registration rate limit', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Counts completed registrations per visitor address and refuses further ones inside the window. Refusing is the whole consequence: no address is blocked and nothing is reported, because a shared office or campus connection opening a few accounts is not an attacker. Whitelisted addresses are never counted. The number compared against the limit is the address\'s current run of registrations, not a sliding window: it starts over once a whole window passes without one, so a steady drip can reach the limit over a longer span than the window.', 'reportedip-hive' ) . '</p>';
		echo '<div class="rip-grid rip-grid-cols-2">';
		self::render_stat_card(
			array(
				'value' => $limit_on ? __( 'Active', 'reportedip-hive' ) : __( 'Disabled', 'reportedip-hive' ),
				'badge' => $limit_on ? 'rip-badge--success' : 'rip-badge--neutral',
				'label' => __( 'Rate limit', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				/* translators: 1: registrations allowed, 2: window length in minutes */
				'value' => sprintf( __( '%1$d in %2$d min', 'reportedip-hive' ), $limit_max, $limit_win ),
				'label' => __( 'Current limit', 'reportedip-hive' ),
			)
		);
		echo '</div>';
		printf(
			'<label class="rip-toggle"><input type="checkbox" class="rip-toggle__input" data-opt="%1$s" value="1"%2$s /><span class="rip-toggle__slider"></span><span class="rip-toggle__label">%3$s</span></label>',
			esc_attr( ReportedIP_Hive_Registration_Guard::OPT_LIMIT_ENABLED ),
			checked( $limit_on, true, false ),
			esc_html__( 'Limit registrations per visitor address', 'reportedip-hive' )
		);
		printf(
			'<div class="rip-form-row"><label class="rip-form-label" for="rip-reg-limit-count">%1$s</label><input type="number" id="rip-reg-limit-count" class="rip-input" min="1" max="100" data-opt="%2$s" value="%3$s" /></div>',
			esc_html__( 'Registrations per window', 'reportedip-hive' ),
			esc_attr( ReportedIP_Hive_Registration_Guard::OPT_LIMIT_COUNT ),
			esc_attr( (string) $limit_max )
		);
		printf(
			'<div class="rip-form-row"><label class="rip-form-label" for="rip-reg-limit-window">%1$s</label><input type="number" id="rip-reg-limit-window" class="rip-input" min="1" max="60" data-opt="%2$s" value="%3$s" /></div>',
			esc_html__( 'Window (minutes)', 'reportedip-hive' ),
			esc_attr( ReportedIP_Hive_Registration_Guard::OPT_LIMIT_TIMEFRAME ),
			esc_attr( (string) $limit_win )
		);
		self::render_card_save_button();
		echo '</div></div>';

		$allowlist = (string) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_Registration_Guard::OPT_ALLOWLIST, '' );

		echo '<div class="rip-card" id="rip-reg-allowlist"><div class="rip-card__header"><h2>' . esc_html__( 'Registration from allowlisted addresses only', 'reportedip-hive' ) . '</h2>';
		ReportedIP_Hive_Admin_Settings::render_tier_marker( $status );
		echo '</div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Leave empty to accept registrations from everywhere. With entries, only visitors from those addresses or ranges may register. One IP or CIDR range per line, lines starting with # are notes. Administrators creating accounts in wp-admin are never restricted.', 'reportedip-hive' ) . '</p>';
		if ( ! $unlimited ) {
			echo '<p class="rip-help-text">' . esc_html__( 'Restricting registration to an address list needs the Professional plan.', 'reportedip-hive' ) . '</p>';
		}
		echo '<div class="rip-alert rip-alert--warning">' . esc_html__( 'With a non-empty list every other visitor is told that registration is not available from their network. Add your own address first.', 'reportedip-hive' ) . '</div>';
		printf(
			'<div class="rip-form-row"><label class="rip-form-label" for="rip-reg-allowlist-input">%1$s</label><textarea id="rip-reg-allowlist-input" class="rip-textarea" rows="4" data-opt="%2$s" placeholder="%3$s"%4$s>%5$s</textarea></div>',
			esc_html__( 'Allowed addresses', 'reportedip-hive' ),
			esc_attr( ReportedIP_Hive_Registration_Guard::OPT_ALLOWLIST ),
			esc_attr( '203.0.113.0/24' ),
			disabled( $unlimited, false, false ),
			esc_textarea( $allowlist )
		);
		self::render_card_save_button();
		echo '</div></div>';

		$probe_on = (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_Registration_Guard::OPT_BLOCK_UNKNOWN_USERNAME, false );

		echo '<div class="rip-card" id="rip-reg-probe"><div class="rip-card__header"><h2>' . esc_html__( 'Instant block on unknown usernames', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'A failed login naming an account nobody owns is usually a credential list being read out loud. With this on, the visitor address is blocked right away and the escalation ladder decides for how long. The login response does not change: it stays the same "Invalid credentials." every failed login gets, and the block appears in the log as an unknown-username login probe.', 'reportedip-hive' ) . '</p>';
		echo '<div class="rip-alert rip-alert--warning">' . esc_html__( 'Two things to accept before switching this on. One typo in the username locks that visitor out until the block expires, and anyone who can observe whether a block follows learns whether an account name exists here. Whitelist your own addresses first.', 'reportedip-hive' ) . '</div>';
		self::render_stat_card(
			array(
				'value' => $probe_on ? __( 'Active', 'reportedip-hive' ) : __( 'Disabled', 'reportedip-hive' ),
				'badge' => $probe_on ? 'rip-badge--success' : 'rip-badge--neutral',
				'label' => __( 'Instant block', 'reportedip-hive' ),
			)
		);
		printf(
			'<label class="rip-toggle"><input type="checkbox" class="rip-toggle__input" data-opt="%1$s" value="1"%2$s /><span class="rip-toggle__slider"></span><span class="rip-toggle__label">%3$s</span></label>',
			esc_attr( ReportedIP_Hive_Registration_Guard::OPT_BLOCK_UNKNOWN_USERNAME ),
			checked( $probe_on, true, false ),
			esc_html__( 'Block the address after a login with a username no account uses', 'reportedip-hive' )
		);
		self::render_card_save_button();
		echo '</div></div>';

		$has_proof      = class_exists( 'ReportedIP_Hive_Form_Proof' );
		$proof_on       = $has_proof && ReportedIP_Hive_Form_Proof::get_instance()->is_enabled();
		$login_forms_on = $has_proof && ReportedIP_Hive_Form_Proof::get_instance()->login_forms_enabled();
		$report_only    = $has_proof && ReportedIP_Hive_Form_Proof::get_instance()->report_only();
		$has_gate       = class_exists( 'ReportedIP_Hive_Reputation_Gate' );
		$gate_on        = $has_gate && ReportedIP_Hive_Reputation_Gate::get_instance()->is_enabled();
		$gate_threshold = $has_gate ? ReportedIP_Hive_Reputation_Gate::threshold() : 0;
		$community      = ReportedIP_Hive_Mode_Manager::get_instance()->is_community_mode();

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Form Protection', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Adds an invisible decoy field to the comment form, the sign-up form and the password-reset form. A bot that fills every field trips it, and a script that posts straight at the address without ever loading the form is recognised because it cannot carry the field a browser would have added.', 'reportedip-hive' ) . '</p>';
		echo '<p class="rip-help-text">' . esc_html__( 'No CAPTCHA and no extra step for real visitors. Someone browsing without JavaScript can still comment, their comment is filed for review instead; sign-up and password reset do ask for JavaScript and say so.', 'reportedip-hive' ) . '</p>';

		echo '<div class="rip-grid rip-grid-cols-2">';
		self::render_stat_card(
			array(
				'value' => $honeypot ? __( 'Active', 'reportedip-hive' ) : __( 'Disabled', 'reportedip-hive' ),
				'badge' => $honeypot ? 'rip-badge--success' : 'rip-badge--neutral',
				'label' => __( 'Comment decoy', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => $proof_on ? __( 'Active', 'reportedip-hive' ) : __( 'Disabled', 'reportedip-hive' ),
				'badge' => $proof_on ? 'rip-badge--success' : 'rip-badge--neutral',
				'label' => __( 'Execution proof', 'reportedip-hive' ),
			)
		);
		echo '</div>';

		printf(
			'<p><button type="button" class="rip-button rip-button--secondary" data-rip-action="reportedip_hive_spam_toggle" data-rip-field="honeypot">%s</button></p>',
			esc_html( $honeypot ? __( 'Disable the comment decoy', 'reportedip-hive' ) : __( 'Enable the comment decoy', 'reportedip-hive' ) )
		);
		printf(
			'<label class="rip-toggle"><input type="checkbox" class="rip-toggle__input" data-opt="%1$s" value="1"%2$s /><span class="rip-toggle__slider"></span><span class="rip-toggle__label">%3$s</span></label>',
			esc_attr( ReportedIP_Hive_Form_Proof::OPT_ENABLED ),
			checked( $proof_on, true, false ),
			esc_html__( 'Require proof that the form was rendered in a browser', 'reportedip-hive' )
		);
		printf(
			'<label class="rip-toggle"><input type="checkbox" class="rip-toggle__input" data-opt="%1$s" value="1"%2$s /><span class="rip-toggle__slider"></span><span class="rip-toggle__label">%3$s</span></label>',
			esc_attr( ReportedIP_Hive_Form_Proof::OPT_LOGIN_FORMS ),
			checked( $login_forms_on, true, false ),
			esc_html__( 'Apply it to the sign-up and password-reset forms as well', 'reportedip-hive' )
		);
		echo '<p class="rip-help-text">' . esc_html__( 'A comment that fails the check is filed for review, a sign-up or password reset that fails is refused outright. Leave the second switch off if you would rather never risk a visitor being unable to recover their password.', 'reportedip-hive' ) . '</p>';

		printf(
			'<label class="rip-toggle"><input type="checkbox" class="rip-toggle__input" data-opt="%1$s" value="1"%2$s /><span class="rip-toggle__slider"></span><span class="rip-toggle__label">%3$s</span></label>',
			esc_attr( ReportedIP_Hive_Reputation_Gate::OPT_ENABLED ),
			checked( $gate_on, true, false ),
			esc_html__( 'Run a community threat check when a form is submitted', 'reportedip-hive' )
		);
		printf(
			'<p class="rip-help-text">%s</p>',
			esc_html(
				sprintf(
					/* translators: %d: protection level in percent. */
					__( 'Asks the community network about the visitor address the moment a comment, sign-up or password reset arrives, at the same protection level the sign-in page uses (currently %d%%). A visitor the site would refuse a login to cannot post a comment instead. Each check spends one lookup from your daily allowance; a submission the local filter has already judged is not looked up.', 'reportedip-hive' ),
					(int) $gate_threshold
				)
			)
		);
		if ( ! $community ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'The threat check needs Community Network mode with a Community Access Key. Without one it stays dormant and nothing is refused.', 'reportedip-hive' ) . '</div>';
		}

		if ( $report_only ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'Report-only mode is on, so nothing is refused anywhere. Failed checks are written to the log and the sign-up and password-reset forms let every visitor through.', 'reportedip-hive' ) . '</div>';
		}
		self::render_card_save_button();
		echo '</div></div>';

		$this->render_comment_filter_card();
	}

	/**
	 * Render the comment spam filter card: the action selector plus the two
	 * counter fields that decide when a repeat offender is blocked.
	 *
	 * @since 2.1.52
	 * @return void
	 */
	private function render_comment_filter_card() {
		$action    = class_exists( 'ReportedIP_Hive_Comment_Spam_Filter' )
			? ReportedIP_Hive_Comment_Spam_Filter::get_instance()->action()
			: 'spam';
		$threshold = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_spam_threshold', 5 );
		$window    = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_spam_timeframe', 60 );

		echo '<div class="rip-card" id="rip-comment-filter"><div class="rip-card__header"><h2>' . esc_html__( 'Comment Spam Filter', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Reads every incoming comment and scores it on link count, link density, throwaway domains, giveaway top-level domains, a link in the author name and a body that carries no message. A comment needs several of those before it counts, so an ordinary reader who leaves their website address is not caught by one signal alone.', 'reportedip-hive' ) . '</p>';
		echo '<p class="rip-help-text">' . esc_html__( 'Filing it as spam is the safe setting, because the comment lands in the spam folder where you can review it. Rejecting refuses the comment outright and leaves the visitor with an error page.', 'reportedip-hive' ) . '</p>';

		$actions = array(
			'spam'  => __( 'File as spam (recommended)', 'reportedip-hive' ),
			'block' => __( 'Reject the comment outright', 'reportedip-hive' ),
			'off'   => __( 'Off, leave the decision to WordPress', 'reportedip-hive' ),
		);
		echo '<div class="rip-form-row"><label class="rip-form-label" for="rip-comment-spam-action">' . esc_html__( 'Action on a comment scored as spam', 'reportedip-hive' ) . '</label>';
		printf( '<select id="rip-comment-spam-action" class="rip-select" data-opt="%s">', esc_attr( ReportedIP_Hive_Comment_Spam_Filter::OPT_ACTION ) );
		foreach ( $actions as $value => $label ) {
			printf(
				'<option value="%s"%s>%s</option>',
				esc_attr( $value ),
				selected( $action, $value, false ),
				esc_html( $label )
			);
		}
		echo '</select></div>';

		echo '<p class="rip-help-text">' . esc_html__( 'An address that keeps producing spam comments is blocked once it passes the counter below, and reported to the community network.', 'reportedip-hive' ) . '</p>';
		printf(
			'<div class="rip-form-row"><label class="rip-form-label" for="rip-comment-threshold">%1$s</label><input type="number" id="rip-comment-threshold" class="rip-input" min="1" max="50" data-opt="%2$s" value="%3$s" /></div>',
			esc_html__( 'Spam comments per window', 'reportedip-hive' ),
			esc_attr( 'reportedip_hive_comment_spam_threshold' ),
			esc_attr( (string) $threshold )
		);
		printf(
			'<div class="rip-form-row"><label class="rip-form-label" for="rip-comment-window">%1$s</label><input type="number" id="rip-comment-window" class="rip-input" min="1" max="1440" data-opt="%2$s" value="%3$s" /></div>',
			esc_html__( 'Window (minutes)', 'reportedip-hive' ),
			esc_attr( 'reportedip_hive_comment_spam_timeframe' ),
			esc_attr( (string) $window )
		);
		self::render_card_save_button();
		echo '</div></div>';
	}

	/**
	 * Render the Scan & Decoy tab: the 404/honeypot scan detector status and
	 * toggle, followed by the Decoy Path Block status. Both sensors are free on
	 * every plan; the optional web-server-level rules live on the Server Setup
	 * tab and the numeric 404 thresholds on Settings › Protection.
	 *
	 * @since 2.1.2
	 * @return void
	 */
	private function render_scan_tab() {
		self::render_tab_intro( __( 'Catches vulnerability scanners two ways: a burst of 404s in a short window (rate trigger), and a single request to a known bait path like .env or wp-config.php.bak (instant trigger). Both sensors run in PHP and need no server configuration; the optional web-server rules on the Server Setup tab harden the same paths one layer earlier.', 'reportedip-hive' ) );

		$scan_on   = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_404_scans', true );
		$threshold = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_scan_404_threshold', 12 );
		$timeframe = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_scan_404_timeframe', 2 );
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
			'<button type="button" class="rip-button rip-button--secondary" data-rip-action="reportedip_hive_scan_toggle" data-rip-field="scan">%s</button>',
			esc_html( $scan_on ? __( 'Disable scan detector', 'reportedip-hive' ) : __( 'Enable scan detector', 'reportedip-hive' ) )
		);

		echo '<p class="rip-help-text">';
		printf(
			/* translators: 1: opening Protection-settings link tag, 2: closing tag, 3: opening Rule-Sync link tag, 4: closing tag. */
			esc_html__( 'Tune the 404 thresholds on the %1$sProtection settings%2$s; review the active probe-path list on the %3$sRule Sync%4$s tab.', 'reportedip-hive' ),
			'<a href="' . esc_url( ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-settings&tab=protection' ) ) . '">',
			'</a>',
			'<a href="' . esc_url( self::tab_url( 'rule_sync' ) ) . '">',
			'</a>'
		);
		echo '</p>';

		echo '</div></div>';

		$this->render_decoy_box();
	}

	/**
	 * Resolve the status of an auto-managed .htaccess block: the detected web
	 * server with its display label, whether that server reads .htaccess at
	 * all, and the badge for the block itself. Two states must never read as
	 * "Active": the empty marker skeleton a disabled switch leaves behind, and
	 * a block in an .htaccess the web server never reads — nginx ignores the
	 * file, so a present block is inert there and the badge says so instead of
	 * claiming protection.
	 *
	 * @param bool $enabled  Whether the owning switch is on.
	 * @param bool $present  Whether the marker block is currently in the file.
	 * @param bool $writable Whether the target file is writable.
	 * @return array<string,mixed> Keys: server, server_label, htaccess, badge, label.
	 * @since  2.1.51
	 */
	private static function htaccess_block_status( $enabled, $present, $writable ) {
		$manager  = class_exists( 'ReportedIP_Hive_WAF_Dropin_Manager' )
			? ReportedIP_Hive_WAF_Dropin_Manager::get_instance()
			: null;
		$server   = $manager ? $manager->detect_web_server() : 'unknown';
		$htaccess = $manager ? $manager->supports_htaccess() : false;
		$labels   = array(
			'apache'    => 'Apache (.htaccess)',
			'litespeed' => 'LiteSpeed (.htaccess)',
			'nginx'     => 'nginx',
			'unknown'   => __( 'Unknown', 'reportedip-hive' ),
		);

		if ( ! $enabled ) {
			$badge = 'rip-badge--neutral';
			$label = __( 'Inactive', 'reportedip-hive' );
		} elseif ( ! $htaccess ) {
			$badge = 'rip-badge--info';
			$label = __( 'Not applicable', 'reportedip-hive' );
		} elseif ( $present ) {
			$badge = 'rip-badge--success';
			$label = __( 'Active', 'reportedip-hive' );
		} elseif ( $writable ) {
			$badge = 'rip-badge--warning';
			$label = __( 'Pending', 'reportedip-hive' );
		} else {
			$badge = 'rip-badge--info';
			$label = __( 'Manual', 'reportedip-hive' );
		}

		return array(
			'server'       => $server,
			'server_label' => isset( $labels[ $server ] ) ? $labels[ $server ] : $server,
			'htaccess'     => $htaccess,
			'badge'        => $badge,
			'label'        => $label,
		);
	}

	/**
	 * Render the Decoy Path Block surface: the master toggle and the
	 * auto-managed .htaccess status. A decoy hit is answered with a 403 and
	 * reported, but the IP is never added to the local block list, so a
	 * misbehaving backup plugin cannot lock the operator out. The optional
	 * web-server snippets live on the Server Setup tab.
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
		$status   = self::htaccess_block_status( $decoy_on, $present, $writable );
		$htaccess = $status['htaccess'];

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
				'value' => $status['label'],
				'badge' => $status['badge'],
				'label' => __( '.htaccess block', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => $status['server_label'],
				'label' => __( 'Detected server', 'reportedip-hive' ),
			)
		);
		echo '</div>';

		if ( ! $decoy_on ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'The decoy trap is off — no rewrite rules are active and no bait-path hits are reported.', 'reportedip-hive' ) . '</div>';
		} elseif ( ! $htaccess ) {
			echo '<div class="rip-alert rip-alert--info">';
			printf(
				/* translators: 1: opening link tag to the Server Setup tab, 2: closing tag. */
				esc_html__( 'This web server does not read .htaccess, so no rewrite block can be auto-managed here. The PHP sensor still catches every bait-path request that reaches WordPress. Only a bait file that physically exists on disk is served without touching PHP — the rule on the %1$sServer Setup tab%2$s closes that gap.', 'reportedip-hive' ),
				'<a href="' . esc_url( self::tab_url( 'server' ) ) . '">',
				'</a>'
			);
			echo '</div>';
		} elseif ( $writable && $present ) {
			echo '<div class="rip-alert rip-alert--success">' . esc_html__( 'Auto-managed — Hive wrote the rewrite block to .htaccess. Real bait files on disk will no longer be served directly.', 'reportedip-hive' ) . '</div>';
		} elseif ( $writable ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( '.htaccess is writable but the block is not in place yet. Re-toggle the trap to trigger a sync.', 'reportedip-hive' ) . '</div>';
		} else {
			echo '<div class="rip-alert rip-alert--warning">';
			printf(
				/* translators: 1: opening link tag to the Server Setup tab, 2: closing tag. */
				esc_html__( '.htaccess is not writable, so the rewrite block cannot be auto-managed. The PHP sensor still catches every bait-path hit; the optional web-server rule on the %1$sServer Setup tab%2$s blocks them one layer earlier.', 'reportedip-hive' ),
				'<a href="' . esc_url( self::tab_url( 'server' ) ) . '">',
				'</a>'
			);
			echo '</div>';
		}

		printf(
			'<p><button type="button" class="rip-button rip-button--secondary" data-rip-action="reportedip_hive_scan_toggle" data-rip-field="decoy">%s</button> ',
			esc_html( $decoy_on ? __( 'Disable decoy trap', 'reportedip-hive' ) : __( 'Enable decoy trap', 'reportedip-hive' ) )
		);
		printf(
			'<a href="%s" class="rip-button rip-button--secondary">%s</a></p>',
			esc_url( self::tab_url( 'server' ) ),
			esc_html__( 'Open Server Setup', 'reportedip-hive' )
		);

		echo '</div></div>';
	}

	/**
	 * Render the Server Setup tab: every web-server-level rule the plugin can
	 * use, in one place — the WAF drop-in directive (auto or manual), the decoy
	 * rewrite rules and an optional server-level export of the security
	 * headers. All sections are optional; the PHP sensors work without them.
	 *
	 * @since 2.1.3
	 * @return void
	 */
	private function render_server_tab() {
		self::render_tab_intro( __( 'All web-server-level rules in one place, with your live paths filled in. Everything here is optional — the PHP sensors work without any of it — but each rule rejects bad requests one layer earlier. Configure your server once, from this tab only.', 'reportedip-hive' ) );

		$this->render_server_waf_section();
		$this->render_server_decoy_section();
		$this->render_server_headers_section();
	}

	/**
	 * Render the WAF drop-in section of the Server Setup tab: the live status,
	 * the auto-managed state on Apache/FPM, and the two manual options (nginx
	 * snippet or php.ini line) as an explicit either/or choice.
	 *
	 * @since 2.1.3
	 * @return void
	 */
	private function render_server_waf_section() {
		if ( ! class_exists( 'ReportedIP_Hive_WAF_Dropin_Manager' ) ) {
			return;
		}
		$dropin  = ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
		$enabled = (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false );
		$server  = $dropin->detect_server();
		$running = $dropin->is_running();
		$auto    = in_array( $server, array( 'apache', 'fpm' ), true );

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'WAF Extended Protection (auto_prepend_file)', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Runs the firewall guard before WordPress loads. Hive generates the guard file; the server only needs one auto_prepend_file directive pointing at it.', 'reportedip-hive' ) . '</p>';

		if ( ! $enabled ) {
			echo '<div class="rip-alert rip-alert--info">';
			printf(
				/* translators: 1: opening link tag to the WAF tab, 2: closing tag. */
				esc_html__( 'Extended Protection is currently off. Enable it on the %1$sWAF tab%2$s first — that generates the guard file this directive points at.', 'reportedip-hive' ),
				'<a href="' . esc_url( self::tab_url( 'waf' ) ) . '">',
				'</a>'
			);
			echo '</div>';
			echo '</div></div>';
			return;
		}

		if ( $running ) {
			echo '<div class="rip-alert rip-alert--success">' . esc_html__( 'Setup complete — the guard executed for this very request. No further action needed; Hive keeps the guard file up to date automatically on every rule sync.', 'reportedip-hive' ) . '</div>';
		}

		if ( $auto && $running ) {
			echo '<p class="rip-help-text">' . esc_html__( 'This server is auto-managed — Hive wrote and maintains the directive itself (.htaccess on Apache, .user.ini on PHP-FPM).', 'reportedip-hive' ) . '</p>';
			echo '</div></div>';
			return;
		}

		/*
		 * `detect_server()` reports the PHP SAPI, so an nginx + PHP-FPM stack is
		 * classified as `fpm` and Hive writes a `.user.ini`. That file is only
		 * honoured when PHP's `user_ini.filename` is enabled and the document
		 * root is the scan path — frequently not the case on nginx. When the
		 * auto-written directive has not taken effect we therefore fall through
		 * to the manual snippets (php.ini / FPM pool + nginx server block) so
		 * nginx operators are never left without instructions.
		 */
		if ( $auto && ! $running ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'Hive wrote the directive automatically (.htaccess on Apache, .user.ini on PHP-FPM), and PHP-FPM caches .user.ini for up to five minutes — give it a moment. If the status never flips to Running — common on nginx, or when PHP\'s user_ini.filename is disabled or the document root is not the .user.ini scan path — apply ONE of the manual options below instead.', 'reportedip-hive' ) . '</div>';
		} elseif ( ! $running ) {
			echo '<div class="rip-alert rip-alert--warning">' . esc_html__( 'One manual step: add the directive below. Pick exactly ONE of the two options — whichever your hosting lets you edit. The status above flips to Running automatically once the directive is live.', 'reportedip-hive' ) . '</div>';
		}

		self::render_snippet(
			'rip-waf-snip-phpini',
			__( 'Option A — php.ini / PHP-FPM pool / hosting panel (recommended)', 'reportedip-hive' ),
			$dropin->php_ini_snippet(),
			__( 'Most managed hosts (ISPConfig, Plesk, cPanel) offer a "custom php.ini settings" field — paste this single line there and reload PHP-FPM. In a PHP-FPM pool config the equivalent line is php_admin_value[auto_prepend_file] = <the same path>. This is usually the easiest route on nginx.', 'reportedip-hive' )
		);

		self::render_snippet(
			'rip-waf-snip-nginx',
			__( 'Option B — nginx server block', 'reportedip-hive' ),
			$dropin->nginx_snippet(),
			__( 'For direct nginx access: merge this into your existing "location ~ \\.php$" block and reload nginx. Do not combine with Option A.', 'reportedip-hive' )
		);

		echo '<div class="rip-alert rip-alert--warning">';
		echo '<strong>' . esc_html__( 'Before deactivating or deleting Hive, remove this directive from your php.ini / nginx config first.', 'reportedip-hive' ) . '</strong> ';
		echo esc_html__( 'Because this directive lives in a file Hive cannot edit, it stays behind when the plugin is removed. Hive now leaves an inert placeholder at the guard path so a leftover directive can no longer crash the site with a 500 error — but the cleanest path is still to remove the line yourself.', 'reportedip-hive' );
		echo '<br><br>';
		echo '<strong>' . esc_html__( 'Recovery, if the site ever returns a 500 referencing reportedip-hive-waf.php:', 'reportedip-hive' ) . '</strong> ';
		echo esc_html__( 'comment out the auto_prepend_file line in your php.ini / nginx config (prefix it with a semicolon, or delete it) and reload PHP-FPM / nginx. No FTP file restore is required.', 'reportedip-hive' );
		echo '</div>';

		echo '</div></div>';
	}

	/**
	 * Render the decoy rewrite-rule section of the Server Setup tab — the
	 * Apache preview and both nginx variants, moved here from the Scan & Decoy
	 * tab so every server snippet lives on one surface.
	 *
	 * @since 2.1.3
	 * @return void
	 */
	private function render_server_decoy_section() {
		if ( ! class_exists( 'ReportedIP_Hive_Decoy_Path_Block' ) ) {
			return;
		}
		$decoy_on = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_decoy_pathblock_enabled', true );
		$htaccess = class_exists( 'ReportedIP_Hive_WAF_Dropin_Manager' )
			&& ReportedIP_Hive_WAF_Dropin_Manager::get_instance()->supports_htaccess();

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Decoy Path Block (rewrite rules)', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Blocks the bait paths at the web-server layer so real backup files on disk are never served directly. Every snippet rewrites to /index.php on purpose: the Hive sensor still loads, logs the hit and reports it — a bare return 403 would skip detection entirely.', 'reportedip-hive' ) . '</p>';

		if ( ! $decoy_on ) {
			echo '<div class="rip-alert rip-alert--info">';
			printf(
				/* translators: 1: opening link tag to the Scan & Decoy tab, 2: closing tag. */
				esc_html__( 'The decoy trap is currently off — enable it on the %1$sScan & Decoy tab%2$s before adding server rules.', 'reportedip-hive' ),
				'<a href="' . esc_url( self::tab_url( 'scan' ) ) . '">',
				'</a>'
			);
			echo '</div>';
		} elseif ( $htaccess ) {
			echo '<div class="rip-alert rip-alert--success">' . esc_html__( 'On Apache this block is auto-managed in .htaccess — the snippet below shows verbatim what Hive wrote (or would write). No manual step needed.', 'reportedip-hive' ) . '</div>';
		} else {
			echo '<div class="rip-alert rip-alert--warning">' . esc_html__( 'This web server does not read .htaccess, so the auto-managed block does not apply here. Pick one of the nginx snippets below to cover bait files that exist on disk.', 'reportedip-hive' ) . '</div>';
		}

		self::render_snippet(
			'rip-decoy-snip-apache',
			__( 'Apache (.htaccess) — auto-managed', 'reportedip-hive' ),
			ReportedIP_Hive_Decoy_Path_Block::htaccess_snippet()
		);
		self::render_snippet(
			'rip-decoy-snip-nginx',
			__( 'nginx — regex form (plain nginx)', 'reportedip-hive' ),
			ReportedIP_Hive_Decoy_Path_Block::nginx_snippet()
		);
		self::render_snippet(
			'rip-decoy-snip-nginx-exact',
			__( 'nginx — exact-match form (ISPConfig & managed stacks)', 'reportedip-hive' ),
			ReportedIP_Hive_Decoy_Path_Block::nginx_snippet_exact_match(),
			__( 'Use this variant when your host template ships a "location ~ /\\." dot-file deny rule before your custom directives — exact-match locations have higher priority than any regex location and survive that ordering.', 'reportedip-hive' )
		);

		echo '</div></div>';
	}

	/**
	 * Render the optional server-level security-header export on the Server
	 * Setup tab: nginx add_header and Apache Header lines generated from the
	 * live header configuration on the Hardening tab.
	 *
	 * @since 2.1.3
	 * @return void
	 */
	private function render_server_headers_section() {
		if ( ! class_exists( 'ReportedIP_Hive_Security_Headers' ) ) {
			return;
		}
		$planned = ReportedIP_Hive_Security_Headers::planned_headers();

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Security Headers at the web server (optional)', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Hive already sends the configured headers via PHP on every WordPress response — nothing to do for normal pages. Setting them at the web server additionally covers static files (images, CSS, uploads) that never touch PHP. The snippets mirror your live configuration from the Hardening tab.', 'reportedip-hive' ) . '</p>';

		if ( empty( $planned ) ) {
			echo '<div class="rip-alert rip-alert--info">';
			printf(
				/* translators: 1: opening link tag to the Hardening tab, 2: closing tag. */
				esc_html__( 'No headers are configured yet. Enable the header engine on the %1$sHardening tab%2$s first — the snippets here update automatically.', 'reportedip-hive' ),
				'<a href="' . esc_url( self::tab_url( 'hardening' ) ) . '">',
				'</a>'
			);
			echo '</div>';
			echo '</div></div>';
			return;
		}

		$nginx_lines  = array();
		$apache_lines = array();
		foreach ( $planned as $name => $value ) {
			$nginx_lines[]  = 'add_header ' . $name . ' "' . str_replace( '"', '\"', $value ) . '" always;';
			$apache_lines[] = 'Header always set ' . $name . ' "' . str_replace( '"', '\"', $value ) . '"';
		}

		echo '<details class="rip-form-group"><summary><strong>' . esc_html__( 'Show server snippets (generated from your current header settings)', 'reportedip-hive' ) . '</strong></summary>';
		self::render_snippet(
			'rip-headers-snip-nginx',
			__( 'nginx (server block)', 'reportedip-hive' ),
			implode( "\n", $nginx_lines ),
			__( 'When a header is set at the server, Hive detects it and stops sending its own copy — no duplicates.', 'reportedip-hive' )
		);
		self::render_snippet(
			'rip-headers-snip-apache',
			__( 'Apache (.htaccess or vhost, requires mod_headers)', 'reportedip-hive' ),
			implode( "\n", $apache_lines )
		);
		echo '</details>';

		echo '</div></div>';
	}

	/**
	 * Render the Rule Sync status surface: per-ruleset version, rule count and
	 * source, the last sync time and the operation-mode-aware state. The
	 * Free-vs-Professional comparison appears only while Priority Sync is not
	 * on the plan; an active plan gets a compact confirmation instead.
	 *
	 * @since 2.1.2
	 * @return void
	 */
	private function render_rule_sync_tab() {
		self::render_tab_intro( __( 'The detection rules behind the WAF, Bot Verification, Spam Defence, Scan Detection and Tor Exit Node Blocking are not hard-coded: they are versioned rulesets, maintained on reportedip.com, signed with Ed25519 and delivered through the Rule API. A bundled baseline ships with the plugin, so every install is protected even fully offline.', 'reportedip-hive' ) );

		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$sync         = ReportedIP_Hive_Rule_Sync::get_instance();
		$priority     = $mode_manager->feature_status( 'rule_sync_priority' );
		$last_run     = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_rule_sync_last_run', 0 );
		$enabled      = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_rule_sync_enabled', true );
		$has_priority = ! empty( $priority['available'] );

		if ( ! $has_priority ) {
			$this->render_rule_sync_tiers( false );
		}

		echo '<div class="rip-card" id="rip-rule-sync-switch"><div class="rip-card__header"><h2>' . esc_html__( 'Rule synchronisation', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		self::render_select_row(
			'rip-rule-sync-enabled',
			'reportedip_hive_rule_sync_enabled',
			__( 'Fetch rules from the community server', 'reportedip-hive' ),
			array(
				'1' => __( 'On', 'reportedip-hive' ),
				'0' => __( 'Off', 'reportedip-hive' ),
			),
			ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_rule_sync_enabled', true ) ? '1' : '0'
		);
		self::render_card_save_button();
		echo '</div></div>';

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Active rulesets', 'reportedip-hive' ) . '</h2>';
		ReportedIP_Hive_Admin_Settings::render_tier_marker( $priority );
		echo '</div><div class="rip-card__body">';

		if ( $has_priority ) {
			echo '<div class="rip-alert rip-alert--success">' . esc_html__( 'Priority Sync is active on your plan — the rulesets below refresh automatically from the reportedip.com Rule API, signed and verified on every download.', 'reportedip-hive' ) . '</div>';
		} elseif ( $mode_manager->is_local_mode() ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'Local Shield mode: the bundled baseline rulesets are active. Connect the Community Network to receive the richer, frequently-updated rulesets.', 'reportedip-hive' ) . '</div>';
		}

		$meta = self::ruleset_meta();
		echo '<table class="rip-table"><thead><tr><th>' . esc_html__( 'Ruleset', 'reportedip-hive' ) . '</th><th>' . esc_html__( 'Feeds', 'reportedip-hive' ) . '</th><th>' . esc_html__( 'Rules', 'reportedip-hive' ) . '</th><th>' . esc_html__( 'Version', 'reportedip-hive' ) . '</th><th>' . esc_html__( 'Source', 'reportedip-hive' ) . '</th></tr></thead><tbody>';
		foreach ( ReportedIP_Hive_Rule_Store::VALID_KEYS as $key ) {
			$ruleset    = $sync->get_ruleset( $key );
			$version    = isset( $ruleset['version'] ) ? (int) $ruleset['version'] : 0;
			$rule_count = isset( $ruleset['rules'] ) && is_array( $ruleset['rules'] ) ? count( $ruleset['rules'] ) : 0;
			$synced     = $version > 0;
			$badge      = $synced ? 'rip-badge--success' : 'rip-badge--neutral';
			$source     = $synced
				? __( 'reportedip.com Rule API', 'reportedip-hive' )
				: __( 'Bundled baseline', 'reportedip-hive' );
			$label      = isset( $meta[ $key ] ) ? $meta[ $key ]['label'] : $key;
			$feeds_lbl  = isset( $meta[ $key ] ) ? $meta[ $key ]['feeds'] : '';
			$feeds_tab  = isset( $meta[ $key ] ) ? $meta[ $key ]['tab'] : 'overview';
			$feeds_url  = isset( $meta[ $key ]['url'] ) ? $meta[ $key ]['url'] : self::tab_url( $feeds_tab );
			printf(
				'<tr><td><strong>%1$s</strong><br /><code>%2$s</code></td><td><a href="%3$s">%4$s</a></td><td>%5$d</td><td>%6$s</td><td><span class="rip-badge %7$s">%8$s</span></td></tr>',
				esc_html( $label ),
				esc_html( $key ),
				esc_url( $feeds_url ),
				esc_html( $feeds_lbl ),
				absint( $rule_count ),
				$synced ? 'v' . absint( $version ) : esc_html__( 'bundled', 'reportedip-hive' ),
				esc_attr( $badge ),
				esc_html( $source )
			);
		}
		echo '</tbody></table>';

		echo '<p class="rip-help-text">' . esc_html__( 'Sync:', 'reportedip-hive' ) . ' ' . ( $enabled ? esc_html__( 'enabled', 'reportedip-hive' ) : esc_html__( 'disabled', 'reportedip-hive' ) ) . ' &middot; ' . esc_html__( 'Last sync:', 'reportedip-hive' ) . ' ' . ( $last_run ? esc_html( wp_date( 'Y-m-d H:i:s', $last_run ) ) : esc_html__( 'never (baseline only)', 'reportedip-hive' ) ) . '</p>';

		if ( ! $has_priority ) {
			echo '<p class="rip-help-text">' . esc_html__( 'The bundled baseline rulesets stay active and free on every plan. Priority Sync — deeper coverage and frequent updates — is part of the Professional plan.', 'reportedip-hive' ) . ' ';
			ReportedIP_Hive_Admin_Settings::render_tier_lock( $priority, array( 'label' => __( 'Unlock with Professional', 'reportedip-hive' ) ) );
			echo '</p>';
		} else {
			echo '<button type="button" class="rip-button rip-button--primary" id="rip-rule-sync-now" data-rip-action="reportedip_hive_rule_sync_now">' . esc_html__( 'Sync now', 'reportedip-hive' ) . '</button>';
		}

		echo '</div></div>';
	}

	/**
	 * Render the two-column Free-vs-Professional coverage comparison for the
	 * Rule Sync tab so the plan boundary is explicit: the WAF engine and the
	 * baseline rulesets ship with every plan, Priority Sync is Professional.
	 * Rendered only while Priority Sync is not on the plan.
	 *
	 * @param bool $has_priority Whether the current tier has Priority Sync.
	 * @return void
	 * @since  2.1.2
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

		echo '<div class="rip-card"><div class="rip-card__header rip-card__header--icon"><h3 class="rip-card__title">' . esc_html__( 'Priority Sync', 'reportedip-hive' ) . '</h3>';
		ReportedIP_Hive_Admin_Settings::render_tier_badge( 'professional' );
		echo '</div><div class="rip-card__body"><ul class="rip-pricing-card__features">';
		foreach ( $pro_features as $feature ) {
			echo '<li>' . esc_html( $feature ) . '</li>';
		}
		echo '</ul><p class="rip-help-text">';
		if ( $has_priority ) {
			echo '<span class="rip-badge rip-badge--success">' . esc_html__( 'Active on your plan', 'reportedip-hive' ) . '</span>';
		} else {
			ReportedIP_Hive_Admin_Settings::render_tier_lock(
				ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'rule_sync_priority' ),
				array( 'label' => __( 'Unlock with Professional', 'reportedip-hive' ) )
			);
		}
		echo '</p></div></div>';

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

		self::render_tab_intro( __( 'Hardening response headers tell the browser to refuse risky behaviour — MIME sniffing, framing by foreign sites, leaking referrers, downgrade to HTTP. Hive sends them via PHP on every front-end response; an optional server-level export for static files lives on the Server Setup tab.', 'reportedip-hive' ) );

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
		echo '<p class="rip-help-text">';
		printf(
			/* translators: 1: opening link tag to the Server Setup tab, 2: closing tag. */
			esc_html__( 'Running nginx? The %1$sServer Setup tab%2$s generates matching add_header lines from this configuration so static files are covered too.', 'reportedip-hive' ),
			'<a href="' . esc_url( self::tab_url( 'server' ) ) . '">',
			'</a>'
		);
		echo '</p>';
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

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Advanced Headers', 'reportedip-hive' ) . '</h2>';
		ReportedIP_Hive_Admin_Settings::render_tier_marker( $adv_status );
		echo '</div><div class="rip-card__body">';
		if ( ! $adv_ok ) {
			echo '<p class="rip-help-text">' . esc_html__( 'HSTS, Permissions-Policy, the CSP builder and the Cross-Origin headers unlock with Professional. The basic headers above stay free.', 'reportedip-hive' ) . '</p>';
			echo '</div></div>';
			self::render_headers_save_button();
			$this->render_attack_surface_section();
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

		self::render_headers_save_button();
		$this->render_attack_surface_section();
	}

	/**
	 * Render the attack-surface section below the security headers: REST
	 * access control, the endpoint switches and the PHP-execution block for
	 * the uploads directory.
	 *
	 * Saved through the Settings API (not the headers' AJAX bulk save), so the
	 * inputs carry `name` attributes and deliberately no `data-opt` — the
	 * Firewall script would otherwise post them a second time.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	private function render_attack_surface_section() {
		if ( ! class_exists( 'ReportedIP_Hive_Attack_Surface' ) ) {
			return;
		}

		$as       = 'ReportedIP_Hive_Attack_Surface';
		$mode     = $as::rest_mode();
		$xmlrpc   = $as::switch_on( $as::OPT_XMLRPC_OFF );
		$feeds    = $as::switch_on( $as::OPT_FEEDS_OFF );
		$guests   = $as::switch_on( $as::OPT_ADMIN_GUESTS );
		$uploads  = $as::switch_on( $as::OPT_UPLOADS_PHP );
		$software = $as::switch_on( $as::OPT_HIDE_SOFTWARE );
		$hide_on  = class_exists( 'ReportedIP_Hive_Hide_Login' ) && ReportedIP_Hive_Hide_Login::get_instance()->is_active();
		$closed   = (int) $xmlrpc + (int) $feeds + (int) ( $guests || $hide_on ) + (int) $software;
		$mode_lbl = array(
			'open'       => __( 'Open', 'reportedip-hive' ),
			'logged_in'  => __( 'Logged-in only', 'reportedip-hive' ),
			'restricted' => __( 'Restricted to roles', 'reportedip-hive' ),
		);

		printf(
			'<form method="post" action="%s" class="rip-form" id="rip-attack-surface-form">',
			esc_url( ReportedIP_Hive_Admin_Settings::settings_form_action() )
		);
		settings_fields( 'reportedip_hive_attack_surface' );
		echo '<input type="hidden" name="reportedip_hive_disable_xmlrpc" value="0" />';
		echo '<input type="hidden" name="reportedip_hive_disable_xmlrpc_multicall" value="0" />';
		echo '<input type="hidden" name="reportedip_hive_disable_feeds" value="0" />';
		echo '<input type="hidden" name="reportedip_hive_block_admin_guests" value="0" />';
		echo '<input type="hidden" name="reportedip_hive_block_uploads_php" value="0" />';
		echo '<input type="hidden" name="reportedip_hive_hide_software_info" value="0" />';

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Attack surface', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Every WordPress endpoint you do not use is an endpoint someone else can probe. These switches close the ones most sites never need. They are free, and all of them are off until you turn them on.', 'reportedip-hive' ) . '</p>';
		echo '<div class="rip-grid rip-grid-cols-3">';
		self::render_stat_card(
			array(
				/* translators: 1: number of closed endpoints, 2: number of available switches */
				'value' => sprintf( __( '%1$d of %2$d', 'reportedip-hive' ), $closed, 4 ),
				'badge' => $closed > 0 ? 'rip-badge--success' : 'rip-badge--neutral',
				'label' => __( 'Endpoints closed', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => isset( $mode_lbl[ $mode ] ) ? $mode_lbl[ $mode ] : $mode,
				'badge' => 'open' === $mode ? 'rip-badge--neutral' : 'rip-badge--success',
				'label' => __( 'REST API', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => $uploads ? __( 'On', 'reportedip-hive' ) : __( 'Off', 'reportedip-hive' ),
				'badge' => $uploads ? 'rip-badge--success' : 'rip-badge--neutral',
				'label' => __( 'PHP in uploads', 'reportedip-hive' ),
			)
		);
		echo '</div></div></div>';

		$this->render_rest_access_card( $mode );
		$this->render_endpoints_card( $xmlrpc, $feeds, $guests, $software, $hide_on );
		$this->render_uploads_php_card( $uploads );

		printf(
			'<p><button type="submit" class="rip-button rip-button--primary">%s</button></p>',
			esc_html__( 'Save attack surface', 'reportedip-hive' )
		);
		echo '</form>';
		?>
		<script>
		(function () {
			var select = document.getElementById('rip-rest-access-mode');
			var deps   = document.getElementById('rip-rest-dependent');
			if (!select || !deps) { return; }
			select.addEventListener('change', function () {
				deps.classList.toggle('rip-is-disabled', select.value === 'open');
			});
		})();
		</script>
		<?php
	}

	/**
	 * REST access-control card: mode, namespace allowlist and role allowlist.
	 *
	 * @param string $mode Current REST access mode.
	 * @return void
	 * @since  2.1.51
	 */
	private function render_rest_access_card( $mode ) {
		$as         = 'ReportedIP_Hive_Attack_Surface';
		$namespaces = (string) ReportedIP_Hive_Option_Routing::get( $as::OPT_REST_NAMESPACES, ReportedIP_Hive_Defaults::all_option_defaults()[ $as::OPT_REST_NAMESPACES ] );
		$roles      = $as::allowed_roles();

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'REST API access', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'The REST API answers anonymous requests by default. Closing it stops content and metadata scraping, but the block editor, many page builders and every headless frontend depend on it — change this only if you know which of your plugins call it.', 'reportedip-hive' ) . '</p>';

		printf(
			'<div class="rip-form-row"><label class="rip-form-label" for="rip-rest-access-mode">%1$s</label><select id="rip-rest-access-mode" class="rip-select" name="%2$s">',
			esc_html__( 'Who may use the REST API', 'reportedip-hive' ),
			esc_attr( $as::OPT_REST_MODE )
		);
		foreach ( array(
			'open'       => __( 'Everyone (WordPress default)', 'reportedip-hive' ),
			'logged_in'  => __( 'Logged-in users only', 'reportedip-hive' ),
			'restricted' => __( 'Selected roles only', 'reportedip-hive' ),
		) as $value => $label ) {
			printf( '<option value="%1$s"%2$s>%3$s</option>', esc_attr( $value ), selected( $mode, $value, false ), esc_html( $label ) );
		}
		echo '</select></div>';

		printf( '<div id="rip-rest-dependent"%s>', 'open' === $mode ? ' class="rip-is-disabled"' : '' );

		echo '<div class="rip-alert rip-alert--warning">' . esc_html__( 'In "Selected roles only" mode every role that edits content still needs the REST API for the block editor. Administrators and super admins always keep access, and so does each user on their own application-password page.', 'reportedip-hive' ) . '</div>';
		echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'A logged-in request without a REST nonce counts as anonymous — that is WordPress own rule, not a bug. Pasting a /wp-json/ URL into the browser therefore answers 401 even while you are signed in. Plugins that sign their REST calls without a WordPress cookie (Jetpack, mobile apps, marketing tools) are anonymous for the same reason: keep their namespace on the allowlist below.', 'reportedip-hive' ) . '</div>';

		printf(
			'<div class="rip-form-row"><label class="rip-form-label" for="rip-rest-namespaces">%1$s</label><textarea id="rip-rest-namespaces" class="rip-textarea" rows="6" name="%2$s">%3$s</textarea></div>',
			esc_html__( 'Namespaces that always stay open', 'reportedip-hive' ),
			esc_attr( $as::OPT_REST_NAMESPACES ),
			esc_textarea( $namespaces )
		);
		echo '<p class="rip-help-text">' . esc_html__( 'One namespace or route prefix per line, for example oembed/1.0 or wc/store. The plugin namespace reportedip-hive/v1 is always allowed.', 'reportedip-hive' ) . '</p>';

		echo '<div class="rip-form-group"><label class="rip-label">' . esc_html__( 'Roles allowed in "Selected roles only" mode', 'reportedip-hive' ) . '</label>';
		foreach ( wp_roles()->get_names() as $role_slug => $role_name ) {
			$is_admin_role = 'administrator' === $role_slug;
			printf(
				'<label class="rip-toggle"><input type="checkbox" class="rip-toggle__input" name="%1$s[]" value="%2$s"%3$s%4$s /><span class="rip-toggle__slider"></span><span class="rip-toggle__label">%5$s</span></label>',
				esc_attr( $as::OPT_REST_ROLES ),
				esc_attr( $role_slug ),
				checked( $is_admin_role || in_array( $role_slug, $roles, true ), true, false ),
				disabled( $is_admin_role, true, false ),
				esc_html( translate_user_role( $role_name ) )
			);
		}
		printf( '<input type="hidden" name="%s[]" value="administrator" />', esc_attr( $as::OPT_REST_ROLES ) );
		echo '<p class="rip-help-text">' . esc_html__( 'Administrators cannot be removed — locking yourself out of your own REST API is not a setting.', 'reportedip-hive' ) . '</p>';
		echo '</div>';

		echo '</div></div></div>';
	}

	/**
	 * Endpoint switches: XML-RPC, feeds, wp-admin for visitors and the
	 * software fingerprints.
	 *
	 * @param bool $xmlrpc   XML-RPC switched off.
	 * @param bool $feeds    Feeds switched off.
	 * @param bool $guests   wp-admin closed for visitors.
	 * @param bool $software Fingerprints hidden.
	 * @param bool $hide_on  Hide Login is active.
	 * @return void
	 * @since  2.1.51
	 */
	private function render_endpoints_card( $xmlrpc, $feeds, $guests, $software, $hide_on ) {
		$as   = 'ReportedIP_Hive_Attack_Surface';
		$mode = ReportedIP_Hive_Hide_Login::response_mode();

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Endpoints', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';

		self::render_switch_row(
			$as::OPT_XMLRPC_OFF,
			__( 'Disable XML-RPC', 'reportedip-hive' ),
			__( 'Answers xmlrpc.php with the configured block response and removes the pingback methods, the X-Pingback header and the RSD discovery tags. The WordPress mobile apps, Jetpack and remote-publishing tools stop working — check before you switch it on.', 'reportedip-hive' ),
			$xmlrpc,
			false
		);

		self::render_switch_row(
			'reportedip_hive_disable_xmlrpc_multicall',
			__( 'Disable XML-RPC multicall only', 'reportedip-hive' ),
			__( 'The middle ground when you still need XML-RPC. Multicall lets an attacker pack hundreds of password guesses into one request; removing it leaves the rest of the interface working. Redundant while the full switch above is on.', 'reportedip-hive' ),
			(bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_disable_xmlrpc_multicall', true ),
			false
		);

		self::render_switch_row(
			$as::OPT_FEEDS_OFF,
			__( 'Disable RSS and Atom feeds', 'reportedip-hive' ),
			__( 'Answers every feed URL with a 404 and removes the feed links from the page head. Comment and podcast feeds are covered too, so a podcast directory or newsletter that pulls your feed stops receiving posts.', 'reportedip-hive' ),
			$feeds,
			false
		);

		self::render_switch_row(
			$as::OPT_ADMIN_GUESTS,
			__( 'Close wp-admin for visitors', 'reportedip-hive' ),
			$hide_on
				? __( 'Always on while Hide Login is active — a visible wp-admin would redirect straight to the login URL you just hid.', 'reportedip-hive' )
				: sprintf(
					/* translators: %s: currently configured response, for example "Block page" */
					__( 'Logged-out requests to wp-admin are refused instead of redirected to the login form. Answers with the response configured on Settings, Hide Login (currently: %s). admin-ajax.php and admin-post.php stay reachable so front-end forms keep working.', 'reportedip-hive' ),
					ReportedIP_Hive_Hide_Login::RESPONSE_MODE_404 === $mode ? __( 'Soft 404', 'reportedip-hive' ) : __( 'Block page', 'reportedip-hive' )
				),
			$hide_on || $guests,
			$hide_on
		);

		self::render_switch_row(
			$as::OPT_HIDE_SOFTWARE,
			__( 'Hide software fingerprints', 'reportedip-hive' ),
			__( 'Removes the WordPress generator tag from pages and feeds and switches PHP error display off. Errors raised before the plugin loads, and a wp-config.php that enables WP_DEBUG_DISPLAY, stay as they are — those are out of reach from here.', 'reportedip-hive' ),
			$software,
			false
		);

		echo '</div></div>';
	}

	/**
	 * Render one labelled toggle row of the endpoint card.
	 *
	 * @param string $option    Option key used as the field name.
	 * @param string $label     Toggle label.
	 * @param string $help      Help text below the toggle.
	 * @param bool   $checked   Whether the toggle is on.
	 * @param bool   $locked_on Render checked and disabled, with a hidden "1".
	 * @return void
	 * @since  2.1.51
	 */
	private static function render_switch_row( $option, $label, $help, $checked, $locked_on ) {
		echo '<div class="rip-form-group">';
		if ( $locked_on ) {
			printf( '<input type="hidden" name="%s" value="1" />', esc_attr( $option ) );
		}
		printf(
			'<label class="rip-toggle"><input type="checkbox" class="rip-toggle__input" name="%1$s" value="1"%2$s%3$s /><span class="rip-toggle__slider"></span><span class="rip-toggle__label">%4$s</span></label>',
			esc_attr( $option ),
			checked( $checked, true, false ),
			disabled( $locked_on, true, false ),
			esc_html( $label )
		);
		echo '<p class="rip-help-text">' . esc_html( $help ) . '</p>';
		echo '</div>';
	}

	/**
	 * PHP-execution block for the uploads directory: toggle, live status and
	 * the copy-paste snippets for stacks Hive cannot manage itself.
	 *
	 * @param bool $enabled Whether the switch is on.
	 * @return void
	 * @since  2.1.51
	 */
	private function render_uploads_php_card( $enabled ) {
		$as       = 'ReportedIP_Hive_Attack_Surface';
		$writer   = class_exists( 'ReportedIP_Hive_Uploads_Htaccess_Writer' )
			? ReportedIP_Hive_Uploads_Htaccess_Writer::get_instance()
			: null;
		$writable = $writer && $writer->is_writable_target();
		$present  = $writer && $writer->is_block_present();
		$status   = self::htaccess_block_status( $enabled, $present, $writable );
		$htaccess = $status['htaccess'];

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'PHP execution in uploads', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'The uploads directory holds media, never code. Refusing requests for PHP and other executable file types there turns a successful file-upload exploit into a dead file on disk. Hive writes the rule into the uploads .htaccess on Apache and LiteSpeed; on nginx you paste the matching snippet once.', 'reportedip-hive' ) . '</p>';

		self::render_switch_row(
			$as::OPT_UPLOADS_PHP,
			__( 'Block PHP execution in the uploads directory', 'reportedip-hive' ),
			__( 'A handful of plugins really do ship PHP inside uploads, mostly caching and gallery tools. If something breaks right after you switch this on, that is where to look first.', 'reportedip-hive' ),
			$enabled,
			false
		);

		echo '<div class="rip-grid rip-grid-cols-3">';
		self::render_stat_card(
			array(
				'value' => $status['label'],
				'badge' => $status['badge'],
				'label' => __( 'Uploads .htaccess block', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => $status['server_label'],
				'label' => __( 'Detected server', 'reportedip-hive' ),
			)
		);
		self::render_stat_card(
			array(
				'value' => ReportedIP_Hive_Uploads_Htaccess_Writer::uploads_url_path(),
				'label' => __( 'Covered path', 'reportedip-hive' ),
			)
		);
		echo '</div>';

		if ( ! $enabled ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'The switch is off — nothing is written to the uploads directory and executable files there are served as usual.', 'reportedip-hive' ) . '</div>';
		} elseif ( ! $htaccess ) {
			echo '<div class="rip-alert rip-alert--warning">' . esc_html__( 'This web server does not read .htaccess, so the block cannot be auto-managed. Paste the nginx snippet below into your server block once.', 'reportedip-hive' ) . '</div>';
		} elseif ( $present ) {
			echo '<div class="rip-alert rip-alert--success">' . esc_html__( 'Auto-managed — Hive wrote the block into the uploads .htaccess.', 'reportedip-hive' ) . '</div>';
		} elseif ( $writable ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'The uploads .htaccess is writable but the block is not in place yet. Save this page once to trigger a sync.', 'reportedip-hive' ) . '</div>';
		} else {
			echo '<div class="rip-alert rip-alert--warning">' . esc_html__( 'The uploads .htaccess is not writable, so the block cannot be auto-managed. Add the Apache snippet below by hand.', 'reportedip-hive' ) . '</div>';
		}

		if ( is_multisite() && get_site_option( 'ms_files_rewriting' ) ) {
			echo '<div class="rip-alert rip-alert--warning">' . esc_html__( 'This network still uses the legacy blogs.dir upload layout. The single main-site file does not cover those directories — add the snippet there by hand.', 'reportedip-hive' ) . '</div>';
		}

		if ( ! $htaccess || ! $writable ) {
			self::render_snippet(
				'rip-uploads-snip-apache',
				__( 'Apache (.htaccess in the uploads directory)', 'reportedip-hive' ),
				ReportedIP_Hive_Uploads_Htaccess_Writer::htaccess_snippet()
			);
			self::render_snippet(
				'rip-uploads-snip-nginx',
				__( 'nginx (server block)', 'reportedip-hive' ),
				ReportedIP_Hive_Uploads_Htaccess_Writer::nginx_snippet(),
				__( 'Place this above your PHP location block — nginx picks the first matching regex location, so the order decides.', 'reportedip-hive' )
			);
		}

		echo '</div></div>';
	}

	/**
	 * Render the security-headers save button. Extracted so both return paths
	 * of the Hardening tab (advanced headers locked or unlocked) end with the
	 * same button and the attack-surface section below it.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	private static function render_headers_save_button() {
		printf(
			'<p><button type="button" class="rip-button rip-button--primary" id="rip-headers-save">%s</button> <span id="rip-headers-saved" class="rip-help-text"></span></p>',
			esc_html__( 'Save headers', 'reportedip-hive' )
		);
	}
}
