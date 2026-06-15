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
	 * Event types the firewall surfaces own (overview feed + counters).
	 *
	 * @var string[]
	 */
	const FIREWALL_EVENT_TYPES = array(
		'waf_block',
		'waf_would_block',
		'fake_bot',
		'fake_bot_blocked',
		'decoy_pathblock_hit',
		'scan_404',
		'disposable_email',
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
		echo '</select></div>';
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
	 * Display metadata for the four server-delivered ruleset keys.
	 *
	 * @return array<string,array{label:string,feeds:string,tab:string}>
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
				'feeds' => __( 'Spam Defence', 'reportedip-hive' ),
				'tab'   => 'spam',
			),
			'scan_paths'         => array(
				'label' => __( 'Scanner probe paths', 'reportedip-hive' ),
				'feeds' => __( 'Scan Detection', 'reportedip-hive' ),
				'tab'   => 'scan',
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
			'waf_block'                => __( 'WAF blocked a request', 'reportedip-hive' ),
			'waf_would_block'          => __( 'WAF match (report-only)', 'reportedip-hive' ),
			'fake_bot'                 => __( 'Spoofed crawler flagged', 'reportedip-hive' ),
			'fake_bot_blocked'         => __( 'Spoofed crawler blocked', 'reportedip-hive' ),
			'decoy_pathblock_hit'      => __( 'Decoy path hit', 'reportedip-hive' ),
			'scan_404'                 => __( 'Scan detected', 'reportedip-hive' ),
			'disposable_email'         => __( 'Disposable e-mail address detected', 'reportedip-hive' ),
			'rule_sync_signature_fail' => __( 'Ruleset signature rejected', 'reportedip-hive' ),
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
			'spam'      => __( 'Spam Defence', 'reportedip-hive' ),
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

		$disp_action = class_exists( 'ReportedIP_Hive_Disposable_Email' )
			? ReportedIP_Hive_Disposable_Email::get_instance()->action()
			: 'off';
		$honeypot    = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_honeypot_enabled', true );
		$spam_active = ( 'off' !== $disp_action ) || $honeypot;
		$rows[]      = array(
			'label'  => __( 'Spam Defence', 'reportedip-hive' ),
			'status' => $spam_active ? __( 'Active', 'reportedip-hive' ) : __( 'Off', 'reportedip-hive' ),
			'badge'  => $spam_active ? 'rip-badge--success' : 'rip-badge--neutral',
			'detail' => sprintf(
				/* translators: 1: disposable-email mode, 2: honeypot state. */
				__( 'Disposable e-mail: %1$s · Comment honeypot: %2$s', 'reportedip-hive' ),
				ucfirst( $disp_action ),
				$honeypot ? __( 'on', 'reportedip-hive' ) : __( 'off', 'reportedip-hive' )
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
						__( '%1$d of %2$d rulesets delivered by the reportedip.de Rule API.', 'reportedip-hive' ),
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
				'value' => (string) ( $counts['decoy_pathblock_hit'] + $counts['scan_404'] ),
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

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'WAF Exceptions', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Relieve a false positive without editing code. Scope an exception to a single rule (optionally on one path), a rule group, or — for a first-party endpoint that legitimately receives attack-like payloads — the whole engine on a path. A whole-engine exception must always carry a path or IP.', 'reportedip-hive' ) . '</p>';

		echo '<form id="add-waf-exception-form" class="rip-form">';
		echo '<div class="rip-form-row"><label class="rip-form-label" for="rip-waf-ex-scope">' . esc_html__( 'Scope', 'reportedip-hive' ) . '</label>';
		echo '<select id="rip-waf-ex-scope" name="scope" class="rip-select">';
		echo '<option value="rule">' . esc_html__( 'Single rule', 'reportedip-hive' ) . '</option>';
		echo '<option value="group">' . esc_html__( 'Rule group', 'reportedip-hive' ) . '</option>';
		echo '<option value="all">' . esc_html__( 'Whole engine (path/IP required)', 'reportedip-hive' ) . '</option>';
		echo '</select></div>';

		echo '<div class="rip-form-row"><label class="rip-form-label" for="rip-waf-ex-rule">' . esc_html__( 'Rule ID or group', 'reportedip-hive' ) . '</label>';
		echo '<input type="text" id="rip-waf-ex-rule" name="rule_id" class="rip-input" placeholder="waf_sqli_union" /></div>';

		echo '<div class="rip-form-row"><label class="rip-form-label" for="rip-waf-ex-path">' . esc_html__( 'Path prefix (optional)', 'reportedip-hive' ) . '</label>';
		echo '<input type="text" id="rip-waf-ex-path" name="path_prefix" class="rip-input" placeholder="/wp-json/my-api/v1" /></div>';

		echo '<div class="rip-form-row"><label class="rip-form-label" for="rip-waf-ex-ip">' . esc_html__( 'IP or CIDR (optional)', 'reportedip-hive' ) . '</label>';
		echo '<input type="text" id="rip-waf-ex-ip" name="ip_address" class="rip-input" placeholder="203.0.113.7" /></div>';

		echo '<div class="rip-form-row"><label class="rip-form-label" for="rip-waf-ex-reason">' . esc_html__( 'Reason (optional)', 'reportedip-hive' ) . '</label>';
		echo '<input type="text" id="rip-waf-ex-reason" name="reason" class="rip-input" /></div>';

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

		echo '</div></div>';
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

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Extended Protection (pre-WordPress)', 'reportedip-hive' ) . '</h2></div><div class="rip-card__body">';
		echo '<p class="rip-help-text">' . esc_html__( 'Optionally run the firewall before WordPress loads, so a malicious request is rejected earlier and cheaper. Off by default. On Apache and PHP-FPM the configuration is written automatically; on nginx or via php.ini one manual step is needed (see Server Setup).', 'reportedip-hive' ) . '</p>';

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
		echo '</div>';

		if ( $enabled && $running ) {
			echo '<div class="rip-alert rip-alert--success">' . esc_html__( 'Setup complete — the guard executed for this very request, so every request to this site passes the firewall before WordPress loads.', 'reportedip-hive' ) . '</div>';
		} elseif ( $enabled && $auto ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'The directive was written automatically. PHP-FPM caches .user.ini for up to five minutes — reload this page shortly; the status flips to Running as soon as the guard executes.', 'reportedip-hive' ) . '</div>';
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
			? esc_html__( 'The crawler list is delivered and signed by the reportedip.de Rule API.', 'reportedip-hive' ) . ' (v' . absint( $bot_ver ) . ')'
			: esc_html__( 'The bundled baseline crawler list is active. Connect the Community Network for the server-delivered list.', 'reportedip-hive' ) ) . '</p>';

		$actions = array(
			'off'   => __( 'Off — do not verify', 'reportedip-hive' ),
			'flag'  => __( 'Flag — log spoofers only (recommended)', 'reportedip-hive' ),
			'block' => __( 'Block — reject confirmed spoofers', 'reportedip-hive' ),
		);
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
		self::render_tab_intro( __( 'Stops registration and comment spam at its two favourite doors: throwaway e-mail addresses are detected at signup (WordPress and WooCommerce), and an invisible honeypot field rejects comment bots — no CAPTCHA, no friction for real visitors.', 'reportedip-hive' ) );

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
			'<p><button type="button" class="rip-button rip-button--secondary" data-rip-action="reportedip_hive_spam_toggle" data-rip-field="honeypot">%s</button></p>',
			esc_html( $honeypot ? __( 'Disable honeypot', 'reportedip-hive' ) : __( 'Enable honeypot', 'reportedip-hive' ) )
		);
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
			echo '<div class="rip-alert rip-alert--warning">';
			printf(
				/* translators: 1: opening link tag to the Server Setup tab, 2: closing tag. */
				esc_html__( 'This server is not auto-managed (nginx, or a read-only .htaccess). The PHP sensor still catches every bait-path hit; the optional web-server rule on the %1$sServer Setup tab%2$s blocks them one layer earlier.', 'reportedip-hive' ),
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

		if ( $auto ) {
			if ( ! $running ) {
				echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'This server is auto-managed: Hive wrote the directive itself (.htaccess on Apache, .user.ini on PHP-FPM). PHP-FPM caches .user.ini for up to five minutes — the status flips to Running on its own.', 'reportedip-hive' ) . '</div>';
			} else {
				echo '<p class="rip-help-text">' . esc_html__( 'This server is auto-managed — Hive wrote and maintains the directive itself (.htaccess on Apache, .user.ini on PHP-FPM).', 'reportedip-hive' ) . '</p>';
			}
			echo '</div></div>';
			return;
		}

		if ( ! $running ) {
			echo '<div class="rip-alert rip-alert--warning">' . esc_html__( 'One manual step: add the directive below. Pick exactly ONE of the two options — whichever your hosting lets you edit. The status above flips to Running automatically once the directive is live.', 'reportedip-hive' ) . '</div>';
		}

		self::render_snippet(
			'rip-waf-snip-phpini',
			__( 'Option A — php.ini / hosting panel (recommended)', 'reportedip-hive' ),
			$dropin->php_ini_snippet(),
			__( 'Most managed hosts (ISPConfig, Plesk, cPanel) offer a "custom php.ini settings" field — paste this single line there and reload PHP-FPM. This is usually the easiest route.', 'reportedip-hive' )
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
		$decoy_on  = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_decoy_pathblock_enabled', true );
		$server    = class_exists( 'ReportedIP_Hive_WAF_Dropin_Manager' )
			? ReportedIP_Hive_WAF_Dropin_Manager::get_instance()->detect_server()
			: 'unknown';
		$is_apache = ( 'apache' === $server || 'fpm' === $server );

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
		} elseif ( $is_apache ) {
			echo '<div class="rip-alert rip-alert--success">' . esc_html__( 'On Apache this block is auto-managed in .htaccess — the snippet below shows verbatim what Hive wrote (or would write). No manual step needed.', 'reportedip-hive' ) . '</div>';
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
		self::render_tab_intro( __( 'The detection rules behind the WAF, Bot Verification, Spam Defence and Scan Detection are not hard-coded: they are versioned rulesets, maintained on reportedip.de, signed with Ed25519 and delivered through the Rule API. A bundled baseline ships with the plugin, so every install is protected even fully offline.', 'reportedip-hive' ) );

		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$sync         = ReportedIP_Hive_Rule_Sync::get_instance();
		$priority     = $mode_manager->feature_status( 'rule_sync_priority' );
		$last_run     = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_rule_sync_last_run', 0 );
		$enabled      = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_rule_sync_enabled', true );
		$has_priority = ! empty( $priority['available'] );

		if ( ! $has_priority ) {
			$this->render_rule_sync_tiers( false );
		}

		echo '<div class="rip-card"><div class="rip-card__header"><h2>' . esc_html__( 'Active rulesets', 'reportedip-hive' ) . '</h2>';
		ReportedIP_Hive_Admin_Settings::render_tier_marker( $priority );
		echo '</div><div class="rip-card__body">';

		if ( $has_priority ) {
			echo '<div class="rip-alert rip-alert--success">' . esc_html__( 'Priority Sync is active on your plan — the rulesets below refresh automatically from the reportedip.de Rule API, signed and verified on every download.', 'reportedip-hive' ) . '</div>';
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
				? __( 'reportedip.de Rule API', 'reportedip-hive' )
				: __( 'Bundled baseline', 'reportedip-hive' );
			$label      = isset( $meta[ $key ] ) ? $meta[ $key ]['label'] : $key;
			$feeds_lbl  = isset( $meta[ $key ] ) ? $meta[ $key ]['feeds'] : '';
			$feeds_tab  = isset( $meta[ $key ] ) ? $meta[ $key ]['tab'] : 'overview';
			printf(
				'<tr><td><strong>%1$s</strong><br /><code>%2$s</code></td><td><a href="%3$s">%4$s</a></td><td>%5$d</td><td>%6$s</td><td><span class="rip-badge %7$s">%8$s</span></td></tr>',
				esc_html( $label ),
				esc_html( $key ),
				esc_url( self::tab_url( $feeds_tab ) ),
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
			printf(
				'<p><button type="button" class="rip-button rip-button--primary" id="rip-headers-save">%s</button> <span id="rip-headers-saved" class="rip-help-text"></span></p>',
				esc_html__( 'Save headers', 'reportedip-hive' )
			);
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
	}
}
