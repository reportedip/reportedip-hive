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
	 * Where a former firewall tab lives now (protection anchor or tools tab).
	 *
	 * @param string $slug Former tab slug.
	 * @return string
	 */
	private static function tab_url( $slug ) {
		return ReportedIP_Hive_Admin_Settings::get_admin_page_url( ReportedIP_Hive_Admin_Aliases::resolve( 'reportedip-hive-firewall', $slug ) );
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
				'url'   => ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-protection#blocking' ),
			),
		);
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
	public function render_waf_exceptions_box() {
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
		printf( '<input type="hidden" name="page" value="%s" />', esc_attr( ReportedIP_Hive_Tools_Page::PAGE_SLUG ) );
		printf( '<input type="hidden" name="tab" value="%s" />', esc_attr( 'rules' ) );
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
	public function render_waf_dropin_box() {
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
	 * Render the Server Setup tab: every web-server-level rule the plugin can
	 * use, in one place — the WAF drop-in directive (auto or manual), the decoy
	 * rewrite rules and an optional server-level export of the security
	 * headers. All sections are optional; the PHP sensors work without them.
	 *
	 * @since 2.1.3
	 * @return void
	 */
	public function render_server_tab() {
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
	public function render_rule_sync_tab() {
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
}
