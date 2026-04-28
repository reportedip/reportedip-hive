<?php
/**
 * Frontend shortcodes that render community-trust banners and stat cards on
 * public-facing pages, each linking back to reportedip.de.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.3.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Public shortcodes and auto-footer banner renderer.
 *
 * Renders four `<rip-hive-banner>` custom-element variants (badge, stat,
 * banner, shield) into the page. Each banner includes a Light-DOM `<a href>`
 * fallback so search engines and no-JavaScript clients still see the
 * backlink to reportedip.de — the Web Component only enhances the visual
 * presentation inside a Shadow Root.
 *
 * @since 1.3.0
 */
class ReportedIP_Hive_Frontend_Shortcodes {

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Transient key used to cache the aggregated public stats. Suffix bumps
	 * any time the cached array shape changes, so older versions of the
	 * plugin do not feed stale arrays into the new resolver.
	 */
	const STATS_TRANSIENT_KEY = 'reportedip_hive_public_stats_v2';

	/**
	 * Required keys in a valid cached stats array. A cache hit missing any
	 * of these is treated as a miss and the data is re-aggregated.
	 *
	 * @var string[]
	 */
	private static $required_stat_keys = array(
		'attacks_30d',
		'attacks_total',
		'blocked_active',
		'whitelist_active',
		'logins_30d',
		'spam_30d',
		'api_reports_30d',
		'reports_total',
	);

	/**
	 * Cache TTL for the stats transient (6 hours).
	 */
	const STATS_TTL = 21600;

	/**
	 * Default stat key when none is supplied.
	 */
	const DEFAULT_STAT = 'attacks_total';

	/**
	 * Default tone preset when none is supplied.
	 */
	const DEFAULT_TONE = 'protect';

	/**
	 * Regex: 3- or 6-hex-digit colour with leading `#`.
	 */
	const HEX_COLOR_REGEX = '/^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i';

	/**
	 * Regex: single hex colour OR two comma-separated hex colours (gradient stops).
	 */
	const BG_REGEX = '/^#(?:[0-9a-f]{3}|[0-9a-f]{6})(?:,#(?:[0-9a-f]{3}|[0-9a-f]{6}))?$/i';

	/**
	 * Maximum length for free-text label/intro overrides.
	 */
	const TEXT_OVERRIDE_MAX_LEN = 80;

	/**
	 * All supported banner variants.
	 *
	 * @var string[]
	 */
	const VARIANTS = array( 'badge', 'stat', 'banner', 'shield' );

	/**
	 * Variants offered for the auto-footer (subset that fits in a footer).
	 *
	 * @var string[]
	 */
	const FOOTER_VARIANTS = array( 'badge', 'shield' );

	/**
	 * Stat keys accepted via `[…type="…"]`.
	 *
	 * @var string[]
	 */
	const STAT_KEYS = array(
		'attacks_30d',
		'attacks_total',
		'blocked_active',
		'whitelist_active',
		'logins_30d',
		'spam_30d',
		'api_reports_30d',
		'reports_total',
	);

	/**
	 * Marketing-tone presets.
	 *
	 * @var string[]
	 */
	const TONES = array( 'protect', 'trust', 'community', 'contributor' );

	/**
	 * Per-request memoised stats array (avoids repeated transient reads when
	 * the admin Promote tab renders multiple previews on a single page load).
	 *
	 * @var array|null
	 */
	private $stats_memo = null;

	/**
	 * Map of shortcode tag → variant + UTM medium + default tone. Drives the
	 * single `render_shortcode()` handler so all four shortcodes share one
	 * code path.
	 *
	 * @var array<string, array{variant:string, medium:string, tone:string}>
	 */
	private static $tag_map = array(
		'reportedip_badge'  => array(
			'variant' => 'badge',
			'medium'  => 'banner',
			'tone'    => 'protect',
		),
		'reportedip_stat'   => array(
			'variant' => 'stat',
			'medium'  => 'stat',
			'tone'    => 'trust',
		),
		'reportedip_banner' => array(
			'variant' => 'banner',
			'medium'  => 'banner',
			'tone'    => 'community',
		),
		'reportedip_shield' => array(
			'variant' => 'shield',
			'medium'  => 'shield',
			'tone'    => 'protect',
		),
	);

	/**
	 * Get the singleton instance.
	 *
	 * @return self
	 * @since  1.3.0
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor: register shortcodes, asset enqueue, and the auto-footer hook.
	 *
	 * @since 1.3.0
	 */
	private function __construct() {
		foreach ( array_keys( self::$tag_map ) as $tag ) {
			add_shortcode( $tag, array( $this, 'render_shortcode' ) );
		}

		add_action( 'wp_enqueue_scripts', array( $this, 'maybe_enqueue_assets' ) );
		add_action( 'wp_footer', array( $this, 'maybe_render_auto_footer' ), 99 );
		add_action( 'admin_enqueue_scripts', array( $this, 'maybe_enqueue_admin_preview' ) );
	}

	/**
	 * Marketing-tone definitions. Each tone supplies a translated headline
	 * and an optional fixed noun appended to the formatted number; tones that
	 * leave `noun` null fall back to the resolved stat label, which keeps the
	 * default `protect` tone backwards-compatible with v1.3.0.
	 *
	 * @return array<string, array{headline:string, noun:?string}>
	 * @since  1.3.1
	 */
	public static function tone_definitions() {
		return array(
			'protect'     => array(
				'headline' => __( 'Protected by ReportedIP Hive', 'reportedip-hive' ),
				'noun'     => null,
			),
			'trust'       => array(
				'headline' => __( 'Secured by ReportedIP Hive', 'reportedip-hive' ),
				'noun'     => __( 'threats stopped', 'reportedip-hive' ),
			),
			'community'   => array(
				'headline' => __( 'Part of the ReportedIP Hive', 'reportedip-hive' ),
				'noun'     => __( 'IPs reported to the community', 'reportedip-hive' ),
			),
			'contributor' => array(
				'headline' => __( 'ReportedIP Contributor', 'reportedip-hive' ),
				'noun'     => __( 'reports shared with the network', 'reportedip-hive' ),
			),
		);
	}

	/**
	 * Validate a banner variant against the full allowlist.
	 *
	 * @param mixed $value Raw value.
	 * @return string A valid variant; falls back to `badge`.
	 * @since  1.3.0
	 */
	public static function sanitize_variant( $value ) {
		$value = sanitize_key( (string) $value );
		return in_array( $value, self::VARIANTS, true ) ? $value : 'badge';
	}

	/**
	 * Validate a footer-variant choice.
	 *
	 * @param mixed $value Raw value.
	 * @return string A valid footer variant; falls back to `badge`.
	 * @since  1.3.0
	 */
	public static function sanitize_footer_variant( $value ) {
		$value = sanitize_key( (string) $value );
		return in_array( $value, self::FOOTER_VARIANTS, true ) ? $value : 'badge';
	}

	/**
	 * Validate a tone choice.
	 *
	 * @param mixed $value Raw value.
	 * @return string A valid tone; falls back to `protect`.
	 * @since  1.3.1
	 */
	public static function sanitize_tone( $value ) {
		$value = sanitize_key( (string) $value );
		return in_array( $value, self::TONES, true ) ? $value : self::DEFAULT_TONE;
	}

	/**
	 * Enqueue the frontend Web Component on the Community → Promote tab so
	 * admins see live banner previews with their actual stats.
	 *
	 * @param string $hook Current admin page hook suffix.
	 * @since 1.3.0
	 */
	public function maybe_enqueue_admin_preview( $hook ) {
		if ( ! is_string( $hook ) || strpos( $hook, 'reportedip-hive-community' ) === false ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- $_GET['subtab'] only switches which read-only view is rendered.
		$subtab = isset( $_GET['subtab'] ) ? sanitize_key( wp_unslash( $_GET['subtab'] ) ) : 'main';
		if ( 'promote' !== $subtab ) {
			return;
		}
		$this->enqueue_frontend_script();
	}

	/**
	 * Get aggregated public stats with transient caching.
	 *
	 * Sources both 30-day and all-time totals from the daily `stats` table —
	 * `Database::update_daily_stats()` writes there atomically per event via
	 * `INSERT … ON DUPLICATE KEY UPDATE`, the table is never pruned by
	 * `cleanup_old_data()`, and that single source avoids the race conditions
	 * a parallel option-counter write path would introduce.
	 *
	 * @return array{attacks_30d:int, attacks_total:int, blocked_active:int, whitelist_active:int, logins_30d:int, spam_30d:int, api_reports_30d:int, reports_total:int, activated_at:int}
	 * @since  1.3.0
	 */
	public function get_cached_stats() {
		if ( null !== $this->stats_memo ) {
			return $this->stats_memo;
		}

		$cached = get_transient( self::STATS_TRANSIENT_KEY );
		if ( is_array( $cached ) && $this->is_cached_schema_valid( $cached ) ) {
			$this->stats_memo = $cached;
			return $cached;
		}

		$db       = ReportedIP_Hive_Database::get_instance();
		$summary  = $db->get_security_summary( 30 );
		$ip_stats = $db->get_ip_management_stats();
		$lifetime = $db->get_security_summary( 365000 );

		$totals_30d = isset( $summary['summary'] ) && is_object( $summary['summary'] ) ? $summary['summary'] : new stdClass();
		$totals_all = isset( $lifetime['summary'] ) && is_object( $lifetime['summary'] ) ? $lifetime['summary'] : new stdClass();

		$failed_logins_30d     = (int) ( $totals_30d->total_failed_logins ?? 0 );
		$comment_spam_30d      = (int) ( $totals_30d->total_comment_spam ?? 0 );
		$xmlrpc_calls_30d      = (int) ( $totals_30d->total_xmlrpc_calls ?? 0 );
		$reputation_blocks_30d = (int) ( $totals_30d->total_reputation_blocks ?? 0 );
		$api_reports_30d       = (int) ( $totals_30d->total_api_reports ?? 0 );

		$attacks_total = (int) ( ( $totals_all->total_failed_logins ?? 0 )
			+ ( $totals_all->total_comment_spam ?? 0 )
			+ ( $totals_all->total_xmlrpc_calls ?? 0 )
			+ ( $totals_all->total_reputation_blocks ?? 0 ) );

		$stats = array(
			'attacks_30d'      => $failed_logins_30d + $comment_spam_30d + $xmlrpc_calls_30d + $reputation_blocks_30d,
			'attacks_total'    => $attacks_total,
			'blocked_active'   => (int) ( $ip_stats['active_blocked'] ?? 0 ),
			'whitelist_active' => (int) ( $ip_stats['active_whitelist'] ?? 0 ),
			'logins_30d'       => $failed_logins_30d,
			'spam_30d'         => $comment_spam_30d,
			'api_reports_30d'  => $api_reports_30d,
			'reports_total'    => (int) ( $totals_all->total_api_reports ?? 0 ),
			'activated_at'     => (int) get_option( 'reportedip_hive_activated_at', 0 ),
		);

		set_transient( self::STATS_TRANSIENT_KEY, $stats, self::STATS_TTL );
		$this->stats_memo = $stats;
		return $stats;
	}

	/**
	 * Check whether a cached stats array carries the current schema. Older
	 * plugin versions wrote a smaller array shape; without this guard the
	 * resolver would emit "Undefined array key" warnings until the 6 h TTL
	 * expires.
	 *
	 * @param array $cached Decoded transient payload.
	 * @return bool
	 * @since  1.3.1
	 */
	private function is_cached_schema_valid( array $cached ) {
		foreach ( self::$required_stat_keys as $key ) {
			if ( ! array_key_exists( $key, $cached ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Resolve a stat key to a numeric value and a human label.
	 *
	 * @param string $type Stat key.
	 * @return array{value:int, label:string, fallback_text:string}
	 * @since  1.3.0
	 */
	private function resolve_stat( $type ) {
		$stats = $this->get_cached_stats();
		switch ( $type ) {
			case 'attacks_total':
				return array(
					'value'         => (int) $stats['attacks_total'],
					'label'         => __( 'attacks blocked', 'reportedip-hive' ),
					'fallback_text' => __( 'Active threat protection', 'reportedip-hive' ),
				);
			case 'reports_total':
				return array(
					'value'         => (int) $stats['reports_total'],
					'label'         => __( 'IPs reported to the community', 'reportedip-hive' ),
					'fallback_text' => __( 'Active community member', 'reportedip-hive' ),
				);
			case 'blocked_active':
				return array(
					'value'         => (int) $stats['blocked_active'],
					'label'         => __( 'IPs currently blocked', 'reportedip-hive' ),
					'fallback_text' => __( 'Active IP protection', 'reportedip-hive' ),
				);
			case 'whitelist_active':
				return array(
					'value'         => (int) $stats['whitelist_active'],
					'label'         => __( 'Trusted IPs', 'reportedip-hive' ),
					'fallback_text' => __( 'Trust-aware filtering', 'reportedip-hive' ),
				);
			case 'logins_30d':
				return array(
					'value'         => (int) $stats['logins_30d'],
					'label'         => __( 'Failed logins blocked (30 days)', 'reportedip-hive' ),
					'fallback_text' => __( 'Brute-force protection', 'reportedip-hive' ),
				);
			case 'spam_30d':
				return array(
					'value'         => (int) $stats['spam_30d'],
					'label'         => __( 'Spam comments stopped (30 days)', 'reportedip-hive' ),
					'fallback_text' => __( 'Comment spam protection', 'reportedip-hive' ),
				);
			case 'api_reports_30d':
				return array(
					'value'         => (int) $stats['api_reports_30d'],
					'label'         => __( 'reports shared this month', 'reportedip-hive' ),
					'fallback_text' => __( 'Community contributor', 'reportedip-hive' ),
				);
			case 'attacks_30d':
			default:
				return array(
					'value'         => (int) $stats['attacks_30d'],
					'label'         => __( 'attacks blocked (30 days)', 'reportedip-hive' ),
					'fallback_text' => __( 'Active threat protection', 'reportedip-hive' ),
				);
		}
	}

	/**
	 * Build the canonical backlink URL with UTM parameters.
	 *
	 * @param string $medium  UTM medium (banner|footer|stat|shield).
	 * @param string $variant Banner variant for utm_content.
	 * @param string $tone    Tone for utm_term.
	 * @return string Fully escaped URL.
	 * @since  1.3.0
	 */
	private function build_backlink_url( $medium, $variant, $tone ) {
		$base = defined( 'REPORTEDIP_HIVE_SITE_URL' ) ? REPORTEDIP_HIVE_SITE_URL : 'https://reportedip.de';
		return add_query_arg(
			array(
				'utm_source'   => 'hive',
				'utm_medium'   => $medium,
				'utm_campaign' => 'protected',
				'utm_content'  => $variant,
				'utm_term'     => $tone,
			),
			$base
		);
	}

	/**
	 * Validate a hex colour. Returns the normalised value or empty string.
	 *
	 * @param mixed $value Raw value.
	 * @return string `#rgb`, `#rrggbb`, or '' for invalid input.
	 * @since  1.3.1
	 */
	private function clean_color_hex( $value ) {
		$value = is_string( $value ) ? trim( $value ) : '';
		return preg_match( self::HEX_COLOR_REGEX, $value ) ? $value : '';
	}

	/**
	 * Validate a `bg=` value (single hex OR two comma-separated hex stops).
	 *
	 * @param mixed $value Raw value.
	 * @return string Normalised value or '' for invalid input.
	 * @since  1.3.1
	 */
	private function clean_bg( $value ) {
		$value = is_string( $value ) ? trim( $value ) : '';
		return preg_match( self::BG_REGEX, $value ) ? $value : '';
	}

	/**
	 * Validate a `border=` value: hex colour or the literal `none`.
	 *
	 * @param mixed $value Raw value.
	 * @return string Normalised value (`#…` or `none`) or '' for invalid input.
	 * @since  1.3.1
	 */
	private function clean_border( $value ) {
		$value = is_string( $value ) ? trim( $value ) : '';
		if ( '' === $value ) {
			return '';
		}
		if ( 0 === strcasecmp( $value, 'none' ) ) {
			return 'none';
		}
		return $this->clean_color_hex( $value );
	}

	/**
	 * Strip tags + length-clamp a free-text override (label / intro).
	 *
	 * @param mixed $value Raw value.
	 * @return string Sanitised string (may be empty).
	 * @since  1.3.1
	 */
	private function clean_text_override( $value ) {
		$value = wp_strip_all_tags( (string) $value );
		$value = trim( $value );
		if ( '' === $value ) {
			return '';
		}
		if ( function_exists( 'mb_substr' ) ) {
			return mb_substr( $value, 0, self::TEXT_OVERRIDE_MAX_LEN );
		}
		return substr( $value, 0, self::TEXT_OVERRIDE_MAX_LEN );
	}

	/**
	 * Build the `<rip-hive-banner>` element markup with a Light-DOM
	 * `<a href>` fallback that remains visible when JavaScript is disabled
	 * and crawlable for search engines.
	 *
	 * @param string $variant Banner variant: badge|stat|banner|shield.
	 * @param array  $args    Optional overrides: type, theme, align, tone, bg, color, border, label, intro, live, utm_medium.
	 * @return string Rendered HTML.
	 * @since  1.3.0
	 */
	public function build_element( $variant, $args = array() ) {
		$variant = self::sanitize_variant( $variant );
		$tag_key = 'reportedip_' . $variant;
		$tag_def = self::$tag_map[ $tag_key ] ?? self::$tag_map['reportedip_badge'];

		$defaults = array(
			'type'       => self::DEFAULT_STAT,
			'theme'      => 'dark',
			'align'      => 'left',
			'tone'       => $tag_def['tone'],
			'bg'         => '',
			'color'      => '',
			'border'     => '',
			'label'      => '',
			'intro'      => '',
			'live'       => 'true',
			'utm_medium' => $tag_def['medium'],
		);
		$args     = wp_parse_args( $args, $defaults );

		$args['theme']  = in_array( $args['theme'], array( 'dark', 'light' ), true ) ? $args['theme'] : 'dark';
		$args['align']  = in_array( $args['align'], array( 'left', 'center', 'right' ), true ) ? $args['align'] : 'left';
		$args['tone']   = self::sanitize_tone( $args['tone'] );
		$args['bg']     = $this->clean_bg( $args['bg'] );
		$args['color']  = $this->clean_color_hex( $args['color'] );
		$args['border'] = $this->clean_border( $args['border'] );
		$args['label']  = $this->clean_text_override( $args['label'] );
		$args['intro']  = $this->clean_text_override( $args['intro'] );
		$args['live']   = in_array( $args['live'], array( 'false', '0', 'no', false ), true ) ? 'false' : 'true';

		$stat = $this->resolve_stat( (string) $args['type'] );
		$tone = self::tone_definitions()[ $args['tone'] ];

		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$mode         = $mode_manager->is_community_mode() ? 'community' : 'local';

		$href = $this->build_backlink_url( (string) $args['utm_medium'], $variant, $args['tone'] );

		$show_value = $stat['value'] > 0;
		$value_attr = $show_value ? (string) $stat['value'] : '';

		$headline = '' !== $args['intro'] ? $args['intro'] : $tone['headline'];
		$noun     = '' !== $args['label']
			? $args['label']
			: ( null !== $tone['noun'] ? $tone['noun'] : $stat['label'] );

		$metric_text   = $show_value
			? number_format_i18n( $stat['value'] ) . ' ' . $noun
			: $stat['fallback_text'];
		$fallback_text = $headline . ' — ' . $metric_text;

		$wrapper_align = 'left' === $args['align']
			? 'text-align:left;'
			: ( 'right' === $args['align'] ? 'text-align:right;' : 'text-align:center;' );

		$this->enqueue_frontend_script();

		ob_start();
		?>
<span class="rip-hive-banner-wrap" style="display:block;<?php echo esc_attr( $wrapper_align ); ?>margin:1em 0;">
<rip-hive-banner
	data-variant="<?php echo esc_attr( $variant ); ?>"
	data-tone="<?php echo esc_attr( $args['tone'] ); ?>"
	data-stat="<?php echo esc_attr( (string) $args['type'] ); ?>"
	data-value="<?php echo esc_attr( $value_attr ); ?>"
	data-headline="<?php echo esc_attr( $headline ); ?>"
	data-noun="<?php echo esc_attr( $noun ); ?>"
	data-metric-text="<?php echo esc_attr( $metric_text ); ?>"
	data-mode="<?php echo esc_attr( $mode ); ?>"
	data-theme="<?php echo esc_attr( $args['theme'] ); ?>"
	data-bg="<?php echo esc_attr( $args['bg'] ); ?>"
	data-color="<?php echo esc_attr( $args['color'] ); ?>"
	data-border="<?php echo esc_attr( $args['border'] ); ?>"
	data-live="<?php echo esc_attr( $args['live'] ); ?>"
	data-href="<?php echo esc_url( $href ); ?>">
	<a href="<?php echo esc_url( $href ); ?>" rel="noopener" class="rip-hive-fallback-link"><?php echo esc_html( $fallback_text ); ?></a>
</rip-hive-banner>
</span>
		<?php
		return (string) ob_get_clean();
	}

	/**
	 * Single shortcode handler for all four tags.
	 *
	 * WordPress passes the shortcode tag as the third argument; we use it to
	 * look up the variant and default UTM medium / tone from `$tag_map` so
	 * the four `[reportedip_*]` shortcodes share one code path.
	 *
	 * @param array|string $atts    Shortcode attributes.
	 * @param string|null  $content Inner content (unused).
	 * @param string       $tag     The shortcode tag actually invoked.
	 * @return string Rendered HTML.
	 * @since  1.3.0
	 */
	public function render_shortcode( $atts, $content = null, $tag = '' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		$map     = self::$tag_map[ $tag ] ?? self::$tag_map['reportedip_badge'];
		$variant = $map['variant'];

		$atts = shortcode_atts(
			array(
				'type'   => self::DEFAULT_STAT,
				'theme'  => 'dark',
				'align'  => 'left',
				'tone'   => $map['tone'],
				'bg'     => '',
				'color'  => '',
				'border' => '',
				'label'  => '',
				'intro'  => '',
				'live'   => 'true',
			),
			(array) $atts,
			$tag
		);

		return $this->build_element(
			$variant,
			array(
				'type'       => sanitize_key( (string) $atts['type'] ),
				'theme'      => sanitize_key( (string) $atts['theme'] ),
				'align'      => sanitize_key( (string) $atts['align'] ),
				'tone'       => sanitize_key( (string) $atts['tone'] ),
				'live'       => sanitize_key( (string) $atts['live'] ),
				'bg'         => (string) $atts['bg'],
				'color'      => (string) $atts['color'],
				'border'     => (string) $atts['border'],
				'label'      => (string) $atts['label'],
				'intro'      => (string) $atts['intro'],
				'utm_medium' => $map['medium'],
			)
		);
	}

	/**
	 * Whether the auto-footer is enabled in plugin options.
	 *
	 * @return bool
	 * @since  1.3.0
	 */
	public function auto_footer_enabled() {
		return (bool) get_option( 'reportedip_hive_auto_footer_enabled', false );
	}

	/**
	 * Conditionally enqueue the frontend Web Component script.
	 *
	 * Only loaded when (a) auto-footer is on, or (b) the current post
	 * contains one of the four shortcodes.
	 *
	 * @since 1.3.0
	 */
	public function maybe_enqueue_assets() {
		if ( is_admin() ) {
			return;
		}

		if ( $this->auto_footer_enabled() || $this->current_post_uses_shortcode() ) {
			$this->enqueue_frontend_script();
		}
	}

	/**
	 * Detect shortcode usage in the current main post via a single regex.
	 *
	 * Cheaper than four sequential `has_shortcode()` calls (each of which runs
	 * `get_shortcode_regex()` + a full `preg_match_all`). The pattern matches
	 * the same delimiter rules WordPress uses for opening tags.
	 *
	 * @return bool
	 * @since  1.3.0
	 */
	private function current_post_uses_shortcode() {
		global $post;
		if ( ! $post || empty( $post->post_content ) ) {
			return false;
		}
		return (bool) preg_match( '/\[reportedip_(?:badge|stat|banner|shield)\b/', (string) $post->post_content );
	}

	/**
	 * Register and enqueue the frontend Web Component script. Idempotent —
	 * WordPress deduplicates by handle, so callers can invoke it freely.
	 *
	 * @since 1.3.0
	 */
	public function enqueue_frontend_script() {
		wp_enqueue_script(
			'reportedip-hive-frontend',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/frontend-banner.js',
			array(),
			REPORTEDIP_HIVE_VERSION,
			true
		);
	}

	/**
	 * Render the auto-footer banner via `wp_footer`, when the option is on.
	 *
	 * @since 1.3.0
	 */
	public function maybe_render_auto_footer() {
		if ( ! $this->auto_footer_enabled() ) {
			return;
		}

		$variant   = self::sanitize_footer_variant( get_option( 'reportedip_hive_auto_footer_variant', 'badge' ) );
		$align_raw = sanitize_key( (string) get_option( 'reportedip_hive_auto_footer_align', 'center' ) );
		$align     = in_array( $align_raw, array( 'left', 'center', 'right', 'below' ), true ) ? $align_raw : 'center';

		echo '<div class="rip-hive-auto-footer" style="text-align:' . esc_attr( $align ) . ';margin:1.5em 0;">';
		echo $this->build_element( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- build_element() escapes its own attributes and text nodes; a custom-element wrapper cannot pass through wp_kses without losing the tag.
			$variant,
			array(
				'utm_medium' => 'footer',
				'theme'      => 'dark',
				'align'      => $align,
			)
		);
		echo '</div>';
	}

	/**
	 * Invalidate the public stats cache.
	 *
	 * @since 1.3.0
	 */
	public static function flush_stats_cache() {
		delete_transient( self::STATS_TRANSIENT_KEY );
		if ( null !== self::$instance ) {
			self::$instance->stats_memo = null;
		}
	}
}
