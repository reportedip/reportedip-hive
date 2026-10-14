<?php
/**
 * Mode Manager Class for ReportedIP Hive.
 *
 * Manages the dual-mode system (Local Protection vs Community Network).
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ReportedIP_Hive_Mode_Manager
 *
 * Central manager for plugin operation modes.
 * Supports two modes:
 * - Local Mode: Standalone protection without API connectivity
 * - Community Mode: Full feature set with API integration
 */
class ReportedIP_Hive_Mode_Manager {

	/**
	 * Mode constants
	 */
	const MODE_LOCAL     = 'local';
	const MODE_COMMUNITY = 'community';

	/**
	 * Option names
	 */
	const OPTION_MODE                = 'reportedip_hive_operation_mode';
	const OPTION_WIZARD_COMPLETED    = 'reportedip_hive_wizard_completed';
	const OPTION_WIZARD_COMPLETED_AT = 'reportedip_hive_wizard_completed_at';
	const OPTION_WIZARD_SKIPPED      = 'reportedip_hive_wizard_skipped';

	/**
	 * Single instance of the class
	 *
	 * @var ReportedIP_Hive_Mode_Manager|null
	 */
	private static $instance = null;

	/**
	 * Cached mode value
	 *
	 * @var string|null
	 */
	private $cached_mode = null;

	/**
	 * Cached tier value for the current request lifecycle.
	 *
	 * @var string|null
	 */
	private $cached_tier = null;

	/**
	 * Feature definitions for each mode, `null` until the first read builds them.
	 *
	 * @var array|null
	 */
	private $feature_matrix = null;

	/**
	 * Lazily-built map of translated feature texts (see {@see feature_texts()}).
	 *
	 * @var array<string, array{0:string,1:string}>|null
	 */
	private $feature_texts_cache = null;

	/**
	 * Get single instance (Singleton pattern)
	 *
	 * @return ReportedIP_Hive_Mode_Manager
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor
	 */
	private function __construct() {
		add_action( 'reportedip_hive_tier_changed', array( $this, 'flush_cached_tier' ) );
		add_action( 'update_option_' . self::OPTION_MODE, array( $this, 'on_mode_option_updated' ), 10, 2 );
		add_action( 'update_site_option_' . self::OPTION_MODE, array( $this, 'on_mode_site_option_updated' ), 10, 3 );
	}

	/**
	 * Mirror {@see on_mode_option_updated()} for the sitemeta storage path.
	 *
	 * On Multisite the canonical storage for the operation mode is sitemeta,
	 * so the regular `update_option_*` hook does not fire. We adapt the
	 * site-option signature ($option, $value, $old_value) to the same
	 * downstream handler.
	 *
	 * @param string $option    Option name.
	 * @param mixed  $value     New value.
	 * @param mixed  $old_value Previous value.
	 * @return void
	 * @since 2.0.0
	 */
	public function on_mode_site_option_updated( $option, $value, $old_value ) {
		unset( $option );
		$this->on_mode_option_updated( $old_value, $value );
	}

	/**
	 * Whether the given string is a valid operation-mode identifier.
	 *
	 * @param string $mode Candidate mode.
	 * @return bool
	 * @since 1.6.0
	 */
	public static function is_valid_mode( $mode ) {
		return in_array( (string) $mode, array( self::MODE_LOCAL, self::MODE_COMMUNITY ), true );
	}

	/**
	 * Mirror the `set_mode()` side effects when the option is updated through
	 * the WordPress Settings API or any other `update_option()` caller, cache
	 * reset, `reportedip_hive_mode_changed` action, audit-log entry. Listens
	 * on `update_option_<OPTION_MODE>`.
	 *
	 * @param mixed $old_value Previous option value.
	 * @param mixed $value     New option value.
	 * @return void
	 * @since 1.6.0
	 */
	public function on_mode_option_updated( $old_value, $value ) {
		$mode = (string) $value;
		if ( $old_value === $value || ! self::is_valid_mode( $mode ) ) {
			return;
		}
		$this->cached_mode = $mode;

		do_action( 'reportedip_hive_mode_changed', $mode );

		if ( class_exists( 'ReportedIP_Hive_Logger' ) ) {
			$logger = ReportedIP_Hive_Logger::get_instance();
			$logger->log_security_event(
				'mode_changed',
				'system',
				array(
					'new_mode' => $mode,
					'user_id'  => get_current_user_id(),
				),
				'low'
			);
		}
	}

	/**
	 * Reset the per-request tier memo. Listens on `reportedip_hive_tier_changed`.
	 *
	 * @return void
	 * @since 1.5.3
	 */
	public function flush_cached_tier() {
		$this->cached_tier                    = null;
		$this->api_rate_limit_snapshot_cache  = null;
		$this->community_layer_degraded_cache = null;
	}

	/**
	 * Ensure the feature matrix is initialised.
	 *
	 * Carries ONLY machine-readable gating fields (local/community/requires_tier).
	 * The translated label/description pairs live in {@see feature_texts()}.
	 * building them here meant 50 `__()` calls on the first `feature_status()`
	 * of every request, which on localised sites triggered the just-in-time
	 * load of the full .mo file on anonymous front-end requests (measured at
	 * 284 KB per request on a German install) even though nothing on the
	 * front end ever renders a feature label.
	 *
	 * @return void
	 */
	private function ensure_feature_matrix_loaded() {
		if ( null !== $this->feature_matrix ) {
			return;
		}

		$this->feature_matrix = array(
			'login_monitoring'             => array(
				'local'     => true,
				'community' => true,
			),
			'comment_monitoring'           => array(
				'local'     => true,
				'community' => true,
			),
			'xmlrpc_monitoring'            => array(
				'local'     => true,
				'community' => true,
			),
			'auto_blocking'                => array(
				'local'     => true,
				'community' => true,
			),
			'local_blocklist'              => array(
				'local'     => true,
				'community' => true,
			),
			'local_statistics'             => array(
				'local'     => true,
				'community' => true,
			),
			'api_reputation_check'         => array(
				'local'     => false,
				'community' => true,
			),
			'api_report'                   => array(
				'local'     => false,
				'community' => true,
			),
			'global_blacklist'             => array(
				'local'     => false,
				'community' => true,
			),
			'reputation_blocking'          => array(
				'local'     => false,
				'community' => true,
			),
			'advanced_analytics'           => array(
				'local'     => false,
				'community' => true,
			),
			'threat_intelligence'          => array(
				'local'     => false,
				'community' => true,
			),
			'coordinated_attack_detection' => array(
				'local'     => false,
				'community' => true,
			),
			'mail_relay_via_api'           => array(
				'local'         => false,
				'community'     => true,
				'requires_tier' => 'professional',
			),
			'sms_relay_via_api'            => array(
				'local'         => false,
				'community'     => true,
				'requires_tier' => 'professional',
			),
			'frontend_2fa'                 => array(
				'local'         => true,
				'community'     => true,
				'requires_tier' => 'professional',
			),
			'webauthn_advanced'            => array(
				'local'         => true,
				'community'     => true,
				'requires_tier' => 'business',
			),
			'decoy_pathblock'              => array(
				'local'     => true,
				'community' => true,
			),
			'hardening_mode'               => array(
				'local'         => true,
				'community'     => true,
				'requires_tier' => 'professional',
			),
			'form_proof_pow'               => array(
				'local'         => true,
				'community'     => true,
				'requires_tier' => 'professional',
			),
			'form_adapters'                => array(
				'local'     => true,
				'community' => true,
			),
			'form_adapters_advanced'       => array(
				'local'         => true,
				'community'     => true,
				'requires_tier' => 'business',
			),
			'tor_blocking'                 => array(
				'local'         => false,
				'community'     => true,
				'requires_tier' => 'professional',
			),
			'waf'                          => array(
				'local'     => true,
				'community' => true,
			),
			'rule_sync_priority'           => array(
				'local'         => false,
				'community'     => true,
				'requires_tier' => 'contributor',
			),
			'bot_verification'             => array(
				'local'     => true,
				'community' => true,
			),
			'disposable_email'             => array(
				'local'     => true,
				'community' => true,
			),
			'security_headers'             => array(
				'local'     => true,
				'community' => true,
			),
			'security_headers_advanced'    => array(
				'local'         => true,
				'community'     => true,
				'requires_tier' => 'professional',
			),
			'audit_log'                    => array(
				'local'         => true,
				'community'     => true,
				'requires_tier' => 'business',
			),
			'cloud_management'             => array(
				'local'         => false,
				'community'     => true,
				'requires_tier' => 'business',
			),
			'registration_rules_unlimited' => array(
				'local'         => true,
				'community'     => true,
				'requires_tier' => 'professional',
			),
			'user_management'              => array(
				'local'         => true,
				'community'     => true,
				'requires_tier' => 'business',
			),
			'2fa_policies'                 => array(
				'local'         => true,
				'community'     => true,
				'requires_tier' => 'professional',
			),
		);

		/**
		 * Extend the feature matrix.
		 *
		 * The free plugin lists only features it ships. An add-on appends its
		 * own rows, each with `local`, `community` and optionally
		 * `requires_tier`; a key nobody registered stays `unknown`.
		 *
		 * @param array<string, array<string, mixed>> $matrix Feature key to gating row.
		 * @since 3.0.0
		 */
		$this->feature_matrix = apply_filters( 'reportedip_hive_feature_matrix', $this->feature_matrix );
	}

	/**
	 * Forget the memoised matrix and texts, so a filter added later in the
	 * request (tests, late-loading add-ons) is honoured.
	 *
	 * @return void
	 * @since  3.0.0
	 */
	public function flush_feature_matrix() {
		$this->feature_matrix      = null;
		$this->feature_texts_cache = null;
	}

	/**
	 * Translated label/description pair per feature key, built on first use.
	 *
	 * Kept apart from the gating matrix so hot-path availability checks never
	 * pull the textdomain in. Callers that render feature texts (admin pages,
	 * wizard, AJAX) hit this lazily; the literal `__()` calls keep the strings
	 * visible to the POT extractor and the translation gate.
	 *
	 * @return array<string, array{0:string,1:string}> Map feature => [label, description].
	 * @since  2.1.32
	 */
	private function feature_texts() {
		if ( null !== $this->feature_texts_cache ) {
			return $this->feature_texts_cache;
		}

		$this->feature_texts_cache = array(
			'login_monitoring'             => array( __( 'Login Monitoring', 'reportedip-hive' ), __( 'Monitor and log failed login attempts', 'reportedip-hive' ) ),
			'comment_monitoring'           => array( __( 'Comment Spam Monitoring', 'reportedip-hive' ), __( 'Detect and block spam comments', 'reportedip-hive' ) ),
			'xmlrpc_monitoring'            => array( __( 'XMLRPC Monitoring', 'reportedip-hive' ), __( 'Monitor XMLRPC endpoint for abuse', 'reportedip-hive' ) ),
			'auto_blocking'                => array( __( 'Automatic IP Blocking', 'reportedip-hive' ), __( 'Automatically block IPs that exceed thresholds', 'reportedip-hive' ) ),
			'local_blocklist'              => array( __( 'Local Block/Whitelist', 'reportedip-hive' ), __( 'Manage local IP block and whitelist', 'reportedip-hive' ) ),
			'local_statistics'             => array( __( 'Local Statistics', 'reportedip-hive' ), __( 'View local security statistics', 'reportedip-hive' ) ),
			'api_reputation_check'         => array( __( 'Community Reputation Check', 'reportedip-hive' ), __( 'Check IP reputation against community database', 'reportedip-hive' ) ),
			'api_report'                   => array( __( 'Share Threats with Community', 'reportedip-hive' ), __( 'Report detected threats to the community network', 'reportedip-hive' ) ),
			'global_blacklist'             => array( __( 'Global Blacklist', 'reportedip-hive' ), __( 'Access and download the global threat blacklist', 'reportedip-hive' ) ),
			'reputation_blocking'          => array( __( 'Reputation-based Blocking', 'reportedip-hive' ), __( 'Block IPs based on community reputation scores', 'reportedip-hive' ) ),
			'advanced_analytics'           => array( __( 'Advanced Analytics', 'reportedip-hive' ), __( 'Access advanced threat analytics and trends', 'reportedip-hive' ) ),
			'threat_intelligence'          => array( __( 'Threat Intelligence', 'reportedip-hive' ), __( 'Receive threat intelligence from the community', 'reportedip-hive' ) ),
			'coordinated_attack_detection' => array( __( 'Coordinated Attack Detection', 'reportedip-hive' ), __( 'Detect coordinated attacks across the network', 'reportedip-hive' ) ),
			'mail_relay_via_api'           => array( __( 'Mail Relay via reportedip.com', 'reportedip-hive' ), __( 'Send 2FA mails through our SMTP for guaranteed deliverability, no own SMTP setup needed.', 'reportedip-hive' ) ),
			'sms_relay_via_api'            => array( __( 'SMS Relay via reportedip.com', 'reportedip-hive' ), __( 'Send 2FA SMS via our managed EU gateway, included with Professional and Business.', 'reportedip-hive' ) ),
			'frontend_2fa'                 => array( __( 'WooCommerce Frontend Login 2FA', 'reportedip-hive' ), __( 'Two-factor verification on My Account, classic checkout and WooCommerce blocks login, kept inside the theme frame instead of bouncing customers to wp-login.php.', 'reportedip-hive' ) ),
			'webauthn_advanced'            => array( __( 'Advanced Security Keys', 'reportedip-hive' ), __( 'Multiple security keys per account (primary + backup), automatic model detection via attestation and key-lifecycle email alerts. One security key or passkey per account stays free.', 'reportedip-hive' ) ),
			'decoy_pathblock'              => array( __( 'Decoy Path Block', 'reportedip-hive' ), __( 'Instant ban on the first request to a known bait path (.env.backup, wp-config.old.php, ...), distinct from the N-of-Y scan-detector.', 'reportedip-hive' ) ),
			'hardening_mode'               => array( __( 'Hardening Mode on Coordinated Attack', 'reportedip-hive' ), __( 'Tighten failed-login and reputation thresholds network-wide for one hour after a coordinated-attack pattern is detected.', 'reportedip-hive' ) ),
			'form_proof_pow'               => array( __( 'Computation Check on Forms', 'reportedip-hive' ), __( 'Give the form a small sum to work out in the background and check the answer on submit, so a script that copies the hidden field out of the page no longer passes for a visitor.', 'reportedip-hive' ) ),
			'form_adapters'                => array( __( 'Contact Form Protection', 'reportedip-hive' ), __( 'Carry the execution proof into Contact Form 7, so it is covered by the same check as the comment form and needs no distorted image.', 'reportedip-hive' ) ),
			'form_adapters_advanced'       => array( __( 'Advanced Form Protection', 'reportedip-hive' ), __( 'The same protection on WPForms, Gravity Forms, Forminator, Formidable Forms, Formidable Forms PRO, Elementor Forms and the Ultimate Member forms. An Ultimate Member sign-up also runs through the registration rules.', 'reportedip-hive' ) ),
			'tor_blocking'                 => array( __( 'Tor Exit Node Blocking', 'reportedip-hive' ), __( 'Block login attempts from known Tor exit nodes using a signed exit-node list that is refreshed twice a day, plus the live community check.', 'reportedip-hive' ) ),
			'waf'                          => array( __( 'Web Application Firewall', 'reportedip-hive' ), __( 'Payload-inspecting request firewall. The engine and a baseline ruleset are free; the richer, frequently-updated ruleset arrives via Priority Sync.', 'reportedip-hive' ) ),
			'rule_sync_priority'           => array( __( 'Priority Rule Sync', 'reportedip-hive' ), __( 'Server-delivered rulesets instead of the bundled baseline: Paranoia Level 2 signatures and bot IP-range feeds refreshed weekly on Contributor; daily refresh, Paranoia Level 3 and the live disposable list from Professional.', 'reportedip-hive' ) ),
			'bot_verification'             => array( __( 'Verified Bot Detection', 'reportedip-hive' ), __( 'Verify search-engine crawlers via IP ranges and forward-confirmed reverse DNS; flag or block user-agent spoofers.', 'reportedip-hive' ) ),
			'disposable_email'             => array( __( 'Disposable Email Block', 'reportedip-hive' ), __( 'Block registrations from throwaway-mail providers. Baseline list is free; the live list arrives via Priority Sync.', 'reportedip-hive' ) ),
			'security_headers'             => array( __( 'Security Headers', 'reportedip-hive' ), __( 'Site-wide X-Content-Type-Options, X-Frame-Options and Referrer-Policy.', 'reportedip-hive' ) ),
			'security_headers_advanced'    => array( __( 'Advanced Security Headers', 'reportedip-hive' ), __( 'CSP builder, HSTS with preload, Permissions-Policy and the Cross-Origin-Opener/Embedder/Resource trio.', 'reportedip-hive' ) ),
			'audit_log'                    => array( __( 'Audit Event Trail', 'reportedip-hive' ), __( 'Who changed what: settings with old and new value, plugins and themes, pages, menus, edited files and user accounts, with configurable triggers, filtering, CSV/JSON export and long retention.', 'reportedip-hive' ) ),
			'cloud_management'             => array( __( 'Cloud Fleet Management', 'reportedip-hive' ), __( 'Manage this site remotely from the reportedip.com dashboard: security policies, per-site overrides and drift detection across all your Hive installations.', 'reportedip-hive' ) ),
			'registration_rules_unlimited' => array( __( 'Unlimited Registration Rules', 'reportedip-hive' ), __( 'Unlimited prohibited-username and e-mail rule entries, regular-expression patterns and registration restricted to allowlisted IP addresses. Ten plain entries per list stay free.', 'reportedip-hive' ) ),
			'user_management'              => array( __( 'User Account Control', 'reportedip-hive' ), __( 'Block user accounts with a message and an admin note, end their sessions and password resets, and review or terminate active sessions.', 'reportedip-hive' ) ),
			'2fa_policies'                 => array( __( 'Configurable 2FA Policies per Role', 'reportedip-hive' ), __( 'Per-role step-up rules that ask for the second factor again on a new device, IP address, network or country, every N days or sign-ins, or above a concurrent-session limit, even on a trusted device.', 'reportedip-hive' ) ),
		);

		/**
		 * Extend the feature texts with label and description pairs for rows
		 * an add-on registered through `reportedip_hive_feature_matrix`.
		 *
		 * @param array<string, array{0:string,1:string}> $texts Feature key to [label, description].
		 * @since 3.0.0
		 */
		$this->feature_texts_cache = apply_filters( 'reportedip_hive_feature_texts', $this->feature_texts_cache );

		return $this->feature_texts_cache;
	}

	/**
	 * Label/description for one feature, empty strings on the front end.
	 *
	 * Availability consumers on the hot path (WAF paranoia cap, bot verifier,
	 * security headers, frontend 2FA) only read `available`/`reason`; loading
	 * the textdomain for them would be pure waste. Contexts that actually
	 * render texts (wp-admin including AJAX, cron mails, WP-CLI, REST) get the
	 * translated pair.
	 *
	 * @param string $feature Feature key.
	 * @return array{0:string,1:string} [label, description].
	 * @since  2.1.32
	 */
	private function feature_text( $feature ) {
		$translating_context = ( function_exists( 'is_admin' ) && is_admin() )
			|| ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() )
			|| ( defined( 'WP_CLI' ) && WP_CLI )
			|| ( defined( 'REST_REQUEST' ) && REST_REQUEST );
		if ( ! $translating_context ) {
			return array( '', '' );
		}
		$texts = $this->feature_texts();
		return isset( $texts[ $feature ] ) ? $texts[ $feature ] : array( '', '' );
	}

	/**
	 * Tiers ordered by privilege level (lowest → highest).
	 *
	 * @var string[]
	 */
	const TIER_ORDER = array( 'free', 'contributor', 'professional', 'business', 'enterprise' );

	/**
	 * Map a WordPress role slug to a marketing-friendly tier label.
	 *
	 * @param string $role
	 * @return string
	 */
	public static function tier_from_role( $role ) {
		$map = array(
			'reportedip_free'         => 'free',
			'reportedip_contributor'  => 'contributor',
			'reportedip_professional' => 'professional',
			'reportedip_business'     => 'business',
			'reportedip_enterprise'   => 'enterprise',
			'reportedip_honeypot'     => 'honeypot',
			'administrator'           => 'enterprise',
		);
		return $map[ (string) $role ] ?? 'free';
	}

	/**
	 * Whether the cached tier (from /verify-key or /relay-quota) is at least $minimum.
	 *
	 * The `honeypot` tier is not part of {@see TIER_ORDER}; a honeypot
	 * operator is a Contributor for every feature gate (see
	 * {@see get_tier_info()}), so it is aliased before the lookup instead of
	 * failing every minimum.
	 *
	 * @param string $minimum One of TIER_ORDER values.
	 * @return bool
	 */
	public function tier_at_least( $minimum ) {
		$tier     = $this->get_cached_tier_or_default();
		$tier     = 'honeypot' === $tier ? 'contributor' : $tier;
		$ord      = self::TIER_ORDER;
		$idx_have = array_search( $tier, $ord, true );
		$idx_need = array_search( $minimum, $ord, true );
		if ( false === $idx_have || false === $idx_need ) {
			return false;
		}
		return $idx_have >= $idx_need;
	}

	/**
	 * Determine the current tier from cached API state (verify-key, relay-quota
	 * or the durable known-tier baseline).
	 *
	 * Never performs a live `/relay-quota` call: this method runs on hot,
	 * per-request paths (WAF, security headers, bot verification via
	 * {@see feature_status()}), where a synchronous HTTP round-trip would both
	 * delay the response and, on installs whose cache cannot be populated.
	 * stampede the service. Live refresh is owned exclusively by the six-hour
	 * cron and the API-key-save hook. Delegates to {@see get_cached_tier_or_default()}.
	 *
	 * @return string
	 */
	public function get_current_tier() {
		return $this->get_cached_tier_or_default();
	}

	/**
	 * Get current operation mode
	 *
	 * @return string MODE_LOCAL or MODE_COMMUNITY
	 */
	public function get_mode() {
		if ( null !== $this->cached_mode ) {
			return $this->cached_mode;
		}

		$mode = ReportedIP_Hive_Option_Routing::get( self::OPTION_MODE, self::MODE_LOCAL );

		if ( ! in_array( $mode, array( self::MODE_LOCAL, self::MODE_COMMUNITY ), true ) ) {
			$mode = self::MODE_LOCAL;
		}

		$this->cached_mode = $mode;
		return $mode;
	}

	/**
	 * Set operation mode
	 *
	 * @param string $mode MODE_LOCAL or MODE_COMMUNITY
	 * @return bool Success status
	 */
	public function set_mode( $mode ) {
		if ( ! self::is_valid_mode( $mode ) ) {
			return false;
		}

		$result = ReportedIP_Hive_Option_Routing::set( self::OPTION_MODE, $mode );
		$saved  = $result || ReportedIP_Hive_Option_Routing::get( self::OPTION_MODE ) === $mode;
		if ( $saved ) {
			$this->cached_mode = $mode;
		}

		return $saved;
	}

	/**
	 * Check if currently in local mode
	 *
	 * @return bool
	 */
	public function is_local_mode() {
		return $this->get_mode() === self::MODE_LOCAL;
	}

	/**
	 * Check if currently in community mode
	 *
	 * @return bool
	 */
	public function is_community_mode() {
		return $this->get_mode() === self::MODE_COMMUNITY;
	}

	/**
	 * Check if API can be used in current mode
	 *
	 * In local mode, API calls should be skipped.
	 * In community mode, API can be used if configured.
	 *
	 * @return bool
	 */
	public function can_use_api() {
		if ( $this->is_local_mode() ) {
			return false;
		}

		$api_key = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' );
		return ! empty( $api_key );
	}

	/**
	 * Check if a specific feature is available in current mode
	 *
	 * @param string $feature Feature key
	 * @return bool
	 */
	public function is_feature_available( $feature ) {
		$this->ensure_feature_matrix_loaded();

		if ( ! isset( $this->feature_matrix[ $feature ] ) ) {
			return false;
		}

		$mode = $this->get_mode();
		return ! empty( $this->feature_matrix[ $feature ][ $mode ] );
	}

	/**
	 * Check if setup wizard has been completed
	 *
	 * @return bool
	 */
	public function is_wizard_completed() {
		return (bool) ReportedIP_Hive_Option_Routing::get( self::OPTION_WIZARD_COMPLETED, false );
	}

	/**
	 * Mark setup wizard as completed
	 *
	 * @return bool
	 */
	public function mark_wizard_completed() {
		ReportedIP_Hive_Option_Routing::set( self::OPTION_WIZARD_COMPLETED, true );
		ReportedIP_Hive_Option_Routing::set( self::OPTION_WIZARD_COMPLETED_AT, current_time( 'mysql', true ) );

		ReportedIP_Hive_Option_Routing::delete( self::OPTION_WIZARD_SKIPPED );

		return true;
	}

	/**
	 * Check if wizard was skipped
	 *
	 * @return bool
	 */
	public function is_wizard_skipped() {
		return (bool) ReportedIP_Hive_Option_Routing::get( self::OPTION_WIZARD_SKIPPED, false );
	}

	/**
	 * Mark wizard as skipped
	 *
	 * @return bool
	 */
	public function skip_wizard() {
		ReportedIP_Hive_Option_Routing::set( self::OPTION_WIZARD_SKIPPED, true );
		return true;
	}

	/**
	 * Get mode display information
	 *
	 * @param string|null $mode Mode to get info for (null = current mode)
	 * @return array Mode display information
	 */
	public function get_mode_info( $mode = null ) {
		if ( null === $mode ) {
			$mode = $this->get_mode();
		}

		$modes = array(
			self::MODE_LOCAL     => array(
				'key'         => self::MODE_LOCAL,
				'label'       => __( 'Local Shield', 'reportedip-hive' ),
				'short_label' => __( 'Local', 'reportedip-hive' ),
				'description' => __( 'Standalone protection without external connectivity', 'reportedip-hive' ),
				'icon'        => 'shield',
				'icon_class'  => 'rip-icon-shield-local',
				'badge_class' => 'rip-mode-badge--local',
				'color'       => '#6366F1',
			),
			self::MODE_COMMUNITY => array(
				'key'         => self::MODE_COMMUNITY,
				'label'       => __( 'Community Network', 'reportedip-hive' ),
				'short_label' => __( 'Community', 'reportedip-hive' ),
				'description' => __( 'Connected to the community threat intelligence network', 'reportedip-hive' ),
				'icon'        => 'globe',
				'icon_class'  => 'rip-icon-shield-community',
				'badge_class' => 'rip-mode-badge--community',
				'color'       => '#10B981',
			),
		);

		return isset( $modes[ $mode ] ) ? $modes[ $mode ] : $modes[ self::MODE_LOCAL ];
	}

	/**
	 * Determine the gating status for a feature against the current mode and tier.
	 *
	 * Reason codes:
	 *  - 'ok'     , feature is available
	 *  - 'mode'   , current operation mode does not include the feature
	 *  - 'tier'   , current tier is below the required minimum tier
	 *  - 'unknown', feature key is not present in the matrix
	 *
	 * @param string $feature Feature key from the feature matrix.
	 * @return array{available:bool,reason:string,min_tier:?string,mode_required:?string,label:string,description:string}
	 * @since 1.5.3
	 */
	public function feature_status( $feature ) {
		$this->ensure_feature_matrix_loaded();

		if ( ! isset( $this->feature_matrix[ $feature ] ) ) {
			return array(
				'available'     => false,
				'reason'        => 'unknown',
				'min_tier'      => null,
				'mode_required' => null,
				'label'         => '',
				'description'   => '',
			);
		}

		$row      = $this->feature_matrix[ $feature ];
		$mode     = $this->get_mode();
		$min_tier = isset( $row['requires_tier'] ) ? (string) $row['requires_tier'] : null;
		$texts    = $this->feature_text( $feature );

		$mode_required = null;
		if ( empty( $row[ $mode ] ) ) {
			if ( ! empty( $row['community'] ) && ! empty( $row['local'] ) ) {
				$mode_required = null;
			} elseif ( ! empty( $row['community'] ) ) {
				$mode_required = self::MODE_COMMUNITY;
			} elseif ( ! empty( $row['local'] ) ) {
				$mode_required = self::MODE_LOCAL;
			}

			return array(
				'available'     => false,
				'reason'        => 'mode',
				'min_tier'      => $min_tier,
				'mode_required' => $mode_required,
				'label'         => $texts[0],
				'description'   => $texts[1],
			);
		}

		if ( null !== $min_tier && ! $this->tier_at_least( $min_tier ) ) {
			return array(
				'available'     => false,
				'reason'        => 'tier',
				'min_tier'      => $min_tier,
				'mode_required' => null,
				'label'         => $texts[0],
				'description'   => $texts[1],
			);
		}

		return array(
			'available'     => true,
			'reason'        => 'ok',
			'min_tier'      => $min_tier,
			'mode_required' => null,
			'label'         => $texts[0],
			'description'   => $texts[1],
		);
	}

	/**
	 * Get tier display information (label, badge class, icon, color).
	 *
	 * @param string|null $tier Tier key (null = current tier).
	 * @return array{key:string,label:string,short_label:string,description:string,icon:string,badge_class:string,color:string}
	 * @since 1.5.3
	 */
	public function get_tier_info( $tier = null ) {
		if ( null === $tier ) {
			$tier = $this->get_current_tier();
		}
		$tier = (string) $tier;

		$tiers = array(
			'free'         => array(
				'key'         => 'free',
				'label'       => _x( 'Free', 'subscription tier name', 'reportedip-hive' ),
				'short_label' => _x( 'Free', 'subscription tier name', 'reportedip-hive' ),
				'description' => __( 'Local protection, free forever.', 'reportedip-hive' ),
				'icon'        => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
				'badge_class' => 'rip-tier-badge--free',
				'color'       => '#9CA3AF',
			),
			'contributor'  => array(
				'key'         => 'contributor',
				'label'       => __( 'Contributor', 'reportedip-hive' ),
				'short_label' => __( 'Contrib.', 'reportedip-hive' ),
				'description' => __( 'Honeypot operator, community contributor.', 'reportedip-hive' ),
				'icon'        => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M9 12l2 2 4-5"/></svg>',
				'badge_class' => 'rip-tier-badge--contributor',
				'color'       => '#818CF8',
			),
			'professional' => array(
				'key'         => 'professional',
				'label'       => __( 'Professional', 'reportedip-hive' ),
				'short_label' => __( 'PRO', 'reportedip-hive' ),
				'description' => __( 'Up to 3 domains, managed mail and SMS relay, priority sync.', 'reportedip-hive' ),
				'icon'        => '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2l2.4 4.9 5.4.8-3.9 3.8.9 5.4L12 14.3 7.2 16.9l.9-5.4L4.2 7.7l5.4-.8L12 2z"/></svg>',
				'badge_class' => 'rip-tier-badge--professional',
				'color'       => '#4F46E5',
			),
			'business'     => array(
				'key'         => 'business',
				'label'       => __( 'Business', 'reportedip-hive' ),
				'short_label' => __( 'Business', 'reportedip-hive' ),
				'description' => __( 'Agency-grade: 15 domains per licence (bookable x2, x20), whitelabel, WooCommerce, full WP-CLI.', 'reportedip-hive' ),
				'icon'        => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="3" y="7" width="18" height="13" rx="2"/><path d="M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"/></svg>',
				'badge_class' => 'rip-tier-badge--business',
				'color'       => '#7C3AED',
			),
			'enterprise'   => array(
				'key'         => 'enterprise',
				'label'       => __( 'Enterprise', 'reportedip-hive' ),
				'short_label' => __( 'Enterprise', 'reportedip-hive' ),
				'description' => __( 'Unlimited domains, AVV, dedicated onboarding, priority phone support.', 'reportedip-hive' ),
				'icon'        => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M3 21h18M5 21V8l7-5 7 5v13M9 21v-6h6v6"/></svg>',
				'badge_class' => 'rip-tier-badge--enterprise',
				'color'       => '#B45309',
			),
			'honeypot'     => array(
				'key'         => 'honeypot',
				'label'       => __( 'Honeypot Operator', 'reportedip-hive' ),
				'short_label' => __( 'Honeypot', 'reportedip-hive' ),
				'description' => __( 'Operating a honeypot node for the network.', 'reportedip-hive' ),
				'icon'        => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M6 9h12l-1 11H7L6 9zM9 9V6a3 3 0 1 1 6 0v3"/></svg>',
				'badge_class' => 'rip-tier-badge--honeypot',
				'color'       => '#7C2D92',
			),
		);

		return isset( $tiers[ $tier ] ) ? $tiers[ $tier ] : $tiers['free'];
	}

	/** @var array|null Per-request memo for {@see get_api_rate_limit_snapshot()}. */
	private $api_rate_limit_snapshot_cache = null;

	/** @var bool|null Per-request memo for {@see is_community_layer_degraded()}. */
	private $community_layer_degraded_cache = null;

	/**
	 * Tier-bound hourly rate-limit caps for outgoing API calls, split into three buckets.
	 *
	 * Derived from the daily quotas in PRICING-PLAN.md (`Tagesquote / 24 × 3` spike factor)
	 * so a bot storm cannot burn the whole daily quota in two hours. `null` means
	 * "no cap" (Enterprise / Honeypot).
	 *
	 * @param string $tier Tier slug.
	 * @return array{reputation:?int,submission:?int,meta:?int}
	 * @since  2.0.5
	 */
	public function default_api_rate_limits_for_tier( $tier ) {
		switch ( (string) $tier ) {
			case 'contributor':
				return array(
					'reputation' => 600,
					'submission' => 30,
					'meta'       => 60,
				);
			case 'professional':
				return array(
					'reputation' => 3000,
					'submission' => 150,
					'meta'       => 100,
				);
			case 'business':
				return array(
					'reputation' => 12000,
					'submission' => 600,
					'meta'       => 100,
				);
			case 'enterprise':
			case 'honeypot':
				return array(
					'reputation' => null,
					'submission' => null,
					'meta'       => null,
				);
			case 'free':
			default:
				return array(
					'reputation' => 150,
					'submission' => 10,
					'meta'       => 30,
				);
		}
	}

	/**
	 * Canonical tier lookup. Never triggers a live `/relay-quota` API call.
	 *
	 * This is the single read path for the current tier on both admin and
	 * front-end requests; {@see get_current_tier()} and {@see tier_at_least()}
	 * delegate here. A live HTTP round-trip on a hot path would delay the
	 * response and stampede the service when the cache cannot be populated.
	 *
	 * Lookup order (most-fresh to most-durable):
	 *   1. per-request memo (`$cached_tier`)
	 *   2. `reportedip_hive_api_status` transient, `userRole` (5 min)
	 *   3. `reportedip_hive_relay_quota` transient, `tier` (12 h)
	 *   4. `reportedip_hive_known_tier` option, durable baseline that survives
	 *      relay-mail/sms cache busting and the gap between six-hour cron runs,
	 *      so a paid site is never mis-read as `free` mid-window
	 *   5. `free`
	 *
	 * @return string
	 * @since  2.0.7
	 */
	private function get_cached_tier_or_default() {
		if ( null !== $this->cached_tier ) {
			return $this->cached_tier;
		}

		$status = get_transient( 'reportedip_hive_api_status' );
		if ( is_array( $status ) ) {
			$role = $status['userRole'] ?? ( $status['user_role'] ?? '' );
			if ( ! empty( $role ) ) {
				$this->cached_tier = self::tier_from_role( (string) $role );
				return $this->cached_tier;
			}
		}

		$quota = get_transient( 'reportedip_hive_relay_quota' );
		if ( is_array( $quota ) && ! empty( $quota['tier'] ) ) {
			$this->cached_tier = (string) $quota['tier'];
			return $this->cached_tier;
		}

		$known = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_known_tier', '' );
		if ( '' !== $known ) {
			$this->cached_tier = $known;
			return $this->cached_tier;
		}

		$this->cached_tier = 'free';
		return $this->cached_tier;
	}

	/**
	 * Last known domain usage vs. plan limit, as announced by the service on
	 * verify-key / quota refreshes. Durable option (survives transient lapses);
	 * null while the service has not reported a snapshot yet (LOCAL mode,
	 * pre-2.1.45 server, or no verify since the update).
	 *
	 * @return array{used:int,limit:int,status:string,fetched_at:int}|null
	 * @since  2.1.45
	 */
	public function get_domains_snapshot() {
		$snapshot = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_domains_snapshot', null );
		if ( ! is_array( $snapshot ) || ! isset( $snapshot['used'], $snapshot['limit'] ) ) {
			return null;
		}

		return array(
			'used'       => (int) $snapshot['used'],
			'limit'      => (int) $snapshot['limit'],
			'status'     => (string) ( $snapshot['status'] ?? 'ok' ),
			'fetched_at' => (int) ( $snapshot['fetched_at'] ?? 0 ),
		);
	}

	/**
	 * Snapshot of the current API rate-limit state across all three buckets.
	 *
	 * Used by the admin "API call usage" card and the degraded-banner helper.
	 *
	 * @return array{tier:string,source:string,limits:array{reputation:?int,submission:?int,meta:?int},used:array{reputation:int,submission:int,meta:int}}
	 * @since  2.0.5
	 */
	public function get_api_rate_limit_snapshot() {
		if ( null !== $this->api_rate_limit_snapshot_cache ) {
			return $this->api_rate_limit_snapshot_cache;
		}

		$tier     = $this->get_cached_tier_or_default();
		$defaults = $this->default_api_rate_limits_for_tier( $tier );

		$manual = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_max_api_calls_per_hour', 0 );
		$source = 'auto';
		$limits = $defaults;

		if ( $manual > 0 ) {
			$source = 'manual';
			$limits = array(
				'reputation' => $manual,
				'submission' => $manual,
				'meta'       => $manual,
			);
		}

		$this->api_rate_limit_snapshot_cache = array(
			'tier'   => $tier,
			'source' => $source,
			'limits' => $limits,
			'used'   => array(
				'reputation' => (int) get_transient( 'reportedip_hive_hourly_api_calls_reputation' ),
				'submission' => (int) get_transient( 'reportedip_hive_hourly_api_calls_submission' ),
				'meta'       => (int) get_transient( 'reportedip_hive_hourly_api_calls_meta' ),
			),
		);
		return $this->api_rate_limit_snapshot_cache;
	}

	/**
	 * Whether the community threat-check layer is currently degraded.
	 *
	 * True when (a) Community-mode is active AND (b) any bucket is at or above 80%
	 * of its effective limit OR a server-side 429 has set the global rate-limit reset
	 * transient. In that state the local firewall (sensors, blocks, logs, queue)
	 * remains fully active; only the API-backed reputation lookups + report
	 * submissions are temporarily silent.
	 *
	 * Short-circuits before consulting the tier-cap helper when none of the
	 * bucket counters has ticked this hour, the snapshot would otherwise
	 * trigger a `get_current_tier()` lookup that can fall through to a live
	 * `/relay-quota` call on installs without a cached tier (30 s timeout
	 * per admin page load).
	 *
	 * @return bool
	 * @since  2.0.5
	 */
	public function is_community_layer_degraded() {
		if ( null !== $this->community_layer_degraded_cache ) {
			return $this->community_layer_degraded_cache;
		}

		if ( ! $this->is_community_mode() ) {
			$this->community_layer_degraded_cache = false;
			return false;
		}

		$server_reset = get_transient( 'reportedip_hive_rate_limit_reset' );
		if ( $server_reset && (int) $server_reset > time() ) {
			$this->community_layer_degraded_cache = true;
			return true;
		}

		$used = array(
			'reputation' => (int) get_transient( 'reportedip_hive_hourly_api_calls_reputation' ),
			'submission' => (int) get_transient( 'reportedip_hive_hourly_api_calls_submission' ),
			'meta'       => (int) get_transient( 'reportedip_hive_hourly_api_calls_meta' ),
		);
		if ( 0 === $used['reputation'] && 0 === $used['submission'] && 0 === $used['meta'] ) {
			$this->community_layer_degraded_cache = false;
			return false;
		}

		$snapshot = $this->get_api_rate_limit_snapshot();
		foreach ( array( 'reputation', 'submission', 'meta' ) as $bucket ) {
			$limit = $snapshot['limits'][ $bucket ] ?? null;
			if ( null === $limit || $limit <= 0 ) {
				continue;
			}
			if ( $used[ $bucket ] >= (int) ceil( $limit * 0.8 ) ) {
				$this->community_layer_degraded_cache = true;
				return true;
			}
		}

		$this->community_layer_degraded_cache = false;
		return false;
	}
}
