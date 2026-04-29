<?php
/**
 * Mode Manager Class for ReportedIP Hive.
 *
 * Manages the dual-mode system (Local Protection vs Community Network).
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
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
	 * Feature definitions for each mode
	 *
	 * @var array
	 */
	private $feature_matrix = array();

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
	}

	/**
	 * Reset the per-request tier memo. Listens on `reportedip_hive_tier_changed`.
	 *
	 * @return void
	 * @since 1.5.3
	 */
	public function flush_cached_tier() {
		$this->cached_tier = null;
	}

	/**
	 * Ensure feature matrix is initialized (lazy loaded to ensure translations are available)
	 *
	 * @return void
	 */
	private function ensure_feature_matrix_loaded() {
		if ( ! empty( $this->feature_matrix ) ) {
			return;
		}

		$this->feature_matrix = array(
			'login_monitoring'             => array(
				'local'       => true,
				'community'   => true,
				'label'       => __( 'Login Monitoring', 'reportedip-hive' ),
				'description' => __( 'Monitor and log failed login attempts', 'reportedip-hive' ),
			),
			'comment_monitoring'           => array(
				'local'       => true,
				'community'   => true,
				'label'       => __( 'Comment Spam Monitoring', 'reportedip-hive' ),
				'description' => __( 'Detect and block spam comments', 'reportedip-hive' ),
			),
			'xmlrpc_monitoring'            => array(
				'local'       => true,
				'community'   => true,
				'label'       => __( 'XMLRPC Monitoring', 'reportedip-hive' ),
				'description' => __( 'Monitor XMLRPC endpoint for abuse', 'reportedip-hive' ),
			),
			'auto_blocking'                => array(
				'local'       => true,
				'community'   => true,
				'label'       => __( 'Automatic IP Blocking', 'reportedip-hive' ),
				'description' => __( 'Automatically block IPs that exceed thresholds', 'reportedip-hive' ),
			),
			'local_blocklist'              => array(
				'local'       => true,
				'community'   => true,
				'label'       => __( 'Local Block/Whitelist', 'reportedip-hive' ),
				'description' => __( 'Manage local IP block and whitelist', 'reportedip-hive' ),
			),
			'local_statistics'             => array(
				'local'       => true,
				'community'   => true,
				'label'       => __( 'Local Statistics', 'reportedip-hive' ),
				'description' => __( 'View local security statistics', 'reportedip-hive' ),
			),

			'api_reputation_check'         => array(
				'local'       => false,
				'community'   => true,
				'label'       => __( 'Community Reputation Check', 'reportedip-hive' ),
				'description' => __( 'Check IP reputation against community database', 'reportedip-hive' ),
			),
			'api_report'                   => array(
				'local'       => false,
				'community'   => true,
				'label'       => __( 'Share Threats with Community', 'reportedip-hive' ),
				'description' => __( 'Report detected threats to the community network', 'reportedip-hive' ),
			),
			'global_blacklist'             => array(
				'local'       => false,
				'community'   => true,
				'label'       => __( 'Global Blacklist', 'reportedip-hive' ),
				'description' => __( 'Access and download the global threat blacklist', 'reportedip-hive' ),
			),
			'reputation_blocking'          => array(
				'local'       => false,
				'community'   => true,
				'label'       => __( 'Reputation-based Blocking', 'reportedip-hive' ),
				'description' => __( 'Block IPs based on community reputation scores', 'reportedip-hive' ),
			),
			'advanced_analytics'           => array(
				'local'       => false,
				'community'   => true,
				'label'       => __( 'Advanced Analytics', 'reportedip-hive' ),
				'description' => __( 'Access advanced threat analytics and trends', 'reportedip-hive' ),
			),
			'threat_intelligence'          => array(
				'local'       => false,
				'community'   => true,
				'label'       => __( 'Threat Intelligence', 'reportedip-hive' ),
				'description' => __( 'Receive threat intelligence from the community', 'reportedip-hive' ),
			),
			'coordinated_attack_detection' => array(
				'local'       => false,
				'community'   => true,
				'label'       => __( 'Coordinated Attack Detection', 'reportedip-hive' ),
				'description' => __( 'Detect coordinated attacks across the network', 'reportedip-hive' ),
			),
			'mail_relay_via_api'           => array(
				'local'         => false,
				'community'     => true,
				'requires_tier' => 'professional',
				'label'         => __( 'Mail Relay via reportedip.de', 'reportedip-hive' ),
				'description'   => __( 'Send 2FA mails through our SMTP for guaranteed deliverability — no own SMTP setup needed.', 'reportedip-hive' ),
			),
			'sms_relay_via_api'            => array(
				'local'         => false,
				'community'     => true,
				'requires_tier' => 'professional',
				'label'         => __( 'SMS Relay via reportedip.de', 'reportedip-hive' ),
				'description'   => __( 'Send 2FA SMS via our managed EU gateway — included with Professional and Business.', 'reportedip-hive' ),
			),
		);
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
	 * @param string $minimum One of TIER_ORDER values.
	 * @return bool
	 */
	public function tier_at_least( $minimum ) {
		$tier     = $this->get_current_tier();
		$ord      = self::TIER_ORDER;
		$idx_have = array_search( $tier, $ord, true );
		$idx_need = array_search( $minimum, $ord, true );
		if ( false === $idx_have || false === $idx_need ) {
			return false;
		}
		return $idx_have >= $idx_need;
	}

	/**
	 * Determine the current tier from cached API state (verify-key or relay-quota).
	 *
	 * @return string
	 */
	public function get_current_tier() {
		if ( null !== $this->cached_tier ) {
			return $this->cached_tier;
		}

		$tier   = 'free';
		$status = get_transient( 'reportedip_hive_api_status' );
		if ( is_array( $status ) ) {
			$role = $status['userRole'] ?? ( $status['user_role'] ?? '' );
			if ( ! empty( $role ) ) {
				$tier              = self::tier_from_role( (string) $role );
				$this->cached_tier = $tier;
				return $tier;
			}
		}
		$quota = get_transient( 'reportedip_hive_relay_quota' );
		if ( is_array( $quota ) && ! empty( $quota['tier'] ) ) {
			$tier              = (string) $quota['tier'];
			$this->cached_tier = $tier;
			return $tier;
		}
		if ( class_exists( 'ReportedIP_Hive_API' ) ) {
			$api = ReportedIP_Hive_API::get_instance();
			if ( method_exists( $api, 'get_relay_quota' ) ) {
				$fresh = $api->get_relay_quota();
				if ( is_array( $fresh ) && ! empty( $fresh['tier'] ) ) {
					$tier              = (string) $fresh['tier'];
					$this->cached_tier = $tier;
					return $tier;
				}
			}
		}
		$this->cached_tier = $tier;
		return $tier;
	}

	/**
	 * Whether the relay (mail or sms) is currently usable.
	 * Requires Community mode + a tier that includes the feature.
	 *
	 * @param string $type 'mail' or 'sms'.
	 * @return bool
	 */
	public function is_relay_available( $type = 'mail' ) {
		$type    = ( 'sms' === $type ) ? 'sms' : 'mail';
		$feature = $type . '_relay_via_api';

		if ( ! $this->is_feature_available( $feature ) ) {
			return false;
		}
		return $this->tier_at_least( 'professional' );
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

		$mode = get_option( self::OPTION_MODE, self::MODE_LOCAL );

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
		if ( ! in_array( $mode, array( self::MODE_LOCAL, self::MODE_COMMUNITY ), true ) ) {
			return false;
		}

		$result = update_option( self::OPTION_MODE, $mode );

		if ( $result || get_option( self::OPTION_MODE ) === $mode ) {
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

			return true;
		}

		return false;
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

		$api_key = get_option( 'reportedip_hive_api_key', '' );
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
	 * Get all available features for current mode
	 *
	 * @return array Features available in current mode
	 */
	public function get_available_features() {
		$this->ensure_feature_matrix_loaded();

		$mode      = $this->get_mode();
		$available = array();

		foreach ( $this->feature_matrix as $key => $feature ) {
			if ( ! empty( $feature[ $mode ] ) ) {
				$available[ $key ] = array(
					'label'       => $feature['label'],
					'description' => $feature['description'],
				);
			}
		}

		return $available;
	}

	/**
	 * Get all features with their availability status
	 *
	 * @return array Complete feature matrix with current status
	 */
	public function get_feature_matrix() {
		$this->ensure_feature_matrix_loaded();

		$mode   = $this->get_mode();
		$matrix = array();

		foreach ( $this->feature_matrix as $key => $feature ) {
			$matrix[ $key ] = array(
				'label'             => $feature['label'],
				'description'       => $feature['description'],
				'available'         => ! empty( $feature[ $mode ] ),
				'local_support'     => $feature['local'],
				'community_support' => $feature['community'],
			);
		}

		return $matrix;
	}

	/**
	 * Get features that would be available by upgrading to community mode
	 *
	 * @return array Features only available in community mode
	 */
	public function get_community_only_features() {
		$this->ensure_feature_matrix_loaded();

		$community_only = array();

		foreach ( $this->feature_matrix as $key => $feature ) {
			if ( ! $feature['local'] && $feature['community'] ) {
				$community_only[ $key ] = array(
					'label'       => $feature['label'],
					'description' => $feature['description'],
				);
			}
		}

		return $community_only;
	}

	/**
	 * Check if setup wizard has been completed
	 *
	 * @return bool
	 */
	public function is_wizard_completed() {
		return (bool) get_option( self::OPTION_WIZARD_COMPLETED, false );
	}

	/**
	 * Mark setup wizard as completed
	 *
	 * @return bool
	 */
	public function mark_wizard_completed() {
		update_option( self::OPTION_WIZARD_COMPLETED, true );
		update_option( self::OPTION_WIZARD_COMPLETED_AT, current_time( 'mysql' ) );

		delete_option( self::OPTION_WIZARD_SKIPPED );

		return true;
	}

	/**
	 * Check if wizard was skipped
	 *
	 * @return bool
	 */
	public function is_wizard_skipped() {
		return (bool) get_option( self::OPTION_WIZARD_SKIPPED, false );
	}

	/**
	 * Mark wizard as skipped
	 *
	 * @return bool
	 */
	public function skip_wizard() {
		update_option( self::OPTION_WIZARD_SKIPPED, true );
		return true;
	}

	/**
	 * Check if wizard should be shown
	 *
	 * Shows wizard if:
	 * - Not completed AND not skipped
	 * - Plugin was just activated (first time)
	 *
	 * @return bool
	 */
	public function should_show_wizard() {
		if ( $this->is_wizard_completed() ) {
			return false;
		}

		if ( $this->is_wizard_skipped() ) {
			return false;
		}

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
	 *  - 'ok'      — feature is available
	 *  - 'mode'    — current operation mode does not include the feature
	 *  - 'tier'    — current tier is below the required minimum tier
	 *  - 'unknown' — feature key is not present in the matrix
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
				'label'         => (string) ( $row['label'] ?? '' ),
				'description'   => (string) ( $row['description'] ?? '' ),
			);
		}

		if ( null !== $min_tier && ! $this->tier_at_least( $min_tier ) ) {
			return array(
				'available'     => false,
				'reason'        => 'tier',
				'min_tier'      => $min_tier,
				'mode_required' => null,
				'label'         => (string) ( $row['label'] ?? '' ),
				'description'   => (string) ( $row['description'] ?? '' ),
			);
		}

		return array(
			'available'     => true,
			'reason'        => 'ok',
			'min_tier'      => $min_tier,
			'mode_required' => null,
			'label'         => (string) ( $row['label'] ?? '' ),
			'description'   => (string) ( $row['description'] ?? '' ),
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
				'label'       => __( 'Free', 'reportedip-hive' ),
				'short_label' => __( 'Free', 'reportedip-hive' ),
				'description' => __( 'Local protection, free forever.', 'reportedip-hive' ),
				'icon'        => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
				'badge_class' => 'rip-tier-badge--free',
				'color'       => '#9CA3AF',
			),
			'contributor'  => array(
				'key'         => 'contributor',
				'label'       => __( 'Contributor', 'reportedip-hive' ),
				'short_label' => __( 'Contrib.', 'reportedip-hive' ),
				'description' => __( 'Honeypot operator — community contributor.', 'reportedip-hive' ),
				'icon'        => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M9 12l2 2 4-5"/></svg>',
				'badge_class' => 'rip-tier-badge--contributor',
				'color'       => '#818CF8',
			),
			'professional' => array(
				'key'         => 'professional',
				'label'       => __( 'Professional', 'reportedip-hive' ),
				'short_label' => __( 'PRO', 'reportedip-hive' ),
				'description' => __( 'Up to 3 domains, managed mail and SMS relay, priority sync.', 'reportedip-hive' ),
				'icon'        => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 2l2.4 4.9 5.4.8-3.9 3.8.9 5.4L12 14.3 7.2 16.9l.9-5.4L4.2 7.7l5.4-.8L12 2z"/></svg>',
				'badge_class' => 'rip-tier-badge--professional',
				'color'       => '#4F46E5',
			),
			'business'     => array(
				'key'         => 'business',
				'label'       => __( 'Business', 'reportedip-hive' ),
				'short_label' => __( 'Business', 'reportedip-hive' ),
				'description' => __( 'Agency-grade: 15 domains, whitelabel, WooCommerce, full WP-CLI.', 'reportedip-hive' ),
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

	/**
	 * Default monthly relay limits by tier (mail, sms) per pricing plan.
	 *
	 * @param string $tier Tier key.
	 * @return array{mail:?int,sms:?int}
	 * @since 1.5.3
	 */
	private function default_relay_limits_for_tier( $tier ) {
		switch ( (string) $tier ) {
			case 'professional':
				return array(
					'mail' => 500,
					'sms'  => 25,
				);
			case 'business':
				return array(
					'mail' => 2500,
					'sms'  => 75,
				);
			case 'enterprise':
				return array(
					'mail' => null,
					'sms'  => null,
				);
			default:
				return array(
					'mail' => 0,
					'sms'  => 0,
				);
		}
	}

	/**
	 * Normalized snapshot of the current relay quota, suitable for the dashboard widget.
	 *
	 * Reads transient `reportedip_hive_relay_quota` (populated by API client / cron) and
	 * fills missing fields with defaults derived from the current tier so the UI always
	 * has something sensible to render.
	 *
	 * @return array{tier:string,period_start:?int,period_end:?int,mail:array{used:int,limit:?int},sms:array{used:int,limit:?int},sms_bundle_balance:int,fetched_at:?int,is_stale:bool}
	 * @since 1.5.3
	 */
	public function get_relay_quota_snapshot() {
		$tier     = $this->get_current_tier();
		$defaults = $this->default_relay_limits_for_tier( $tier );

		$snapshot = array(
			'tier'               => $tier,
			'period_start'       => null,
			'period_end'         => null,
			'mail'               => array(
				'used'  => 0,
				'limit' => $defaults['mail'],
			),
			'sms'                => array(
				'used'  => 0,
				'limit' => $defaults['sms'],
			),
			'sms_bundle_balance' => 0,
			'fetched_at'         => null,
			'is_stale'           => true,
		);

		$cached = get_transient( 'reportedip_hive_relay_quota' );
		if ( ! is_array( $cached ) ) {
			return $snapshot;
		}

		if ( ! empty( $cached['tier'] ) ) {
			$snapshot['tier'] = (string) $cached['tier'];
		}
		if ( isset( $cached['period_start'] ) ) {
			$snapshot['period_start'] = (int) $cached['period_start'];
		}
		if ( isset( $cached['period_end'] ) ) {
			$snapshot['period_end'] = (int) $cached['period_end'];
		}
		if ( isset( $cached['mail'] ) && is_array( $cached['mail'] ) ) {
			$snapshot['mail']['used']  = (int) ( $cached['mail']['used'] ?? 0 );
			$snapshot['mail']['limit'] = array_key_exists( 'limit', $cached['mail'] ) ? ( null === $cached['mail']['limit'] ? null : (int) $cached['mail']['limit'] ) : $defaults['mail'];
		}
		if ( isset( $cached['sms'] ) && is_array( $cached['sms'] ) ) {
			$snapshot['sms']['used']  = (int) ( $cached['sms']['used'] ?? 0 );
			$snapshot['sms']['limit'] = array_key_exists( 'limit', $cached['sms'] ) ? ( null === $cached['sms']['limit'] ? null : (int) $cached['sms']['limit'] ) : $defaults['sms'];
		}
		if ( isset( $cached['sms_bundle_balance'] ) ) {
			$snapshot['sms_bundle_balance'] = (int) $cached['sms_bundle_balance'];
		}
		if ( isset( $cached['fetched_at'] ) ) {
			$snapshot['fetched_at'] = (int) $cached['fetched_at'];
		}

		$age_threshold = 24 * HOUR_IN_SECONDS;
		if ( null !== $snapshot['fetched_at'] && ( time() - $snapshot['fetched_at'] ) < $age_threshold ) {
			$snapshot['is_stale'] = false;
		}

		return $snapshot;
	}
}
