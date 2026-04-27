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
		);
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
}
