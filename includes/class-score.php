<?php
/**
 * Aggregate protection- and hardening-score calculation.
 *
 * Reads the live state of the existing detection sensors and hardening
 * features and condenses each group into a weighted 0-100 score plus a
 * letter grade. The computation is split into a pure {@see self::compute()}
 * stage (no WordPress calls, fully unit-testable) and a data-gathering stage
 * that resolves each item's present/available/enabled flags from options and
 * {@see ReportedIP_Hive_Mode_Manager::feature_status()}. Results are cached in
 * a short-lived transient and invalidated whenever a plugin option changes.
 *
 * Not-yet-built features (Security-Header items, Phase 6) are gated on
 * class_exists and excluded from the score until they ship; tier- or
 * mode-locked features count toward the maximum (and the upgrade potential)
 * but never toward the earned score.
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
 * Calculates the detection and hardening security scores.
 *
 * @since 2.1.2
 */
final class ReportedIP_Hive_Score {

	/**
	 * Transient key holding the computed score blob for both groups.
	 */
	const CACHE_KEY = 'reportedip_hive_score_cache';

	/**
	 * Cache lifetime in seconds.
	 */
	const CACHE_TTL = 600;

	/**
	 * Detection-score item weights. Sum is exactly 100.
	 *
	 * @var array<string,int>
	 */
	const DETECTION_WEIGHTS = array(
		'failed_login'     => 12,
		'waf'              => 15,
		'rest_burst'       => 8,
		'scan_404'         => 8,
		'user_enum'        => 8,
		'geo_anomaly'      => 8,
		'app_password'     => 6,
		'bot_verification' => 8,
		'decoy_pathblock'  => 6,
		'comment_xmlrpc'   => 6,
		'reputation'       => 15,
	);

	/**
	 * Hardening-score item weights. Sum is exactly 100.
	 *
	 * @var array<string,int>
	 */
	const HARDENING_WEIGHTS = array(
		'hide_login'                => 18,
		'twofa_enforce'             => 22,
		'security_headers'          => 15,
		'security_headers_advanced' => 10,
		'password_hibp'             => 15,
		'hardening_mode'            => 10,
		'disposable_block'          => 10,
	);

	/**
	 * Reduce a list of item descriptors to a scored summary.
	 *
	 * Pure function — no WordPress calls. Only items with `present === true`
	 * participate; the maximum is the sum of their weights (renormalisation
	 * base). A present item earns its weight when both available and enabled;
	 * a present-but-unavailable item (tier/mode lock) contributes to the
	 * maximum and to `locked_potential` but never to `earned`.
	 *
	 * @param array<int,array<string,mixed>> $items Item descriptors.
	 * @return array{score:int,grade:string,earned:int,max:int,locked_potential:int,off_potential:int,items:array<int,array<string,mixed>>}
	 * @since  2.1.2
	 */
	public static function compute( array $items ) {
		$earned  = 0;
		$max     = 0;
		$locked  = 0;
		$present = array();

		foreach ( $items as $item ) {
			if ( empty( $item['present'] ) ) {
				continue;
			}
			$weight = (int) ( $item['weight'] ?? 0 );
			$max   += $weight;
			if ( empty( $item['available'] ) ) {
				$locked += $weight;
			} elseif ( ! empty( $item['enabled'] ) ) {
				$earned += $weight;
			}
			$present[] = $item;
		}

		$score = $max > 0 ? (int) round( $earned / $max * 100 ) : 0;

		return array(
			'score'            => $score,
			'grade'            => self::grade_for( $score ),
			'earned'           => $earned,
			'max'              => $max,
			'locked_potential' => $locked,
			'off_potential'    => max( 0, $max - $earned - $locked ),
			'items'            => $present,
		);
	}

	/**
	 * Map a 0-100 score to a Mozilla-Observatory-style letter grade.
	 *
	 * @param int $score Score in the 0-100 range.
	 * @return string A+ | A | B | C | D | F.
	 * @since  2.1.2
	 */
	public static function grade_for( $score ) {
		$score = (int) $score;
		if ( $score >= 95 ) {
			return 'A+';
		}
		if ( $score >= 90 ) {
			return 'A';
		}
		if ( $score >= 80 ) {
			return 'B';
		}
		if ( $score >= 70 ) {
			return 'C';
		}
		if ( $score >= 60 ) {
			return 'D';
		}
		return 'F';
	}

	/**
	 * Computed scores for both groups, served from the transient cache.
	 *
	 * @return array{detection:array<string,mixed>,hardening:array<string,mixed>}
	 * @since  2.1.2
	 */
	public static function all() {
		$cached = get_transient( self::CACHE_KEY );
		if ( is_array( $cached ) && isset( $cached['detection'], $cached['hardening'] ) ) {
			return $cached;
		}

		$data = array(
			'detection' => self::compute( self::detection_items() ),
			'hardening' => self::compute( self::hardening_items() ),
		);

		set_transient( self::CACHE_KEY, $data, self::CACHE_TTL );
		return $data;
	}

	/**
	 * Detection score summary.
	 *
	 * @return array<string,mixed>
	 * @since  2.1.2
	 */
	public static function detection_score() {
		return self::all()['detection'];
	}

	/**
	 * Hardening score summary.
	 *
	 * @return array<string,mixed>
	 * @since  2.1.2
	 */
	public static function hardening_score() {
		return self::all()['hardening'];
	}

	/**
	 * Drop the cached score so the next read recomputes from live state.
	 *
	 * @return void
	 * @since  2.1.2
	 */
	public static function flush_cache() {
		delete_transient( self::CACHE_KEY );
	}

	/**
	 * Flush the cache when a plugin-prefixed option changes.
	 *
	 * Hooked to the generic option-write actions so wizard, import, CLI and
	 * AJAX paths all invalidate the score; an unrelated option write is a
	 * cheap prefix-check no-op.
	 *
	 * @param string $option Option name being written.
	 * @return void
	 * @since  2.1.2
	 */
	public static function flush_on_option_change( $option ) {
		if ( is_string( $option ) && 0 === strpos( $option, 'reportedip_hive_' ) ) {
			self::flush_cache();
		}
	}

	/**
	 * Build the detection-group item descriptors from live sensor state.
	 *
	 * @return array<int,array<string,mixed>>
	 * @since  2.1.2
	 */
	public static function detection_items() {
		$w = self::DETECTION_WEIGHTS;

		return array(
			self::item( 'failed_login', $w['failed_login'], 'detection', __( 'Failed-login monitor', 'reportedip-hive' ), (bool) self::opt( 'reportedip_hive_monitor_failed_logins', true ), self::url( 'reportedip-hive-settings', 'detection' ) ),
			self::item( 'waf', $w['waf'], 'detection', __( 'Web Application Firewall', 'reportedip-hive' ), (bool) self::opt( 'reportedip_hive_waf_enabled', true ), self::url( 'reportedip-hive-firewall', 'waf' ) ),
			self::item( 'rest_burst', $w['rest_burst'], 'detection', __( 'REST-API burst limit', 'reportedip-hive' ), (bool) self::opt( 'reportedip_hive_monitor_rest_api', true ), self::url( 'reportedip-hive-settings', 'detection' ) ),
			self::item( 'scan_404', $w['scan_404'], 'detection', __( 'Scan detector', 'reportedip-hive' ), (bool) self::opt( 'reportedip_hive_monitor_404_scans', true ), self::url( 'reportedip-hive-firewall', 'scan' ) ),
			self::item( 'user_enum', $w['user_enum'], 'detection', __( 'User-enumeration block', 'reportedip-hive' ), (bool) self::opt( 'reportedip_hive_block_user_enumeration', true ), self::url( 'reportedip-hive-settings', 'detection' ) ),
			self::item( 'geo_anomaly', $w['geo_anomaly'], 'detection', __( 'Geo-anomaly detection', 'reportedip-hive' ), (bool) self::opt( 'reportedip_hive_monitor_geo_anomaly', true ), self::url( 'reportedip-hive-settings', 'detection' ) ),
			self::item( 'app_password', $w['app_password'], 'detection', __( 'App-password monitor', 'reportedip-hive' ), (bool) self::opt( 'reportedip_hive_monitor_app_passwords', true ), self::url( 'reportedip-hive-settings', 'detection' ) ),
			self::item( 'bot_verification', $w['bot_verification'], 'detection', __( 'Verified-bot detection', 'reportedip-hive' ), 'off' !== (string) self::opt( 'reportedip_hive_bot_action', 'flag' ), self::url( 'reportedip-hive-firewall', 'bot' ), 'bot_verification' ),
			self::item( 'decoy_pathblock', $w['decoy_pathblock'], 'detection', __( 'Decoy-path block', 'reportedip-hive' ), (bool) self::opt( 'reportedip_hive_decoy_pathblock_enabled', true ), self::url( 'reportedip-hive-firewall', 'scan' ) ),
			self::item( 'comment_xmlrpc', $w['comment_xmlrpc'], 'detection', __( 'Comment & XML-RPC monitor', 'reportedip-hive' ), (bool) self::opt( 'reportedip_hive_monitor_comments', true ) && (bool) self::opt( 'reportedip_hive_monitor_xmlrpc', true ), self::url( 'reportedip-hive-settings', 'detection' ) ),
			self::item( 'reputation', $w['reputation'], 'detection', __( 'Community threat blocking', 'reportedip-hive' ), 'community' === (string) self::opt( 'reportedip_hive_operation_mode', 'local' ) && (bool) self::opt( 'reportedip_hive_auto_block', true ), self::url( 'reportedip-hive-settings', 'general' ), 'reputation_blocking' ),
		);
	}

	/**
	 * Build the hardening-group item descriptors from live feature state.
	 *
	 * @return array<int,array<string,mixed>>
	 * @since  2.1.2
	 */
	public static function hardening_items() {
		$w               = self::HARDENING_WEIGHTS;
		$headers_present = class_exists( 'ReportedIP_Hive_Security_Headers' );

		return array(
			self::item( 'hide_login', $w['hide_login'], 'hardening', __( 'Hide login URL', 'reportedip-hive' ), (bool) self::opt( 'reportedip_hive_hide_login_enabled', false ), self::url( 'reportedip-hive-settings', 'hide_login' ) ),
			self::item( 'twofa_enforce', $w['twofa_enforce'], 'hardening', __( 'Two-factor enforced for a role', 'reportedip-hive' ), self::twofa_enforced(), self::url( 'reportedip-hive-settings', 'two_factor' ) ),
			self::item( 'security_headers', $w['security_headers'], 'hardening', __( 'Security headers (basic)', 'reportedip-hive' ), $headers_present && ReportedIP_Hive_Security_Headers::basic_active(), self::url( 'reportedip-hive-firewall', 'hardening' ), 'security_headers', $headers_present ),
			self::item( 'security_headers_advanced', $w['security_headers_advanced'], 'hardening', __( 'Security headers (advanced)', 'reportedip-hive' ), $headers_present && ReportedIP_Hive_Security_Headers::advanced_active(), self::url( 'reportedip-hive-firewall', 'hardening' ), 'security_headers_advanced', $headers_present ),
			self::item( 'password_hibp', $w['password_hibp'], 'hardening', __( 'Password strength & breach check', 'reportedip-hive' ), (bool) self::opt( 'reportedip_hive_password_policy_enabled', true ), self::url( 'reportedip-hive-settings', 'detection' ) ),
			self::item( 'hardening_mode', $w['hardening_mode'], 'hardening', __( 'Hardening mode', 'reportedip-hive' ), class_exists( 'ReportedIP_Hive_Hardening_Mode' ) && ReportedIP_Hive_Hardening_Mode::is_active(), self::url( 'reportedip-hive-settings', 'hardening_mode' ), 'hardening_mode' ),
			self::item( 'disposable_block', $w['disposable_block'], 'hardening', __( 'Disposable-email defence', 'reportedip-hive' ), 'off' !== (string) self::opt( 'reportedip_hive_disposable_email_action', 'monitor' ), self::url( 'reportedip-hive-firewall', 'spam' ), 'disposable_email' ),
		);
	}

	/**
	 * Assemble a single item descriptor, resolving availability from the
	 * feature matrix when a feature key is supplied.
	 *
	 * @param string  $key          Item key (matches a weight key).
	 * @param int     $weight       Item weight.
	 * @param string  $group        'detection' | 'hardening'.
	 * @param string  $label        Human-readable label.
	 * @param bool    $enabled      Whether the underlying toggle is on.
	 * @param string  $settings_url Deep link to the controlling settings tab.
	 * @param ?string $feature_key  Feature-matrix key for tier/mode gating, or null for Free core.
	 * @param bool    $present      Whether the feature exists in this build.
	 * @return array<string,mixed>
	 * @since  2.1.2
	 */
	private static function item( $key, $weight, $group, $label, $enabled, $settings_url, $feature_key = null, $present = true ) {
		list( $available, $status ) = self::resolve_availability( $feature_key );

		return array(
			'key'          => $key,
			'label'        => $label,
			'weight'       => (int) $weight,
			'group'        => $group,
			'present'      => (bool) $present,
			'available'    => $available,
			'enabled'      => (bool) $enabled,
			'status'       => $status,
			'settings_url' => $settings_url,
		);
	}

	/**
	 * Resolve a feature's availability and raw status from the mode manager.
	 *
	 * @param ?string $feature_key Feature-matrix key, or null for ungated Free core.
	 * @return array{0:bool,1:?array<string,mixed>}
	 * @since  2.1.2
	 */
	private static function resolve_availability( $feature_key ) {
		if ( null === $feature_key || ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			return array( true, null );
		}
		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( $feature_key );
		return array( ! empty( $status['available'] ), $status );
	}

	/**
	 * True when two-factor is enforced for at least one role.
	 *
	 * @return bool
	 * @since  2.1.2
	 */
	private static function twofa_enforced() {
		if ( ! class_exists( 'ReportedIP_Hive_Option_Routing' ) ) {
			return false;
		}
		$roles = ReportedIP_Hive_Option_Routing::resolve_2fa_enforce_roles();
		return is_array( $roles ) && count( $roles ) > 0;
	}

	/**
	 * Read a plugin option through the multisite-aware routing layer.
	 *
	 * @param string $key      Option key.
	 * @param mixed  $fallback Value returned when the option is unset.
	 * @return mixed
	 * @since  2.1.2
	 */
	private static function opt( $key, $fallback ) {
		if ( ! class_exists( 'ReportedIP_Hive_Option_Routing' ) ) {
			return $fallback;
		}
		return ReportedIP_Hive_Option_Routing::get( $key, $fallback );
	}

	/**
	 * Build an admin deep link to a settings/firewall tab.
	 *
	 * @param string $page Admin page slug.
	 * @param string $tab  Tab slug.
	 * @return string
	 * @since  2.1.2
	 */
	private static function url( $page, $tab ) {
		$path = 'admin.php?page=' . $page . '&tab=' . $tab;
		if ( class_exists( 'ReportedIP_Hive_Admin_Settings' ) ) {
			return ReportedIP_Hive_Admin_Settings::get_admin_page_url( $path );
		}
		return admin_url( $path );
	}
}
