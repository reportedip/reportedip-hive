<?php
/**
 * Audit connector for site, network and Hive settings.
 *
 * One listener on `updated_option` and one on `update_site_option`, with a
 * whitelist: the core options of {@see ReportedIP_Hive_Audit_Registry} and
 * every key of the Hive settings registry. Listening on the option write
 * covers every writer the same way (Protection page, quickstart, import,
 * MainWP, cloud fleet, WP-CLI), which is also how the settings side effects
 * are wired. The old and the new value are stored, cut to length, lists as
 * a diff, and a key that names a secret keeps its values out.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.62
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Settings change capture.
 *
 * @since 2.1.62
 */
class ReportedIP_Hive_Audit_Connector_Settings extends ReportedIP_Hive_Audit_Connector {

	/**
	 * Hooks of this connector.
	 *
	 * @return array<string, array{0:string, 1:int, 2:int}>
	 * @since  2.1.62
	 */
	protected function hooks() {
		return array(
			'updated_option'     => array( 'on_option', 10, 3 ),
			'update_site_option' => array( 'on_site_option', 10, 4 ),
		);
	}

	/**
	 * Whether an option name is on the watch list, and under which label.
	 *
	 * @param string $option  Option name.
	 * @param bool   $network Whether the write was a network option.
	 * @return string|null Label, or null when not watched.
	 * @since  2.1.62
	 */
	public static function watched_label( $option, $network = false ) {
		$option = (string) $option;
		if ( $network ) {
			$labels = ReportedIP_Hive_Audit_Registry::network_options();
			if ( isset( $labels[ $option ] ) ) {
				return $labels[ $option ];
			}
		} else {
			$labels = ReportedIP_Hive_Audit_Registry::core_options();
			if ( isset( $labels[ $option ] ) ) {
				return $labels[ $option ];
			}
		}
		if ( class_exists( 'ReportedIP_Hive_Settings_Registry' ) ) {
			$spec = ReportedIP_Hive_Settings_Registry::spec();
			if ( isset( $spec[ $option ] ) ) {
				return (string) ( $spec[ $option ]['label'] ?? $option );
			}
		}
		return null;
	}

	/**
	 * Whether the option name itself marks a secret.
	 *
	 * `Audit_Logger::redact()` only sees data keys, and the values sit under
	 * `old` and `new`, so the check has to run on the option name.
	 *
	 * @param string $option Option name.
	 * @return bool
	 * @since  2.1.62
	 */
	public static function is_secret( $option ) {
		$lower = strtolower( (string) $option );
		foreach ( ReportedIP_Hive_Audit_Logger::REDACT_KEYS as $needle ) {
			if ( false !== strpos( $lower, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Site option changed.
	 *
	 * @param string $option Option name.
	 * @param mixed  $old    Previous value.
	 * @param mixed  $new    New value.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_option( $option, $old, $new ) {
		$option = (string) $option;
		global $wpdb;
		if ( $wpdb->prefix . 'user_roles' === $option ) {
			$this->log_roles( $old, $new );
			return;
		}
		$this->log_change( $option, $old, $new, false );
	}

	/**
	 * Network option changed. Core passes the new value before the old one here.
	 *
	 * @param string $option     Option name.
	 * @param mixed  $new        New value.
	 * @param mixed  $old        Previous value.
	 * @param int    $network_id Network id.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_site_option( $option, $new, $old, $network_id = 0 ) {
		unset( $network_id );
		$this->log_change( (string) $option, $old, $new, true );
	}

	/**
	 * One row for one watched option.
	 *
	 * @param string $option  Option name.
	 * @param mixed  $old     Previous value.
	 * @param mixed  $new     New value.
	 * @param bool   $network Network option.
	 * @return void
	 * @since  2.1.62
	 */
	private function log_change( $option, $old, $new, $network ) {
		$label = self::watched_label( $option, $network );
		if ( null === $label ) {
			return;
		}
		if ( self::is_secret( $option ) ) {
			$old = '';
			$new = '';
		}
		$old_row = self::value_for_row( $old, $new );
		$new_row = self::value_for_row( $new, $old );
		if ( $old_row === $new_row ) {
			return;
		}
		if ( self::seen( 'setting:' . $option . ':' . md5( wp_json_encode( array( $old_row, $new_row ) ) ) ) ) {
			return;
		}
		$this->log(
			'setting',
			'updated',
			array(
				'option'  => $option,
				'old'     => $old_row,
				'new'     => $new_row,
				'network' => $network ? 1 : 0,
			),
			array(
				'type'  => 'option',
				'id'    => 0,
				'label' => $label,
			),
			$network ? 0 : null
		);
	}

	/**
	 * Role table changed: added or removed roles and roles whose capabilities differ.
	 *
	 * @param mixed $old Previous `user_roles` blob.
	 * @param mixed $new New blob.
	 * @return void
	 * @since  2.1.62
	 */
	private function log_roles( $old, $new ) {
		if ( ! ReportedIP_Hive_Audit_Registry::group_enabled( 'users' ) ) {
			return;
		}
		$diff = self::diff_roles( is_array( $old ) ? $old : array(), is_array( $new ) ? $new : array() );
		if ( empty( $diff['added'] ) && empty( $diff['removed'] ) && empty( $diff['caps_changed'] ) ) {
			return;
		}
		if ( self::seen( 'roles:' . md5( wp_json_encode( $diff ) ) ) ) {
			return;
		}
		$this->log(
			'role',
			'caps_changed',
			$diff,
			array(
				'type'  => 'roles',
				'id'    => 0,
				'label' => __( 'User roles', 'reportedip-hive' ),
			)
		);
	}

	/**
	 * Pure diff of two role tables.
	 *
	 * @param array<string, array<string,mixed>> $old Old roles.
	 * @param array<string, array<string,mixed>> $new New roles.
	 * @return array{added:string[], removed:string[], caps_changed:string[]}
	 * @since  2.1.62
	 */
	public static function diff_roles( array $old, array $new ) {
		$added   = array_values( array_diff( array_keys( $new ), array_keys( $old ) ) );
		$removed = array_values( array_diff( array_keys( $old ), array_keys( $new ) ) );
		$changed = array();
		foreach ( array_intersect( array_keys( $old ), array_keys( $new ) ) as $role ) {
			$old_caps = (array) ( $old[ $role ]['capabilities'] ?? array() );
			$new_caps = (array) ( $new[ $role ]['capabilities'] ?? array() );
			ksort( $old_caps );
			ksort( $new_caps );
			if ( $old_caps !== $new_caps ) {
				$changed[] = (string) $role;
			}
		}
		return array(
			'added'        => array_map( 'strval', $added ),
			'removed'      => array_map( 'strval', $removed ),
			'caps_changed' => $changed,
		);
	}
}
