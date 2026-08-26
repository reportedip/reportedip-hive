<?php
/**
 * Transport-agnostic settings apply service — the single entry point every
 * remote management channel (MainWP, the future reportedip.com API) and the
 * settings import use to write registry-managed options.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.47
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Validates a settings batch against the registry, writes the changes and
 * reports a per-key result map plus the fresh settings fingerprint.
 *
 * @since 2.1.47
 */
final class ReportedIP_Hive_Settings_Apply {

	/**
	 * Per-key result status: value written.
	 */
	const STATUS_APPLIED = 'applied';

	/**
	 * Per-key result status: sanitized value equals the stored value.
	 */
	const STATUS_UNCHANGED = 'unchanged';

	/**
	 * Per-key result status: value requires a higher plan on this site.
	 */
	const STATUS_SKIPPED_TIER = 'skipped_tier';

	/**
	 * Per-key result status: value rejected by validation.
	 */
	const STATUS_INVALID = 'invalid';

	/**
	 * Per-key result status: key is not part of the remote registry.
	 */
	const STATUS_UNKNOWN = 'unknown_key';

	/**
	 * Apply a batch of settings values.
	 *
	 * Pipeline: filter to remote keys, sanitize each (tier gate included),
	 * run cross-field validation, compare normalized against the stored
	 * state, write changes via the option router (side effects fire through
	 * the registered option-update watchers) and log one audit event.
	 *
	 * @param array<string, mixed> $values Incoming key => value map.
	 * @param string               $origin Transport identifier (`mainwp`, `import`, `cloud`).
	 * @return array{schema_version:int, results:array<string, array<string, string>>, applied:int, unchanged:int, failed:int, hash:string}
	 */
	public static function apply( array $values, $origin ) {
		$remote_spec = ReportedIP_Hive_Settings_Registry::remote_spec();
		$results     = array();
		$sanitized   = array();

		foreach ( $values as $key => $value ) {
			if ( ! is_string( $key ) || ! isset( $remote_spec[ $key ] ) ) {
				$results[ (string) $key ] = array( 'status' => self::STATUS_UNKNOWN );
				continue;
			}

			$clean = ReportedIP_Hive_Settings_Registry::sanitize( $key, $value );
			if ( is_wp_error( $clean ) ) {
				$results[ $key ] = array(
					'status'  => 'tier_locked' === $clean->get_error_code() ? self::STATUS_SKIPPED_TIER : self::STATUS_INVALID,
					'message' => $clean->get_error_message(),
				);
				continue;
			}

			$sanitized[ $key ] = $clean;
		}

		$current      = ReportedIP_Hive_Settings_Registry::current_values();
		$batch_errors = ReportedIP_Hive_Settings_Registry::validate_batch( $sanitized, $current );
		foreach ( $batch_errors as $key => $error ) {
			$results[ $key ] = array(
				'status'  => self::STATUS_INVALID,
				'message' => $error->get_error_message(),
			);
			unset( $sanitized[ $key ] );
		}

		$applied   = 0;
		$unchanged = 0;

		foreach ( $sanitized as $key => $value ) {
			$same = ReportedIP_Hive_Settings_Registry::normalize_value( $key, $value )
				=== ReportedIP_Hive_Settings_Registry::normalize_value( $key, $current[ $key ] );

			if ( $same ) {
				$results[ $key ] = array( 'status' => self::STATUS_UNCHANGED );
				++$unchanged;
				continue;
			}

			ReportedIP_Hive_Option_Routing::set( $key, $value );
			$results[ $key ] = array( 'status' => self::STATUS_APPLIED );
			++$applied;
		}

		$failed = 0;
		foreach ( $results as $result ) {
			if ( in_array( $result['status'], array( self::STATUS_INVALID, self::STATUS_UNKNOWN ), true ) ) {
				++$failed;
			}
		}

		if ( $applied > 0 ) {
			self::log_apply( (string) $origin, $applied, $unchanged, $failed );
		}

		return array(
			'schema_version' => ReportedIP_Hive_Settings_Registry::SCHEMA_VERSION,
			'results'        => $results,
			'applied'        => $applied,
			'unchanged'      => $unchanged,
			'failed'         => $failed,
			'hash'           => ReportedIP_Hive_Settings_Registry::settings_hash(),
		);
	}

	/**
	 * Error envelope returned when a transport delivers an undecodable
	 * `values_json` payload — shared by every transport so the error shape
	 * cannot drift between MainWP and the cloud API.
	 *
	 * @return array{schema_version:int, results:array<string, array<string, string>>, applied:int, unchanged:int, failed:int, error:string, hash:string}
	 * @since  2.1.48
	 */
	public static function invalid_payload_envelope() {
		return array(
			'schema_version' => ReportedIP_Hive_Settings_Registry::SCHEMA_VERSION,
			'results'        => array(),
			'applied'        => 0,
			'unchanged'      => 0,
			'failed'         => 0,
			'error'          => 'invalid_payload',
			'hash'           => ReportedIP_Hive_Settings_Registry::settings_hash(),
		);
	}

	/**
	 * Write one security-log event for an apply batch that changed values.
	 *
	 * @param string $origin    Transport identifier.
	 * @param int    $applied   Keys written.
	 * @param int    $unchanged Keys already at the target value.
	 * @param int    $failed    Keys rejected.
	 * @return void
	 */
	private static function log_apply( $origin, $applied, $unchanged, $failed ) {
		if ( ! class_exists( 'ReportedIP_Hive_Logger' ) ) {
			return;
		}

		$remote_ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		ReportedIP_Hive_Logger::get_instance()->log_security_event(
			'settings_remote_apply',
			$remote_ip,
			array(
				'origin'    => $origin,
				'applied'   => $applied,
				'unchanged' => $unchanged,
				'failed'    => $failed,
			),
			'low'
		);
	}
}
