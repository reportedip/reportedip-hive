<?php
/**
 * Option side-effect dispatcher, executes registry-declared side effects
 * (rewrite flushes, cache flushes) for every writer identically, replacing
 * the effects that historically lived inside Settings-API sanitizers.
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
 * Watches option updates for keys with declared side effects and runs each
 * queued effect exactly once per request on shutdown, regardless of whether
 * the write came from the settings page, the wizard, an import, WP-CLI or a
 * remote management channel.
 *
 * @since 2.1.47
 */
final class ReportedIP_Hive_Settings_Effects {

	/**
	 * Effect tokens queued for this request.
	 *
	 * @var array<string, bool>
	 */
	private static $queued = array();

	/**
	 * Whether the shutdown runner has been hooked for this request.
	 *
	 * @var bool
	 */
	private static $hooked_shutdown = false;

	/**
	 * Register option-update watchers for every key that declares side
	 * effects, both `update_option_*` (single site) and
	 * `update_site_option_*` (network) fire for any writer.
	 *
	 * Runs on `init` at priority 0, not from the plugin constructor: reading
	 * the registry translates every label, and WordPress 6.7+ refuses to load
	 * a text domain before `init`. With `WP_DEBUG_DISPLAY` on, that notice is
	 * printed before any header and kills every front-end request. Nothing
	 * writes a watched option earlier than `init`, activation included.
	 *
	 * @return void
	 */
	public static function init() {
		foreach ( self::watched() as $option => $tokens ) {
			$callback = static function () use ( $tokens ) {
				foreach ( $tokens as $token ) {
					self::queue( $token );
				}
			};
			add_action( 'update_option_' . $option, $callback );
			add_action( 'add_option_' . $option, $callback );
			add_action( 'update_site_option_' . $option, $callback );
			add_action( 'add_site_option_' . $option, $callback );
		}
	}

	/**
	 * Watched option => effect-token map, read from the registry's
	 * `side_effects` declarations.
	 *
	 * @return array<string, string[]>
	 */
	public static function watched() {
		$map = array();
		foreach ( ReportedIP_Hive_Settings_Registry::spec() as $key => $entry ) {
			if ( ! empty( $entry['side_effects'] ) ) {
				$map[ $key ] = array_values( (array) $entry['side_effects'] );
			}
		}
		return $map;
	}

	/**
	 * All effect tokens this dispatcher knows how to run.
	 *
	 * @return string[]
	 */
	public static function known_tokens() {
		return array( 'flush_rewrite', 'flush_2fa_frontend_memo', 'stamp_form_proof_pow', 'stamp_form_adapters_since', 'purge_pages_for_form_proof' );
	}

	/**
	 * Queue one effect token for execution on shutdown. Duplicate tokens
	 * collapse, so a 60-key batch triggers each effect at most once.
	 *
	 * @param string $token Effect token.
	 * @return void
	 */
	public static function queue( $token ) {
		if ( ! in_array( $token, self::known_tokens(), true ) ) {
			return;
		}
		self::$queued[ $token ] = true;

		if ( ! self::$hooked_shutdown ) {
			self::$hooked_shutdown = true;
			add_action( 'shutdown', array( __CLASS__, 'run_queued' ) );
		}
	}

	/**
	 * Execute every queued effect once and reset the queue.
	 *
	 * @return void
	 */
	public static function run_queued() {
		$tokens       = array_keys( self::$queued );
		self::$queued = array();

		foreach ( $tokens as $token ) {
			switch ( $token ) {
				case 'flush_rewrite':
					if ( function_exists( 'flush_rewrite_rules' ) ) {
						flush_rewrite_rules( false );
					}
					break;

				case 'flush_2fa_frontend_memo':
					if ( class_exists( 'ReportedIP_Hive_Two_Factor_Frontend' ) ) {
						ReportedIP_Hive_Two_Factor_Frontend::flush_memo();
					}
					break;

				case 'stamp_form_proof_pow':
					if ( class_exists( 'ReportedIP_Hive_Form_Proof' ) ) {
						ReportedIP_Hive_Form_Proof::stamp_pow_since();
					}
					break;

				case 'stamp_form_adapters_since':
					if ( class_exists( 'ReportedIP_Hive_Form_Proof' ) ) {
						ReportedIP_Hive_Form_Proof::stamp_adapters_since();
					}
					break;

				case 'purge_pages_for_form_proof':
					if ( class_exists( 'ReportedIP_Hive_Form_Proof' ) ) {
						ReportedIP_Hive_Form_Proof::purge_on_enable();
					}
					break;
			}
		}
	}
}
