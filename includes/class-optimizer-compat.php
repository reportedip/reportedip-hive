<?php
/**
 * Exclusions handed to caching and optimisation plugins.
 *
 * Optimisers rewrite the front end: they strip CSS they consider unused,
 * hold scripts back until the first interaction, defer, combine and minify
 * them. Applied to the form proof that breaks protection in two ways. An
 * emptied inline style leaves the decoy field visible, autofill fills it and
 * a real visitor is judged a certain bot. A delayed proof script runs after
 * the click it should answer, and the submission is refused. Every optimiser
 * offers a way out; this class takes it for the assets that must stay as
 * they are, so no site owner has to maintain a list by hand.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     3.0.7
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registers the plugin's critical assets with every known optimiser.
 *
 * Each callback only appends to a list the optimiser passes in, so it is
 * harmless while that optimiser is not installed.
 *
 * @since 3.0.7
 */
final class ReportedIP_Hive_Optimizer_Compat {

	/**
	 * Attributes put on every critical script tag. Several optimisers honour
	 * them without any filter: Cloudflare Rocket Loader and LiteSpeed
	 * (`data-cfasync`), LiteSpeed (`data-no-optimize`, `data-no-defer`),
	 * WP Rocket (`data-no-minify`, and `nowprocket` anywhere in the tag for
	 * its delay list), Autoptimize and Breeze (`data-noptimize`), Jetpack
	 * Boost and NitroPack.
	 */
	const SCRIPT_ATTRIBUTES = 'data-cfasync="false" data-no-optimize="1" data-no-defer="1" data-no-minify="1" data-noptimize="1" data-nowprocket data-jetpack-boost="ignore" nitro-exclude';

	/**
	 * Optimiser filters that take a list of CSS selectors to keep.
	 *
	 * @var string[]
	 */
	const SELECTOR_FILTERS = array(
		'rocket_rucss_safelist',
		'litespeed_ucss_whitelist',
		'perfmatters_rucss_excluded_selectors',
	);

	/**
	 * Optimiser filters that take literal fragments of a style tag's attributes.
	 *
	 * @var string[]
	 */
	const STYLE_ID_FILTERS = array(
		'rocket_rucss_inline_atts_exclusions',
	);

	/**
	 * Optimiser filters that take literal fragments of a script URL or tag.
	 *
	 * @var string[]
	 */
	const PATH_FILTERS = array(
		'litespeed_optm_js_defer_exc',
		'litespeed_optimize_js_excludes',
		'litespeed_optm_gm_js_exc',
		'perfmatters_delay_js_exclusions',
		'perfmatters_defer_js_exclusions',
		'perfmatters_minify_js_exclusions',
		'flying_press_exclude_from_delay:js',
		'flying_press_exclude_from_defer:js',
		'flying_press_exclude_from_minify:js',
		'wp-optimize-minify-default-exclusions',
	);

	/**
	 * Optimiser filters that take regular expressions matched against a
	 * script URL or tag (WP Rocket wraps each entry in `#` delimiters).
	 *
	 * @var string[]
	 */
	const PATTERN_FILTERS = array(
		'rocket_delay_js_exclusions',
		'rocket_exclude_defer_js',
		'rocket_exclude_js',
	);

	/**
	 * Optimiser filters that take a comma separated string (or an array) of
	 * fragments matched against the script tag.
	 *
	 * @var string[]
	 */
	const CSV_FILTERS = array(
		'autoptimize_filter_js_exclude',
		'breeze_filter_js_exclude',
	);

	/**
	 * Optimiser filters that take a list of script handles.
	 *
	 * @var string[]
	 */
	const HANDLE_FILTERS = array(
		'sgo_js_minify_exclude',
		'sgo_js_async_exclude',
		'sgo_javascript_combine_exclude',
		'jetpack_boost_render_blocking_js_exclude_handles',
		'wphb_dont_combine_handles',
	);

	/**
	 * Optimiser filters that ask per handle whether to touch it; the handle
	 * is the second argument.
	 *
	 * @var string[]
	 */
	const HANDLE_VETO_FILTERS = array(
		'wphb_minify_resource',
		'wphb_combine_resource',
		'wphb_defer_resource',
		'js_do_concat',
	);

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton.
	 *
	 * @return self
	 * @since  3.0.7
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Hook into every optimiser filter.
	 *
	 * @since 3.0.7
	 */
	private function __construct() {
		foreach ( self::SELECTOR_FILTERS as $filter ) {
			add_filter( $filter, array( __CLASS__, 'add_selectors' ) );
		}
		foreach ( self::STYLE_ID_FILTERS as $filter ) {
			add_filter( $filter, array( __CLASS__, 'add_style_ids' ) );
		}
		foreach ( self::PATH_FILTERS as $filter ) {
			add_filter( $filter, array( __CLASS__, 'add_paths' ) );
		}
		foreach ( self::PATTERN_FILTERS as $filter ) {
			add_filter( $filter, array( __CLASS__, 'add_patterns' ) );
		}
		foreach ( self::CSV_FILTERS as $filter ) {
			add_filter( $filter, array( __CLASS__, 'add_csv' ) );
		}
		foreach ( self::HANDLE_FILTERS as $filter ) {
			add_filter( $filter, array( __CLASS__, 'add_handles' ) );
		}
		foreach ( self::HANDLE_VETO_FILTERS as $filter ) {
			add_filter( $filter, array( __CLASS__, 'veto_handle' ), 10, 2 );
		}
		add_filter( 'w3tc_minify_js_do_tag_minification', array( __CLASS__, 'veto_tag' ), 10, 2 );
		add_filter( 'script_loader_tag', array( __CLASS__, 'script_tag' ), 10, 2 );
	}

	/**
	 * The assets no optimiser may rewrite.
	 *
	 * @return array{handles: string[], js_paths: string[], css_ids: string[], selectors: string[]}
	 * @since  3.0.7
	 */
	public static function exclusions() {
		$defaults = array(
			'handles'   => array( 'reportedip-hive-form-proof', 'reportedip-hive-two-factor-login' ),
			'js_paths'  => array( '/assets/js/form-proof', '/assets/js/two-factor-login' ),
			'css_ids'   => array( 'reportedip-hive-form-proof-inline-css' ),
			'selectors' => array( '.rip-hp-field' ),
		);

		/**
		 * Assets that caching and optimisation plugins must leave alone.
		 *
		 * `handles` are script handles, `js_paths` fragments of their URLs
		 * (literal, matched anywhere), `css_ids` ids of inline style tags and
		 * `selectors` CSS selectors an unused-CSS remover must keep.
		 *
		 * @param array<string, string[]> $exclusions Lists by kind.
		 * @since 3.0.7
		 */
		$filtered = apply_filters( 'reportedip_hive_optimizer_exclusions', $defaults );

		$out = array();
		foreach ( array_keys( $defaults ) as $kind ) {
			$items        = is_array( $filtered ) && isset( $filtered[ $kind ] ) ? (array) $filtered[ $kind ] : $defaults[ $kind ];
			$out[ $kind ] = array_values( array_unique( array_filter( array_map( 'strval', $items ) ) ) );
		}

		return $out;
	}

	/**
	 * Append entries to an optimiser's list without duplicates.
	 *
	 * @param mixed    $items   Incoming list.
	 * @param string[] $entries Entries to add.
	 * @return array<int|string, mixed>
	 */
	private static function merge( $items, array $entries ) {
		$items = is_array( $items ) ? $items : ( '' === (string) $items ? array() : array( (string) $items ) );
		foreach ( $entries as $entry ) {
			if ( ! in_array( $entry, $items, true ) ) {
				$items[] = $entry;
			}
		}
		return $items;
	}

	/**
	 * Keep the decoy selectors through unused-CSS removal.
	 *
	 * @param mixed $items Selectors.
	 * @return array<int|string, mixed>
	 * @since  3.0.7
	 */
	public static function add_selectors( $items ) {
		return self::merge( $items, self::exclusions()['selectors'] );
	}

	/**
	 * Keep the inline style tags through unused-CSS removal.
	 *
	 * @param mixed $items Attribute fragments.
	 * @return array<int|string, mixed>
	 * @since  3.0.7
	 */
	public static function add_style_ids( $items ) {
		return self::merge( $items, self::exclusions()['css_ids'] );
	}

	/**
	 * Exclude the scripts by URL fragment.
	 *
	 * @param mixed $items Fragments.
	 * @return array<int|string, mixed>
	 * @since  3.0.7
	 */
	public static function add_paths( $items ) {
		return self::merge( $items, self::exclusions()['js_paths'] );
	}

	/**
	 * Exclude the scripts by pattern, each fragment quoted for `#` delimiters.
	 *
	 * @param mixed $items Patterns.
	 * @return array<int|string, mixed>
	 * @since  3.0.7
	 */
	public static function add_patterns( $items ) {
		return self::merge(
			$items,
			array_map(
				static function ( $path ) {
					return preg_quote( $path, '#' );
				},
				self::exclusions()['js_paths']
			)
		);
	}

	/**
	 * Exclude the scripts from a comma separated list. An array stays an
	 * array (Autoptimize accepts both).
	 *
	 * @param mixed $items Comma separated fragments or an array.
	 * @return string|array<int|string, mixed>
	 * @since  3.0.7
	 */
	public static function add_csv( $items ) {
		if ( is_array( $items ) ) {
			return self::merge( $items, self::exclusions()['js_paths'] );
		}

		$parts = array_filter( array_map( 'trim', explode( ',', (string) $items ) ) );
		return implode( ', ', self::merge( array_values( $parts ), self::exclusions()['js_paths'] ) );
	}

	/**
	 * Exclude the scripts by handle.
	 *
	 * @param mixed $items Handles.
	 * @return array<int|string, mixed>
	 * @since  3.0.7
	 */
	public static function add_handles( $items ) {
		return self::merge( $items, self::exclusions()['handles'] );
	}

	/**
	 * Answer "no" for a critical handle, pass every other answer through.
	 *
	 * @param mixed $value  Optimiser's answer.
	 * @param mixed $handle Asset handle.
	 * @return mixed
	 * @since  3.0.7
	 */
	public static function veto_handle( $value, $handle = '' ) {
		return in_array( (string) $handle, self::exclusions()['handles'], true ) ? false : $value;
	}

	/**
	 * Answer "no" for a script tag that loads a critical file.
	 *
	 * @param mixed $value Optimiser's answer.
	 * @param mixed $tag   Script tag.
	 * @return mixed
	 * @since  3.0.7
	 */
	public static function veto_tag( $value, $tag = '' ) {
		foreach ( self::exclusions()['js_paths'] as $path ) {
			if ( false !== strpos( (string) $tag, $path ) ) {
				return false;
			}
		}
		return $value;
	}

	/**
	 * Mark a critical script tag with the attributes optimisers honour.
	 * They go right after `<script`, ahead of `src`, which Rocket Loader
	 * requires.
	 *
	 * @param string $tag    Script tag.
	 * @param string $handle Script handle.
	 * @return string
	 * @since  3.0.7
	 */
	public static function script_tag( $tag, $handle ) {
		if ( ! in_array( (string) $handle, self::exclusions()['handles'], true ) ) {
			return $tag;
		}

		return (string) preg_replace( '/<script(?=[\s>])(?![^>]*data-no-optimize)/i', '<script ' . self::SCRIPT_ATTRIBUTES, (string) $tag );
	}
}
