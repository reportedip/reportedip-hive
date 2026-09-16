<?php
/**
 * Page-cache purge for switches whose effect lives in the rendered markup.
 *
 * A feature that plants something into a form only reaches visitors once the
 * page carrying that form is rendered again. A full-page cache filled before
 * the switch keeps serving the old markup for as long as its lifetime says,
 * which on LiteSpeed is a week by default, and Elementor stores its rendered
 * widgets in post meta with no lifetime at all. The result is a protection
 * that looks armed in the settings and refuses real visitors on the front end.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.58
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Purges the page caches this plugin knows about.
 *
 * @since 2.1.58
 */
final class ReportedIP_Hive_Cache_Flush {

	/**
	 * Cache plugins that clear everything through one global function.
	 *
	 * @var string[]
	 */
	const PURGE_FUNCTIONS = array(
		'rocket_clean_domain',
		'w3tc_flush_posts',
		'wp_cache_clear_cache',
		'sg_cachepress_purge_cache',
	);

	/**
	 * Cache plugins that listen for an action instead.
	 *
	 * @var string[]
	 */
	const PURGE_ACTIONS = array(
		'litespeed_purge_all',
		'cache_enabler_clear_complete_cache',
	);

	/**
	 * Throw away every cached rendering of a page.
	 *
	 * Deliberately not `wp_cache_flush()`: that empties the object cache, which
	 * costs every site a cold start and does nothing whatsoever about the HTML
	 * a page cache already wrote to disk.
	 *
	 * @return void
	 * @since  2.1.58
	 */
	public static function purge_pages() {
		self::purge_elementor();

		foreach ( self::purge_functions() as $purge ) {
			if ( function_exists( $purge ) ) {
				call_user_func( $purge );
			}
		}

		foreach ( self::PURGE_ACTIONS as $action ) {
			do_action( $action ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.DynamicHooknameFound -- These are the cache plugins' own hook names, not ours.
		}

		/**
		 * Fires after every known page cache has been purged.
		 *
		 * The attach point for a cache this plugin does not know about.
		 *
		 * @since 2.1.58
		 */
		do_action( 'reportedip_hive_page_caches_purged' );
	}

	/**
	 * The global purge functions, as names rather than as the literal list.
	 *
	 * None of them exists in this codebase, and static analysis is right about
	 * that: they arrive with a cache plugin or not at all.
	 *
	 * @return string[]
	 * @since  2.1.58
	 */
	private static function purge_functions() {
		return self::PURGE_FUNCTIONS;
	}

	/**
	 * Drop Elementor's rendered markup.
	 *
	 * The widget cache is post meta, so it outlives any page cache and any
	 * lifetime setting. Dropping the meta is what actually gets the anchor back
	 * into the form; the file manager call is the supported way to ask for the
	 * rest and is guarded because Elementor is rarely there.
	 *
	 * @return void
	 * @since  2.1.58
	 */
	private static function purge_elementor() {
		if ( function_exists( 'delete_post_meta_by_key' ) ) {
			delete_post_meta_by_key( '_elementor_element_cache' );
		}

		if ( ! class_exists( 'Elementor\\Plugin' ) || ! is_callable( array( 'Elementor\\Plugin', 'instance' ) ) ) {
			return;
		}

		$plugin = call_user_func( array( 'Elementor\\Plugin', 'instance' ) );

		if ( ! is_object( $plugin ) || ! isset( $plugin->files_manager ) || ! is_object( $plugin->files_manager ) ) {
			return;
		}

		if ( method_exists( $plugin->files_manager, 'clear_cache' ) ) {
			$plugin->files_manager->clear_cache();
		}
	}
}
