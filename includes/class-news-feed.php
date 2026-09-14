<?php
/**
 * News feed from reportedip.com for the Security Dashboard.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.54
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads the localised news feed of reportedip.com through WordPress' own
 * feed cache. Fail-open: any error yields an empty list and a one-hour
 * negative cache so a dashboard load never waits twice for a dead feed.
 *
 * @since 2.1.54
 */
class ReportedIP_Hive_News_Feed {

	/**
	 * Languages reportedip.com publishes news in, apart from English.
	 *
	 * @var string[]
	 */
	const LANGUAGES = array( 'de', 'es', 'fr' );

	/**
	 * Site transient set after a failed fetch.
	 *
	 * @var string
	 */
	const ERROR_TRANSIENT = 'reportedip_hive_news_feed_error';

	/**
	 * Feed URL for a WordPress locale; unknown languages fall back to English.
	 *
	 * @param string $locale WordPress locale such as `de_DE` or `en_US`.
	 * @return string
	 * @since  2.1.54
	 */
	public static function url_for_locale( $locale ) {
		$lang = strtolower( substr( (string) $locale, 0, 2 ) );
		$base = 'https://reportedip.com/';
		$url  = in_array( $lang, self::LANGUAGES, true )
			? $base . $lang . '/feed/?post_type=news'
			: $base . 'feed/?post_type=news';

		return (string) apply_filters( 'reportedip_hive_external_url', $url, 'news_feed' );
	}

	/**
	 * The newest items, oldest last.
	 *
	 * @param int $limit Maximum number of items.
	 * @return array<int, array{title:string, link:string, timestamp:int, summary:string, category:string}>
	 * @since  2.1.54
	 */
	public static function items( $limit = 3 ) {
		if ( get_site_transient( self::ERROR_TRANSIENT ) ) {
			return array();
		}
		if ( ! function_exists( 'fetch_feed' ) ) {
			include_once ABSPATH . WPINC . '/feed.php';
		}

		add_action( 'wp_feed_options', array( __CLASS__, 'shorten_timeout' ) );
		$feed = fetch_feed( self::url_for_locale( get_user_locale() ) );
		remove_action( 'wp_feed_options', array( __CLASS__, 'shorten_timeout' ) );
		if ( is_wp_error( $feed ) ) {
			set_site_transient( self::ERROR_TRANSIENT, 1, HOUR_IN_SECONDS );
			return array();
		}

		$items = array();
		foreach ( $feed->get_items( 0, max( 1, (int) $limit ) ) as $item ) {
			$category = $item->get_category();
			$items[]  = array(
				'title'     => (string) $item->get_title(),
				'link'      => (string) $item->get_permalink(),
				'timestamp' => (int) $item->get_date( 'U' ),
				'summary'   => wp_trim_words( wp_strip_all_tags( (string) $item->get_description() ), 24, '…' ),
				'category'  => is_object( $category ) && method_exists( $category, 'get_label' ) ? (string) $category->get_label() : '',
			);
		}

		return $items;
	}

	/**
	 * Five seconds is all a dashboard load may spend on the feed.
	 *
	 * @param SimplePie\SimplePie|SimplePie $feed Feed instance passed by `wp_feed_options`.
	 * @return void
	 */
	public static function shorten_timeout( $feed ) {
		$feed->set_timeout( 5 );
	}
}
