<?php
/**
 * Unit tests for the localised reportedip.com news feed URL.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.54
 */

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-news-feed.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @covers \ReportedIP_Hive_News_Feed::url_for_locale
	 */
	class NewsFeedTest extends TestCase {

		public function test_english_and_unknown_locales_use_the_default_feed(): void {
			$expected = 'https://reportedip.com/feed/?post_type=news';
			$this->assertSame( $expected, \ReportedIP_Hive_News_Feed::url_for_locale( 'en_US' ) );
			$this->assertSame( $expected, \ReportedIP_Hive_News_Feed::url_for_locale( 'en_GB' ) );
			$this->assertSame( $expected, \ReportedIP_Hive_News_Feed::url_for_locale( 'pl_PL' ) );
			$this->assertSame( $expected, \ReportedIP_Hive_News_Feed::url_for_locale( '' ) );
		}

		public function test_published_languages_get_their_own_feed(): void {
			$this->assertSame( 'https://reportedip.com/de/feed/?post_type=news', \ReportedIP_Hive_News_Feed::url_for_locale( 'de_DE' ) );
			$this->assertSame( 'https://reportedip.com/de/feed/?post_type=news', \ReportedIP_Hive_News_Feed::url_for_locale( 'de_AT' ) );
			$this->assertSame( 'https://reportedip.com/es/feed/?post_type=news', \ReportedIP_Hive_News_Feed::url_for_locale( 'es_ES' ) );
			$this->assertSame( 'https://reportedip.com/fr/feed/?post_type=news', \ReportedIP_Hive_News_Feed::url_for_locale( 'fr_FR' ) );
		}
	}
}
