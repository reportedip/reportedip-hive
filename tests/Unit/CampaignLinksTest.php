<?php
/**
 * Every link to reportedip.com carries the campaign tag of its channel.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.1
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\CampaignLinkScanner;
use ReportedIP\Hive\Tests\TestCase;

require_once dirname( __DIR__ ) . '/CampaignLinkScanner.php';

/**
 * Inside the plugin a link says `rc=hive-plugin`, the frontend badges say
 * `rc=hive-badge`, readme.txt says `rc=hive-wporg`. reportedip.com counts
 * clicks, sign-ups and revenue per source from that tag.
 */
class CampaignLinksTest extends TestCase {

	/**
	 * Files whose links end up on visitors' pages as a backlink.
	 */
	const BADGE_FILES = array(
		'includes/class-frontend-shortcodes.php',
		'assets/js/badges.js',
		'assets/js/frontend-banner.js',
	);

	/**
	 * Untagged literals that are bases, never links on their own. Every
	 * rendered link built from them goes through
	 * {@see \ReportedIP_Hive_Catalog::campaign_url()}.
	 */
	const ALLOW = array(
		'reportedip-hive.php|https://reportedip.com'  => 'REPORTEDIP_HIVE_SITE_URL, the base every link is built from',
		'includes/class-news-feed.php|https://reportedip.com/' => 'base of the feed URL, the path is appended (feed, exempt)',
		'includes/class-frontend-shortcodes.php|https://reportedip.com' => 'fallback base of build_backlink_url(), tagged there',
		'includes/class-migration-manager.php|https://reportedip.de/wp-json/reportedip/v2' => 'migration v14 compares the stored legacy API endpoint',
	);

	protected function set_up() {
		parent::set_up();
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-catalog.php';
	}

	public function test_every_shipped_link_carries_its_campaign_tag() {
		$root  = rtrim( REPORTEDIP_HIVE_PLUGIN_DIR, '/\\' );
		$files = array();
		foreach ( array( 'admin', 'includes', 'templates', 'assets', 'data' ) as $dir ) {
			$files = array_merge( $files, CampaignLinkScanner::files( $root . '/' . $dir, array( 'php', 'js', 'css' ) ) );
		}
		$files[] = $root . '/reportedip-hive.php';
		$files[] = $root . '/readme.txt';
		$files[] = $root . '/languages/reportedip-hive.pot';
		foreach ( glob( $root . '/languages/*.po' ) as $po ) {
			$files[] = $po;
		}

		$findings = CampaignLinkScanner::scan(
			$root,
			$files,
			static function ( $rel ) {
				if ( 'readme.txt' === $rel ) {
					return 'hive-wporg';
				}
				return in_array( $rel, self::BADGE_FILES, true ) ? 'hive-badge' : 'hive-plugin';
			},
			self::ALLOW
		);

		$this->assertSame( array(), $findings, implode( "\n", $findings ) );
	}

	public function test_campaign_url_tags_a_deep_link_before_the_anchor() {
		$this->assertSame( 'https://reportedip.com/pricing/?rc=hive-plugin#tor_blocking', \ReportedIP_Hive_Catalog::campaign_url( 'https://reportedip.com/pricing/#tor_blocking' ) );
		$this->assertSame( 'https://reportedip.com/?rc=hive-badge', \ReportedIP_Hive_Catalog::campaign_url( 'https://reportedip.com', 'hive-badge' ) );
	}

	public function test_campaign_url_replaces_utm_and_an_old_tag_and_keeps_other_args() {
		$this->assertSame(
			'https://reportedip.com/news/item/?lang=de&rc=hive-plugin',
			\ReportedIP_Hive_Catalog::campaign_url( 'https://reportedip.com/news/item/?utm_' . 'source=hive&lang=de&rc=old&utm_' . 'medium=x' )
		);
	}

	public function test_campaign_url_leaves_api_feeds_legal_pages_and_other_hosts_alone() {
		foreach ( array(
			'https://reportedip.com/wp-json/reportedip/v2/',
			'https://reportedip.com/de/feed/?post_type=news',
			'https://reportedip.com/datenschutzerklaerung/',
			'https://reportedip.com/dashboard/dsgvo/',
			'https://example.com/pricing/',
		) as $url ) {
			$this->assertSame( $url, \ReportedIP_Hive_Catalog::campaign_url( $url ) );
		}
	}

	public function test_scanner_and_helper_share_the_exempt_rule() {
		$this->assertSame( CampaignLinkScanner::EXEMPT, \ReportedIP_Hive_Catalog::CAMPAIGN_EXEMPT );
	}

	/**
	 * The em dash cleanup turned empty-value dashes into a lone comma
	 * ("Oldest report: ,"). An empty value says so in words or stays empty.
	 */
	public function test_no_lone_comma_stands_in_for_an_empty_value() {
		$root = rtrim( REPORTEDIP_HIVE_PLUGIN_DIR, '/\\' );
		$hits = array();
		foreach ( array( 'admin', 'includes', 'templates', 'assets/js' ) as $dir ) {
			foreach ( CampaignLinkScanner::files( $root . '/' . $dir, array( 'php', 'js' ) ) as $file ) {
				foreach ( preg_split( '/\R/', (string) file_get_contents( $file ) ) as $i => $line ) {
					if ( preg_match( "/(?:\\?\\?|\\|\\||[?:]|echo|return)\\s*', '\\s*[;)]/", $line ) ) {
						$hits[] = substr( $file, strlen( $root ) ) . ':' . ( $i + 1 );
					}
				}
			}
		}
		$this->assertSame( array(), $hits, implode( "\n", $hits ) );
	}
}
