<?php
/**
 * Unit tests for {@see ReportedIP_Hive_Whats_New}.
 *
 * Exercises the full gate matrix (dismissal, payload cache, seen version,
 * backoff), the fetch outcomes and the feed sanitization through a test
 * double that overrides the protected {@see ReportedIP_Hive_Whats_New::fetch_feed()}
 * HTTP seam, so no request ever leaves the process.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.41
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

if ( ! function_exists( 'esc_url_raw' ) ) {
	/**
	 * Minimal stub: passthrough. Scheme/host validation under test lives in
	 * ReportedIP_Hive_Whats_New::sanitize_notes_url() itself.
	 *
	 * @param string $url       URL to sanitize.
	 * @param array  $protocols Allowed protocols (ignored by the stub).
	 * @return string
	 */
	function esc_url_raw( $url, $protocols = array() ) {
		return (string) $url;
	}
}

require_once dirname( __DIR__, 2 ) . '/includes/class-admin-notice.php';
require_once dirname( __DIR__, 2 ) . '/includes/class-whats-new.php';

/**
 * Test double that replaces the HTTP seam with a canned feed.
 */
class WhatsNewFetchDouble extends \ReportedIP_Hive_Whats_New {

	/**
	 * Number of fetch_feed() invocations.
	 *
	 * @var int
	 */
	public static $fetch_calls = 0;

	/**
	 * Canned feed returned by the override (null = fetch failure).
	 *
	 * @var array|null
	 */
	public static $feed = null;

	/**
	 * Return the canned feed instead of performing HTTP.
	 *
	 * @return array|null
	 */
	protected static function fetch_feed() {
		++self::$fetch_calls;
		return self::$feed;
	}
}

class WhatsNewTest extends TestCase {

	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_options']         = array();
		$GLOBALS['wp_transients']      = array();
		$GLOBALS['wp_user_meta']       = array();
		$GLOBALS['wp_current_user_id'] = 1;

		WhatsNewFetchDouble::$fetch_calls = 0;
		WhatsNewFetchDouble::$feed        = null;
	}

	private function ver_key(): string {
		return 'whatsnew_' . str_replace( '.', '_', REPORTEDIP_HIVE_VERSION );
	}

	private function valid_feed( array $overrides = array() ): array {
		return array_merge(
			array(
				'version'    => REPORTEDIP_HIVE_VERSION,
				'highlights' => array( 'First highlight', 'Second highlight' ),
				'notes_url'  => 'https://reportedip.com/news/release/',
			),
			$overrides
		);
	}

	private function run_maybe_render(): string {
		ob_start();
		WhatsNewFetchDouble::maybe_render();
		return (string) ob_get_clean();
	}

	private function stored_payload() {
		return $GLOBALS['wp_options'][ \ReportedIP_Hive_Whats_New::OPT_PAYLOAD ] ?? null;
	}

	public function test_dismissed_user_meta_skips_fetch_and_render(): void {
		$GLOBALS['wp_user_meta'][1][ 'reportedip_dismissed_' . $this->ver_key() ] = time();
		WhatsNewFetchDouble::$feed = $this->valid_feed();

		$output = $this->run_maybe_render();

		$this->assertSame( '', $output );
		$this->assertSame( 0, WhatsNewFetchDouble::$fetch_calls );
	}

	public function test_cached_payload_renders_without_fetch(): void {
		$GLOBALS['wp_options'][ \ReportedIP_Hive_Whats_New::OPT_PAYLOAD ] = array(
			'version'    => REPORTEDIP_HIVE_VERSION,
			'highlights' => array( 'Cached highlight' ),
			'notes_url'  => 'https://reportedip.com/news/release/',
		);

		$output = $this->run_maybe_render();

		$this->assertStringContainsString( 's new in ReportedIP Hive', $output );
		$this->assertStringContainsString( 'Cached highlight', $output );
		$this->assertSame( 0, WhatsNewFetchDouble::$fetch_calls );
	}

	public function test_seen_version_skips_fetch(): void {
		$GLOBALS['wp_options'][ \ReportedIP_Hive_Whats_New::OPT_SEEN_VERSION ] = REPORTEDIP_HIVE_VERSION;
		WhatsNewFetchDouble::$feed = $this->valid_feed();

		$output = $this->run_maybe_render();

		$this->assertSame( '', $output );
		$this->assertSame( 0, WhatsNewFetchDouble::$fetch_calls );
	}

	public function test_backoff_transient_skips_fetch(): void {
		set_site_transient( \ReportedIP_Hive_Whats_New::BACKOFF_TRANSIENT, 1, 3600 );
		WhatsNewFetchDouble::$feed = $this->valid_feed();

		$output = $this->run_maybe_render();

		$this->assertSame( '', $output );
		$this->assertSame( 0, WhatsNewFetchDouble::$fetch_calls );
	}

	public function test_version_mismatch_sets_backoff_without_seen_version(): void {
		WhatsNewFetchDouble::$feed = $this->valid_feed( array( 'version' => '0.0.1' ) );

		$output = $this->run_maybe_render();

		$this->assertSame( '', $output );
		$this->assertSame( 1, WhatsNewFetchDouble::$fetch_calls );
		$this->assertNotFalse( get_site_transient( \ReportedIP_Hive_Whats_New::BACKOFF_TRANSIENT ) );
		$this->assertArrayNotHasKey( \ReportedIP_Hive_Whats_New::OPT_SEEN_VERSION, $GLOBALS['wp_options'] );
	}

	public function test_fetch_failure_sets_backoff_and_stays_silent(): void {
		WhatsNewFetchDouble::$feed = null;

		$output = $this->run_maybe_render();

		$this->assertSame( '', $output );
		$this->assertSame( 1, WhatsNewFetchDouble::$fetch_calls );
		$this->assertNotFalse( get_site_transient( \ReportedIP_Hive_Whats_New::BACKOFF_TRANSIENT ) );
		$this->assertNull( $this->stored_payload() );
	}

	public function test_successful_fetch_renders_and_persists_state(): void {
		WhatsNewFetchDouble::$feed = $this->valid_feed();

		$output = $this->run_maybe_render();

		$this->assertStringContainsString( 's new in ReportedIP Hive', $output );
		$this->assertStringContainsString( 'First highlight', $output );
		$this->assertStringContainsString( 'Read the release notes', $output );
		$this->assertSame( 1, WhatsNewFetchDouble::$fetch_calls );
		$this->assertSame(
			REPORTEDIP_HIVE_VERSION,
			$GLOBALS['wp_options'][ \ReportedIP_Hive_Whats_New::OPT_SEEN_VERSION ]
		);
		$payload = $this->stored_payload();
		$this->assertIsArray( $payload );
		$this->assertSame( REPORTEDIP_HIVE_VERSION, $payload['version'] );
	}

	public function test_highlights_capped_at_six(): void {
		WhatsNewFetchDouble::$feed = $this->valid_feed(
			array(
				'highlights' => array( 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'H7', 'H8' ),
			)
		);

		$this->run_maybe_render();

		$payload = $this->stored_payload();
		$this->assertCount( 6, $payload['highlights'] );
		$this->assertSame( array( 'H1', 'H2', 'H3', 'H4', 'H5', 'H6' ), $payload['highlights'] );
	}

	public function test_highlights_html_stripped_and_truncated(): void {
		$long = str_repeat( 'a', 300 );
		WhatsNewFetchDouble::$feed = $this->valid_feed(
			array(
				'highlights' => array( '<strong>Bold</strong> <a href="#">text</a>', $long ),
			)
		);

		$this->run_maybe_render();

		$payload = $this->stored_payload();
		$this->assertSame( 'Bold text', $payload['highlights'][0] );
		$this->assertSame( 200, strlen( $payload['highlights'][1] ) );
	}

	public function test_empty_highlights_dropped(): void {
		WhatsNewFetchDouble::$feed = $this->valid_feed(
			array(
				'highlights' => array( '', '   ', '<b></b>', 'Kept', 42 ),
			)
		);

		$this->run_maybe_render();

		$payload = $this->stored_payload();
		$this->assertSame( array( 'Kept' ), $payload['highlights'] );
	}

	public function test_http_notes_url_rejected(): void {
		WhatsNewFetchDouble::$feed = $this->valid_feed(
			array( 'notes_url' => 'http://reportedip.com/news/release/' )
		);

		$this->run_maybe_render();

		$payload = $this->stored_payload();
		$this->assertSame( \ReportedIP_Hive_Whats_New::FALLBACK_NOTES_URL, $payload['notes_url'] );
	}

	public function test_evil_host_https_url_rejected(): void {
		foreach ( array(
			'https://reportedip.com.evil.example/x',
			'https://evil-github.com/releases',
			'https://github.com.attacker.net/releases',
		) as $evil_url ) {
			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();
			WhatsNewFetchDouble::$feed = $this->valid_feed( array( 'notes_url' => $evil_url ) );

			$this->run_maybe_render();

			$payload = $this->stored_payload();
			$this->assertSame(
				\ReportedIP_Hive_Whats_New::FALLBACK_NOTES_URL,
				$payload['notes_url'],
				'URL must be rejected: ' . $evil_url
			);
		}
	}

	public function test_github_release_url_accepted(): void {
		$url = 'https://github.com/reportedip/reportedip-hive/releases/tag/v9.9.9';
		WhatsNewFetchDouble::$feed = $this->valid_feed( array( 'notes_url' => $url ) );

		$this->run_maybe_render();

		$payload = $this->stored_payload();
		$this->assertSame( $url, $payload['notes_url'] );
	}

	public function test_notice_id_contains_no_dots(): void {
		WhatsNewFetchDouble::$feed = $this->valid_feed();

		$output = $this->run_maybe_render();

		$this->assertStringContainsString( 'data-notice-id="' . $this->ver_key() . '"', $output );
		$this->assertStringNotContainsString( '.', $this->ver_key() );
		$this->assertSame( sanitize_key( $this->ver_key() ), $this->ver_key() );
	}
}
