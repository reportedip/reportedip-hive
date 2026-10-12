<?php
/**
 * Unit tests for the site-wide pause of live reputation lookups.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.74
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * @covers \ReportedIP_Hive_API::pause_reputation_lookups
 * @covers \ReportedIP_Hive_API::reputation_lookups_paused
 */
class ReputationPauseTest extends TestCase {

	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_transients'] = array();
		require_once dirname( __DIR__, 2 ) . '/includes/class-api-client.php';
	}

	public function test_lookups_run_without_a_pause(): void {
		$this->assertFalse( \ReportedIP_Hive_API::reputation_lookups_paused() );
	}

	public function test_a_transport_error_pauses_lookups_for_two_minutes(): void {
		\ReportedIP_Hive_API::pause_reputation_lookups();

		$this->assertTrue( \ReportedIP_Hive_API::reputation_lookups_paused() );
		$this->assertSame( 120, \ReportedIP_Hive_API::REPUTATION_PAUSE_SECONDS );
	}

	public function test_a_lapsed_pause_lets_lookups_run_again(): void {
		set_site_transient( \ReportedIP_Hive_API::REPUTATION_PAUSE_KEY, time() - 1, 60 );

		$this->assertFalse( \ReportedIP_Hive_API::reputation_lookups_paused() );
	}

	public function test_the_failure_branch_sets_the_pause(): void {
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-api-client.php' );
		$start  = strpos( $source, 'public function check_ip_reputation' );
		$body   = substr( $source, $start, strpos( $source, 'wp_remote_retrieve_response_code', $start ) - $start );

		$this->assertStringContainsString( 'self::reputation_lookups_paused()', $body, 'a paused site must skip the live lookup' );
		$this->assertStringContainsString( 'self::pause_reputation_lookups()', $body, 'a transport error must pause further lookups' );
	}
}
