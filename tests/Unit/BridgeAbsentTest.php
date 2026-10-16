<?php
/**
 * The bridge loader is a build artefact of the GitHub release only.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * Bridge absence, plus the key filter of the bridge where the build source
 * is present (the monorepo, not the public mirror).
 */
class BridgeAbsentTest extends TestCase {

	public function test_no_bridge_in_the_plugin_tree() {
		$this->assertFileDoesNotExist( REPORTEDIP_HIVE_PLUGIN_DIR . 'bridge.php' );
		$this->assertStringNotContainsString( 'bridge.php', (string) file_get_contents( REPORTEDIP_HIVE_PLUGIN_FILE ) );
	}

	public function test_bridge_sends_the_key_only_to_the_exact_download_url() {
		$source = dirname( REPORTEDIP_HIVE_PLUGIN_DIR, 2 ) . '/tools/bridge/bridge.php';
		if ( ! is_file( $source ) ) {
			$this->markTestSkipped( 'Bridge source lives in the build tooling only.' );
		}
		require_once $source;

		$url    = \ReportedIP_Hive_Bridge::DOWNLOAD_URL;
		$signed = \ReportedIP_Hive_Bridge::sign( $url, array( 'headers' => array( 'A' => 'b' ) ), 'k1' );
		$this->assertSame( 'k1', $signed['headers']['X-Key'] );
		$this->assertSame( 'b', $signed['headers']['A'] );
		$this->assertSame( 0, $signed['redirection'] );

		foreach ( array(
			'http://reportedip.com/wp-json/reportedip/v2/hive/pro/download',
			$url . '?version=1',
			$url . '.evil.example/',
			'https://reportedip.com.evil.example/wp-json/reportedip/v2/hive/pro/download',
			'https://evil.example/?u=' . $url,
		) as $other ) {
			$this->assertSame( array(), \ReportedIP_Hive_Bridge::sign( $other, array(), 'k1' ), $other );
		}
		$this->assertSame( array( 'headers' => 'raw' ), \ReportedIP_Hive_Bridge::sign( $url, array( 'headers' => 'raw' ), 'k1' ) );
	}
}
