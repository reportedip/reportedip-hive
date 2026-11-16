<?php
/**
 * Tests for the actions that announce unsure findings to listeners.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.1.0
 */

/**
 * A flagged fake bot and a report-only WAF hit are announced to listeners.
 *
 * @group ms-required
 */
class ReportedIP_Hive_Suspect_Signal_Actions_Test extends WP_UnitTestCase {

	/**
	 * Addresses the action reported.
	 *
	 * @var string[]
	 */
	private $seen = array();

	/**
	 * Skip on single-site, ensure tables, listen.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		ReportedIP_Hive_Schema::ensure_tables();
		$this->seen = array();
		add_action( 'reportedip_hive_fake_bot_detected', array( $this, 'record' ) );
		add_action( 'reportedip_hive_waf_would_block', array( $this, 'record' ) );
	}

	/**
	 * Listener double.
	 *
	 * @param string $ip Address.
	 * @return void
	 */
	public function record( $ip ) {
		$this->seen[] = $ip;
	}

	/**
	 * Run the private spoofer handler.
	 *
	 * @param string $ip Address.
	 * @return void
	 */
	private function handle_fake( $ip ) {
		$method = new ReflectionMethod( ReportedIP_Hive_Bot_Verifier::class, 'handle_fake' );
		$method->invoke( ReportedIP_Hive_Bot_Verifier::get_instance(), array( 'ua' => 'Googlebot' ), $ip );
	}

	public function test_flagged_fake_bot_is_announced() {
		update_site_option( ReportedIP_Hive_Bot_Verifier::OPT_ACTION, 'flag' );
		$this->handle_fake( '203.0.113.9' );
		$this->assertSame( array( '203.0.113.9' ), $this->seen );
	}

	public function test_report_only_waf_hit_is_announced() {
		update_site_option( ReportedIP_Hive_WAF::OPT_REPORT_ONLY, true );
		$method = new ReflectionMethod( ReportedIP_Hive_WAF::class, 'handle_hit' );
		$method->invoke(
			ReportedIP_Hive_WAF::get_instance(),
			array(
				'id'    => 'sqli_test',
				'group' => 'sqli',
			),
			'203.0.113.10'
		);
		$this->assertSame( array( '203.0.113.10' ), $this->seen );
	}
}
