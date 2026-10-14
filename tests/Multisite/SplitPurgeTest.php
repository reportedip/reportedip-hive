<?php
/**
 * The update that leaves 2.x purges the page caches once, from the upgrade
 * seed, when the 2.x computation check was on and nothing judges it now.
 *
 * Runs against the real bootstrap, so the wiring from
 * `ReportedIP_Hive::maybe_seed_on_upgrade()` to
 * `ReportedIP_Hive_Form_Proof::purge_after_split()` is exercised, not only
 * the pure decision in `split_purge_needed()`.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Split_Purge_Test extends WP_UnitTestCase {

	/**
	 * Option keys the tests write.
	 *
	 * @var string[]
	 */
	private $touched = array(
		'reportedip_hive_seeded_version',
		'reportedip_hive_form_proof_pow_since',
	);

	/**
	 * Skip on single-site runs.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
	}

	/**
	 * Drop the written options.
	 */
	public function tear_down() {
		foreach ( $this->touched as $key ) {
			ReportedIP_Hive_Option_Routing::delete( $key );
		}
		parent::tear_down();
	}

	/**
	 * Run the upgrade seed from a stored version and count the purges.
	 *
	 * Every default is seeded first: a fresh default's side effects purge
	 * the caches as well, and only the purge after the split counts here.
	 *
	 * @param string $from      Seeded version before the update.
	 * @param int    $pow_since Stored start of the 2.x computation grace.
	 * @return int Purges the run fired.
	 */
	private function purges_after_seed( $from, $pow_since ) {
		ReportedIP_Hive_Defaults::seed_missing();
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_seeded_version', $from );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_form_proof_pow_since', $pow_since );
		$before = did_action( 'reportedip_hive_page_caches_purged' );

		ReportedIP_Hive::maybe_seed_on_upgrade();

		return did_action( 'reportedip_hive_page_caches_purged' ) - $before;
	}

	/**
	 * Leaving 2.x with the computation on purges once.
	 */
	public function test_the_seed_purges_when_leaving_2x_with_the_computation_on() {
		$this->assertFalse( ReportedIP_Hive_Form_Proof::computation_owned(), 'precondition: nothing judges the computation' );

		$this->assertSame( 1, $this->purges_after_seed( '2.1.70', time() ) );
		$this->assertSame( REPORTEDIP_HIVE_VERSION, ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_seeded_version' ) );
	}

	/**
	 * No purge with the computation off, on a fresh install, or once the
	 * seed already ran for this version.
	 */
	public function test_the_seed_does_not_purge_otherwise() {
		$this->assertSame( 0, $this->purges_after_seed( '2.1.70', 0 ), 'the computation was off' );
		$this->assertSame( 0, $this->purges_after_seed( '', time() ), 'a fresh install has nothing cached' );
		$this->assertSame( 0, $this->purges_after_seed( REPORTEDIP_HIVE_VERSION, time() ), 'the seed already ran for this version' );
	}
}
