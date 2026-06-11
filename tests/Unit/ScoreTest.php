<?php
/**
 * Unit tests for the aggregate security-score calculation.
 *
 * Locks the pure scoring core: weight tables sum to 100, the renormalising
 * present/available/enabled algorithm earns and withholds points correctly,
 * tier/mode-locked items count to the potential but not the earned score,
 * not-yet-built items drop out of the maximum, and the letter-grade mapping
 * holds at every boundary.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.2
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-score.php';

	/**
	 * @covers \ReportedIP_Hive_Score
	 */
	class ScoreTest extends TestCase {

		/**
		 * Build a single item descriptor for compute().
		 *
		 * @param int  $weight    Item weight.
		 * @param bool $present   Feature exists in the build.
		 * @param bool $available Tier/mode allows the feature.
		 * @param bool $enabled   Underlying toggle is on.
		 * @return array<string,mixed>
		 */
		private function item( int $weight, bool $present, bool $available, bool $enabled ): array {
			return array(
				'key'       => 'k' . $weight,
				'weight'    => $weight,
				'present'   => $present,
				'available' => $available,
				'enabled'   => $enabled,
			);
		}

		public function test_detection_weights_sum_to_100(): void {
			$this->assertSame( 100, array_sum( \ReportedIP_Hive_Score::DETECTION_WEIGHTS ) );
		}

		public function test_hardening_weights_sum_to_100(): void {
			$this->assertSame( 100, array_sum( \ReportedIP_Hive_Score::HARDENING_WEIGHTS ) );
		}

		public function test_all_off_scores_zero(): void {
			$items = array(
				$this->item( 60, true, true, false ),
				$this->item( 40, true, true, false ),
			);
			$out = \ReportedIP_Hive_Score::compute( $items );
			$this->assertSame( 0, $out['score'] );
			$this->assertSame( 'F', $out['grade'] );
			$this->assertSame( 100, $out['max'] );
			$this->assertSame( 100, $out['off_potential'] );
		}

		public function test_all_on_scores_full(): void {
			$items = array(
				$this->item( 60, true, true, true ),
				$this->item( 40, true, true, true ),
			);
			$out = \ReportedIP_Hive_Score::compute( $items );
			$this->assertSame( 100, $out['score'] );
			$this->assertSame( 'A+', $out['grade'] );
			$this->assertSame( 0, $out['off_potential'] );
			$this->assertSame( 0, $out['locked_potential'] );
		}

		public function test_locked_item_counts_to_potential_not_earned(): void {
			$items = array(
				$this->item( 70, true, true, true ),
				$this->item( 30, true, false, true ),
			);
			$out = \ReportedIP_Hive_Score::compute( $items );
			$this->assertSame( 100, $out['max'] );
			$this->assertSame( 70, $out['earned'] );
			$this->assertSame( 30, $out['locked_potential'] );
			$this->assertSame( 70, $out['score'] );
			$this->assertSame( 'C', $out['grade'] );
		}

		public function test_not_present_item_is_excluded_from_maximum(): void {
			$items = array(
				$this->item( 70, true, true, true ),
				$this->item( 30, false, true, true ),
			);
			$out = \ReportedIP_Hive_Score::compute( $items );
			$this->assertSame( 70, $out['max'] );
			$this->assertSame( 70, $out['earned'] );
			$this->assertSame( 100, $out['score'] );
			$this->assertCount( 1, $out['items'] );
		}

		public function test_available_but_off_lowers_score_without_locking(): void {
			$items = array(
				$this->item( 80, true, true, true ),
				$this->item( 20, true, true, false ),
			);
			$out = \ReportedIP_Hive_Score::compute( $items );
			$this->assertSame( 80, $out['score'] );
			$this->assertSame( 0, $out['locked_potential'] );
			$this->assertSame( 20, $out['off_potential'] );
		}

		public function test_empty_present_set_scores_zero_without_division_error(): void {
			$out = \ReportedIP_Hive_Score::compute( array( $this->item( 50, false, true, true ) ) );
			$this->assertSame( 0, $out['score'] );
			$this->assertSame( 0, $out['max'] );
		}

		public function test_grade_boundaries(): void {
			$this->assertSame( 'A+', \ReportedIP_Hive_Score::grade_for( 95 ) );
			$this->assertSame( 'A', \ReportedIP_Hive_Score::grade_for( 94 ) );
			$this->assertSame( 'A', \ReportedIP_Hive_Score::grade_for( 90 ) );
			$this->assertSame( 'B', \ReportedIP_Hive_Score::grade_for( 89 ) );
			$this->assertSame( 'B', \ReportedIP_Hive_Score::grade_for( 80 ) );
			$this->assertSame( 'C', \ReportedIP_Hive_Score::grade_for( 79 ) );
			$this->assertSame( 'C', \ReportedIP_Hive_Score::grade_for( 70 ) );
			$this->assertSame( 'D', \ReportedIP_Hive_Score::grade_for( 69 ) );
			$this->assertSame( 'D', \ReportedIP_Hive_Score::grade_for( 60 ) );
			$this->assertSame( 'F', \ReportedIP_Hive_Score::grade_for( 59 ) );
			$this->assertSame( 'F', \ReportedIP_Hive_Score::grade_for( 0 ) );
		}
	}
}
