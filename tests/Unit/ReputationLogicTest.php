<?php
/**
 * Unit Tests for Reputation Score Logic.
 *
 * Tests reputation scoring and blocking decisions without WordPress dependencies.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.0.0
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * Test class for reputation logic.
 */
class ReputationLogicTest extends TestCase {

	/**
	 * Default block threshold.
	 *
	 * @var int
	 */
	private $default_threshold = 75;

	/**
	 * Test blocking decision based on threshold.
	 *
	 * @dataProvider threshold_decision_provider
	 * @param int  $confidence_score The confidence score.
	 * @param int  $threshold        The block threshold.
	 * @param bool $should_block     Expected blocking decision.
	 */
	public function test_blocking_decision_based_on_threshold( $confidence_score, $threshold, $should_block ) {
		$decision = $this->should_block_ip( $confidence_score, $threshold );
		$this->assertEquals(
			$should_block,
			$decision,
			sprintf(
				'IP with score %d should %sbe blocked at threshold %d',
				$confidence_score,
				$should_block ? '' : 'not ',
				$threshold
			)
		);
	}

	/**
	 * Data provider for blocking decisions.
	 *
	 * @return array
	 */
	public function threshold_decision_provider() {
		return array(
			'score 100, threshold 75' => array( 100, 75, true ),
			'score 90, threshold 75'  => array( 90, 75, true ),
			'score 75, threshold 75'  => array( 75, 75, true ),
			'score 74, threshold 75'  => array( 74, 75, false ),
			'score 50, threshold 75'  => array( 50, 75, false ),
			'score 0, threshold 75'   => array( 0, 75, false ),

			'score 50, threshold 50'  => array( 50, 50, true ),
			'score 49, threshold 50'  => array( 49, 50, false ),

			'score 90, threshold 90'  => array( 90, 90, true ),
			'score 89, threshold 90'  => array( 89, 90, false ),
			'score 75, threshold 90'  => array( 75, 90, false ),

			'score 25, threshold 25'  => array( 25, 25, true ),
			'score 24, threshold 25'  => array( 24, 25, false ),

			'score 100, threshold 100' => array( 100, 100, true ),
			'score 99, threshold 100'  => array( 99, 100, false ),
		);
	}

	/**
	 * Test reputation severity classification.
	 *
	 * @dataProvider severity_classification_provider
	 * @param int    $confidence_score The confidence score.
	 * @param string $expected_severity Expected severity level.
	 */
	public function test_reputation_severity_classification( $confidence_score, $expected_severity ) {
		$severity = $this->classify_severity( $confidence_score );
		$this->assertEquals(
			$expected_severity,
			$severity,
			sprintf( 'Score %d should be classified as %s', $confidence_score, $expected_severity )
		);
	}

	/**
	 * Data provider for severity classifications.
	 *
	 * @return array
	 */
	public function severity_classification_provider() {
		return array(
			'score 0'   => array( 0, 'low' ),
			'score 10'  => array( 10, 'low' ),
			'score 24'  => array( 24, 'low' ),

			'score 25'  => array( 25, 'medium' ),
			'score 35'  => array( 35, 'medium' ),
			'score 49'  => array( 49, 'medium' ),

			'score 50'  => array( 50, 'high' ),
			'score 60'  => array( 60, 'high' ),
			'score 74'  => array( 74, 'high' ),

			'score 75'  => array( 75, 'critical' ),
			'score 90'  => array( 90, 'critical' ),
			'score 100' => array( 100, 'critical' ),
		);
	}

	/**
	 * Test recommended action based on score.
	 *
	 * @dataProvider recommended_action_provider
	 * @param int    $confidence_score The confidence score.
	 * @param string $expected_action  Expected recommended action.
	 */
	public function test_recommended_action_based_on_score( $confidence_score, $expected_action ) {
		$action = $this->get_recommended_action( $confidence_score );
		$this->assertEquals(
			$expected_action,
			$action,
			sprintf( 'Score %d should recommend %s', $confidence_score, $expected_action )
		);
	}

	/**
	 * Data provider for recommended actions.
	 *
	 * @return array
	 */
	public function recommended_action_provider() {
		return array(
			'score 0'   => array( 0, 'allow' ),
			'score 24'  => array( 24, 'allow' ),
			'score 25'  => array( 25, 'monitor' ),
			'score 49'  => array( 49, 'monitor' ),
			'score 50'  => array( 50, 'monitor' ),
			'score 74'  => array( 74, 'monitor' ),
			'score 75'  => array( 75, 'block_temporary' ),
			'score 89'  => array( 89, 'block_temporary' ),
			'score 90'  => array( 90, 'block_permanent' ),
			'score 100' => array( 100, 'block_permanent' ),
		);
	}

	/**
	 * Test block duration based on severity.
	 *
	 * @dataProvider block_duration_provider
	 * @param int $confidence_score The confidence score.
	 * @param int $expected_hours   Expected block duration in hours.
	 */
	public function test_block_duration_based_on_severity( $confidence_score, $expected_hours ) {
		$hours = $this->calculate_block_duration( $confidence_score );
		$this->assertEquals(
			$expected_hours,
			$hours,
			sprintf( 'Score %d should result in %d hour block', $confidence_score, $expected_hours )
		);
	}

	/**
	 * Data provider for block durations.
	 *
	 * @return array
	 */
	public function block_duration_provider() {
		return array(
			'score 75'  => array( 75, 24 ),
			'score 84'  => array( 84, 24 ),
			'score 85'  => array( 85, 48 ),
			'score 94'  => array( 94, 48 ),
			'score 95'  => array( 95, 168 ),
			'score 100' => array( 100, 168 ),
		);
	}

	/**
	 * Test report count influence on blocking.
	 *
	 * @dataProvider report_count_influence_provider
	 * @param int  $confidence_score The confidence score.
	 * @param int  $report_count     Number of reports.
	 * @param bool $should_escalate  Whether blocking should be escalated.
	 */
	public function test_report_count_influence_on_blocking( $confidence_score, $report_count, $should_escalate ) {
		$escalate = $this->should_escalate_blocking( $confidence_score, $report_count );
		$this->assertEquals(
			$should_escalate,
			$escalate,
			sprintf(
				'Score %d with %d reports should %sescalate',
				$confidence_score,
				$report_count,
				$should_escalate ? '' : 'not '
			)
		);
	}

	/**
	 * Data provider for report count influence.
	 *
	 * @return array
	 */
	public function report_count_influence_provider() {
		return array(
			'score 50, 1 report'    => array( 50, 1, false ),
			'score 50, 10 reports'  => array( 50, 10, false ),
			'score 50, 50 reports'  => array( 50, 50, true ),

			'score 70, 5 reports'   => array( 70, 5, false ),
			'score 70, 25 reports'  => array( 70, 25, true ),

			'score 85, 1 report'    => array( 85, 1, false ),
			'score 85, 10 reports'  => array( 85, 10, true ),
		);
	}

	/**
	 * Test threat category priority.
	 *
	 * @dataProvider threat_category_priority_provider
	 * @param array  $categories        Array of threat categories.
	 * @param string $expected_priority Expected priority level.
	 */
	public function test_threat_category_priority( $categories, $expected_priority ) {
		$priority = $this->get_threat_priority( $categories );
		$this->assertEquals(
			$expected_priority,
			$priority,
			sprintf( 'Categories %s should have %s priority', implode( ', ', $categories ), $expected_priority )
		);
	}

	/**
	 * Data provider for threat category priorities.
	 *
	 * @return array
	 */
	public function threat_category_priority_provider() {
		return array(
			'brute force'            => array( array( 'brute_force' ), 'high' ),
			'malware distribution'   => array( array( 'malware_distribution' ), 'critical' ),
			'comment spam'           => array( array( 'comment_spam' ), 'medium' ),
			'web crawler'            => array( array( 'web_crawler' ), 'low' ),
			'mixed threats'          => array( array( 'comment_spam', 'brute_force' ), 'high' ),
			'mixed with critical'    => array( array( 'comment_spam', 'malware_distribution' ), 'critical' ),
			'empty categories'       => array( array(), 'low' ),
		);
	}

	/**
	 * Test confidence score validation.
	 *
	 * @dataProvider score_validation_provider
	 * @param mixed $score    The score to validate.
	 * @param bool  $is_valid Expected validity.
	 */
	public function test_confidence_score_validation( $score, $is_valid ) {
		$valid = $this->is_valid_score( $score );
		$this->assertEquals(
			$is_valid,
			$valid,
			sprintf( 'Score %s should be %s', var_export( $score, true ), $is_valid ? 'valid' : 'invalid' )
		);
	}

	/**
	 * Data provider for score validation.
	 *
	 * @return array
	 */
	public function score_validation_provider() {
		return array(
			'score 0'         => array( 0, true ),
			'score 50'        => array( 50, true ),
			'score 100'       => array( 100, true ),
			'score -1'        => array( -1, false ),
			'score 101'       => array( 101, false ),
			'score null'      => array( null, false ),
			'score string'    => array( 'fifty', false ),
			'score float'     => array( 50.5, true ),
			'score array'     => array( array( 50 ), false ),
		);
	}

	/**
	 * Helper method to determine if IP should be blocked.
	 *
	 * @param int $confidence_score The confidence score.
	 * @param int $threshold        The block threshold.
	 * @return bool
	 */
	private function should_block_ip( $confidence_score, $threshold ) {
		return $confidence_score >= $threshold;
	}

	/**
	 * Helper method to classify severity.
	 *
	 * @param int $confidence_score The confidence score.
	 * @return string
	 */
	private function classify_severity( $confidence_score ) {
		if ( $confidence_score >= 75 ) {
			return 'critical';
		} elseif ( $confidence_score >= 50 ) {
			return 'high';
		} elseif ( $confidence_score >= 25 ) {
			return 'medium';
		}
		return 'low';
	}

	/**
	 * Helper method to get recommended action.
	 *
	 * @param int $confidence_score The confidence score.
	 * @return string
	 */
	private function get_recommended_action( $confidence_score ) {
		if ( $confidence_score >= 90 ) {
			return 'block_permanent';
		} elseif ( $confidence_score >= 75 ) {
			return 'block_temporary';
		} elseif ( $confidence_score >= 25 ) {
			return 'monitor';
		}
		return 'allow';
	}

	/**
	 * Helper method to calculate block duration.
	 *
	 * @param int $confidence_score The confidence score.
	 * @return int Hours to block.
	 */
	private function calculate_block_duration( $confidence_score ) {
		if ( $confidence_score >= 95 ) {
			return 168;
		} elseif ( $confidence_score >= 85 ) {
			return 48;
		}
		return 24;
	}

	/**
	 * Helper method to determine if blocking should be escalated.
	 *
	 * @param int $confidence_score The confidence score.
	 * @param int $report_count     Number of reports.
	 * @return bool
	 */
	private function should_escalate_blocking( $confidence_score, $report_count ) {
		if ( $confidence_score >= 85 && $report_count >= 10 ) {
			return true;
		}
		if ( $confidence_score >= 70 && $report_count >= 25 ) {
			return true;
		}
		if ( $confidence_score >= 50 && $report_count >= 50 ) {
			return true;
		}
		return false;
	}

	/**
	 * Helper method to get threat priority from categories.
	 *
	 * @param array $categories Threat categories.
	 * @return string
	 */
	private function get_threat_priority( $categories ) {
		$critical_threats = array( 'malware_distribution', 'ddos', 'ransomware', 'phishing' );
		$high_threats     = array( 'brute_force', 'sql_injection', 'xss', 'credential_stuffing' );
		$medium_threats   = array( 'comment_spam', 'email_spam', 'scraping' );

		foreach ( $categories as $category ) {
			if ( in_array( $category, $critical_threats, true ) ) {
				return 'critical';
			}
		}

		foreach ( $categories as $category ) {
			if ( in_array( $category, $high_threats, true ) ) {
				return 'high';
			}
		}

		foreach ( $categories as $category ) {
			if ( in_array( $category, $medium_threats, true ) ) {
				return 'medium';
			}
		}

		return 'low';
	}

	/**
	 * Helper method to validate confidence score.
	 *
	 * @param mixed $score The score to validate.
	 * @return bool
	 */
	private function is_valid_score( $score ) {
		if ( ! is_numeric( $score ) ) {
			return false;
		}
		$score = (float) $score;
		return $score >= 0 && $score <= 100;
	}
}
