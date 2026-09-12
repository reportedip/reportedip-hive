<?php
/**
 * Unit tests for the form-side community reputation gate.
 *
 * The load-bearing claim is that a form submission is judged at exactly the
 * confidence the sign-in path enforces, floor and hardening clamp included.
 * If those two ever drift apart, a visitor refused a login could post a comment
 * instead, which is the hole this gate was built to close.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.53
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @covers \ReportedIP_Hive_Reputation_Gate
	 */
	class ReputationGateTest extends TestCase {

		/**
		 * Read the plugin source once.
		 *
		 * @param string $relative Path below the plugin root.
		 * @return string
		 */
		private function source( string $relative ): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/' . $relative );
		}

		/**
		 * The sign-in path must not carry a second copy of the threshold
		 * calculation. One definition, or the two surfaces drift.
		 */
		public function test_the_login_path_reads_the_shared_threshold(): void {
			$source = $this->source( 'reportedip-hive.php' );
			$start  = strpos( $source, 'public function pre_auth_check(' );

			$this->assertNotFalse( $start, 'pre_auth_check() not found.' );

			$body = substr( $source, $start, 3000 );

			$this->assertStringContainsString( 'ReportedIP_Hive_Reputation_Gate::threshold()', $body );
			$this->assertStringNotContainsString( 'effective_block_threshold', $body );
		}

		/**
		 * Every exemption the sign-in path honours must be honoured here too.
		 */
		public function test_the_gate_honours_every_exemption(): void {
			$source = $this->source( 'includes/class-reputation-gate.php' );
			$start  = strpos( $source, 'public function check(' );

			$this->assertNotFalse( $start, 'check() not found.' );

			$body = substr( $source, $start, 2600 );

			$this->assertStringContainsString( 'is_enabled()', $body );
			$this->assertStringContainsString( 'is_whitelisted', $body );
			$this->assertStringContainsString( 'is_own_server_ip', $body );
			$this->assertStringContainsString( 'is_blocked', $body );
			$this->assertStringContainsString( 'infrastructure', $body );
			$this->assertStringContainsString( 'report_only_mode', $body );
		}

		/**
		 * A comment the local filter already judged costs no community lookup.
		 */
		public function test_a_locally_judged_comment_is_not_looked_up(): void {
			$source = $this->source( 'includes/class-reputation-gate.php' );
			$start  = strpos( $source, 'public function check_comment(' );

			$this->assertNotFalse( $start, 'check_comment() not found.' );

			$body = substr( $source, $start, 1400 );

			$this->assertStringContainsString( 'last_verdict()', $body );
		}

		/**
		 * The comment check runs after the local scoring, never before.
		 */
		public function test_the_comment_hook_runs_after_the_local_score(): void {
			$gate   = $this->source( 'includes/class-reputation-gate.php' );
			$filter = $this->source( 'includes/class-comment-spam-filter.php' );

			$this->assertStringContainsString( "add_filter( 'preprocess_comment', array( \$this, 'check_comment' ), 6 )", $gate );
			$this->assertStringContainsString( "add_filter( 'preprocess_comment', array( \$this, 'inspect_comment' ), 5 )", $filter );
		}

		/**
		 * Each of the three surfaces has exactly one owning class, and none of
		 * them registers a competing hook.
		 */
		public function test_each_surface_keeps_one_owner(): void {
			$gate  = $this->source( 'includes/class-reputation-gate.php' );
			$guard = $this->source( 'includes/class-registration-guard.php' );
			$proof = $this->source( 'includes/class-form-proof.php' );

			$this->assertStringNotContainsString( "add_filter( 'registration_errors'", $gate );
			$this->assertStringNotContainsString( "add_action( 'lostpassword_post'", $gate );

			$this->assertStringContainsString( "ReportedIP_Hive_Reputation_Gate::get_instance()->check( 'register'", $guard );
			$this->assertStringContainsString( "ReportedIP_Hive_Reputation_Gate::get_instance()->check( 'lostpassword'", $proof );
		}

		/**
		 * All three refusals name the cause and a way forward. A shared address
		 * means the reader is often not the person who earned the reputation.
		 */
		public function test_every_refusal_explains_itself(): void {
			require_once dirname( __DIR__, 2 ) . '/includes/class-reputation-gate.php';

			foreach ( array( 'comment', 'register', 'lostpassword' ) as $surface ) {
				$message = \ReportedIP_Hive_Reputation_Gate::message( $surface );

				$this->assertNotSame( '', $message );
				$this->assertStringContainsString( 'community threat network', $message );
				$this->assertStringContainsString( 'contact the site owner', $message );
			}
		}

		/**
		 * Every way a lookup can fail must read as "no opinion".
		 *
		 * An exhausted daily allowance, an HTTP 429, a timeout, a network
		 * error, a negative cache hit and a missing key all arrive here as
		 * `false`. If any of them ever produced a refusal, a site would stop
		 * accepting comments the moment its allowance ran out, which is the
		 * one outcome this feature must never cause.
		 *
		 * @dataProvider failed_lookups
		 * @param mixed $answer Lookup answer.
		 */
		public function test_a_failed_lookup_never_refuses( $answer ): void {
			require_once dirname( __DIR__, 2 ) . '/includes/class-reputation-gate.php';

			$verdict = \ReportedIP_Hive_Reputation_Gate::read_response( $answer, 75 );

			$this->assertFalse( $verdict['exceeds'] );
			$this->assertSame( 0, $verdict['confidence'] );
			$this->assertFalse( $verdict['infrastructure'] );
		}

		/**
		 * @return array<string, array<int, mixed>>
		 */
		public function failed_lookups(): array {
			return array(
				'quota exhausted, rate limited, timeout or no key' => array( false ),
				'null'                          => array( null ),
				'empty array'                   => array( array() ),
				'error envelope'                => array( array( 'errors' => array( 'over quota' ) ) ),
				'answer without the confidence' => array( array( 'totalReports' => 40 ) ),
				'non-numeric confidence'        => array( array( 'abuseConfidencePercentage' => 'lots' ) ),
				'string'                        => array( 'service unavailable' ),
				'integer'                       => array( 429 ),
			);
		}

		public function test_a_real_answer_is_read_correctly(): void {
			require_once dirname( __DIR__, 2 ) . '/includes/class-reputation-gate.php';

			$verdict = \ReportedIP_Hive_Reputation_Gate::read_response(
				array(
					'abuseConfidencePercentage' => 96,
					'totalReports'              => 40,
				),
				75
			);

			$this->assertTrue( $verdict['exceeds'] );
			$this->assertSame( 96, $verdict['confidence'] );
			$this->assertSame( 40, $verdict['reports'] );
			$this->assertSame( 75, $verdict['threshold'] );
		}

		public function test_the_threshold_is_inclusive(): void {
			require_once dirname( __DIR__, 2 ) . '/includes/class-reputation-gate.php';

			$this->assertTrue(
				\ReportedIP_Hive_Reputation_Gate::read_response( array( 'abuseConfidencePercentage' => 75 ), 75 )['exceeds']
			);
			$this->assertFalse(
				\ReportedIP_Hive_Reputation_Gate::read_response( array( 'abuseConfidencePercentage' => 74 ), 75 )['exceeds']
			);
		}

		/**
		 * Infrastructure the network vouches for is read but never refused.
		 */
		public function test_infrastructure_is_flagged_rather_than_refused(): void {
			require_once dirname( __DIR__, 2 ) . '/includes/class-reputation-gate.php';

			$verdict = \ReportedIP_Hive_Reputation_Gate::read_response(
				array(
					'abuseConfidencePercentage' => 96,
					'isWhitelisted'             => true,
				),
				75
			);

			$this->assertTrue( $verdict['infrastructure'] );
		}

		/**
		 * The sign-in path must treat a failed lookup the same way.
		 */
		public function test_the_login_path_also_needs_a_positive_answer(): void {
			$source = $this->source( 'reportedip-hive.php' );
			$start  = strpos( $source, 'public function pre_auth_check(' );
			$body   = substr( $source, (int) $start, 3000 );

			$this->assertStringContainsString( '$reputation && isset( $reputation[', $body );
		}
	}
}
