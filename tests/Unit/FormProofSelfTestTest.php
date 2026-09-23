<?php
/**
 * Unit tests for the form protection self-test.
 *
 * Two pure pieces carry the card. The stock take has to name the reason an
 * adapter is inactive, because "off" reads the same whether the form plugin is
 * missing, the plan does not cover it or the switch is simply off, and only one
 * of those three is something the operator can act on. The outcome has to agree
 * with the site it runs on: without the computation check a repeated answer
 * passes, and a test that called that a failure would send operators looking
 * for a fault that is a setting.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.58
 */

declare(strict_types=1);

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-form-proof.php';
	require_once dirname( __DIR__, 2 ) . '/admin/class-tools-page.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use ReportedIP_Hive_Form_Proof;
	use ReportedIP_Hive_Tools_Page;

	/**
	 * @covers \ReportedIP_Hive_Tools_Page
	 */
	final class FormProofSelfTestTest extends TestCase {

		/**
		 * A state with everything switched on and nothing installed.
		 *
		 * @param array<string, mixed> $overrides Values to replace.
		 * @return array<string, mixed>
		 */
		private function state( array $overrides = array() ): array {
			return array_merge(
				array(
					'enabled'         => true,
					'killswitch'      => false,
					'pow_covered'     => true,
					'pow_option'      => true,
					'secure'          => true,
					'pow_grace'       => false,
					'adapters'        => array(),
					'adapters_strict' => false,
					'adapters_until'  => 0,
					'until_text'      => '',
				),
				$overrides
			);
		}

		/**
		 * One adapter entry.
		 *
		 * @param bool $detected Whether the form plugin is loaded.
		 * @param bool $covered  Whether the plan covers the adapter.
		 * @param bool $option   Whether the switch is on.
		 * @return array<string, mixed>
		 */
		private function adapter( bool $detected, bool $covered, bool $option ): array {
			return array(
				'name'     => 'Contact Form 7',
				'detected' => $detected,
				'covered'  => $covered,
				'option'   => $option,
			);
		}

		/**
		 * The row for one adapter state.
		 *
		 * @param array<string, mixed> $state State to render.
		 * @return array<string, string>
		 */
		private function adapter_row( array $state ): array {
			$rows = ReportedIP_Hive_Tools_Page::selftest_inventory( $state );

			return $rows[2];
		}

		public function test_the_kill_switch_outranks_the_option(): void {
			$rows = ReportedIP_Hive_Tools_Page::selftest_inventory(
				$this->state(
					array(
						'enabled'    => false,
						'killswitch' => true,
					)
				)
			);

			$this->assertSame( 'danger', $rows[0]['badge'] );
			$this->assertStringContainsString( 'REPORTEDIP_HIVE_DISABLE_FORM_PROOF', $rows[0]['note'] );
		}

		public function test_a_plain_connection_says_the_task_is_bound_only(): void {
			$rows = ReportedIP_Hive_Tools_Page::selftest_inventory( $this->state( array( 'secure' => false ) ) );

			$this->assertSame( 'info', $rows[1]['badge'] );
			$this->assertStringContainsString( 'secure connection', $rows[1]['note'] );
			$this->assertStringContainsString( 'good once', $rows[1]['note'] );
		}

		public function test_the_plan_is_named_before_the_switch(): void {
			$rows = ReportedIP_Hive_Tools_Page::selftest_inventory(
				$this->state(
					array(
						'pow_covered' => false,
						'pow_option'  => false,
						'secure'      => false,
					)
				)
			);

			$this->assertSame( 'info', $rows[1]['badge'] );
			$this->assertStringContainsString( 'Professional', $rows[1]['note'] );
		}

		public function test_the_grace_shows_as_starting_up(): void {
			$rows = ReportedIP_Hive_Tools_Page::selftest_inventory( $this->state( array( 'pow_grace' => true ) ) );

			$this->assertSame( 'info', $rows[1]['badge'] );
			$this->assertStringContainsString( 'first day', $rows[1]['note'] );
		}

		public function test_the_computation_row_follows_the_master_switch(): void {
			$rows = ReportedIP_Hive_Tools_Page::selftest_inventory( $this->state( array( 'enabled' => false ) ) );

			$this->assertSame( 'warning', $rows[1]['badge'] );
			$this->assertStringContainsString( 'whole site', $rows[1]['note'] );
		}

		public function test_a_missing_form_plugin_is_not_a_switch_someone_forgot(): void {
			$row = $this->adapter_row( $this->state( array( 'adapters' => array( $this->adapter( false, true, true ) ) ) ) );

			$this->assertSame( 'info', $row['badge'] );
			$this->assertStringContainsString( 'Contact Form 7 is not active', $row['note'] );
		}

		public function test_an_uncovered_adapter_names_the_plan_not_the_switch(): void {
			$row = $this->adapter_row( $this->state( array( 'adapters' => array( $this->adapter( true, false, true ) ) ) ) );

			$this->assertSame( 'info', $row['badge'] );
			$this->assertStringContainsString( 'plan', $row['note'] );
		}

		public function test_an_installed_and_covered_adapter_with_its_switch_off(): void {
			$row = $this->adapter_row( $this->state( array( 'adapters' => array( $this->adapter( true, true, false ) ) ) ) );

			$this->assertSame( 'warning', $row['badge'] );
			$this->assertStringContainsString( 'switch on the Protection page is off', $row['note'] );
		}

		public function test_an_armed_adapter_is_inactive_while_the_layer_is_off(): void {
			$row = $this->adapter_row(
				$this->state(
					array(
						'enabled'  => false,
						'adapters' => array( $this->adapter( true, true, true ) ),
					)
				)
			);

			$this->assertSame( 'warning', $row['badge'] );
			$this->assertStringContainsString( 'off for the whole site', $row['note'] );
		}

		public function test_an_armed_adapter_reads_active(): void {
			$row = $this->adapter_row( $this->state( array( 'adapters' => array( $this->adapter( true, true, true ) ) ) ) );

			$this->assertSame( 'success', $row['badge'] );
		}

		public function test_the_grace_row_carries_the_end_time(): void {
			$rows = ReportedIP_Hive_Tools_Page::selftest_inventory(
				$this->state(
					array(
						'adapters_until' => 1757000000,
						'until_text'     => '2026-09-16 12:00',
					)
				)
			);
			$grace = $rows[ count( $rows ) - 1 ];

			$this->assertSame( 'warning', $grace['badge'] );
			$this->assertStringContainsString( '2026-09-16 12:00', $grace['note'] );

			$rows = ReportedIP_Hive_Tools_Page::selftest_inventory(
				$this->state(
					array(
						'adapters_until'  => 1757000000,
						'adapters_strict' => true,
					)
				)
			);

			$this->assertSame( 'success', $rows[ count( $rows ) - 1 ]['badge'] );
		}

		public function test_the_grace_row_is_quiet_without_an_adapter(): void {
			$rows  = ReportedIP_Hive_Tools_Page::selftest_inventory( $this->state() );
			$grace = $rows[ count( $rows ) - 1 ];

			$this->assertSame( 'info', $grace['badge'] );
		}

		public function test_the_expected_verdicts_follow_the_computation_check(): void {
			$this->assertSame( ReportedIP_Hive_Form_Proof::PROVED, ReportedIP_Hive_Tools_Page::selftest_expected( 'visitor', true ) );
			$this->assertSame( ReportedIP_Hive_Form_Proof::PROVED, ReportedIP_Hive_Tools_Page::selftest_expected( 'visitor', false ) );
			$this->assertSame( ReportedIP_Hive_Form_Proof::FAILED, ReportedIP_Hive_Tools_Page::selftest_expected( 'replay', true ) );
			$this->assertSame( ReportedIP_Hive_Form_Proof::PROVED, ReportedIP_Hive_Tools_Page::selftest_expected( 'replay', false ) );
			$this->assertSame( ReportedIP_Hive_Form_Proof::TRIPPED, ReportedIP_Hive_Tools_Page::selftest_expected( 'bot', true ) );
			$this->assertSame( ReportedIP_Hive_Form_Proof::TRIPPED, ReportedIP_Hive_Tools_Page::selftest_expected( 'bot', false ) );
		}

		public function test_three_matching_passes_are_a_pass(): void {
			$outcome = ReportedIP_Hive_Tools_Page::selftest_outcome(
				array(
					'visitor' => ReportedIP_Hive_Form_Proof::PROVED,
					'replay'  => ReportedIP_Hive_Form_Proof::FAILED,
					'bot'     => ReportedIP_Hive_Form_Proof::TRIPPED,
				),
				true
			);

			$this->assertTrue( $outcome['complete'] );
			$this->assertTrue( $outcome['pass'] );
			$this->assertSame( array(), $outcome['failed'] );
			$this->assertTrue( $outcome['rows']['replay']['ok'] );
		}

		public function test_a_passing_replay_is_a_pass_without_the_computation_check(): void {
			$actual = array(
				'visitor' => ReportedIP_Hive_Form_Proof::PROVED,
				'replay'  => ReportedIP_Hive_Form_Proof::PROVED,
				'bot'     => ReportedIP_Hive_Form_Proof::TRIPPED,
			);

			$this->assertTrue( ReportedIP_Hive_Tools_Page::selftest_outcome( $actual, false )['pass'] );
			$this->assertSame( array( 'replay' ), ReportedIP_Hive_Tools_Page::selftest_outcome( $actual, true )['failed'] );
		}

		public function test_a_missing_pass_is_never_a_pass(): void {
			$outcome = ReportedIP_Hive_Tools_Page::selftest_outcome(
				array(
					'visitor' => ReportedIP_Hive_Form_Proof::PROVED,
					'replay'  => ReportedIP_Hive_Form_Proof::FAILED,
				),
				true
			);

			$this->assertFalse( $outcome['complete'] );
			$this->assertFalse( $outcome['pass'] );
			$this->assertArrayNotHasKey( 'bot', $outcome['rows'] );
		}

		public function test_a_let_through_bot_is_reported_as_a_failure(): void {
			$outcome = ReportedIP_Hive_Tools_Page::selftest_outcome(
				array(
					'visitor' => ReportedIP_Hive_Form_Proof::PROVED,
					'replay'  => ReportedIP_Hive_Form_Proof::FAILED,
					'bot'     => ReportedIP_Hive_Form_Proof::PROVED,
				),
				true
			);

			$this->assertFalse( $outcome['pass'] );
			$this->assertSame( array( 'bot' ), $outcome['failed'] );
		}

		public function test_the_replay_meaning_tells_the_two_readings_apart(): void {
			$this->assertStringContainsString( 'refused the second time', ReportedIP_Hive_Tools_Page::selftest_meaning( 'replay', true, true ) );
			$this->assertStringContainsString( 'nothing to repeat', ReportedIP_Hive_Tools_Page::selftest_meaning( 'replay', true, false ) );
		}
	}
}
