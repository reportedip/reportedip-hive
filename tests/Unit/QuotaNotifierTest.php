<?php
/**
 * Unit tests for {@see ReportedIP_Hive_Quota_Notifier}.
 *
 * Covers the pure-function paths (stage evaluation, cooldown decision) so
 * the heart of the 80/100 % notification logic is verified without
 * dragging the Mailer / Defaults dependencies into the test harness.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.16
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

require_once dirname( __DIR__, 2 ) . '/includes/class-quota-notifier.php';

class QuotaNotifierTest extends TestCase {

	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_options'] = array();
	}

	private function snapshot( int $mail_used, int $mail_limit, int $sms_used, int $sms_limit, int $period_start = 1700000000, int $period_end = 1702592000 ): array {
		return array(
			'tier'         => 'professional',
			'period_start' => $period_start,
			'period_end'   => $period_end,
			'mail'         => array(
				'used'           => $mail_used,
				'limit'          => $mail_limit,
				'bundle_balance' => 0,
			),
			'sms'          => array(
				'used'           => $sms_used,
				'limit'          => $sms_limit,
				'bundle_balance' => 0,
			),
		);
	}

	public function test_evaluate_channel_returns_warn_at_80_percent(): void {
		$snapshot = $this->snapshot( 400, 500, 0, 25 );
		$this->assertSame(
			\ReportedIP_Hive_Quota_Notifier::STAGE_WARN,
			\ReportedIP_Hive_Quota_Notifier::evaluate_channel( $snapshot, 'mail' )
		);
	}

	public function test_evaluate_channel_returns_capped_at_100_percent(): void {
		$snapshot = $this->snapshot( 500, 500, 0, 25 );
		$this->assertSame(
			\ReportedIP_Hive_Quota_Notifier::STAGE_CAPPED,
			\ReportedIP_Hive_Quota_Notifier::evaluate_channel( $snapshot, 'mail' )
		);
	}

	public function test_evaluate_channel_returns_capped_when_over_limit(): void {
		$snapshot = $this->snapshot( 0, 25, 30, 25 );
		$this->assertSame(
			\ReportedIP_Hive_Quota_Notifier::STAGE_CAPPED,
			\ReportedIP_Hive_Quota_Notifier::evaluate_channel( $snapshot, 'sms' )
		);
	}

	public function test_evaluate_channel_returns_null_under_threshold(): void {
		$snapshot = $this->snapshot( 100, 500, 5, 25 );
		$this->assertNull( \ReportedIP_Hive_Quota_Notifier::evaluate_channel( $snapshot, 'mail' ) );
		$this->assertNull( \ReportedIP_Hive_Quota_Notifier::evaluate_channel( $snapshot, 'sms' ) );
	}

	public function test_evaluate_channel_returns_null_for_unlimited_or_missing_limit(): void {
		$snap_unl = $this->snapshot( 1000, 0, 0, 0 );
		$this->assertNull( \ReportedIP_Hive_Quota_Notifier::evaluate_channel( $snap_unl, 'mail' ) );

		$snap_null = array(
			'mail' => array(
				'used'  => 500,
				'limit' => null,
			),
			'sms'  => array(),
		);
		$this->assertNull( \ReportedIP_Hive_Quota_Notifier::evaluate_channel( $snap_null, 'mail' ) );
	}

	public function test_should_send_true_when_no_state_recorded(): void {
		$snap = $this->snapshot( 500, 500, 0, 25 );
		$this->assertTrue(
			\ReportedIP_Hive_Quota_Notifier::should_send( 'mail', \ReportedIP_Hive_Quota_Notifier::STAGE_CAPPED, $snap )
		);
	}

	public function test_should_send_false_within_cooldown_of_same_period(): void {
		$period = 1700000000;
		$snap   = $this->snapshot( 500, 500, 0, 25, $period, $period + 2592000 );

		// Pretend we sent the capped mail one second ago in the same period.
		$GLOBALS['wp_options'][ \ReportedIP_Hive_Quota_Notifier::OPT_STATE ] = array(
			'mail.' . \ReportedIP_Hive_Quota_Notifier::STAGE_CAPPED => array(
				'sent_at'      => time() - 1,
				'period_start' => $period,
			),
		);

		$this->assertFalse(
			\ReportedIP_Hive_Quota_Notifier::should_send( 'mail', \ReportedIP_Hive_Quota_Notifier::STAGE_CAPPED, $snap )
		);
	}

	public function test_should_send_true_on_new_billing_period_even_within_cooldown(): void {
		$old_period = 1700000000;
		$new_period = 1702592000;
		$snap       = $this->snapshot( 500, 500, 0, 25, $new_period, $new_period + 2592000 );

		$GLOBALS['wp_options'][ \ReportedIP_Hive_Quota_Notifier::OPT_STATE ] = array(
			'mail.' . \ReportedIP_Hive_Quota_Notifier::STAGE_CAPPED => array(
				'sent_at'      => time() - 60,
				'period_start' => $old_period,
			),
		);

		$this->assertTrue(
			\ReportedIP_Hive_Quota_Notifier::should_send( 'mail', \ReportedIP_Hive_Quota_Notifier::STAGE_CAPPED, $snap )
		);
	}

	public function test_should_send_true_when_cooldown_elapsed_same_period(): void {
		$period = 1700000000;
		$snap   = $this->snapshot( 500, 500, 0, 25, $period, $period + 2592000 );

		$GLOBALS['wp_options'][ \ReportedIP_Hive_Quota_Notifier::OPT_STATE ] = array(
			'mail.' . \ReportedIP_Hive_Quota_Notifier::STAGE_CAPPED => array(
				'sent_at'      => time() - ( \ReportedIP_Hive_Quota_Notifier::COOLDOWN_SECS + 60 ),
				'period_start' => $period,
			),
		);

		$this->assertTrue(
			\ReportedIP_Hive_Quota_Notifier::should_send( 'mail', \ReportedIP_Hive_Quota_Notifier::STAGE_CAPPED, $snap )
		);
	}

	public function test_is_enabled_defaults_true(): void {
		$this->assertTrue( \ReportedIP_Hive_Quota_Notifier::is_enabled() );
	}

	public function test_is_enabled_respects_killswitch(): void {
		$GLOBALS['wp_options'][ \ReportedIP_Hive_Quota_Notifier::OPT_ENABLED ] = false;
		$this->assertFalse( \ReportedIP_Hive_Quota_Notifier::is_enabled() );
	}
}
