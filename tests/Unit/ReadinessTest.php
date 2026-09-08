<?php
/**
 * Unit tests for {@see ReportedIP_Hive_Readiness}.
 *
 * The detectors are pure predicates, so each one is exercised on both
 * branches without touching WordPress. The stateful half — reconcile,
 * dismissal window, mail-failure counter and cache flush — runs against the
 * option/transient stubs. Two source assertions pin the wiring that cannot
 * be observed from a unit process.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

namespace {

	if ( ! defined( 'REPORTEDIP_HIVE_SITE_URL' ) ) {
		define( 'REPORTEDIP_HIVE_SITE_URL', 'https://reportedip.com' );
	}

	if ( ! function_exists( 'number_format_i18n' ) ) {
		/**
		 * Minimal stand-in for the WordPress number formatter.
		 *
		 * @param float|int $number   Value to format.
		 * @param int       $decimals Decimal places.
		 * @return string
		 */
		function number_format_i18n( $number, $decimals = 0 ) {
			return number_format( (float) $number, (int) $decimals, '.', ',' );
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-readiness.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class ReadinessTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();
		}

		public function test_guard_queue_is_critical_only_when_enabled_and_unwritable(): void {
			$issue = \ReportedIP_Hive_Readiness::guard_queue( true, false, '/var/www/uploads/reportedip-hive' );

			$this->assertIsArray( $issue );
			$this->assertSame( 'guard_queue_unwritable', $issue['key'] );
			$this->assertSame( \ReportedIP_Hive_Readiness::SEV_CRITICAL, $issue['severity'] );
			$this->assertStringContainsString( '/var/www/uploads/reportedip-hive', $issue['message'] );

			$this->assertNull( \ReportedIP_Hive_Readiness::guard_queue( false, false, '/tmp' ) );
			$this->assertNull( \ReportedIP_Hive_Readiness::guard_queue( true, true, '/tmp' ) );
		}

		public function test_cron_stalled_requires_every_scheduled_hook_overdue_24h(): void {
			$now      = 1750000000;
			$stale    = $now - 90000;
			$all_late = array(
				'a' => $stale,
				'b' => $stale,
			);

			$issue = \ReportedIP_Hive_Readiness::cron_stalled( $all_late, $now );
			$this->assertIsArray( $issue );
			$this->assertSame( 'cron_stalled', $issue['key'] );
			$this->assertSame( \ReportedIP_Hive_Readiness::SEV_CRITICAL, $issue['severity'] );

			$this->assertNull(
				\ReportedIP_Hive_Readiness::cron_stalled(
					array(
						'a' => $stale,
						'b' => $now + 600,
					),
					$now
				),
				'One healthy hook means cron is firing.'
			);
			$this->assertNull(
				\ReportedIP_Hive_Readiness::cron_stalled(
					array(
						'a' => $stale,
						'b' => false,
					),
					$now
				),
				'A hook without a schedule is a different fault, not an overdue one.'
			);
			$this->assertNull( \ReportedIP_Hive_Readiness::cron_stalled( array(), $now ) );
		}

		public function test_cron_disabled_stale_needs_constant_without_alternate_and_hour_overdue(): void {
			$now  = 1750000000;
			$late = array( 'a' => $now - 7200 );

			$issue = \ReportedIP_Hive_Readiness::cron_disabled_stale( true, false, $late, $now );
			$this->assertIsArray( $issue );
			$this->assertSame( 'cron_disabled_stale', $issue['key'] );
			$this->assertSame( \ReportedIP_Hive_Readiness::SEV_WARNING, $issue['severity'] );

			$this->assertNull( \ReportedIP_Hive_Readiness::cron_disabled_stale( false, false, $late, $now ) );
			$this->assertNull( \ReportedIP_Hive_Readiness::cron_disabled_stale( true, true, $late, $now ) );
			$this->assertNull(
				\ReportedIP_Hive_Readiness::cron_disabled_stale( true, false, array( 'a' => $now - 60 ), $now ),
				'A minute of lag is normal for a server cron.'
			);
		}

		public function test_trusted_header_open_only_when_header_set_and_no_ranges(): void {
			$issue = \ReportedIP_Hive_Readiness::trusted_header( 'HTTP_X_FORWARDED_FOR', array() );

			$this->assertIsArray( $issue );
			$this->assertSame( 'trusted_header_open', $issue['key'] );
			$this->assertSame( \ReportedIP_Hive_Readiness::SEV_WARNING, $issue['severity'] );

			$this->assertNull( \ReportedIP_Hive_Readiness::trusted_header( '', array() ) );
			$this->assertNull( \ReportedIP_Hive_Readiness::trusted_header( 'HTTP_X_REAL_IP', array( '10.0.0.0/8' ) ) );
		}

		public function test_schema_outdated_below_current_version(): void {
			$issue = \ReportedIP_Hive_Readiness::schema_outdated( 15, 16 );

			$this->assertIsArray( $issue );
			$this->assertSame( 'schema_outdated', $issue['key'] );
			$this->assertSame( \ReportedIP_Hive_Readiness::SEV_CRITICAL, $issue['severity'] );
			$this->assertStringContainsString( '15', $issue['message'] );
			$this->assertStringContainsString( '16', $issue['message'] );

			$this->assertNull( \ReportedIP_Hive_Readiness::schema_outdated( 16, 16 ) );
			$this->assertNull( \ReportedIP_Hive_Readiness::schema_outdated( 17, 16 ) );
		}

		public function test_api_degraded_passthrough_formats_rate_and_total(): void {
			$issue = \ReportedIP_Hive_Readiness::api_degraded( true, 42.5, 40 );

			$this->assertIsArray( $issue );
			$this->assertSame( 'api_degraded', $issue['key'] );
			$this->assertStringContainsString( '42.5', $issue['message'] );
			$this->assertStringContainsString( '40', $issue['message'] );

			$this->assertNull( \ReportedIP_Hive_Readiness::api_degraded( false, 42.5, 40 ) );
		}

		public function test_relay_cap_yields_channel_specific_key(): void {
			$state = array(
				'hit_at'      => 1750000000,
				'retry_after' => 3600,
			);

			$mail = \ReportedIP_Hive_Readiness::relay_cap( 'mail', $state );
			$sms  = \ReportedIP_Hive_Readiness::relay_cap( 'sms', $state );

			$this->assertSame( 'relay_cap_mail', $mail['key'] );
			$this->assertSame( 'relay_cap_sms', $sms['key'] );
			$this->assertSame( \ReportedIP_Hive_Readiness::SEV_WARNING, $mail['severity'] );

			$this->assertNull( \ReportedIP_Hive_Readiness::relay_cap( 'mail', null ) );
			$this->assertNull( \ReportedIP_Hive_Readiness::relay_cap( 'sms', null ) );
		}

		public function test_mail_failures_reads_count_and_last_error(): void {
			$issue = \ReportedIP_Hive_Readiness::mail_failures(
				array(
					'count'      => 4,
					'last_error' => 'SMTP connect() failed',
					'last_at'    => 1750000000,
				)
			);

			$this->assertIsArray( $issue );
			$this->assertSame( 'mail_failures', $issue['key'] );
			$this->assertStringContainsString( '4', $issue['message'] );
			$this->assertStringContainsString( 'SMTP connect() failed', $issue['message'] );

			$this->assertNull( \ReportedIP_Hive_Readiness::mail_failures( null ) );
			$this->assertNull(
				\ReportedIP_Hive_Readiness::mail_failures(
					array(
						'count'      => 0,
						'last_error' => '',
						'last_at'    => 0,
					)
				)
			);
		}

		public function test_crypto_missing_when_no_active_method(): void {
			$issue = \ReportedIP_Hive_Readiness::crypto_missing( false );

			$this->assertIsArray( $issue );
			$this->assertSame( 'crypto_missing', $issue['key'] );
			$this->assertSame( \ReportedIP_Hive_Readiness::SEV_WARNING, $issue['severity'] );

			$this->assertNull( \ReportedIP_Hive_Readiness::crypto_missing( 'sodium' ) );
		}

		public function test_queue_failed_and_backlog_thresholds(): void {
			$failed = \ReportedIP_Hive_Readiness::queue_failed( 7 );
			$this->assertSame( 'queue_failed', $failed['key'] );
			$this->assertStringContainsString( '7', $failed['message'] );
			$this->assertNull( \ReportedIP_Hive_Readiness::queue_failed( 0 ) );

			$this->assertNull( \ReportedIP_Hive_Readiness::queue_backlog( 49, 50, 200 ) );

			$warn = \ReportedIP_Hive_Readiness::queue_backlog( 50, 50, 200 );
			$this->assertSame( 'queue_backlog', $warn['key'] );
			$this->assertSame( \ReportedIP_Hive_Readiness::SEV_WARNING, $warn['severity'] );

			$crit = \ReportedIP_Hive_Readiness::queue_backlog( 250, 50, 200 );
			$this->assertSame( \ReportedIP_Hive_Readiness::SEV_CRITICAL, $crit['severity'] );
		}

		public function test_reconcile_sets_first_seen_once_and_prunes_resolved_keys(): void {
			$now    = 1750000000;
			$issues = array(
				array(
					'key'      => 'queue_failed',
					'severity' => \ReportedIP_Hive_Readiness::SEV_WARNING,
					'label'    => 'x',
					'message'  => 'y',
				),
			);
			$state  = array(
				'queue_failed'    => array(
					'first_seen'      => $now - 5000,
					'dismissed_until' => 0,
				),
				'crypto_missing'  => array(
					'first_seen'      => $now - 9000,
					'dismissed_until' => 0,
				),
			);

			$result = \ReportedIP_Hive_Readiness::reconcile( $issues, $state, $now );

			$this->assertSame( $now - 5000, $result['issues'][0]['first_seen'], 'first_seen survives across computes.' );
			$this->assertArrayHasKey( 'queue_failed', $result['state'] );
			$this->assertArrayNotHasKey( 'crypto_missing', $result['state'], 'Resolved conditions are pruned.' );

			$fresh = \ReportedIP_Hive_Readiness::reconcile( $issues, array(), $now );
			$this->assertSame( $now, $fresh['issues'][0]['first_seen'] );
		}

		public function test_reconcile_honours_dismissed_until_but_never_for_critical(): void {
			$now    = 1750000000;
			$issues = array(
				array(
					'key'      => 'queue_backlog',
					'severity' => \ReportedIP_Hive_Readiness::SEV_WARNING,
					'label'    => 'x',
					'message'  => 'y',
				),
				array(
					'key'      => 'schema_outdated',
					'severity' => \ReportedIP_Hive_Readiness::SEV_CRITICAL,
					'label'    => 'x',
					'message'  => 'y',
				),
			);
			$state  = array(
				'queue_backlog'   => array(
					'first_seen'      => $now - 10,
					'dismissed_until' => $now + 600,
				),
				'schema_outdated' => array(
					'first_seen'      => $now - 10,
					'dismissed_until' => $now + 600,
				),
			);

			$result = \ReportedIP_Hive_Readiness::reconcile( $issues, $state, $now );

			$this->assertTrue( $result['issues'][0]['dismissable'] );
			$this->assertTrue( $result['issues'][0]['dismissed'] );
			$this->assertFalse( $result['issues'][1]['dismissable'], 'Critical issues can never be hidden.' );
			$this->assertFalse( $result['issues'][1]['dismissed'] );

			$expired = \ReportedIP_Hive_Readiness::reconcile( $issues, $state, $now + 700 );
			$this->assertFalse( $expired['issues'][0]['dismissed'], 'The window ends on its own.' );
		}

		public function test_dismiss_writes_seven_day_window_through_option_routing(): void {
			$now = time();
			\ReportedIP_Hive_Readiness::dismiss( 'queue_backlog', $now );

			$state = $GLOBALS['wp_options'][ \ReportedIP_Hive_Readiness::OPT_STATE ];
			$this->assertSame(
				$now + \ReportedIP_Hive_Readiness::DISMISS_SECS,
				$state['queue_backlog']['dismissed_until']
			);
			$this->assertSame( 604800, \ReportedIP_Hive_Readiness::DISMISS_SECS );
		}

		public function test_record_mail_failure_increments_rolling_counter_with_throttle(): void {
			\ReportedIP_Hive_Readiness::record_mail_failure( new \WP_Error( 'wp_mail_failed', 'first failure' ) );
			\ReportedIP_Hive_Readiness::record_mail_failure( new \WP_Error( 'wp_mail_failed', 'second failure' ) );

			$record = get_site_transient( \ReportedIP_Hive_Readiness::MAIL_FAIL_TRANSIENT );
			$this->assertSame( 1, $record['count'], 'A burst inside the throttle window costs one write.' );
			$this->assertStringContainsString( 'first failure', $record['last_error'] );

			$record['last_at'] = time() - ( \ReportedIP_Hive_Readiness::MAIL_FAIL_THROTTLE + 5 );
			set_site_transient( \ReportedIP_Hive_Readiness::MAIL_FAIL_TRANSIENT, $record, 86400 );

			\ReportedIP_Hive_Readiness::record_mail_failure( new \WP_Error( 'wp_mail_failed', 'third failure' ) );

			$record = get_site_transient( \ReportedIP_Hive_Readiness::MAIL_FAIL_TRANSIENT );
			$this->assertSame( 2, $record['count'] );
			$this->assertStringContainsString( 'third failure', $record['last_error'] );
		}

		public function test_record_mail_failure_strips_email_addresses(): void {
			\ReportedIP_Hive_Readiness::record_mail_failure(
				new \WP_Error( 'wp_mail_failed', 'Recipient rejected: user.name+tag@example.co.uk (550)' )
			);

			$record = get_site_transient( \ReportedIP_Hive_Readiness::MAIL_FAIL_TRANSIENT );
			$this->assertStringNotContainsString( '@', $record['last_error'] );
			$this->assertStringContainsString( '[redacted]', $record['last_error'] );
			$this->assertStringContainsString( '550', $record['last_error'] );
		}

		public function test_cache_flush_skips_the_hot_counter_options(): void {
			set_site_transient( \ReportedIP_Hive_Readiness::CACHE_KEY, array(), 300 );
			\ReportedIP_Hive_Readiness::flush_on_option_change( 'reportedip_hive_api_stats' );
			$this->assertIsArray(
				get_site_transient( \ReportedIP_Hive_Readiness::CACHE_KEY ),
				'api_stats is rewritten on every API call and must not keep the cache cold.'
			);

			\ReportedIP_Hive_Readiness::flush_on_option_change( 'reportedip_hive_cache_stats' );
			$this->assertIsArray(
				get_site_transient( \ReportedIP_Hive_Readiness::CACHE_KEY ),
				'cache_stats is rewritten at shutdown of every cached reputation lookup.'
			);

			\ReportedIP_Hive_Readiness::flush_on_option_change( 'some_other_plugin_option' );
			$this->assertIsArray( get_site_transient( \ReportedIP_Hive_Readiness::CACHE_KEY ) );

			\ReportedIP_Hive_Readiness::flush_on_option_change( 'reportedip_hive_waf_enabled' );
			$this->assertFalse( get_site_transient( \ReportedIP_Hive_Readiness::CACHE_KEY ) );
		}

		public function test_state_option_is_runtime_only(): void {
			$this->assertArrayNotHasKey(
				\ReportedIP_Hive_Readiness::OPT_STATE,
				\ReportedIP_Hive_Defaults::all_option_defaults(),
				'Readiness state is runtime state and must never be seeded or exported.'
			);
		}

		public function test_bootstrap_requires_and_initialises_readiness(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );

			$this->assertStringContainsString( "includes/class-readiness.php", $source );
			$this->assertStringContainsString( 'ReportedIP_Hive_Readiness::init();', $source );
		}

		public function test_inline_notices_delegate_queue_signals_to_readiness(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-admin-settings.php' );

			$start = strpos( $source, 'public static function render_inline_notices()' );
			$this->assertNotFalse( $start );
			$body = substr( $source, $start, (int) strpos( $source, "\n\t}\n", $start ) - $start );

			$this->assertStringContainsString( 'ReportedIP_Hive_Readiness::open_issues', $body );
			$this->assertStringNotContainsString( "SUM( CASE WHEN status = 'failed'", $body );
			$this->assertStringNotContainsString( "SUM( CASE WHEN status = 'failed'", $source );
		}
	}
}
