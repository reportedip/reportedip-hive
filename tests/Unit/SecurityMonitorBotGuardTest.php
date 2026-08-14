<?php
/**
 * Architecture invariant tests for the central never-block-a-good-bot guard.
 *
 * Every automatic IP block funnels through
 * `Security_Monitor::handle_threshold_exceeded()`; the guard must run there
 * FIRST — before the threshold log, the block, the community API report and
 * the admin mail — and again defensively inside `auto_block_ip()` for direct
 * callers. The full monitor depends on too many runtime singletons to mock
 * cheaply, so the contract is anchored via source inspection (the established
 * pattern, see RestMonitorBotAllowlistTest); the verdict-combination logic
 * itself is behaviourally covered in BotAllowlistExemptionTest.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.26
 */

namespace {
	if ( ! defined( 'ABSPATH' ) ) {
		exit;
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class SecurityMonitorBotGuardTest extends TestCase {

		private function source(): string {
			$path = dirname( __DIR__, 2 ) . '/includes/class-security-monitor.php';
			$buf  = file_get_contents( $path );
			$this->assertNotFalse( $buf, 'security-monitor source must be readable' );
			return (string) $buf;
		}

		public function test_guard_consults_unified_crawler_exemption() {
			$this->assertStringContainsString(
				'ReportedIP_Hive_Bot_Allowlist::is_exempt_crawler',
				$this->source(),
				'The central guard must use the unified crawler-exemption decision'
			);
		}

		public function test_guard_runs_first_in_handle_threshold_exceeded() {
			$source = $this->source();

			$handler_pos = strpos( $source, 'function handle_threshold_exceeded' );
			$this->assertNotFalse( $handler_pos );

			$body       = substr( $source, $handler_pos );
			$guard_pos  = strpos( $body, 'should_spare_verified_bot' );
			$log_pos    = strpos( $body, 'log_security_event' );
			$block_pos  = strpos( $body, 'auto_block_ip' );
			$report_pos = strpos( $body, 'report_security_event' );

			$this->assertNotFalse( $guard_pos );
			$this->assertLessThan( $log_pos, $guard_pos, 'Guard must run before the threshold-exceeded log entry' );
			$this->assertLessThan( $block_pos, $guard_pos, 'Guard must run before the auto-block' );
			$this->assertLessThan( $report_pos, $guard_pos, 'Guard must run before the community API report' );
		}

		public function test_auto_block_ip_has_defensive_recheck() {
			$source = $this->source();

			$block_fn_pos = strpos( $source, 'function auto_block_ip' );
			$this->assertNotFalse( $block_fn_pos );

			$body      = substr( $source, $block_fn_pos );
			$guard_pos = strpos( $body, 'should_spare_verified_bot' );
			$write_pos = strpos( $body, '->block_ip(' );

			$this->assertNotFalse( $guard_pos, 'auto_block_ip() must re-check the exemption for direct callers' );
			$this->assertNotFalse( $write_pos );
			$this->assertLessThan( $write_pos, $guard_pos, 'The re-check must precede the block write' );
		}

		public function test_averted_decisions_are_logged() {
			$this->assertStringContainsString(
				"'verified_bot_block_averted'",
				$this->source(),
				'Averted blocks must be visible to operators in the security log'
			);
		}

		public function test_credential_events_are_never_spared() {
			$source = $this->source();

			$const_pos = strpos( $source, 'CREDENTIAL_EVENTS' );
			$this->assertNotFalse( $const_pos, 'Credential-bearing event slugs must be enumerated in CREDENTIAL_EVENTS' );

			foreach ( array( 'failed_login', 'password_spray', '2fa_brute_force', 'app_password_abuse', 'wc_login_failed' ) as $slug ) {
				$this->assertStringContainsString(
					"'" . $slug . "'",
					substr( $source, $const_pos, 400 ),
					"Credential event '$slug' must be excluded from the bot guard — no genuine crawler submits credentials"
				);
			}

			$guard_fn_pos = strpos( $source, 'function should_spare_verified_bot' );
			$this->assertNotFalse( $guard_fn_pos );

			$body          = substr( $source, $guard_fn_pos );
			$exclusion_pos = strpos( $body, 'CREDENTIAL_EVENTS' );
			$allowlist_pos = strpos( $body, 'is_exempt_crawler' );

			$this->assertNotFalse( $exclusion_pos, 'The guard must check the credential-event exclusion' );
			$this->assertNotFalse( $allowlist_pos );
			$this->assertLessThan(
				$allowlist_pos,
				$exclusion_pos,
				'The credential-event exclusion must run before the crawler allowlist is consulted'
			);
		}

		/**
		 * Reflection handle on the private malicious-request predicate.
		 */
		private function malicious_check(): \ReflectionMethod {
			require_once dirname( __DIR__, 2 ) . '/includes/class-security-monitor.php';

			$method = new \ReflectionMethod( \ReportedIP_Hive_Security_Monitor::class, 'is_unambiguously_malicious' );

			return $method;
		}

		/**
		 * @dataProvider malicious_events
		 */
		public function test_malicious_requests_lose_the_exemption( string $event, array $details, bool $expected, string $message ) {
			$method  = $this->malicious_check();
			$monitor = ( new \ReflectionClass( \ReportedIP_Hive_Security_Monitor::class ) )->newInstanceWithoutConstructor();

			$this->assertSame( $expected, $method->invoke( $monitor, $event, $details ), $message );
		}

		public function malicious_events(): array {
			return array(
				'honeypot path'      => array( 'scan_404', array( 'pattern_hit' => true, 'path' => '/.env' ), true, 'Nothing links to /.env, so no crawler arrives there by following the site' ),
				'ordinary 404 burst' => array( 'scan_404', array( 'pattern_hit' => false, 'path' => '/old-page/' ), false, 'A crawl over stale URLs stays sparable' ),
				'file probe'         => array( 'waf_block', array( 'group' => 'file_probe', 'rule' => 'waf_file_probe' ), true, 'Probing for backup files is an attack on the first attempt' ),
				'path traversal'     => array( 'waf_block', array( 'group' => 'path_traversal', 'rule' => 'waf_traversal' ), true, 'Traversal payloads have no benign reading' ),
				'php wrapper'        => array( 'waf_block', array( 'group' => 'php_injection', 'rule' => 'waf_php_wrapper_b64' ), true, 'php:// wrappers are never sent by a crawler' ),
				'xss'                => array( 'waf_block', array( 'group' => 'xss', 'rule' => 'waf_xss_handler' ), false, 'Editor and form content trips XSS patterns, so it keeps the ladder' ),
				'sqli'               => array( 'waf_block', array( 'group' => 'sql_injection', 'rule' => 'waf_sqli_bool' ), false, 'A customer searching for a product code must not be locked out' ),
				'decoy'              => array( 'decoy_pathblock_hit', array( 'path' => '/wp-config.php.bak' ), true, 'A decoy path cannot be reached by accident' ),
				'rest burst'         => array( 'rest_abuse', array( 'route' => '/wp/v2/posts' ), false, 'Volume alone is not proof of malice' ),
				'no details'         => array( 'waf_block', array(), false, 'Without a group the guard cannot claim certainty' ),
			);
		}

		public function test_denied_exemptions_are_logged_and_throttled() {
			$source = $this->source();

			$this->assertStringContainsString(
				"'bot_exemption_denied'",
				$source,
				'A revoked exemption must leave an audit trail'
			);

			$log_fn_pos = strpos( $source, 'function log_exemption_denied' );
			$this->assertNotFalse( $log_fn_pos );

			$body = substr( $source, $log_fn_pos, 900 );
			$this->assertStringContainsString( 'get_transient', $body, 'The audit log must be throttled like the own-server guard' );
			$this->assertStringContainsString( 'HOUR_IN_SECONDS', $body );
		}

		public function test_malicious_check_precedes_the_averted_log() {
			$source = $this->source();

			$guard_fn_pos = strpos( $source, 'function should_spare_verified_bot' );
			$this->assertNotFalse( $guard_fn_pos );

			$body        = substr( $source, $guard_fn_pos );
			$malicious   = strpos( $body, 'is_unambiguously_malicious' );
			$averted_log = strpos( $body, "'verified_bot_block_averted'" );

			$this->assertNotFalse( $malicious, 'The guard must consult the malicious-request predicate' );
			$this->assertNotFalse( $averted_log );
			$this->assertLessThan(
				$averted_log,
				$malicious,
				'A denied exemption must never be recorded as an averted block'
			);
		}

		public function test_guard_survives_missing_user_agent() {
			$source = $this->source();

			$guard_fn_pos = strpos( $source, 'function should_spare_verified_bot' );
			$this->assertNotFalse( $guard_fn_pos );

			$body = substr( $source, $guard_fn_pos, 1200 );
			$this->assertStringContainsString(
				"HTTP_USER_AGENT",
				$body,
				'Guard reads the UA from the request when present'
			);
			$this->assertStringContainsString(
				": ''",
				$body,
				'Guard must degrade to an empty UA (IP-only check) in cron/CLI contexts'
			);
		}
	}
}
