<?php
/**
 * Unit tests for the registration guard: entry grammar, plan caps, sanitizers
 * and the architectural invariants of the registration pipeline.
 *
 * The matcher and the sanitizers are pure statics, so they are exercised
 * directly. The pipeline itself depends on the plugin's runtime singletons
 * (database, logger, mode manager), so its contract — hook ownership,
 * evaluation order, the silent login-probe path — is anchored via source
 * inspection, the established pattern from SecurityMonitorBotGuardTest.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

declare(strict_types=1);

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-proxy-trust.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-waf.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-registration-guard.php';

	if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
		/**
		 * Minimal Mode-Manager double: the unlimited-rules feature is never
		 * available, so every plan gate behaves like a free installation.
		 */
		class ReportedIP_Hive_Mode_Manager {
			/**
			 * Singleton accessor.
			 *
			 * @return self
			 */
			public static function get_instance() {
				return new self();
			}

			/**
			 * Feature availability lookup.
			 *
			 * @param string $feature Feature slug.
			 * @return array<string, mixed>
			 */
			public function feature_status( $feature ) {
				unset( $feature );
				return array(
					'available' => false,
					'min_tier'  => 'Professional',
				);
			}
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class RegistrationGuardTest extends TestCase {

		/**
		 * Source of the guard class.
		 *
		 * @return string
		 */
		private function guard_source(): string {
			$buf = file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-registration-guard.php' );
			$this->assertNotFalse( $buf, 'guard source must be readable' );
			return (string) $buf;
		}

		/**
		 * Body of one method of the guard, up to the end of the file.
		 *
		 * @param string $name Method name.
		 * @return string
		 */
		private function guard_method( string $name ): string {
			$source = $this->guard_source();
			$pos    = strpos( $source, 'function ' . $name . '(' );
			$this->assertNotFalse( $pos, "method {$name}() must exist" );
			return substr( $source, (int) $pos );
		}

		public function test_entry_kind_classifies_exact_wildcard_and_regex(): void {
			$this->assertSame( 'exact', \ReportedIP_Hive_Registration_Guard::entry_kind( 'admin' ) );
			$this->assertSame( 'wildcard', \ReportedIP_Hive_Registration_Guard::entry_kind( 'admin*' ) );
			$this->assertSame( 'regex', \ReportedIP_Hive_Registration_Guard::entry_kind( '/^admin$/' ) );
			$this->assertSame( 'exact', \ReportedIP_Hive_Registration_Guard::entry_kind( '/' ), 'a lone slash is not a pattern' );
		}

		public function test_exact_entries_match_case_insensitively(): void {
			$this->assertSame( 'admin', \ReportedIP_Hive_Registration_Guard::matches_any( 'Admin', array( 'admin' ) ) );
			$this->assertNull( \ReportedIP_Hive_Registration_Guard::matches_any( 'administrator', array( 'admin' ) ) );
		}

		public function test_wildcard_is_anchored_at_both_ends(): void {
			$rules = array( '*@example.com' );

			$this->assertSame( '*@example.com', \ReportedIP_Hive_Registration_Guard::matches_any( 'a@example.com', $rules ) );
			$this->assertNull(
				\ReportedIP_Hive_Registration_Guard::matches_any( 'a@sub.example.com', $rules ),
				'a domain wildcard must not swallow subdomains'
			);
			$this->assertNull(
				\ReportedIP_Hive_Registration_Guard::matches_any( 'a@example.com.evil.test', $rules ),
				'the pattern must be anchored at the end'
			);
			$this->assertSame(
				'*@*.example.com',
				\ReportedIP_Hive_Registration_Guard::matches_any( 'a@sub.example.com', array( '*@*.example.com' ) )
			);
		}

		public function test_regex_entry_matches_and_reports_the_rule(): void {
			$this->assertSame(
				'/^admin\d+$/',
				\ReportedIP_Hive_Registration_Guard::matches_any( 'admin42', array( '/^admin\d+$/' ) )
			);
			$this->assertNull( \ReportedIP_Hive_Registration_Guard::matches_any( 'admin', array( '/^admin\d+$/' ) ) );
		}

		public function test_regex_entries_are_case_insensitive(): void {
			$this->assertSame(
				'/^admin$/',
				\ReportedIP_Hive_Registration_Guard::matches_any( 'ADMIN', array( '/^admin$/' ) )
			);
		}

		public function test_broken_regex_fails_open(): void {
			$this->assertNull(
				\ReportedIP_Hive_Registration_Guard::matches_any( 'anything', array( '/[/' ) ),
				'an uncompilable rule must be inert, never fatal'
			);
		}

		public function test_free_plan_keeps_the_first_ten_plain_entries(): void {
			$raw = implode( "\n", array( 'a1', 'a2', 'a3', 'a4', '/^r$/', 'a5', 'a6', 'a7', 'a8', 'a9', 'a10', 'a11' ) );

			$active = \ReportedIP_Hive_Registration_Guard::active_entries( $raw, false );

			$this->assertSame( array( 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'a10' ), $active );
		}

		public function test_unlimited_plan_keeps_every_entry(): void {
			$raw = implode( "\n", array( 'a1', '/^r$/', 'a2' ) );

			$this->assertSame( array( 'a1', '/^r$/', 'a2' ), \ReportedIP_Hive_Registration_Guard::active_entries( $raw, true ) );
		}

		public function test_stored_entries_drop_comments_blanks_and_duplicates(): void {
			$raw = "# note\n\nadmin\nadmin\n  root  \n";

			$this->assertSame( array( 'admin', 'root' ), \ReportedIP_Hive_Registration_Guard::stored_entries( $raw ) );
		}

		public function test_list_needs_tier_flags_the_eleventh_entry_and_any_regex(): void {
			$ten    = implode( "\n", array( 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'a10' ) );
			$eleven = $ten . "\na11";

			$this->assertFalse( \ReportedIP_Hive_Registration_Guard::list_needs_tier( $ten ) );
			$this->assertTrue( \ReportedIP_Hive_Registration_Guard::list_needs_tier( $eleven ) );
			$this->assertTrue( \ReportedIP_Hive_Registration_Guard::list_needs_tier( "admin\n/^adm/" ) );
			$this->assertFalse( \ReportedIP_Hive_Registration_Guard::list_needs_tier( '' ) );
		}

		public function test_username_list_splits_on_commas_only(): void {
			$clean = \ReportedIP_Hive_Registration_Guard::sanitize_username_list( "John Doe, Admin\n# note\nroot" );

			$this->assertSame( "john doe\nadmin\nroot", $clean, 'WordPress logins may contain spaces' );
		}

		public function test_username_list_drops_uncompilable_regex_and_keeps_regex_case(): void {
			$clean = \ReportedIP_Hive_Registration_Guard::sanitize_username_list( "/^AdMin\\d+$/\n/[/\nSupport" );

			$this->assertSame( "/^AdMin\\d+$/\nsupport", $clean );
		}

		public function test_email_list_normalises_bare_hosts_dedupes_and_lowercases(): void {
			$clean = \ReportedIP_Hive_Registration_Guard::sanitize_email_rule_list( "Example.COM\n*@example.com\nb.test, c.test" );

			$this->assertSame( "*@example.com\n*@b.test\n*@c.test", $clean );
		}

		public function test_email_list_splits_on_whitespace(): void {
			$clean = \ReportedIP_Hive_Registration_Guard::sanitize_email_rule_list( 'a.test b.test' );

			$this->assertSame( "*@a.test\n*@b.test", $clean, 'a dashboard that flattens newlines must not produce one bogus entry' );
		}

		public function test_ip_list_delegates_to_the_trusted_proxy_parser(): void {
			$clean = \ReportedIP_Hive_Registration_Guard::sanitize_ip_list( "# office\n203.0.113.0/24 198.51.100.7\nnot-an-ip\n2001:db8::/32" );

			$this->assertSame( "203.0.113.0/24\n198.51.100.7\n2001:db8::/32", $clean );
		}

		public function test_every_option_key_is_a_remote_registry_key_with_a_default(): void {
			$remote   = \ReportedIP_Hive_Settings_Registry::remote_spec();
			$defaults = \ReportedIP_Hive_Defaults::all_option_defaults();

			foreach ( \ReportedIP_Hive_Registration_Guard::OPTION_KEYS as $key ) {
				$this->assertArrayHasKey( $key, $remote, "{$key} must be remotely manageable." );
				$this->assertArrayHasKey( $key, $defaults, "{$key} must have a canonical default." );
			}
		}

		public function test_registry_gate_rejects_an_eleventh_entry_on_a_free_plan(): void {
			$ten    = implode( "\n", array( 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'a10' ) );
			$eleven = $ten . "\na11";

			$this->assertSame( $ten, \ReportedIP_Hive_Settings_Registry::sanitize( 'reportedip_hive_prohibited_usernames', $ten ) );

			$rejected = \ReportedIP_Hive_Settings_Registry::sanitize( 'reportedip_hive_prohibited_usernames', $eleven );
			$this->assertTrue( is_wp_error( $rejected ) );
			$this->assertSame( 'tier_locked', $rejected->get_error_code() );
		}

		public function test_registry_gate_rejects_a_regex_entry_on_a_free_plan(): void {
			$rejected = \ReportedIP_Hive_Settings_Registry::sanitize( 'reportedip_hive_email_rules', '/^spam@/' );

			$this->assertTrue( is_wp_error( $rejected ) );
			$this->assertSame( 'tier_locked', $rejected->get_error_code() );
		}

		public function test_registry_gate_rejects_a_non_empty_allowlist_but_never_an_empty_one(): void {
			$rejected = \ReportedIP_Hive_Settings_Registry::sanitize( 'reportedip_hive_registration_allowlist', '203.0.113.0/24' );
			$this->assertTrue( is_wp_error( $rejected ) );
			$this->assertSame( 'tier_locked', $rejected->get_error_code() );

			$this->assertSame( '', \ReportedIP_Hive_Settings_Registry::sanitize( 'reportedip_hive_registration_allowlist', '' ) );
		}

		public function test_disposable_email_no_longer_registers_registration_hooks(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-disposable-email.php' );

			$this->assertStringNotContainsString( "add_filter( 'registration_errors'", $source );
			$this->assertStringNotContainsString( "add_action( 'woocommerce_register_post'", $source );
			$this->assertStringContainsString(
				'public function evaluate(',
				$source,
				'the guard calls the classifier as the last pipeline step'
			);
		}

		public function test_guard_owns_every_registration_surface(): void {
			$source = $this->guard_source();

			foreach ( array(
				"add_filter( 'registration_errors'",
				"add_action( 'woocommerce_register_post'",
				"add_filter( 'wpmu_validate_user_signup'",
				"add_filter( 'wp_pre_insert_user_data'",
				"add_action( 'user_register'",
				"add_action( 'after_signup_user'",
				"add_action( 'wp_login_failed'",
			) as $registration ) {
				$this->assertStringContainsString( $registration, $source );
			}

			$this->assertStringNotContainsString(
				"add_filter( 'woocommerce_registration_errors'",
				$source,
				'WooCommerce fires both hooks on the same errors object; hooking both would evaluate twice'
			);
			$this->assertStringNotContainsString(
				'illegal_user_logins',
				$source,
				'that filter also runs on profile updates and would lock existing users out of their own profile'
			);
			$this->assertStringNotContainsString(
				"add_action( 'after_signup_site'",
				$source,
				'adding another site is not a registration'
			);
		}

		public function test_pipeline_order_is_allowlist_limit_username_email_disposable(): void {
			$body = $this->guard_method( 'validate' );

			$allowlist  = strpos( $body, 'deny_by_allowlist' );
			$limit      = strpos( $body, 'deny_by_rate_limit' );
			$username   = strpos( $body, 'deny_by_username' );
			$email      = strpos( $body, 'deny_by_email' );
			$disposable = strpos( $body, 'Disposable_Email::get_instance()' );

			$this->assertNotFalse( $allowlist );
			$this->assertNotFalse( $disposable );
			$this->assertLessThan( $limit, $allowlist );
			$this->assertLessThan( $username, $limit );
			$this->assertLessThan( $email, $username );
			$this->assertLessThan( $disposable, $email, 'an allow rule must be able to overrule the throwaway list' );
		}

		public function test_login_probe_never_adds_an_error_or_visitor_text(): void {
			$body = substr( $this->guard_method( 'on_login_failed' ), 0, 1800 );

			$this->assertStringNotContainsString( '->add(', $body, 'the login response must stay the unified "Invalid credentials."' );
			$this->assertStringNotContainsString( '__(', $body, 'nothing visitor-facing is emitted here' );
			$this->assertStringContainsString( "'unknown_username_probe'", $body );
			$this->assertStringContainsString( 'username_exists_anywhere', $body );
		}

		public function test_rate_limit_denies_without_escalating_or_reporting(): void {
			$body = substr( $this->guard_method( 'deny_by_rate_limit' ), 0, 2200 );

			$this->assertStringContainsString( "'registration_limit'", $body );
			$this->assertStringNotContainsString(
				'handle_threshold_exceeded',
				$body,
				'a shared office address opening a few accounts must not be blocked or reported'
			);
		}

		public function test_applies_guard_precedes_every_rule(): void {
			foreach ( array(
				'validate'                => 'deny_by_allowlist',
				'count_registration'      => 'is_multisite(',
				'count_signup'            => 'count_source_ip',
				'on_login_failed'         => 'OPT_BLOCK_UNKNOWN_USERNAME',
				'on_pre_insert_user_data' => '$this->validate(',
			) as $method => $marker ) {
				$body    = $this->guard_method( $method );
				$applies = strpos( $body, 'self::applies()' );
				$next    = strpos( $body, $marker );

				$this->assertNotFalse( $applies, "{$method}() must consult applies()" );
				$this->assertNotFalse( $next );
				$this->assertLessThan( $next, $applies, "{$method}() must bail out for privileged actors first" );
			}
		}

		public function test_programmatic_safety_net_only_runs_on_insert(): void {
			$body = substr( $this->guard_method( 'on_pre_insert_user_data' ), 0, 900 );

			$this->assertStringContainsString(
				'|| $update',
				$body,
				'wp_pre_insert_user_data also fires on wp_update_user(); acting there would lock existing users out of their profile'
			);
		}

		public function test_programmatic_safety_net_runs_the_whole_pipeline(): void {
			$body = substr( $this->guard_method( 'on_pre_insert_user_data' ), 0, 1100 );

			$this->assertStringContainsString(
				'$this->validate(',
				$body,
				'WooCommerce creates the checkout account without firing woocommerce_register_post, so every rule must run here'
			);
			$this->assertStringContainsString(
				"'wp-activate.php' === self::current_page()",
				$body,
				'the activation request finishes a signup the visitor already passed and must not be judged again'
			);
			$this->assertStringContainsString(
				'$this->judged[',
				$body,
				'a form surface already judged this identity in the same request; judging it twice would log the same verdict twice'
			);
		}

		public function test_multisite_signup_denials_use_the_codes_the_form_prints(): void {
			$body = $this->guard_method( 'mirror_signup_errors' );

			foreach ( array(
				"'reportedip_hive_prohibited_username' => 'user_name'",
				"'reportedip_hive_email_rule'          => 'user_email'",
				"'reportedip_hive_disposable_email'    => 'user_email'",
				"'reportedip_hive_registration_ip'     => 'generic'",
				"'reportedip_hive_registration_limit'  => 'generic'",
			) as $pair ) {
				$this->assertStringContainsString( $pair, $body );
			}

			$this->assertStringContainsString(
				'self::mirror_signup_errors(',
				substr( $this->guard_method( 'on_wpmu_validate_user_signup' ), 0, 900 ),
				'wp-signup.php renders only user_name, user_email and generic; without the copy the visitor sees no reason at all'
			);
		}
	}
}
