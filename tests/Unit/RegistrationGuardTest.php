<?php
/**
 * Unit tests for the registration guard: entry grammar, plan caps, sanitizers
 * and the architectural invariants of the registration pipeline.
 *
 * The matcher and the sanitizers are pure statics, so they are exercised
 * directly. The pipeline itself depends on the plugin's runtime singletons
 * (database, logger, mode manager), so its contract, hook ownership,
 * evaluation order, the silent login-probe path, is anchored via source
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

		/**
		 * The free plugin stores an entry between slashes but never runs it:
		 * without a listener it matches nothing, a listener decides.
		 */
		public function test_slash_entry_is_not_evaluated_without_a_listener(): void {
			$GLOBALS['wp_filters'] = array();
			$this->assertNull( \ReportedIP_Hive_Registration_Guard::matches_any( 'admin42', array( '/^admin\d+$/' ) ) );
			$this->assertNull( \ReportedIP_Hive_Registration_Guard::entry_pattern( '/^admin\d+$/' ) );

			add_filter(
				'reportedip_hive_registration_entry_matches',
				static function ( $matched, $entry, $subject ) {
					return '/^admin\d+$/' === $entry && 'admin42' === $subject;
				},
				10,
				3
			);
			try {
				$this->assertSame( '/^admin\d+$/', \ReportedIP_Hive_Registration_Guard::matches_any( 'admin42', array( '/^admin\d+$/' ) ) );
				$this->assertNull( \ReportedIP_Hive_Registration_Guard::matches_any( 'admin', array( '/^admin\d+$/' ) ) );
			} finally {
				$GLOBALS['wp_filters'] = array();
			}
		}

		/**
		 * The guard carries no code that compiles or runs an operator pattern.
		 */
		public function test_guard_has_no_regular_expression_path(): void {
			$source = $this->guard_source();

			$this->assertStringNotContainsString( 'substr( $entry, 1, -1 )', $source );
			$this->assertStringNotContainsString( 'compile_pattern(', str_replace( 'WAF::compile_pattern()', '', $source ) );
			$this->assertStringNotContainsString( 'pattern_compiles', $source );
			$this->assertSame( 1, substr_count( $source, 'ReportedIP_Hive_WAF::match_fragment(' ), 'only the wildcard branch runs a pattern' );
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

		public function test_username_list_splits_on_commas_only(): void {
			$clean = \ReportedIP_Hive_Registration_Guard::sanitize_username_list( "John Doe, Admin\n# note\nroot" );

			$this->assertSame( "john doe\nadmin\nroot", $clean, 'WordPress logins may contain spaces' );
		}

		public function test_username_list_keeps_slash_entries_as_written(): void {
			$GLOBALS['wp_filters'] = array();
			$clean                 = \ReportedIP_Hive_Registration_Guard::sanitize_username_list( "/^AdMin\\d+$/\n/[/\nSupport" );

			$this->assertSame( "/^AdMin\\d+$/\n/[/\nsupport", $clean, 'the free plugin stores the entry, validating it is up to a listener' );
		}

		public function test_email_list_normalises_bare_hosts_dedupes_and_lowercases(): void {
			$clean = \ReportedIP_Hive_Registration_Guard::sanitize_email_rule_list( "Example.COM\n*@example.com\nb.test, c.test" );

			$this->assertSame( "*@example.com\n*@b.test\n*@c.test", $clean );
		}

		public function test_email_list_splits_on_whitespace(): void {
			$clean = \ReportedIP_Hive_Registration_Guard::sanitize_email_rule_list( 'a.test b.test' );

			$this->assertSame( "*@a.test\n*@b.test", $clean, 'a dashboard that flattens newlines must not produce one bogus entry' );
		}

		public function test_every_option_key_is_a_remote_registry_key_with_a_default(): void {
			$remote   = \ReportedIP_Hive_Settings_Registry::remote_spec();
			$defaults = \ReportedIP_Hive_Defaults::all_option_defaults();

			foreach ( \ReportedIP_Hive_Registration_Guard::OPTION_KEYS as $key ) {
				$this->assertArrayHasKey( $key, $remote, "{$key} must be remotely manageable." );
				$this->assertArrayHasKey( $key, $defaults, "{$key} must have a canonical default." );
			}
		}

		/**
		 * Without the add-on the lists are lossless: a list a paid plan wrote
		 * (more than ten entries, a regular expression) survives a save, it is
		 * only not evaluated beyond the first ten plain entries.
		 */
		public function test_free_registry_stores_long_lists_and_regex_entries(): void {
			$list = implode( "\n", array( 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'a10', 'a11', '/^adm[0-9]+$/' ) );

			$this->assertSame( $list, \ReportedIP_Hive_Settings_Registry::sanitize( 'reportedip_hive_prohibited_usernames', $list ) );
			$this->assertSame( "*@a.test\n/^spam@/", \ReportedIP_Hive_Settings_Registry::sanitize( 'reportedip_hive_email_rules', "a.test\n/^spam@/" ) );

			foreach ( array( 'reportedip_hive_prohibited_usernames', 'reportedip_hive_email_rules' ) as $key ) {
				$entry = \ReportedIP_Hive_Settings_Registry::spec()[ $key ];
				$this->assertArrayNotHasKey( 'tier', $entry, "{$key}: the free plugin gates no local list by plan" );
				$this->assertArrayNotHasKey( 'tier_gate', $entry, $key );
				$this->assertArrayNotHasKey( 'partial', $entry, $key );
			}
			$this->assertArrayNotHasKey( 'reportedip_hive_registration_allowlist', \ReportedIP_Hive_Settings_Registry::spec(), 'the allowlist belongs to the add-on' );
			$this->assertArrayNotHasKey( 'reportedip_hive_registration_allowlist', \ReportedIP_Hive_Defaults::all_option_defaults() );
		}

		/**
		 * The cap stays on until a listener lifts it: without the add-on the
		 * eleventh entry and every regular expression stay inert, as on a
		 * 2.1.x plan below Professional.
		 */
		public function test_cap_is_lifted_only_by_the_filter(): void {
			$method = new \ReflectionMethod( 'ReportedIP_Hive_Registration_Guard', 'unlimited' );

			$GLOBALS['wp_filters'] = array();
			$this->assertFalse( $method->invoke( null ) );

			add_filter(
				'reportedip_hive_registration_rules_unlimited',
				static function () {
					return true;
				}
			);
			try {
				$this->assertTrue( $method->invoke( null ) );
			} finally {
				$GLOBALS['wp_filters'] = array();
			}

			$active = \ReportedIP_Hive_Registration_Guard::active_entries( implode( "\n", array( 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'a10', 'a11', '/^adm[0-9]+$/' ) ), false );
			$this->assertNull( \ReportedIP_Hive_Registration_Guard::matches_any( 'a11', $active ) );
			$this->assertNull( \ReportedIP_Hive_Registration_Guard::matches_any( 'adm7', $active ) );
			$this->assertSame( 'a10', \ReportedIP_Hive_Registration_Guard::matches_any( 'a10', $active ) );
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

			$allowlist  = strpos( $body, "do_action( 'reportedip_hive_registration_validate'" );
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
			$this->assertLessThan( strpos( $body, 'deny_by_missing_form_proof' ), $allowlist, 'the add-on check runs where the 2.1.x allowlist ran: first' );
			$this->assertStringContainsString(
				'count( $errors->get_error_messages() ) > $before',
				$body,
				'a listener that adds an error stops the pipeline, so a denial stays one error and one log row'
			);
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
				'validate'                => "do_action( 'reportedip_hive_registration_validate'",
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
			$expected = array(
				'reportedip_hive_prohibited_username' => 'login',
				'reportedip_hive_email_rule'          => 'email',
				'reportedip_hive_disposable_email'    => 'email',
				'reportedip_hive_registration_ip'     => 'generic',
				'reportedip_hive_registration_limit'  => 'generic',
				'reportedip_hive_reputation'          => 'generic',
				'reportedip_hive_form_proof'          => 'generic',
			);

			foreach ( $expected as $code => $target ) {
				$this->assertSame( $target, \ReportedIP_Hive_Registration_Guard::error_target( $code ) );
			}

			$this->assertSame(
				'generic',
				\ReportedIP_Hive_Registration_Guard::error_target( 'some_other_plugin_code' ),
				'an unknown code must land somewhere the visitor can read it, not nowhere'
			);

			$body = $this->guard_method( 'mirror_signup_errors' );

			foreach ( array(
				"'login'   => 'user_name'",
				"'email'   => 'user_email'",
				"'generic' => 'generic'",
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
