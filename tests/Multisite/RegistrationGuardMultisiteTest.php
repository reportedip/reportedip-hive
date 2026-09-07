<?php
/**
 * Multisite tests for the registration guard.
 *
 * Every rule is network state: the options live in sitemeta, the attempt
 * counter and the whitelist live under `base_prefix`, and a signup on any
 * sub-site is validated against the same lists. These tests run against a
 * real WordPress + database so the routing is exercised rather than mocked.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Registration_Guard_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Option keys the tests write, reset before and after each case.
	 *
	 * @var string[]
	 */
	private $touched = array(
		'reportedip_hive_prohibited_usernames',
		'reportedip_hive_prohibited_usernames_baseline',
		'reportedip_hive_email_rule_mode',
		'reportedip_hive_email_rules',
		'reportedip_hive_registration_limit_enabled',
		'reportedip_hive_registration_limit_count',
		'reportedip_hive_registration_limit_timeframe',
		'reportedip_hive_block_unknown_username_login',
		'reportedip_hive_disposable_email_action',
		'reportedip_hive_notify_admin',
	);

	/**
	 * Skip on single-site runs, ensure tables, start from a clean state.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}

		ReportedIP_Hive_Schema::ensure_tables();
		$this->reset_options();
		wp_set_current_user( 0 );
		$_SERVER['REMOTE_ADDR'] = '203.0.113.10';
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_notify_admin', 0 );
	}

	/**
	 * Drop every option the case wrote so the next one starts clean.
	 */
	public function tear_down() {
		$this->reset_options();
		parent::tear_down();
	}

	/**
	 * Remove the touched options from sitemeta.
	 */
	private function reset_options() {
		foreach ( $this->touched as $key ) {
			ReportedIP_Hive_Option_Routing::delete( $key );
		}
	}

	/**
	 * Run a signup through the network signup validator.
	 *
	 * @param string $login Submitted login.
	 * @param string $email Submitted e-mail address.
	 * @return WP_Error
	 */
	private function validate_signup( $login, $email ) {
		$result = wpmu_validate_user_signup( $login, $email );
		$this->assertInstanceOf( 'WP_Error', $result['errors'] );
		return $result['errors'];
	}

	/**
	 * An operator rule refuses a network signup and lives in sitemeta, not in
	 * a single blog table.
	 */
	public function test_prohibited_username_rejects_a_network_signup() {
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_prohibited_usernames', 'shopadmin' );

		$errors = $this->validate_signup( 'shopadmin', 'shopadmin@example.org' );

		$this->assertContains( 'reportedip_hive_prohibited_username', $errors->get_error_codes() );
		$this->assertSame( 'shopadmin', get_site_option( 'reportedip_hive_prohibited_usernames' ), 'the rule list is network state' );
		$this->assertFalse( get_option( 'reportedip_hive_prohibited_usernames' ), 'the rule list must not live in a single blog table' );
	}

	/**
	 * wp-signup.php renders exactly three error codes, so every denial has to
	 * arrive under one of them or the visitor gets the form back without a
	 * reason.
	 */
	public function test_signup_denials_carry_a_code_the_signup_form_prints() {
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_prohibited_usernames', 'shopadmin' );

		$username = $this->validate_signup( 'shopadmin', 'shopadmin@example.org' );

		$this->assertContains( 'user_name', $username->get_error_codes() );
		$this->assertSame(
			$username->get_error_message( 'reportedip_hive_prohibited_username' ),
			$username->get_error_message( 'user_name' )
		);

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_email_rule_mode', 'block' );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_email_rules', '*@blocked.test' );

		$email = $this->validate_signup( 'freshuser', 'someone@blocked.test' );

		$this->assertContains( 'user_email', $email->get_error_codes() );
	}

	/**
	 * The bundled baseline names are prohibited without any operator list.
	 */
	public function test_bundled_baseline_rejects_admin_names_without_an_operator_list() {
		$errors = $this->validate_signup( 'webmaster', 'webmaster@example.org' );

		$this->assertContains( 'reportedip_hive_prohibited_username', $errors->get_error_codes() );
	}

	/**
	 * Switching the baseline off releases the bundled names again.
	 */
	public function test_baseline_can_be_switched_off() {
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_prohibited_usernames_baseline', 0 );

		$errors = $this->validate_signup( 'webmaster', 'webmaster@example.org' );

		$this->assertNotContains( 'reportedip_hive_prohibited_username', $errors->get_error_codes() );
	}

	/**
	 * A block rule stored network-wide also refuses a signup made on a sub-site.
	 */
	public function test_email_block_rule_applies_from_a_sub_site() {
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_email_rule_mode', 'block' );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_email_rules', '*@blocked.test' );

		$blog_id = self::factory()->blog->create();
		switch_to_blog( $blog_id );
		$errors = $this->validate_signup( 'freshuser', 'someone@blocked.test' );
		restore_current_blog();

		$this->assertContains( 'reportedip_hive_email_rule', $errors->get_error_codes() );
	}

	/**
	 * An operator's allow rule wins over the throwaway-mail list.
	 */
	public function test_allow_rule_overrides_the_disposable_block() {
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_disposable_email_action', 'block' );

		$blocked = $this->validate_signup( 'freshusera', 'someone@mailinator.com' );
		$this->assertContains( 'reportedip_hive_disposable_email', $blocked->get_error_codes(), 'precondition: the throwaway list rejects this address' );

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_email_rule_mode', 'allow' );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_email_rules', '*@mailinator.com' );

		$allowed = $this->validate_signup( 'freshuserb', 'someone@mailinator.com' );

		$this->assertNotContains( 'reportedip_hive_disposable_email', $allowed->get_error_codes() );
		$this->assertNotContains( 'reportedip_hive_email_rule', $allowed->get_error_codes() );
	}

	/**
	 * Allow mode with an empty effective list behaves like off.
	 */
	public function test_empty_allow_list_behaves_like_off() {
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_email_rule_mode', 'allow' );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_email_rules', '' );

		$errors = $this->validate_signup( 'freshuser', 'someone@example.org' );

		$this->assertNotContains(
			'reportedip_hive_email_rule',
			$errors->get_error_codes(),
			'an empty allow list must never close registration for everybody'
		);
	}

	/**
	 * A super admin passes every rule, on the signup form and through
	 * wp_insert_user().
	 */
	public function test_super_admin_bypasses_every_rule() {
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_prohibited_usernames', 'shopadmin' );

		$admin = self::factory()->user->create( array( 'role' => 'administrator' ) );
		grant_super_admin( $admin );
		wp_set_current_user( $admin );

		$errors = $this->validate_signup( 'shopadmin', 'shopadmin@example.org' );
		$this->assertNotContains( 'reportedip_hive_prohibited_username', $errors->get_error_codes() );

		$created = wp_insert_user(
			array(
				'user_login' => 'shopadmin',
				'user_email' => 'shopadmin2@example.org',
				'user_pass'  => wp_generate_password( 20 ),
			)
		);

		$this->assertIsInt( $created, 'an administrator creating the account deliberately must not be refused' );
	}

	/**
	 * The rate limit refuses the next signup once the window is full and leaves
	 * the address unblocked.
	 */
	public function test_rate_limit_refuses_the_fourth_signup_without_blocking_the_address() {
		$ip                     = '203.0.113.31';
		$_SERVER['REMOTE_ADDR'] = $ip;

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_registration_limit_enabled', 1 );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_registration_limit_count', 3 );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_registration_limit_timeframe', 60 );

		for ( $i = 0; $i < 3; $i++ ) {
			do_action( 'after_signup_user', 'signup' . $i, 'signup' . $i . '@example.org', 'key' . $i, array() );
		}

		$errors = $this->validate_signup( 'freshuser', 'freshuser@example.org' );

		$this->assertContains( 'reportedip_hive_registration_limit', $errors->get_error_codes() );
		$this->assertContains( 'generic', $errors->get_error_codes(), 'the signup form only prints user_name, user_email and generic' );
		$this->assertFalse(
			ReportedIP_Hive_Database::get_instance()->is_blocked( $ip ),
			'refusing the registration is the whole consequence; a shared office address must not be blocked'
		);
	}

	/**
	 * Account creation that never reaches a registration form — WooCommerce
	 * builds the checkout customer with `wc_create_new_customer()` — is held to
	 * the same rate limit.
	 */
	public function test_rate_limit_also_refuses_a_registration_without_a_form() {
		$ip                     = '203.0.113.35';
		$_SERVER['REMOTE_ADDR'] = $ip;

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_registration_limit_enabled', 1 );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_registration_limit_count', 1 );

		$database = ReportedIP_Hive_Database::get_instance();
		$database->track_attempt( $ip, 'registration' );

		$created = wp_insert_user(
			array(
				'user_login' => 'checkoutguest',
				'user_email' => 'checkoutguest@example.org',
				'user_pass'  => wp_generate_password( 20 ),
			)
		);

		$this->assertInstanceOf( 'WP_Error', $created );
		$this->assertSame( 'empty_data', $created->get_error_code() );

		$database->reset_attempt_counter( $ip, 'registration' );
	}

	/**
	 * A whitelisted address is never counted against the rate limit.
	 */
	public function test_whitelisted_address_is_never_rate_limited() {
		$ip                     = '203.0.113.32';
		$_SERVER['REMOTE_ADDR'] = $ip;

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_registration_limit_enabled', 1 );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_registration_limit_count', 1 );

		$database = ReportedIP_Hive_Database::get_instance();
		$database->add_to_whitelist( $ip, 'registration guard test' );
		$database->track_attempt( $ip, 'registration' );
		$database->track_attempt( $ip, 'registration' );

		$errors = $this->validate_signup( 'freshuser', 'freshuser@example.org' );

		$this->assertNotContains( 'reportedip_hive_registration_limit', $errors->get_error_codes() );

		$database->remove_from_whitelist( $ip );
	}

	/**
	 * With the option on, a login naming an unknown account blocks the address
	 * without changing the login response.
	 */
	public function test_unknown_username_probe_blocks_silently_when_enabled() {
		$ip                     = '203.0.113.33';
		$_SERVER['REMOTE_ADDR'] = $ip;

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_block_unknown_username_login', 1 );

		$result = wp_authenticate( 'nobody-here-at-all', 'wrong-password' );

		$this->assertInstanceOf( 'WP_Error', $result );
		$this->assertNotContains(
			'reportedip_hive_prohibited_username',
			$result->get_error_codes(),
			'the login response must not gain a new, distinguishable error'
		);
		$this->assertSame(
			'Invalid credentials.',
			$result->get_error_message(),
			'the visitor keeps seeing the unified login error'
		);
		$this->assertTrue( ReportedIP_Hive_Database::get_instance()->is_blocked( $ip ) );

		ReportedIP_Hive_Database::get_instance()->unblock_ip( $ip );
	}

	/**
	 * With the option off, the same login leaves the address untouched.
	 */
	public function test_unknown_username_probe_does_nothing_when_disabled() {
		$ip                     = '203.0.113.34';
		$_SERVER['REMOTE_ADDR'] = $ip;

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_block_unknown_username_login', 0 );

		wp_authenticate( 'nobody-here-either', 'wrong-password' );

		$this->assertFalse( ReportedIP_Hive_Database::get_instance()->is_blocked( $ip ) );
	}
}
