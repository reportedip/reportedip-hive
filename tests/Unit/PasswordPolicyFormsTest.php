<?php
/**
 * Unit tests for the password policy on WooCommerce and Ultimate Member
 * forms and for the padding-aware breach range parser.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.1
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * @covers \ReportedIP_Hive_Password_Strength
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class PasswordPolicyFormsTest extends TestCase {

	/**
	 * Suffix of SHA-1( "password" ) after the five-character prefix 5BAA6.
	 */
	private const SUFFIX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';

	protected function set_up() {
		parent::set_up();
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'tests/stubs/two-factor-runtime-stubs.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-password-strength.php';
		if ( ! function_exists( 'UM' ) ) {
			eval( 'function UM() { static $um = null; if ( null === $um ) { $um = new class() { public $errors = array(); public function form() { return $this; } public function add_error( $key, $message ) { $this->errors[ $key ] = $message; } }; } return $um; }' ); // phpcs:ignore Squiz.PHP.Eval.Discouraged -- defines the Ultimate Member double only inside this isolated test process.
		}
		if ( ! function_exists( 'wp_get_current_user' ) ) {
			eval( 'function wp_get_current_user() { return new WP_User( 7 ); }' ); // phpcs:ignore Squiz.PHP.Eval.Discouraged -- user double only inside this isolated test process.
		}
		$GLOBALS['wp_options'] = array(
			'reportedip_hive_password_policy_enabled'   => true,
			'reportedip_hive_password_check_hibp'       => false,
			'reportedip_hive_password_min_length'       => 12,
			'reportedip_hive_password_min_classes'      => 3,
			'reportedip_hive_password_policy_all_users' => true,
			'reportedip_hive_2fa_enforce_roles'         => array(),
		);
	}

	private function policy(): \ReportedIP_Hive_Password_Strength {
		return \ReportedIP_Hive_Password_Strength::get_instance();
	}

	public function test_padding_lines_with_count_zero_are_no_hit() {
		$hit     = "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n" . self::SUFFIX . ":9545824\r\n";
		$padding = "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n" . self::SUFFIX . ":0\r\n";
		$this->assertTrue( \ReportedIP_Hive_Password_Strength::range_lists_suffix( $hit, self::SUFFIX ) );
		$this->assertFalse( \ReportedIP_Hive_Password_Strength::range_lists_suffix( $padding, self::SUFFIX ) );
		$this->assertTrue( \ReportedIP_Hive_Password_Strength::range_lists_suffix( strtolower( self::SUFFIX ) . ':2', self::SUFFIX ) );
		$this->assertFalse( \ReportedIP_Hive_Password_Strength::range_lists_suffix( self::SUFFIX, self::SUFFIX ), 'a line without a count is no hit' );
	}

	public function test_woocommerce_account_details_reject_a_weak_password() {
		$errors = new \WP_Error();
		$this->policy()->on_wc_account_details( $errors, (object) array( 'ID' => 7, 'user_pass' => 'short' ) );
		$this->assertNotEmpty( $errors->get_error_messages( 'pass' ) );

		$errors = new \WP_Error();
		$this->policy()->on_wc_account_details( $errors, (object) array( 'ID' => 7, 'user_pass' => 'kQ7!nzM2#fX9' ) );
		$this->assertSame( array(), $errors->get_error_messages( 'pass' ) );

		$errors = new \WP_Error();
		$this->policy()->on_wc_account_details( $errors, (object) array( 'ID' => 7 ) );
		$this->assertSame( array(), $errors->get_error_messages( 'pass' ), 'no password change, nothing to check' );
	}

	public function test_woocommerce_registration_checks_a_chosen_password_only() {
		$result = $this->policy()->on_wc_registration( new \WP_Error(), 'shopper', 'short', 'shopper@example.org' );
		$this->assertNotEmpty( $result->get_error_messages( 'registration-error-invalid-password' ) );

		$result = $this->policy()->on_wc_registration( new \WP_Error(), 'shopper', '', 'shopper@example.org' );
		$this->assertSame( array(), $result->get_error_messages(), 'a generated password is left alone' );
	}

	public function test_a_new_customer_is_covered_only_with_all_users_on() {
		$GLOBALS['wp_options']['reportedip_hive_2fa_enforce_roles']         = array( 'administrator' );
		$GLOBALS['wp_options']['reportedip_hive_password_policy_all_users'] = false;
		$result = $this->policy()->on_wc_registration( new \WP_Error(), 'shopper', 'short', 'shopper@example.org' );
		$this->assertSame( array(), $result->get_error_messages(), 'all users off: a customer is not covered' );

		$GLOBALS['wp_options']['reportedip_hive_password_policy_all_users'] = true;
		\ReportedIP_Hive_Option_Routing::flush_resolve_cache();
		$result = $this->policy()->on_wc_registration( new \WP_Error(), 'shopper', 'short', 'shopper@example.org' );
		$this->assertNotEmpty( $result->get_error_messages(), 'all users on covers a customer next to the administrator role' );
	}

	/**
	 * Scope matrix: enforce roles set or empty, all users on or off, role
	 * listed or not.
	 */
	public function test_scope_matrix() {
		$method = new \ReflectionMethod( \ReportedIP_Hive_Password_Strength::class, 'roles_subject_to_policy' );
		$cases = array(
			array( array( 'administrator' ), true, 'customer', true ),
			array( array( 'administrator' ), true, 'administrator', true ),
			array( array( 'administrator' ), false, 'customer', false ),
			array( array( 'administrator' ), false, 'administrator', true ),
			array( array(), true, 'customer', true ),
			array( array(), false, 'customer', false ),
			array( array(), false, 'administrator', false ),
		);
		foreach ( $cases as $case ) {
			list( $enforce, $all_users, $role, $expected ) = $case;
			$GLOBALS['wp_options']['reportedip_hive_2fa_enforce_roles']         = $enforce;
			$GLOBALS['wp_options']['reportedip_hive_password_policy_all_users'] = $all_users;
			\ReportedIP_Hive_Option_Routing::flush_resolve_cache();
			$this->assertSame( $expected, $method->invoke( $this->policy(), array( $role ) ), wp_json_encode( $case ) );
		}
	}

	public function test_ultimate_member_account_and_registration() {
		$this->policy()->on_um_account( array( 'user_password' => 'short' ) );
		$this->assertArrayHasKey( 'user_password', UM()->errors );

		UM()->errors = array();
		$this->policy()->on_um_registration( array( 'user_password' => ' kQ7!nzM2#fX9 ' ), array() );
		$this->assertSame( array(), UM()->errors );

		$this->policy()->on_um_registration( array( 'user_password' => 'short' ), array( 'role' => 'subscriber' ) );
		$this->assertArrayHasKey( 'user_password', UM()->errors );
	}
}
