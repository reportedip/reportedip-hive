<?php
/**
 * Unit Tests for Hide-Login slug + response-mode validation.
 *
 * Focused on the pure-logic paths through ReportedIP_Hive_Hide_Login that do
 * not require a WordPress environment (format validation, reserved-slug
 * rejection, response-mode whitelist, default-slug suggestion).
 *
 * Permalink-collision detection (get_page_by_path / get_user_by / get_term_by)
 * is exercised by integration tests, not here.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.2.0
 */

namespace {

	if ( ! function_exists( 'sanitize_title' ) ) {
		function sanitize_title( $title ) {
			$title = strtolower( (string) $title );
			$title = preg_replace( '/[^a-z0-9_-]+/', '-', $title );
			$title = preg_replace( '/-+/', '-', $title );
			return trim( (string) $title, '-' );
		}
	}

	if ( ! function_exists( 'add_settings_error' ) ) {
		function add_settings_error( $setting, $code, $message, $type = 'error' ) {
			$GLOBALS['rip_settings_errors'][] = compact( 'setting', 'code', 'message', 'type' );
		}
	}

	if ( ! function_exists( 'wp_generate_password' ) ) {
		function wp_generate_password( $length = 12, $special_chars = true, $extra_special_chars = false ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return substr( str_repeat( 'a1b2c3d4e5f6', (int) ceil( $length / 12 ) ), 0, (int) $length );
		}
	}

	if ( ! function_exists( 'wp_unslash' ) ) {
		function wp_unslash( $value ) {
			return is_string( $value ) ? stripslashes( $value ) : $value;
		}
	}

	if ( ! function_exists( 'sanitize_key' ) ) {
		function sanitize_key( $key ) {
			return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $key ) );
		}
	}

	if ( ! function_exists( 'wp_parse_url' ) ) {
		function wp_parse_url( $url, $component = -1 ) {
			return -1 === $component ? parse_url( $url ) : parse_url( $url, $component );
		}
	}

	if ( ! function_exists( 'is_user_logged_in' ) ) {
		function is_user_logged_in() {
			return false;
		}
	}

	if ( ! function_exists( 'wp_doing_ajax' ) ) {
		function wp_doing_ajax() {
			return false;
		}
	}

	if ( ! function_exists( 'wp_doing_cron' ) ) {
		function wp_doing_cron() {
			return false;
		}
	}

	if ( ! function_exists( 'status_header' ) ) {
		function status_header( $code ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}

	if ( ! function_exists( 'nocache_headers' ) ) {
		function nocache_headers() {}
	}

	if ( ! function_exists( 'add_query_arg' ) ) {
		function add_query_arg( $key, $value, $url ) {
			$sep = false === strpos( $url, '?' ) ? '?' : '&';
			return $url . $sep . rawurlencode( (string) $key ) . ( '' === $value ? '' : '=' . rawurlencode( (string) $value ) );
		}
	}

	if ( ! function_exists( 'get_taxonomies' ) ) {
		function get_taxonomies( $args = array(), $output = 'names' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return array();
		}
	}

	if ( ! defined( 'OBJECT' ) ) {
		define( 'OBJECT', 'OBJECT' );
	}

	if ( ! function_exists( 'get_page_by_path' ) ) {
		function get_page_by_path( $page_path, $output = OBJECT, $post_type = 'page' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return null;
		}
	}

	if ( ! function_exists( 'get_term_by' ) ) {
		function get_term_by( $field, $value, $taxonomy = '', $output = OBJECT ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return false;
		}
	}

	if ( ! function_exists( 'str_starts_with' ) ) {
		function str_starts_with( $haystack, $needle ) {
			return '' === $needle || 0 === strncmp( (string) $haystack, (string) $needle, strlen( (string) $needle ) );
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-hide-login.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

/**
 * Test class for Hide-Login validation logic.
 */
class HideLoginTest extends TestCase {

	/**
	 * Reset the singleton + globals between tests.
	 */
	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['rip_settings_errors'] = array();
		$GLOBALS['wp_options']          = array();
	}

	/**
	 * Helper for accessing the singleton.
	 */
	private function instance(): \ReportedIP_Hive_Hide_Login {
		return \ReportedIP_Hive_Hide_Login::get_instance();
	}

	public function test_response_mode_accepts_block_page() {
		$this->assertSame( 'block_page', $this->instance()->sanitize_response_mode( 'block_page' ) );
	}

	public function test_response_mode_accepts_404() {
		$this->assertSame( '404', $this->instance()->sanitize_response_mode( '404' ) );
	}

	public function test_response_mode_falls_back_to_block_page_for_garbage() {
		$this->assertSame( 'block_page', $this->instance()->sanitize_response_mode( 'nope' ) );
		$this->assertSame( 'block_page', $this->instance()->sanitize_response_mode( '' ) );
		$this->assertSame( 'block_page', $this->instance()->sanitize_response_mode( null ) );
	}

	/**
	 * @dataProvider reserved_slug_provider
	 */
	public function test_reserved_slugs_are_rejected( string $slug ) {
		$result = $this->instance()->sanitize_slug( $slug );
		$this->assertSame( '', $result, "Reserved slug '$slug' must be rejected" );
		$this->assertNotEmpty( $GLOBALS['rip_settings_errors'], "Reserved slug '$slug' should produce a settings error" );
	}

	public function reserved_slug_provider() {
		return array(
			'wp-admin'   => array( 'wp-admin' ),
			'wp-login'   => array( 'wp-login' ),
			'wp-json'    => array( 'wp-json' ),
			'admin'      => array( 'admin' ),
			'login'      => array( 'login' ),
			'dashboard'  => array( 'dashboard' ),
			'xmlrpc'     => array( 'xmlrpc' ),
			'feed'       => array( 'feed' ),
			'wp-config'  => array( 'wp-config' ),
		);
	}

	/**
	 * @dataProvider invalid_format_provider
	 */
	public function test_invalid_formats_are_rejected( string $slug ) {
		$result = $this->instance()->sanitize_slug( $slug );
		$this->assertSame( '', $result, "Invalid slug '$slug' must be rejected" );
	}

	public function invalid_format_provider() {
		return array(
			'too short'              => array( 'a' ),
			'two chars'              => array( 'ab' ),
			'too long'               => array( str_repeat( 'a', 60 ) ),
		);
	}

	/**
	 * @dataProvider valid_slug_provider
	 */
	public function test_valid_slugs_pass( string $slug, string $expected ) {
		$result = $this->instance()->sanitize_slug( $slug );
		$this->assertSame( $expected, $result, "Slug '$slug' should normalise to '$expected'" );
		$this->assertEmpty( $GLOBALS['rip_settings_errors'], 'No settings errors expected for valid slugs' );
	}

	public function valid_slug_provider() {
		return array(
			'simple'             => array( 'welcome', 'welcome' ),
			'with dash'          => array( 'my-login', 'my-login' ),
			'with underscore'    => array( 'my_login', 'my_login' ),
			'mixed digits'       => array( 'login2024', 'login2024' ),
			'longer slug'        => array( 'super-secret-portal', 'super-secret-portal' ),
		);
	}

	public function test_uppercase_is_normalised_to_lowercase() {
		$result = $this->instance()->sanitize_slug( 'Welcome' );
		$this->assertSame( 'welcome', $result );
	}

	public function test_suggest_default_slug_has_expected_prefix() {
		$slug = \ReportedIP_Hive_Hide_Login::suggest_default_slug();
		$this->assertStringStartsWith( 'wp-secure-', $slug );
		$this->assertGreaterThanOrEqual( 12, strlen( $slug ) );
	}

	public function test_get_slug_returns_lowercase_trimmed() {
		$GLOBALS['wp_options']['reportedip_hive_hide_login_slug'] = '  Welcome/ ';
		$this->assertSame( 'welcome', $this->instance()->get_slug() );
	}

	public function test_is_active_requires_enabled_and_slug() {
		$inst = $this->instance();

		$GLOBALS['wp_options']['reportedip_hive_hide_login_enabled'] = false;
		$GLOBALS['wp_options']['reportedip_hive_hide_login_slug']    = 'welcome';
		$this->assertFalse( $inst->is_active(), 'Disabled feature must report inactive even with slug' );

		$GLOBALS['wp_options']['reportedip_hive_hide_login_enabled'] = true;
		$GLOBALS['wp_options']['reportedip_hive_hide_login_slug']    = '';
		$this->assertFalse( $inst->is_active(), 'Empty slug must report inactive even when enabled' );

		$GLOBALS['wp_options']['reportedip_hive_hide_login_enabled'] = true;
		$GLOBALS['wp_options']['reportedip_hive_hide_login_slug']    = 'welcome';
		$this->assertTrue( $inst->is_active(), 'Both enabled + slug => active' );
	}

	public function test_kill_switch_constant_disables_feature() {
		if ( ! defined( 'REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN' ) ) {
			define( 'REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN', true );
		}

		$GLOBALS['wp_options']['reportedip_hive_hide_login_enabled'] = true;
		$GLOBALS['wp_options']['reportedip_hive_hide_login_slug']    = 'welcome';

		$this->assertFalse( $this->instance()->is_active(), 'Kill-switch constant must override active state' );
	}

	/**
	 * Invoke a private no-arg method on the singleton via reflection.
	 *
	 * @param string $method Private method name.
	 * @return mixed
	 */
	private function call_private( string $method ) {
		$inst       = $this->instance();
		$reflection = new \ReflectionClass( $inst );
		$ref        = $reflection->getMethod( $method );
		return $ref->invoke( $inst );
	}

	public function test_probe_sensor_enabled_defaults_to_true() {
		$this->assertTrue( (bool) $this->call_private( 'probe_sensor_enabled' ) );
	}

	public function test_probe_sensor_can_be_disabled() {
		$GLOBALS['wp_options']['reportedip_hive_monitor_hide_login_probe'] = false;
		$this->assertFalse( (bool) $this->call_private( 'probe_sensor_enabled' ) );
	}

	public function test_probe_threshold_defaults_to_five() {
		$this->assertSame( 5, (int) $this->call_private( 'get_probe_threshold' ) );
	}

	public function test_probe_threshold_reads_option() {
		$GLOBALS['wp_options']['reportedip_hive_hide_login_probe_threshold'] = 12;
		$this->assertSame( 12, (int) $this->call_private( 'get_probe_threshold' ) );
	}

	public function test_probe_threshold_floors_at_one() {
		$GLOBALS['wp_options']['reportedip_hive_hide_login_probe_threshold'] = 0;
		$this->assertSame( 1, (int) $this->call_private( 'get_probe_threshold' ) );
	}

	public function test_probe_timeframe_defaults_to_ten() {
		$this->assertSame( 10, (int) $this->call_private( 'get_probe_timeframe' ) );
	}

	public function test_probe_timeframe_floors_at_one() {
		$GLOBALS['wp_options']['reportedip_hive_hide_login_probe_timeframe'] = 0;
		$this->assertSame( 1, (int) $this->call_private( 'get_probe_timeframe' ) );
	}

	/**
	 * Architecture invariant: the probe sensor must hand off to the
	 * Security-Monitor with the 'hide_login_probe' attempt type, gated on the
	 * monitor toggle, and the counting handoff must happen BEFORE the recon-log
	 * throttle (set_transient) so the 5-second log throttle never starves the
	 * attempt counter. Verified by source inspection so a future refactor
	 * cannot silently break the ordering.
	 */
	public function test_probe_sensor_counts_before_log_throttle() {
		$source = file_get_contents(
			dirname( __DIR__, 2 ) . '/includes/class-hide-login.php'
		);
		$this->assertNotFalse( $source );

		$this->assertStringContainsString( 'track_generic_attempt', $source );
		$this->assertStringContainsString( "'hide_login_probe'", $source );
		$this->assertStringContainsString( 'reportedip_hive_monitor_hide_login_probe', $source );

		$track_pos = strpos( $source, 'track_generic_attempt' );
		$set_trans = strpos( $source, "set_transient( \$throttle_key" );
		$this->assertNotFalse( $track_pos );
		$this->assertNotFalse( $set_trans );
		$this->assertLessThan(
			$set_trans,
			$track_pos,
			'Probe counting must run before the recon-log throttle is set'
		);
	}
}

}
