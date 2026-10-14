<?php
/**
 * Pins the contract of the `reportedip_hive_2fa_stepup` filter inside
 * `filter_authenticate()`, the order 2.1.74 established for the adaptive
 * step-up: the bypass filter and the IP allowlist win, a trigger skips the
 * trusted-device bypass, and a `no_method:` verdict only records the skip.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * Loads the real classes in set_up(), which only runs in the child process.
 *
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class TwoFactorStepupFilterTest extends TestCase {

	private const USER_ID = 9;

	/**
	 * An editor with an authenticator app and a valid trusted-device cookie.
	 */
	protected function set_up() {
		parent::set_up();
		require_once dirname( __DIR__ ) . '/stubs/two-factor-runtime-stubs.php';
		require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-verifier.php';
		require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor.php';
		$GLOBALS['wp_options']          = array();
		$GLOBALS['wp_transients']       = array();
		$GLOBALS['rip_test_logs']       = array();
		$GLOBALS['rip_test_doing_ajax'] = true;
		$GLOBALS['wp_user_meta']        = array(
			self::USER_ID => array(
				'reportedip_hive_2fa_enabled'      => '1',
				'reportedip_hive_2fa_method'       => 'totp',
				'reportedip_hive_2fa_totp_enabled' => '1',
			),
		);
		$GLOBALS['wpdb']                = new class() {

			/**
			 * Network table prefix.
			 *
			 * @var string
			 */
			public $base_prefix = 'wp_';

			/**
			 * Site table prefix.
			 *
			 * @var string
			 */
			public $prefix = 'wp_';

			/**
			 * @param string $query Query.
			 * @return string
			 */
			public function prepare( $query ) {
				return $query;
			}

			/**
			 * Every cookie belongs to a live trusted device.
			 *
			 * @return object
			 */
			public function get_row() {
				return (object) array( 'id' => 1 );
			}

			/**
			 * @return int
			 */
			public function update() {
				return 1;
			}

			/**
			 * @return int
			 */
			public function delete() {
				return 0;
			}
		};
		$_COOKIE[ \ReportedIP_Hive_Two_Factor::TRUSTED_COOKIE ] = 'trusted-token';
		\ReportedIP_Hive_Two_Factor::flush_methods();
	}

	/**
	 * Drop the cookie again.
	 */
	protected function tear_down() {
		unset( $_COOKIE[ \ReportedIP_Hive_Two_Factor::TRUSTED_COOKIE ] );
		parent::tear_down();
	}

	/**
	 * Answer the step-up filter with a fixed verdict.
	 *
	 * @param string $verdict Trigger name, `no_method:<trigger>` or ''.
	 */
	private function stepup( string $verdict ): void {
		add_filter(
			'reportedip_hive_2fa_stepup',
			static function () use ( $verdict ) {
				return $verdict;
			}
		);
	}

	/**
	 * Run the authenticate filter for the test user.
	 *
	 * @return mixed
	 */
	private function sign_in() {
		return ( new \ReportedIP_Hive_Two_Factor() )->filter_authenticate( new \WP_User( self::USER_ID ), 'jane', 'secret' );
	}

	/**
	 * Log rows of one security event.
	 *
	 * @param string $event Event type.
	 * @return array<int, array>
	 */
	private function events( string $event ): array {
		return array_values(
			array_filter(
				$GLOBALS['rip_test_logs'],
				static function ( $entry ) use ( $event ) {
					return 'log_security_event' === $entry['level'] && $event === $entry['args'][0];
				}
			)
		);
	}

	public function test_a_trusted_device_skips_the_challenge_without_a_trigger(): void {
		$user = $this->sign_in();

		$this->assertInstanceOf( \WP_User::class, $user );
		$this->assertSame( array(), $this->events( '2fa_stepup_required' ) );
	}

	public function test_a_trigger_forces_the_challenge_despite_a_trusted_device(): void {
		$this->stepup( 'new_ip' );
		add_filter(
			'reportedip_hive_2fa_login_signals',
			static function ( array $signals ) {
				$signals['country'] = 'DE';
				return $signals;
			}
		);

		$result = $this->sign_in();

		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 'reportedip_2fa_required', $result->get_error_code() );
		$rows = $this->events( '2fa_stepup_required' );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'new_ip', $rows[0]['args'][2]['trigger'] );
		$this->assertSame( 'DE', $rows[0]['args'][2]['country'], 'The country comes from the signals filter.' );
	}

	public function test_without_a_signals_listener_the_country_is_empty(): void {
		$this->stepup( 'every_n_days' );

		$this->sign_in();

		$this->assertSame( '', $this->events( '2fa_stepup_required' )[0]['args'][2]['country'] );
	}

	public function test_the_filter_receives_the_method_and_enforcement_state(): void {
		$seen = array();
		add_filter(
			'reportedip_hive_2fa_stepup',
			static function ( $stepup, $user, $has_any_method, $is_enforced ) use ( &$seen ) {
				$seen = array( $stepup, $user->ID, $has_any_method, $is_enforced );
				return $stepup;
			},
			10,
			4
		);

		$this->sign_in();

		$this->assertSame( array( '', self::USER_ID, true, false ), $seen );
	}

	public function test_a_no_method_verdict_logs_the_skip_and_signs_in(): void {
		$GLOBALS['wp_user_meta'][ self::USER_ID ] = array();
		$this->stepup( \ReportedIP_Hive_Two_Factor::STEPUP_NO_METHOD_PREFIX . 'new_device' );

		$user = $this->sign_in();

		$this->assertInstanceOf( \WP_User::class, $user, 'A user without a method is never locked out by a trigger.' );
		$rows = $this->events( '2fa_stepup_skipped_no_method' );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'new_device', $rows[0]['args'][2]['trigger'] );
		$this->assertSame( 'low', $rows[0]['args'][3] );
		$this->assertSame( 'no_method:', \ReportedIP_Hive_Two_Factor::STEPUP_NO_METHOD_PREFIX, 'The add-on writes the same prefix.' );
	}

	public function test_the_ip_allowlist_still_wins_over_a_trigger(): void {
		$GLOBALS['wp_options']['reportedip_hive_2fa_ip_allowlist'] = '203.0.113.10';
		$this->stepup( 'new_ip' );

		$this->assertInstanceOf( \WP_User::class, $this->sign_in() );
		$this->assertSame( array(), $this->events( '2fa_stepup_required' ) );
	}

	public function test_the_bypass_filter_still_wins_over_a_trigger(): void {
		add_filter(
			'reportedip_2fa_bypass',
			static function () {
				return true;
			}
		);
		$this->stepup( 'new_ip' );

		$this->assertInstanceOf( \WP_User::class, $this->sign_in() );
	}

	public function test_the_verdict_reaches_the_should_challenge_context(): void {
		$this->stepup( 'sessions_above_n' );
		$context = array();
		add_filter(
			'reportedip_2fa_should_challenge',
			static function ( $challenge, $user, $ctx ) use ( &$context ) {
				$context = $ctx;
				return $challenge;
			},
			10,
			3
		);

		$this->sign_in();

		$this->assertSame( 'sessions_above_n', $context['stepup'] );
	}

	/**
	 * Read one source file from the plugin.
	 *
	 * @param string $relative Path relative to the plugin root.
	 * @return string
	 */
	private function source( string $relative ): string {
		return (string) file_get_contents( dirname( __DIR__, 2 ) . '/' . $relative );
	}

	public function test_trusted_device_bypass_is_gated_by_the_stepup_verdict(): void {
		$source = $this->source( 'includes/class-two-factor.php' );

		$this->assertStringContainsString(
			"if ( '' === \$stepup && \$this->verify_trusted_device( \$user->ID ) ) {",
			$source,
			'A fired trigger must override the trusted-device cookie.'
		);
	}

	public function test_allowlist_and_bypass_filter_still_win_over_a_stepup(): void {
		$source    = $this->source( 'includes/class-two-factor.php' );
		$body      = substr( $source, (int) strpos( $source, 'public function filter_authenticate(' ) );
		$bypass    = (int) strpos( $body, "apply_filters( 'reportedip_2fa_bypass'" );
		$allowlist = (int) strpos( $body, 'self::is_ip_allowlisted()' );
		$trusted   = (int) strpos( $body, "'' === \$stepup && \$this->verify_trusted_device(" );

		$this->assertGreaterThan( 0, $bypass );
		$this->assertGreaterThan( $bypass, $allowlist );
		$this->assertGreaterThan( $allowlist, $trusted, 'The IP allowlist must be checked before the step-up gate.' );
	}

	public function test_enforcement_reader_is_untouched(): void {
		$this->assertStringContainsString(
			'ReportedIP_Hive_Option_Routing::resolve_2fa_enforce_roles()',
			$this->source( 'includes/class-password-strength.php' ),
			'The enforcement list is shared, the policies must not change how it is read.'
		);
	}

	public function test_both_success_branches_announce_a_verification(): void {
		$occurrences = substr_count(
			$this->source( 'includes/class-two-factor.php' ),
			'do_action( \'reportedip_hive_2fa_verified\', (int) $user_id'
		) + substr_count(
			$this->source( 'includes/class-two-factor-rest.php' ),
			'do_action( \'reportedip_hive_2fa_verified\', (int) $user_id'
		);

		$this->assertSame( 2, $occurrences );
	}

	public function test_login_context_is_the_only_meta_key_added(): void {
		$source = $this->source( 'includes/class-two-factor.php' );

		$this->assertStringContainsString( "const META_LOGIN_CONTEXT = 'reportedip_hive_login_context';", $source );
		$this->assertSame(
			2,
			substr_count( $source, 'self::META_LOGIN_CONTEXT,' ),
			'The key belongs in both disable_for_user() and get_all_meta_keys().'
		);
	}
}
