<?php
/**
 * Unit tests for the per-user sign-in history.
 *
 * The history is the only state the adaptive triggers read, and it is
 * personal data, so both halves are pinned here: the LRU caps and counters
 * that make the triggers correct, and the refusal to write anything at all
 * while the feature is not part of the plan or 2FA is switched off.
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

	if ( ! function_exists( 'wp_roles' ) ) {
		/**
		 * Stub role provider.
		 *
		 * @return object
		 */
		function wp_roles() {
			return new class() {
				/**
				 * Role slug => display name map.
				 *
				 * @return array<string, string>
				 */
				public function get_names() {
					return array(
						'administrator' => 'Administrator',
						'editor'        => 'Editor',
					);
				}
			};
		}
	}

	if ( ! function_exists( 'is_super_admin' ) ) {
		/**
		 * Unit stub: super admins are listed in `$GLOBALS['rip_test_super_admins']`.
		 *
		 * @param int $user_id User id.
		 * @return bool
		 */
		function is_super_admin( $user_id = 0 ) {
			$ids = $GLOBALS['rip_test_super_admins'] ?? array();
			return in_array( (int) $user_id, array_map( 'intval', $ids ), true );
		}
	}

	if ( ! function_exists( 'get_userdata' ) ) {
		/**
		 * Unit stub: users live in `$GLOBALS['wp_users']`.
		 *
		 * @param int $id User id.
		 * @return object|false
		 */
		function get_userdata( $id ) {
			return $GLOBALS['wp_users'][ (int) $id ] ?? false;
		}
	}

	if ( ! class_exists( 'WP_User' ) ) {
		/**
		 * Minimal user double.
		 */
		class WP_User {
			/**
			 * User id.
			 *
			 * @var int
			 */
			public $ID;

			/**
			 * Role slugs.
			 *
			 * @var string[]
			 */
			public $roles = array();

			/**
			 * @param int      $id    User id.
			 * @param string[] $roles Role slugs.
			 */
			public function __construct( $id, array $roles = array() ) {
				$this->ID    = (int) $id;
				$this->roles = $roles;
			}
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive' ) ) {
		/**
		 * Plugin double supplying the client IP.
		 */
		class ReportedIP_Hive {
			/**
			 * IP the stub reports.
			 *
			 * @var string
			 */
			public static $client_ip = '203.0.113.10';

			/**
			 * @return string
			 */
			public static function get_client_ip() {
				return self::$client_ip;
			}
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
		/**
		 * 2FA double carrying the meta key and the role filter.
		 */
		class ReportedIP_Hive_Two_Factor {
			const META_LOGIN_CONTEXT = 'reportedip_hive_login_context';

			/**
			 * Whether the 2FA master switch is on.
			 *
			 * @var bool
			 */
			public static $globally_enabled = true;

			/**
			 * @return bool
			 */
			public static function is_globally_enabled() {
				return self::$globally_enabled;
			}

			/**
			 * @param array<int, mixed> $roles Candidate slugs.
			 * @return string[]
			 */
			public static function filter_valid_roles( array $roles ) {
				$valid = array_keys( wp_roles()->get_names() );
				return array_values( array_unique( array_intersect( array_map( 'strval', $roles ), $valid ) ) );
			}
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
		/**
		 * Mode-manager double with a switchable feature verdict.
		 */
		class ReportedIP_Hive_Mode_Manager {
			/**
			 * Whether every feature is available.
			 *
			 * @var bool
			 */
			public static $available = true;

			/**
			 * @return self
			 */
			public static function get_instance() {
				return new self();
			}

			/**
			 * @param string $feature Feature slug.
			 * @return array<string, mixed>
			 */
			public function feature_status( $feature ) {
				unset( $feature );
				return array(
					'available' => self::$available,
					'min_tier'  => 'professional',
				);
			}
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_Geo_Anomaly' ) ) {
		/**
		 * Geo double.
		 */
		class ReportedIP_Hive_Geo_Anomaly {
			/**
			 * Country the stub reports.
			 *
			 * @var string
			 */
			public static $country = '';

			/**
			 * @param string $ip Client IP.
			 * @return array<string, mixed>
			 */
			public static function fetch_reputation( string $ip ): array {
				unset( $ip );
				return '' === self::$country ? array() : array( 'countryCode' => self::$country );
			}

			/**
			 * @param array<string, mixed> $reputation Cached reputation.
			 * @return string
			 */
			public static function extract_country( array $reputation ): string {
				return isset( $reputation['countryCode'] ) ? (string) $reputation['countryCode'] : '';
			}
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-option-routing.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-audit-logger.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-user-sessions.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-notifications.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-login-context.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-policies.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class LoginContextTest extends TestCase {

		/**
		 * Start from empty options, meta and per-request guard.
		 */
		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options']               = array();
			$GLOBALS['wp_user_meta']             = array();
			$GLOBALS['wp_user_caps']             = array();
			$GLOBALS['rip_test_super_admins']    = array();
			$GLOBALS['wp_users']                 = array( 5 => new \WP_User( 5, array( 'editor' ) ) );
			\ReportedIP_Hive_Mode_Manager::$available      = true;
			\ReportedIP_Hive_Two_Factor::$globally_enabled = true;
			\ReportedIP_Hive_Geo_Anomaly::$country         = 'DE';
			\ReportedIP_Hive::$client_ip                   = '203.0.113.10';
			$_SERVER['HTTP_USER_AGENT']                    = 'Mozilla/5.0 (Test Browser)';
			$this->reset_guard();
		}

		/**
		 * Drop the in-memory buckets again.
		 */
		protected function tear_down() {
			$GLOBALS['wp_options']   = array();
			$GLOBALS['wp_user_meta'] = array();
			$GLOBALS['wp_user_caps'] = array();
			unset( $_SERVER['HTTP_USER_AGENT'] );
			parent::tear_down();
		}

		/**
		 * Clear the per-request "already recorded" and "verified" flags.
		 */
		private function reset_guard(): void {
			foreach ( array( 'recorded', 'verified' ) as $name ) {
				$property = new \ReflectionProperty( \ReportedIP_Hive_Login_Context::class, $name );
				$property->setValue( null, array() );
			}
		}

		/**
		 * The stored context of the test user.
		 *
		 * @return array<string, mixed>
		 */
		private function stored(): array {
			return \ReportedIP_Hive_Login_Context::get( 5 );
		}

		public function test_get_returns_the_full_shape_without_stored_data(): void {
			$context = $this->stored();

			$this->assertSame( 0, $context['verified_at'] );
			$this->assertSame( 0, $context['logins_since_verify'] );
			$this->assertSame( array(), $context['nets'] );
			$this->assertSame( '', $context['last']['ip'] );
		}

		public function test_record_writes_the_current_signals(): void {
			\ReportedIP_Hive_Login_Context::record( $GLOBALS['wp_users'][5], false );
			$context = $this->stored();

			$this->assertSame( '203.0.113.10', $context['last']['ip'] );
			$this->assertSame( '203.0.113.0/24', $context['last']['net'] );
			$this->assertSame( hash( 'sha256', 'Mozilla/5.0 (Test Browser)' ), $context['last']['ua'] );
			$this->assertSame( 'DE', $context['last']['country'] );
			$this->assertSame( array( '203.0.113.0/24' ), $context['nets'] );
			$this->assertSame( array( 'DE' ), $context['countries'] );
			$this->assertGreaterThan( 0, $context['last']['ts'] );
		}

		public function test_known_ip_list_is_shared_with_the_audit_logger(): void {
			\ReportedIP_Hive_Login_Context::record( $GLOBALS['wp_users'][5], false );

			$this->assertSame(
				array( '203.0.113.10' ),
				$GLOBALS['wp_user_meta'][5][ \ReportedIP_Hive_Audit_Logger::KNOWN_IPS_META ],
				'There must be exactly one known-IP list in the plugin.'
			);
		}

		public function test_lists_are_lru_capped(): void {
			for ( $i = 1; $i <= \ReportedIP_Hive_Login_Context::MAX_NETS + 5; $i++ ) {
				\ReportedIP_Hive::$client_ip = '10.0.' . $i . '.7';
				$this->reset_guard();
				\ReportedIP_Hive_Login_Context::record( $GLOBALS['wp_users'][5], false );
			}

			$context = $this->stored();

			$this->assertCount( \ReportedIP_Hive_Login_Context::MAX_NETS, $context['nets'] );
			$this->assertSame( '10.0.55.0/24', end( $context['nets'] ) );
			$this->assertNotContains( '10.0.1.0/24', $context['nets'], 'The oldest network drops out first.' );
			$this->assertCount( 1, $context['countries'], 'Repeated values must not grow the list.' );
		}

		public function test_unverified_logins_increment_and_a_verification_resets(): void {
			\ReportedIP_Hive_Login_Context::record( $GLOBALS['wp_users'][5], false );
			$baseline = $this->stored()['verified_at'];
			$this->reset_guard();
			\ReportedIP_Hive_Login_Context::record( $GLOBALS['wp_users'][5], false );

			$this->assertSame( 2, $this->stored()['logins_since_verify'] );
			$this->assertSame( $baseline, $this->stored()['verified_at'], 'Only a verification moves the clock forward.' );

			$this->reset_guard();
			\ReportedIP_Hive_Login_Context::record( $GLOBALS['wp_users'][5], true );

			$this->assertSame( 0, $this->stored()['logins_since_verify'] );
			$this->assertGreaterThan( 0, $this->stored()['verified_at'] );
		}

		public function test_request_guard_records_one_login_once(): void {
			\ReportedIP_Hive_Login_Context::record( $GLOBALS['wp_users'][5], true );
			\ReportedIP_Hive_Login_Context::record( $GLOBALS['wp_users'][5], false );

			$this->assertSame(
				0,
				$this->stored()['logins_since_verify'],
				'A wp_login fired twice for one sign-in must still count once.'
			);
		}

		public function test_a_verification_is_recorded_by_the_wp_login_listener(): void {
			\ReportedIP_Hive_Login_Context::on_verified( 5, 'totp', 'wp_login' );

			$this->assertArrayNotHasKey(
				\ReportedIP_Hive_Two_Factor::META_LOGIN_CONTEXT,
				$GLOBALS['wp_user_meta'][5] ?? array(),
				'Recording before wp_login would hand the audit logger a known IP and cost it the new_ip flag.'
			);
			$this->assertArrayNotHasKey(
				\ReportedIP_Hive_Audit_Logger::KNOWN_IPS_META,
				$GLOBALS['wp_user_meta'][5] ?? array()
			);

			\ReportedIP_Hive_Login_Context::on_login( 'tester', $GLOBALS['wp_users'][5] );

			$this->assertGreaterThan( 0, $this->stored()['verified_at'] );
			$this->assertSame( 0, $this->stored()['logins_since_verify'] );
			$this->assertSame(
				array( '203.0.113.10' ),
				$GLOBALS['wp_user_meta'][5][ \ReportedIP_Hive_Audit_Logger::KNOWN_IPS_META ]
			);
		}

		public function test_a_sign_in_without_a_second_factor_counts_up(): void {
			\ReportedIP_Hive_Login_Context::on_login( 'tester', $GLOBALS['wp_users'][5] );

			$this->assertSame( 1, $this->stored()['logins_since_verify'] );
			$this->assertGreaterThan(
				0,
				$this->stored()['verified_at'],
				'The first recorded sign-in seeds the every_n_days baseline instead of firing it.'
			);
		}

		public function test_nothing_is_stored_while_the_feature_is_unavailable(): void {
			\ReportedIP_Hive_Mode_Manager::$available = false;

			\ReportedIP_Hive_Login_Context::record( $GLOBALS['wp_users'][5], false );

			$this->assertArrayNotHasKey( 5, $GLOBALS['wp_user_meta'] );
		}

		public function test_nothing_is_stored_while_the_2fa_master_switch_is_off(): void {
			\ReportedIP_Hive_Two_Factor::$globally_enabled = false;

			\ReportedIP_Hive_Login_Context::record( $GLOBALS['wp_users'][5], false );

			$this->assertArrayNotHasKey(
				5,
				$GLOBALS['wp_user_meta'],
				'Without the master switch nothing hooks filter_authenticate, so the profile could never be read.'
			);
		}

		public function test_admin_latch_opens_only_for_a_user_who_may_manage_the_site(): void {
			$GLOBALS['wp_user_caps']['5|manage_options'] = false;

			\ReportedIP_Hive_Login_Context::on_verified( 5, 'totp', 'wp_login' );

			$this->assertFalse( \ReportedIP_Hive_Login_Context::admin_latch_open() );

			$GLOBALS['wp_user_caps']['5|manage_options'] = true;
			$this->reset_guard();
			\ReportedIP_Hive_Login_Context::on_verified( 5, 'totp', 'wp_login' );

			$this->assertTrue( \ReportedIP_Hive_Login_Context::admin_latch_open() );
		}

		public function test_admin_latch_opens_for_a_super_admin(): void {
			$GLOBALS['wp_user_caps']['5|manage_options'] = false;
			$GLOBALS['rip_test_super_admins']            = array( 5 );

			\ReportedIP_Hive_Login_Context::on_verified( 5, 'totp', 'rest' );

			$this->assertTrue( \ReportedIP_Hive_Login_Context::admin_latch_open() );
		}

		public function test_known_ips_reads_the_shared_list(): void {
			$GLOBALS['wp_user_meta'][5][ \ReportedIP_Hive_Audit_Logger::KNOWN_IPS_META ] = array( '198.51.100.7' );

			$this->assertSame( array( '198.51.100.7' ), \ReportedIP_Hive_Login_Context::known_ips( 5 ) );
			$this->assertSame( array(), \ReportedIP_Hive_Login_Context::known_ips( 99 ) );
		}
	}
}
