<?php
/**
 * Unit tests for the adaptive 2FA step-up evaluator.
 *
 * The evaluator decides whether a sign-in that would otherwise pass has to
 * show the second factor again, so both directions matter: it must fire when
 * a configured condition holds, and it must stay silent for enforced users,
 * unlisted roles, missing baselines and plans that do not include the
 * feature. The wiring inside `filter_authenticate()` — allowlist before the
 * gate, trusted device only when nothing fired — is anchored by source
 * inspection, the pattern from SecurityMonitorBotGuardTest.
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

	if ( ! defined( 'DAY_IN_SECONDS' ) ) {
		define( 'DAY_IN_SECONDS', 86400 );
	}

	if ( ! function_exists( 'wp_roles' ) ) {
		/**
		 * Stub role provider exposing the default role slugs.
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
						'author'        => 'Author',
						'subscriber'    => 'Subscriber',
					);
				}
			};
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
		 * 2FA double: only the pieces the policies touch.
		 */
		class ReportedIP_Hive_Two_Factor {
			const META_LOGIN_CONTEXT = 'reportedip_hive_login_context';

			/**
			 * Reduce role slugs to the ones this site knows.
			 *
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
		 * Geo double: the reputation cache is not available in unit tests.
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
	class TwoFactorPoliciesTest extends TestCase {

		/**
		 * Start every case from empty options and empty user meta.
		 */
		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options']                        = array();
			$GLOBALS['wp_user_meta']                      = array();
			\ReportedIP_Hive_Mode_Manager::$available      = true;
			\ReportedIP_Hive_Geo_Anomaly::$country         = '';
			\ReportedIP_Hive::$client_ip                   = '203.0.113.10';
			$_SERVER['HTTP_USER_AGENT']                    = 'Mozilla/5.0 (Test Browser)';
		}

		/**
		 * Drop the in-memory buckets again.
		 */
		protected function tear_down() {
			$GLOBALS['wp_options']   = array();
			$GLOBALS['wp_user_meta'] = array();
			unset( $_SERVER['HTTP_USER_AGENT'] );
			parent::tear_down();
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

		/**
		 * Configure one trigger for one role.
		 *
		 * @param string $trigger Trigger slug.
		 * @param array  $roles   Role slugs.
		 */
		private function configure( string $trigger, array $roles ): void {
			$GLOBALS['wp_options'][ \ReportedIP_Hive_Two_Factor_Policies::option_key( $trigger ) ] = (string) wp_json_encode( $roles );
		}

		/**
		 * Seed a user's stored sign-in history.
		 *
		 * @param int   $user_id User id.
		 * @param array $context Partial context.
		 */
		private function seed_context( int $user_id, array $context ): void {
			$stored = array_merge(
				array(
					'last'                => array(
						'ip'       => '',
						'net'      => '',
						'ua'       => '',
						'ua_short' => '',
						'country'  => '',
						'ts'       => 0,
					),
					'verified_at'         => 0,
					'logins_since_verify' => 0,
					'nets'                => array(),
					'uas'                 => array(),
					'countries'           => array(),
				),
				$context
			);
			$GLOBALS['wp_user_meta'][ $user_id ]['reportedip_hive_login_context'] = (string) wp_json_encode( $stored );
		}

		/**
		 * An editor with a second factor and one configured trigger.
		 *
		 * @return \WP_User
		 */
		private function editor(): \WP_User {
			return new \WP_User( 7, array( 'editor' ) );
		}

		public function test_unavailable_feature_returns_empty(): void {
			$this->configure( 'new_ip', array( 'editor' ) );
			$GLOBALS['wp_user_meta'][7]['_reportedip_hive_known_ips'] = array( '198.51.100.1' );
			\ReportedIP_Hive_Mode_Manager::$available                 = false;

			$this->assertSame( '', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );
		}

		public function test_enforced_user_is_excluded(): void {
			$this->configure( 'new_ip', array( 'editor' ) );
			$GLOBALS['wp_user_meta'][7]['_reportedip_hive_known_ips'] = array( '198.51.100.1' );

			$this->assertSame( '', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, true ) );
		}

		public function test_role_not_listed_returns_empty(): void {
			$this->configure( 'new_ip', array( 'author' ) );
			$GLOBALS['wp_user_meta'][7]['_reportedip_hive_known_ips'] = array( '198.51.100.1' );

			$this->assertSame( '', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );
		}

		public function test_user_without_a_method_returns_the_sentinel(): void {
			$this->configure( 'new_ip', array( 'editor' ) );

			$this->assertSame(
				'no_method:new_ip',
				\ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), false, false )
			);
		}

		public function test_new_ip_needs_a_baseline(): void {
			$this->configure( 'new_ip', array( 'editor' ) );

			$this->assertSame( '', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );

			$GLOBALS['wp_user_meta'][7]['_reportedip_hive_known_ips'] = array( '198.51.100.1' );
			$this->assertSame( 'new_ip', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );

			$GLOBALS['wp_user_meta'][7]['_reportedip_hive_known_ips'] = array( '203.0.113.10' );
			$this->assertSame( '', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );
		}

		public function test_new_subnet_compares_the_network_block(): void {
			$this->configure( 'new_subnet', array( 'editor' ) );
			$this->seed_context( 7, array( 'nets' => array( '203.0.113.0/24' ) ) );

			$this->assertSame( '', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );

			\ReportedIP_Hive::$client_ip = '198.51.100.4';
			$this->assertSame( 'new_subnet', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );
		}

		public function test_new_device_compares_the_user_agent_hash(): void {
			$this->configure( 'new_device', array( 'editor' ) );
			$this->seed_context( 7, array( 'uas' => array( hash( 'sha256', 'Mozilla/5.0 (Test Browser)' ) ) ) );

			$this->assertSame( '', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );

			$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Another Browser)';
			$this->assertSame( 'new_device', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );
		}

		public function test_new_country_stays_quiet_without_reputation_data(): void {
			$this->configure( 'new_country', array( 'editor' ) );
			$this->seed_context( 7, array( 'countries' => array( 'DE' ) ) );

			$this->assertSame( '', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );

			\ReportedIP_Hive_Geo_Anomaly::$country = 'US';
			$this->assertSame( 'new_country', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );
		}

		public function test_every_n_days_needs_a_verification_baseline(): void {
			$this->configure( 'every_n_days', array( 'editor' ) );
			$this->seed_context( 7, array( 'verified_at' => 0 ) );

			$this->assertSame(
				'',
				\ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ),
				'A site that just switched the feature on must not challenge everyone at once.'
			);

			$this->seed_context( 7, array( 'verified_at' => time() - ( 31 * DAY_IN_SECONDS ) ) );
			$this->assertSame( 'every_n_days', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );

			$this->seed_context( 7, array( 'verified_at' => time() - ( 2 * DAY_IN_SECONDS ) ) );
			$this->assertSame( '', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );
		}

		public function test_every_n_logins_uses_the_configured_threshold(): void {
			$this->configure( 'every_n_logins', array( 'editor' ) );
			$GLOBALS['wp_options']['reportedip_hive_2fa_policy_logins'] = 4;

			$this->seed_context( 7, array( 'logins_since_verify' => 3 ) );
			$this->assertSame( '', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );

			$this->seed_context( 7, array( 'logins_since_verify' => 4 ) );
			$this->assertSame( 'every_n_logins', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );
		}

		public function test_sessions_above_n_counts_live_sessions(): void {
			$this->configure( 'sessions_above_n', array( 'editor' ) );
			$GLOBALS['wp_options']['reportedip_hive_2fa_policy_sessions'] = 2;

			$GLOBALS['wp_user_meta'][7]['session_tokens'] = array(
				'a' => array( 'expiration' => time() + 3600 ),
			);
			$this->assertSame( '', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );

			$GLOBALS['wp_user_meta'][7]['session_tokens'] = array(
				'a' => array( 'expiration' => time() + 3600 ),
				'b' => array( 'expiration' => time() + 3600 ),
				'c' => array( 'expiration' => time() - 10 ),
			);
			$this->assertSame( 'sessions_above_n', \ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ) );
		}

		public function test_evaluation_order_returns_the_first_match(): void {
			$this->configure( 'new_country', array( 'editor' ) );
			$this->configure( 'every_n_logins', array( 'editor' ) );
			$GLOBALS['wp_options']['reportedip_hive_2fa_policy_logins'] = 2;
			\ReportedIP_Hive_Geo_Anomaly::$country                      = 'US';
			$this->seed_context(
				7,
				array(
					'logins_since_verify' => 9,
					'countries'           => array( 'DE' ),
				)
			);

			$this->assertSame(
				'every_n_logins',
				\ReportedIP_Hive_Two_Factor_Policies::evaluate( $this->editor(), true, false ),
				'EVAL_ORDER puts the cheap counters before the signal comparisons.'
			);
		}

		public function test_filter_policy_roles_strips_administrator_until_the_latch_opens(): void {
			$this->assertSame(
				array( 'editor' ),
				\ReportedIP_Hive_Two_Factor_Policies::filter_policy_roles( array( 'administrator', 'editor', 'ghost' ) )
			);

			$GLOBALS['wp_options'][ \ReportedIP_Hive_Login_Context::OPT_ADMIN_VERIFIED ] = time();

			$this->assertSame(
				array( 'administrator', 'editor' ),
				\ReportedIP_Hive_Two_Factor_Policies::filter_policy_roles( array( 'administrator', 'editor', 'ghost' ) )
			);
		}

		public function test_roles_for_drops_unknown_slugs(): void {
			$this->configure( 'new_ip', array( 'editor', 'ghost' ) );

			$this->assertSame( array( 'editor' ), \ReportedIP_Hive_Two_Factor_Policies::roles_for( 'new_ip' ) );
			$this->assertSame( array(), \ReportedIP_Hive_Two_Factor_Policies::roles_for( 'not_a_trigger' ) );
		}

		public function test_matrix_covers_every_trigger(): void {
			$matrix = \ReportedIP_Hive_Two_Factor_Policies::matrix();

			$this->assertSame( \ReportedIP_Hive_Two_Factor_Policies::TRIGGERS, array_keys( $matrix ) );
			$this->assertSame(
				\ReportedIP_Hive_Two_Factor_Policies::TRIGGERS,
				array_keys( \ReportedIP_Hive_Two_Factor_Policies::trigger_texts() ),
				'Every trigger needs a label and a description in the settings matrix.'
			);

			$triggers = \ReportedIP_Hive_Two_Factor_Policies::TRIGGERS;
			$order    = \ReportedIP_Hive_Two_Factor_Policies::EVAL_ORDER;
			sort( $triggers );
			sort( $order );
			$this->assertSame(
				$triggers,
				$order,
				'A trigger missing from EVAL_ORDER would render in the matrix but never fire.'
			);
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
				'The enforcement list is shared — the policies must not change how it is read.'
			);
		}

		public function test_session_count_goes_through_the_single_reader(): void {
			$this->assertStringContainsString(
				'ReportedIP_Hive_User_Sessions::for_user(',
				$this->source( 'includes/class-two-factor-policies.php' )
			);
			$this->assertStringNotContainsString(
				'WP_Session_Tokens',
				$this->source( 'includes/class-two-factor-policies.php' ),
				'There is exactly one session reader in the plugin.'
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
}
