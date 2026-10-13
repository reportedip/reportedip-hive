<?php
/**
 * The extension points the add-on consumes, each proven with a filter.
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
 * Filter-driven extension points.
 */
class ExtensionApiTest extends TestCase {

	protected function set_up() {
		parent::set_up();
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-defaults.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-mode-manager.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-settings-registry.php';
		global $wp_filters, $wp_actions;
		$wp_filters               = array();
		$wp_actions               = array();
		$GLOBALS['wp_options']    = array();
		$GLOBALS['wp_transients'] = array();
		\ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
	}

	protected function tear_down() {
		global $wp_filters, $wp_actions;
		$wp_filters = array();
		$wp_actions = array();
		\ReportedIP_Hive_Mode_Manager::get_instance()->flush_feature_matrix();
		\ReportedIP_Hive_Settings_Registry::flush_spec_cache();
		if ( class_exists( 'ReportedIP_Hive_Event_Taxonomy', false ) ) {
			\ReportedIP_Hive_Event_Taxonomy::flush_registry();
		}
		parent::tear_down();
	}

	public function test_feature_matrix_accepts_injected_rows() {
		add_filter(
			'reportedip_hive_feature_matrix',
			static function ( array $matrix ) {
				$matrix['demo_pro_feature'] = array(
					'local'         => true,
					'community'     => true,
					'requires_tier' => 'professional',
				);
				return $matrix;
			}
		);
		$manager = \ReportedIP_Hive_Mode_Manager::get_instance();
		$manager->flush_feature_matrix();
		$manager->set_mode( 'local' );

		$status = $manager->feature_status( 'demo_pro_feature' );

		$this->assertFalse( $status['available'] );
		$this->assertSame( 'tier', $status['reason'] );
		$this->assertSame( 'professional', $status['min_tier'] );
	}

	public function test_unknown_feature_stays_unknown_without_filter() {
		$manager = \ReportedIP_Hive_Mode_Manager::get_instance();
		$manager->flush_feature_matrix();

		$status = $manager->feature_status( 'demo_pro_feature' );

		$this->assertFalse( $status['available'] );
		$this->assertSame( 'unknown', $status['reason'] );
	}

	public function test_matrix_filter_runs_once_even_when_it_returns_an_empty_array() {
		$runs = 0;
		add_filter(
			'reportedip_hive_feature_matrix',
			static function () use ( &$runs ) {
				++$runs;
				return array();
			}
		);
		$manager = \ReportedIP_Hive_Mode_Manager::get_instance();
		$manager->flush_feature_matrix();

		$manager->feature_status( 'x' );
		$manager->feature_status( 'x' );
		$this->assertSame( 1, $runs );

		$manager->flush_feature_matrix();
		$manager->feature_status( 'x' );
		$this->assertSame( 2, $runs );
	}

	public function test_settings_spec_accepts_injected_entries() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-settings-registry.php';
		add_filter(
			'reportedip_hive_settings_spec',
			static function ( array $spec ) {
				$spec['reportedip_hive_demo_switch'] = array(
					'section'     => 'detection',
					'kind'        => 'bool',
					'remote'      => true,
					'label'       => 'Demo',
					'description' => 'Demo switch.',
				);
				return $spec;
			}
		);
		\ReportedIP_Hive_Settings_Registry::flush_spec_cache();

		$spec = \ReportedIP_Hive_Settings_Registry::spec();

		$this->assertArrayHasKey( 'reportedip_hive_demo_switch', $spec );
		$this->assertArrayHasKey( 'reportedip_hive_trusted_ip_header', $spec );
	}

	public function test_settings_sections_accept_injected_sections() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-settings-registry.php';
		add_filter(
			'reportedip_hive_settings_sections',
			static function ( array $sections ) {
				$sections['demo'] = array(
					'label'       => 'Demo',
					'description' => 'Demo section.',
				);
				return $sections;
			}
		);

		$this->assertArrayHasKey( 'demo', \ReportedIP_Hive_Settings_Registry::sections() );
	}

	public function test_option_defaults_accept_injected_keys() {
		add_filter(
			'reportedip_hive_option_defaults',
			static function ( array $defaults ) {
				$defaults['reportedip_hive_demo_switch'] = false;
				return $defaults;
			}
		);

		$defaults = \ReportedIP_Hive_Defaults::all_option_defaults();

		$this->assertArrayHasKey( 'reportedip_hive_demo_switch', $defaults );
		$this->assertArrayHasKey( 'reportedip_hive_failed_login_threshold', $defaults );
	}

	public function test_recommended_values_accept_injected_keys() {
		add_filter(
			'reportedip_hive_recommended_values',
			static function ( array $values, $tier, $mode ) {
				if ( 'professional' === $tier ) {
					$values['reportedip_hive_demo_switch'] = 1;
				}
				return $values;
			},
			10,
			3
		);

		$this->assertArrayHasKey( 'reportedip_hive_demo_switch', \ReportedIP_Hive_Defaults::recommended( 'professional', 'community' ) );
		$this->assertArrayNotHasKey( 'reportedip_hive_demo_switch', \ReportedIP_Hive_Defaults::recommended( 'free', 'community' ) );
	}

	public function test_event_taxonomy_accepts_injected_rows() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-event-taxonomy.php';
		add_filter(
			'reportedip_hive_event_taxonomy',
			static function ( array $rows ) {
				$rows['demo_event'] = array(
					'label'  => 'Demo',
					'group'  => 'login',
					'family' => 'login',
					'writes' => 'direct',
				);
				return $rows;
			}
		);
		\ReportedIP_Hive_Event_Taxonomy::flush_registry();

		$this->assertArrayHasKey( 'demo_event', \ReportedIP_Hive_Event_Taxonomy::registry() );
	}

	public function test_settings_effects_forward_an_unknown_token() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-settings-effects.php';
		$ran = array();
		add_action(
			'reportedip_hive_settings_effect_demo',
			static function () use ( &$ran ) {
				$ran[] = 'demo';
			}
		);
		\ReportedIP_Hive_Settings_Effects::queue( 'demo' );
		\ReportedIP_Hive_Settings_Effects::run_queued();
		$this->assertSame( array( 'demo' ), $ran );
	}

	public function test_cron_jobs_accept_injected_job() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-cron-handler.php';
		add_filter(
			'reportedip_hive_cron_jobs',
			static function ( array $jobs ) {
				$jobs['reportedip_hive_demo_job'] = 'hourly';
				return $jobs;
			}
		);

		$this->assertContains( 'reportedip_hive_demo_job', \ReportedIP_Hive_Cron_Handler::get_hook_names() );
		$this->assertContains( 'reportedip_hive_cleanup', \ReportedIP_Hive_Cron_Handler::get_hook_names() );
	}

	public function test_effective_threshold_is_filterable_per_key() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-security-monitor.php';
		add_filter(
			'reportedip_hive_effective_threshold',
			static function ( $value, $key ) {
				return 'failed_login_threshold' === $key ? 2 : $value;
			},
			10,
			2
		);

		$this->assertSame( 2, \ReportedIP_Hive_Security_Monitor::effective_threshold( 'failed_login_threshold', 5 ) );
		$this->assertSame( 15, \ReportedIP_Hive_Security_Monitor::effective_threshold( 'failed_login_timeframe', 15 ) );
	}

	public function test_effective_threshold_never_returns_less_than_one() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-security-monitor.php';
		add_filter(
			'reportedip_hive_effective_threshold',
			static function () {
				return 0;
			}
		);

		$this->assertSame( 1, \ReportedIP_Hive_Security_Monitor::effective_threshold( 'failed_login_threshold', 5 ) );
		$this->assertSame( 1, \ReportedIP_Hive_Security_Monitor::effective_threshold( 'failed_login_timeframe', 15 ) );
	}

	public function test_distributed_threshold_helpers_live_in_free() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-security-monitor.php';
		$this->set_mocked_option( 'reportedip_hive_hardening_detect_min_ips', 3 );
		$this->set_mocked_option( 'reportedip_hive_hardening_detect_min_attempts', 20 );

		$this->assertTrue( \ReportedIP_Hive_Security_Monitor::breaches_distributed_thresholds( 3, 20 ) );
		$this->assertFalse( \ReportedIP_Hive_Security_Monitor::breaches_distributed_thresholds( 2, 20 ) );
	}

	/**
	 * Load the real two-factor classes with their runtime doubles and
	 * register a dummy method that records every call.
	 *
	 * @return void
	 */
	private function register_dummy_2fa_method() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'tests/stubs/two-factor-runtime-stubs.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-verifier.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor.php';
		$GLOBALS['rip_test_dummy_calls'] = array();
		add_filter(
			'reportedip_hive_2fa_methods',
			static function ( array $methods ) {
				$record                 = static function ( $name ) {
					return static function ( ...$args ) use ( $name ) {
						$GLOBALS['rip_test_dummy_calls'][] = array( $name, $args );
						switch ( $name ) {
							case 'verify':
								return '424242' === $args[1];
							case 'resend_wait':
								return 45;
							case 'mask':
								return '+49 ****42';
							case 'health':
								return 'Dummy gateway is down';
							default:
								return true;
						}
					};
				};
				$methods['dummy']       = array(
					'meta_key'    => 'reportedip_hive_2fa_dummy_enabled',
					'label'       => 'Dummy code',
					'prompt'      => 'Enter the dummy code',
					'verify'      => $record( 'verify' ),
					'send'        => $record( 'send' ),
					'resend_wait' => $record( 'resend_wait' ),
					'mask'        => $record( 'mask' ),
					'health'      => $record( 'health' ),
					'data_keys'   => array( 'reportedip_hive_2fa_dummy_secret' ),
				);
				$methods['totp']        = array(
					'meta_key' => 'hijacked',
					'verify'   => '__return_true',
				);
				$methods['no_verifier'] = array( 'meta_key' => 'reportedip_hive_2fa_no_verifier_enabled' );
				return $methods;
			}
		);
		\ReportedIP_Hive_Two_Factor::flush_methods();
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_2fa_method_registry_accepts_an_injected_method() {
		$this->register_dummy_2fa_method();

		$this->assertSame( array( 'totp', 'email', 'webauthn', 'dummy' ), \ReportedIP_Hive_Two_Factor::valid_methods() );
		$this->assertSame( 'reportedip_hive_2fa_dummy_enabled', \ReportedIP_Hive_Two_Factor::get_method_meta_key( 'dummy' ) );
		$this->assertSame( 'reportedip_hive_2fa_totp_enabled', \ReportedIP_Hive_Two_Factor::get_method_meta_key( 'totp' ), 'A core method cannot be replaced.' );
		$this->assertNull( \ReportedIP_Hive_Two_Factor::get_method_meta_key( 'no_verifier' ), 'A method without a verifier is not registered.' );

		update_user_meta( 3, 'reportedip_hive_2fa_dummy_enabled', '1' );
		update_user_meta( 3, 'reportedip_hive_2fa_dummy_secret', 'x' );
		$this->assertSame( array( 'dummy' ), \ReportedIP_Hive_Two_Factor::configured_method_flags( 3 ) );
		$this->assertContains( 'reportedip_hive_2fa_dummy_secret', \ReportedIP_Hive_Two_Factor::get_all_meta_keys() );

		\ReportedIP_Hive_Two_Factor::disable_for_user( 3 );
		$this->assertSame( '', get_user_meta( 3, 'reportedip_hive_2fa_dummy_enabled', true ), 'A full reset clears a registered method.' );
		$this->assertSame( '', get_user_meta( 3, 'reportedip_hive_2fa_dummy_secret', true ), 'A full reset clears the data a registered method owns.' );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_resend_ajax_uses_send_wait_and_mask_of_a_registered_method() {
		$this->register_dummy_2fa_method();
		$this->set_mocked_option( 'reportedip_hive_2fa_allowed_methods', '["totp","dummy"]' );
		update_user_meta( 5, 'reportedip_hive_2fa_dummy_enabled', '1' );
		$_COOKIE[ \ReportedIP_Hive_Two_Factor::NONCE_COOKIE ] = 'challenge-token';
		set_transient(
			\ReportedIP_Hive_Two_Factor::NONCE_PREFIX . hash( 'sha256', 'challenge-token' ),
			array(
				'user_id' => 5,
				'ip'      => \ReportedIP_Hive::get_client_ip(),
			),
			600
		);
		$_POST['method'] = 'dummy';

		try {
			( new \ReportedIP_Hive_Two_Factor() )->ajax_resend_code();
			$this->fail( 'The handler must answer with JSON.' );
		} catch ( \ReportedIP_Hive_Test_Json_Response $response ) {
			$this->assertTrue( $response->success );
			$this->assertSame( '+49 ****42', $response->data['destination'] );
			$this->assertSame( 45, $response->data['cooldown'] );
		}
		$this->assertSame( array( 'send', 'resend_wait', 'mask' ), array_column( $GLOBALS['rip_test_dummy_calls'], 0 ) );
		$this->assertSame( array( 5 ), $GLOBALS['rip_test_dummy_calls'][0][1], 'send() receives the challenged user.' );
	}
}
