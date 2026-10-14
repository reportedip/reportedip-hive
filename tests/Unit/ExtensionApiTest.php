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
					'meta_key'        => 'reportedip_hive_2fa_dummy_enabled',
					'label'           => 'Dummy code',
					'choice_label'    => 'Dummy choice',
					'prompt'          => 'Enter the dummy code',
					'verify'          => $record( 'verify' ),
					'send'            => $record( 'send' ),
					'resend_wait'     => $record( 'resend_wait' ),
					'mask'            => $record( 'mask' ),
					'health'          => $record( 'health' ),
					'data_keys'       => array( 'reportedip_hive_2fa_dummy_secret' ),
					'resent_message'  => 'A new dummy code is on its way.',
					'expired_message' => 'No dummy code is active.',
					'code_active'     => static function () {
						return ! empty( $GLOBALS['rip_test_dummy_active'] );
					},
					'choice_lock'     => static function () {
						return (string) ( $GLOBALS['rip_test_dummy_plan'] ?? '' );
					},
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
	public function test_verifier_calls_the_verify_of_a_registered_method() {
		$this->register_dummy_2fa_method();
		$reasons = array();
		$report  = static function ( $reason, $method ) use ( &$reasons ) {
			$reasons[] = array( $reason, $method );
		};

		$this->assertTrue( \ReportedIP_Hive_Two_Factor_Verifier::verify_method( 9, 'dummy', '424242', $report ) );
		$this->assertFalse( \ReportedIP_Hive_Two_Factor_Verifier::verify_method( 9, 'dummy', '000000', $report ) );
		$this->assertSame( array( array( 9, '424242' ), array( 9, '000000' ) ), array_column( $GLOBALS['rip_test_dummy_calls'], 1 ) );

		$this->assertFalse( \ReportedIP_Hive_Two_Factor_Verifier::verify_method( 9, 'sms', '424242', $report ), 'A method nobody registered never verifies.' );
		$this->assertSame( array( array( 'unknown_method', 'sms' ) ), $reasons );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_reset_gate_uses_send_mask_wait_and_health_of_a_registered_method() {
		$this->register_dummy_2fa_method();
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-reset-gate.php';
		$gate   = new \ReportedIP_Hive_Two_Factor_Reset_Gate();
		$invoke = static function ( $name, ...$args ) use ( $gate ) {
			return ( new \ReflectionMethod( $gate, $name ) )->invoke( $gate, ...$args );
		};

		$this->assertTrue( $invoke( 'dispatch_initial_code', 4, 'dummy' ) );
		$this->assertSame( 'We have sent a verification code to +49 ****42.', $invoke( 'code_sent_notice', 4, 'dummy' ) );
		$this->assertSame( 45, $invoke( 'get_resend_wait_seconds', 4, 'dummy' ) );
		$this->assertSame( 'Dummy code', $invoke( 'method_label', 'dummy' ) );
		$this->assertSame( 'Enter the dummy code', $invoke( 'method_prompt', 'dummy' ) );
		$this->assertStringContainsString( 'resend_dummy=1', $invoke( 'build_resend_url', 'jane', 'key', 'dummy' ) );
		$this->assertSame(
			array(
				'ok'     => array( 'recovery' ),
				'broken' => array( 'dummy' => 'Dummy gateway is down' ),
			),
			$invoke( 'assess_methods_health', 4, array( 'dummy', 'recovery' ) )
		);
		$this->assertSame( array( 'send', 'mask', 'resend_wait', 'health' ), array_column( $GLOBALS['rip_test_dummy_calls'], 0 ) );
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
			$this->assertSame( 'A new dummy code is on its way.', $response->data['message'], 'The method supplies its own confirmation.' );
		}
		$this->assertSame( array( 'send', 'resend_wait', 'mask' ), array_column( $GLOBALS['rip_test_dummy_calls'], 0 ) );
		$this->assertSame( array( 5 ), $GLOBALS['rip_test_dummy_calls'][0][1], 'send() receives the challenged user.' );
	}

	/**
	 * Start a challenge for user 5 and ask the resend endpoint for a method.
	 *
	 * @param string $method Method slug posted by the client.
	 * @return \ReportedIP_Hive_Test_Json_Response
	 */
	private function resend_for_user_5( $method ) {
		$_COOKIE[ \ReportedIP_Hive_Two_Factor::NONCE_COOKIE ] = 'challenge-token';
		set_transient(
			\ReportedIP_Hive_Two_Factor::NONCE_PREFIX . hash( 'sha256', 'challenge-token' ),
			array(
				'user_id' => 5,
				'ip'      => \ReportedIP_Hive::get_client_ip(),
			),
			600
		);
		$_POST['method'] = $method;

		try {
			( new \ReportedIP_Hive_Two_Factor() )->ajax_resend_code();
		} catch ( \ReportedIP_Hive_Test_Json_Response $response ) {
			return $response;
		}
		$this->fail( 'The handler must answer with JSON.' );
	}

	/**
	 * A method the account never set up must not send, even though the
	 * site allows it and it can send.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_resend_ajax_refuses_a_method_the_user_has_not_enabled() {
		$this->register_dummy_2fa_method();
		$this->set_mocked_option( 'reportedip_hive_2fa_allowed_methods', '["totp","dummy"]' );
		update_user_meta( 5, 'reportedip_hive_2fa_totp_enabled', '1' );

		$response = $this->resend_for_user_5( 'dummy' );

		$this->assertFalse( $response->success );
		$this->assertSame( 400, $response->status );
		$this->assertSame( array(), $GLOBALS['rip_test_dummy_calls'], 'Nothing is sent for a method the user has not enabled.' );
	}

	/**
	 * A method without a callable `send` answers with an error instead of a
	 * fatal call.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_resend_ajax_refuses_a_method_whose_send_is_not_callable() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'tests/stubs/two-factor-runtime-stubs.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-verifier.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor.php';
		add_filter(
			'reportedip_hive_2fa_methods',
			static function ( array $methods ) {
				$methods['broken'] = array(
					'meta_key' => 'reportedip_hive_2fa_broken_enabled',
					'verify'   => '__return_false',
					'send'     => 'no_such_function_anywhere',
				);
				return $methods;
			}
		);
		\ReportedIP_Hive_Two_Factor::flush_methods();
		$this->set_mocked_option( 'reportedip_hive_2fa_allowed_methods', '["totp","broken"]' );
		update_user_meta( 5, 'reportedip_hive_2fa_broken_enabled', '1' );

		$response = $this->resend_for_user_5( 'broken' );

		$this->assertFalse( $response->success );
		$this->assertSame( 400, $response->status );
	}

	/**
	 * The `?resend_{slug}=1` link of the challenge page only sends for the
	 * methods the user has enabled, never for the whole registry.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_resend_link_sends_only_for_an_enabled_method() {
		$this->register_dummy_2fa_method();
		$send          = new \ReflectionMethod( \ReportedIP_Hive_Two_Factor::class, 'send_requested_codes' );
		$_GET['resend_dummy'] = '1';

		$this->assertSame(
			array(
				'method' => '',
				'error'  => '',
			),
			$send->invoke( null, 5, array( 'totp' ) )
		);
		$this->assertSame( array(), $GLOBALS['rip_test_dummy_calls'], 'A registered method the user has not enabled never sends.' );

		$this->assertSame(
			array(
				'method' => 'dummy',
				'error'  => '',
			),
			$send->invoke( null, 5, array( 'totp', 'dummy' ) )
		);
		$this->assertSame( array( array( 'send', array( 5 ) ) ), $GLOBALS['rip_test_dummy_calls'] );

		$source = (string) file_get_contents( REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor.php' );
		$this->assertMatchesRegularExpression(
			'/\$allowed_methods = self::get_user_enabled_methods\( \$user_id \);\s+\$resent\s+= self::send_requested_codes\( \(int\) \$user_id, \$allowed_methods \);/',
			$source,
			'The challenge page hands the user\'s enabled methods to the resend, not the registry.'
		);
	}

	/**
	 * A wrong code reads the method's expiry sentence while it reports no
	 * active code, the generic sentence otherwise.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_wrong_code_message_uses_the_expired_message_of_the_method() {
		$this->register_dummy_2fa_method();
		$message = new \ReflectionMethod( \ReportedIP_Hive_Two_Factor::class, 'wrong_code_message' );
		$generic = 'Invalid verification code. Please make sure you are using the most recent code.';

		$this->assertSame( 'No dummy code is active.', $message->invoke( null, 5, 'dummy' ) );
		$GLOBALS['rip_test_dummy_active'] = true;
		$this->assertSame( $generic, $message->invoke( null, 5, 'dummy' ) );
		$this->assertSame( $generic, $message->invoke( null, 5, 'totp' ), 'A method without an expiry sentence keeps the generic one.' );
		$this->assertStringStartsWith( 'No valid code is active', $message->invoke( null, 5, 'email' ), 'The email expiry sentence comes from the registry now.' );
	}

	/**
	 * Load the protection page renderer next to the dummy method.
	 *
	 * @return array<string, mixed> Registry entry of the allowed-methods key.
	 */
	private function allowed_methods_entry() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-protection-page.php';
		return \ReportedIP_Hive_Settings_Registry::spec()['reportedip_hive_2fa_allowed_methods'];
	}

	/**
	 * A method that needs a higher plan is listed disabled with that plan,
	 * under its `choice_label`; a stored choice of it stays an enabled,
	 * checked box, so it can be removed but not newly added.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_choice_lock_disables_the_choice_and_keeps_it_removable() {
		$this->register_dummy_2fa_method();
		$entry = $this->allowed_methods_entry();
		$key   = 'reportedip_hive_2fa_allowed_methods';

		$open = \ReportedIP_Hive_Protection_Page::choices_for( $entry, $key );
		$this->assertFalse( $open['dummy']['disabled'] );
		$this->assertSame( 'Dummy choice', $open['dummy']['label'] );

		$GLOBALS['rip_test_dummy_plan'] = 'Professional';
		$locked                         = \ReportedIP_Hive_Protection_Page::choices_for( $entry, $key );
		$this->assertTrue( $locked['dummy']['disabled'] );
		$this->assertSame( 'Dummy choice (Professional plan)', $locked['dummy']['label'] );
		$this->assertFalse( $locked['totp']['disabled'] );

		$status = array( 'available' => true );
		$hidden = '<input type="hidden" name="' . $key . '[]" value="dummy" />';
		$stored = \ReportedIP_Hive_Protection_Page::field_markup( $key, $entry, '["totp","dummy"]', $status, $locked );
		$this->assertStringContainsString( 'value="dummy" checked />', $stored, 'A stored locked choice can be unchecked.' );
		$this->assertStringNotContainsString( $hidden, $stored, 'Unchecking it drops it on save.' );
		$this->assertStringContainsString( 'value="dummy"  disabled', \ReportedIP_Hive_Protection_Page::field_markup( $key, $entry, '["totp"]', $status, $locked ), 'A locked choice that is not stored cannot be added.' );
		$this->assertStringNotContainsString( $hidden, \ReportedIP_Hive_Protection_Page::field_markup( $key, $entry, '["totp","dummy"]', $status, $open ), 'A selectable choice travels as its checkbox.' );
	}

	/**
	 * The sub-site 2FA page offers a slot for further read-only blocks and
	 * names no add-on class itself.
	 */
	public function test_site_2fa_page_offers_the_settings_slot() {
		$source = (string) file_get_contents( REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-admin-settings.php' );
		$body   = substr( $source, (int) strpos( $source, 'public function render_site_2fa_settings_page(' ) );
		$body   = substr( $body, 0, (int) strpos( $body, 'private function render_site_admin_header(' ) );

		$this->assertStringContainsString( "do_action( 'reportedip_hive_site_2fa_settings_after', \$all_roles );", $body );
		$this->assertStringNotContainsString( 'Two_Factor_Policies', $body );
		$this->assertLessThan( strpos( $body, 'submit_button(' ), strpos( $body, 'reportedip_hive_site_2fa_settings_after' ), 'The slot sits above the submit button.' );
	}

	/**
	 * The challenge URL goes through a filter that sees the origin token.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_challenge_url_is_filterable_by_origin() {
		$this->register_dummy_2fa_method();
		$default = wp_login_url() . '?action=' . \ReportedIP_Hive_Two_Factor::ACTION_CHALLENGE;

		$this->assertSame( $default, \ReportedIP_Hive_Two_Factor::resolve_challenge_url( 'shop' ), 'Without a listener every sign-in keeps wp-login.' );

		add_filter(
			'reportedip_hive_2fa_challenge_url',
			static function ( $url, $origin ) {
				return 'shop' === $origin ? 'https://example.org/verify/' : $url;
			},
			10,
			2
		);
		$this->assertSame( 'https://example.org/verify/', \ReportedIP_Hive_Two_Factor::resolve_challenge_url( 'shop' ) );
		$this->assertSame( $default, \ReportedIP_Hive_Two_Factor::resolve_challenge_url( '' ) );
	}

	/**
	 * The redirect after a passed challenge keeps `redirect_to` and hands
	 * event, context and payload to the filter.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_post_verify_redirect_is_filterable_per_context() {
		$this->register_dummy_2fa_method();
		$nonce = array(
			'redirect_to' => 'https://example.org/wp-admin/profile.php',
			'origin'      => 'shop',
		);

		$this->assertSame( 'https://example.org/wp-admin/profile.php', \ReportedIP_Hive_Two_Factor::resolve_post_verify_redirect( $nonce, 'storefront' ) );

		$seen = array();
		add_filter(
			'reportedip_hive_2fa_redirect_url',
			static function ( $url, $event, $context, $payload ) use ( &$seen ) {
				$seen = array( $url, $event, $context, $payload );
				return 'storefront' === $context ? 'https://example.org/account/' : $url;
			},
			10,
			4
		);
		$this->assertSame( 'https://example.org/account/', \ReportedIP_Hive_Two_Factor::resolve_post_verify_redirect( $nonce, 'storefront' ) );
		$this->assertSame( array( 'https://example.org/wp-admin/profile.php', 'verified', 'storefront', $nonce ), $seen );
	}

	/**
	 * The challenge engine knows no storefront: the surface plugs in through
	 * the payload, URL, redirect and render hooks, and wp-login renders when
	 * nobody listens.
	 */
	public function test_challenge_engine_has_no_storefront_knowledge() {
		$source = (string) file_get_contents( REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor.php' );

		foreach ( array( 'wc_get_page_permalink', 'woocommerce', 'WooCommerce', 'Two_Factor_Frontend', 'open_theme_frame', 'HTTP_REFERER' ) as $needle ) {
			$this->assertStringNotContainsString( $needle, $source, $needle );
		}
		$this->assertStringContainsString( "array_merge( (array) apply_filters( 'reportedip_hive_2fa_challenge_payload', array(), \$user ), \$nonce_data )", $source, 'Core payload fields win over extra fields.' );
		$this->assertStringContainsString( "if ( 'wp_login' !== \$context && has_action( 'reportedip_hive_2fa_render_challenge_' . \$context ) ) {", $source );
		$this->assertStringContainsString( "if ( 'wp_login' !== \$context && has_action( 'reportedip_hive_2fa_render_expired_' . \$context ) ) {", $source );
		$this->assertStringContainsString( "self::challenge_redirect( 'locked', wp_login_url() . '?reportedip_2fa_locked=1', \$context, \$nonce_data )", $source );
		$this->assertStringContainsString( "self::challenge_redirect( 'signed_in', admin_url(), \$context, array() )", $source );
	}
}
