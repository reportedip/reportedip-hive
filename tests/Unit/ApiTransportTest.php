<?php
/**
 * The public API transport stays on the API host, keeps the bodies of
 * add-on calls out of the debug log on request, and the free plugin's own
 * quota paths never reach a relay endpoint.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

namespace {

	if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
		define( 'HOUR_IN_SECONDS', 3600 );
	}
	if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
		define( 'MINUTE_IN_SECONDS', 60 );
	}
	if ( ! defined( 'DAY_IN_SECONDS' ) ) {
		define( 'DAY_IN_SECONDS', 86400 );
	}

	if ( ! function_exists( 'wp_remote_request' ) ) {
		/**
		 * Record the request and answer with the programmed response.
		 *
		 * @param string $url  URL.
		 * @param array  $args Arguments.
		 * @return array|\WP_Error
		 */
		function wp_remote_request( $url, $args = array() ) {
			$GLOBALS['rip_transport_requests'][] = array(
				'url'  => $url,
				'args' => $args,
			);
			$next = $GLOBALS['rip_transport_next'] ?? null;
			return null === $next ? new \WP_Error( 'no_network', 'Network calls disabled in unit tests' ) : $next;
		}
	}
	if ( ! function_exists( 'wp_remote_get' ) ) {
		function wp_remote_get( $url, $args = array() ) {
			return wp_remote_request( $url, $args );
		}
	}
	if ( ! function_exists( 'wp_remote_post' ) ) {
		function wp_remote_post( $url, $args = array() ) {
			return wp_remote_request( $url, $args );
		}
	}
	if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
		function wp_remote_retrieve_body( $r ) { return is_array( $r ) ? ( $r['body'] ?? '' ) : ''; }
	}
	if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
		function wp_remote_retrieve_response_code( $r ) { return is_array( $r ) ? ( $r['response']['code'] ?? 0 ) : 0; }
	}
	if ( ! function_exists( 'wp_remote_retrieve_header' ) ) {
		function wp_remote_retrieve_header( $r, $h ) { return is_array( $r ) ? ( $r['headers'][ $h ] ?? '' ) : ''; }
	}

	if ( ! class_exists( 'ReportedIP_Hive_Logger' ) ) {
		class ReportedIP_Hive_Logger {
			private static $instance = null;
			public static function get_instance() {
				if ( null === self::$instance ) {
					self::$instance = new self();
				}
				return self::$instance;
			}
			public function log_security_event( ...$args ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			public function info( ...$args ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			public function warning( ...$args ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			public function error( ...$args ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			public static function truncate( $text, $len = 200 ) { return substr( (string) $text, 0, $len ); }
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-mode-manager.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-api-client.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-cron-handler.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class ApiTransportTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			if ( ! class_exists( 'ReportedIP_Hive_Cache' ) ) {
				require_once dirname( __DIR__, 2 ) . '/includes/class-cache.php';
			}
			$GLOBALS['wp_transients']          = array();
			$GLOBALS['wp_options']             = array(
				'reportedip_hive_api_key'        => 'test-key',
				'reportedip_hive_api_endpoint'   => 'https://api.example.test/v2/',
				'reportedip_hive_operation_mode' => 'community',
			);
			$GLOBALS['rip_transport_requests'] = array();
			$GLOBALS['rip_transport_next']     = null;

			$prop = new \ReflectionProperty( '\ReportedIP_Hive_API', 'instance' );
			$prop->setValue( null, null );
		}

		/**
		 * URLs of every captured request.
		 *
		 * @return string[]
		 */
		private function urls(): array {
			return array_column( $GLOBALS['rip_transport_requests'], 'url' );
		}

		public function test_an_absolute_or_protocol_relative_endpoint_stays_below_the_api_base(): void {
			$api = \ReportedIP_Hive_API::get_instance();
			foreach ( array( 'https://evil.example/x', '//evil.example/x', '/check' ) as $endpoint ) {
				$api->request( 'GET', $endpoint );
			}
			$this->assertCount( 3, $this->urls() );
			foreach ( $this->urls() as $url ) {
				$this->assertStringStartsWith( 'https://api.example.test/v2/', $url );
				$this->assertSame( 'api.example.test', wp_parse_url( $url, PHP_URL_HOST ), $url );
			}
		}

		public function test_a_call_that_opts_out_is_kept_out_of_the_debug_log(): void {
			define( 'REPORTEDIP_DEBUG', true );
			$log = tempnam( sys_get_temp_dir(), 'riplog' );
			ini_set( 'error_log', $log ); // phpcs:ignore WordPress.PHP.IniSet.Risky -- Test captures debug.log output in a temp file.
			$GLOBALS['rip_transport_next'] = array(
				'response' => array( 'code' => 200 ),
				'body'     => '{"secret":"123456"}',
				'headers'  => array(),
			);

			\ReportedIP_Hive_API::get_instance()->request( 'POST', 'quiet-endpoint', array(), '{"code":"123456"}', null, '', false );
			$this->assertStringNotContainsString( 'quiet-endpoint', (string) file_get_contents( $log ) );
			$this->assertStringNotContainsString( '123456', (string) file_get_contents( $log ) );

			\ReportedIP_Hive_API::get_instance()->request( 'GET', 'loud-endpoint' );
			$this->assertStringContainsString( 'loud-endpoint', (string) file_get_contents( $log ), 'The default still logs.' );
			unlink( $log );
		}

		public function test_the_quota_cron_reaches_no_relay_endpoint(): void {
			$GLOBALS['rip_transport_next'] = array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode(
					array(
						'valid'            => true,
						'userRole'         => 'reportedip_professional',
						'remainingReports' => 10,
						'dailyReportLimit' => 50,
					)
				),
				'headers'  => array(),
			);
			$cron = ( new \ReflectionClass( \ReportedIP_Hive_Cron_Handler::class ) )->newInstanceWithoutConstructor();
			foreach (
				array(
					'api_client' => \ReportedIP_Hive_API::get_instance(),
					'logger'     => \ReportedIP_Hive_Logger::get_instance(),
					'database'   => new class() {
						public function get_queue_size() {
							return 0;
						}
					},
				) as $name => $value
			) {
				$prop = new \ReflectionProperty( $cron, $name );
				$prop->setValue( $cron, $value );
			}

			$cron->cron_refresh_quota();

			$this->assertNotEmpty( $this->urls(), 'The cron asks the API for the quota.' );
			foreach ( $this->urls() as $url ) {
				$this->assertDoesNotMatchRegularExpression( '#/relay-(mail|sms|quota)#', $url );
			}
		}

		public function test_the_key_change_refresh_reaches_no_relay_endpoint(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );
			$start  = strpos( $source, 'public static function refresh_tier_after_key_change()' );
			$this->assertNotFalse( $start );
			$body = substr( $source, $start, (int) strpos( $source, "\n\t}", $start ) - $start );
			$this->assertStringContainsString( 'ReportedIP_Hive_API::get_instance()->refresh_api_quota();', $body );
			$this->assertSame( 1, substr_count( $body, '->' ), 'The handler makes exactly the one free quota call.' );

			$GLOBALS['rip_transport_next'] = array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( array( 'valid' => true, 'userRole' => 'reportedip_business' ) ),
				'headers'  => array(),
			);
			\ReportedIP_Hive_API::get_instance()->refresh_api_quota();
			$this->assertNotEmpty( $this->urls() );
			foreach ( $this->urls() as $url ) {
				$this->assertDoesNotMatchRegularExpression( '#/relay-(mail|sms|quota)#', $url );
			}
		}
	}
}
