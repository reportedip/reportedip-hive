<?php
/**
 * Tests for the generic registry AJAX writer and the retrofitted Firewall
 * card writers.
 *
 * Every AJAX path that persists a registry-managed option must pass the
 * registry sanitizer (kind coercion plus tier gate) before the option
 * router sees the value; a bespoke enum whitelist or a raw boolean flip
 * bypasses the tier contract that the Settings API, MainWP and the cloud
 * transport already honour.
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
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Source inspection of the handler plus a registry check for every key
	 * the retrofitted writers touch.
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class AjaxRegistrySaveTest extends TestCase {

		/**
		 * Option keys written by the retrofitted Firewall card handlers.
		 *
		 * @var string[]
		 */
		const RETROFIT_KEYS = array(
			'reportedip_hive_waf_enabled',
			'reportedip_hive_waf_report_only',
			'reportedip_hive_waf_paranoia',
			'reportedip_hive_bot_action',
			'reportedip_hive_disposable_email_action',
			'reportedip_hive_block_email_relays',
			'reportedip_hive_comment_honeypot_enabled',
			'reportedip_hive_monitor_404_scans',
			'reportedip_hive_decoy_pathblock_enabled',
		);

		/**
		 * Handler source text.
		 *
		 * @return string
		 */
		private function handler_source(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-ajax-handler.php' );
		}

		/**
		 * Body of one method in the handler class.
		 *
		 * @param string $method Method name.
		 * @return string
		 */
		private function method_body( string $method ): string {
			$this->assertSame(
				1,
				preg_match( '/function ' . preg_quote( $method, '/' ) . '\([^)]*\)\s*\{(.*?)\n\t\}/s', $this->handler_source(), $match ),
				"$method() must exist"
			);

			return $match[1];
		}

		public function test_registry_save_action_is_registered() {
			$this->assertStringContainsString(
				"add_action( 'wp_ajax_reportedip_hive_registry_save', array( \$this, 'ajax_registry_save' ) );",
				$this->handler_source()
			);
		}

		public function test_registry_save_hands_the_decoded_payload_to_the_atomic_helper() {
			$body = $this->method_body( 'ajax_registry_save' );

			$this->assertStringContainsString( "check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );", $body, 'nonce check stays inline' );
			$this->assertStringContainsString( '$this->require_admin_capability();', $body );
			$this->assertStringContainsString( '$result = $this->apply_registry_batch( $values );', $body, 'the batch runs through the shared atomic helper' );
			$this->assertStringNotContainsString( 'Settings_Registry::', $body, 'the handler must not carry a second copy of the apply pipeline' );
			$this->assertStringNotContainsString( 'Option_Routing::set(', $body, 'writes go through Settings_Apply only' );
			$this->assertStringContainsString( "'results'   => \$result['results']", $body, 'the per-key result map is returned to the page' );
		}

		public function test_atomic_helper_applies_once_and_rejects_before_any_write() {
			$body = $this->method_body( 'apply_registry_batch' );

			$apply = strpos( $body, "ReportedIP_Hive_Settings_Apply::apply( \$values, 'admin', true )" );
			$error = strpos( $body, 'wp_send_json_error(' );

			$this->assertNotFalse( $apply, "the batch is applied atomically with origin 'admin'" );
			$this->assertNotFalse( $error, 'a rejected key terminates the request' );
			$this->assertSame( 1, substr_count( $body, 'Settings_Apply::apply(' ), 'validation and write are one apply() call, not two' );
			$this->assertStringContainsString( "'key'     => \$key", $body, 'the error names the rejected key' );
			$this->assertStringNotContainsString( 'Settings_Registry::', $body, 'the helper does not re-implement the registry pre-flight' );
			$this->assertStringNotContainsString( 'Option_Routing::set(', $body, 'the helper must not bypass the apply pipeline' );
		}

		public function test_every_retrofitted_key_is_a_remote_registry_key() {
			$remote = \ReportedIP_Hive_Settings_Registry::remote_spec();

			foreach ( self::RETROFIT_KEYS as $key ) {
				$this->assertArrayHasKey( $key, $remote, "$key must be in the remote registry" );
			}
		}

		public function test_disposable_action_rejects_values_outside_the_enum() {
			$this->assertInstanceOf(
				\WP_Error::class,
				\ReportedIP_Hive_Settings_Registry::sanitize( 'reportedip_hive_disposable_email_action', 'nuke' )
			);
			$this->assertSame(
				'block',
				\ReportedIP_Hive_Settings_Registry::sanitize( 'reportedip_hive_disposable_email_action', 'block' )
			);
		}

		public function test_relay_toggle_coerces_to_the_registry_bool_form() {
			$this->assertSame( 1, \ReportedIP_Hive_Settings_Registry::sanitize( 'reportedip_hive_block_email_relays', true ) );
			$this->assertSame( 0, \ReportedIP_Hive_Settings_Registry::sanitize( 'reportedip_hive_block_email_relays', false ) );
		}
	}
}
