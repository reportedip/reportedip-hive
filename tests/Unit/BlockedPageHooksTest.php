<?php
/**
 * Source-inspection guards for the blocked-page extension points.
 *
 * The 403 response path terminates in `exit` and the main plugin file cannot
 * be loaded in the unit harness, so — following the IsPublicIpTest idiom —
 * these tests anchor the contracts in the source text:
 *
 *  1. `serve_blocked_page()` fires `reportedip_hive_access_denied` before the
 *     403 status and before the template renders, so a listener can observe
 *     (or decorate) every denied request.
 *  2. `templates/blocked.php` filters its visitor-facing strings through
 *     `reportedip_hive_blocked_page_strings` after the defaults are assembled
 *     and before rendering starts, key-clamped via array_intersect_key() so
 *     missing keys fall back to the defaults.
 *  3. The blocked-page contact URL is read through Option_Routing (network
 *     scope on Multisite), never a bare get_option().
 *  4. `ajax_block_ip()` validates through the CIDR-aware
 *     IP_Manager::validate_ip_address() instead of a plain filter_var() that
 *     rejected CIDR ranges the block path supports.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.41
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class BlockedPageHooksTest extends TestCase {

		/**
		 * Main plugin file source.
		 *
		 * @return string
		 */
		private function main_file(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );
		}

		/**
		 * Blocked-page template source.
		 *
		 * @return string
		 */
		private function template_file(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/templates/blocked.php' );
		}

		/**
		 * AJAX handler source.
		 *
		 * @return string
		 */
		private function ajax_file(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-ajax-handler.php' );
		}

		public function test_access_denied_hook_fires_before_the_403_response() {
			$source = $this->main_file();
			$start  = strpos( $source, 'function serve_blocked_page' );
			$this->assertNotFalse( $start, 'serve_blocked_page() must exist' );

			$end  = strpos( $source, 'public function get_logger', $start );
			$body = false !== $end ? substr( $source, $start, $end - $start ) : substr( $source, $start );

			$hook_pos    = strpos( $body, "do_action( 'reportedip_hive_access_denied'" );
			$status_pos  = strpos( $body, 'status_header( 403 )' );
			$include_pos = strpos( $body, 'templates/blocked.php' );

			$this->assertNotFalse( $hook_pos, 'serve_blocked_page() must fire the access-denied hook' );
			$this->assertNotFalse( $status_pos );
			$this->assertNotFalse( $include_pos );
			$this->assertLessThan( $status_pos, $hook_pos, 'The hook must fire before the 403 status is emitted' );
			$this->assertLessThan( $include_pos, $hook_pos, 'The hook must fire before the block template renders' );
		}

		public function test_blocked_page_strings_filter_runs_after_defaults_and_before_render() {
			$template = $this->template_file();

			$defaults_pos = strpos( $template, "\$reportedip_hive_block_strings = 'hide_login'" );
			$filter_pos   = strpos( $template, "apply_filters( 'reportedip_hive_blocked_page_strings'" );
			$ref_pos      = strpos( $template, 'block_ref_code' );

			$this->assertNotFalse( $defaults_pos, 'The template must assemble the default string set' );
			$this->assertNotFalse( $filter_pos, 'The template must expose the visitor-facing strings filter' );
			$this->assertNotFalse( $ref_pos );
			$this->assertLessThan( $filter_pos, $defaults_pos, 'The filter receives the defaults, so it must run after they are assembled' );
			$this->assertLessThan( $ref_pos, $filter_pos, 'The filter must run before the reference code and the markup are produced' );
		}

		public function test_blocked_page_strings_filter_falls_back_on_missing_keys() {
			$this->assertStringContainsString(
				'array_intersect_key',
				$this->template_file(),
				'Filtered strings must be key-clamped so a partial override falls back to the defaults for missing keys'
			);
		}

		public function test_blocked_page_contact_url_reads_through_option_routing() {
			$template = $this->template_file();

			$this->assertStringContainsString(
				"ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_blocked_page_contact_url'",
				$template,
				'The contact URL must be read through the option-routing service'
			);
			$this->assertStringNotContainsString(
				'get_option(',
				$template,
				'A bare get_option() would read the wrong scope on Multisite'
			);
		}

		public function test_ajax_block_ip_uses_the_central_ip_validator() {
			$source = $this->ajax_file();
			$start  = strpos( $source, 'function ajax_block_ip' );
			$this->assertNotFalse( $start, 'ajax_block_ip() must exist' );

			$end = strpos( $source, 'function ajax_add_whitelist', $start );
			$this->assertNotFalse( $end, 'ajax_add_whitelist() bounds the inspected method body' );
			$body = substr( $source, $start, $end - $start );

			$this->assertStringContainsString(
				'$this->ip_manager->validate_ip_address(',
				$body,
				'ajax_block_ip() must validate through the CIDR-aware central validator'
			);
			$this->assertStringNotContainsString(
				'filter_var( $ip_address, FILTER_VALIDATE_IP )',
				$body,
				'The plain filter_var() check rejected the CIDR ranges the block path supports'
			);
		}
	}
}
