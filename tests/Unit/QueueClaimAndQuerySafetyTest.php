<?php
/**
 * Guards for three database-layer correctness fixes from the 2.1.43 audit.
 *
 *  1. The API-queue search ran an already-prepared WHERE clause through
 *     `$wpdb->prepare()` a second time. The `%` of the LIKE pattern was then
 *     read as a placeholder, so searching for anything starting with s, d or
 *     f produced a placeholder/argument mismatch and an empty result.
 *  2. Claiming a queue row was not atomic: two workers could select the same
 *     pending rows and both send them, spending the API quota twice.
 *  3. `anonymize_old_data()` counted update attempts rather than successes.
 *     Since the loop re-selects rows that still lack the marker — written by
 *     that very update — a persistently failing write span the same batch
 *     until the time budget expired, every cron tick, anonymising nothing.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.44
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class QueueClaimAndQuerySafetyTest extends TestCase {

		/**
		 * Capture a method body from a source file.
		 *
		 * @param string $relative  Path relative to the plugin root.
		 * @param string $signature Method signature to start at.
		 * @param int    $length    Characters to capture.
		 * @return string
		 */
		private function method_body( string $relative, string $signature, int $length = 2200 ): string {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/' . $relative );
			$start  = strpos( $source, $signature );
			$this->assertNotFalse( $start, "$signature must exist in $relative" );

			return substr( $source, $start, $length );
		}

		public function test_queue_search_does_not_prepare_an_already_prepared_clause() {
			$body = $this->method_body( 'includes/class-database.php', 'public function get_api_queue_items(' );

			$select_pos = strpos( $body, 'SELECT * FROM $table_name' );
			$this->assertNotFalse( $select_pos, 'The listing query must exist' );

			$prefix = substr( $body, 0, $select_pos );
			$this->assertStringContainsString(
				"\$wpdb->prepare( 'LIMIT %d OFFSET %d'",
				$prefix,
				'LIMIT/OFFSET must be prepared on their own and concatenated'
			);

			$this->assertStringNotContainsString(
				'$sql = $wpdb->prepare(',
				$body,
				'Re-preparing the assembled clause makes a LIKE pattern look like a placeholder'
			);
		}

		public function test_queue_search_still_escapes_the_search_term() {
			$body = $this->method_body( 'includes/class-database.php', 'public function get_api_queue_items(' );

			$this->assertStringContainsString( 'esc_like(', $body );
			$this->assertStringContainsString( "\$wpdb->prepare( '(ip_address LIKE %s OR comment LIKE %s)'", $body );
		}

		public function test_orderby_allow_list_uses_a_strict_comparison() {
			$body = $this->method_body( 'includes/class-database.php', 'public function get_api_queue_items(' );

			$this->assertStringContainsString(
				'in_array( $args[\'orderby\'] ?? \'\', $allowed_orderby, true )',
				$body,
				'The value is interpolated into SQL, so the allow-list check must be strict'
			);
		}

		public function test_processing_claim_is_conditional_on_the_previous_status() {
			$body = $this->method_body( 'includes/class-database.php', 'public function update_api_report_status(' );

			$this->assertStringContainsString(
				"WHERE id = %d AND status IN ('pending', 'failed')",
				$body,
				'Without a status precondition two workers can both claim the same row'
			);
		}

		public function test_worker_skips_rows_it_failed_to_claim() {
			$body = $this->method_body( 'includes/class-api-client.php', 'foreach ( $pending_reports as $report ) {', 1200 );

			$this->assertStringContainsString( '$claimed = $database->update_api_report_status( $report->id, \'processing\' );', $body );

			$claim_pos  = strpos( $body, '$claimed' );
			$submit_pos = strpos( $body, 'mark_report_submitted' );
			$this->assertNotFalse( $submit_pos );
			$this->assertLessThan( $submit_pos, $claim_pos, 'The claim must be evaluated before the row is submitted' );
			$this->assertStringContainsString( 'continue;', substr( $body, $claim_pos, $submit_pos - $claim_pos ) );
		}

		public function test_anonymize_counts_successful_updates_only() {
			$body = $this->method_body( 'includes/class-database.php', 'public function anonymize_old_data(', 3000 );

			$this->assertStringContainsString( '$updated = $wpdb->update(', $body, 'The update result must be captured' );
			$this->assertStringContainsString( 'if ( false === $updated )', $body, 'A failed write must not count as progress' );
			$this->assertStringContainsString( '$updated_in_batch > 0', $body, 'The loop guard relies on the success count to terminate' );
		}
	}
}
