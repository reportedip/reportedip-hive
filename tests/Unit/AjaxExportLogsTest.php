<?php
/**
 * Regression tests for the log-export AJAX handler.
 *
 * Two export bugs are locked in place here:
 *
 *  1. The export buttons are GET links, so `format`/`days` must be read from
 *     `$_REQUEST` — the old `$_POST` read made the JSON button silently
 *     deliver CSV and ignored any custom day range.
 *  2. `Logger::get_logs()` JSON-decodes the `details` column into an array;
 *     handing that array straight to `fputcsv()` cast it to the literal
 *     string "Array" and lost the entire payload in every CSV export.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.7
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class AjaxExportLogsTest extends TestCase {

		public static function setUpBeforeClass(): void {
			parent::setUpBeforeClass();
			require_once dirname( __DIR__, 2 ) . '/includes/class-ajax-handler.php';
		}

		private function handler_file(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-ajax-handler.php' );
		}

		public function test_csv_row_encodes_decoded_details_as_json() {
			$log = (object) array(
				'created_at' => '2026-06-12 06:14:07',
				'event_type' => 'decoy_pathblock_hit',
				'ip_address' => '127.0.0.1',
				'severity'   => 'high',
				'details'    => array(
					'path'       => '/backup.sql',
					'user_agent' => 'python-requests/2.31.0',
				),
			);

			$row = \ReportedIP_Hive_Ajax_Handler::csv_export_row( $log );

			$this->assertSame( '2026-06-12 06:14:07', $row[0] );
			$this->assertSame( 'decoy_pathblock_hit', $row[1] );
			$this->assertSame( '127.0.0.1', $row[2] );
			$this->assertSame( 'high', $row[3] );
			$this->assertSame(
				array(
					'path'       => '/backup.sql',
					'user_agent' => 'python-requests/2.31.0',
				),
				json_decode( $row[4], true ),
				'Array details must round-trip through the CSV cell as JSON'
			);
		}

		public function test_csv_row_passes_string_details_through() {
			$log = (object) array(
				'created_at' => '2026-06-12 00:00:01',
				'event_type' => 'failed_login',
				'ip_address' => '203.0.113.7',
				'severity'   => 'medium',
				'details'    => 'plain text detail',
			);

			$row = \ReportedIP_Hive_Ajax_Handler::csv_export_row( $log );

			$this->assertSame( 'plain text detail', $row[4] );
		}

		public function test_csv_row_tolerates_missing_fields() {
			$row = \ReportedIP_Hive_Ajax_Handler::csv_export_row( (object) array() );

			$this->assertSame( array( '', '', '', '', '' ), $row );
		}

		public function test_export_params_are_read_from_request_not_post() {
			$src = $this->handler_file();

			$this->assertMatchesRegularExpression(
				'/function ajax_export_logs\(.*?\$_REQUEST\[\s*\'format\'\s*\].*?\$_REQUEST\[\s*\'days\'\s*\]/s',
				$src,
				'ajax_export_logs() must read format and days from $_REQUEST so the GET export links work'
			);
			$this->assertDoesNotMatchRegularExpression(
				'/function ajax_export_logs\(.*?\$_POST\[\s*\'format\'\s*\]/s',
				$src,
				'ajax_export_logs() must not read the format from $_POST only'
			);
		}
	}
}
