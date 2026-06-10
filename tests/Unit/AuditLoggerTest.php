<?php
/**
 * Unit tests for the audit-logger core.
 *
 * Locks the pure pieces that never touch the database: sensitive keys are
 * redacted (recursively), an unfamiliar IP is recognised, and the row builder
 * clamps fields to their column widths, drops an empty user to NULL and never
 * lets a secret reach the stored JSON.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.2.0
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-audit-logger.php';

	/**
	 * @covers \ReportedIP_Hive_Audit_Logger
	 */
	class AuditLoggerTest extends TestCase {

		public function test_redact_masks_sensitive_keys(): void {
			$out = \ReportedIP_Hive_Audit_Logger::redact(
				array(
					'changed_by' => 5,
					'password'   => 'hunter2',
					'new_role'   => 'administrator',
					'nested'     => array(
						'api_key' => 'abc',
						'role'    => 'editor',
					),
				)
			);
			$this->assertSame( 5, $out['changed_by'] );
			$this->assertSame( '[redacted]', $out['password'] );
			$this->assertSame( 'administrator', $out['new_role'] );
			$this->assertSame( '[redacted]', $out['nested']['api_key'] );
			$this->assertSame( 'editor', $out['nested']['role'] );
		}

		public function test_is_new_ip(): void {
			$this->assertFalse( \ReportedIP_Hive_Audit_Logger::is_new_ip( '', array() ) );
			$this->assertFalse( \ReportedIP_Hive_Audit_Logger::is_new_ip( '1.2.3.4', array( '1.2.3.4' ) ) );
			$this->assertTrue( \ReportedIP_Hive_Audit_Logger::is_new_ip( '5.6.7.8', array( '1.2.3.4' ) ) );
		}

		public function test_build_row_maps_and_clamps(): void {
			$row = \ReportedIP_Hive_Audit_Logger::build_row(
				array(
					'blog_id'      => 3,
					'created_at'   => '2026-06-10 12:00:00',
					'ip'           => '1.2.3.4',
					'user_id'      => 0,
					'username'     => str_repeat( 'a', 80 ),
					'event_type'   => 'login',
					'event_action' => 'success',
					'data'         => array(),
				)
			);
			$this->assertSame( 3, $row['blog_id'] );
			$this->assertNull( $row['user_id'] );
			$this->assertSame( 60, strlen( $row['username'] ) );
			$this->assertNull( $row['event_data'] );
			$this->assertSame( 'login', $row['event_type'] );
		}

		public function test_build_row_redacts_secret_in_json(): void {
			$row = \ReportedIP_Hive_Audit_Logger::build_row(
				array(
					'event_type'   => 'login',
					'event_action' => 'failed',
					'data'         => array( 'token' => 'super-secret-value' ),
				)
			);
			$this->assertIsString( $row['event_data'] );
			$this->assertStringNotContainsString( 'super-secret-value', $row['event_data'] );
			$this->assertStringContainsString( '[redacted]', $row['event_data'] );
		}

		public function test_build_row_keeps_populated_user(): void {
			$row = \ReportedIP_Hive_Audit_Logger::build_row(
				array(
					'user_id'      => 42,
					'event_type'   => 'profile_change',
					'event_action' => 'role_changed',
					'data'         => array( 'changed_by' => 7 ),
				)
			);
			$this->assertSame( 42, $row['user_id'] );
			$this->assertStringContainsString( 'changed_by', (string) $row['event_data'] );
		}
	}
}
