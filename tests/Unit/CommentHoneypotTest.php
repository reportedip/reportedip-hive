<?php
/**
 * Unit tests for the comment-honeypot sensor.
 *
 * Locks the trap logic (a filled decoy field springs, an empty/whitespace or
 * absent field does not) and confirms the rendered field is screen-reader
 * excluded.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.2
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-comment-honeypot.php';

	/**
	 * @covers \ReportedIP_Hive_Comment_Honeypot
	 */
	class CommentHoneypotTest extends TestCase {

		public function test_sprung_when_decoy_field_filled(): void {
			$this->assertTrue( \ReportedIP_Hive_Comment_Honeypot::is_sprung( array( 'reportedip_hive_hp' => 'http://spam' ) ) );
		}

		public function test_not_sprung_when_field_empty(): void {
			$this->assertFalse( \ReportedIP_Hive_Comment_Honeypot::is_sprung( array( 'reportedip_hive_hp' => '' ) ) );
		}

		public function test_not_sprung_when_field_whitespace(): void {
			$this->assertFalse( \ReportedIP_Hive_Comment_Honeypot::is_sprung( array( 'reportedip_hive_hp' => '   ' ) ) );
		}

		public function test_not_sprung_when_field_absent(): void {
			$this->assertFalse( \ReportedIP_Hive_Comment_Honeypot::is_sprung( array( 'comment' => 'hello' ) ) );
		}

		public function test_field_markup_is_accessibility_hidden(): void {
			$markup = \ReportedIP_Hive_Comment_Honeypot::get_instance()->field_markup();
			$this->assertStringContainsString( 'aria-hidden="true"', $markup );
			$this->assertStringContainsString( 'rip-hp-field', $markup );
			$this->assertStringContainsString( 'reportedip_hive_hp', $markup );
			$this->assertStringContainsString( 'tabindex="-1"', $markup );
		}
	}
}
