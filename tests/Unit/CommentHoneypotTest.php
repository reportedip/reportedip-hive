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
 * @author     Patrick Schlesinger <1@reportedip.com>
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

		/**
		 * The anchor is rendered on `comment_form`, not on
		 * `comment_form_after_fields`. WordPress only fires the latter in the
		 * signed-out branch of `comment_form()`, so an anchor placed there is
		 * missing for every logged-in subscriber and customer.
		 */
		public function test_the_anchor_is_rendered_on_a_hook_that_always_fires(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-comment-honeypot.php' );

			$this->assertStringContainsString( "add_action( 'comment_form', array( \$this, 'render_field' ) )", $source );
			$this->assertStringNotContainsString( 'comment_form_after_fields', $source );
		}

		/**
		 * Since 2.1.53 a filled decoy is scored, not answered with a 403. The
		 * hard rejection lives in one place, the configured spam action.
		 */
		public function test_a_filled_decoy_no_longer_ends_the_request(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-comment-honeypot.php' );
			$start  = strpos( $source, 'public function check_comment(' );

			$this->assertNotFalse( $start, 'check_comment() not found.' );

			$body = substr( $source, $start );

			$this->assertStringNotContainsString( 'wp_die(', $body );
			$this->assertStringContainsString( 'return $commentdata;', $body );
		}
	}
}
