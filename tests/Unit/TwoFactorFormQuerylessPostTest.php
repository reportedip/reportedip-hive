<?php
/**
 * Source-pattern guards: the 2FA forms post to a bare wp-login.php.
 *
 * Host firewalls such as the ModSecurity rule set at Infomaniak answer a
 * POST to wp-login.php with a 403 as soon as the URL carries a query string
 * WordPress core does not know. The challenge then failed on the first
 * submit and locked the user out. The forms therefore send `action` as a
 * hidden field; wp-login.php reads it from $_REQUEST either way.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.11
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

class TwoFactorFormQuerylessPostTest extends TestCase {

	/**
	 * Read a plugin file relative to the plugin root.
	 *
	 * @param string $relative Relative path.
	 * @return string
	 */
	private function source( string $relative ): string {
		return (string) file_get_contents( dirname( __DIR__, 2 ) . '/' . $relative );
	}

	/**
	 * Every POST form of a wp-login.php challenge targets the bare login URL
	 * and carries the action as a hidden field.
	 *
	 * @return void
	 */
	public function test_challenge_forms_post_without_query_string(): void {
		$surfaces = array(
			'templates/two-factor-challenge.php'           => 'value="reportedip_2fa"',
			'includes/class-two-factor-reset-gate.php'     => 'value="<?php echo esc_attr( self::ACTION_CHALLENGE ); ?>"',
		);
		foreach ( $surfaces as $file => $hidden_value ) {
			$src = $this->source( $file );
			$this->assertSame( 1, preg_match( '/<form method="post" action="([^"]*)"/', $src, $m ), $file );
			$this->assertSame( '<?php echo esc_url( wp_login_url() ); ?>', $m[1], $file . ' must post to wp_login_url() without a query string.' );
			$this->assertStringContainsString( '<input type="hidden" name="action" ' . $hidden_value, $src, $file );
		}
	}

	/**
	 * The login error mask recognises the challenge action from the POST body.
	 *
	 * @return void
	 */
	public function test_error_mask_reads_action_from_request(): void {
		$src = $this->source( 'includes/class-user-enumeration.php' );
		$this->assertStringContainsString( "\$_REQUEST['action']", $src );
		$this->assertStringNotContainsString( "\$_GET['action']", $src );
	}
}
