<?php
/**
 * Unit tests for the central mailer + unified template.
 *
 * Verifies:
 *   - send() routes through the configured provider.
 *   - The HTML body contains the brand chrome and every populated slot.
 *   - The plain-text alternative includes greeting, intro, main block, and footer.
 *   - The reportedip_hive_mail_provider filter swaps the provider.
 *   - Default headers (Content-Type, From) are applied when missing.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.1.0
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;
use ReportedIP_Hive_Mail_Provider_Interface;
use ReportedIP_Hive_Mailer;

require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-defaults.php';
require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/interface-mail-provider.php';
require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/mail-providers/class-mail-provider-wordpress.php';
require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-mailer.php';

/**
 * In-memory provider that captures the last send() call.
 */
class CapturingMailProvider implements ReportedIP_Hive_Mail_Provider_Interface {

	public $captured = array();

	public function send( $to, $subject, $html_body, $plain_body, $headers ) {
		$this->captured = compact( 'to', 'subject', 'html_body', 'plain_body', 'headers' );
		return true;
	}

	public function get_name() {
		return 'capturing';
	}
}

class MailerTemplateTest extends TestCase {

	/**
	 * Reset filter/provider state between tests.
	 */
	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_filters']            = array();
		$GLOBALS['wp_actions']            = array();
		$GLOBALS['wp_options']            = array();
		$GLOBALS['rip_test_wp_mail_calls'] = array();
		ReportedIP_Hive_Mailer::get_instance()->reset_provider_cache();
	}

	private function install_capturing_provider(): CapturingMailProvider {
		$provider = new CapturingMailProvider();
		add_filter(
			'reportedip_hive_mail_provider',
			static function () use ( $provider ) {
				return $provider;
			}
		);
		ReportedIP_Hive_Mailer::get_instance()->reset_provider_cache();
		return $provider;
	}

	public function test_send_routes_through_filtered_provider() {
		$provider = $this->install_capturing_provider();

		$result = ReportedIP_Hive_Mailer::get_instance()->send(
			array(
				'to'         => 'user@example.org',
				'subject'    => '[Example Site] Hello',
				'intro_text' => 'Hi there.',
			)
		);

		$this->assertTrue( $result, 'Send should report success when the provider returns true.' );
		$this->assertSame( 'user@example.org', $provider->captured['to'] );
		$this->assertSame( '[Example Site] Hello', $provider->captured['subject'] );
		$this->assertSame( array(), $GLOBALS['rip_test_wp_mail_calls'], 'wp_mail must NOT be called when a custom provider takes over.' );
	}

	public function test_html_body_contains_brand_chrome_and_slots() {
		$provider = $this->install_capturing_provider();

		ReportedIP_Hive_Mailer::get_instance()->send(
			array(
				'to'              => 'user@example.org',
				'subject'         => '[Example Site] Verify',
				'greeting'        => 'Hello Patrick,',
				'intro_text'      => 'A verification code is required.',
				'main_block_html' => '<div class="code-box">123456</div>',
				'security_notice' => array(
					'ip'        => '203.0.113.7',
					'timestamp' => '2026-04-26 10:00',
				),
				'disclaimer'      => 'Never share this code.',
			)
		);

		$html = $provider->captured['html_body'];

		$this->assertStringContainsString( 'linear-gradient(135deg,#4F46E5,#7C3AED)', $html, 'Header gradient must use brand indigo.' );
		$this->assertStringContainsString( 'Example Site', $html, 'Site name must appear in header + footer.' );
		$this->assertStringContainsString( 'Protected by ReportedIP Hive', $html, 'Footer trust line must appear.' );
		$this->assertStringContainsString( 'https://reportedip.de/', $html, 'Footer must link to the ReportedIP brand site.' );

		$this->assertStringContainsString( 'Hello Patrick,', $html );
		$this->assertStringContainsString( 'A verification code is required.', $html );
		$this->assertStringContainsString( '123456', $html, 'Main block HTML must be rendered.' );
		$this->assertStringContainsString( '203.0.113.7', $html, 'Security notice IP must appear.' );
		$this->assertStringContainsString( 'Never share this code.', $html );
	}

	public function test_plain_body_mirrors_source_strings() {
		$provider = $this->install_capturing_provider();

		ReportedIP_Hive_Mailer::get_instance()->send(
			array(
				'to'              => 'user@example.org',
				'subject'         => '[Example Site] Hi',
				'greeting'        => 'Hello Patrick,',
				'intro_text'      => 'A verification code is required.',
				'main_block_html' => '<div>123456</div>',
				'main_block_text' => 'Code: 123456',
				'disclaimer'      => 'Never share this code.',
			)
		);

		$plain = $provider->captured['plain_body'];

		$this->assertStringContainsString( 'Hello Patrick,', $plain );
		$this->assertStringContainsString( 'A verification code is required.', $plain );
		$this->assertStringContainsString( 'Code: 123456', $plain, 'main_block_text should win over the HTML version.' );
		$this->assertStringContainsString( 'Never share this code.', $plain );
		$this->assertStringContainsString( 'Protected by ReportedIP Hive', $plain, 'Footer line must be present.' );
		$this->assertStringContainsString( 'https://reportedip.de/', $plain, 'Plaintext footer must include the brand link.' );
	}

	public function test_headers_get_default_content_type_and_from() {
		global $wp_options;
		$wp_options['admin_email'] = 'admin@example.org';

		$provider = $this->install_capturing_provider();

		ReportedIP_Hive_Mailer::get_instance()->send(
			array(
				'to'         => 'user@example.org',
				'subject'    => '[Example Site] Hi',
				'intro_text' => 'Hello.',
			)
		);

		$headers = $provider->captured['headers'];

		$has_content_type = false;
		$has_from         = false;
		foreach ( $headers as $h ) {
			if ( stripos( $h, 'content-type:' ) === 0 ) {
				$has_content_type = true;
			}
			if ( stripos( $h, 'from:' ) === 0 ) {
				$has_from = true;
				$this->assertStringContainsString( 'admin@example.org', $h );
			}
		}
		$this->assertTrue( $has_content_type, 'Content-Type header must default to text/html.' );
		$this->assertTrue( $has_from, 'From header must default to site name + admin_email.' );
	}

	public function test_send_returns_false_without_recipient() {
		$this->install_capturing_provider();

		$result = ReportedIP_Hive_Mailer::get_instance()->send(
			array(
				'subject'    => '[Example Site] Hi',
				'intro_text' => 'Hello.',
			)
		);

		$this->assertFalse( $result, 'Empty recipient must short-circuit to false.' );
	}

	public function test_template_path_filter_overrides_template() {
		$provider = $this->install_capturing_provider();

		$override = sys_get_temp_dir() . '/rip-mailer-override-' . uniqid() . '.php';
		file_put_contents( $override, '<?php echo "OVERRIDE_TEMPLATE_MARKER";' );

		add_filter(
			'reportedip_hive_mail_template_path',
			static function () use ( $override ) {
				return $override;
			}
		);

		ReportedIP_Hive_Mailer::get_instance()->send(
			array(
				'to'         => 'user@example.org',
				'subject'    => '[Example Site] Hi',
				'intro_text' => 'Hello.',
			)
		);

		unlink( $override );

		$this->assertSame( 'OVERRIDE_TEMPLATE_MARKER', $provider->captured['html_body'] );
	}
}
