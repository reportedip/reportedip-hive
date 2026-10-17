<?php
/**
 * Unit tests for the daily summary and the instant breach alerts.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.3
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;
use ReportedIP_Hive_Alerts;
use ReportedIP_Hive_Digest;
use ReportedIP_Hive_Event_Taxonomy;
use ReportedIP_Hive_Mailer;

require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-defaults.php';
require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-event-taxonomy.php';
require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/interface-mail-provider.php';
require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/mail-providers/class-mail-provider-wordpress.php';
require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-mailer.php';
require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-alerts.php';
require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-digest.php';

/**
 * In-memory provider that keeps the last mail.
 */
class DigestCapturingMailProvider implements \ReportedIP_Hive_Mail_Provider_Interface {

	public $captured = array();

	public function send( $to, $subject, $html_body, $plain_body, $headers ) {
		$this->captured = compact( 'to', 'subject', 'html_body', 'plain_body', 'headers' );
		return true;
	}

	public function get_name() {
		return 'digest-capturing';
	}
}

/**
 * Covers the mode switch, the summary maths and the alert gates.
 */
class NotificationDigestAlertsTest extends TestCase {

	/**
	 * Clean option, transient and filter state.
	 */
	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_filters'] = array();
		$GLOBALS['wp_actions'] = array();
		$GLOBALS['wp_options'] = array( 'admin_email' => 'admin@example.test' );
		ReportedIP_Hive_Mailer::get_instance()->reset_provider_cache();
	}

	/**
	 * Route mails into an array instead of wp_mail().
	 *
	 * @return DigestCapturingMailProvider
	 */
	private function capture() {
		$provider = new DigestCapturingMailProvider();
		add_filter(
			'reportedip_hive_mail_provider',
			static function () use ( $provider ) {
				return $provider;
			}
		);
		return $provider;
	}

	public function test_attack_mode_defaults_to_digest_and_rejects_junk() {
		$this->assertSame( 'digest', ReportedIP_Hive_Digest::attack_mode() );

		update_option( 'reportedip_hive_notify_attacks', 'instant' );
		$this->assertSame( 'instant', ReportedIP_Hive_Digest::attack_mode() );

		update_option( 'reportedip_hive_notify_attacks', 'loud' );
		$this->assertSame( 'digest', ReportedIP_Hive_Digest::attack_mode() );
	}

	public function test_build_counts_each_kind_once_and_skips_operational_rows() {
		$summary = ReportedIP_Hive_Digest::build(
			array(
				'failed_login'                    => 40,
				'failed_login_threshold_exceeded' => 4,
				'scan_404_threshold_exceeded'     => 7,
				'ip_blocked'                      => 5,
				'mail_sent'                       => 99,
			),
			array(
				array(
					'ip'   => '203.0.113.9',
					'hits' => 30,
				),
			)
		);

		$this->assertSame( 47, $summary['total'], 'failed_login takes the larger count, scan_404 only has the threshold row' );
		$this->assertSame( 5, $summary['blocks'] );
		$this->assertSame( 40, $summary['kinds'][ ReportedIP_Hive_Event_Taxonomy::label( 'failed_login' ) ] );
		$this->assertSame( 7, $summary['kinds'][ ReportedIP_Hive_Event_Taxonomy::label( 'scan_404' ) ] );
		$this->assertCount( 2, $summary['kinds'], 'mail_sent and ip_blocked are not attack kinds' );
		$this->assertSame( '203.0.113.9', $summary['top_ips'][0]['ip'] );
	}

	public function test_build_of_nothing_is_zero() {
		$summary = ReportedIP_Hive_Digest::build( array(), array() );
		$this->assertSame( 0, $summary['total'] );
		$this->assertSame( array(), $summary['kinds'] );
	}

	public function test_only_a_new_administrator_role_is_a_promotion() {
		$this->assertTrue( ReportedIP_Hive_Alerts::is_admin_promotion( 'administrator', array( 'subscriber' ) ) );
		$this->assertFalse( ReportedIP_Hive_Alerts::is_admin_promotion( 'administrator', array( 'administrator' ) ) );
		$this->assertFalse( ReportedIP_Hive_Alerts::is_admin_promotion( 'editor', array( 'subscriber' ) ) );
	}

	public function test_alert_respects_both_switches() {
		$provider = $this->capture();

		update_option( 'reportedip_hive_notify_alerts', false );
		$this->assertFalse( ReportedIP_Hive_Alerts::send( 'k1', 'Test', array() ) );

		update_option( 'reportedip_hive_notify_alerts', true );
		update_option( 'reportedip_hive_notify_admin', false );
		$this->assertFalse( ReportedIP_Hive_Alerts::send( 'k1', 'Test', array() ) );

		$this->assertSame( array(), $provider->captured );
	}

	public function test_alert_mails_once_per_key_with_alert_subject() {
		$provider = $this->capture();

		$this->assertTrue( ReportedIP_Hive_Alerts::send( 'k2', 'New administrator account', array( array( 'Account', 'eve' ) ) ) );
		$this->assertStringContainsString( 'Alert: New administrator account', $provider->captured['subject'] );
		$this->assertStringContainsString( 'eve', $provider->captured['plain_body'] );

		$this->assertFalse( ReportedIP_Hive_Alerts::send( 'k2', 'New administrator account', array() ), 'same key inside the dedupe window' );
		$this->assertTrue( ReportedIP_Hive_Alerts::send( 'k3', 'Other', array() ) );
	}
}
