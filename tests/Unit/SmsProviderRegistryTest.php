<?php
/**
 * Unit tests for the SMS provider registry and readiness gate.
 *
 * Locks down that SMS-2FA is delivered exclusively through the managed
 * reportedip.de relay: the registry exposes only the relay adapter, and
 * is_ready() is true only while the relay is available for the current tier.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.25
 */

namespace {

	if ( ! defined( 'ABSPATH' ) ) {
		define( 'ABSPATH', __DIR__ );
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-sms.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class SmsProviderRegistryTest extends TestCase {

		public function test_registry_exposes_only_the_relay() {
			$providers = \ReportedIP_Hive_Two_Factor_SMS::providers();

			$this->assertSame(
				array( 'reportedip_relay' => 'ReportedIP_Hive_SMS_Provider_Relay' ),
				$providers
			);
		}

		public function test_is_ready_false_without_mode_manager() {
			$this->assertFalse(
				class_exists( 'ReportedIP_Hive_Mode_Manager' ),
				'Mode_Manager must not be loaded in this isolated process.'
			);
			$this->assertFalse( \ReportedIP_Hive_Two_Factor_SMS::is_ready() );
		}
	}
}
