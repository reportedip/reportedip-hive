<?php
/**
 * Unit tests for the settings drift fingerprint.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.47
 */

declare(strict_types=1);

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * The hash must be stable across value representations and blind to
	 * non-remote keys, otherwise every dashboard shows phantom drift.
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class SettingsHashTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options'] = array();
		}

		public function test_hash_is_prefixed_and_deterministic() {
			$first  = \ReportedIP_Hive_Settings_Registry::settings_hash();
			$second = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$this->assertStringStartsWith( 'sha256:', $first );
			$this->assertSame( $first, $second );
		}

		public function test_hash_is_stable_across_boolean_representations() {
			$GLOBALS['wp_options']['reportedip_hive_auto_block'] = true;
			$as_bool = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$GLOBALS['wp_options']['reportedip_hive_auto_block'] = 1;
			$as_int = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$GLOBALS['wp_options']['reportedip_hive_auto_block'] = '1';
			$as_string = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$this->assertSame( $as_bool, $as_int );
			$this->assertSame( $as_bool, $as_string );
		}

		public function test_hash_is_stable_across_integer_representations() {
			$GLOBALS['wp_options']['reportedip_hive_failed_login_threshold'] = 7;
			$as_int = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$GLOBALS['wp_options']['reportedip_hive_failed_login_threshold'] = '7';
			$as_string = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$this->assertSame( $as_int, $as_string );
		}

		public function test_hash_changes_when_a_remote_value_changes() {
			$before = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$GLOBALS['wp_options']['reportedip_hive_failed_login_threshold'] = 42;

			$this->assertNotSame( $before, \ReportedIP_Hive_Settings_Registry::settings_hash() );
		}

		public function test_hash_ignores_non_remote_options() {
			$before = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$GLOBALS['wp_options']['reportedip_hive_api_key']        = 'secret-key';
			$GLOBALS['wp_options']['reportedip_hive_operation_mode'] = 'community';

			$this->assertSame( $before, \ReportedIP_Hive_Settings_Registry::settings_hash() );
		}
	}
}
