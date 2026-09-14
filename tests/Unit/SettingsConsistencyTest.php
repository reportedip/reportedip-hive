<?php
/**
 * Cross-writer consistency tests for the settings standard.
 *
 * Guards the invariant behind the remote-settings protocol: every writer.
 * settings page, quickstart, import, MainWP, cloud, produces the identical
 * stored state for the identical input, because they all validate through
 * the registry. The static cross-repo twin of this test is the workspace
 * script `scripts/settings-consistency-check.php` (not shipped).
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.48
 */

declare(strict_types=1);

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-apply.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-hide-login.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-security-headers.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-frontend.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-proxy-trust.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-registration-guard.php';

	if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
		/**
		 * Minimal Mode-Manager double: gated features unavailable.
		 */
		class ReportedIP_Hive_Mode_Manager {
			/**
			 * Singleton accessor.
			 *
			 * @return self
			 */
			public static function get_instance() {
				return new self();
			}

			/**
			 * Feature availability lookup.
			 *
			 * @param string $feature Feature slug.
			 * @return array<string, mixed>
			 */
			public function feature_status( $feature ) {
				unset( $feature );
				return array(
					'available' => false,
					'min_tier'  => 'Professional',
				);
			}
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Origin parity and schema completeness.
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class SettingsConsistencyTest extends TestCase {

		/**
		 * Kinds vocabulary of protocol schema v1 (docs/remote-settings-protocol.md).
		 *
		 * @var string[]
		 */
		private const PROTOCOL_KINDS = array( 'bool', 'int', 'enum', 'text', 'textarea', 'email', 'email_list', 'url', 'csv_int_list', 'slug', 'json_list' );

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options'] = array();
		}

		/**
		 * One representative value per kind, valid for the first remote key
		 * of that kind found in the registry.
		 *
		 * @return array<string, mixed> key => sample value.
		 */
		private function sample_values() {
			$spec    = \ReportedIP_Hive_Settings_Registry::remote_spec();
			$samples = array();
			$seen    = array();
			foreach ( $spec as $key => $entry ) {
				$kind = (string) $entry['kind'];
				if ( isset( $seen[ $kind ] ) || ! empty( $entry['tier'] ) || ! empty( $entry['sanitize'] ) ) {
					continue;
				}
				switch ( $kind ) {
					case 'bool':
						$samples[ $key ] = '1';
						break;
					case 'int':
						$samples[ $key ] = isset( $entry['min'] ) ? (string) $entry['min'] : '1';
						break;
					case 'enum':
						$samples[ $key ] = (string) $entry['allowed'][0];
						break;
					case 'email':
						$samples[ $key ] = 'parity@example.com';
						break;
					case 'email_list':
						$samples[ $key ] = 'a@example.com, b@example.com';
						break;
					case 'url':
						$samples[ $key ] = 'https://example.com/contact/';
						break;
					case 'csv_int_list':
						$samples[ $key ] = isset( $entry['min'] ) ? (string) $entry['min'] : '5';
						break;
					case 'json_list':
						continue 2;
					default:
						$samples[ $key ] = 'parity-sample';
						break;
				}
				$seen[ $kind ] = true;
			}
			return $samples;
		}

		public function test_apply_result_is_identical_for_every_origin() {
			$values    = $this->sample_values();
			$this->assertNotEmpty( $values );
			$snapshots = array();

			foreach ( array( 'mainwp', 'cloud', 'import' ) as $origin ) {
				$GLOBALS['wp_options'] = array();
				$result                = \ReportedIP_Hive_Settings_Apply::apply( $values, $origin );

				$stored = array();
				foreach ( array_keys( $values ) as $key ) {
					$stored[ $key ] = \ReportedIP_Hive_Option_Routing::get( $key );
				}
				$snapshots[ $origin ] = array(
					'results' => $result['results'],
					'applied' => $result['applied'],
					'failed'  => $result['failed'],
					'hash'    => $result['hash'],
					'stored'  => $stored,
				);
			}

			$this->assertSame( $snapshots['mainwp'], $snapshots['cloud'], 'MainWP and cloud origins must produce identical state.' );
			$this->assertSame( $snapshots['mainwp'], $snapshots['import'], 'MainWP and import origins must produce identical state.' );
			$this->assertSame( 0, $snapshots['mainwp']['failed'] );
		}

		public function test_exported_schema_is_renderable_by_dashboards() {
			$schema = \ReportedIP_Hive_Settings_Registry::export_schema();

			$this->assertNotEmpty( $schema['sections'] );
			$this->assertNotEmpty( $schema['fields'] );

			foreach ( $schema['fields'] as $key => $field ) {
				$this->assertContains( $field['kind'], self::PROTOCOL_KINDS, "Field $key uses a kind outside the protocol vocabulary." );
				$this->assertArrayHasKey( 'default', $field, "Field $key exports no default, dashboards cannot prefill it." );
				$this->assertArrayHasKey( 'label', $field );
				if ( 'enum' === $field['kind'] ) {
					$this->assertNotEmpty( $field['allowed'], "Enum field $key exports no allowed values." );
				}
			}

			foreach ( $schema['sections'] as $section ) {
				foreach ( $section['keys'] as $key ) {
					$this->assertArrayHasKey( $key, $schema['fields'], "Section {$section['id']} references unknown field $key." );
				}
			}
		}

		public function test_every_remote_default_round_trips_unchanged_through_apply() {
			$defaults = \ReportedIP_Hive_Defaults::all_option_defaults();
			$spec     = \ReportedIP_Hive_Settings_Registry::remote_spec();
			$batch    = array();
			foreach ( $spec as $key => $entry ) {
				if ( ! empty( $entry['tier'] ) || ! array_key_exists( $key, $defaults ) ) {
					continue;
				}
				$batch[ $key ] = $defaults[ $key ];
			}

			$result = \ReportedIP_Hive_Settings_Apply::apply( $batch, 'test' );

			$not_unchanged = array();
			foreach ( $result['results'] as $key => $row ) {
				if ( 'unchanged' !== $row['status'] ) {
					$not_unchanged[ $key ] = $row['status'];
				}
			}
			$this->assertSame( array(), $not_unchanged, 'Pushing the canonical defaults must be a no-op for every writer.' );
		}
	}
}
