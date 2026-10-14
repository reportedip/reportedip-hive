<?php
/**
 * Every reader of the form adapter table reads the filtered table.
 *
 * An add-on registers its adapters through `reportedip_hive_form_adapters`
 * and names them through `reportedip_hive_form_adapter_names`. A reader that
 * falls back to the `ADAPTERS` constant would see Contact Form 7 alone and
 * leave the add-on's adapters out of the readiness register, the support
 * bundle, the Protection page, the quickstart and the self-test. Each case
 * registers a demo adapter whose plugin counts as detected and asserts that
 * the reader shows it.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-form-proof.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-form-adapters.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-readiness.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-support-bundle.php';
	require_once dirname( __DIR__, 2 ) . '/admin/class-protection-page.php';
	require_once dirname( __DIR__, 2 ) . '/admin/class-quickstart.php';
	require_once dirname( __DIR__, 2 ) . '/admin/class-tools-page.php';

	if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
		/**
		 * Mode-Manager double: every feature is available on the free plan.
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
					'available' => true,
					'min_tier'  => 'free',
				);
			}
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class FormAdapterConsumersTest extends TestCase {

		const OPTION = 'reportedip_hive_form_proof_demo';

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_filters']                 = array();
			$GLOBALS['wp_options']                 = array();
			$GLOBALS['wp_options'][ self::OPTION ] = 1;
			add_filter(
				'reportedip_hive_form_adapters',
				static function ( $adapters ) {
					$adapters['demo'] = array(
						'option'  => self::OPTION,
						'feature' => 'form_adapters',
						'detect'  => 'ReportedIP_Hive_Form_Adapters',
					);
					return $adapters;
				}
			);
			add_filter(
				'reportedip_hive_form_adapter_names',
				static function ( $names ) {
					$names['demo'] = 'Demo Forms';
					return $names;
				}
			);
			add_filter(
				'reportedip_hive_form_proof_adapter_options',
				static function ( $options ) {
					$options[] = self::OPTION;
					return $options;
				}
			);
		}

		protected function tear_down() {
			$GLOBALS['wp_filters'] = array();
			$GLOBALS['wp_options'] = array();
			parent::tear_down();
		}

		/**
		 * Call a private static method.
		 *
		 * @param string $class  Class name.
		 * @param string $method Method name.
		 * @param mixed  ...$args Arguments.
		 * @return mixed
		 */
		private function call( string $class, string $method, ...$args ) {
			return ( new \ReflectionMethod( $class, $method ) )->invoke( null, ...$args );
		}

		public function test_readiness_lists_and_links_the_registered_adapter(): void {
			$rows = $this->call( 'ReportedIP_Hive_Readiness', 'form_adapters' );

			$this->assertSame(
				array(
					'label'   => 'Demo Forms',
					'feature' => 'form_adapters',
					'option'  => self::OPTION,
				),
				$rows['demo'] ?? null
			);
			$this->assertSame( array( 'reportedip-hive-protection', 'forms' ), $this->call( 'ReportedIP_Hive_Readiness', 'links' )['form_adapter_demo'] ?? null );
		}

		public function test_support_bundle_reports_the_registered_adapter(): void {
			$proof = $this->call( 'ReportedIP_Hive_Support_Bundle', 'form_proof' );

			$this->assertContains( 'demo', $proof['detected'] );
			$this->assertContains( 'demo', $proof['active'] );
		}

		public function test_protection_page_detects_and_locks_the_registered_adapter(): void {
			$this->assertContains( 'demo', \ReportedIP_Hive_Protection_Page::detected_forms() );
			$this->assertSame(
				array(
					'detect' => 'ReportedIP_Hive_Form_Adapters',
					'name'   => 'Demo Forms',
				),
				$this->call( 'ReportedIP_Hive_Protection_Page', 'adapter_behind', self::OPTION )
			);
		}

		public function test_quickstart_names_the_registered_adapter(): void {
			$rows = $this->call( 'ReportedIP_Hive_Quickstart', 'form_plugin_rows', 'free' );

			$this->assertCount( 1, $rows );
			$this->assertStringContainsString( 'Demo Forms', $rows[0]['label'] );
		}

		public function test_selftest_state_carries_the_registered_adapter(): void {
			$state = \ReportedIP_Hive_Tools_Page::selftest_state();

			$this->assertSame(
				array(
					'name'     => 'Demo Forms',
					'detected' => true,
					'covered'  => true,
					'option'   => true,
				),
				$state['adapters']['demo'] ?? null
			);
		}
	}
}
