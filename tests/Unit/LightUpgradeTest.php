<?php
/**
 * Unit tests for the update from ReportedIP Hive Light 1.3.x.
 *
 * Light shipped on the same wordpress.org slug. It stored its schema
 * version as `1.2.0`, permanent whitelist entries as the zero date, no
 * `ip_type`, a NOT NULL `attempts.window_start` and two proxy headers the
 * free plugin did not know. These tests pin what the update does with each.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * Covers v6 and v24 of the migration manager for a Light install.
 */
class LightUpgradeTest extends TestCase {

	/**
	 * Previous `$wpdb`.
	 *
	 * @var mixed
	 */
	private $saved_wpdb;

	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_options'] = array();
		$this->saved_wpdb      = $GLOBALS['wpdb'] ?? null;
		$GLOBALS['wpdb']       = new class() {
			public $prefix      = 'wp_';
			public $base_prefix = 'wp_';
			public $columns     = array( 'expires_at', 'ip_type', 'window_start' );
			public $queries     = array();
			public function prepare( $sql, ...$args ) {
				foreach ( $args as $arg ) {
					$sql = (string) preg_replace( '/%[sd]/', "'" . $arg . "'", (string) $sql, 1 );
				}
				return $sql;
			}
			public function get_var( $sql = null ) {
				foreach ( $this->columns as $column ) {
					if ( false !== strpos( (string) $sql, "'" . $column . "'" ) ) {
						return 1;
					}
				}
				return 0;
			}
			public function query( $sql ) {
				$this->queries[] = (string) $sql;
				return 1;
			}
		};
	}

	protected function tear_down() {
		$GLOBALS['wpdb'] = $this->saved_wpdb;
		$this->set_from_light( false );
		parent::tear_down();
	}

	/**
	 * Invoke a private migration step.
	 *
	 * @param int $version Step number.
	 * @return void
	 */
	private function run_step( int $version ): void {
		$method = new \ReflectionMethod( \ReportedIP_Hive_Migration_Manager::class, 'migrate_to_v' . $version );
		$method->invoke( null );
	}

	/**
	 * Set the "started from Light" flag maybe_run() derives.
	 *
	 * @param bool $value Flag.
	 * @return void
	 */
	private function set_from_light( bool $value ): void {
		$prop = new \ReflectionProperty( \ReportedIP_Hive_Migration_Manager::class, 'from_light' );
		$prop->setValue( null, $value );
	}

	public function test_current_version_covers_the_light_step() {
		$this->assertGreaterThanOrEqual( 24, \ReportedIP_Hive_Migration_Manager::CURRENT_VERSION );
	}

	public function test_light_version_strings_are_recognised() {
		$this->assertTrue( \ReportedIP_Hive_Migration_Manager::is_light_version( '1.2.0' ) );
		$this->assertTrue( \ReportedIP_Hive_Migration_Manager::is_light_version( '1.1' ) );
		$this->assertFalse( \ReportedIP_Hive_Migration_Manager::is_light_version( 16 ) );
		$this->assertFalse( \ReportedIP_Hive_Migration_Manager::is_light_version( '16' ) );
		$this->assertFalse( \ReportedIP_Hive_Migration_Manager::is_light_version( 0 ) );
	}

	public function test_v6_turns_the_light_default_into_the_free_default() {
		$this->set_from_light( true );
		update_option( 'reportedip_hive_max_api_calls_per_hour', 100 );

		$this->run_step( 6 );

		$this->assertSame( 0, (int) get_option( 'reportedip_hive_max_api_calls_per_hour' ), 'Kept as 100, the untouched Light default would cap every paid plan.' );
	}

	public function test_v6_keeps_a_value_a_light_site_chose() {
		$this->set_from_light( true );
		update_option( 'reportedip_hive_max_api_calls_per_hour', 40 );

		$this->run_step( 6 );

		$this->assertSame( 40, (int) get_option( 'reportedip_hive_max_api_calls_per_hour' ) );
	}

	public function test_v6_still_resets_a_2x_install() {
		update_option( 'reportedip_hive_max_api_calls_per_hour', 40 );

		$this->run_step( 6 );

		$this->assertSame( 0, (int) get_option( 'reportedip_hive_max_api_calls_per_hour' ) );
	}

	public function test_v24_makes_light_whitelist_rows_effective() {
		$this->run_step( 24 );

		$sql = implode( "\n", $GLOBALS['wpdb']->queries );
		$this->assertStringContainsString( "SET expires_at = NULL WHERE expires_at = '0000-00-00 00:00:00'", $sql );
		$this->assertStringContainsString( "SET ip_type = 'cidr' WHERE ip_address LIKE '%/%'", $sql );
		$this->assertStringContainsString( "SET ip_type = 'ipv6'", $sql );
		$this->assertStringContainsString( 'MODIFY window_start datetime NULL DEFAULT NULL', $sql );
	}

	public function test_v24_leaves_a_table_without_light_columns_alone() {
		$GLOBALS['wpdb']->columns = array( 'expires_at', 'ip_type' );

		$this->run_step( 24 );

		$this->assertStringNotContainsString( 'window_start', implode( "\n", $GLOBALS['wpdb']->queries ) );
	}

	public function test_zero_date_never_counts_as_expired() {
		$this->assertStringContainsString( "expires_at = '0000-00-00 00:00:00'", \ReportedIP_Hive_Database::WHITELIST_UNEXPIRED );
		$this->assertStringContainsString( "expires_at <> '0000-00-00 00:00:00'", \ReportedIP_Hive_Database::WHITELIST_EXPIRED );
	}

	public function test_every_whitelist_expiry_check_uses_the_shared_condition() {
		$root = dirname( __DIR__, 2 );
		foreach ( array_merge( glob( $root . '/includes/*.php' ), glob( $root . '/admin/*.php' ) ) as $file ) {
			$src = (string) file_get_contents( $file );
			$this->assertDoesNotMatchRegularExpression(
				'/expires_at\s*(>|<|<=|>=)\s*NOW\(\)/',
				str_replace( array( \ReportedIP_Hive_Database::WHITELIST_UNEXPIRED, \ReportedIP_Hive_Database::WHITELIST_EXPIRED ), '', $src ),
				basename( $file ) . ' compares expires_at itself; a Light zero date would read as expired there.'
			);
		}
	}

	public function test_light_proxy_headers_survive_a_save() {
		foreach ( array( 'HTTP_TRUE_CLIENT_IP', 'HTTP_X_CLUSTER_CLIENT_IP' ) as $header ) {
			$this->assertSame( $header, \ReportedIP_Hive_Proxy_Trust::sanitize_header( $header ) );
		}
		$spec = \ReportedIP_Hive_Settings_Registry::spec();
		$this->assertSame( \ReportedIP_Hive_Proxy_Trust::ALLOWED_HEADERS, $spec['reportedip_hive_trusted_ip_header']['allowed'] );
	}
}
