<?php
/**
 * Unit tests for the v15 attempts-table uniqueness migration.
 *
 * Locks down `migrate_to_v15()`: when the `unique_ip_type` key is missing the
 * migration first deduplicates stale (ip_address, attempt_type) rows and only
 * then adds the UNIQUE key (the ALTER would fail on duplicates otherwise);
 * when the key already exists neither statement runs again; and the redundant
 * non-unique `composite_ip_type` index is dropped when present. Also pins
 * `CURRENT_VERSION` at 15 so the migration actually runs on upgrade.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.41
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * A `$wpdb` stub that records migration DDL/DML and answers the
 * `Schema::index_exists()` information_schema probes from a fixed map.
 *
 * `prepare()` interpolates the bound values so `get_var()` can see which
 * index name the probe asks about.
 *
 * @since 2.1.41
 */
class Migration_V15_WPDB_Stub {

	/**
	 * Table prefix.
	 *
	 * @var string
	 */
	public string $prefix = 'wp_';

	/**
	 * Network-wide table prefix used by Schema::table().
	 *
	 * @var string
	 */
	public string $base_prefix = 'wp_';

	/**
	 * Index names index_exists() reports as present.
	 *
	 * @var string[]
	 */
	public array $existing_indexes = array();

	/**
	 * Raw SQL passed to query(), in execution order.
	 *
	 * @var string[]
	 */
	public array $queries = array();

	/**
	 * Interpolate bound values into the placeholders.
	 *
	 * @param string $sql     SQL with %s/%d placeholders.
	 * @param mixed  ...$args Bound values.
	 * @return string
	 */
	public function prepare( $sql, ...$args ) {
		$sql = (string) $sql;
		foreach ( $args as $arg ) {
			$sql = (string) preg_replace( '/%[sd]/', "'" . $arg . "'", $sql, 1 );
		}
		return $sql;
	}

	/**
	 * Answer the index-existence probe from the configured map.
	 *
	 * @param string|null $sql Interpolated probe SQL.
	 * @return int 1 when the probed index is in the map, 0 otherwise.
	 */
	public function get_var( $sql = null ) {
		foreach ( $this->existing_indexes as $index ) {
			if ( false !== strpos( (string) $sql, "'" . $index . "'" ) ) {
				return 1;
			}
		}
		return 0;
	}

	/**
	 * Record a migration statement.
	 *
	 * @param string $sql Raw SQL.
	 * @return int
	 */
	public function query( $sql ) {
		$this->queries[] = (string) $sql;
		return 1;
	}
}

/**
 * Exercises `ReportedIP_Hive_Migration_Manager::migrate_to_v15()`.
 *
 * @since 2.1.41
 */
class MigrationV15Test extends TestCase {

	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_options'] = array();
		$GLOBALS['wpdb']       = new Migration_V15_WPDB_Stub();
	}

	protected function tear_down() {
		unset( $GLOBALS['wpdb'] );
		parent::tear_down();
	}

	private function run_v15(): void {
		$method = new \ReflectionMethod( \ReportedIP_Hive_Migration_Manager::class, 'migrate_to_v15' );
		$method->invoke( null );
	}

	/**
	 * The recorded migration statements.
	 *
	 * @return string[]
	 */
	private function queries(): array {
		return $GLOBALS['wpdb']->queries;
	}

	public function test_current_version_is_fifteen() {
		$this->assertSame( 15, \ReportedIP_Hive_Migration_Manager::CURRENT_VERSION );
	}

	public function test_missing_unique_index_dedupes_before_adding_the_unique_key() {
		$GLOBALS['wpdb']->existing_indexes = array();

		$this->run_v15();

		$queries = $this->queries();
		$this->assertCount( 2, $queries );
		$this->assertStringContainsString( 'DELETE stale FROM wp_reportedip_hive_attempts', $queries[0] );
		$this->assertStringContainsString( 'INNER JOIN wp_reportedip_hive_attempts AS fresh', $queries[0] );
		$this->assertStringContainsString(
			'ADD UNIQUE KEY unique_ip_type (ip_address, attempt_type)',
			$queries[1],
			'The dedupe DELETE must run before the ALTER — the ADD UNIQUE KEY fails on duplicate rows.'
		);
	}

	public function test_existing_unique_index_skips_dedupe_and_add() {
		$GLOBALS['wpdb']->existing_indexes = array( 'unique_ip_type' );

		$this->run_v15();

		$this->assertSame(
			array(),
			$this->queries(),
			'With unique_ip_type in place, neither the DELETE nor the ADD UNIQUE KEY may run again.'
		);
	}

	public function test_composite_index_is_dropped_when_present() {
		$GLOBALS['wpdb']->existing_indexes = array( 'unique_ip_type', 'composite_ip_type' );

		$this->run_v15();

		$queries = $this->queries();
		$this->assertCount( 1, $queries );
		$this->assertStringContainsString( 'ALTER TABLE wp_reportedip_hive_attempts DROP INDEX composite_ip_type', $queries[0] );
	}

	public function test_fresh_upgrade_runs_dedupe_add_and_drop_in_order() {
		$GLOBALS['wpdb']->existing_indexes = array( 'composite_ip_type' );

		$this->run_v15();

		$queries = $this->queries();
		$this->assertCount( 3, $queries );
		$this->assertStringContainsString( 'DELETE stale FROM', $queries[0] );
		$this->assertStringContainsString( 'ADD UNIQUE KEY unique_ip_type', $queries[1] );
		$this->assertStringContainsString( 'DROP INDEX composite_ip_type', $queries[2] );
	}
}
