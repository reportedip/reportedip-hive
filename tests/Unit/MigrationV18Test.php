<?php
/**
 * Unit tests for the v18 comment spam counter migration.
 *
 * Locks down `migrate_to_v18()`: an install still carrying the old five
 * offences per hour is moved onto three per day, a value the operator picked
 * themselves survives, and `CURRENT_VERSION` is at 18 so the migration runs
 * on upgrade.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.63
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * Exercises `ReportedIP_Hive_Migration_Manager::migrate_to_v18()`.
 *
 * @since 2.1.63
 */
class MigrationV18Test extends TestCase {

	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_options'] = array();
	}

	private function run_v18(): void {
		$method = new \ReflectionMethod( \ReportedIP_Hive_Migration_Manager::class, 'migrate_to_v18' );
		$method->invoke( null );
	}

	public function test_current_version_is_at_least_eighteen() {
		$this->assertGreaterThanOrEqual( 18, \ReportedIP_Hive_Migration_Manager::CURRENT_VERSION );
	}

	public function test_the_old_default_is_moved_onto_the_new_one() {
		\ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_comment_spam_threshold', 5 );
		\ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_comment_spam_timeframe', 60 );

		$this->run_v18();

		$this->assertSame( 3, (int) \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_spam_threshold', null ) );
		$this->assertSame( 1440, (int) \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_spam_timeframe', null ) );
	}

	public function test_an_operator_value_stays_untouched() {
		\ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_comment_spam_threshold', 10 );
		\ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_comment_spam_timeframe', 15 );

		$this->run_v18();

		$this->assertSame( 10, (int) \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_spam_threshold', null ) );
		$this->assertSame( 15, (int) \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_spam_timeframe', null ) );
	}

	public function test_the_new_defaults_match_the_migration_target() {
		$canonical = \ReportedIP_Hive_Defaults::all_option_defaults();

		$this->assertSame( 3, $canonical['reportedip_hive_comment_spam_threshold'] );
		$this->assertSame( 1440, $canonical['reportedip_hive_comment_spam_timeframe'] );
	}
}
