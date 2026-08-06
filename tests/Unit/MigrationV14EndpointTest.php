<?php
/**
 * Unit tests for the v14 API-endpoint domain migration.
 *
 * Locks down the reportedip.de → reportedip.com move: installs still carrying
 * the old default endpoint are rewritten to the new default, custom endpoints
 * survive untouched, and the migration is a no-op when the option is unset.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.37
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * Exercises `ReportedIP_Hive_Migration_Manager::migrate_to_v14()`.
 *
 * @since 2.1.37
 */
class MigrationV14EndpointTest extends TestCase {

	private const OPTION       = 'reportedip_hive_api_endpoint';
	private const OLD_DEFAULT  = 'https://reportedip.de/wp-json/reportedip/v2/';
	private const NEW_DEFAULT  = 'https://reportedip.com/wp-json/reportedip/v2/';

	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_options'] = array();
	}

	public function test_old_default_is_rewritten_to_new_domain() {
		\ReportedIP_Hive_Option_Routing::set( self::OPTION, self::OLD_DEFAULT );

		$this->run_v14();

		$this->assertSame( self::NEW_DEFAULT, \ReportedIP_Hive_Option_Routing::get( self::OPTION ) );
	}

	public function test_old_default_without_trailing_slash_is_rewritten() {
		\ReportedIP_Hive_Option_Routing::set( self::OPTION, rtrim( self::OLD_DEFAULT, '/' ) );

		$this->run_v14();

		$this->assertSame( self::NEW_DEFAULT, \ReportedIP_Hive_Option_Routing::get( self::OPTION ) );
	}

	public function test_custom_endpoint_is_left_untouched() {
		\ReportedIP_Hive_Option_Routing::set( self::OPTION, 'https://proxy.example.com/wp-json/reportedip/v2/' );

		$this->run_v14();

		$this->assertSame( 'https://proxy.example.com/wp-json/reportedip/v2/', \ReportedIP_Hive_Option_Routing::get( self::OPTION ) );
	}

	public function test_migration_is_noop_when_option_unset() {
		$this->run_v14();

		$this->assertSame( '__unset__', \ReportedIP_Hive_Option_Routing::get( self::OPTION, '__unset__' ) );
	}

	public function test_migration_is_idempotent() {
		\ReportedIP_Hive_Option_Routing::set( self::OPTION, self::OLD_DEFAULT );

		$this->run_v14();
		$this->run_v14();

		$this->assertSame( self::NEW_DEFAULT, \ReportedIP_Hive_Option_Routing::get( self::OPTION ) );
	}

	private function run_v14(): void {
		$method = new \ReflectionMethod( \ReportedIP_Hive_Migration_Manager::class, 'migrate_to_v14' );
		$method->invoke( null );
	}
}
