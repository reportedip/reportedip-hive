<?php
/**
 * The bootstrap contract the add-on relies on, pinned at the source level.
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
 * Source assertions on reportedip-hive.php.
 */
class BootstrapContractTest extends TestCase {

	/**
	 * Main plugin file source.
	 *
	 * @return string
	 */
	private function source() {
		return (string) file_get_contents( REPORTEDIP_HIVE_PLUGIN_FILE );
	}

	public function test_loaded_action_is_fired_with_the_instance() {
		$this->assertMatchesRegularExpression( '/do_action\(\s*\'reportedip_hive_loaded\',\s*\$[a-z_]+\s*\)/', $this->source() );
	}

	public function test_instance_is_assigned_before_dependencies_load() {
		$source = $this->source();
		$assign = strpos( $source, 'self::$instance = $this;' );
		$load   = strpos( $source, '$this->load_dependencies();' );
		$this->assertNotFalse( $assign );
		$this->assertNotFalse( $load );
		$this->assertLessThan( $load, $assign );
	}

	public function test_api_version_constant_exists() {
		$this->assertMatchesRegularExpression( "/define\( 'REPORTEDIP_HIVE_API_VERSION', '[0-9]+' \)/", $this->source() );
	}

	public function test_uninstall_action_is_fired_before_the_tables_drop() {
		$source = $this->source();
		$action = strpos( $source, "do_action( 'reportedip_hive_uninstall', \$delete_requested )" );
		$drop   = strpos( $source, 'ReportedIP_Hive_Schema::drop_all_tables()' );
		$this->assertNotFalse( $action );
		$this->assertNotFalse( $drop );
		$this->assertLessThan( $drop, $action );
	}

	public function test_no_update_checker_or_update_uri() {
		$source = $this->source();
		$this->assertStringNotContainsString( 'PucFactory', $source );
		$this->assertStringNotContainsString( 'Update URI:', $source );
		$this->assertStringNotContainsString( 'force_auto_update', $source );
		$this->assertStringNotContainsString( 'vendor/autoload.php', $source );
	}

	public function test_composer_has_no_runtime_dependency() {
		$composer = json_decode( (string) file_get_contents( REPORTEDIP_HIVE_PLUGIN_DIR . 'composer.json' ), true );
		$this->assertSame( array( 'php' ), array_keys( $composer['require'] ) );
	}
}
