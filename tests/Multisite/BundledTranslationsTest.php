<?php
/**
 * The bundled catalog wins over an incomplete wordpress.org language pack.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.1
 */

/**
 * A language pack from translate.wordpress.org may carry only a handful of
 * strings. WordPress loads it instead of the bundled catalog, so the admin
 * turned English. The bundled catalog is now loaded first and the pack only
 * fills gaps.
 */
class ReportedIP_Hive_Bundled_Translations_Test extends WP_UnitTestCase {

	/**
	 * Pack file written by the test.
	 *
	 * @var string
	 */
	private $pack = '';

	/**
	 * Remove the pack and the loaded domain.
	 */
	public function tear_down() {
		unload_textdomain( 'reportedip-hive' );
		if ( '' !== $this->pack && file_exists( $this->pack ) ) {
			unlink( $this->pack );
		}
		parent::tear_down();
	}

	public function test_the_bundled_catalog_wins_and_the_pack_fills_gaps() {
		require_once ABSPATH . WPINC . '/pomo/mo.php';

		$dir = WP_LANG_DIR . '/plugins';
		wp_mkdir_p( $dir );
		$this->pack = $dir . '/reportedip-hive-de_DE.mo';

		$mo = new MO();
		$mo->add_entry( new Translation_Entry( array( 'singular' => 'Security Dashboard', 'translations' => array( 'PACK' ) ) ) );
		$mo->add_entry( new Translation_Entry( array( 'singular' => 'Only in the pack', 'translations' => array( 'Nur im Pack' ) ) ) );
		$this->assertTrue( $mo->export_to_file( $this->pack ) );

		unload_textdomain( 'reportedip-hive' );
		load_textdomain( 'reportedip-hive', $this->pack );

		$this->assertSame( 'Sicherheits-Dashboard', __( 'Security Dashboard', 'reportedip-hive' ), 'The bundled catalog must win over the pack.' );
		$this->assertSame( 'Einstellungen', __( 'Settings', 'reportedip-hive' ), 'A string missing in the pack comes from the bundled catalog.' );
		$this->assertSame( 'Nur im Pack', __( 'Only in the pack', 'reportedip-hive' ), 'The pack still fills gaps.' );
	}
}
