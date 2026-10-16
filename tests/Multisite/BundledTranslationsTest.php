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
	 * Fake Loco Translate catalog written by the test.
	 *
	 * @var string
	 */
	private $loco = '';

	/**
	 * Every file the Loco-like listener saw being loaded.
	 *
	 * @var string[]
	 */
	private $seen = array();

	/**
	 * Remove the pack and the loaded domain.
	 */
	public function tear_down() {
		unload_textdomain( 'reportedip-hive' );
		remove_all_actions( 'load_textdomain', 20 );
		foreach ( array( $this->pack, $this->loco ) as $file ) {
			if ( '' !== $file && file_exists( $file ) ) {
				unlink( $file );
			}
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

	/**
	 * Write a pack and a Loco catalog and hook a listener that, like Loco
	 * Translate, loads its own catalog for every file loaded outside its
	 * folder. It throws after 50 calls, so a recursion fails the test
	 * instead of exhausting the memory of the PHPUnit process.
	 */
	private function hook_loco_like_listener() {
		require_once ABSPATH . WPINC . '/pomo/mo.php';

		wp_mkdir_p( WP_LANG_DIR . '/plugins' );
		wp_mkdir_p( WP_LANG_DIR . '/loco/plugins' );
		$this->pack = WP_LANG_DIR . '/plugins/reportedip-hive-de_DE.mo';
		$this->loco = WP_LANG_DIR . '/loco/plugins/reportedip-hive-de_DE.mo';

		$mo = new MO();
		$mo->add_entry( new Translation_Entry( array( 'singular' => 'Only in the pack', 'translations' => array( 'Nur im Pack' ) ) ) );
		$this->assertTrue( $mo->export_to_file( $this->pack ) );
		$mo = new MO();
		$mo->add_entry( new Translation_Entry( array( 'singular' => 'Only in Loco', 'translations' => array( 'Nur in Loco' ) ) ) );
		$this->assertTrue( $mo->export_to_file( $this->loco ) );

		$loco_dir   = wp_normalize_path( WP_LANG_DIR . '/loco/' );
		$loco       = $this->loco;
		$this->seen = array();
		$seen       = &$this->seen;
		add_action(
			'load_textdomain',
			static function ( $domain, $mofile ) use ( $loco_dir, $loco, &$seen ) {
				if ( 'reportedip-hive' !== $domain ) {
					return;
				}
				$seen[] = wp_normalize_path( $mofile );
				if ( count( $seen ) > 50 ) {
					throw new RuntimeException( 'load_textdomain recursed.' );
				}
				if ( 0 !== strpos( wp_normalize_path( $mofile ), $loco_dir ) ) {
					load_textdomain( $domain, $loco );
				}
			},
			20,
			2
		);
	}

	/**
	 * Number of times the bundled de_DE catalog was loaded.
	 *
	 * @return int
	 */
	private function bundled_loads() {
		$bundled = trailingslashit( wp_normalize_path( REPORTEDIP_HIVE_LANGUAGES_DIR ) ) . 'reportedip-hive-de_DE.mo';
		return count( array_keys( $this->seen, $bundled, true ) );
	}

	public function test_a_plugin_that_loads_its_own_catalog_does_not_recurse() {
		$this->hook_loco_like_listener();

		unload_textdomain( 'reportedip-hive' );
		load_textdomain( 'reportedip-hive', $this->pack );

		$this->assertSame( 1, $this->bundled_loads(), 'The bundled catalog is loaded exactly once.' );
		$this->assertSame( 'Sicherheits-Dashboard', __( 'Security Dashboard', 'reportedip-hive' ), 'The bundled catalog still wins.' );
		$this->assertSame( 'Nur im Pack', __( 'Only in the pack', 'reportedip-hive' ), 'The pack still fills gaps.' );
		$this->assertSame( 'Nur in Loco', __( 'Only in Loco', 'reportedip-hive' ), 'The Loco catalog still fills gaps.' );
	}

	public function test_the_bundled_catalog_is_loaded_again_after_an_unload() {
		$this->hook_loco_like_listener();

		unload_textdomain( 'reportedip-hive' );
		load_textdomain( 'reportedip-hive', $this->pack );
		unload_textdomain( 'reportedip-hive' );
		load_textdomain( 'reportedip-hive', $this->pack );

		$this->assertSame( 2, $this->bundled_loads(), 'An unload, as in switch_to_locale(), allows the next load.' );
		$this->assertSame( 'Sicherheits-Dashboard', __( 'Security Dashboard', 'reportedip-hive' ) );
	}
}
