<?php
/**
 * Every notice is dismissible and has an id (wordpress.org rule 11).
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
 * Notice contract.
 */
class NoticeContractTest extends TestCase {

	/**
	 * One-shot notices: the result of an action the operator just took,
	 * printed once in the response to it and never again. They close with
	 * the X, and a persistent dismissal would hide the next result. Keyed
	 * by a fragment of the call's arguments.
	 */
	private const ONE_SHOT = array(
		"\$error['message']" => 'The settings-API result of the save that rendered this page.',
		'has been reset. The user has been notified' => 'Confirms the 2FA reset the admin just triggered (query flag of the redirect).',
	);

	public function test_every_render_call_is_dismissible_with_an_id() {
		$files = array_merge(
			glob( REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/*.php' ),
			glob( REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/*.php' ),
			array( REPORTEDIP_HIVE_PLUGIN_FILE )
		);
		$seen = 0;
		foreach ( $files as $file ) {
			$source = (string) file_get_contents( $file );
			if ( ! preg_match_all( '/Admin_Notice::render\(\s+(.*?)\);/s', $source, $calls ) ) {
				continue;
			}
			foreach ( $calls[1] as $args ) {
				++$seen;
				if ( preg_match( "/'variant'\s*=>\s*'error'/", $args ) ) {
					continue;
				}
				$this->assertStringContainsString( "'dismissible'", $args, basename( $file ) );
				if ( $this->is_one_shot( $args ) ) {
					continue;
				}
				$this->assertStringContainsString( "'data_notice_id'", $args, basename( $file ) );
			}
		}
		$this->assertGreaterThan( 5, $seen, 'The sweep found no notices; the pattern no longer matches the calls.' );
	}

	/**
	 * Whether a call is one of the listed one-shot notices.
	 *
	 * @param string $args Source of the call's arguments.
	 * @return bool
	 */
	private function is_one_shot( $args ) {
		foreach ( array_keys( self::ONE_SHOT ) as $fragment ) {
			if ( false !== strpos( $args, $fragment ) ) {
				return true;
			}
		}
		return false;
	}

	public function test_no_notice_targets_the_wp_dashboard_with_upgrade_wording() {
		$source = (string) file_get_contents( REPORTEDIP_HIVE_PLUGIN_FILE );
		preg_match( '/\$show_on_screens\s*=\s*array\((.*?)\);/s', $source, $m );
		$this->assertStringNotContainsString( "'dashboard'", $m[1] ?? '' );
		$this->assertStringNotContainsString( 'Upgrade API tier', $source );
	}
}
