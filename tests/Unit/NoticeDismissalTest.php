<?php
/**
 * Notice dismissal: a closed id list and one meta row per notice, whose
 * timestamp decides when an expiring notice may return.
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

if ( ! defined( 'REPORTEDIP_HIVE_SITE_URL' ) ) {
	define( 'REPORTEDIP_HIVE_SITE_URL', 'https://reportedip.com' );
}
require_once dirname( __DIR__, 2 ) . '/includes/class-mode-manager.php';
require_once dirname( __DIR__, 2 ) . '/includes/class-catalog.php';
require_once dirname( __DIR__, 2 ) . '/includes/class-addon-notice.php';
require_once dirname( __DIR__, 2 ) . '/includes/class-admin-notice.php';

/**
 * @covers \ReportedIP_Hive_Admin_Notice
 */
class NoticeDismissalTest extends TestCase {

	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_user_meta']       = array();
		$GLOBALS['wp_current_user_id'] = 7;
	}

	public function test_only_listed_ids_are_accepted(): void {
		foreach ( array( 'rate_limited', 'twofa_recommend', 'no_api_key', 'domain_limit', 'queue_warning', 'readiness', 'reportedip_hive_addon_available_business' ) as $id ) {
			$this->assertTrue( \ReportedIP_Hive_Admin_Notice::is_dismissible_id( $id ), $id );
		}
		foreach ( array( '', 'anything', 'rate_limited_2026-10-15-01', 'twofa_recommend_x', 'queue_critical', 'reputation_listed_' . md5( '203.0.113.9' ) ) as $id ) {
			$this->assertFalse( \ReportedIP_Hive_Admin_Notice::is_dismissible_id( $id ), $id );
		}
	}

	public function test_the_reputation_id_follows_the_stored_listing(): void {
		$this->set_mocked_option(
			'reportedip_hive_reputation',
			array(
				'listed'  => true,
				'address' => '203.0.113.9',
			)
		);
		$this->assertTrue( \ReportedIP_Hive_Admin_Notice::is_dismissible_id( \ReportedIP_Hive_Admin_Notice::reputation_notice_id( '203.0.113.9' ) ) );
		$this->assertFalse( \ReportedIP_Hive_Admin_Notice::is_dismissible_id( \ReportedIP_Hive_Admin_Notice::reputation_notice_id( '203.0.113.10' ) ) );
	}

	public function test_an_add_on_lists_its_own_ids(): void {
		$filters_before = $GLOBALS['wp_filters'] ?? array();
		try {
			add_filter(
				'reportedip_hive_dismissible_notice_ids',
				static function ( $ids ) {
					$ids[] = 'group_tier';
					return $ids;
				}
			);
			$this->assertTrue( \ReportedIP_Hive_Admin_Notice::is_dismissible_id( 'group_tier' ) );
		} finally {
			$GLOBALS['wp_filters'] = $filters_before;
		}
		$this->assertFalse( \ReportedIP_Hive_Admin_Notice::is_dismissible_id( 'group_tier' ) );
	}

	public function test_an_expiring_dismissal_holds_for_its_ttl_only(): void {
		$now = 1760000000;
		$GLOBALS['wp_user_meta'][7]['reportedip_dismissed_rate_limited']    = $now - 3599;
		$GLOBALS['wp_user_meta'][7]['reportedip_dismissed_twofa_recommend'] = $now - 86400;
		$GLOBALS['wp_user_meta'][7]['reportedip_dismissed_no_api_key']      = $now - 86399;

		$this->assertTrue( \ReportedIP_Hive_Admin_Notice::is_dismissed( 'rate_limited', 0, $now ) );
		$this->assertFalse( \ReportedIP_Hive_Admin_Notice::is_dismissed( 'rate_limited', 0, $now + 1 ) );
		$this->assertFalse( \ReportedIP_Hive_Admin_Notice::is_dismissed( 'twofa_recommend', 0, $now ) );
		$this->assertTrue( \ReportedIP_Hive_Admin_Notice::is_dismissed( 'no_api_key', 7, $now ) );
		$this->assertFalse( \ReportedIP_Hive_Admin_Notice::is_dismissed( 'domain_limit', 0, $now ), 'Never clicked.' );
	}

	public function test_a_dismissal_without_ttl_holds_until_the_id_changes(): void {
		$GLOBALS['wp_user_meta'][7]['reportedip_dismissed_reportedip_hive_addon_available_business'] = 1;
		$this->assertTrue( \ReportedIP_Hive_Admin_Notice::is_dismissed( 'reportedip_hive_addon_available_business', 0, 1760000000 ) );
		$this->assertFalse( \ReportedIP_Hive_Admin_Notice::is_dismissed( 'reportedip_hive_addon_available_enterprise', 0, 1760000000 ) );
	}

	/**
	 * No notice id carries a date any more, so a dismissal never adds a row
	 * per day or hour.
	 */
	public function test_no_notice_id_is_built_from_a_date(): void {
		$files = array_merge(
			glob( REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/*.php' ),
			glob( REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/*.php' ),
			array( REPORTEDIP_HIVE_PLUGIN_FILE )
		);
		foreach ( $files as $file ) {
			$source = (string) file_get_contents( $file );
			$this->assertDoesNotMatchRegularExpression( "/'data_notice_id'\s*=>[^,\n]*gmdate/", $source, basename( $file ) );
			$this->assertDoesNotMatchRegularExpression( "/reportedip_dismissed_[a-z_]*'\s*\.\s*gmdate/", $source, basename( $file ) );
		}
	}
}
