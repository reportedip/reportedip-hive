<?php
/**
 * Unit tests for the tier-change detection in ReportedIP_Hive_API::persist_api_status().
 *
 * Regression guard for the "plan is active" mail spam: the previous tier must
 * be read from the durable `reportedip_hive_known_tier` option, never from the
 * five-minute status transient. Repeated refreshes of an already-active paid
 * tier must not re-fire `reportedip_hive_tier_changed`; a genuine flip must
 * fire it exactly once.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.20
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

require_once dirname( __DIR__, 2 ) . '/includes/class-mode-manager.php';
require_once dirname( __DIR__, 2 ) . '/includes/class-api-client.php';

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class ApiTierChangeDedupTest extends TestCase {

	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_options']    = array();
		$GLOBALS['wp_transients'] = array();
		if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
			define( 'MINUTE_IN_SECONDS', 60 );
		}
	}

	/**
	 * Invoke the private persist_api_status() with a validated status payload,
	 * simulating a fresh API refresh (the status transient is cleared first,
	 * exactly the condition that used to collapse the previous tier to "free").
	 *
	 * @param string $role Upstream userRole returned by the key check.
	 * @return void
	 */
	private function refresh_with_role( $role ) {
		unset( $GLOBALS['wp_transients']['reportedip_hive_api_status'] );
		$api    = ( new \ReflectionClass( \ReportedIP_Hive_API::class ) )->newInstanceWithoutConstructor();
		$method = new \ReflectionMethod( $api, 'persist_api_status' );
		$method->invoke( $api, array( 'valid' => true, 'userRole' => $role ) );
	}

	public function test_repeated_refresh_of_same_paid_tier_does_not_refire() {
		$fired = 0;
		\add_action(
			'reportedip_hive_tier_changed',
			static function () use ( &$fired ) {
				++$fired;
			}
		);

		$this->refresh_with_role( 'reportedip_enterprise' );
		$this->refresh_with_role( 'reportedip_enterprise' );
		$this->refresh_with_role( 'reportedip_enterprise' );

		$this->assertSame( 0, $fired, 'An already-active tier must never re-fire the change action on refresh.' );
		$this->assertSame( 'enterprise', $GLOBALS['wp_options']['reportedip_hive_known_tier'] ?? null );
	}

	public function test_genuine_upgrade_fires_exactly_once() {
		$events = array();
		\add_action(
			'reportedip_hive_tier_changed',
			static function ( $old, $new ) use ( &$events ) {
				$events[] = $old . '>' . $new;
			},
			5,
			2
		);

		$this->refresh_with_role( 'reportedip_free' );
		$this->refresh_with_role( 'reportedip_enterprise' );
		$this->refresh_with_role( 'reportedip_enterprise' );

		$this->assertSame( array( 'free>enterprise' ), $events );
		$this->assertSame( 'enterprise', $GLOBALS['wp_options']['reportedip_hive_known_tier'] ?? null );
	}

	public function test_the_new_plan_counts_within_the_same_request() {
		$this->assertSame( 'free', \ReportedIP_Hive_Mode_Manager::get_instance()->get_current_tier() );

		$this->refresh_with_role( 'reportedip_business' );

		$this->assertSame( 'business', \ReportedIP_Hive_Mode_Manager::get_instance()->get_current_tier(), 'the tier memo of the request is dropped with the stored status' );
	}

	public function test_a_verified_key_check_counts_within_the_same_request() {
		$this->assertSame( 'free', \ReportedIP_Hive_Mode_Manager::get_instance()->get_current_tier() );

		$api = ( new \ReflectionClass( \ReportedIP_Hive_API::class ) )->newInstanceWithoutConstructor();
		$api->persist_verified_status( array( 'valid' => true, 'userRole' => 'reportedip_professional' ) );

		$this->assertSame( 'professional', \ReportedIP_Hive_Mode_Manager::get_instance()->get_current_tier() );
	}

	public function test_an_answer_without_a_role_keeps_the_known_plan() {
		$fired = 0;
		\add_action(
			'reportedip_hive_tier_changed',
			static function () use ( &$fired ) {
				++$fired;
			}
		);
		$this->refresh_with_role( 'reportedip_business' );

		$this->refresh_with_role( '' );

		$this->assertSame( 'business', $GLOBALS['wp_options']['reportedip_hive_known_tier'] ?? null, 'a missing role is no downgrade' );
		$this->assertSame( 0, $fired );
	}
}
