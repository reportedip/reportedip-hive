<?php
/**
 * Unit tests for the v23 cleanup of dated notice-dismissal rows.
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
 * Runs `migrate_to_v23()` against an in-memory usermeta table.
 */
class MigrationV23Test extends TestCase {

	/**
	 * Previous `$wpdb`.
	 *
	 * @var mixed
	 */
	private $saved_wpdb;

	protected function set_up() {
		parent::set_up();
		$this->saved_wpdb = $GLOBALS['wpdb'] ?? null;
		$GLOBALS['wpdb']  = new class() {
			public $usermeta = 'wp_usermeta';
			public $rows     = array();
			public function esc_like( $text ) {
				return addcslashes( (string) $text, '_%\\' );
			}
			public function prepare( $sql, ...$args ) {
				return str_replace( '%s', "'" . $args[0] . "'", (string) $sql );
			}
			public function query( $sql ) {
				if ( ! preg_match( "/^DELETE FROM wp_usermeta WHERE meta_key LIKE '(.*)'$/", (string) $sql, $m ) ) {
					return false;
				}
				$like  = $m[1];
				$regex = '';
				for ( $i = 0, $n = strlen( $like ); $i < $n; $i++ ) {
					$char = $like[ $i ];
					if ( '\\' === $char && $i + 1 < $n ) {
						$regex .= preg_quote( $like[ ++$i ], '/' );
					} elseif ( '%' === $char ) {
						$regex .= '.*';
					} elseif ( '_' === $char ) {
						$regex .= '.';
					} else {
						$regex .= preg_quote( $char, '/' );
					}
				}
				$regex = '/^' . $regex . '$/';
				$before     = count( $this->rows );
				$this->rows = array_values( array_filter( $this->rows, static fn( $key ) => ! preg_match( $regex, $key ) ) );
				return $before - count( $this->rows );
			}
		};
	}

	protected function tear_down() {
		$GLOBALS['wpdb'] = $this->saved_wpdb;
		parent::tear_down();
	}

	private function run_v23(): void {
		$method = new \ReflectionMethod( \ReportedIP_Hive_Migration_Manager::class, 'migrate_to_v23' );
		$method->invoke( null );
	}

	public function test_current_version_is_at_least_twenty_three() {
		$this->assertGreaterThanOrEqual( 23, \ReportedIP_Hive_Migration_Manager::CURRENT_VERSION );
	}

	public function test_dated_rows_go_and_fixed_rows_stay() {
		$GLOBALS['wpdb']->rows = array(
			'reportedip_dismissed_rate_limited_2026-10-15-01',
			'reportedip_dismissed_twofa_recommend_2026-10-14',
			'reportedip_dismissed_no_api_key_2026-10-14',
			'reportedip_dismissed_domain_limit_2026-10-13',
			'reportedip_dismissed_queue_warning_2026-10-13',
			'reportedip_dismissed_queue_critical_2026-10-13',
			'reportedip_dismissed_readiness_0123456789abcdef0123456789abcdef',
			'reportedip_dismissed_rate_limited',
			'reportedip_dismissed_twofa_recommend',
			'reportedip_dismissed_reputation_listed_0123456789abcdef0123456789abcdef',
			'reportedip_dismissed_reportedip_hive_addon_available_business',
			'reportedip_dismissed_group_tier',
		);

		$this->run_v23();
		$this->run_v23();

		$this->assertSame(
			array(
				'reportedip_dismissed_rate_limited',
				'reportedip_dismissed_twofa_recommend',
				'reportedip_dismissed_reputation_listed_0123456789abcdef0123456789abcdef',
				'reportedip_dismissed_reportedip_hive_addon_available_business',
				'reportedip_dismissed_group_tier',
			),
			$GLOBALS['wpdb']->rows
		);
	}
}
