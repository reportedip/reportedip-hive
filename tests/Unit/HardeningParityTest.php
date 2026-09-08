<?php
/**
 * Parity guard: every failed-login threshold read must pass the hardening clamp.
 *
 * Hardening Mode tightens the failed-login threshold and timeframe network-wide
 * for the duration of a coordinated attack. That promise only holds if *every*
 * surface that authenticates credentials reads its threshold through
 * {@see ReportedIP_Hive_Hardening_Mode::effective_failed_login_threshold()} /
 * `effective_failed_login_timeframe()`. A sensor that reads the raw option keeps
 * running on the relaxed value while the rest of the site is hardened — the hole
 * the WooCommerce login monitor carried from 2.0.8 until this test landed.
 *
 * The check is a source scan rather than a behavioural test on purpose: it costs
 * nothing, is deterministic, and it also catches sensors that do not exist yet.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

namespace ReportedIP\Hive\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Locks the hardening clamp onto every credential-brute-force threshold read.
 *
 * @since 2.1.51
 */
class HardeningParityTest extends TestCase {

	/**
	 * Option key => the clamp wrapper the read has to be wrapped in.
	 *
	 * @var array<string, string>
	 */
	private const CLAMPED_KEYS = array(
		'reportedip_hive_failed_login_threshold' => 'effective_failed_login_threshold',
		'reportedip_hive_failed_login_timeframe' => 'effective_failed_login_timeframe',
		'reportedip_hive_app_password_threshold' => 'effective_failed_login_threshold',
		'reportedip_hive_app_password_timeframe' => 'effective_failed_login_timeframe',
	);

	/**
	 * Every runtime read of a clamped threshold sits inside its clamp wrapper.
	 *
	 * @return void
	 */
	public function test_every_login_threshold_read_is_clamped(): void {
		$files    = glob( dirname( __DIR__, 2 ) . '/includes/*.php' );
		$offences = array();
		$scanned  = 0;

		foreach ( (array) $files as $file ) {
			$source = (string) file_get_contents( $file );

			foreach ( self::CLAMPED_KEYS as $key => $wrapper ) {
				$reads = preg_match_all(
					'/Option_Routing::get\(\s*\'' . preg_quote( $key, '/' ) . '\'/',
					$source
				);
				if ( ! $reads ) {
					continue;
				}

				++$scanned;
				$clamps = substr_count( $source, $wrapper . '(' );
				if ( $clamps < $reads ) {
					$offences[] = sprintf(
						'%s reads %s %d time(s) but calls %s() only %d time(s)',
						basename( $file ),
						$key,
						$reads,
						$wrapper,
						$clamps
					);
				}
			}
		}

		$this->assertGreaterThan( 0, $scanned, 'No threshold reads found — the scan pattern has drifted from the code.' );
		$this->assertSame( array(), $offences, "Hardening Mode is bypassed:\n" . implode( "\n", $offences ) );
	}
}
