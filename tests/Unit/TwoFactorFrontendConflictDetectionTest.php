<?php
/**
 * Unit tests for {@see ReportedIP_Hive_Two_Factor_Frontend::detect_conflicts()}.
 *
 * Locks down the exact identifiers used to fingerprint other 2FA /
 * login-hardening plugins. The settings UI relies on the returned
 * descriptors verbatim, so a refactor that renames a slug or drops a
 * conflict entry would silently take the warning banner off air.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.7.0
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

class TwoFactorFrontendConflictDetectionTest extends TestCase {

	private function source(): string {
		return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor-frontend.php' );
	}

	public function test_solid_security_indicator_is_itsec_core(): void {
		$source = $this->source();
		$this->assertStringContainsString(
			"class_exists( 'ITSEC_Core' )",
			$source,
			'`ITSEC_Core` is the canonical Solid Security marker — keep it as the conflict trigger so future Solid renames still fingerprint correctly.'
		);
		$this->assertStringContainsString(
			"'slug'    => 'solid-security'",
			$source,
			'The conflict descriptor must use the `solid-security` slug so the settings UI can target the entry.'
		);
	}

	public function test_wp_two_factor_indicator_is_two_factor_core(): void {
		$source = $this->source();
		$this->assertStringContainsString(
			"class_exists( 'Two_Factor_Core' )",
			$source,
			'The official WordPress.org Two Factor plugin is fingerprinted by `Two_Factor_Core`.'
		);
		$this->assertStringContainsString(
			"'slug'    => 'wp-two-factor'",
			$source,
			'The descriptor for the WordPress.org Two Factor plugin uses the `wp-two-factor` slug.'
		);
	}

	public function test_wordfence_indicator_is_wfconfig_function(): void {
		$source = $this->source();
		$this->assertStringContainsString(
			"function_exists( 'wfConfig' )",
			$source,
			'Wordfence is fingerprinted via the `wfConfig` function — class names there shift between versions.'
		);
	}

	public function test_wc_subscriptions_membership_disclosure_present(): void {
		$source = $this->source();
		$this->assertStringContainsString(
			"class_exists( 'WC_Subscriptions' )",
			$source,
			'WC Subscriptions detection is a non-blocking informational note — magic-login bypass intentional.'
		);
		$this->assertStringContainsString(
			"class_exists( 'WC_Memberships' )",
			$source,
			'WC Memberships detection ditto.'
		);
	}
}
