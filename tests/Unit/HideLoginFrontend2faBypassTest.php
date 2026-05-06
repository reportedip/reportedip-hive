<?php
/**
 * Unit tests for the Hide-Login bypass that protects the
 * frontend 2FA challenge / setup slugs.
 *
 * Hide-Login's `should_bypass()` is the choke-point that decides whether
 * the request gets rewritten or rendered as a fake 404 / block-page.
 * The frontend 2FA module exposes two public slugs (challenge and setup)
 * that MUST always pass through, otherwise enabling Hide-Login on a
 * customer-facing site silently breaks the second-factor for every
 * WooCommerce user.
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

class HideLoginFrontend2faBypassTest extends TestCase {

	private function source(): string {
		return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-hide-login.php' );
	}

	public function test_should_bypass_pulls_slugs_from_frontend_module(): void {
		$source = $this->source();

		$this->assertStringContainsString(
			"ReportedIP_Hive_Two_Factor_Frontend::get_challenge_slug()",
			$source,
			'should_bypass() must read the configured challenge slug from the Frontend module so admins who customised the slug do not lock themselves out.'
		);
		$this->assertStringContainsString(
			"ReportedIP_Hive_Two_Factor_Frontend::get_setup_slug()",
			$source,
			'should_bypass() must read the configured setup slug from the Frontend module — the onboarding wizard is on its own slug.'
		);
	}

	public function test_should_bypass_returns_true_for_frontend_paths(): void {
		$source = $this->source();

		$this->assertMatchesRegularExpression(
			'/foreach\s*\(\s*\$rip_2fa_slugs\s+as\s+\$rip_slug\s*\)/',
			$source,
			'The bypass must iterate both slugs and short-circuit on a match — a single hardcoded slug would break the moment the operator renames either one.'
		);
		$this->assertStringContainsString(
			"str_starts_with( \$path, '/' . \$rip_slug . '/' )",
			$source,
			'The match has to cover both bare-slug and trailing-segment paths so a future onboarding step like /reportedip-hive-2fa-setup/totp/ stays bypassed.'
		);
	}

	public function test_bypass_guarded_by_class_exists(): void {
		$source = $this->source();

		$this->assertStringContainsString(
			"class_exists( 'ReportedIP_Hive_Two_Factor_Frontend' )",
			$source,
			'The bypass branch must be wrapped in a class_exists() guard so old installs without the Frontend module keep parsing this file without fatals.'
		);
	}
}
