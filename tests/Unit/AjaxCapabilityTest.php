<?php
/**
 * Source-inspection tests for the AJAX capability split.
 *
 * On Multisite every plugin option is sitemeta, so a handler that writes
 * settings must demand `manage_network_options`; a sub-site administrator
 * holding only `manage_options` must never reach the option router through
 * admin-ajax.php. The one handler a site administrator legitimately calls
 * (per-user notice dismissal) keeps the site-level check.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

declare(strict_types=1);

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * Locks the multisite-aware capability helper and its use in every handler
 * that writes plugin state.
 */
class AjaxCapabilityTest extends TestCase {

	/**
	 * Handlers that must always use the network-aware capability helper.
	 *
	 * @var string[]
	 */
	const WRITING_HANDLERS = array(
		'ajax_set_mode',
		'ajax_disposable_action',
		'ajax_spam_toggle',
		'ajax_scan_toggle',
		'ajax_headers_save',
		'ajax_registry_save',
		'ajax_hardening_deactivate',
	);

	/**
	 * Handler source text.
	 *
	 * @return string
	 */
	private function handler_source(): string {
		return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-ajax-handler.php' );
	}

	/**
	 * Map every `ajax_*` method name to its body.
	 *
	 * @return array<string, string>
	 */
	private function handler_bodies(): array {
		preg_match_all( '/public function (ajax_[a-z0-9_]+)\(\)\s*\{(.*?)\n\t\}/s', $this->handler_source(), $matches, PREG_SET_ORDER );

		$bodies = array();
		foreach ( $matches as $match ) {
			$bodies[ $match[1] ] = $match[2];
		}

		return $bodies;
	}

	public function test_admin_capability_helper_is_multisite_aware() {
		$this->assertMatchesRegularExpression(
			'/function require_admin_capability\(\)\s*\{\s*if \( ! current_user_can\( is_multisite\(\) \? \'manage_network_options\' : \'manage_options\' \) \)/s',
			$this->handler_source(),
			'require_admin_capability() must demand manage_network_options on Multisite'
		);
	}

	public function test_site_capability_helper_checks_manage_options_only() {
		$this->assertMatchesRegularExpression(
			'/function require_site_capability\(\)\s*\{\s*if \( ! current_user_can\( \'manage_options\' \) \)/s',
			$this->handler_source()
		);
	}

	public function test_known_writing_handlers_use_the_network_aware_helper() {
		$bodies = $this->handler_bodies();

		foreach ( self::WRITING_HANDLERS as $handler ) {
			$this->assertArrayHasKey( $handler, $bodies, "$handler() must exist" );
			$this->assertStringContainsString(
				'$this->require_admin_capability();',
				$bodies[ $handler ],
				"$handler() must call require_admin_capability()"
			);
			$this->assertStringNotContainsString( 'require_site_capability', $bodies[ $handler ] );
		}
	}

	public function test_every_handler_that_writes_options_uses_the_network_aware_helper() {
		$writers = 0;

		foreach ( $this->handler_bodies() as $handler => $body ) {
			$writes = false !== strpos( $body, 'Option_Routing::set(' )
				|| false !== strpos( $body, 'Option_Routing::delete(' )
				|| false !== strpos( $body, 'Settings_Apply::apply(' )
				|| false !== strpos( $body, 'apply_registry_batch(' )
				|| false !== strpos( $body, 'save_registry_option(' );
			if ( ! $writes ) {
				continue;
			}

			++$writers;
			$this->assertStringContainsString(
				'$this->require_admin_capability();',
				$body,
				"$handler() writes plugin options and must call require_admin_capability()"
			);
		}

		$this->assertGreaterThanOrEqual( count( self::WRITING_HANDLERS ), $writers );
	}

	public function test_no_handler_checks_a_capability_inline() {
		foreach ( $this->handler_bodies() as $handler => $body ) {
			$this->assertStringNotContainsString(
				'current_user_can(',
				$body,
				"$handler() must route its capability check through one of the two helpers"
			);
		}
	}

	public function test_notice_dismissal_keeps_the_site_level_capability() {
		$bodies = $this->handler_bodies();

		$this->assertStringContainsString( '$this->require_site_capability();', $bodies['ajax_dismiss_notice'] );
		$this->assertStringNotContainsString( 'require_admin_capability', $bodies['ajax_dismiss_notice'] );
		$this->assertStringNotContainsString( 'Option_Routing::', $bodies['ajax_dismiss_notice'] );
	}

	public function test_setup_wizard_gates_render_and_every_step_with_the_network_capability() {
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-setup-wizard.php' );

		$this->assertMatchesRegularExpression(
			'/function user_can_run_wizard\(\)\s*\{\s*return current_user_can\( is_multisite\(\) \? \'manage_network_options\' : \'manage_options\' \);/s',
			$source,
			'the wizard must follow the option-writing capability rule'
		);
		$this->assertStringNotContainsString( "current_user_can( 'manage_options' )", $source, 'no wizard path may accept a sub-site administrator' );
		$this->assertStringContainsString( "\$cap = is_multisite() ? 'manage_network_options' : 'manage_options';", $source, 'the hidden menu entry must 403 sub-site administrators' );

		foreach ( array( 'maybe_render_standalone_wizard', 'ajax_save_step', 'ajax_import_settings', 'ajax_save_mode', 'ajax_validate_api_key', 'ajax_validate_login_slug', 'ajax_skip_wizard' ) as $method ) {
			$this->assertSame( 1, preg_match( '/function ' . $method . '\(\)\s*\{(.*?)\n\t\}/s', $source, $match ), "$method() must exist" );
			$this->assertStringContainsString( '$this->user_can_run_wizard()', $match[1], "$method() must gate on the wizard capability helper" );
		}
	}

	public function test_settings_import_demands_the_network_capability_on_multisite() {
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-settings-import-export.php' );

		$this->assertMatchesRegularExpression(
			'/function require_authorised_admin\(\): void\s*\{\s*if \( ! current_user_can\( is_multisite\(\) \? \'manage_network_options\' : \'manage_options\' \) \)/s',
			$source,
			'the settings import writes sitemeta and must not be reachable by a sub-site administrator'
		);
	}

	public function test_admin_test_sms_demands_the_network_capability_on_multisite() {
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-two-factor-admin.php' );

		$this->assertMatchesRegularExpression(
			'/function ajax_admin_test_sms\(\)\s*\{\s*check_ajax_referer\( \'reportedip_hive_nonce\', \'nonce\' \);\s*if \( ! current_user_can\( is_multisite\(\) \? \'manage_network_options\' : \'manage_options\' \) \)/s',
			$source,
			'the relay test SMS spends network quota behind the shared nonce and must not be reachable by a sub-site administrator'
		);
	}
}
