<?php
/**
 * Source-inspection tests for the AJAX capability split.
 *
 * On Multisite every plugin option is sitemeta, so a handler that writes
 * settings must demand `manage_network_options`; a sub-site administrator
 * holding only `manage_options` must never reach the option router through
 * admin-ajax.php. The one handler a site administrator legitimately calls
 * (per-user notice dismissal) keeps the site-level check. The rule itself
 * has exactly one owner, `ReportedIP_Hive_Option_Routing::manage_capability()`.
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
		'ajax_registry_save',
		'ajax_hardening_deactivate',
	);

	/**
	 * The one place the Multisite capability rule may be spelled out.
	 */
	const RULE = "is_multisite() ? 'manage_network_options' : 'manage_options'";

	/**
	 * Handler source text.
	 *
	 * @return string
	 */
	private function handler_source(): string {
		return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-ajax-handler.php' );
	}

	/**
	 * Every PHP source file under admin/ and includes/.
	 *
	 * @return array<string, string> Relative path => source text.
	 */
	private function plugin_sources(): array {
		$root    = dirname( __DIR__, 2 );
		$sources = array();
		foreach ( array_merge( array( $root . '/reportedip-hive.php' ), (array) glob( $root . '/admin/*.php' ), (array) glob( $root . '/includes/*.php' ) ) as $file ) {
			$sources[ str_replace( '\\', '/', substr( (string) $file, strlen( $root ) + 1 ) ) ] = (string) file_get_contents( (string) $file );
		}

		return $sources;
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

	public function test_capability_rule_has_a_single_owner() {
		$sources = $this->plugin_sources();
		$this->assertArrayHasKey( 'includes/class-option-routing.php', $sources );

		foreach ( $sources as $path => $source ) {
			if ( 'includes/class-option-routing.php' === $path ) {
				$this->assertMatchesRegularExpression(
					'/function manage_capability\(\)\s*\{\s*return ' . preg_quote( self::RULE, '/' ) . ';/s',
					$source,
					'Option_Routing::manage_capability() must own the Multisite capability rule'
				);
				$this->assertMatchesRegularExpression(
					'/function current_user_can_manage\(\)\s*\{\s*return current_user_can\( self::manage_capability\(\) \);/s',
					$source
				);
				continue;
			}

			$this->assertStringNotContainsString(
				self::RULE,
				$source,
				"$path must call Option_Routing::current_user_can_manage() instead of restating the capability rule"
			);
		}
	}

	public function test_admin_capability_helper_is_multisite_aware() {
		$this->assertMatchesRegularExpression(
			'/function require_admin_capability\(\)\s*\{\s*if \( ! ReportedIP_Hive_Option_Routing::current_user_can_manage\(\) \)/s',
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

	/**
	 * The quickstart renders standalone and answers four AJAX handlers, all of
	 * which write plugin state, so every one of them goes through the same
	 * network-aware helper. The hidden menu entry is registered in the network
	 * admin only; a sub-site never gets an entry, so core's own 403 answers
	 * there before any plugin code runs.
	 */
	public function test_quickstart_gates_render_and_every_handler_with_the_network_capability() {
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-quickstart.php' );

		$this->assertMatchesRegularExpression(
			'/function user_can_run_quickstart\(\)\s*\{\s*return ReportedIP_Hive_Option_Routing::current_user_can_manage\(\);/s',
			$source,
			'the quickstart must follow the option-writing capability rule'
		);
		$this->assertStringNotContainsString( "current_user_can( 'manage_options' )", $source, 'no quickstart path may accept a sub-site administrator' );
		$this->assertMatchesRegularExpression(
			'/function add_page\(\)\s*\{\s*if \( is_multisite\(\) && ! is_network_admin\(\) \) \{\s*return;\s*\}\s*foreach \(.*?\) as \$slug \) \{\s*add_submenu_page\((?:(?!\);).)*?ReportedIP_Hive_Option_Routing::manage_capability\(\),/s',
			$source,
			'the hidden menu entry must return early on sub-sites and use the network-aware capability'
		);

		foreach ( array( 'maybe_render_standalone', 'ajax_validate_api_key', 'ajax_activate', 'ajax_import_settings', 'ajax_validate_login_slug' ) as $method ) {
			$this->assertSame( 1, preg_match( '/function ' . $method . '\(\)\s*\{(.*?)\n\t\}/s', $source, $match ), "$method() must exist" );
			$this->assertStringContainsString( '$this->user_can_run_quickstart()', $match[1], "$method() must gate on the quickstart capability helper" );
		}
	}

	public function test_settings_import_demands_the_network_capability_on_multisite() {
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-settings-import-export.php' );

		$this->assertMatchesRegularExpression(
			'/function require_authorised_admin\(\): void\s*\{\s*if \( ! ReportedIP_Hive_Option_Routing::current_user_can_manage\(\) \)/s',
			$source,
			'the settings import writes sitemeta and must not be reachable by a sub-site administrator'
		);
	}

	public function test_dashboard_widget_uses_the_shared_predicate() {
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-dashboard-widget.php' );

		$this->assertMatchesRegularExpression(
			'/function current_user_can_view\(\)\s*\{\s*return ReportedIP_Hive_Option_Routing::current_user_can_manage\(\);/s',
			$source,
			'the dashboard widget visibility must follow the same rule as the settings writers'
		);
	}
}
