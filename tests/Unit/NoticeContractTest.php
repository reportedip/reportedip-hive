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

	/**
	 * Callbacks allowed on the core notice hooks, which print on every admin
	 * screen including the WordPress dashboard, keyed by the file path below
	 * `plugins/`, one reason per callback. None carries plan wording.
	 */
	private const CORE_HOOK_CALLBACKS = array(
		'reportedip-hive/admin/class-two-factor-admin.php'        => array(
			'show_admin_reset_notice' => 'Confirms the 2FA reset the admin just triggered.',
		),
		'reportedip-hive/includes/class-two-factor-recommend.php' => array(
			'maybe_render_soft_banner' => 'Account-security reminder for the user in front of the screen.',
		),
		'reportedip-hive-pro/admin/class-relay-cards.php'         => array(
			'render_cap_status_notice' => 'Pro is not on wordpress.org; an exhausted relay quota is an operating state, not an upsell, and also shows on the WordPress dashboard.',
		),
		'reportedip-hive-pro/admin/class-user-admin.php'          => array(
			'show_users_notice' => 'Result of the bulk account action the admin just ran (query flag of the redirect).',
		),
		'reportedip-hive-pro/includes/class-dependency.php'       => array(
			'render_notice' => 'The add-on cannot run without the free plugin; the notice is the only way to say so.',
		),
	);

	/**
	 * Closures and string callbacks on a core notice hook, keyed by file and
	 * a fragment of the callback source. They cannot be inspected by name,
	 * so each one needs a reason here. Empty on purpose.
	 */
	private const NON_ARRAY_CALLBACKS = array();

	/**
	 * Notices about the account, the queue, the plan or the add-on print
	 * through the in-page funnel on the plugin pages only. Only the listed
	 * callbacks hang on the core notice hooks, and none carries upgrade or
	 * plan wording. The add-on is scanned too when it sits next to the free
	 * plugin (monorepo); the public mirror has no add-on to scan.
	 */
	public function test_no_notice_targets_the_wp_dashboard_with_upgrade_wording() {
		$plugins = dirname( REPORTEDIP_HIVE_PLUGIN_DIR ) . '/';
		$files   = array_merge(
			glob( REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/*.php' ),
			glob( REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/*.php' ),
			array( REPORTEDIP_HIVE_PLUGIN_FILE )
		);
		$expected = self::CORE_HOOK_CALLBACKS;
		if ( is_dir( $plugins . 'reportedip-hive-pro' ) ) {
			$files = array_merge(
				$files,
				glob( $plugins . 'reportedip-hive-pro/includes/*.php' ),
				glob( $plugins . 'reportedip-hive-pro/admin/*.php' ),
				array( $plugins . 'reportedip-hive-pro/reportedip-hive-pro.php' )
			);
		} else {
			foreach ( array_keys( $expected ) as $rel ) {
				if ( 0 === strpos( $rel, 'reportedip-hive-pro/' ) ) {
					unset( $expected[ $rel ] );
				}
			}
		}

		$hook  = "add_action\(\s*'(?:network_|all_|user_)?admin_notices'\s*,\s*+";
		$found = array();
		foreach ( $files as $file ) {
			$source = (string) file_get_contents( $file );
			$rel    = str_replace( '\\', '/', substr( $file, strlen( $plugins ) ) );
			if ( preg_match_all( '/' . $hook . "array\(\s*[^,]+,\s*'([a-z_]+)'/", $source, $m ) ) {
				foreach ( $m[1] as $callback ) {
					$found[ $rel ][] = $callback;
				}
			}
			if ( preg_match_all( '/' . $hook . '(?!array)([^\n]{1,60})/', $source, $m ) ) {
				foreach ( $m[1] as $snippet ) {
					$this->assertTrue( $this->is_listed_non_array( $rel, $snippet ), $rel . ': closure or string callback on a core notice hook: ' . $snippet );
				}
			}
		}

		$expected_lists = array();
		foreach ( $expected as $rel => $callbacks ) {
			$expected_lists[ $rel ] = array_keys( $callbacks );
		}
		foreach ( $found as $rel => $callbacks ) {
			$found[ $rel ] = array_values( array_unique( $callbacks ) );
			sort( $found[ $rel ] );
		}
		ksort( $found );
		ksort( $expected_lists );
		$this->assertSame( $expected_lists, $found, 'A new callback on a core notice hook reaches the WordPress dashboard.' );

		foreach ( $expected as $rel => $callbacks ) {
			$source = (string) file_get_contents( $plugins . $rel );
			foreach ( array_keys( $callbacks ) as $callback ) {
				$this->assertSame( 1, preg_match( '/function ' . $callback . '\(.*?\n\t\}/s', $source, $body ), $callback );
				$this->assertDoesNotMatchRegularExpression( '/upgrade|pricing|plan\b|tier/i', $body[0], $callback . ' carries plan wording.' );
			}
		}

		$settings = (string) file_get_contents( REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-admin-settings.php' );
		$this->assertSame( 1, preg_match( '/public static function render_inline_notices\(\).*?\n\t\}/s', $settings, $funnel ) );
		foreach ( array( 'display_api_status_notices()', 'maybe_render_domain_limit_notice()', 'Addon_Notice::render()' ) as $call ) {
			$this->assertStringContainsString( $call, $funnel[0], $call . ' left the in-page funnel.' );
		}
	}

	/**
	 * Whether a closure or string callback is listed with a reason.
	 *
	 * @param string $rel     File path below `plugins/`.
	 * @param string $snippet Start of the callback source.
	 * @return bool
	 */
	private function is_listed_non_array( $rel, $snippet ) {
		foreach ( array_keys( self::NON_ARRAY_CALLBACKS[ $rel ] ?? array() ) as $fragment ) {
			if ( false !== strpos( $snippet, $fragment ) ) {
				return true;
			}
		}
		return false;
	}
}
