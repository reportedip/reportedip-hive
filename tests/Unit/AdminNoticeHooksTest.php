<?php
/**
 * Every notice of the free plugin that reaches a screen outside its own
 * pages (the WordPress dashboard, the plugin list, a profile) is a deliberate
 * entry here. The plugin pages print their notices through
 * `render_inline_notices()`, and an upsell never goes on an outside screen
 * (wordpress.org rule 11).
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
 * Source scan over the shipped PHP of the free plugin.
 */
class AdminNoticeHooksTest extends TestCase {

	/**
	 * The documented registrations: file => hook => reason. None of them
	 * promotes a plan.
	 *
	 * @var array<string, array<string, string>>
	 */
	const ALLOWED = array(
		'admin/class-two-factor-admin.php'      => array(
			'admin_notices' => 'Profile screen: confirms that an administrator reset a user\'s second factor.',
		),
		'includes/class-two-factor-recommend.php' => array(
			'admin_notices' => 'Reminder for a user without a second factor, shown after sign-in; a security prompt, not an offer.',
		),
	);

	/**
	 * Every registration of a notice hook in the shipped free PHP.
	 *
	 * @return array<int, array{0:string,1:string}> File relative to the plugin, hook.
	 */
	private function registrations(): array {
		$root  = dirname( __DIR__, 2 );
		$found = array();
		$it    = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $file ) {
			$path = str_replace( '\\', '/', (string) $file );
			$rel  = substr( $path, strlen( str_replace( '\\', '/', $root ) ) + 1 );
			if ( '.php' !== substr( $rel, -4 ) || preg_match( '#^(vendor|tests|node_modules|bin|coverage)/#', $rel ) ) {
				continue;
			}
			$source = (string) file_get_contents( $path );
			if ( preg_match_all( '/add_(?:action|filter)\(\s*[\'"]((?:network_|all_|user_)?admin_notices)[\'"]/', $source, $m ) ) {
				foreach ( $m[1] as $hook ) {
					$found[] = array( $rel, $hook );
				}
			}
		}
		return $found;
	}

	public function test_every_outside_notice_is_documented(): void {
		$found = $this->registrations();
		$this->assertNotEmpty( $found, 'the scan must see the known registrations' );
		foreach ( $found as list( $rel, $hook ) ) {
			$this->assertArrayHasKey( $hook, self::ALLOWED[ $rel ] ?? array(), "{$rel} registers {$hook}: render it through render_inline_notices() on the plugin pages, or document it here" );
		}
	}

	public function test_no_documented_entry_is_stale_or_an_upsell(): void {
		$found = array();
		foreach ( $this->registrations() as list( $rel, $hook ) ) {
			$found[ $rel ][ $hook ] = true;
		}
		foreach ( self::ALLOWED as $rel => $hooks ) {
			foreach ( $hooks as $hook => $reason ) {
				$this->assertArrayHasKey( $hook, $found[ $rel ] ?? array(), "{$rel} no longer registers {$hook}, drop the entry" );
				$this->assertDoesNotMatchRegularExpression( '/upgrade|pricing|\bplans?\b|add-on/i', $reason, "{$rel}: an outside notice is never an offer" );
			}
		}
	}
}
