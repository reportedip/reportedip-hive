<?php
/**
 * Unit tests for logging a refused XML-RPC multicall.
 *
 * @package   ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     3.0.10
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A refused multicall is answered by WordPress itself, so before 3.0.10
 * the bundled brute force left no trace in the log.
 */
class XmlrpcMulticallLogTest extends TestCase {

	/**
	 * Load the class under test.
	 */
	protected function setUp(): void {
		parent::setUp();
		require_once dirname( __DIR__, 2 ) . '/includes/class-attack-surface.php';
	}

	public function test_detects_multicall_body_only() {
		$this->assertTrue( \ReportedIP_Hive_Attack_Surface::is_multicall_request( '<?xml version="1.0"?><methodCall><methodName> system.multicall </methodName></methodCall>' ) );
		$this->assertFalse( \ReportedIP_Hive_Attack_Surface::is_multicall_request( '<methodCall><methodName>wp.getUsersBlogs</methodName></methodCall>' ) );
		$this->assertFalse( \ReportedIP_Hive_Attack_Surface::is_multicall_request( '' ) );
	}

	/**
	 * The filter that removes multicall must log once per request, skip
	 * whitelisted and blocked addresses and count the attempt like a
	 * failed login, so the threshold blocks and reports the address.
	 */
	public function test_filter_logs_and_counts_the_refused_multicall() {
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );
		$body   = substr( $source, (int) strpos( $source, 'function disable_xmlrpc_multicall' ) );
		$body   = substr( $body, 0, (int) strpos( $body, 'function is_ip_blocked_cached' ) );

		$this->assertStringContainsString( "unset( \$methods['system.multicall'] )", $body );
		$this->assertStringContainsString( '! $this->multicall_logged && ReportedIP_Hive_Attack_Surface::is_multicall_request( $body )', $body );
		$this->assertStringContainsString( "'reportedip_hive_monitor_failed_logins'", $body );
		$this->assertStringContainsString( '! $this->ip_manager->is_whitelisted( $ip_address )', $body );
		$this->assertStringContainsString( '$this->is_ip_blocked_cached( $ip_address )', $body );
		$this->assertLessThan( strpos( $body, '$this->refuse_multicall();' ), strpos( $body, '$this->log_refused_multicall( $ip_address );' ), 'Logged before the request ends.' );
		$this->assertStringContainsString( 'new IXR_Error( -32601,', $body );
		$this->assertLessThan(
			strpos( $body, 'check_failed_login_threshold( $ip_address, \'\', true )' ),
			strpos( $body, "log_security_event( 'xmlrpc_multicall_denied'" )
		);
	}

	/**
	 * A failed login names its door without personal data.
	 */
	public function test_login_endpoint_defaults_to_login_and_spots_woocommerce() {
		$this->assertSame( 'login', \ReportedIP_Hive_Attack_Surface::login_endpoint() );
		$_POST['woocommerce-login-nonce'] = 'x';
		$this->assertSame( 'woocommerce', \ReportedIP_Hive_Attack_Surface::login_endpoint() );
		unset( $_POST['woocommerce-login-nonce'] );

		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );
		$this->assertStringContainsString( "array( 'endpoint' => ReportedIP_Hive_Attack_Surface::login_endpoint() )", $source );
	}
}
