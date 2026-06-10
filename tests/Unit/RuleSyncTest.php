<?php
/**
 * Unit tests for the rule delivery framework.
 *
 * Locks down the security-critical contract: a ruleset is only applied when its
 * detached Ed25519 signature verifies against an accepted public key, the
 * payload is within the size cap and its shape matches the requested key.
 * Anything else falls back to the bundled baseline — a tampered or oversized
 * feed can never poison the WAF patterns. The bundled baseline is always
 * available offline.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.2.0
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-rule-store.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-rule-sync.php';

	/**
	 * @covers \ReportedIP_Hive_Rule_Sync
	 */
	class RuleSyncTest extends TestCase {

		/** @var string Raw Ed25519 secret key for the injected test public key. */
		private $secret;

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options'] = array();
			$GLOBALS['wp_filters'] = array();
			\ReportedIP_Hive_Rule_Store::flush_cache();

			$keypair      = sodium_crypto_sign_keypair();
			$this->secret = sodium_crypto_sign_secretkey( $keypair );
			$public_b64   = base64_encode( sodium_crypto_sign_publickey( $keypair ) );

			add_filter(
				'reportedip_hive_rule_public_keys',
				static function ( $keys ) use ( $public_b64 ) {
					$keys[] = $public_b64;
					return $keys;
				}
			);
		}

		private function sync(): \ReportedIP_Hive_Rule_Sync {
			return \ReportedIP_Hive_Rule_Sync::get_instance();
		}

		private function signed_envelope( array $data, ?string $secret = null ): array {
			$payload = wp_json_encode( $data );
			$sig     = sodium_crypto_sign_detached( $payload, $secret ?? $this->secret );
			return array(
				'payload'   => $payload,
				'signature' => base64_encode( $sig ),
			);
		}

		public function test_baseline_waf_has_rules(): void {
			$baseline = $this->sync()->load_baseline( 'waf' );
			$this->assertSame( 'waf', $baseline['key'] );
			$this->assertNotEmpty( $baseline['rules'] );
		}

		public function test_baseline_invalid_key_is_empty(): void {
			$baseline = $this->sync()->load_baseline( 'bogus' );
			$this->assertSame( array(), $baseline['rules'] );
		}

		public function test_get_ruleset_falls_back_to_baseline(): void {
			$got = $this->sync()->get_ruleset( 'disposable_domains' );
			$this->assertNotEmpty( $got['rules'] );
			$this->assertSame( 0, $got['version'], 'Unsynced ruleset must be the bundled baseline (version 0).' );
		}

		public function test_get_ruleset_returns_stored_over_baseline(): void {
			\ReportedIP_Hive_Rule_Store::set( 'waf', array( 'key' => 'waf', 'version' => 99, 'rules' => array( array( 'id' => 'x' ) ) ) );
			$this->assertSame( 99, $this->sync()->get_ruleset( 'waf' )['version'] );
		}

		public function test_verify_signature_accepts_valid(): void {
			$payload = 'the exact signed bytes';
			$sig     = base64_encode( sodium_crypto_sign_detached( $payload, $this->secret ) );
			$this->assertTrue( $this->sync()->verify_signature( $payload, $sig ) );
		}

		public function test_verify_signature_rejects_tampered_payload(): void {
			$sig = base64_encode( sodium_crypto_sign_detached( 'original', $this->secret ) );
			$this->assertFalse( $this->sync()->verify_signature( 'tampered', $sig ) );
		}

		public function test_verify_signature_rejects_wrong_key(): void {
			$other   = sodium_crypto_sign_keypair();
			$payload = 'payload';
			$sig     = base64_encode( sodium_crypto_sign_detached( $payload, sodium_crypto_sign_secretkey( $other ) ) );
			$this->assertFalse( $this->sync()->verify_signature( $payload, $sig ), 'A signature from a non-accepted key must be rejected.' );
		}

		public function test_verify_signature_rejects_garbage(): void {
			$this->assertFalse( $this->sync()->verify_signature( 'x', 'not-base64-!!!' ) );
			$this->assertFalse( $this->sync()->verify_signature( 'x', '' ) );
		}

		public function test_apply_ruleset_stores_verified(): void {
			$envelope = $this->signed_envelope( array( 'key' => 'waf', 'version' => 5, 'rules' => array( array( 'id' => 'r' ) ) ) );
			$this->assertTrue( $this->sync()->apply_ruleset( 'waf', $envelope ) );
			$this->assertSame( 5, $this->sync()->get_ruleset( 'waf' )['version'] );
		}

		public function test_apply_ruleset_rejects_bad_signature(): void {
			$envelope              = $this->signed_envelope( array( 'key' => 'waf', 'version' => 5, 'rules' => array() ) );
			$envelope['signature'] = base64_encode( str_repeat( "\0", SODIUM_CRYPTO_SIGN_BYTES ) );
			$this->assertFalse( $this->sync()->apply_ruleset( 'waf', $envelope ) );
			$this->assertNull( \ReportedIP_Hive_Rule_Store::get( 'waf' ) );
		}

		public function test_apply_ruleset_rejects_oversize_payload(): void {
			$big      = array( 'key' => 'waf', 'version' => 1, 'rules' => array( str_repeat( 'a', 524300 ) ) );
			$envelope = $this->signed_envelope( $big );
			$this->assertFalse( $this->sync()->apply_ruleset( 'waf', $envelope ) );
		}

		public function test_apply_ruleset_rejects_key_mismatch(): void {
			$envelope = $this->signed_envelope( array( 'key' => 'scan_paths', 'version' => 1, 'rules' => array() ) );
			$this->assertFalse( $this->sync()->apply_ruleset( 'waf', $envelope ), 'A payload whose key does not match the requested key must be rejected.' );
		}

		public function test_sync_not_eligible_without_api_key(): void {
			\ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_rule_sync_enabled', 1 );
			\ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_api_key' );
			$this->assertFalse( $this->sync()->is_sync_eligible() );
		}

		public function test_sync_not_eligible_when_disabled(): void {
			\ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_rule_sync_enabled', 0 );
			\ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_api_key', 'abc' );
			$this->assertFalse( $this->sync()->is_sync_eligible() );
		}
	}
}
