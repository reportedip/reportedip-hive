<?php
/**
 * Unit tests for the WebAuthn assertion verification path.
 *
 * Builds complete, cryptographically valid assertion fixtures in pure PHP
 * (P-256 keypair via OpenSSL, hand-assembled authenticatorData and COSE key
 * CBOR) and drives them through the private verify_assertion() pipeline.
 * Locks down:
 *
 *   1. The happy path — valid signature, fresh counter — verifies and
 *      persists the updated sign_count / last_used.
 *   2. Legacy credential records (only the six original fields) keep
 *      verifying — the migration guard for existing installs.
 *   3. Challenge, origin and user-presence rejections.
 *   4. The four sign-counter branches per WebAuthn L2 §7.2 step 21,
 *      including the clone-detection regression rejection and its
 *      security-log event.
 *   5. UV enforcement when the user_verification filter returns 'required'.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.33
 */

namespace {

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn' ) ) {
		/**
		 * Minimal Two_Factor stub: only the constants the WebAuthn class
		 * reads via static class access on the assertion path.
		 */
		class ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn {
			const METHOD_WEBAUTHN           = 'webauthn';
			const META_WEBAUTHN_ENABLED     = 'reportedip_hive_2fa_webauthn_enabled';
			const META_WEBAUTHN_CREDENTIALS = 'reportedip_hive_2fa_webauthn_credentials';
			const NONCE_COOKIE              = 'reportedip_2fa_token';
			const NONCE_PREFIX              = 'reportedip_2fa_nonce_';

			/**
			 * Register-path helper, unused on the assertion path.
			 *
			 * @param int $user_id User id.
			 * @return bool
			 */
			public static function is_user_enabled( $user_id ) {
				return true;
			}

			/**
			 * Register-path helper, unused on the assertion path.
			 *
			 * @param int    $user_id User id.
			 * @param string $method  Method id.
			 */
			public static function enable_for_user( $user_id, $method ) {}

			/**
			 * Register-path helper, unused on the assertion path.
			 *
			 * @param int    $user_id User id.
			 * @param string $method  Method id.
			 * @return bool
			 */
			public static function activate_method( $user_id, $method ) {
				return true;
			}
		}
	}
	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor', false ) ) {
		class_alias( 'ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn', 'ReportedIP_Hive_Two_Factor' );
	}

	if ( ! class_exists( 'ReportedIP_Hive_Stub_For_WebAuthn' ) ) {
		/**
		 * Plugin-core stub: the counter-regression logging path resolves the
		 * client IP through this static.
		 */
		class ReportedIP_Hive_Stub_For_WebAuthn {
			/**
			 * Fixed client IP for assertions on the logged event payload.
			 *
			 * @return string
			 */
			public static function get_client_ip() {
				return '203.0.113.5';
			}
		}
	}
	if ( ! class_exists( 'ReportedIP_Hive', false ) ) {
		class_alias( 'ReportedIP_Hive_Stub_For_WebAuthn', 'ReportedIP_Hive' );
	}

	if ( ! class_exists( 'ReportedIP_Hive_Logger_Stub_For_WebAuthn' ) ) {
		/**
		 * Logger stub capturing security events into a global for assertions.
		 */
		class ReportedIP_Hive_Logger_Stub_For_WebAuthn {
			/**
			 * Singleton accessor mirroring the production API.
			 *
			 * @return self
			 */
			public static function get_instance() {
				static $instance = null;
				if ( null === $instance ) {
					$instance = new self();
				}
				return $instance;
			}

			/**
			 * Capture the event instead of writing to the database.
			 *
			 * @param string $event_type Event type slug.
			 * @param string $ip_address Client IP.
			 * @param array  $details    Event details.
			 * @param string $severity   Severity bucket.
			 * @return bool
			 */
			public function log_security_event( $event_type, $ip_address, $details = array(), $severity = 'medium' ) {
				$GLOBALS['rip_test_logged_events'][] = array(
					'event'    => $event_type,
					'ip'       => $ip_address,
					'details'  => $details,
					'severity' => $severity,
				);
				return true;
			}
		}
	}
	if ( ! class_exists( 'ReportedIP_Hive_Logger', false ) ) {
		class_alias( 'ReportedIP_Hive_Logger_Stub_For_WebAuthn', 'ReportedIP_Hive_Logger' );
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-webauthn.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use ReportedIP_Hive_Two_Factor_WebAuthn;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class WebAuthnAssertionTest extends TestCase {

		private const USER_ID = 7;

		/**
		 * Static throwaway P-256 keypair used as the authenticator key in
		 * fixtures. Embedded instead of generated because openssl_pkey_new()
		 * needs an openssl.cnf that Windows PHP builds often lack — signing
		 * and key inspection work everywhere.
		 */
		private const FIXTURE_EC_PEM = <<<'PEM'
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGZcH9vfxPOJ1rWgJBXKun4e8gDEyIRUNzJ8+t6La9EioAoGCCqGSM49
AwEHoUQDQgAEgA9iyGDCCaVf+zN1PtCks6n5GgE3rtT3TvI2EFxEKsGRVorYo9Wy
1CBJ+8QYHG0gNqEAGewmoHtY/HI7OhYHbQ==
-----END EC PRIVATE KEY-----
PEM;

		/**
		 * OpenSSL EC key resource for the current test.
		 *
		 * @var \OpenSSLAsymmetricKey
		 */
		private $private_key;

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_transients']          = array();
			$GLOBALS['wp_user_meta']           = array();
			$GLOBALS['wp_filters']             = array();
			$GLOBALS['rip_test_logged_events'] = array();
		}

		/**
		 * Load the fixture P-256 keypair and return the padded raw X/Y
		 * coordinates.
		 *
		 * @return array{0:string,1:string} 32-byte X and Y.
		 */
		private function make_keypair(): array {
			$this->private_key = openssl_pkey_get_private( self::FIXTURE_EC_PEM );
			$this->assertNotFalse( $this->private_key, 'OpenSSL must be able to load the fixture P-256 key.' );
			$details = openssl_pkey_get_details( $this->private_key );
			$x       = str_pad( $details['ec']['x'], 32, "\0", STR_PAD_LEFT );
			$y       = str_pad( $details['ec']['y'], 32, "\0", STR_PAD_LEFT );
			return array( $x, $y );
		}

		/**
		 * Hand-assembled COSE_Key CBOR map for an ES256 public key:
		 * {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}.
		 *
		 * @param string $x Raw 32-byte X coordinate.
		 * @param string $y Raw 32-byte Y coordinate.
		 * @return string CBOR bytes.
		 */
		private function cose_key( string $x, string $y ): string {
			return "\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20" . $x . "\x22\x58\x20" . $y;
		}

		/**
		 * Assemble assertion authenticatorData (no attested credential data).
		 *
		 * @param int $flags      Flag byte.
		 * @param int $sign_count Counter value.
		 * @return string
		 */
		private function auth_data( int $flags, int $sign_count ): string {
			return hash( 'sha256', 'example.org', true ) . chr( $flags ) . pack( 'N', $sign_count );
		}

		/**
		 * Store a credential record + login challenge, then build a signed
		 * assertion for it.
		 *
		 * @param array $overrides {record?: array, flags?: int, count?: int,
		 *                          challenge_b64url?: string, origin?: string}.
		 * @return array Assertion payload as the browser would POST it.
		 */
		private function arrange_assertion( array $overrides = array() ): array {
			list( $x, $y ) = $this->make_keypair();

			$cred_id_raw = random_bytes( 16 );
			$cred_id     = ReportedIP_Hive_Two_Factor_WebAuthn::b64url_encode( $cred_id_raw );

			$record = array_merge(
				array(
					'id'         => $cred_id,
					'public_key' => base64_encode( $this->cose_key( $x, $y ) ),
					'sign_count' => 0,
					'created_at' => time() - 100,
					'transports' => array( 'usb', 'nfc' ),
					'name'       => 'Test key',
				),
				$overrides['record'] ?? array()
			);
			update_user_meta(
				self::USER_ID,
				\ReportedIP_Hive_Two_Factor::META_WEBAUTHN_CREDENTIALS,
				wp_json_encode( array( $record ) )
			);

			$challenge = random_bytes( 32 );
			set_transient( 'reportedip_2fa_webauthn_login_' . self::USER_ID, base64_encode( $challenge ), 300 );

			$client_data      = array(
				'type'      => 'webauthn.get',
				'challenge' => $overrides['challenge_b64url'] ?? ReportedIP_Hive_Two_Factor_WebAuthn::b64url_encode( $challenge ),
				'origin'    => $overrides['origin'] ?? 'https://example.org',
			);
			$client_data_json = (string) wp_json_encode( $client_data );

			$auth_data = $this->auth_data( $overrides['flags'] ?? 0x01, $overrides['count'] ?? 5 );
			$signed    = $auth_data . hash( 'sha256', $client_data_json, true );
			openssl_sign( $signed, $signature, $this->private_key, OPENSSL_ALGO_SHA256 );

			return array(
				'id'       => $cred_id,
				'type'     => 'public-key',
				'response' => array(
					'clientDataJSON'    => ReportedIP_Hive_Two_Factor_WebAuthn::b64url_encode( $client_data_json ),
					'authenticatorData' => ReportedIP_Hive_Two_Factor_WebAuthn::b64url_encode( $auth_data ),
					'signature'         => ReportedIP_Hive_Two_Factor_WebAuthn::b64url_encode( $signature ),
					'userHandle'        => null,
				),
			);
		}

		/**
		 * Invoke the private verify_assertion() pipeline.
		 *
		 * @param array $assertion Assertion payload.
		 * @return true|\WP_Error
		 */
		private function verify( array $assertion ) {
			$method = new \ReflectionMethod( ReportedIP_Hive_Two_Factor_WebAuthn::class, 'verify_assertion' );
			return $method->invoke( null, self::USER_ID, $assertion );
		}

		/**
		 * Read the stored credential record back.
		 *
		 * @return array
		 */
		private function stored_record(): array {
			$creds = ReportedIP_Hive_Two_Factor_WebAuthn::get_user_credentials( self::USER_ID );
			return $creds[0] ?? array();
		}

		public function test_valid_assertion_verifies_and_updates_counter(): void {
			$assertion = $this->arrange_assertion( array( 'count' => 5 ) );
			$this->assertTrue( $this->verify( $assertion ) );

			$record = $this->stored_record();
			$this->assertSame( 5, (int) $record['sign_count'], 'A fresh, higher counter must be persisted.' );
			$this->assertArrayHasKey( 'last_used', $record, 'last_used must be stamped on every successful assertion.' );
		}

		public function test_legacy_record_without_new_fields_still_verifies(): void {
			$assertion = $this->arrange_assertion(
				array(
					'record' => array(
						'transports' => array(),
						'name'       => 'Passkey',
					),
				)
			);
			$this->assertTrue(
				$this->verify( $assertion ),
				'Credential records enrolled before 2.1.33 (no uv/aaguid fields) must keep verifying unchanged.'
			);
		}

		public function test_challenge_mismatch_is_rejected(): void {
			$assertion = $this->arrange_assertion(
				array( 'challenge_b64url' => ReportedIP_Hive_Two_Factor_WebAuthn::b64url_encode( random_bytes( 32 ) ) )
			);
			$result = $this->verify( $assertion );
			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'webauthn_challenge', $result->get_error_code() );
		}

		public function test_origin_mismatch_is_rejected(): void {
			$assertion = $this->arrange_assertion( array( 'origin' => 'https://evil.example.com' ) );
			$result    = $this->verify( $assertion );
			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'webauthn_origin', $result->get_error_code() );
		}

		public function test_missing_user_presence_flag_is_rejected(): void {
			$assertion = $this->arrange_assertion( array( 'flags' => 0x00 ) );
			$result    = $this->verify( $assertion );
			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame(
				'webauthn_no_user_presence',
				$result->get_error_code(),
				'WebAuthn §7.2 requires the UP flag on every assertion — a YubiKey only sets it after a physical touch.'
			);
		}

		public function test_uv_enforced_when_filter_requires_it(): void {
			$GLOBALS['wp_filters']['reportedip_hive_webauthn_user_verification'] = array(
				array(
					'callback'      => static function () {
						return 'required';
					},
					'accepted_args' => 1,
				),
			);

			$assertion = $this->arrange_assertion( array( 'flags' => 0x01 ) );
			$result    = $this->verify( $assertion );
			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'webauthn_no_user_verification', $result->get_error_code() );

			$assertion = $this->arrange_assertion( array( 'flags' => 0x05 ) );
			$this->assertTrue( $this->verify( $assertion ), 'UP+UV flags must satisfy the required policy.' );
		}

		public function test_counter_regression_is_rejected_and_logged(): void {
			$assertion = $this->arrange_assertion(
				array(
					'record' => array( 'sign_count' => 10 ),
					'count'  => 5,
				)
			);
			$result = $this->verify( $assertion );
			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'webauthn_counter', $result->get_error_code() );

			$this->assertCount( 1, $GLOBALS['rip_test_logged_events'] );
			$event = $GLOBALS['rip_test_logged_events'][0];
			$this->assertSame( '2fa_webauthn_counter_regression', $event['event'] );
			$this->assertSame( 'high', $event['severity'] );
			$this->assertSame( 10, $event['details']['stored_count'] );
			$this->assertSame( 5, $event['details']['asserted'] );

			$this->assertSame(
				10,
				(int) $this->stored_record()['sign_count'],
				'A rejected regression must not overwrite the stored counter.'
			);
		}

		public function test_zero_counter_after_nonzero_history_is_rejected(): void {
			$assertion = $this->arrange_assertion(
				array(
					'record' => array( 'sign_count' => 42 ),
					'count'  => 0,
				)
			);
			$result = $this->verify( $assertion );
			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame(
				'webauthn_counter',
				$result->get_error_code(),
				'A zero assertion against a counter-bearing credential is the classic cloned-key signature and must not reset the stored counter.'
			);
			$this->assertSame( 42, (int) $this->stored_record()['sign_count'] );
		}

		public function test_counterless_authenticator_passes_with_both_zero(): void {
			$assertion = $this->arrange_assertion(
				array(
					'record' => array( 'sign_count' => 0 ),
					'count'  => 0,
				)
			);
			$this->assertTrue(
				$this->verify( $assertion ),
				'Counter-less authenticators (synced platform passkeys) always report 0 and must stay valid.'
			);
			$this->assertSame( 0, (int) $this->stored_record()['sign_count'] );
		}

		public function test_unknown_credential_is_rejected(): void {
			$assertion       = $this->arrange_assertion();
			$assertion['id'] = ReportedIP_Hive_Two_Factor_WebAuthn::b64url_encode( random_bytes( 16 ) );
			$result          = $this->verify( $assertion );
			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'webauthn_unknown_cred', $result->get_error_code() );
		}

		public function test_tampered_signature_is_rejected(): void {
			$assertion = $this->arrange_assertion();
			$raw       = ReportedIP_Hive_Two_Factor_WebAuthn::b64url_decode( $assertion['response']['signature'] );
			$raw[10]   = chr( ord( $raw[10] ) ^ 0xff );
			$assertion['response']['signature'] = ReportedIP_Hive_Two_Factor_WebAuthn::b64url_encode( $raw );

			$result = $this->verify( $assertion );
			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'webauthn_sig', $result->get_error_code() );
		}
	}
}
