<?php
/**
 * Regression guard: every event type the Firewall page counts must be one the
 * plugin actually writes.
 *
 * The Firewall overview listed `scan_404`, but the scan detector funnels 404s
 * through the shared attempt tracker, which logs only the generated
 * `scan_404_threshold_exceeded` variant. The counter and the log filter
 * therefore reported zero forever while scanners were being blocked and their
 * IPs laddered, a silent, self-consistent lie. This test locks the two lists
 * together so a new counter cannot drift from the writer again.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.30
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-rule-store.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-event-taxonomy.php';
	require_once dirname( __DIR__, 2 ) . '/admin/class-admin-firewall.php';

	/**
	 * @covers \ReportedIP_Hive_Admin_Firewall
	 */
	class FirewallEventTypesTest extends TestCase {

		/**
		 * Memoised source blob, built once per test case.
		 *
		 * @var string|null
		 */
		private $source_blob = null;

		/**
		 * Concatenated plugin sources, without the tests themselves.
		 */
		private function sources(): string {
			if ( null !== $this->source_blob ) {
				return $this->source_blob;
			}

			$root  = dirname( __DIR__, 2 );
			$files = array_merge(
				glob( $root . '/includes/*.php' ) ?: array(),
				glob( $root . '/includes/*/*.php' ) ?: array(),
				glob( $root . '/admin/*.php' ) ?: array(),
				array( $root . '/reportedip-hive.php' )
			);

			$body = '';
			foreach ( $files as $file ) {
				$body .= (string) file_get_contents( $file ) . "\n";
			}

			$this->source_blob = $body;
			return $body;
		}

		/**
		 * Assert that some code path can actually write `$type` into the logs.
		 *
		 * Three ways an event slug reaches the table, and a list that offers it
		 * has to hit one of them: the threshold tracker generates the
		 * `_threshold_exceeded` variants from a base slug, a logging call takes
		 * the literal, or a logging call passes an `EVENT_*` constant that holds
		 * it. The constant fallback still demands a caller, a declaration whose
		 * last call site was deleted would otherwise keep a dead slug alive.
		 *
		 * @param string $type    Event slug under test.
		 * @param string $context Sentence opener naming the list that offers it.
		 */
		private function assert_has_writer( string $type, string $context ): void {
			$sources = $this->sources();

			if ( str_ends_with( $type, '_threshold_exceeded' ) ) {
				$base    = substr( $type, 0, -strlen( '_threshold_exceeded' ) );
				$tracker = '(?:track_generic_attempt|handle_threshold_exceeded)\(';
				$quoted  = preg_quote( $base, '/' );

				if ( 1 === preg_match( '/' . $tracker . '(?:[^;]{0,200}?)\'' . $quoted . '\'/s', $sources ) ) {
					return;
				}

				$this->assertSame(
					1,
					preg_match( '/const\s+([A-Z][A-Z0-9_]*)\s*=\s*\'' . $quoted . '\';/', $sources, $constant ),
					"{$context} '{$type}', but nothing feeds '{$base}' into the threshold tracker."
				);

				$this->assertMatchesRegularExpression(
					'/' . $tracker . '(?:[^;]{0,200}?)(?:self|static|parent|[A-Za-z_][A-Za-z0-9_]*)::' . $constant[1] . '\b/s',
					$sources,
					"{$context} '{$type}': the constant {$constant[1]} holds the slug, but no tracker call passes it."
				);
				return;
			}

			$quoted = preg_quote( $type, '/' );
			$call   = '(?:log_security_event|log_event|log_denied|log_denial|->log|::log)\(';

			if ( 1 === preg_match( '/' . $call . '(?:[^;]{0,240}?)\'' . $quoted . '\'/s', $sources ) ) {
				return;
			}

			preg_match_all( '/' . $call . '(?:[^;]{0,240}?)\'([a-z0-9_]+_)\'\s*\./s', $sources, $prefixes );
			foreach ( $prefixes[1] as $prefix ) {
				if ( str_starts_with( $type, $prefix ) ) {
					return;
				}
			}

			$this->assertSame(
				1,
				preg_match( '/const\s+(EVENT_[A-Z0-9_]+)\s*=\s*\'' . $quoted . '\';/', $sources, $constant ),
				"{$context} '{$type}', but no logging call writes it."
			);

			$this->assertMatchesRegularExpression(
				'/' . $call . '(?:[^;]{0,240}?)(?:self|static|parent|[A-Za-z_][A-Za-z0-9_]*)::' . $constant[1] . '\b/s',
				$sources,
				"{$context} '{$type}': the constant {$constant[1]} still holds the slug, but no logging call passes it."
			);
		}

		public function test_every_counted_event_type_has_a_writer(): void {
			$types = \ReportedIP_Hive_Admin_Firewall::FIREWALL_EVENT_TYPES;
			$this->assertNotEmpty( $types, 'The Firewall page must count event types.' );

			foreach ( $types as $type ) {
				$this->assert_has_writer( $type, 'The Firewall page counts' );
			}
		}

		/**
		 * Event slugs the Logs filter must offer for the features added in
		 * 2.1.51. Each one is written by a class that shipped with them, so a
		 * rename that forgets the filter fails here.
		 */
		private const NEW_FEATURE_EVENTS = array(
			'prohibited_username',
			'registration_denied',
			'registration_limit',
			'unknown_username_probe_threshold_exceeded',
			'rest_denied',
			'xmlrpc_denied',
			'feed_denied',
			'admin_guest_denied',
			'blocked_user_denied',
			'2fa_stepup_required',
			'2fa_stepup_skipped_no_method',
		);

		/**
		 * Every option value of the Logs page event-type filter.
		 *
		 * Since 2.1.62 the select is rendered from the taxonomy registry, so the
		 * registry is what this reads. Parsing the markup would only prove the
		 * renderer loop exists.
		 *
		 * @return string[]
		 */
		private function log_filter_event_types(): array {
			$types = array();
			foreach ( \ReportedIP_Hive_Event_Taxonomy::filter_options() as $options ) {
				foreach ( array_keys( $options ) as $slug ) {
					$types[] = $slug;
				}
			}
			return $types;
		}

		/**
		 * Every literal event slug a logging call writes into the logs table.
		 *
		 * Dynamically built slugs do not match and are covered by the threshold
		 * branch of {@see assert_has_writer()} instead. `Audit_Logger::log_event()`
		 * is excluded because it writes the separate audit table, which has its
		 * own small vocabulary and its own filter.
		 *
		 * @return string[]
		 */
		private function logged_event_types(): array {
			$audit  = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-audit-logger.php' );
			$blob   = str_replace( $audit, '', $this->sources() );
			$call   = '(?<!Audit_Logger::)(?:log_security_event|log_event|log_denied|log_denial)\(\s*\'([a-z0-9_]{3,})\'\s*,';
			preg_match_all( '/' . $call . '/s', $blob, $matches );

			return array_values( array_unique( $matches[1] ) );
		}

		/**
		 * The filter offers a fixed vocabulary; an entry nothing writes is a
		 * dead choice that silently returns an empty result set.
		 */
		public function test_every_filterable_event_type_has_a_writer(): void {
			$types = $this->log_filter_event_types();
			$this->assertNotEmpty( $types, 'The event-type filter must offer choices.' );

			foreach ( $types as $type ) {
				$this->assert_has_writer( $type, 'The Logs filter offers' );
			}
		}

		/**
		 * A new sensor that logs an event nobody can filter for is invisible in
		 * practice, so the filter has to grow with the writers.
		 */
		public function test_every_new_feature_event_is_filterable(): void {
			$types = $this->log_filter_event_types();

			foreach ( self::NEW_FEATURE_EVENTS as $event ) {
				$this->assertContains(
					$event,
					$types,
					"Event '{$event}' is logged but missing from the Logs page event-type filter."
				);
			}
		}

		/**
		 * The inverse guard, and the one that would have caught form spam: a
		 * slug that reaches the logs table without a registry row is unfilterable
		 * and invisible in every chart. Register it, operational rows included,
		 * they simply carry no family.
		 */
		public function test_every_logged_event_type_is_registered(): void {
			$logged = $this->logged_event_types();
			$this->assertNotEmpty( $logged, 'The plugin must write event types.' );

			foreach ( $logged as $type ) {
				$this->assertTrue(
					\ReportedIP_Hive_Event_Taxonomy::is_registered( $type ),
					"Event '{$type}' is written but has no row in ReportedIP_Hive_Event_Taxonomy."
				);
			}
		}

		/**
		 * The Firewall page counts a curated subset; curated or not, every slug
		 * in it has to exist in the registry.
		 */
		public function test_every_counted_event_type_is_registered(): void {
			foreach ( \ReportedIP_Hive_Admin_Firewall::FIREWALL_EVENT_TYPES as $type ) {
				$this->assertTrue(
					\ReportedIP_Hive_Event_Taxonomy::is_registered( $type ),
					"The Firewall page counts '{$type}', which has no registry row."
				);
			}
		}

		/**
		 * The bare base type is the trap that caused the bug: it reads plausible
		 * and is used all over the detector, but it is never a stored event type.
		 */
		public function test_bare_scan_404_is_not_counted(): void {
			$this->assertNotContains(
				'scan_404',
				\ReportedIP_Hive_Admin_Firewall::FIREWALL_EVENT_TYPES,
				'scan_404 is an attempt-tracker key, not a logged event type.'
			);
		}

		/**
		 * The Rule Sync tab iterates `Rule_Store::VALID_KEYS` and falls back to
		 * the raw key with an empty "Feeds" cell for anything `ruleset_meta()`
		 * does not know, which is how `tor_exits` shipped unlabeled.
		 */
		public function test_every_ruleset_key_has_display_metadata(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-admin-firewall.php' );
			$this->assertSame(
				1,
				preg_match( '/function ruleset_meta\(\)\s*\{(.*?)\n\t\}/s', $source, $m ),
				'ruleset_meta() must exist in Admin_Firewall.'
			);

			foreach ( \ReportedIP_Hive_Rule_Store::VALID_KEYS as $key ) {
				$this->assertMatchesRegularExpression(
					'/\'' . preg_quote( $key, '/' ) . '\'\s*=>\s*array\(/',
					$m[1],
					"Ruleset '{$key}' has no label/feeds entry in ruleset_meta(); the Rule Sync tab renders it raw."
				);
			}
		}
	}
}
