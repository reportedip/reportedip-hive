<?php
/**
 * The standard every protected form has to meet.
 *
 * Eight surfaces carry the execution proof: the comment form, the sign-up,
 * the password reset and the six third-party adapters. Each one was added at
 * a different time, and three of them ended up with their own reading of the
 * same four verdicts. Two of those readings let a filled decoy through, which
 * is the strongest bot signal the layer has.
 *
 * These tests pin the rule down in one place and make it expensive to add a
 * ninth surface with a ninth opinion. Extending the rule stays easy: change
 * `consequence()` and every surface moves with it.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.66
 */

namespace {
	if ( ! function_exists( 'wp_salt' ) ) {
		function wp_salt( $scheme = 'auth' ) {
			return 'unit-test-salt-' . $scheme;
		}
	}

	if ( ! function_exists( '__' ) ) {
		function __( $text, $domain = 'default' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return $text;
		}
	}

	if ( ! function_exists( 'wp_generate_password' ) ) {
		function wp_generate_password( $length = 12, $special_chars = true, $extra_special_chars = false ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return substr( str_repeat( 'a1b2c3d4e5f6', (int) ceil( $length / 12 ) ), 0, (int) $length );
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-form-proof.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-form-adapters.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-readiness.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-promo-manager.php';
	require_once dirname( __DIR__, 2 ) . '/admin/class-dashboard-next-steps.php';

	/**
	 * @covers \ReportedIP_Hive_Form_Proof
	 */
	class FormSurfaceStandardTest extends TestCase {

		/**
		 * Files that may read a verdict without handing it to the shared rule,
		 * each with the reason it is allowed to.
		 *
		 * A new entry here is a deliberate exception and needs a sentence that
		 * says why this surface is different. Anything else belongs in
		 * {@see \ReportedIP_Hive_Form_Proof::enforce()}.
		 *
		 * @var array<string, string>
		 */
		private const READERS = array(
			'class-form-proof.php'         => 'owns the rule',
			'class-form-adapters.php'      => 'delegates to it and keeps the old method names',
			'class-comment-spam-filter.php' => 'scores a comment instead of refusing it, by design',
			'class-ajax-handler.php'       => 'rebuilds a verdict for the Tools self-test, which enforces nothing',
		);

		/**
		 * Source of one shipped class.
		 *
		 * @param string $file File name below includes/.
		 * @return string
		 */
		private function source( string $file ): string {
			$buf = file_get_contents( dirname( __DIR__, 2 ) . '/includes/' . $file );
			$this->assertNotFalse( $buf, $file . ' must be readable' );

			return (string) $buf;
		}

		/**
		 * @dataProvider provide_consequences
		 *
		 * @param string $verdict Verdict constant.
		 * @param bool   $strict  Whether a missing anchor counts.
		 * @param bool   $refuse  Expected refusal.
		 * @param bool   $certain Expected escalation.
		 */
		public function test_the_rule_is_the_same_for_every_surface( string $verdict, bool $strict, bool $refuse, bool $certain ): void {
			$this->assertSame(
				array(
					'refuse'  => $refuse,
					'certain' => $certain,
				),
				\ReportedIP_Hive_Form_Proof::consequence( $verdict, $strict )
			);
		}

		/**
		 * All eight combinations of the four verdicts and the grace.
		 *
		 * @return array<string, array{0:string, 1:bool, 2:bool, 3:bool}>
		 */
		public static function provide_consequences(): array {
			return array(
				'proved, lenient'  => array( \ReportedIP_Hive_Form_Proof::PROVED, false, false, false ),
				'proved, strict'   => array( \ReportedIP_Hive_Form_Proof::PROVED, true, false, false ),
				'failed, lenient'  => array( \ReportedIP_Hive_Form_Proof::FAILED, false, true, false ),
				'failed, strict'   => array( \ReportedIP_Hive_Form_Proof::FAILED, true, true, false ),
				'tripped, lenient' => array( \ReportedIP_Hive_Form_Proof::TRIPPED, false, true, true ),
				'tripped, strict'  => array( \ReportedIP_Hive_Form_Proof::TRIPPED, true, true, true ),
				'absent, lenient'  => array( \ReportedIP_Hive_Form_Proof::ABSENT, false, false, false ),
				'absent, strict'   => array( \ReportedIP_Hive_Form_Proof::ABSENT, true, true, false ),
			);
		}

		/**
		 * The adapter entry point is a delegate, so it cannot drift away from
		 * the shared rule without this failing.
		 */
		public function test_the_adapter_entry_point_cannot_drift(): void {
			foreach ( self::provide_consequences() as $case ) {
				$this->assertSame(
					\ReportedIP_Hive_Form_Proof::consequence( $case[0], $case[1] ),
					\ReportedIP_Hive_Form_Adapters::consequence( $case[0], $case[1] ),
					'the adapters must read the verdict exactly as every other surface does'
				);
			}
		}

		/**
		 * A filled decoy is the clearest evidence the layer produces, and it
		 * has to cost the sender the same everywhere. The sign-up and the
		 * password reset ignored it until 2.1.66.
		 */
		public function test_a_filled_decoy_always_refuses_and_always_escalates(): void {
			foreach ( array( true, false ) as $strict ) {
				$outcome = \ReportedIP_Hive_Form_Proof::consequence( \ReportedIP_Hive_Form_Proof::TRIPPED, $strict );

				$this->assertTrue( $outcome['refuse'], 'a filled decoy is never let through' );
				$this->assertTrue( $outcome['certain'], 'a filled decoy always costs the address at once' );
			}
		}

		/**
		 * A visitor without JavaScript is refused but never held against
		 * anybody, whatever surface they landed on. Getting this backwards
		 * turns a browser setting into a site-wide ban.
		 */
		public function test_a_visitor_without_javascript_is_never_escalated(): void {
			foreach ( array( true, false ) as $strict ) {
				$outcome = \ReportedIP_Hive_Form_Proof::consequence( \ReportedIP_Hive_Form_Proof::FAILED, $strict );

				$this->assertTrue( $outcome['refuse'] );
				$this->assertFalse( $outcome['certain'] );
			}
		}

		/**
		 * The certain case skips the attempt counter and goes straight to the
		 * sensor dispatcher, which is where a tripped threshold goes: block
		 * ladder, community report, admin mail. Until 2.1.66 a single sender
		 * filling a decoy paid nothing but one counter tick.
		 */
		public function test_a_certain_verdict_reaches_the_sensor_dispatcher(): void {
			$proof = $this->source( 'class-form-proof.php' );

			$this->assertStringContainsString(
				'handle_threshold_exceeded(',
				$proof,
				'a certain bot has to reach the same consequences a tripped threshold reaches'
			);
			$this->assertStringContainsString(
				"if ( \$outcome['certain'] ) {",
				$proof,
				'the escalation is decided by the shared rule, not by a verdict comparison of its own'
			);
			$this->assertStringNotContainsString(
				'track_generic_attempt(',
				$proof,
				'the form surfaces no longer wait for a counter to fill up'
			);
		}

		/**
		 * The dispatcher is now reached without the counter that used to guard
		 * it, so the address has to be looked up in the whitelist there. An
		 * office address autofilling a hidden field must never be blocked and
		 * reported, and neither the auto-block path nor the block writer looks
		 * it up again.
		 */
		public function test_the_dispatcher_spares_a_whitelisted_address(): void {
			$monitor = $this->source( 'class-security-monitor.php' );
			$body    = substr( $monitor, (int) strpos( $monitor, 'public function handle_threshold_exceeded(' ) );
			$body    = substr( $body, 0, (int) strpos( $body, 'do_action(' ) );

			$this->assertStringContainsString(
				'is_whitelisted( $ip_address )',
				$body,
				'handle_threshold_exceeded() has to spare a whitelisted address before any consequence runs'
			);
		}

		/**
		 * `passes()` is the published contract for a form this plugin does not
		 * own. It has to answer exactly what the rule says, or a site that
		 * builds on it gets different protection than the shipped surfaces.
		 */
		public function test_the_published_contract_answers_the_same_rule(): void {
			$reflection = new \ReflectionMethod( \ReportedIP_Hive_Form_Proof::class, 'passes' );

			$this->assertTrue( $reflection->isStatic(), 'passes() is called without an instance' );
			$this->assertStringContainsString(
				'self::consequence(',
				$this->source( 'class-form-proof.php' ),
				'passes() has to read the shared rule rather than repeat it'
			);
		}

		/**
		 * Nobody outside the allowlist decides on a verdict of their own.
		 *
		 * This is the guard that makes a ninth surface meet the standard: the
		 * moment a new file compares a verdict itself, this names it and says
		 * where the decision belongs.
		 */
		public function test_no_surface_decides_on_a_verdict_of_its_own(): void {
			$files = glob( dirname( __DIR__, 2 ) . '/includes/*.php' );

			$this->assertNotEmpty( $files, 'No source file was scanned, the file walk has drifted from the tree.' );

			$offenders = array();
			$scanned   = 0;

			foreach ( (array) $files as $path ) {
				$name = basename( (string) $path );

				if ( isset( self::READERS[ $name ] ) ) {
					continue;
				}

				$body = (string) file_get_contents( (string) $path );

				if ( false === strpos( $body, 'ReportedIP_Hive_Form_Proof::' ) ) {
					continue;
				}

				++$scanned;

				foreach ( array( 'TRIPPED', 'FAILED', 'ABSENT', 'PROVED' ) as $verdict ) {
					if ( false !== strpos( $body, 'ReportedIP_Hive_Form_Proof::' . $verdict ) ) {
						$offenders[] = $name . ' compares ' . $verdict;
					}
				}
			}

			$this->assertGreaterThan( 0, $scanned, 'No consumer of the form proof was scanned, the search pattern has drifted.' );
			$this->assertSame(
				array(),
				$offenders,
				"A protected form must hand its verdict to ReportedIP_Hive_Form_Proof::enforce() instead of reading it:\n"
					. implode( "\n", $offenders )
			);
		}

		/**
		 * The two surface tables together are the whole list, and they never
		 * name the same surface twice. A duplicate would give one form two
		 * field names and two graces.
		 */
		public function test_the_surface_tables_do_not_overlap(): void {
			$own      = \ReportedIP_Hive_Form_Proof::SURFACES;
			$adapters = array_keys( \ReportedIP_Hive_Form_Adapters::ADAPTERS );

			$this->assertSame(
				array(),
				array_intersect( $own, $adapters ),
				'a surface belongs either to this plugin or to an adapter, never to both'
			);

			$all = array_merge( $own, $adapters );

			$this->assertSame( count( $all ), count( array_unique( $all ) ), 'every surface is named once' );
		}

		/**
		 * A new adapter is only half done when its callbacks work: the switch
		 * has to be a setting, the plan has to switch it on where the plan
		 * covers it, and the operator has to be told about it while it is off.
		 * Each of those lives in a different file, and each of them was
		 * forgotten at least once.
		 *
		 * @dataProvider provide_adapters
		 *
		 * @param string $slug    Adapter slug.
		 * @param string $option  Its switch.
		 * @param string $feature Its plan gate.
		 */
		public function test_every_adapter_is_wired_into_the_settings_surfaces( string $slug, string $option, string $feature ): void {
			$this->assertArrayHasKey(
				$option,
				\ReportedIP_Hive_Defaults::all_option_defaults(),
				$slug . ' needs a default, or an install never seeds the switch'
			);

			$spec = \ReportedIP_Hive_Settings_Registry::spec();

			$this->assertArrayHasKey( $option, $spec, $slug . ' needs a registry entry, or no form draws it' );
			$this->assertSame( 'forms', $spec[ $option ]['section'] );
			$this->assertSame( $slug, $spec[ $option ]['simple_form'], 'the switch shows up on a site that runs this plugin' );
			if ( 'form_adapters_advanced' === $feature ) {
				$this->assertSame(
					$feature,
					isset( $spec[ $option ]['tier'] ) ? $spec[ $option ]['tier'] : '',
					'a paid adapter needs its plan gate, or the sanitizer lets the value through below the plan'
				);
			} else {
				$this->assertArrayNotHasKey(
					'tier',
					$spec[ $option ],
					'a free adapter carries no plan gate, which is what made it free in 2.1.63'
				);
			}
			$this->assertContains(
				'stamp_form_adapters_since',
				(array) $spec[ $option ]['side_effects'],
				'without the stamp the grace never starts and every cached page is refused on day one'
			);

			$step = 'form_adapter_' . $slug;

			$this->assertArrayHasKey(
				$step,
				\ReportedIP_Hive_Dashboard_Next_Steps::step_actions(),
				'the dashboard has to offer the switch while it is off'
			);
			$this->assertSame(
				array( $option => 1 ),
				\ReportedIP_Hive_Dashboard_Next_Steps::step_values( $step, array() )
			);

			$this->assertNotNull(
				\ReportedIP_Hive_Readiness::form_adapter_off( $slug, 'Plugin', true, true, false ),
				'an installed plugin the plan covers has to be advised while the switch is off'
			);
			$this->assertNull(
				\ReportedIP_Hive_Readiness::form_adapter_off( $slug, 'Plugin', true, true, true ),
				'nothing to advise once it runs'
			);
			$this->assertNull(
				\ReportedIP_Hive_Readiness::form_adapter_off( $slug, 'Plugin', false, true, false ),
				'a plugin that is not installed is not a finding'
			);
			$this->assertNull(
				\ReportedIP_Hive_Readiness::form_adapter_off( $slug, 'Plugin', true, false, false ),
				'a plan that does not cover it is an upsell, not a finding'
			);
		}

		/**
		 * The plan that includes an adapter also switches it on, both in the
		 * quickstart and in the upgrade delta, which read the same table.
		 *
		 * @dataProvider provide_adapters
		 *
		 * @param string $slug    Adapter slug.
		 * @param string $option  Its switch.
		 * @param string $feature Its plan gate.
		 */
		public function test_the_plan_that_covers_an_adapter_switches_it_on( string $slug, string $option, string $feature ): void {
			$business = \ReportedIP_Hive_Defaults::recommended( 'business', 'community' );

			$this->assertArrayHasKey( $option, $business, $slug . ' is included in Business and has to be recommended there' );
			$this->assertSame( 1, $business[ $option ] );

			$professional = \ReportedIP_Hive_Defaults::recommended( 'professional', 'community' );

			if ( 'form_adapters_advanced' === $feature ) {
				$this->assertArrayNotHasKey(
					$option,
					$professional,
					$slug . ' needs Business, so recommending it below that writes a value the sanitizer refuses'
				);

				return;
			}

			$this->assertSame( 1, $professional[ $option ] );
		}

		/**
		 * Every adapter, as the one table names them.
		 *
		 * @return array<string, array{0:string, 1:string, 2:string}>
		 */
		public static function provide_adapters(): array {
			$cases = array();

			foreach ( \ReportedIP_Hive_Form_Adapters::ADAPTERS as $slug => $adapter ) {
				$cases[ $slug ] = array( $slug, $adapter['option'], $adapter['feature'] );
			}

			return $cases;
		}

		/**
		 * Both surfaces this plugin refuses on route through the shared path.
		 */
		public function test_the_own_refusing_surfaces_use_the_shared_path(): void {
			$proof = $this->source( 'class-form-proof.php' );
			$guard = $this->source( 'class-registration-guard.php' );

			$this->assertStringContainsString(
				"\$this->enforce( 'lostpassword'",
				$proof,
				'the password reset has to go through the shared enforcement'
			);
			$this->assertStringContainsString(
				"enforce( 'register'",
				$guard,
				'the sign-up has to go through the shared enforcement'
			);
		}
	}
}
