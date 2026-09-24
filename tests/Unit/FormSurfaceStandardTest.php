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
		 * @param bool   $count   Expected counting.
		 */
		public function test_the_rule_is_the_same_for_every_surface( string $verdict, bool $strict, bool $refuse, bool $count ): void {
			$this->assertSame(
				array(
					'refuse' => $refuse,
					'count'  => $count,
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
		public function test_a_filled_decoy_always_refuses_and_always_counts(): void {
			foreach ( array( true, false ) as $strict ) {
				$outcome = \ReportedIP_Hive_Form_Proof::consequence( \ReportedIP_Hive_Form_Proof::TRIPPED, $strict );

				$this->assertTrue( $outcome['refuse'], 'a filled decoy is never let through' );
				$this->assertTrue( $outcome['count'], 'a filled decoy always costs the address' );
			}
		}

		/**
		 * A visitor without JavaScript is refused but never counted, whatever
		 * surface they landed on. Getting this backwards turns a browser
		 * setting into a site-wide ban.
		 */
		public function test_a_visitor_without_javascript_is_never_counted(): void {
			foreach ( array( true, false ) as $strict ) {
				$outcome = \ReportedIP_Hive_Form_Proof::consequence( \ReportedIP_Hive_Form_Proof::FAILED, $strict );

				$this->assertTrue( $outcome['refuse'] );
				$this->assertFalse( $outcome['count'] );
			}
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
