<?php
/**
 * Unit tests for the third-party form adapters.
 *
 * Two things are worth pinning down here. The enforcement rule is a pure
 * table, so it is exercised directly: refusing a client that never ran the
 * script is fine, counting it against the address is not, and getting that
 * backwards locks people without JavaScript out of the site. Everything else
 * is a hook contract against three plugins this suite cannot load, so it is
 * anchored by source inspection the way SecurityMonitorBotGuardTest does it.
 * A misspelled hook name fails silently forever otherwise.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.58
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
	 * @covers \ReportedIP_Hive_Form_Adapters
	 */
	class FormAdaptersTest extends TestCase {

		/**
		 * Source of the adapter class.
		 *
		 * @return string
		 */
		private function source(): string {
			$buf = file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-form-adapters.php' );
			$this->assertNotFalse( $buf, 'adapter source must be readable' );
			return (string) $buf;
		}

		public function test_adapter_table_carries_exactly_the_three_supported_plugins(): void {
			$this->assertSame(
				array( 'cf7', 'formidable', 'elementor' ),
				array_keys( \ReportedIP_Hive_Form_Adapters::ADAPTERS )
			);
		}

		public function test_every_adapter_names_its_option_feature_and_detection_class(): void {
			$expected = array(
				'cf7'        => array(
					'option'  => 'reportedip_hive_form_proof_cf7',
					'feature' => 'form_adapters',
					'detect'  => 'WPCF7_Submission',
				),
				'formidable' => array(
					'option'  => 'reportedip_hive_form_proof_formidable',
					'feature' => 'form_adapters_advanced',
					'detect'  => 'FrmAppHelper',
				),
				'elementor'  => array(
					'option'  => 'reportedip_hive_form_proof_elementor',
					'feature' => 'form_adapters_advanced',
					'detect'  => 'ElementorPro\\Modules\\Forms\\Module',
				),
			);

			$this->assertSame( $expected, \ReportedIP_Hive_Form_Adapters::ADAPTERS );
		}

		/**
		 * The adapter options are the very list the grace stamp watches. A
		 * fourth adapter added to one table and not the other would never start
		 * its grace and would refuse every cached page on day one.
		 */
		public function test_adapter_options_match_the_grace_stamp_list(): void {
			$from_table = array();
			foreach ( \ReportedIP_Hive_Form_Adapters::ADAPTERS as $adapter ) {
				$from_table[] = $adapter['option'];
			}

			sort( $from_table );
			$from_proof = \ReportedIP_Hive_Form_Proof::ADAPTER_OPTIONS;
			sort( $from_proof );

			$this->assertSame( $from_proof, $from_table );
		}

		/**
		 * @dataProvider provide_consequences
		 *
		 * @param string $verdict Verdict constant.
		 * @param bool   $strict  Whether the grace has run out.
		 * @param bool   $refuse  Expected refusal.
		 * @param bool   $count   Expected counting.
		 */
		public function test_consequence_table( string $verdict, bool $strict, bool $refuse, bool $count ): void {
			$this->assertSame(
				array(
					'refuse' => $refuse,
					'count'  => $count,
				),
				\ReportedIP_Hive_Form_Adapters::consequence( $verdict, $strict )
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
		 * A client without JavaScript is refused but never tracked. This is the
		 * single assertion that keeps the feature from turning a browser
		 * setting into a site-wide ban.
		 */
		public function test_a_client_without_javascript_is_never_counted(): void {
			$outcome = \ReportedIP_Hive_Form_Adapters::consequence( \ReportedIP_Hive_Form_Proof::FAILED, true );

			$this->assertTrue( $outcome['refuse'] );
			$this->assertFalse( $outcome['count'] );
		}

		/**
		 * @dataProvider provide_required_hooks
		 *
		 * @param string $needle Source fragment that must be present.
		 * @param string $why    Failure hint.
		 */
		public function test_required_hooks_are_registered( string $needle, string $why ): void {
			$this->assertStringContainsString( $needle, $this->source(), $why );
		}

		/**
		 * Hook names and priorities, spelled exactly as the three plugins fire
		 * them.
		 *
		 * @return array<string, array{0:string, 1:string}>
		 */
		public static function provide_required_hooks(): array {
			return array(
				'cf7 render'          => array(
					"add_filter( 'wpcf7_form_elements', array( \$this, 'cf7_anchor' ) )",
					'the anchor has to reach the Contact Form 7 markup',
				),
				'cf7 spam'            => array(
					"add_filter( 'wpcf7_spam', array( \$this, 'cf7_spam' ), 10, 2 )",
					'the spam verdict is where a Contact Form 7 submission is refused',
				),
				'cf7 second bolt'     => array(
					"add_action( 'wpcf7_before_send_mail', array( \$this, 'cf7_before_send_mail' ), 10, 3 )",
					'wpcf7_skip_spam_check can switch the spam stage off entirely',
				),
				'formidable render'   => array(
					"add_action( 'frm_entry_form', array( \$this, 'formidable_anchor' ) )",
					'the anchor has to reach the Formidable entry form',
				),
				'formidable validate' => array(
					"add_filter( 'frm_validate_entry', array( \$this, 'formidable_validate' ), 10, 2 )",
					'Formidable validation is where its submission is refused',
				),
				'elementor render'    => array(
					"add_filter( 'elementor/widget/render_content', array( \$this, 'elementor_anchor' ), 10, 2 )",
					'the anchor has to reach the rendered Elementor widget',
				),
				'elementor validate'  => array(
					"add_action( 'elementor_pro/forms/validation', array( \$this, 'elementor_validate' ), 10, 2 )",
					'Elementor Pro validation is where its submission is refused',
				),
				'proof surfaces'      => array(
					"add_filter( 'reportedip_hive_form_proof_adapters', array( \$this, 'add_surfaces' ) )",
					'without this filter surface_enabled() answers false and nothing renders',
				),
				'reputation surfaces' => array(
					"add_filter( 'reportedip_hive_reputation_form_surfaces', array( \$this, 'add_surfaces' ) )",
					'the community check must cover the contact forms too',
				),
				'early enqueue'       => array(
					"add_action( 'wp_enqueue_scripts', array( \$this, 'enqueue_script' ) )",
					'a widget rendered in wp_footer is past the point a footer script can be enqueued',
				),
			);
		}

		/**
		 * @dataProvider provide_forbidden_fragments
		 *
		 * @param string $needle Source fragment that must be absent.
		 * @param string $why    Failure hint.
		 */
		public function test_forbidden_fragments_are_absent( string $needle, string $why ): void {
			$this->assertStringNotContainsString( $needle, $this->source(), $why );
		}

		/**
		 * The three mistakes that fail silently rather than loudly.
		 *
		 * @return array<string, array{0:string, 1:string}>
		 */
		public static function provide_forbidden_fragments(): array {
			return array(
				'hyphenated elementor hook' => array(
					'elementor-pro/forms/validation',
					'the namespace is elementor_pro with an underscore; the hyphenated spelling never fires',
				),
				'classic submit button'     => array(
					"add_action( 'frm_before_submit_btn'",
					'that hook is skipped when a form uses the newer submit field, leaving it anchorless',
				),
				'record field lookup'       => array(
					'$record->get_field',
					'Form_Record only knows the fields defined in the editor and never sees our anchor',
				),
			);
		}

		/**
		 * The enqueue must reuse the handle Form_Proof registers. A second
		 * handle for the same file would load the script twice and append two
		 * proof fields, and a doubled field name is not what the verdict reads.
		 */
		public function test_the_shared_script_handle_is_reused(): void {
			$source = $this->source();

			$this->assertStringContainsString( 'register_script()', $source );
			$this->assertStringContainsString( "wp_enqueue_script( 'reportedip-hive-form-proof' )", $source );
			$this->assertStringNotContainsString( 'wp_register_script(', $source );
		}

		/**
		 * The refusal is decided in one place. A second copy of the pipeline on
		 * one of the six callbacks is how the surfaces drift apart.
		 */
		public function test_only_the_shared_pipeline_produces_a_refusal(): void {
			$this->assertSame(
				1,
				substr_count( $this->source(), 'private function judge(' ),
				'the pipeline exists exactly once'
			);
			$this->assertSame(
				1,
				substr_count( $this->source(), '$verdict = ReportedIP_Hive_Form_Proof::check(' ),
				'the verdict is read exactly once'
			);
		}

		/**
		 * The counter reuses the comment-spam budget rather than inventing a
		 * fourth threshold nobody would keep in sync.
		 */
		public function test_the_counter_reuses_the_comment_spam_budget(): void {
			$source = $this->source();

			$this->assertStringContainsString( 'reportedip_hive_comment_spam_threshold', $source );
			$this->assertStringContainsString( 'reportedip_hive_comment_spam_timeframe', $source );
			$this->assertStringContainsString( 'track_generic_attempt(', $source );
			$this->assertSame( 'form_spam', \ReportedIP_Hive_Form_Adapters::ATTEMPT_TYPE );
		}

		/**
		 * A refusal never names the field that gave the sender away, otherwise
		 * the message itself is the instruction for getting past it. The
		 * JavaScript hint is the one exception and says nothing about our
		 * fields either.
		 */
		public function test_messages_stay_unrevealing(): void {
			$failed = \ReportedIP_Hive_Form_Adapters::message( \ReportedIP_Hive_Form_Proof::FAILED );
			$other  = \ReportedIP_Hive_Form_Adapters::message( \ReportedIP_Hive_Form_Proof::TRIPPED );

			$this->assertStringContainsString( 'JavaScript', $failed );
			$this->assertNotSame( $failed, $other );
			$this->assertStringNotContainsString( 'field', strtolower( $other ) );
			$this->assertSame(
				$other,
				\ReportedIP_Hive_Form_Adapters::message( \ReportedIP_Hive_Form_Proof::ABSENT ),
				'a missing anchor and a tripped decoy must be indistinguishable to the sender'
			);
		}
	}
}
