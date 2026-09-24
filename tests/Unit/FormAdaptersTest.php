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

		public function test_adapter_table_carries_exactly_the_supported_plugins(): void {
			$this->assertSame(
				array( 'cf7', 'formidable', 'elementor', 'ultimate_member', 'gravity_forms', 'wpforms', 'forminator' ),
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
				'ultimate_member' => array(
					'option'  => 'reportedip_hive_form_proof_um',
					'feature' => 'form_adapters_advanced',
					'detect'  => 'UM_Functions',
				),
				'gravity_forms'   => array(
					'option'  => 'reportedip_hive_form_proof_gravity',
					'feature' => 'form_adapters_advanced',
					'detect'  => 'GFCommon',
				),
				'wpforms'         => array(
					'option'  => 'reportedip_hive_form_proof_wpforms',
					'feature' => 'form_adapters_advanced',
					'detect'  => 'WPForms\\WPForms',
				),
				'forminator'      => array(
					'option'  => 'reportedip_hive_form_proof_forminator',
					'feature' => 'form_adapters_advanced',
					'detect'  => 'Forminator_API',
				),
			);

			$this->assertSame( $expected, \ReportedIP_Hive_Form_Adapters::ADAPTERS );
		}

		/**
		 * The adapter options are the very list the grace stamp watches. A
		 * new adapter added to one table and not the other would never start
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
		 * @param bool   $certain Expected escalation.
		 */
		public function test_consequence_table( string $verdict, bool $strict, bool $refuse, bool $certain ): void {
			$this->assertSame(
				array(
					'refuse'  => $refuse,
					'certain' => $certain,
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
		 * A client without JavaScript is refused but never held against
		 * anybody. This is the single assertion that keeps the feature from
		 * turning a browser setting into a site-wide ban.
		 */
		public function test_a_client_without_javascript_is_never_escalated(): void {
			$outcome = \ReportedIP_Hive_Form_Adapters::consequence( \ReportedIP_Hive_Form_Proof::FAILED, true );

			$this->assertTrue( $outcome['refuse'] );
			$this->assertFalse( $outcome['certain'] );
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
				'elementor field error' => array(
					'$ajax_handler->add_error( self::elementor_first_field( $record ), $message )',
					'Form_Record::validate() only reads the field errors; a message alone lets every submit action, the mail included, run first',
				),
				'gravity render'      => array(
					"add_filter( 'gform_form_tag', array( \$this, 'gravity_anchor' ), 10, 2 )",
					'the anchor has to reach the Gravity Forms markup',
				),
				'gravity validate'    => array(
					"add_filter( 'gform_validation', array( \$this, 'gravity_validate' ), 10, 2 )",
					'Gravity Forms validation is where its submission is refused, in front of the sender',
				),
				'gravity api guard'   => array(
					"'form-submit' === (string) \$context",
					'a submission through GFAPI carries no anchor and must never be read as a refusal',
				),
				'wpforms render'      => array(
					"add_action( 'wpforms_display_submit_before', array( \$this, 'wpforms_anchor' ) )",
					'the anchor has to sit inside the WPForms form element',
				),
				'wpforms validate'    => array(
					"add_action( 'wpforms_process', array( \$this, 'wpforms_validate' ), 10, 3 )",
					'WPForms processing is where its submission is refused, before the entry and the mail',
				),
				'forminator render'   => array(
					"add_filter( 'forminator_render_form_submit_markup', array( \$this, 'forminator_anchor' ) )",
					'the anchor has to sit inside the Forminator form element, which the wider markup filter cannot promise',
				),
				'forminator validate' => array(
					"add_filter( 'forminator_custom_form_submit_errors', array( \$this, 'forminator_validate' ), 10, 3 )",
					'Forminator validation is where its submission is refused, before the entry and the mail',
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
				'gravity wrapper hook'      => array(
					"add_filter( 'gform_form_after_open'",
					'that hook fires before the form element exists and again on the confirmation page',
				),
				'gravity spam route'        => array(
					"add_filter( 'gform_entry_is_spam'",
					'an entry filed as spam is a message the sender was thanked for and nobody reads',
				),
				'gravity silent abort'      => array(
					"add_filter( 'gform_abort_submission_with_confirmation'",
					'a confirmation shown for a dropped submission is a lost message without a warning',
				),
				'wpforms honeypot route'    => array(
					"'wpforms_process_honeypot'",
					'a submission flagged through the honeypot filter is dropped as spam without a word to the sender',
				),
				'wpforms spam entry'        => array(
					"'wpforms_process_spam_entry'",
					'an entry filed as spam is a message the sender was thanked for and nobody reads',
				),
				'forminator spam filter'    => array(
					"'forminator_spam_protection'",
					'that filter drops the submission into the spam folder and shows the sender a success message',
				),
				'forminator honeypot route' => array(
					"'forminator_honeypot'",
					'the plugin honeypot path answers with a confirmation and stores nothing',
				),
			);
		}

		/**
		 * A Forminator refusal has to reach the sender as an error keyed by a
		 * field of the form, because that is the only shape the plugin renders.
		 * The hook runs a second time while attachments are handled, so the
		 * same refusal must not pile up twice.
		 */
		public function test_a_forminator_refusal_is_a_field_error_added_once(): void {
			$source = $this->source();

			$this->assertStringContainsString(
				'$errors[] = array( self::forminator_first_field( $fields ) => $message );',
				$source,
				'the refusal is keyed by a field id, the only shape Forminator renders'
			);
			$this->assertStringContainsString(
				'in_array( $message, $entry, true )',
				$source,
				'the validation hook fires twice on a form with an upload, and a doubled refusal reads as two problems'
			);
		}

		/**
		 * The field a Forminator refusal is attached to, in the shape the
		 * plugin hands over: a list of field descriptors keyed by `name`.
		 */
		public function test_the_forminator_target_field_is_the_first_of_the_submission(): void {
			$this->assertSame(
				'email-1',
				\ReportedIP_Hive_Form_Adapters::forminator_first_field(
					array(
						array( 'name' => 'email-1' ),
						array( 'name' => 'name-1' ),
					)
				)
			);
			$this->assertSame(
				'reportedip_hive',
				\ReportedIP_Hive_Form_Adapters::forminator_first_field( array() ),
				'a submission without a single named field still has to carry the sentence somewhere'
			);
			$this->assertSame(
				'reportedip_hive',
				\ReportedIP_Hive_Form_Adapters::forminator_first_field( 'not an array' )
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
		 *
		 * Since 2.1.66 the enforcement itself lives in
		 * {@see ReportedIP_Hive_Form_Proof::enforce()}, shared with the comment
		 * form, the sign-up and the password reset, so the adapters must hold
		 * no copy of it at all.
		 */
		public function test_only_the_shared_pipeline_produces_a_refusal(): void {
			$source = $this->source();

			$this->assertSame(
				1,
				substr_count( $source, 'private function judge(' ),
				'the pipeline exists exactly once'
			);
			$this->assertSame(
				1,
				substr_count( $source, '->enforce(' ),
				'the shared enforcement is called exactly once'
			);
			$this->assertStringNotContainsString(
				'log_failure(',
				$source,
				'logging a refusal belongs to the shared path, not to an adapter'
			);
			$this->assertStringNotContainsString(
				'track_generic_attempt(',
				$source,
				'counting a refusal belongs to the shared path, not to an adapter'
			);
		}

		/**
		 * A filled decoy escalates at once instead of filling a counter first.
		 *
		 * Until 2.1.66 three of them within a day were needed before anything
		 * happened, so a sender who hit one form once was never blocked and
		 * never reported. The comment surface has treated the same evidence as
		 * certain since 2.1.52; this keeps the two readings together.
		 */
		public function test_a_filled_decoy_escalates_without_a_counter(): void {
			$shared = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-form-proof.php' );

			$this->assertStringContainsString( 'handle_threshold_exceeded(', $shared );
			$this->assertStringNotContainsString(
				'track_generic_attempt(',
				$shared,
				'the certain case no longer waits for a threshold'
			);
			$this->assertStringNotContainsString(
				'reportedip_hive_comment_spam_threshold',
				$shared,
				'the form surfaces no longer borrow the comment counter'
			);
			$this->assertSame( 'form_spam', \ReportedIP_Hive_Form_Proof::ATTEMPT_TYPE );
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::ATTEMPT_TYPE,
				\ReportedIP_Hive_Form_Adapters::ATTEMPT_TYPE,
				'the adapters must report under the same sensor slug as every other surface'
			);
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

		/**
		 * Ultimate Member renders its own markup and validates on its own
		 * hooks, so the names are pinned. `um_after_form_fields` is the only
		 * render hook inside the form element of all three public templates,
		 * and `um_before_form` fires outside it.
		 */
		public function test_the_ultimate_member_hooks_are_the_ones_inside_the_form(): void {
			$source = $this->source();
			$self   = '$this';

			$this->assertStringContainsString( "add_action( 'um_after_form_fields', array( {$self}, 'um_anchor' ) );", $source );
			$this->assertStringContainsString( "add_action( 'um_submit_form_errors_hook', array( {$self}, 'um_validate' ), 20, 2 );", $source );
			$this->assertStringContainsString( "add_action( 'um_reset_password_errors_hook', array( {$self}, 'um_reset_validate' ), 20 );", $source );
			$this->assertStringNotContainsString( "add_action( 'um_before_form'", $source );
		}

		/**
		 * The profile and the account form fire the same render hook. Judging
		 * them would refuse a signed-in member for something they cannot fix.
		 */
		public function test_only_the_public_ultimate_member_forms_take_part(): void {
			$this->assertSame(
				array( 'login', 'register', 'password' ),
				\ReportedIP_Hive_Form_Adapters::UM_MODES
			);

			$source = $this->source();

			$this->assertStringNotContainsString( "'profile'", $source );
			$this->assertStringNotContainsString( "'account'", $source );
		}

		/**
		 * A form set up to sign people in by e-mail carries no `user_login` at
		 * all, so the message has to follow the fields that are actually there.
		 *
		 * @dataProvider provide_um_fields
		 *
		 * @param array<string,mixed> $data     Submitted keys.
		 * @param string              $target   Target from the guard.
		 * @param string              $expected Field the error is hung on.
		 */
		public function test_the_refusal_follows_the_fields_the_form_has( array $data, string $target, string $expected ): void {
			$this->assertSame( $expected, \ReportedIP_Hive_Form_Adapters::um_field( $data, $target ) );
		}

		/**
		 * @return array<string, array{0:array<string,mixed>, 1:string, 2:string}>
		 */
		public static function provide_um_fields(): array {
			return array(
				'username form, name denial'  => array( array( 'user_login' => 'root', 'user_email' => 'a@b.de' ), 'login', 'user_login' ),
				'username form, mail denial'  => array( array( 'user_login' => 'root', 'user_email' => 'a@b.de' ), 'email', 'user_email' ),
				'email as username'           => array( array( 'user_email' => 'a@b.de' ), 'login', 'user_email' ),
				'legacy username key'         => array( array( 'username' => 'root' ), 'generic', 'username' ),
				'nothing recognisable'        => array( array( 'first_name' => 'x' ), 'generic', 'user_login' ),
				'not an array'                => array( array(), 'email', 'user_login' ),
			);
		}

		/**
		 * Ultimate Member calls `wp_insert_user()` itself, so the registration
		 * pipeline has to be invoked here or the sign-up is only caught by the
		 * safety net, with the core wording and after every one of the
		 * plugin's own checks.
		 */
		public function test_a_sign_up_runs_the_registration_pipeline(): void {
			$source = $this->source();

			$this->assertStringContainsString( 'ReportedIP_Hive_Registration_Guard::get_instance()->validate(', $source );
			$this->assertStringContainsString( "ReportedIP_Hive_Registration_Guard::error_target(", $source );
		}

		/**
		 * The pipeline already looks the address up in the community network,
		 * so the sign-up path takes the proof half on its own. One lookup per
		 * submission, not two.
		 */
		public function test_a_sign_up_does_not_spend_the_community_lookup_twice(): void {
			$source = $this->source();
			$self   = '$this';

			$this->assertSame(
				1,
				substr_count( $source, 'ReportedIP_Hive_Reputation_Gate::get_instance()->check(' ),
				'the address is looked up in exactly one place'
			);
			$this->assertStringContainsString( "{$self}->proof_refusal( 'ultimate_member' )", $source );
		}

		/**
		 * The reset form is what somebody reaches for once they are already
		 * locked out, so a page served from a cache filled before the switch
		 * must not close that door.
		 */
		public function test_the_password_reset_never_refuses_a_missing_anchor(): void {
			$self = '$this';

			$this->assertStringContainsString(
				"{$self}->judge( 'ultimate_member', false )",
				$this->source()
			);
		}

		/**
		 * A refused Gravity Forms submission is told so. The refusal travels as
		 * the plugin's own form-level error, which is what it renders above the
		 * form on both the page-load and the background path, and the final
		 * page is the only one judged.
		 */
		public function test_a_gravity_refusal_is_a_form_level_error_on_the_final_page(): void {
			$source = $this->source();

			$this->assertStringContainsString(
				"GFFormDisplay::\$submission[ \$form_id ]['form_level_error'] = \$message;",
				$source,
				'the sender must read why nothing was sent'
			);
			$this->assertStringContainsString( "\$result['is_valid'] = false;", $source );
			$this->assertStringContainsString(
				"'gform_target_page_number_' . \$form_id",
				$source,
				'an earlier page of a multi-page form is a request of its own, not a submission'
			);
		}

		/**
		 * A refused WPForms submission is told so. The refusal is the plugin's
		 * own header error, the one it renders above the form and returns in
		 * the background response; anything in that list stops the entry and
		 * the mail.
		 */
		public function test_a_wpforms_refusal_is_the_processors_header_error(): void {
			$source = $this->source();

			$this->assertStringContainsString(
				"\$process->errors[ \$form_id ]['header'] = \$message;",
				$source,
				'the sender must read why nothing was sent'
			);
			$this->assertStringContainsString( "wpforms()->obj( 'process' )", $source );
		}
	}
}
