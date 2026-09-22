<?php
/**
 * Execution-proof adapters for third-party form plugins.
 *
 * Contact Form 7, Formidable Forms, Elementor Forms and Ultimate Member each
 * render their own markup and run their own validation, so the shared anchor
 * from {@see ReportedIP_Hive_Form_Proof} has to be planted and read back on
 * their hooks. Everything plugin-specific lives here; the verdict, the grace
 * and the field names stay where they were.
 *
 * Ultimate Member is the one adapter that guards more than a message: its
 * registration form opens an account, so it also runs the pipeline that
 * {@see ReportedIP_Hive_Registration_Guard} owns.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.58
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Third-party form adapters.
 *
 * @since 2.1.58
 */
final class ReportedIP_Hive_Form_Adapters {

	/**
	 * Every adapter, keyed by surface identifier. One table decides which
	 * option arms it, which plan covers it and which class proves the plugin
	 * is there, so another form plugin is one entry plus its own hooks.
	 *
	 * @var array<string, array<string, string>>
	 */
	const ADAPTERS = array(
		'cf7'             => array(
			'option'  => 'reportedip_hive_form_proof_cf7',
			'feature' => 'form_adapters',
			'detect'  => 'WPCF7_Submission',
		),
		'formidable'      => array(
			'option'  => 'reportedip_hive_form_proof_formidable',
			'feature' => 'form_adapters_advanced',
			'detect'  => 'FrmAppHelper',
		),
		'elementor'       => array(
			'option'  => 'reportedip_hive_form_proof_elementor',
			'feature' => 'form_adapters_advanced',
			'detect'  => 'ElementorPro\\Modules\\Forms\\Module',
		),
		'ultimate_member' => array(
			'option'  => 'reportedip_hive_form_proof_um',
			'feature' => 'form_adapters',
			'detect'  => 'UM_Functions',
		),
	);

	/**
	 * Ultimate Member form modes this adapter takes part in.
	 *
	 * The profile and account forms run on the same render hook and stay out
	 * on purpose: their sender is signed in, so there is nothing to prove
	 * about them.
	 *
	 * @var string[]
	 */
	const UM_MODES = array( 'login', 'register', 'password' );

	/**
	 * Display names of the supported form plugins, keyed by adapter slug.
	 *
	 * One source, because three surfaces name these plugins to the operator:
	 * the readiness advisory, the quickstart feature list and the hint that
	 * explains why a setting is not in the simple view. A name that drifts
	 * apart between them reads as three different products.
	 *
	 * Product names, so they are deliberately not translated.
	 *
	 * @return array<string, string>
	 * @since  2.1.61
	 */
	public static function names() {
		return array(
			'cf7'             => 'Contact Form 7',
			'formidable'      => 'Formidable Forms',
			'elementor'       => 'Elementor Forms',
			'ultimate_member' => 'Ultimate Member',
		);
	}

	/**
	 * Attempt-tracker key a tripped decoy counts against.
	 */
	const ATTEMPT_TYPE = 'form_spam';

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Form_Adapters|null
	 */
	private static $instance = null;

	/**
	 * Memoised activation state for this request, keyed by surface.
	 *
	 * @var array<string, bool>
	 */
	private $armed = array();

	/**
	 * Memoised refusal for this request, keyed by surface. Contact Form 7 is
	 * judged on two hooks, and without this the second one would count the same
	 * submission against the sender a second time.
	 *
	 * @var array<string, string>
	 */
	private $refusals = array();

	/**
	 * Get the singleton instance.
	 *
	 * @return ReportedIP_Hive_Form_Adapters
	 * @since  2.1.58
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Register every hook unconditionally and decide inside the callback.
	 *
	 * A plan, an option or a plugin can all change after this class is built,
	 * and Elementor renders widgets long after `init`, so asking "is this
	 * adapter on" at registration time would answer a question nobody asked
	 * yet. The price is one string comparison per rendered Elementor widget,
	 * and that comparison runs before anything else.
	 *
	 * @since 2.1.58
	 */
	private function __construct() {
		add_filter( 'reportedip_hive_form_proof_adapters', array( $this, 'add_surfaces' ) );
		add_filter( 'reportedip_hive_reputation_form_surfaces', array( $this, 'add_surfaces' ) );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_script' ) );

		add_filter( 'wpcf7_form_elements', array( $this, 'cf7_anchor' ) );
		add_filter( 'wpcf7_spam', array( $this, 'cf7_spam' ), 10, 2 );
		add_action( 'wpcf7_before_send_mail', array( $this, 'cf7_before_send_mail' ), 10, 3 );

		add_action( 'frm_entry_form', array( $this, 'formidable_anchor' ) );
		add_filter( 'frm_validate_entry', array( $this, 'formidable_validate' ), 10, 2 );

		add_filter( 'elementor/widget/render_content', array( $this, 'elementor_anchor' ), 10, 2 );
		add_action( 'elementor_pro/forms/validation', array( $this, 'elementor_validate' ), 10, 2 );

		add_action( 'um_after_form_fields', array( $this, 'um_anchor' ) );
		add_action( 'um_submit_form_errors_hook', array( $this, 'um_validate' ), 20, 2 );
		add_action( 'um_reset_password_errors_hook', array( $this, 'um_reset_validate' ), 20 );
	}

	/**
	 * Whether the form plugin behind an adapter is installed and loaded.
	 *
	 * Detection alone, without the option and the plan, because the settings
	 * form and the readiness register both need to say "the plugin is here but
	 * the switch is off" and "there is nothing to switch on here".
	 *
	 * @param string $slug Surface identifier.
	 * @return bool
	 * @since  2.1.58
	 */
	public function detected( $slug ) {
		$slug = (string) $slug;

		if ( ! isset( self::ADAPTERS[ $slug ] ) ) {
			return false;
		}

		return class_exists( self::ADAPTERS[ $slug ]['detect'] );
	}

	/**
	 * Whether an adapter takes part in this request. The one place that
	 * decides, so the render hook, the validation hook, the surface filters and
	 * the script enqueue can never disagree with each other.
	 *
	 * @param string $slug Surface identifier.
	 * @return bool
	 * @since  2.1.58
	 */
	public function active( $slug ) {
		$slug = (string) $slug;

		if ( ! isset( $this->armed[ $slug ] ) ) {
			$this->armed[ $slug ] = $this->resolve( $slug );
		}

		return $this->armed[ $slug ];
	}

	/**
	 * Work out whether an adapter is armed.
	 *
	 * @param string $slug Surface identifier.
	 * @return bool
	 * @since  2.1.58
	 */
	private function resolve( $slug ) {
		if ( ! $this->detected( $slug ) ) {
			return false;
		}

		if ( ! ReportedIP_Hive_Option_Routing::get( self::ADAPTERS[ $slug ]['option'], false ) ) {
			return false;
		}

		if ( ! class_exists( 'ReportedIP_Hive_Form_Proof' ) || ! ReportedIP_Hive_Form_Proof::get_instance()->is_enabled() ) {
			return false;
		}

		if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			return false;
		}

		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( self::ADAPTERS[ $slug ]['feature'] );

		return ! empty( $status['available'] );
	}

	/**
	 * Admit every armed adapter to a surface list.
	 *
	 * Serves both `reportedip_hive_form_proof_adapters`, without which the
	 * anchor renders nothing, and `reportedip_hive_reputation_form_surfaces`,
	 * without which a contact form would be the one public surface the
	 * community check does not cover.
	 *
	 * @param mixed $surfaces Surface identifiers.
	 * @return string[]
	 * @since  2.1.58
	 */
	public function add_surfaces( $surfaces ) {
		$surfaces = array_values( (array) $surfaces );

		foreach ( array_keys( self::ADAPTERS ) as $slug ) {
			if ( $this->active( $slug ) && ! in_array( $slug, $surfaces, true ) ) {
				$surfaces[] = $slug;
			}
		}

		return $surfaces;
	}

	/**
	 * Load the proof script on any page of a site running an adapter.
	 *
	 * An Elementor popup or a theme-builder template can render its widget
	 * during `wp_footer`, which is past the point a footer script can still be
	 * enqueued. The anchor would then sit in the page with nothing to fill its
	 * partner field and every submission would read as a client that never ran
	 * the script. Enqueueing up front costs one small file on pages without a
	 * form and removes that whole failure mode.
	 *
	 * @return void
	 * @since  2.1.58
	 */
	public function enqueue_script() {
		if ( ! class_exists( 'ReportedIP_Hive_Form_Proof' ) ) {
			return;
		}

		foreach ( array_keys( self::ADAPTERS ) as $slug ) {
			if ( ! $this->active( $slug ) ) {
				continue;
			}

			ReportedIP_Hive_Form_Proof::get_instance()->register_script();
			wp_enqueue_script( 'reportedip-hive-form-proof' );
			wp_enqueue_style( 'reportedip-hive-form-proof' );

			return;
		}
	}

	/**
	 * Append the anchor to the Contact Form 7 form body. The filtered value is
	 * placed directly before the closing form tag, so no positioning of our own
	 * is needed.
	 *
	 * @param mixed $html Rendered form elements.
	 * @return string
	 * @since  2.1.58
	 */
	public function cf7_anchor( $html ) {
		$html = (string) $html;

		if ( ! $this->active( 'cf7' ) ) {
			return $html;
		}

		return $html . ReportedIP_Hive_Form_Proof::get_instance()->anchor_html( 'cf7' );
	}

	/**
	 * Judge a Contact Form 7 submission through its own spam verdict.
	 *
	 * The reason is written into the plugin's spam log as well, because the
	 * operator looking for the missing enquiry reads that log, not ours.
	 *
	 * @param mixed $spam       Existing spam verdict.
	 * @param mixed $submission Current submission object.
	 * @return bool
	 * @since  2.1.58
	 */
	public function cf7_spam( $spam, $submission ) {
		if ( $spam ) {
			return true;
		}

		$message = $this->refuse( 'cf7' );

		if ( '' === $message ) {
			return false;
		}

		if ( is_object( $submission ) && method_exists( $submission, 'add_spam_log' ) ) {
			$submission->add_spam_log(
				array(
					'agent'  => 'reportedip-hive',
					'reason' => $message,
				)
			);
		}

		return true;
	}

	/**
	 * Second bolt on the Contact Form 7 path.
	 *
	 * `wpcf7_skip_spam_check` lets any plugin switch the whole spam stage off,
	 * and a protection that a third party can silently disable is not one. This
	 * hook runs after that stage either way, so the refusal still lands.
	 *
	 * @param mixed $contact_form Contact form object.
	 * @param bool  $abort        Whether sending is aborted, by reference.
	 * @param mixed $submission   Current submission object.
	 * @return void
	 * @since  2.1.58
	 */
	public function cf7_before_send_mail( $contact_form, &$abort, $submission ) {
		unset( $contact_form );

		$message = $this->refuse( 'cf7' );

		if ( '' === $message ) {
			return;
		}

		$abort = true;

		if ( is_object( $submission ) && method_exists( $submission, 'set_status' ) ) {
			$submission->set_status( 'spam' );
		}

		if ( is_object( $submission ) && method_exists( $submission, 'set_response' ) ) {
			$submission->set_response( $message );
		}
	}

	/**
	 * Plant the anchor inside a Formidable Forms entry form.
	 *
	 * Deliberately not `frm_before_submit_btn`: that hook is skipped entirely
	 * when a form uses the newer submit field instead of the classic button,
	 * which would leave those forms without an anchor and read every genuine
	 * visitor as a direct post.
	 *
	 * @return void
	 * @since  2.1.58
	 */
	public function formidable_anchor() {
		ReportedIP_Hive_Form_Proof::field( 'formidable' );
	}

	/**
	 * Judge a Formidable Forms entry. The return value must stay an array;
	 * Formidable treats a non-array as "no errors at all".
	 *
	 * @param mixed $errors Existing validation errors.
	 * @param mixed $values Submitted entry values.
	 * @return array<string, string>
	 * @since  2.1.58
	 */
	public function formidable_validate( $errors, $values ) {
		unset( $values );

		$errors  = is_array( $errors ) ? $errors : array();
		$message = $this->refuse( 'formidable' );

		if ( '' !== $message ) {
			$errors['rip_form_proof'] = $message;
		}

		return $errors;
	}

	/**
	 * Plant the anchor inside a rendered Elementor form widget.
	 *
	 * The anchor goes before the last closing form tag rather than into the
	 * field wrapper: a multi-step form moves the nodes inside
	 * `.elementor-form-fields-wrapper` around between steps, and a field that
	 * travels with them can end up on a step that is never submitted.
	 *
	 * @param mixed $content Rendered widget markup.
	 * @param mixed $widget  Widget instance.
	 * @return string
	 * @since  2.1.58
	 */
	public function elementor_anchor( $content, $widget ) {
		$content = (string) $content;

		if ( ! is_object( $widget ) || ! method_exists( $widget, 'get_name' ) || 'form' !== $widget->get_name() ) {
			return $content;
		}

		if ( ! $this->active( 'elementor' ) ) {
			return $content;
		}

		$position = strrpos( $content, '</form>' );

		if ( false === $position ) {
			return $content;
		}

		$anchor = ReportedIP_Hive_Form_Proof::get_instance()->anchor_html( 'elementor' );

		if ( '' === $anchor ) {
			return $content;
		}

		return substr( $content, 0, $position ) . $anchor . substr( $content, $position );
	}

	/**
	 * Judge an Elementor Pro form submission.
	 *
	 * The record is deliberately not consulted: `Form_Record::set_fields()`
	 * only knows the fields defined in the editor, so our anchor is invisible
	 * to it. {@see ReportedIP_Hive_Form_Proof::check()} reads the request.
	 *
	 * @param mixed $record       Submitted form record.
	 * @param mixed $ajax_handler Elementor ajax handler.
	 * @return void
	 * @since  2.1.58
	 */
	public function elementor_validate( $record, $ajax_handler ) {
		unset( $record );

		$message = $this->refuse( 'elementor' );

		if ( '' === $message ) {
			return;
		}

		if ( is_object( $ajax_handler ) && method_exists( $ajax_handler, 'add_error_message' ) ) {
			$ajax_handler->add_error_message( $message );
		}
	}

	/**
	 * Plant the anchor in an Ultimate Member form.
	 *
	 * `um_after_form_fields` is the one hook that sits inside the form element
	 * of the login, registration and password-reset templates, so all three are
	 * covered without knowing anything about the fields the operator put on
	 * them.
	 *
	 * @param mixed $args Shortcode arguments of the rendered form.
	 * @return void
	 * @since  2.1.61
	 */
	public function um_anchor( $args ) {
		if ( ! $this->active( 'ultimate_member' ) ) {
			return;
		}

		if ( ! in_array( self::um_mode( $args ), self::UM_MODES, true ) ) {
			return;
		}

		ReportedIP_Hive_Form_Proof::field( 'ultimate_member' );
	}

	/**
	 * Judge an Ultimate Member login or registration.
	 *
	 * Priority 20 puts this behind the plugin's own validation, the same place
	 * its reCAPTCHA extension hooks into. An error on any field is enough to
	 * stop the submission: both handlers return early once the form carries
	 * one.
	 *
	 * @param mixed $submitted_data Sanitised submission.
	 * @param mixed $form_data      Form row of the submitted form.
	 * @return void
	 * @since  2.1.61
	 */
	public function um_validate( $submitted_data, $form_data = array() ) {
		if ( ! $this->active( 'ultimate_member' ) ) {
			return;
		}

		$mode = self::um_mode( $form_data );

		if ( 'login' === $mode ) {
			$this->um_add_error( $submitted_data, $this->refuse( 'ultimate_member' ) );
			return;
		}

		if ( 'register' === $mode ) {
			$this->um_register( $submitted_data );
		}
	}

	/**
	 * Judge an Ultimate Member password-reset request.
	 *
	 * A missing anchor never refuses here. The page carrying the reset form is
	 * the one an operator reaches for when they are already locked out, and a
	 * copy of it served from a cache filled before this adapter was switched on
	 * would otherwise close the last door behind them.
	 *
	 * @param mixed $args Sanitised submission.
	 * @return void
	 * @since  2.1.61
	 */
	public function um_reset_validate( $args ) {
		unset( $args );

		if ( ! $this->active( 'ultimate_member' ) || ! function_exists( 'UM' ) ) {
			return;
		}

		$message = $this->judge( 'ultimate_member', false );

		if ( '' === $message ) {
			return;
		}

		UM()->form()->add_error( 'username_b', $message );
	}

	/**
	 * Judge an Ultimate Member registration.
	 *
	 * Ultimate Member never fires `registration_errors`; it calls
	 * `wp_insert_user()` itself, so without this the registration pipeline
	 * would only catch the sign-up in the `wp_pre_insert_user_data` safety net,
	 * after every one of the plugin's own checks and with nothing but the core
	 * `empty_data` wording to show the visitor. Running it here refuses the
	 * account before it exists and says why.
	 *
	 * The execution proof goes first because it costs nothing, and the
	 * pipeline owns the community lookup for this surface, so the address is
	 * looked up once.
	 *
	 * @param mixed $submitted_data Sanitised submission.
	 * @return void
	 * @since  2.1.61
	 */
	private function um_register( $submitted_data ) {
		$proof = $this->proof_refusal( 'ultimate_member' );

		if ( '' !== $proof ) {
			$this->um_add_error( $submitted_data, $proof );
			return;
		}

		if ( ! class_exists( 'ReportedIP_Hive_Registration_Guard' ) ) {
			return;
		}

		$data   = is_array( $submitted_data ) ? $submitted_data : array();
		$errors = new WP_Error();

		ReportedIP_Hive_Registration_Guard::get_instance()->validate(
			self::um_value( $data, array( 'user_login', 'username' ) ),
			self::um_value( $data, array( 'user_email' ) ),
			$errors,
			'ultimate_member'
		);

		foreach ( $errors->get_error_codes() as $code ) {
			$this->um_add_error(
				$data,
				$errors->get_error_message( $code ),
				self::um_field( $data, ReportedIP_Hive_Registration_Guard::error_target( $code ) )
			);
		}
	}

	/**
	 * Hang a refusal on an Ultimate Member form.
	 *
	 * @param mixed  $submitted_data Sanitised submission.
	 * @param string $message        Refusal text.
	 * @param string $field          Field key, empty to pick one.
	 * @return void
	 * @since  2.1.61
	 */
	private function um_add_error( $submitted_data, $message, $field = '' ) {
		if ( '' === (string) $message || ! function_exists( 'UM' ) ) {
			return;
		}

		if ( '' === (string) $field ) {
			$field = self::um_field( $submitted_data, 'generic' );
		}

		UM()->form()->add_error( $field, $message );
	}

	/**
	 * The mode of an Ultimate Member form.
	 *
	 * The shortcode arguments carry it on render and the form row carries it on
	 * submit. The live field set is the fallback, because a form rendered
	 * without the mode in its arguments would otherwise silently skip the
	 * anchor and then be judged for not carrying one.
	 *
	 * @param mixed $args Shortcode arguments or form row.
	 * @return string
	 * @since  2.1.61
	 */
	private static function um_mode( $args ) {
		if ( is_array( $args ) && isset( $args['mode'] ) ) {
			return (string) $args['mode'];
		}

		if ( function_exists( 'UM' ) && isset( UM()->fields()->set_mode ) ) {
			return (string) UM()->fields()->set_mode;
		}

		return '';
	}

	/**
	 * First submitted value out of a list of keys.
	 *
	 * @param array<string,mixed> $data Sanitised submission.
	 * @param string[]            $keys Keys to try, in order.
	 * @return string
	 * @since  2.1.61
	 */
	private static function um_value( array $data, array $keys ) {
		foreach ( $keys as $key ) {
			if ( isset( $data[ $key ] ) && is_scalar( $data[ $key ] ) ) {
				return (string) $data[ $key ];
			}
		}

		return '';
	}

	/**
	 * The field a refusal is rendered next to.
	 *
	 * Ultimate Member prints an error beside a field that exists on the form,
	 * so the message goes to the submitted key it is about. The order matters
	 * more than the exact hit: a form set up to sign people in by e-mail has no
	 * `user_login` at all.
	 *
	 * @param mixed  $submitted_data Sanitised submission.
	 * @param string $target         Target from the registration guard.
	 * @return string
	 * @since  2.1.61
	 */
	public static function um_field( $submitted_data, $target ) {
		$data  = is_array( $submitted_data ) ? $submitted_data : array();
		$order = 'email' === (string) $target
			? array( 'user_email', 'username', 'user_login' )
			: array( 'user_login', 'username', 'user_email' );

		foreach ( $order as $key ) {
			if ( array_key_exists( $key, $data ) ) {
				return $key;
			}
		}

		return 'user_login';
	}

	/**
	 * Decide one submission and produce its refusal, or an empty string when it
	 * may proceed. Same order as every other surface: plan and switch, then the
	 * community reputation of the address, then the execution proof.
	 *
	 * @param string $slug Surface identifier.
	 * @return string Refusal message, or an empty string to proceed.
	 * @since  2.1.58
	 */
	private function refuse( $slug ) {
		$slug = (string) $slug;

		if ( ! isset( $this->refusals[ $slug ] ) ) {
			$this->refusals[ $slug ] = $this->judge( $slug );
		}

		return $this->refusals[ $slug ];
	}

	/**
	 * Run the pipeline for one submission.
	 *
	 * @param string    $slug   Surface identifier.
	 * @param bool|null $strict Whether a missing anchor counts as a refusal;
	 *                          null reads the adapter grace.
	 * @return string Refusal message, or an empty string to proceed.
	 * @since  2.1.58
	 */
	private function judge( $slug, $strict = null ) {
		if ( ! $this->active( $slug ) ) {
			return '';
		}

		if ( class_exists( 'ReportedIP_Hive_Reputation_Gate' ) ) {
			$reputation = ReportedIP_Hive_Reputation_Gate::get_instance()->check( $slug, ReportedIP_Hive::get_client_ip() );

			if ( '' !== $reputation ) {
				return $reputation;
			}
		}

		return $this->proof_refusal( $slug, $strict );
	}

	/**
	 * The execution-proof half of the pipeline on its own.
	 *
	 * The registration surface needs it separately, because the registration
	 * pipeline already looks the address up in the community network and the
	 * same sign-up must not spend that lookup twice.
	 *
	 * @param string    $slug   Surface identifier.
	 * @param bool|null $strict Whether a missing anchor counts as a refusal;
	 *                          null reads the adapter grace.
	 * @return string Refusal message, or an empty string to proceed.
	 * @since  2.1.61
	 */
	private function proof_refusal( $slug, $strict = null ) {
		if ( ! $this->active( $slug ) ) {
			return '';
		}

		$proof   = ReportedIP_Hive_Form_Proof::get_instance();
		$verdict = ReportedIP_Hive_Form_Proof::check( $slug );
		$outcome = self::consequence( $verdict, null === $strict ? $proof->adapters_strict() : (bool) $strict );

		if ( ! $outcome['refuse'] ) {
			return '';
		}

		$proof->log_failure( $slug );

		if ( $outcome['count'] ) {
			$this->count_attempt( ReportedIP_Hive::get_client_ip() );
		}

		if ( $proof->report_only() ) {
			return '';
		}

		return self::message( $verdict );
	}

	/**
	 * What a verdict costs a submission. Pure, because this is the whole
	 * enforcement rule and it deserves to be pinned down on its own.
	 *
	 * Only a filled decoy is counted against the address. A client that never
	 * ran the script is refused but never tracked: somebody browsing without
	 * JavaScript produces exactly that, and locking them out of the site is a
	 * far worse outcome than the submission they were trying to send. A
	 * submission that never carried our anchor is refused only once the grace
	 * after switching the adapter on has run out, and is never counted either.
	 *
	 * @param string $verdict Verdict from {@see ReportedIP_Hive_Form_Proof::check()}.
	 * @param bool   $strict  Whether a missing anchor counts as a refusal.
	 * @return array{refuse:bool, count:bool}
	 * @since  2.1.58
	 */
	public static function consequence( $verdict, $strict ) {
		if ( ReportedIP_Hive_Form_Proof::TRIPPED === $verdict ) {
			return array(
				'refuse' => true,
				'count'  => true,
			);
		}

		if ( ReportedIP_Hive_Form_Proof::FAILED === $verdict ) {
			return array(
				'refuse' => true,
				'count'  => false,
			);
		}

		if ( ReportedIP_Hive_Form_Proof::ABSENT === $verdict ) {
			return array(
				'refuse' => (bool) $strict,
				'count'  => false,
			);
		}

		return array(
			'refuse' => false,
			'count'  => false,
		);
	}

	/**
	 * Count one tripped decoy against the source address, on the same threshold
	 * and window the comment surface uses. Spam arriving through a contact form
	 * is the same address doing the same thing, so it gets the same budget
	 * rather than a second set of numbers to keep in sync.
	 *
	 * @param string $ip Client address.
	 * @return void
	 * @since  2.1.58
	 */
	private function count_attempt( $ip ) {
		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return;
		}

		$monitor = ReportedIP_Hive::get_instance()->get_security_monitor();

		if ( ! $monitor instanceof ReportedIP_Hive_Security_Monitor ) {
			return;
		}

		$monitor->track_generic_attempt(
			$ip,
			self::ATTEMPT_TYPE,
			self::ATTEMPT_TYPE,
			(int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_spam_threshold', 3 ),
			(int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_spam_timeframe', 1440 )
		);
	}

	/**
	 * The refusal a visitor sees.
	 *
	 * A client that never ran the script is told what to do about it, because
	 * that is a real person with JavaScript switched off often enough to be
	 * worth the sentence. Every other refusal stays short and says nothing
	 * about which field gave the sender away.
	 *
	 * @param string $verdict Verdict from {@see ReportedIP_Hive_Form_Proof::check()}.
	 * @return string
	 * @since  2.1.58
	 */
	public static function message( $verdict ) {
		if ( ReportedIP_Hive_Form_Proof::FAILED === $verdict ) {
			return __( 'This form needs JavaScript to be submitted. Switch it on and try again.', 'reportedip-hive' );
		}

		return __( 'Your submission was not accepted. Please reload the page and try again.', 'reportedip-hive' );
	}
}
