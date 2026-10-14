<?php
/**
 * Execution-proof adapters for third-party form plugins.
 *
 * A third-party form plugin renders its own markup and runs its own
 * validation, so the shared anchor from {@see ReportedIP_Hive_Form_Proof} has
 * to be planted and read back on its hooks. This class owns the adapter
 * table, the rule that arms an adapter, the surface filters, the script and
 * the pipeline that decides a submission, and it ships the Contact Form 7
 * adapter. An add-on registers further adapters through the
 * `reportedip_hive_form_adapters` filter and hangs its own render and
 * validation hooks onto {@see refuse()}; the verdict, the grace and the field
 * names stay where they were.
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
	 * The bundled adapters, keyed by surface identifier. One table decides
	 * which option arms it, which plan covers it and which class proves the
	 * plugin is there, so another form plugin is one entry plus its own hooks.
	 * Read through {@see adapters()}, which adds what an add-on registers.
	 *
	 * @var array<string, array<string, string>>
	 */
	const ADAPTERS = array(
		'cf7' => array(
			'option'  => 'reportedip_hive_form_proof_cf7',
			'feature' => 'form_adapters',
			'detect'  => 'WPCF7_Submission',
		),
	);

	/**
	 * Display names of the supported form plugins, keyed by adapter slug.
	 *
	 * One source, because three surfaces name these plugins to the operator:
	 * the readiness advisory, the quickstart feature list and the hint that
	 * explains why a switch waits in the technical details. A name that drifts
	 * apart between them reads as three different products.
	 *
	 * Product names, so they are deliberately not translated.
	 *
	 * @return array<string, string>
	 * @since  2.1.61
	 */
	public static function names() {
		/**
		 * Display names of the registered form plugins, keyed by adapter slug.
		 *
		 * @param array<string, string> $names Slug to product name.
		 * @since 3.0.0
		 */
		return (array) apply_filters( 'reportedip_hive_form_adapter_names', array( 'cf7' => 'Contact Form 7' ) );
	}

	/**
	 * The adapters this site knows: the bundled Contact Form 7 adapter plus
	 * whatever an add-on registers.
	 *
	 * @return array<string, array<string, string>>
	 * @since  3.0.0
	 */
	public static function adapters() {
		/**
		 * Register further form adapters (option, feature, detect class).
		 *
		 * @param array<string, array<string, string>> $adapters Slug to definition.
		 * @since 3.0.0
		 */
		return (array) apply_filters( 'reportedip_hive_form_adapters', self::ADAPTERS );
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
	 * and an adapter an add-on registers renders long after `init`, so asking
	 * "is this adapter on" at registration time would answer a question
	 * nobody asked yet. {@see active()} is memoised per request and runs
	 * before anything else in every callback.
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

		$adapters = self::adapters();

		if ( ! isset( $adapters[ $slug ]['detect'] ) ) {
			return false;
		}

		return class_exists( $adapters[ $slug ]['detect'] );
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

		$adapter = self::adapters()[ $slug ];

		if ( ! isset( $adapter['option'], $adapter['feature'] ) || ! ReportedIP_Hive_Option_Routing::get( $adapter['option'], false ) ) {
			return false;
		}

		if ( ! class_exists( 'ReportedIP_Hive_Form_Proof' ) || ! ReportedIP_Hive_Form_Proof::get_instance()->is_enabled() ) {
			return false;
		}

		if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			return false;
		}

		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( $adapter['feature'] );

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

		foreach ( array_keys( self::adapters() ) as $slug ) {
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

		foreach ( array_keys( self::adapters() ) as $slug ) {
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
	 * Decide one submission and produce its refusal, or an empty string when it
	 * may proceed. Same order as every other surface: plan and switch, then the
	 * community reputation of the address, then the execution proof.
	 *
	 * Public since 3.0.0, so an adapter an add-on registers decides through
	 * the same memoised pipeline. Contact Form 7 is judged on two hooks, and
	 * the memo keeps the second one from counting the submission again.
	 *
	 * @param string $slug Surface identifier.
	 * @return string Refusal message, or an empty string to proceed.
	 * @since  2.1.58
	 */
	public function refuse( $slug ) {
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
	public function judge( $slug, $strict = null ) {
		if ( ! $this->active( $slug ) ) {
			return '';
		}

		if ( class_exists( 'ReportedIP_Hive_Reputation_Gate' ) ) {
			$reputation = ReportedIP_Hive_Reputation_Gate::get_instance()->check( $slug, ReportedIP_Hive::get_client_ip() );

			if ( '' !== $reputation ) {
				return $reputation;
			}
		}

		$refusal = $this->proof_refusal( $slug, $strict );
		if ( '' !== $refusal || 'ultimate_member' === $slug || ! class_exists( 'ReportedIP_Hive_Disposable_Email' ) ) {
			return $refusal;
		}

		return ReportedIP_Hive_Disposable_Email::get_instance()->check_submission(
			$slug,
			ReportedIP_Hive_Disposable_Email::emails_in( wp_unslash( $_POST ) ) // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Read-only scan for address shapes on a submission the form plugin itself verifies; every value passes is_email().
		);
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
	public function proof_refusal( $slug, $strict = null ) {
		if ( ! $this->active( $slug ) ) {
			return '';
		}

		$proof = ReportedIP_Hive_Form_Proof::get_instance();

		return $proof->enforce( $slug, null === $strict ? $proof->adapters_strict() : (bool) $strict );
	}

	/**
	 * What a verdict costs a submission.
	 *
	 * The rule itself lives in {@see ReportedIP_Hive_Form_Proof::consequence()}
	 * since 2.1.66, because the comment form, the sign-up and the password
	 * reset need exactly the same reading and used to carry their own. This
	 * stays as the name the adapters and their tests already use.
	 *
	 * @param string $verdict Verdict from {@see ReportedIP_Hive_Form_Proof::check()}.
	 * @param bool   $strict  Whether a missing anchor counts as a refusal.
	 * @return array{refuse:bool, certain:bool}
	 * @since  2.1.58
	 */
	public static function consequence( $verdict, $strict ) {
		return ReportedIP_Hive_Form_Proof::consequence( $verdict, $strict );
	}

	/**
	 * The refusal a visitor sees.
	 *
	 * Shared with every other surface since 2.1.66; see
	 * {@see ReportedIP_Hive_Form_Proof::message()}.
	 *
	 * @param string $verdict Verdict from {@see ReportedIP_Hive_Form_Proof::check()}.
	 * @return string
	 * @since  2.1.58
	 */
	public static function message( $verdict ) {
		return ReportedIP_Hive_Form_Proof::message( $verdict );
	}
}
