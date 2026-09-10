<?php
/**
 * Form execution proof.
 *
 * Answers one question about a submission: did the sender ever render our form
 * and run its script? Content heuristics are an arms race, but a client that
 * posts straight at an endpoint without ever loading a page cannot be mistaken
 * for a reader. The server plants one hidden anchor field, a small script adds
 * a second field whose name is random per install, and the pair is read back on
 * submit.
 *
 * Nothing request-specific is ever emitted, so a full-page cache cannot
 * invalidate the proof.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.53
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Execution-proof layer shared by every protected form surface.
 *
 * @since 2.1.53
 */
class ReportedIP_Hive_Form_Proof {

	/**
	 * Master enable toggle.
	 */
	const OPT_ENABLED = 'reportedip_hive_form_proof_enabled';

	/**
	 * Per-install proof field name.
	 */
	const OPT_FIELD = 'reportedip_hive_form_proof_field';

	/**
	 * Unix time an anchor was last rendered on a comment form.
	 */
	const OPT_SEEN = 'reportedip_hive_form_proof_seen';

	/**
	 * Whether the sign-up and password-reset forms take part.
	 */
	const OPT_LOGIN_FORMS = 'reportedip_hive_form_proof_login_forms';

	/**
	 * Surfaces whose refusal is absolute rather than a scoring signal, and
	 * which are therefore governed by {@see OPT_LOGIN_FORMS} together.
	 *
	 * @var string[]
	 */
	const HARD_SURFACES = array( 'register', 'lostpassword' );

	/**
	 * The submission carried every field and the anchor was filled in.
	 */
	const TRIPPED = 'tripped';

	/**
	 * The client ran our script.
	 */
	const PROVED = 'proved';

	/**
	 * We rendered here, the script never ran.
	 */
	const FAILED = 'failed';

	/**
	 * We never rendered into this form.
	 */
	const ABSENT = 'absent';

	/**
	 * How long a recorded render keeps vouching that this site plants anchors.
	 * A site that stops rendering (theme swap, feature switched off) falls back
	 * to the lenient reading within a month.
	 */
	const SEEN_TTL = 2592000;

	/**
	 * Minimum gap between two writes of {@see OPT_SEEN}. The value only has to
	 * be roughly current, and a comment form renders on every article view.
	 */
	const SEEN_THROTTLE = 86400;

	/**
	 * Surfaces that plant an anchor, keyed by identifier.
	 */
	const SURFACES = array( 'comment', 'register', 'lostpassword' );

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Form_Proof|null
	 */
	private static $instance = null;

	/**
	 * Memoised field name for this request.
	 *
	 * @var string|null
	 */
	private $field = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return ReportedIP_Hive_Form_Proof
	 * @since  2.1.53
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Register the script handle and the two login-surface adapters. The
	 * comment anchor belongs to {@see ReportedIP_Hive_Comment_Honeypot}, the
	 * registration check to {@see ReportedIP_Hive_Registration_Guard}: each
	 * surface keeps exactly one owning class.
	 *
	 * @since 2.1.53
	 */
	private function __construct() {
		add_action( 'wp_enqueue_scripts', array( $this, 'register_script' ) );
		add_action( 'login_enqueue_scripts', array( $this, 'register_script' ) );
		add_action( 'admin_init', array( $this, 'ensure_field_name' ) );
		add_action( 'register_form', array( $this, 'print_register_anchor' ) );
		add_action( 'lostpassword_form', array( $this, 'print_lostpassword_anchor' ) );
		add_action( 'lostpassword_post', array( $this, 'check_lostpassword' ), 10, 1 );
	}

	/**
	 * Whether the layer is active. The `wp-config.php` constant is the support
	 * escape hatch and wins over every option, mirroring the hide-login switch.
	 *
	 * @return bool
	 * @since  2.1.53
	 */
	public function is_enabled() {
		if ( defined( 'REPORTEDIP_HIVE_DISABLE_FORM_PROOF' ) && REPORTEDIP_HIVE_DISABLE_FORM_PROOF ) {
			return false;
		}
		return (bool) ReportedIP_Hive_Option_Routing::get( self::OPT_ENABLED, true );
	}

	/**
	 * Whether a surface is armed. Operators and integrations can drop a single
	 * surface without switching off the whole layer.
	 *
	 * @param string $surface Surface identifier.
	 * @return bool
	 * @since  2.1.53
	 */
	public function surface_enabled( $surface ) {
		if ( ! $this->is_enabled() ) {
			return false;
		}

		if ( in_array( (string) $surface, self::HARD_SURFACES, true ) && ! $this->login_forms_enabled() ) {
			return false;
		}

		/**
		 * Filters the list of form surfaces that plant an execution anchor.
		 *
		 * @param string[] $surfaces Surface identifiers.
		 * @since 2.1.53
		 */
		$surfaces = (array) apply_filters( 'reportedip_hive_form_proof_adapters', self::SURFACES );

		return in_array( (string) $surface, $surfaces, true );
	}

	/**
	 * Whether the sign-up and password-reset forms take part.
	 *
	 * Comments and login surfaces carry different risk: a comment that fails
	 * the check is filed for review, a password reset that fails is refused,
	 * and the reset form is the one an operator reaches for when they are
	 * already locked out. Keeping the two apart lets a site run the comment
	 * protection without ever putting its own recovery path at risk.
	 *
	 * @return bool
	 * @since  2.1.53
	 */
	public function login_forms_enabled() {
		return (bool) ReportedIP_Hive_Option_Routing::get( self::OPT_LOGIN_FORMS, true );
	}

	/**
	 * Whether the operator asked for detection without enforcement.
	 *
	 * The global report-only mode means exactly that everywhere else in the
	 * plugin, so a refusal on a login surface must stand down for it too. The
	 * detection is still logged, which is the point of the mode: run it for a
	 * week, read the log, then decide.
	 *
	 * @return bool
	 * @since  2.1.53
	 */
	public function report_only() {
		return (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false );
	}

	/**
	 * The per-install proof field name, generating and persisting one on first
	 * use.
	 *
	 * @return string
	 * @since  2.1.53
	 */
	public function field_name() {
		if ( null !== $this->field ) {
			return $this->field;
		}

		$stored = (string) ReportedIP_Hive_Option_Routing::get( self::OPT_FIELD, '' );

		if ( ! self::is_valid_field_name( $stored ) ) {
			$stored = self::generate_field_name();
			ReportedIP_Hive_Option_Routing::set( self::OPT_FIELD, $stored );
		}

		$this->field = $stored;

		return $this->field;
	}

	/**
	 * Seed the field name outside a front-end request, so a cached page is
	 * never generated while the name is still being decided.
	 *
	 * @return void
	 * @since  2.1.53
	 */
	public function ensure_field_name() {
		$this->field_name();
	}

	/**
	 * Register the proof script. Enqueueing happens in {@see anchor_html()}, so
	 * a page without a protected form gains no asset.
	 *
	 * @return void
	 * @since  2.1.53
	 */
	public function register_script() {
		if ( ! $this->is_enabled() || wp_script_is( 'reportedip-hive-form-proof', 'registered' ) ) {
			return;
		}

		wp_register_script(
			'reportedip-hive-form-proof',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/form-proof.js',
			array(),
			REPORTEDIP_HIVE_VERSION,
			true
		);

		wp_register_style( 'reportedip-hive-form-proof', false, array(), REPORTEDIP_HIVE_VERSION );
		wp_add_inline_style(
			'reportedip-hive-form-proof',
			'.rip-hp-field{position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;}'
		);
	}

	/**
	 * The anchor field: DOM marker for the script, decoy for a bot that fills
	 * every input, and evidence that we rendered on this page.
	 *
	 * @param string $surface Surface identifier.
	 * @return string Markup, or an empty string when the surface is not armed.
	 * @since  2.1.53
	 */
	public function anchor_html( $surface ) {
		if ( ! $this->surface_enabled( $surface ) ) {
			return '';
		}

		$this->register_script();
		wp_enqueue_script( 'reportedip-hive-form-proof' );
		wp_enqueue_style( 'reportedip-hive-form-proof' );

		if ( 'comment' === $surface ) {
			$this->note_render();
		}

		return self::anchor_markup(
			ReportedIP_Hive_Comment_Honeypot::FIELD_NAME,
			$this->field_name(),
			esc_html__( 'Leave this field empty', 'reportedip-hive' )
		);
	}

	/**
	 * Build the anchor markup. Pure, so the rendered contract is testable
	 * without the enqueue machinery around it.
	 *
	 * The class hides it off-screen, `aria-hidden`, `tabindex="-1"` and
	 * `autocomplete="off"` keep it away from assistive tech and password
	 * managers, and `data-n` carries the proof field name for the script.
	 *
	 * @param string $decoy Anchor field name.
	 * @param string $proof Proof field name.
	 * @param string $label Visually hidden label text.
	 * @return string
	 * @since  2.1.53
	 */
	public static function anchor_markup( $decoy, $proof, $label ) {
		$decoy = esc_attr( (string) $decoy );

		return '<div class="rip-hp-field" aria-hidden="true">'
			. '<label for="' . $decoy . '">' . esc_html( (string) $label ) . '</label>'
			. '<input type="text" name="' . $decoy . '" id="' . $decoy . '" value=""'
			. ' class="rip-fp-anchor" data-n="' . esc_attr( (string) $proof ) . '"'
			. ' tabindex="-1" autocomplete="off" /></div>';
	}

	/**
	 * Echo the anchor through the shared kses allowlist.
	 *
	 * @param string $surface Surface identifier.
	 * @return void
	 * @since  2.1.53
	 */
	public function print_anchor( $surface ) {
		echo wp_kses( $this->anchor_html( $surface ), self::anchor_kses() );
	}

	/**
	 * Anchor markup for the WordPress registration form.
	 *
	 * @return void
	 * @since  2.1.53
	 */
	public function print_register_anchor() {
		$this->print_anchor( 'register' );
	}

	/**
	 * Anchor markup for the lost-password form.
	 *
	 * @return void
	 * @since  2.1.53
	 */
	public function print_lostpassword_anchor() {
		$this->print_anchor( 'lostpassword' );
	}

	/**
	 * Tags and attributes the anchor is allowed to carry.
	 *
	 * @return array<string, array<string, bool>>
	 * @since  2.1.53
	 */
	public static function anchor_kses() {
		return array(
			'div'   => array(
				'class'       => true,
				'aria-hidden' => true,
			),
			'label' => array( 'for' => true ),
			'input' => array(
				'type'         => true,
				'name'         => true,
				'id'           => true,
				'value'        => true,
				'class'        => true,
				'data-n'       => true,
				'tabindex'     => true,
				'autocomplete' => true,
			),
		);
	}

	/**
	 * Record that an anchor reached a comment form, throttled to one write per
	 * day. This is what lets {@see renders_anchors()} tell "our field is missing
	 * because the sender never loaded the form" from "this form was never ours".
	 *
	 * @return void
	 * @since  2.1.53
	 */
	public function note_render() {
		$seen = (int) ReportedIP_Hive_Option_Routing::get( self::OPT_SEEN, 0 );
		$now  = time();

		if ( $seen > 0 && ( $now - $seen ) < self::SEEN_THROTTLE ) {
			return;
		}

		ReportedIP_Hive_Option_Routing::set( self::OPT_SEEN, $now );
	}

	/**
	 * Whether this site is known to plant anchors on its comment form.
	 *
	 * A switched-off layer plants nothing, whatever the recorded timestamp
	 * still says. Without that check the off switch would leave the harsh
	 * reading of a missing field in place until the record aged out, which is
	 * the opposite of what an operator reaching for it needs.
	 *
	 * @return bool
	 * @since  2.1.53
	 */
	public function renders_anchors() {
		if ( ! $this->is_enabled() ) {
			return false;
		}

		$seen = (int) ReportedIP_Hive_Option_Routing::get( self::OPT_SEEN, 0 );

		return $seen > 0 && ( time() - $seen ) < self::SEEN_TTL;
	}

	/**
	 * Verdict for the current request on a surface we own.
	 *
	 * @param string $surface Surface identifier.
	 * @return string One of the four verdict constants.
	 * @since  2.1.53
	 */
	public function verdict_for_request( $surface ) {
		if ( ! $this->surface_enabled( $surface ) ) {
			return self::ABSENT;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Reads two decoy fields, not state; each form carries its own nonce.
		$post = (array) wp_unslash( $_POST );

		return self::evaluate( $post, $this->field_name(), ReportedIP_Hive_Comment_Honeypot::FIELD_NAME );
	}

	/**
	 * Refuse a lost-password request that reached a rendered form without ever
	 * running its script. `absent` never blocks here: an administrator locked
	 * out of their own recovery is worse than the spam this stops.
	 *
	 * @param WP_Error $errors Error container.
	 * @return void
	 * @since  2.1.53
	 */
	public function check_lostpassword( $errors ) {
		if ( ! $errors instanceof WP_Error ) {
			return;
		}

		if ( class_exists( 'ReportedIP_Hive_Reputation_Gate' ) ) {
			$reputation = ReportedIP_Hive_Reputation_Gate::get_instance()->check( 'lostpassword', ReportedIP_Hive::get_client_ip() );

			if ( '' !== $reputation ) {
				$errors->add( 'reportedip_hive_reputation', $reputation );

				return;
			}
		}

		if ( self::FAILED !== $this->verdict_for_request( 'lostpassword' ) ) {
			return;
		}

		$this->log_failure( 'lostpassword' );

		if ( $this->report_only() ) {
			return;
		}

		$errors->add(
			'reportedip_hive_form_proof',
			esc_html__( 'This form needs JavaScript to be submitted. Switch it on and try again. If you cannot, ask another administrator to reset your password, or use WP-CLI on the server.', 'reportedip-hive' )
		);
	}

	/**
	 * Log a refused submission so a support case is explainable from the log.
	 *
	 * @param string $surface Surface identifier.
	 * @return void
	 * @since  2.1.53
	 */
	public function log_failure( $surface ) {
		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return;
		}

		$logger = ReportedIP_Hive::get_instance()->get_logger();

		if ( $logger instanceof ReportedIP_Hive_Logger ) {
			$logger->log_security_event(
				'form_proof_failed',
				ReportedIP_Hive::get_client_ip(),
				array( 'surface' => (string) $surface ),
				'low'
			);
		}
	}

	/**
	 * Read the verdict out of a submission. Pure: everything it needs arrives
	 * as an argument, so the whole contract is testable without WordPress.
	 *
	 * The anchor decides. A proof field without an anchor means the submission
	 * carries a field we did not plant on a form we did not render, which is
	 * `absent`, not evidence.
	 *
	 * @param array<string,mixed> $post  Request body fields.
	 * @param string              $name  Proof field name.
	 * @param string              $decoy Anchor field name.
	 * @return string One of the four verdict constants.
	 * @since  2.1.53
	 */
	public static function evaluate( array $post, $name, $decoy ) {
		$decoy = (string) $decoy;

		if ( '' === $decoy || ! array_key_exists( $decoy, $post ) ) {
			return self::ABSENT;
		}

		$anchor = $post[ $decoy ];

		if ( ! is_scalar( $anchor ) || '' !== trim( (string) $anchor ) ) {
			return self::TRIPPED;
		}

		$name = (string) $name;

		if ( '' !== $name && isset( $post[ $name ] ) && is_scalar( $post[ $name ] ) && '' !== trim( (string) $post[ $name ] ) ) {
			return self::PROVED;
		}

		return self::FAILED;
	}

	/**
	 * Whether a stored field name is one we generated.
	 *
	 * @param string $name Candidate name.
	 * @return bool
	 * @since  2.1.53
	 */
	public static function is_valid_field_name( $name ) {
		return (bool) preg_match( '/^rip_[a-z0-9]{10}$/', (string) $name );
	}

	/**
	 * Build a field name. Random per install so one crafted submission cannot
	 * fit every site.
	 *
	 * @return string
	 * @since  2.1.53
	 */
	public static function generate_field_name() {
		$raw    = strtolower( preg_replace( '/[^A-Za-z0-9]/', '', wp_generate_password( 32, false, false ) ) );
		$length = strlen( $raw );

		while ( $length < 10 ) {
			$raw   .= strtolower( preg_replace( '/[^A-Za-z0-9]/', '', wp_generate_password( 32, false, false ) ) );
			$length = strlen( $raw );
		}

		return 'rip_' . substr( $raw, 0, 10 );
	}
}
