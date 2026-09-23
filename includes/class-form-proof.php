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
	 * Prefix the field names carry on every surface this plugin does not own.
	 *
	 * Contact Form 7 copies every posted key without a leading underscore into
	 * its own posted data, which then reaches Flamingo records and the posted
	 * data hash. An underscore keeps our two fields out of the mail, out of the
	 * stored entry and out of that hash.
	 */
	const ADAPTER_PREFIX = '_';

	/**
	 * The adapter switches. One list, read by the grace stamp and by
	 * anything else that needs to know whether a third-party form takes part.
	 *
	 * @var string[]
	 */
	const ADAPTER_OPTIONS = array(
		'reportedip_hive_form_proof_cf7',
		'reportedip_hive_form_proof_formidable',
		'reportedip_hive_form_proof_elementor',
		'reportedip_hive_form_proof_um',
		'reportedip_hive_form_proof_gravity',
	);

	/**
	 * Unix time the first adapter was switched on, 0 while they are all off.
	 */
	const OPT_ADAPTERS_SINCE = 'reportedip_hive_form_adapters_since';

	/**
	 * Grace after switching an adapter on, during which a submission that never
	 * carried our anchor still passes. A page served from a cache filled before
	 * the switch has no anchor to carry.
	 */
	const ADAPTER_GRACE = 86400;

	/**
	 * Longest grace a filter may ask for.
	 */
	const ADAPTER_GRACE_MAX = 2592000;

	/**
	 * Whether the proof field must carry a solved computation.
	 */
	const OPT_POW = 'reportedip_hive_form_proof_pow';

	/**
	 * Unix time the computation was switched on, 0 while it is off.
	 */
	const OPT_POW_SINCE = 'reportedip_hive_form_proof_pow_since';

	/**
	 * Plugin version the computation was last armed for. A version change
	 * restarts the grace, because a page cache filled by the previous version
	 * still carries the previous markup and its readers must not be refused.
	 */
	const OPT_POW_VERSION = 'reportedip_hive_form_proof_pow_version';

	/**
	 * Grace after switching the computation on, during which a page served
	 * from a cache filled beforehand still passes on the plain marker.
	 */
	const POW_GRACE = 86400;

	/**
	 * Seconds a form has to be on screen before the submission stops reading
	 * as automatic.
	 *
	 * The duration is measured in the browser and travels as a suffix on the
	 * proof field. It is not signed, so anyone who reads this code can write
	 * whatever number they like into it. That is the ceiling of the signal: it
	 * catches the careless bot, not the determined one, which is why the only
	 * consequence anywhere is two points on the comment score.
	 */
	const FAST_SECONDS = 3;

	/**
	 * Shortest threshold a filter may ask for.
	 */
	const FAST_SECONDS_MIN = 1;

	/**
	 * Longest threshold a filter may ask for.
	 */
	const FAST_SECONDS_MAX = 60;

	/**
	 * Separator between the proof payload and the measured duration.
	 */
	const SECONDS_SEPARATOR = '~';

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
	 * Why the submission last judged was refused, null when it was not.
	 *
	 * @var string|null
	 */
	private $reason = null;

	/**
	 * Measured fill duration of the submission last judged, null when none
	 * arrived.
	 *
	 * @var int|null
	 */
	private $seconds = null;

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
		add_action(
			'admin_init',
			function () {
				$this->field_name();
			}
		);
		add_action(
			'register_form',
			function () {
				$this->print_anchor( 'register' );
			}
		);
		add_action(
			'lostpassword_form',
			function () {
				$this->print_anchor( 'lostpassword' );
			}
		);
		add_action( 'lostpassword_post', array( $this, 'check_lostpassword' ), 10, 1 );
		add_action( 'init', array( $this, 'restamp_after_update' ), 5 );
		add_filter( 'script_loader_tag', array( __CLASS__, 'script_tag' ), 10, 2 );
	}

	/**
	 * Restart the grace when the plugin version changes while the computation
	 * is on.
	 *
	 * A page cache filled by the previous version still carries the previous
	 * markup, and a browser reading it must not be refused for the lifetime
	 * of that cache. The marker keeps passing for a day, the cache is purged,
	 * and no visitor loses a message over an update.
	 *
	 * @since 2.1.64
	 */
	public function restamp_after_update() {
		if ( ! (bool) ReportedIP_Hive_Option_Routing::get( self::OPT_POW, false ) ) {
			return;
		}

		$seen = (string) ReportedIP_Hive_Option_Routing::get( self::OPT_POW_VERSION, '' );

		if ( REPORTEDIP_HIVE_VERSION === $seen ) {
			return;
		}

		ReportedIP_Hive_Option_Routing::set( self::OPT_POW_VERSION, REPORTEDIP_HIVE_VERSION );
		ReportedIP_Hive_Option_Routing::set( self::OPT_POW_SINCE, time() );
		self::purge_pages();
	}

	/**
	 * Keep the proof script out of Cloudflare's Rocket Loader and WP Rocket's
	 * combining, both of which reorder scripts. The script survives a delayed
	 * start on its own; this only spares it a rewrite.
	 *
	 * @param string $tag    Script tag.
	 * @param string $handle Script handle.
	 * @return string
	 * @since  2.1.64
	 */
	public static function script_tag( $tag, $handle ) {
		if ( 'reportedip-hive-form-proof' !== $handle ) {
			return $tag;
		}

		return str_replace( '<script ', '<script data-cfasync="false" data-nowprocket ', (string) $tag );
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
	 * Whether the plan covers the computation. It is pure local arithmetic and
	 * makes no request, so it is available in Local Shield too.
	 *
	 * @return bool
	 * @since  2.1.58
	 */
	public function pow_available() {
		if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			return false;
		}

		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'form_proof_pow' );

		return ! empty( $status['available'] );
	}

	/**
	 * Whether a challenge is handed out. A site reached over plain HTTP is left
	 * alone: `crypto.subtle` only exists in a secure context, so the browser
	 * could not answer and every visitor would look like a script.
	 *
	 * @return bool
	 * @since  2.1.58
	 */
	public function pow_enabled() {
		return $this->is_enabled()
			&& (bool) ReportedIP_Hive_Option_Routing::get( self::OPT_POW, false )
			&& $this->pow_available();
	}

	/**
	 * Whether the visitor reaches this site over a secure connection.
	 *
	 * `is_ssl()` describes the connection that reached PHP, which is plain HTTP
	 * on every site whose TLS ends at a proxy or CDN. Reading it alone would
	 * switch the check off on a large share of perfectly secure sites without
	 * saying so, and a protection that quietly does nothing is worse than one
	 * that is plainly off. The configured home address is the operator's own
	 * statement about how visitors arrive and survives any number of proxies.
	 *
	 * @return bool
	 * @since  2.1.58
	 */
	public static function connection_is_secure() {
		return is_ssl() || 0 === strpos( (string) home_url(), 'https://' );
	}

	/**
	 * Whether a solution is demanded rather than merely offered.
	 *
	 * During the grace after switching on, a challenge is already planted but
	 * the plain marker still passes, so a page cache filled before the switch
	 * cannot turn every reader into a suspect.
	 *
	 * @return bool
	 * @since  2.1.58
	 */
	public function pow_required() {
		if ( ! $this->pow_enabled() ) {
			return false;
		}

		$since = (int) ReportedIP_Hive_Option_Routing::get( self::OPT_POW_SINCE, 0 );

		return $since > 0 && ( time() - $since ) >= self::POW_GRACE;
	}

	/**
	 * Start or clear the grace, called from the option side-effect dispatcher
	 * whenever {@see OPT_POW} is written by any channel.
	 *
	 * @return void
	 * @since  2.1.58
	 */
	public static function stamp_pow_since() {
		$on    = (bool) ReportedIP_Hive_Option_Routing::get( self::OPT_POW, false );
		$since = (int) ReportedIP_Hive_Option_Routing::get( self::OPT_POW_SINCE, 0 );

		if ( ! $on ) {
			if ( 0 !== $since ) {
				ReportedIP_Hive_Option_Routing::set( self::OPT_POW_SINCE, 0 );
			}

			return;
		}

		if ( 0 === $since ) {
			ReportedIP_Hive_Option_Routing::set( self::OPT_POW_SINCE, time() );
			self::purge_pages();
		}
	}

	/**
	 * Purge the page caches when the whole layer is switched on, called from the
	 * option side-effect dispatcher whenever {@see OPT_ENABLED} is written.
	 *
	 * Switching off purges nothing. An anchor left in a cached page is read by
	 * no one once the layer is gone, so the cold cache would buy nothing.
	 *
	 * @return void
	 * @since  2.1.58
	 */
	public static function purge_on_enable() {
		if ( ReportedIP_Hive_Option_Routing::get( self::OPT_ENABLED, true ) ) {
			self::purge_pages();
		}
	}

	/**
	 * Throw away every cached rendering, so the pages carrying a protected form
	 * are built again with the anchor in them.
	 *
	 * @return void
	 * @since  2.1.58
	 */
	private static function purge_pages() {
		if ( class_exists( 'ReportedIP_Hive_Cache_Flush' ) ) {
			ReportedIP_Hive_Cache_Flush::purge_pages();
		}
	}

	/**
	 * Start or clear the adapter grace, called from the option side-effect
	 * dispatcher whenever one of {@see ADAPTER_OPTIONS} is written.
	 *
	 * @return void
	 * @since  2.1.58
	 */
	public static function stamp_adapters_since() {
		$on = false;

		foreach ( self::ADAPTER_OPTIONS as $option ) {
			if ( ReportedIP_Hive_Option_Routing::get( $option, false ) ) {
				$on = true;
				break;
			}
		}

		$since = (int) ReportedIP_Hive_Option_Routing::get( self::OPT_ADAPTERS_SINCE, 0 );

		if ( ! $on ) {
			if ( 0 !== $since ) {
				ReportedIP_Hive_Option_Routing::set( self::OPT_ADAPTERS_SINCE, 0 );
			}

			return;
		}

		if ( 0 === $since ) {
			ReportedIP_Hive_Option_Routing::set( self::OPT_ADAPTERS_SINCE, time() );
			self::purge_pages();
		}
	}

	/**
	 * Whether a submission that never carried our anchor counts against the
	 * sender on a third-party form.
	 *
	 * On a contact form `absent` means either a direct post at the endpoint,
	 * which is nearly always a script, or a page from a cache filled before the
	 * adapter was switched on. The first reading is the useful one, the second
	 * would refuse real visitors, so the harsh reading waits out the grace.
	 *
	 * @return bool
	 * @since  2.1.58
	 */
	public function adapters_strict() {
		/**
		 * Filters the grace after switching a form adapter on.
		 *
		 * Sites whose page cache outlives a day can buy more room here.
		 *
		 * @param int $seconds Grace in seconds, clamped to 0..30 days afterwards.
		 * @since 2.1.58
		 */
		$grace = (int) apply_filters( 'reportedip_hive_form_adapters_grace', self::ADAPTER_GRACE );

		return self::grace_elapsed(
			ReportedIP_Hive_Option_Routing::get( self::OPT_ADAPTERS_SINCE, 0 ),
			time(),
			$grace
		);
	}

	/**
	 * Whether a grace that started at a given time has run out. Pure, so the
	 * arithmetic and the clamp are testable without WordPress.
	 *
	 * An unstamped start reads as "still in the grace": a switch written by a
	 * channel that never ran the side effect must not make the site strict
	 * behind the operator's back.
	 *
	 * @param mixed $since Unix time the grace started, 0 for none.
	 * @param mixed $now   Current Unix time.
	 * @param mixed $grace Grace in seconds before clamping.
	 * @return bool
	 * @since  2.1.58
	 */
	public static function grace_elapsed( $since, $now, $grace ) {
		$since = (int) $since;
		$grace = max( 0, min( self::ADAPTER_GRACE_MAX, (int) $grace ) );

		return $since > 0 && ( (int) $now - $since ) >= $grace;
	}

	/**
	 * The field-name prefix for one surface.
	 *
	 * Empty on the three surfaces this plugin owns, so their markup stays
	 * byte-identical, and an underscore everywhere else. Pure.
	 *
	 * @param string $surface Surface identifier.
	 * @return string
	 * @since  2.1.58
	 */
	public static function surface_prefix( $surface ) {
		return in_array( (string) $surface, self::SURFACES, true ) ? '' : self::ADAPTER_PREFIX;
	}

	/**
	 * The anchor field name on one surface.
	 *
	 * @param string $surface Surface identifier.
	 * @return string
	 * @since  2.1.58
	 */
	public function decoy_name( $surface ) {
		return self::surface_prefix( $surface ) . ReportedIP_Hive_Comment_Honeypot::FIELD_NAME;
	}

	/**
	 * The proof field name on one surface.
	 *
	 * @param string $surface Surface identifier.
	 * @return string
	 * @since  2.1.58
	 */
	public function proof_name( $surface ) {
		return self::surface_prefix( $surface ) . $this->field_name();
	}

	/**
	 * How many leading zero bits a raw digest carries.
	 *
	 * @param string $digest Raw binary digest.
	 * @return int
	 * @since  2.1.58
	 */
	public static function leading_zero_bits( $digest ) {
		$digest = (string) $digest;
		$length = strlen( $digest );
		$bits   = 0;

		for ( $i = 0; $i < $length; $i++ ) {
			$byte = ord( $digest[ $i ] );

			if ( 0 === $byte ) {
				$bits += 8;
				continue;
			}

			while ( $byte < 128 ) {
				++$bits;
				$byte <<= 1;
			}

			break;
		}

		return $bits;
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

		$endpoint = '';

		if ( $this->pow_enabled() && class_exists( 'ReportedIP_Hive_Form_Challenge' ) ) {
			$endpoint = rest_url( ReportedIP_Hive_Form_Challenge::NAMESPACE_STR . ReportedIP_Hive_Form_Challenge::ROUTE );
		}

		return self::anchor_markup(
			$this->decoy_name( $surface ),
			$this->proof_name( $surface ),
			esc_html__( 'Leave this field empty', 'reportedip-hive' ),
			$endpoint
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
	 * The label wraps the input and neither carries an identifier. Two forms on
	 * one page each get an anchor, and a fixed `id` would be in the document
	 * twice with the `for` of both labels pointing at the first field. A random
	 * identifier would fix the markup and break the cache, so the association
	 * runs through the nesting instead.
	 *
	 * With the computation on, `data-e` names the endpoint the script fetches
	 * its task from. The address is the same for every visitor, so the markup
	 * stays byte-identical and a page cache keeps working; the visitor's own
	 * task never touches the page. Without one the output is unchanged.
	 *
	 * @param string $decoy    Anchor field name.
	 * @param string $proof    Proof field name.
	 * @param string $label    Visually hidden label text.
	 * @param string $endpoint Challenge endpoint URL, empty for none.
	 * @return string
	 * @since  2.1.53
	 */
	public static function anchor_markup( $decoy, $proof, $label, $endpoint = '' ) {
		$decoy     = esc_attr( (string) $decoy );
		$challenge = '';

		if ( '' !== (string) $endpoint ) {
			$challenge = ' data-e="' . esc_url( (string) $endpoint ) . '"';
		}

		return '<div class="rip-hp-field" aria-hidden="true">'
			. '<label>' . esc_html( (string) $label )
			. '<input type="text" name="' . $decoy . '" value=""'
			. ' class="rip-fp-anchor" data-n="' . esc_attr( (string) $proof ) . '"'
			. $challenge
			. ' tabindex="-1" autocomplete="off" /></label></div>';
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
			'label' => array(),
			'input' => array(
				'type'         => true,
				'name'         => true,
				'value'        => true,
				'class'        => true,
				'data-n'       => true,
				'data-e'       => true,
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
	 * Split a submitted field value into its proof payload and the duration
	 * the browser measured. Pure, so the whole parsing rule is testable.
	 *
	 * The duration rides on the existing field rather than a second hidden one,
	 * which keeps the markup as small and as cacheable as it is today. It is
	 * stripped here before anything else looks at the value, because the
	 * challenge verifier reads the solution off the last dot and a suffix would
	 * turn every solved task into a refusal.
	 *
	 * An unusable suffix never devalues the proof. A client that writes
	 * nonsense after the separator, or one from a release that knew nothing
	 * about the suffix, is read as a submission without a measurement.
	 *
	 * @param mixed $raw Submitted field value.
	 * @return array{proof:string, seconds:int|null}
	 * @since  2.1.58
	 */
	public static function split_payload( $raw ): array {
		$raw = (string) $raw;
		$cut = strpos( $raw, self::SECONDS_SEPARATOR );

		if ( false === $cut ) {
			return array(
				'proof'   => $raw,
				'seconds' => null,
			);
		}

		$suffix = substr( $raw, $cut + 1 );

		return array(
			'proof'   => substr( $raw, 0, $cut ),
			'seconds' => preg_match( '/^[0-9]{1,4}$/', $suffix ) ? (int) $suffix : null,
		);
	}

	/**
	 * Hold a requested threshold inside a sane range. Pure, so the arithmetic
	 * is testable without WordPress.
	 *
	 * @param mixed $seconds Requested threshold.
	 * @return int
	 * @since  2.1.58
	 */
	public static function clamp_fast_seconds( $seconds ) {
		return max( self::FAST_SECONDS_MIN, min( self::FAST_SECONDS_MAX, (int) $seconds ) );
	}

	/**
	 * The duration under which a submission counts as too quick for a reader.
	 *
	 * @return int
	 * @since  2.1.58
	 */
	public function fast_seconds() {
		/**
		 * Filters the seconds a form has to be on screen before the submission
		 * stops reading as automatic.
		 *
		 * @param int $seconds Threshold in seconds, clamped to 1..60 afterwards.
		 * @since 2.1.58
		 */
		$seconds = apply_filters( 'reportedip_hive_form_proof_fast_seconds', self::FAST_SECONDS );

		return self::clamp_fast_seconds( $seconds );
	}

	/**
	 * How long the sender had the form on screen, for the submission last
	 * judged by {@see verdict_for_request()}.
	 *
	 * @return int|null Whole seconds, or null when nothing was measured.
	 * @since  2.1.58
	 */
	public function last_seconds(): ?int {
		return $this->seconds;
	}

	/**
	 * Verdict for the current request on a surface we own.
	 *
	 * This is the one place the computation is checked, so every surface
	 * inherits it together with its own consequence: a comment gains a scoring
	 * signal, a sign-up or password reset is refused. A field filled with
	 * anything other than a solved challenge reads as `failed`, which is what
	 * closes the copy-the-field-name shortcut.
	 *
	 * @param string $surface Surface identifier.
	 * @return string One of the four verdict constants.
	 * @since  2.1.53
	 */
	public function verdict_for_request( $surface ) {
		$this->seconds = null;
		$this->reason  = null;

		if ( ! $this->surface_enabled( $surface ) ) {
			return self::ABSENT;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Reads two decoy fields, not state; each form carries its own nonce.
		$post = (array) wp_unslash( $_POST );

		$field = $this->proof_name( $surface );

		if ( isset( $post[ $field ] ) && is_scalar( $post[ $field ] ) ) {
			$split          = self::split_payload( $post[ $field ] );
			$post[ $field ] = $split['proof'];
			$this->seconds  = $split['seconds'];
		}

		$verdict = self::evaluate( $post, $field, $this->decoy_name( $surface ) );

		if ( self::PROVED !== $verdict || ! $this->pow_required() ) {
			return $verdict;
		}

		$result = ReportedIP_Hive_Form_Challenge::judge( (string) $post[ $field ] );

		if ( 'ok' === $result ) {
			return self::PROVED;
		}

		$this->reason = $result;

		return self::FAILED;
	}

	/**
	 * Fold the computation result into a structural verdict. Pure, because this
	 * is the whole rule and it is worth pinning down on its own.
	 *
	 * Only `proved` can be revoked. A filled decoy stays `tripped` no matter how
	 * well the sender computed, and a submission that never carried our anchor
	 * stays `absent`, which is the lenient reading the password-reset path
	 * depends on.
	 *
	 * @param string $verdict  Structural verdict from {@see evaluate()}.
	 * @param bool   $required Whether a solved computation is demanded.
	 * @param bool   $solved   Whether the payload solved its challenge.
	 * @return string One of the four verdict constants.
	 * @since  2.1.58
	 */
	public static function resolve( $verdict, $required, $solved ) {
		if ( self::PROVED !== $verdict || ! $required ) {
			return $verdict;
		}

		return $solved ? self::PROVED : self::FAILED;
	}

	/**
	 * Print the anchor into a form this plugin does not own.
	 *
	 * Together with {@see check()} and {@see passes()} this is the whole
	 * contract for a third-party or custom form. Admit the surface through the
	 * `reportedip_hive_form_proof_adapters` filter first, then call this on the
	 * render hook and one of the other two on the validation hook.
	 *
	 * @param string $surface Surface identifier.
	 * @return void
	 * @since  2.1.58
	 */
	public static function field( $surface ) {
		self::get_instance()->print_anchor( $surface );
	}

	/**
	 * Verdict for the current submission on any surface.
	 *
	 * @param string $surface Surface identifier.
	 * @return string One of the four verdict constants.
	 * @since  2.1.58
	 */
	public static function check( $surface ) {
		return self::get_instance()->verdict_for_request( $surface );
	}

	/**
	 * Whether a submission may proceed.
	 *
	 * Strict is the right reading for a contact form, where requiring a browser
	 * is exactly what a captcha would demand anyway. The lenient reading is for
	 * surfaces where locking someone out costs more than the spam does: it lets
	 * a submission through that never carried our field at all, which is how
	 * the password-reset path behaves.
	 *
	 * A third-party form adapter hands {@see adapters_strict()} in here, so a
	 * page still served from a cache filled before the switch is read leniently
	 * for the first day.
	 *
	 * @param string $surface Surface identifier.
	 * @param bool   $strict  Whether a missing anchor counts as a refusal.
	 * @return bool
	 * @since  2.1.58
	 */
	public static function passes( $surface, $strict = true ) {
		$verdict = self::check( $surface );

		if ( self::PROVED === $verdict ) {
			return true;
		}

		if ( self::ABSENT === $verdict ) {
			return ! $strict;
		}

		return false;
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
	 * The measured duration rides along when there is one, so the activity view
	 * shows how the refusals on a surface are distributed before anyone decides
	 * whether a threshold is worth enforcing there.
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

		if ( ! $logger instanceof ReportedIP_Hive_Logger ) {
			return;
		}

		$details = array( 'surface' => (string) $surface );

		if ( null !== $this->seconds ) {
			$details['seconds'] = $this->seconds;
		}

		if ( null !== $this->reason ) {
			$details['reason'] = $this->reason;
		}

		$logger->log_security_event(
			'form_proof_failed',
			ReportedIP_Hive::get_client_ip(),
			$details,
			'low'
		);
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
