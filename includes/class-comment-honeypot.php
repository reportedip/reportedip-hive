<?php
/**
 * Comment-honeypot sensor.
 *
 * Adds a visually hidden, screen-reader-excluded decoy field to the comment
 * form. A human never sees or fills it; an automated spam bot that fills every
 * field trips the trap and is rejected before the comment is processed. This
 * runs ahead of the existing comment-spam counter and is a zero-friction
 * alternative to a CAPTCHA. Logged-in content authors are exempt.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.2
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hidden-field comment honeypot.
 *
 * @since 2.1.2
 */
class ReportedIP_Hive_Comment_Honeypot {

	/**
	 * Master enable toggle option.
	 */
	const OPT_ENABLED = 'reportedip_hive_comment_honeypot_enabled';

	/**
	 * Name of the decoy form field.
	 */
	const FIELD_NAME = 'reportedip_hive_hp';

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Comment_Honeypot|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return ReportedIP_Hive_Comment_Honeypot
	 * @since  2.1.2
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Wire the form-render and the early validation hooks.
	 *
	 * @since 2.1.2
	 */
	private function __construct() {
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_style' ) );
		add_action( 'comment_form_after_fields', array( $this, 'render_field' ) );
		add_filter( 'preprocess_comment', array( $this, 'check_comment' ), 1 );
	}

	/**
	 * Guarantee the decoy field is hidden on the front end without loading the
	 * whole design system: a single rule is attached to an own style handle and
	 * printed only where a comment form can appear.
	 *
	 * @return void
	 * @since  2.1.2
	 */
	public function enqueue_style() {
		if ( ! $this->is_enabled() || ! is_singular() || ! comments_open() ) {
			return;
		}
		wp_register_style( 'reportedip-hive-honeypot', false, array(), REPORTEDIP_HIVE_VERSION );
		wp_enqueue_style( 'reportedip-hive-honeypot' );
		wp_add_inline_style(
			'reportedip-hive-honeypot',
			'.rip-hp-field{position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;}'
		);
	}

	/**
	 * Whether the honeypot is enabled.
	 *
	 * @return bool
	 * @since  2.1.2
	 */
	public function is_enabled() {
		return (bool) ReportedIP_Hive_Option_Routing::get( self::OPT_ENABLED, true );
	}

	/**
	 * Echo the decoy field into the comment form.
	 *
	 * @return void
	 * @since  2.1.2
	 */
	public function render_field() {
		if ( ! $this->is_enabled() ) {
			return;
		}
		echo wp_kses(
			$this->field_markup(),
			array(
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
					'tabindex'     => true,
					'autocomplete' => true,
				),
			)
		);
	}

	/**
	 * Build the decoy field markup. A design-system class hides it off-screen
	 * (no inline style) and `aria-hidden`/`tabindex="-1"`/`autocomplete="off"`
	 * keep it away from assistive tech and password managers.
	 *
	 * @return string
	 * @since  2.1.2
	 */
	public function field_markup() {
		$name = esc_attr( self::FIELD_NAME );
		return '<div class="rip-hp-field" aria-hidden="true">'
			. '<label for="' . $name . '">' . esc_html__( 'Leave this field empty', 'reportedip-hive' ) . '</label>'
			. '<input type="text" name="' . $name . '" id="' . $name . '" value="" tabindex="-1" autocomplete="off" />'
			. '</div>';
	}

	/**
	 * Reject a comment whose decoy field was filled.
	 *
	 * @param array<string,mixed> $commentdata Incoming comment data.
	 * @return array<string,mixed>
	 * @since  2.1.2
	 */
	public function check_comment( $commentdata ) {
		if ( ! $this->is_enabled() ) {
			return $commentdata;
		}
		if ( is_user_logged_in() && current_user_can( 'edit_posts' ) ) {
			return $commentdata;
		}
		if ( ! self::is_sprung( $_POST ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Bot-trap read of a decoy field, not a state change; the comment form carries its own nonce.
			return $commentdata;
		}

		if ( class_exists( 'ReportedIP_Hive' ) ) {
			$ip     = ReportedIP_Hive::get_client_ip();
			$logger = ReportedIP_Hive::get_instance()->get_logger();
			if ( $logger instanceof ReportedIP_Hive_Logger ) {
				$logger->log_security_event( 'comment_honeypot', $ip, array(), 'low' );
			}
		}

		wp_die(
			esc_html__( 'Your comment could not be processed.', 'reportedip-hive' ),
			'',
			array( 'response' => 403 )
		);
	}

	/**
	 * Whether the decoy field was filled. Pure: takes the request array, so it
	 * is deterministically unit-testable.
	 *
	 * @param array<string,mixed> $post Request body params.
	 * @return bool
	 * @since  2.1.2
	 */
	public static function is_sprung( array $post ) {
		return isset( $post[ self::FIELD_NAME ] ) && '' !== trim( (string) $post[ self::FIELD_NAME ] );
	}
}
