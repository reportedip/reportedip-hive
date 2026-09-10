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
 * @author    Patrick Schlesinger <1@reportedip.com>
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
		add_action( 'comment_form', array( $this, 'render_field' ) );
		add_filter( 'preprocess_comment', array( $this, 'check_comment' ), 1 );
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
		echo wp_kses( $this->field_markup(), ReportedIP_Hive_Form_Proof::anchor_kses() );
	}

	/**
	 * The decoy field markup, owned by {@see ReportedIP_Hive_Form_Proof} since
	 * 2.1.53: the same element is the decoy, the script's DOM anchor and the
	 * evidence that we rendered on this page.
	 *
	 * @return string
	 * @since  2.1.2
	 */
	public function field_markup() {
		return ReportedIP_Hive_Form_Proof::get_instance()->anchor_html( 'comment' );
	}

	/**
	 * Log and count a comment whose decoy field was filled.
	 *
	 * Since 2.1.53 this no longer ends the request. The consequence is carried
	 * by the score instead: {@see ReportedIP_Hive_Comment_Spam_Filter} weights a
	 * tripped decoy above its threshold, and whether that files the comment as
	 * spam or refuses it outright is the operator's `comment_spam_action`
	 * decision. One code path for hard rejection rather than two.
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
			$hive   = ReportedIP_Hive::get_instance();
			$ip     = ReportedIP_Hive::get_client_ip();
			$logger = $hive->get_logger();
			if ( $logger instanceof ReportedIP_Hive_Logger ) {
				$logger->log_security_event( 'comment_honeypot', $ip, array(), 'low' );
			}

			$monitor = $hive->get_security_monitor();
			if ( $monitor instanceof ReportedIP_Hive_Security_Monitor ) {
				$monitor->check_comment_spam_threshold( $ip );
			}
		}

		return $commentdata;
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
