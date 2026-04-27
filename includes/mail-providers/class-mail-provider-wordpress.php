<?php
/**
 * Default Mail Provider — wp_mail() wrapper.
 *
 * Sends a multipart/alternative message (HTML + plaintext) by hooking into
 * phpmailer_init for the duration of one wp_mail() call. The hook is removed
 * straight after sending so we don't leak side-effects into other code paths.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ReportedIP_Hive_Mail_Provider_WordPress implements ReportedIP_Hive_Mail_Provider_Interface {

	/**
	 * Plain-text body for the current send call. Captured in send() and
	 * read back inside the phpmailer_init hook.
	 *
	 * @var string
	 */
	private $current_plain = '';

	/**
	 * @inheritDoc
	 */
	public function send( $to, $subject, $html_body, $plain_body, $headers ) {
		$this->current_plain = (string) $plain_body;

		$attach_alt = array( $this, 'attach_plain_alt_body' );
		add_action( 'phpmailer_init', $attach_alt );

		$result = wp_mail( $to, $subject, $html_body, $headers );

		remove_action( 'phpmailer_init', $attach_alt );
		$this->current_plain = '';

		return (bool) $result;
	}

	/**
	 * Attach the plain-text alternative to the outgoing message.
	 *
	 * @param object $phpmailer PHPMailer instance passed by reference by WP.
	 */
	public function attach_plain_alt_body( $phpmailer ) {
		if ( '' !== $this->current_plain && is_object( $phpmailer ) ) {
			$phpmailer->AltBody = $this->current_plain; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHPMailer property.
		}
	}

	/**
	 * @inheritDoc
	 */
	public function get_name() {
		return 'wp_mail';
	}
}
