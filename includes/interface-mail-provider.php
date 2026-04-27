<?php
/**
 * Mail Provider Interface for ReportedIP Hive.
 *
 * Implementations may use wp_mail(), an SMTP relay, a transactional API
 * (Postmark, SES, Mailgun, …) or any other transport. The Mailer always
 * passes a fully rendered HTML body plus a plain-text alternative so the
 * provider can build a multipart/alternative message.
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

interface ReportedIP_Hive_Mail_Provider_Interface {

	/**
	 * Send a mail.
	 *
	 * @param string   $to         Recipient email address.
	 * @param string   $subject    Mail subject (already localized).
	 * @param string   $html_body  Full HTML body.
	 * @param string   $plain_body Plain-text alternative.
	 * @param string[] $headers    Pre-built headers (From, Reply-To, …).
	 * @return bool True on successful queue / dispatch, false on failure.
	 */
	public function send( $to, $subject, $html_body, $plain_body, $headers );

	/**
	 * Stable identifier of the provider, used in logs.
	 *
	 * @return string e.g. 'wp_mail', 'postmark', 'ses'.
	 */
	public function get_name();
}
