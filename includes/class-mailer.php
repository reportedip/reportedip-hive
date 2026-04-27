<?php
/**
 * Central mail dispatcher for ReportedIP Hive.
 *
 * Single point of truth for every outgoing email the plugin produces. Wraps
 * every mail in the unified branded HTML template (templates/emails/base.php),
 * generates a plain-text alternative from the same source strings, and routes
 * the final message through a swappable provider.
 *
 * Custom transports (Postmark, SES, SMTP relay, …) plug in by filtering
 * `reportedip_hive_mail_provider` and returning an instance of
 * ReportedIP_Hive_Mail_Provider_Interface.
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

class ReportedIP_Hive_Mailer {

	/**
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * @var ReportedIP_Hive_Mail_Provider_Interface|null
	 */
	private $resolved_provider = null;

	/**
	 * Singleton accessor.
	 *
	 * @return self
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Send a branded mail.
	 *
	 * Required keys:
	 *   - to              string   Recipient email.
	 *   - subject         string   Localized subject (will receive a [SiteName] prefix if it doesn't already have one).
	 *   - intro_text      string   Plain-text intro line(s).
	 *
	 * Optional keys:
	 *   - greeting        string   "Hello Name," — omit for impersonal admin alerts.
	 *   - main_block_html string   HTML for the main block (caller-controlled, runs through wp_kses_post).
	 *   - main_block_text string   Plain-text mirror of the main block (used in the text/plain part).
	 *   - cta             array    ['label' => string, 'url' => string].
	 *   - security_notice array    ['ip' => string, 'timestamp' => string].
	 *   - disclaimer      string   Final small-print line.
	 *   - headers         string[] Extra headers (From / Reply-To). Defaults to a sane From: line.
	 *   - context         array    Free-form context passed to filters/actions for logging and provider routing.
	 *
	 * @param array $args Mail definition.
	 * @return bool True on send success.
	 */
	public function send( array $args ) {
		$args = $this->normalize_args( $args );

		/**
		 * Last-chance hook to modify recipient, subject, body, headers.
		 *
		 * @param array $args    Normalized mail args.
		 * @param array $context Free-form caller context.
		 */
		$args = apply_filters( 'reportedip_hive_mail_args', $args, $args['context'] );

		if ( empty( $args['to'] ) || empty( $args['subject'] ) ) {
			return false;
		}

		$html_body  = $this->render_html( $args );
		$plain_body = $this->render_plain( $args );

		$provider = $this->resolve_provider();

		/**
		 * Fires before the provider sends the mail.
		 *
		 * @param array                                  $args     Normalized mail args.
		 * @param ReportedIP_Hive_Mail_Provider_Interface $provider Active provider.
		 */
		do_action( 'reportedip_hive_mail_before_send', $args, $provider );

		$result = (bool) $provider->send(
			(string) $args['to'],
			(string) $args['subject'],
			$html_body,
			$plain_body,
			$args['headers']
		);

		/**
		 * Fires after the provider attempted delivery.
		 *
		 * @param array                                  $args     Normalized mail args.
		 * @param bool                                   $result   Provider return value.
		 * @param ReportedIP_Hive_Mail_Provider_Interface $provider Active provider.
		 */
		do_action( 'reportedip_hive_mail_after_send', $args, $result, $provider );

		$this->log_result( $args, $result, $provider );

		return $result;
	}

	/**
	 * Render the branded HTML body via the email template.
	 *
	 * @param array $args Normalized args.
	 * @return string Rendered HTML.
	 */
	public function render_html( array $args ) {
		$context = array(
			'site_name'       => $args['site_name'],
			'site_url'        => $args['site_url'],
			'greeting'        => $args['greeting'],
			'intro_html'      => $args['intro_text'],
			'main_block_html' => $args['main_block_html'],
			'cta'             => $args['cta'],
			'security_notice' => $args['security_notice'],
			'disclaimer'      => $args['disclaimer'],
		);

		$default_template = REPORTEDIP_HIVE_PLUGIN_DIR . 'templates/emails/base.php';

		/**
		 * Allow alternative branded templates (e.g. white-label builds).
		 *
		 * @param string $template_path Absolute path to the template file.
		 * @param array  $context       Slot data passed to the template.
		 */
		$template_path = (string) apply_filters( 'reportedip_hive_mail_template_path', $default_template, $context );

		if ( ! is_readable( $template_path ) ) {
			$template_path = $default_template;
		}

		ob_start();
		include $template_path;
		return (string) ob_get_clean();
	}

	/**
	 * Build a plain-text alternative from the same source strings.
	 *
	 * @param array $args Normalized args.
	 * @return string Plain-text body.
	 */
	public function render_plain( array $args ) {
		$lines = array();

		if ( '' !== $args['greeting'] ) {
			$lines[] = $args['greeting'];
			$lines[] = '';
		}

		if ( '' !== $args['intro_text'] ) {
			$lines[] = wp_strip_all_tags( $args['intro_text'] );
			$lines[] = '';
		}

		if ( '' !== $args['main_block_text'] ) {
			$lines[] = $args['main_block_text'];
			$lines[] = '';
		} elseif ( '' !== $args['main_block_html'] ) {
			$lines[] = trim( wp_strip_all_tags( $args['main_block_html'] ) );
			$lines[] = '';
		}

		if ( ! empty( $args['cta']['label'] ) && ! empty( $args['cta']['url'] ) ) {
			$lines[] = $args['cta']['label'] . ': ' . $args['cta']['url'];
			$lines[] = '';
		}

		if ( ! empty( $args['security_notice'] ) ) {
			$ip      = (string) ( $args['security_notice']['ip'] ?? '' );
			$ts      = (string) ( $args['security_notice']['timestamp'] ?? '' );
			$lines[] = sprintf(
				/* translators: 1: IP address, 2: timestamp */
				__( 'Security notice: recorded for your security from IP %1$s at %2$s. If this wasn\'t you, please update your password and review your recent sessions.', 'reportedip-hive' ),
				$ip,
				$ts
			);
			$lines[] = '';
		}

		if ( '' !== $args['disclaimer'] ) {
			$lines[] = $args['disclaimer'];
			$lines[] = '';
		}

		$lines[] = '--';
		$lines[] = sprintf(
			/* translators: 1: site name, 2: site URL */
			__( 'Protected by ReportedIP Hive on %1$s (%2$s)', 'reportedip-hive' ),
			$args['site_name'],
			$args['site_url']
		);
		$lines[] = __( 'This message is protected by ReportedIP — Open Threat Intelligence for a Safer Internet.', 'reportedip-hive' );
		$lines[] = 'https://reportedip.de/';

		return implode( "\n", $lines );
	}

	/**
	 * Resolve the active provider via filter, with a sensible default.
	 *
	 * @return ReportedIP_Hive_Mail_Provider_Interface
	 */
	public function resolve_provider() {
		if ( null !== $this->resolved_provider ) {
			return $this->resolved_provider;
		}

		$default = new ReportedIP_Hive_Mail_Provider_WordPress();

		/**
		 * Replace the default wp_mail provider with a custom transport.
		 *
		 * @param ReportedIP_Hive_Mail_Provider_Interface $provider Default provider.
		 */
		$provider = apply_filters( 'reportedip_hive_mail_provider', $default );

		if ( ! ( $provider instanceof ReportedIP_Hive_Mail_Provider_Interface ) ) {
			$provider = $default;
		}

		$this->resolved_provider = $provider;
		return $provider;
	}

	/**
	 * Reset the cached provider — useful in tests when a filter is added late.
	 */
	public function reset_provider_cache() {
		$this->resolved_provider = null;
	}

	/**
	 * Normalize / fill defaults for the args array.
	 *
	 * @param array $args Caller args.
	 * @return array Normalized args.
	 */
	private function normalize_args( array $args ) {
		$site_name = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		if ( '' === $site_name ) {
			$site_name = 'WordPress';
		}
		$site_url = home_url();

		$defaults = array(
			'to'              => '',
			'subject'         => '',
			'greeting'        => '',
			'intro_text'      => '',
			'main_block_html' => '',
			'main_block_text' => '',
			'cta'             => array(),
			'security_notice' => array(),
			'disclaimer'      => '',
			'headers'         => array(),
			'context'         => array(),
			'site_name'       => $site_name,
			'site_url'        => $site_url,
		);

		$args = array_merge( $defaults, $args );

		$args['headers']         = (array) $args['headers'];
		$args['cta']             = is_array( $args['cta'] ) ? $args['cta'] : array();
		$args['context']         = is_array( $args['context'] ) ? $args['context'] : array();
		$args['security_notice'] = is_array( $args['security_notice'] ) ? $args['security_notice'] : array();

		$has_content_type = false;
		foreach ( $args['headers'] as $header ) {
			if ( is_string( $header ) && stripos( $header, 'content-type:' ) === 0 ) {
				$has_content_type = true;
				break;
			}
		}
		if ( ! $has_content_type ) {
			$args['headers'][] = 'Content-Type: text/html; charset=UTF-8';
		}

		$has_from = false;
		foreach ( $args['headers'] as $header ) {
			if ( is_string( $header ) && stripos( $header, 'from:' ) === 0 ) {
				$has_from = true;
				break;
			}
		}
		if ( ! $has_from ) {
			$admin_email = (string) get_option( 'admin_email', '' );
			if ( '' !== $admin_email ) {
				$args['headers'][] = 'From: ' . $args['site_name'] . ' <' . $admin_email . '>';
			}
		}

		return $args;
	}

	/**
	 * Log the dispatch result, if a logger is available.
	 *
	 * @param array                                  $args     Normalized args.
	 * @param bool                                   $result   Send result.
	 * @param ReportedIP_Hive_Mail_Provider_Interface $provider Active provider.
	 */
	private function log_result( array $args, $result, $provider ) {
		if ( ! class_exists( 'ReportedIP_Hive_Logger' ) ) {
			return;
		}

		$logger = ReportedIP_Hive_Logger::get_instance();
		if ( ! $logger || ! method_exists( $logger, 'info' ) ) {
			return;
		}

		$mail_type = isset( $args['context']['type'] ) ? (string) $args['context']['type'] : 'generic';
		$ip        = isset( $args['security_notice']['ip'] ) ? (string) $args['security_notice']['ip'] : 'system';
		$payload   = array(
			'type'      => $mail_type,
			'provider'  => method_exists( $provider, 'get_name' ) ? $provider->get_name() : 'unknown',
			'recipient' => $this->mask_email( (string) $args['to'] ),
			'success'   => (bool) $result,
		);

		if ( $result ) {
			$logger->info( 'mail_sent', $ip, $payload );
		} elseif ( method_exists( $logger, 'warning' ) ) {
			$logger->warning( 'mail_failed', $ip, $payload );
		} else {
			$logger->info( 'mail_failed', $ip, $payload );
		}
	}

	/**
	 * Mask an email address for logging (privacy).
	 *
	 * @param string $email Email.
	 * @return string Masked form (a***@example.com).
	 */
	private function mask_email( $email ) {
		$at = strpos( $email, '@' );
		if ( false === $at || $at < 1 ) {
			return '***';
		}
		$local   = substr( $email, 0, $at );
		$domain  = substr( $email, $at );
		$visible = substr( $local, 0, 1 );
		return $visible . str_repeat( '*', max( 1, strlen( $local ) - 1 ) ) . $domain;
	}
}
