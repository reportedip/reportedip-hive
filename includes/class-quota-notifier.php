<?php
/**
 * Sends factual mail-relay / SMS-relay quota notifications to site
 * administrators when the monthly allowance crosses 80 % or reaches 100 %.
 *
 * Required by PRICING-PLAN.md §8 ("Anti-Abuse-Regeln") — the operator must
 * know about an impending cap before transactional 2FA traffic starts
 * silently bouncing to {@see wp_mail()} (mail) or rejecting (SMS).
 *
 * Listens on the {@see do_action() reportedip_hive_relay_quota_refreshed}
 * action that {@see ReportedIP_Hive_Cron_Handler::cron_refresh_quota()}
 * fires every six hours after a successful `/relay-quota` call. Per
 * channel + stage there is a 30-day cooldown so a stuck cap never spams
 * the admin inbox; the cooldown automatically resets at each new billing
 * period (`period_start` change).
 *
 * This class is deliberately separate from the Promo_Manager frequency
 * cap — quota notifications are operational service info, not marketing.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.16
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Static-only listener for relay-quota-refreshed events.
 *
 * @since 2.0.16
 */
class ReportedIP_Hive_Quota_Notifier {

	/**
	 * Site option that the Settings → Notifications toggle writes. Default true.
	 */
	const OPT_ENABLED = 'reportedip_hive_quota_notif_enabled';

	/**
	 * Site option that stores `{channel.stage => {sent_at, period_start}}` for
	 * the per-channel, per-stage cooldown tracking. Implicitly resets when the
	 * billing period flips because we key the suppression on `period_start`.
	 */
	const OPT_STATE = 'reportedip_hive_quota_notif_state';

	/**
	 * Stage key for the 80 % early-warning mail.
	 */
	const STAGE_WARN = 'warn80';

	/**
	 * Stage key for the 100 % cap-reached mail.
	 */
	const STAGE_CAPPED = 'capped';

	/**
	 * Minimum seconds between two mails for the same channel + stage within
	 * the same billing period. 30 days — long enough that a flapping ratio
	 * cannot spam, short enough that a forgotten state still gets a nudge.
	 */
	const COOLDOWN_SECS = 2592000;

	/**
	 * Wire the WordPress hooks. Idempotent.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'reportedip_hive_relay_quota_refreshed', array( __CLASS__, 'evaluate' ), 10, 1 );
	}

	/**
	 * Evaluate the quota snapshot and dispatch any pending stage mails.
	 *
	 * @param array $snapshot Output of {@see ReportedIP_Hive_Mode_Manager::get_relay_quota_snapshot()}.
	 * @return void
	 * @since  2.0.16
	 */
	public static function evaluate( $snapshot ) {
		if ( ! self::is_enabled() ) {
			return;
		}
		if ( ! is_array( $snapshot ) ) {
			return;
		}

		foreach ( array( 'mail', 'sms' ) as $channel ) {
			$stage = self::evaluate_channel( $snapshot, $channel );
			if ( null === $stage ) {
				continue;
			}
			if ( ! self::should_send( $channel, $stage, $snapshot ) ) {
				continue;
			}
			if ( ! self::dispatch( $channel, $stage, $snapshot ) ) {
				continue;
			}
			self::record_sent( $channel, $stage, $snapshot );
		}
	}

	/**
	 * Whether quota notifications are enabled site-wide.
	 *
	 * @return bool
	 * @since  2.0.16
	 */
	public static function is_enabled() {
		return (bool) ReportedIP_Hive_Option_Routing::get( self::OPT_ENABLED, true );
	}

	/**
	 * Map the channel's used/limit ratio to a stage, or null if no notice is due.
	 *
	 * Public so the unit tests can hit the pure-function part of the logic
	 * directly without spinning up a Mailer stub.
	 *
	 * @param array  $snapshot
	 * @param string $channel  'mail' | 'sms'.
	 * @return string|null One of the STAGE_* constants or null.
	 */
	public static function evaluate_channel( array $snapshot, $channel ) {
		$data = $snapshot[ $channel ] ?? null;
		if ( ! is_array( $data ) ) {
			return null;
		}
		$limit = $data['limit'] ?? null;
		if ( null === $limit || (int) $limit <= 0 ) {
			return null;
		}
		$used  = (int) ( $data['used'] ?? 0 );
		$ratio = $used / (int) $limit;
		if ( $ratio >= 1.0 ) {
			return self::STAGE_CAPPED;
		}
		if ( $ratio >= 0.8 ) {
			return self::STAGE_WARN;
		}
		return null;
	}

	/**
	 * Decide whether the stage mail should be sent now. Returns true on a
	 * fresh billing period or after the cooldown has elapsed.
	 *
	 * Public so the unit tests can verify the cooldown and period-reset
	 * behaviour without spinning up a Mailer stub.
	 *
	 * @param string $channel
	 * @param string $stage
	 * @param array  $snapshot
	 * @return bool
	 */
	public static function should_send( $channel, $stage, array $snapshot ) {
		$state  = self::get_state();
		$key    = $channel . '.' . $stage;
		$period = (int) ( $snapshot['period_start'] ?? 0 );
		$last   = isset( $state[ $key ] ) && is_array( $state[ $key ] )
			? $state[ $key ]
			: array(
				'sent_at'      => 0,
				'period_start' => 0,
			);

		if ( $period > 0 && (int) ( $last['period_start'] ?? 0 ) !== $period ) {
			return true;
		}
		if ( time() - (int) ( $last['sent_at'] ?? 0 ) < self::COOLDOWN_SECS ) {
			return false;
		}
		return true;
	}

	/**
	 * Dispatch the stage mail. Returns true on success.
	 *
	 * @param string $channel
	 * @param string $stage
	 * @param array  $snapshot
	 * @return bool
	 */
	private static function dispatch( $channel, $stage, array $snapshot ) {
		if ( ! class_exists( 'ReportedIP_Hive_Mailer' ) ) {
			return false;
		}
		if ( ! class_exists( 'ReportedIP_Hive_Defaults' ) ) {
			return false;
		}

		$recipients = ReportedIP_Hive_Defaults::notify_recipients();
		if ( empty( $recipients ) ) {
			return false;
		}

		$args = self::build_mail( $channel, $stage, $snapshot, $recipients );
		return (bool) ReportedIP_Hive_Mailer::get_instance()->send( $args );
	}

	/**
	 * Persist the sent-timestamp so the cooldown takes effect.
	 *
	 * @param string $channel
	 * @param string $stage
	 * @param array  $snapshot
	 * @return void
	 */
	private static function record_sent( $channel, $stage, array $snapshot ) {
		$state                            = self::get_state();
		$state[ $channel . '.' . $stage ] = array(
			'sent_at'      => time(),
			'period_start' => (int) ( $snapshot['period_start'] ?? 0 ),
		);
		ReportedIP_Hive_Option_Routing::set( self::OPT_STATE, $state );
	}

	/**
	 * @return array<string, array{sent_at:int,period_start:int}>
	 */
	private static function get_state() {
		$raw = ReportedIP_Hive_Option_Routing::get( self::OPT_STATE, array() );
		return is_array( $raw ) ? $raw : array();
	}

	/**
	 * Build the Mailer::send() args for a single stage mail.
	 *
	 * @param string   $channel    'mail' | 'sms'.
	 * @param string   $stage      STAGE_WARN | STAGE_CAPPED.
	 * @param array    $snapshot   Quota snapshot.
	 * @param string[] $recipients Validated admin emails.
	 * @return array
	 */
	private static function build_mail( $channel, $stage, array $snapshot, array $recipients ) {
		$data       = $snapshot[ $channel ] ?? array();
		$used       = (int) ( $data['used'] ?? 0 );
		$limit      = (int) ( $data['limit'] ?? 0 );
		$period_end = (int) ( $snapshot['period_end'] ?? 0 );
		$reset_str  = $period_end > 0
			? date_i18n( get_option( 'date_format', 'Y-m-d' ), $period_end )
			: __( 'at the next monthly reset', 'reportedip-hive' );

		$site_name = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );

		if ( 'mail' === $channel ) {
			$channel_label = __( 'Mail relay', 'reportedip-hive' );
			$fallback_hint = __( 'Mails will keep going out through your local wp_mail() until the relay resumes.', 'reportedip-hive' );
		} else {
			$channel_label = __( 'SMS relay', 'reportedip-hive' );
			$fallback_hint = __( 'SMS-based 2FA codes are paused — users can still authenticate with TOTP, Email or a Passkey.', 'reportedip-hive' );
		}

		if ( self::STAGE_WARN === $stage ) {
			$subject = sprintf(
				/* translators: 1: site name, 2: channel label */
				__( '[%1$s] %2$s: 80%% of monthly allowance used', 'reportedip-hive' ),
				$site_name,
				$channel_label
			);
			$intro = sprintf(
				/* translators: 1: channel label, 2: used, 3: limit, 4: reset date */
				__( 'Your %1$s allowance is currently at %2$d of %3$d for this month. Resets on %4$s.', 'reportedip-hive' ),
				$channel_label,
				$used,
				$limit,
				$reset_str
			);
			$body = __( 'No action required — this is an early heads-up so you can buy a bundle in your customer portal if the rest of the month tends to be busier.', 'reportedip-hive' );
		} else {
			$subject = sprintf(
				/* translators: 1: site name, 2: channel label */
				__( '[%1$s] %2$s: monthly allowance reached', 'reportedip-hive' ),
				$site_name,
				$channel_label
			);
			$intro = sprintf(
				/* translators: 1: channel label, 2: used, 3: limit, 4: reset date */
				__( 'Your %1$s allowance has reached its monthly cap (%2$d of %3$d). Resets on %4$s.', 'reportedip-hive' ),
				$channel_label,
				$used,
				$limit,
				$reset_str
			);
			$body = $fallback_hint;
		}

		$portal_url = defined( 'REPORTEDIP_HIVE_UPGRADE_URL' )
			? REPORTEDIP_HIVE_UPGRADE_URL
			: 'https://reportedip.de/dashboard/';

		return array(
			'to'              => implode( ', ', $recipients ),
			'subject'         => $subject,
			'intro'           => $intro,
			'main_block_html' => '<p>' . esc_html( $body ) . '</p>',
			'main_block_text' => $body,
			'cta'             => array(
				'label' => __( 'Open customer portal', 'reportedip-hive' ),
				'url'   => $portal_url,
			),
			'context'         => array(
				'kind'    => 'quota_notification',
				'channel' => $channel,
				'stage'   => $stage,
			),
		);
	}
}
