<?php
/**
 * Post-update "What's new" banner sourced from the reportedip.com feed.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.41
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Renders a one-time release-highlights banner on plugin admin pages.
 *
 * Called from {@see ReportedIP_Hive_Admin_Settings::render_inline_notices()}
 * so the banner only ever appears inside Hive's own pages, never on foreign
 * admin screens. The highlight feed is fetched at most once per installed
 * version from the public endpoint
 * `/wp-json/reportedip/v2/hive/whats-new` on reportedip.com (no API key
 * required) and cached network-wide; failures back off silently.
 *
 * State keys `reportedip_hive_whatsnew_seen_version` and
 * `reportedip_hive_whatsnew_payload` are deliberately NOT part of
 * `ReportedIP_Hive_Defaults::SAFE_OPTIONS` — like
 * `reportedip_hive_seeded_version` they are state markers, not settings, and
 * must never be seeded, exported or imported.
 *
 * The class is intentionally not final: {@see self::fetch_feed()} is the
 * protected HTTP seam that unit tests override via a subclass.
 *
 * @since 2.1.41
 */
class ReportedIP_Hive_Whats_New {

	/**
	 * Option key holding the last plugin version whose feed was consumed.
	 *
	 * @var string
	 */
	const OPT_SEEN_VERSION = 'reportedip_hive_whatsnew_seen_version';

	/**
	 * Option key holding the sanitized feed payload for the current version.
	 *
	 * @var string
	 */
	const OPT_PAYLOAD = 'reportedip_hive_whatsnew_payload';

	/**
	 * Site-transient key that pauses feed fetches after a miss or failure.
	 *
	 * @var string
	 */
	const BACKOFF_TRANSIENT = 'reportedip_hive_whatsnew_backoff';

	/**
	 * Fallback release-notes target when the feed URL fails validation.
	 *
	 * @var string
	 */
	const FALLBACK_NOTES_URL = 'https://github.com/reportedip/reportedip-hive/releases';

	/**
	 * Maximum number of highlight rows rendered in the banner.
	 *
	 * @var int
	 */
	const MAX_HIGHLIGHTS = 6;

	/**
	 * Maximum character length per highlight row.
	 *
	 * @var int
	 */
	const MAX_HIGHLIGHT_LENGTH = 200;

	/**
	 * Render the banner when the current version has unseen highlights.
	 *
	 * Gate order: per-user dismissal, cached payload (renders without HTTP),
	 * already-consumed version, active backoff, then a single feed fetch.
	 * A feed that reports a different version than the installed one sets a
	 * 12 h backoff without marking the version as seen so the banner can
	 * still appear once the server catches up; fetch failures back off 6 h.
	 *
	 * @return void
	 * @since  2.1.41
	 */
	public static function maybe_render() {
		$ver_key = 'whatsnew_' . str_replace( '.', '_', REPORTEDIP_HIVE_VERSION );

		if ( get_user_meta( get_current_user_id(), 'reportedip_dismissed_' . $ver_key, true ) ) {
			return;
		}

		$payload = ReportedIP_Hive_Option_Routing::get( self::OPT_PAYLOAD, array() );
		if ( is_array( $payload ) && isset( $payload['version'] ) && REPORTEDIP_HIVE_VERSION === $payload['version'] ) {
			self::render_notice( $payload, $ver_key );
			return;
		}

		if ( REPORTEDIP_HIVE_VERSION === ReportedIP_Hive_Option_Routing::get( self::OPT_SEEN_VERSION, '' ) ) {
			return;
		}

		if ( false !== get_site_transient( self::BACKOFF_TRANSIENT ) ) {
			return;
		}

		$feed = static::fetch_feed();
		if ( ! is_array( $feed ) || empty( $feed['version'] ) || ! is_string( $feed['version'] ) ) {
			set_site_transient( self::BACKOFF_TRANSIENT, 1, 6 * HOUR_IN_SECONDS );
			return;
		}

		if ( REPORTEDIP_HIVE_VERSION !== $feed['version'] ) {
			set_site_transient( self::BACKOFF_TRANSIENT, 1, 12 * HOUR_IN_SECONDS );
			return;
		}

		$payload = self::sanitize_payload( $feed );
		ReportedIP_Hive_Option_Routing::set( self::OPT_PAYLOAD, $payload );
		ReportedIP_Hive_Option_Routing::set( self::OPT_SEEN_VERSION, REPORTEDIP_HIVE_VERSION );
		self::render_notice( $payload, $ver_key );
	}

	/**
	 * Fetch and decode the public What's-new feed.
	 *
	 * Protected seam: unit tests subclass this class and override the method
	 * so the gate matrix can be exercised without HTTP.
	 *
	 * @return array<string,mixed>|null Decoded feed on success, null otherwise.
	 * @since  2.1.41
	 */
	protected static function fetch_feed() {
		$base     = untrailingslashit( apply_filters( 'reportedip_hive_external_url', REPORTEDIP_HIVE_SITE_URL, 'whatsnew_feed' ) );
		$response = wp_remote_get(
			$base . '/wp-json/reportedip/v2/hive/whats-new',
			array(
				'timeout' => 5,
				'headers' => array(
					'User-Agent' => class_exists( 'ReportedIP_Hive_API' )
						? ReportedIP_Hive_API::api_user_agent()
						: 'ReportedIP-Hive/' . REPORTEDIP_HIVE_VERSION,
				),
			)
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		$decoded = json_decode( wp_remote_retrieve_body( $response ), true );

		return is_array( $decoded ) ? $decoded : null;
	}

	/**
	 * Reduce a raw feed to the stored payload shape.
	 *
	 * Highlights are capped at {@see self::MAX_HIGHLIGHTS} rows, stripped of
	 * markup, shortened to {@see self::MAX_HIGHLIGHT_LENGTH} characters by
	 * {@see self::shorten()} and cleared of empty rows. The notes URL passes
	 * through {@see self::sanitize_notes_url()}.
	 *
	 * @param array<string,mixed> $feed Decoded feed body.
	 * @return array{version:string,highlights:array<int,string>,notes_url:string}
	 * @since  2.1.41
	 */
	private static function sanitize_payload( array $feed ) {
		$highlights = array();
		$raw        = isset( $feed['highlights'] ) && is_array( $feed['highlights'] ) ? $feed['highlights'] : array();

		foreach ( array_slice( array_values( $raw ), 0, self::MAX_HIGHLIGHTS ) as $item ) {
			if ( ! is_string( $item ) ) {
				continue;
			}
			$clean = trim( wp_strip_all_tags( $item ) );
			if ( '' === $clean ) {
				continue;
			}
			$highlights[] = self::shorten( $clean, self::MAX_HIGHLIGHT_LENGTH );
		}

		return array(
			'version'    => REPORTEDIP_HIVE_VERSION,
			'highlights' => $highlights,
			'notes_url'  => self::sanitize_notes_url( isset( $feed['notes_url'] ) ? $feed['notes_url'] : '' ),
		);
	}

	/**
	 * Shorten a highlight at a sentence or word boundary.
	 *
	 * The feed already shortens its rows; this is the client-side guard for a
	 * row that still arrives over-long. A cut row ends in an ellipsis so a
	 * reader can tell the sentence continues in the release notes instead of
	 * seeing it stop mid-word. The last sentence end inside the limit wins, a
	 * word boundary is the fallback, a hard cut the last resort; the ellipsis
	 * counts towards the limit.
	 *
	 * @param string $text  Plain-text highlight.
	 * @param int    $limit Maximum length in characters, ellipsis included.
	 * @return string Highlight of at most $limit characters.
	 * @since  2.1.45
	 */
	private static function shorten( $text, $limit ) {
		if ( mb_strlen( $text ) <= $limit ) {
			return $text;
		}

		$cut = mb_substr( $text, 0, $limit - 1 );

		if ( preg_match_all( '/[.!?](?=\s|$)/u', $cut, $matches, PREG_OFFSET_CAPTURE ) ) {
			$last     = end( $matches[0] );
			$sentence = substr( $cut, 0, $last[1] );
			if ( mb_strlen( $sentence ) >= (int) round( $limit / 4 ) ) {
				return self::add_ellipsis( $sentence );
			}
		}

		$space = strrpos( $cut, ' ' );
		if ( false !== $space && mb_strlen( substr( $cut, 0, $space ) ) >= (int) round( $limit / 2 ) ) {
			$cut = substr( $cut, 0, $space );
		}

		return self::add_ellipsis( $cut );
	}

	/**
	 * Append an ellipsis, replacing any trailing punctuation.
	 *
	 * @param string $text Plain text to mark as continued.
	 * @return string
	 * @since  2.1.45
	 */
	private static function add_ellipsis( $text ) {
		return rtrim( $text, " \t\n\r\0\x0B.,;:!?-" ) . '…';
	}

	/**
	 * Validate the release-notes URL from the feed.
	 *
	 * Only https URLs whose host is reportedip.com or github.com (or a
	 * subdomain of either) are accepted; anything else falls back to the
	 * plugin releases page so the primary action always has a safe target.
	 *
	 * @param mixed $url Raw notes URL from the feed.
	 * @return string Safe URL.
	 * @since  2.1.41
	 */
	private static function sanitize_notes_url( $url ) {
		if ( ! is_string( $url ) || '' === $url ) {
			return self::FALLBACK_NOTES_URL;
		}

		$url = esc_url_raw( $url, array( 'https' ) );
		if ( '' === $url ) {
			return self::FALLBACK_NOTES_URL;
		}

		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) || ! isset( $parts['scheme'], $parts['host'] ) || 'https' !== strtolower( (string) $parts['scheme'] ) ) {
			return self::FALLBACK_NOTES_URL;
		}

		$host = strtolower( (string) $parts['host'] );
		foreach ( array( 'reportedip.com', 'github.com' ) as $allowed ) {
			if ( $host === $allowed || str_ends_with( $host, '.' . $allowed ) ) {
				return $url;
			}
		}

		return self::FALLBACK_NOTES_URL;
	}

	/**
	 * Render the banner through the shared admin-notice primitive.
	 *
	 * The notice id uses underscores instead of version dots because the
	 * persistent-dismiss AJAX path runs the id through `sanitize_key()`,
	 * which strips dots; a dotted id would never match its user-meta key.
	 *
	 * @param array<string,mixed> $payload Sanitized payload.
	 * @param string              $ver_key Dot-free notice id for this version.
	 * @return void
	 * @since  2.1.41
	 */
	private static function render_notice( array $payload, $ver_key ) {
		$highlights = array();
		if ( isset( $payload['highlights'] ) && is_array( $payload['highlights'] ) ) {
			foreach ( $payload['highlights'] as $item ) {
				if ( is_string( $item ) && '' !== $item ) {
					$highlights[] = esc_html( $item );
				}
			}
		}

		$notes_url = isset( $payload['notes_url'] ) && is_string( $payload['notes_url'] ) && '' !== $payload['notes_url']
			? $payload['notes_url']
			: self::FALLBACK_NOTES_URL;

		ReportedIP_Hive_Admin_Notice::render(
			array(
				'variant'        => 'info',
				'title'          => sprintf(
					/* translators: %s: plugin version */
					__( "What's new in ReportedIP Hive %s", 'reportedip-hive' ),
					REPORTEDIP_HIVE_VERSION
				),
				'list_items'     => $highlights,
				'primary_action' => array(
					'label'  => __( 'Read the release notes', 'reportedip-hive' ),
					'url'    => $notes_url,
					'target' => '_blank',
					'rel'    => 'noopener noreferrer',
				),
				'dismissible'    => true,
				'data_notice_id' => $ver_key,
				'extra_classes'  => 'rip-notice--whatsnew',
			)
		);
	}
}
