<?php
/**
 * Scanner behind the campaign-link gates of both plugins and the repository.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.1
 */

namespace ReportedIP\Hive\Tests;

/**
 * Finds every reportedip.com URL in a set of files and reports the ones
 * that break the campaign rule: a deep link carries `rc=<source>` of its
 * channel, an API endpoint, feed or legal page carries none, reportedip.de
 * and `utm_*` parameters do not appear at all.
 *
 * Plain PHP without WordPress, so the free and the pro unit suites and the
 * repository gate (tools/gates/campaign-links.php) share one rule.
 */
final class CampaignLinkScanner {

	/**
	 * URLs that never carry a campaign tag: REST API, feeds, legal pages,
	 * the GDPR request page. Same list as
	 * {@see \ReportedIP_Hive_Catalog::CAMPAIGN_EXEMPT}.
	 */
	const EXEMPT = '#^/(?:wp-json/|feed/|(?:[a-z]{2}/)?feed/|datenschutzerklaerung/|impressum/|nutzungsbedingungen/|agb/|privacy|terms|dashboard/dsgvo)#i';

	/**
	 * Matches a reportedip URL with scheme.
	 */
	const URL = '#https?://(?:www\.)?reportedip\.(?:com|de)(?:[/?\#][^\s"\'<>()\[\]{}`\\\\,]*)?#i';

	/**
	 * Collect the findings for a list of files.
	 *
	 * @param string                $root     Directory the reported paths are relative to.
	 * @param string[]              $files    Absolute file paths.
	 * @param callable              $expected Maps a relative path to the expected source (`hive-plugin`, ...).
	 * @param array<string, string> $allow    `relpath|url` => reason for literals that may stay untagged.
	 * @return string[] One line per finding.
	 */
	public static function scan( $root, array $files, callable $expected, array $allow = array() ) {
		$root     = rtrim( str_replace( '\\', '/', $root ), '/' ) . '/';
		$findings = array();

		foreach ( $files as $file ) {
			$rel    = substr( str_replace( '\\', '/', $file ), strlen( $root ) );
			$source = (string) $expected( $rel );
			$code   = (bool) preg_match( '/\.(php|js|css)$/', $rel );
			$lines  = preg_split( '/\R/', (string) file_get_contents( $file ) );

			foreach ( $lines as $i => $line ) {
				$where = $rel . ':' . ( $i + 1 );
				if ( preg_match( '/utm_(?:source|medium|campaign|content|term)/i', $line ) ) {
					$findings[] = $where . ' utm_ parameter, use rc';
				}
				if ( preg_match( '/@(?:link|author|copyright)\b|Update URI:|Report-Msgid-Bugs-To:/', $line ) ) {
					continue;
				}
				if ( $code && preg_match( '#^\s*(?:\*|/\*|//)#', $line ) ) {
					continue;
				}
				if ( ! preg_match_all( self::URL, $line, $m ) ) {
					continue;
				}
				foreach ( $m[0] as $url ) {
					$url = rtrim( $url, '.;:' );
					if ( isset( $allow[ $rel . '|' . $url ] ) ) {
						continue;
					}
					$problem = self::problem( $url, $source );
					if ( '' !== $problem ) {
						$findings[] = $where . ' ' . $url . ' ' . $problem;
					}
				}
			}
		}

		return $findings;
	}

	/**
	 * What is wrong with one URL, '' when nothing.
	 *
	 * @param string $url    URL found.
	 * @param string $source Expected campaign source.
	 * @return string
	 */
	public static function problem( $url, $source ) {
		if ( preg_match( '#^https?://(?:www\.)?reportedip\.de#i', $url ) ) {
			return 'points at reportedip.de';
		}
		$path   = (string) parse_url( $url, PHP_URL_PATH );
		$query  = (string) parse_url( $url, PHP_URL_QUERY );
		$tagged = (bool) preg_match( '/(?:^|&)rc=/', $query );

		if ( preg_match( self::EXEMPT, '' === $path ? '/' : $path ) ) {
			return $tagged ? 'API, feed or legal page must not carry rc' : '';
		}
		if ( ! preg_match( '/(?:^|&)rc=' . preg_quote( $source, '/' ) . '(?:&|$)/', $query ) ) {
			return 'needs rc=' . $source;
		}

		return '';
	}

	/**
	 * Files below a directory with one of the extensions.
	 *
	 * @param string   $dir  Directory.
	 * @param string[] $exts Extensions without dot.
	 * @param string[] $skip Path fragments to leave out.
	 * @return string[]
	 */
	public static function files( $dir, array $exts, array $skip = array( '/vendor/', '/node_modules/', '/tests/', '.min.js' ) ) {
		$out = array();
		if ( is_file( $dir ) ) {
			return array( $dir );
		}
		if ( ! is_dir( $dir ) ) {
			return $out;
		}
		$it = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $f ) {
			$path = str_replace( '\\', '/', (string) $f );
			if ( ! in_array( strtolower( pathinfo( $path, PATHINFO_EXTENSION ) ), $exts, true ) ) {
				continue;
			}
			foreach ( $skip as $s ) {
				if ( false !== strpos( $path, $s ) ) {
					continue 2;
				}
			}
			$out[] = $path;
		}
		sort( $out );
		return $out;
	}
}
