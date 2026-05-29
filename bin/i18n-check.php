<?php
/**
 * Translation freshness gate: verifies that the POT is current, the German PO is
 * fully translated and the compiled MO/JSON artifacts are in sync with the PO.
 *
 * Exit code 0 when everything is consistent, 1 otherwise. Runs file-based only
 * (no WordPress install, no database) so it works in CI, GrumPHP and locally on
 * both Windows and Linux.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.18
 */

declare(strict_types=1);

namespace ReportedIP\Hive\Bin;

/**
 * Orchestrates the three consistency checks and aggregates their results.
 *
 * @since 2.0.18
 */
final class I18nCheck {

	private const SLUG     = 'reportedip-hive';
	private const DOMAIN   = 'reportedip-hive';
	private const LANG_DIR = 'languages';
	private const POT      = 'languages/reportedip-hive.pot';
	private const PO_DE    = 'languages/reportedip-hive-de_DE.po';

	/**
	 * Absolute path to the plugin root (parent of bin/).
	 *
	 * @var string
	 */
	private string $root;

	/**
	 * Collected failure messages.
	 *
	 * @var string[]
	 */
	private array $failures = array();

	/**
	 * @param string $root Plugin root directory.
	 */
	public function __construct( string $root ) {
		$this->root = rtrim( $root, '/\\' );
	}

	/**
	 * Runs all checks and returns the process exit code.
	 *
	 * @return int 0 on success, 1 on any failure.
	 */
	public function run(): int {
		$this->check_pot_freshness();
		$this->check_translation_completeness();
		$this->check_artifact_sync();

		if ( empty( $this->failures ) ) {
			fwrite( STDOUT, "[i18n] OK — POT fresh, German translation complete, MO/JSON in sync.\n" );
			return 0;
		}

		fwrite( STDERR, "[i18n] FAILED:\n" );
		foreach ( $this->failures as $message ) {
			fwrite( STDERR, '  - ' . $message . "\n" );
		}
		fwrite( STDERR, "\nRun 'composer i18n' to refresh translations, then translate any new entries.\n" );
		return 1;
	}

	/**
	 * Regenerates the POT into a temp file and compares it to the committed POT,
	 * ignoring the volatile header dates.
	 *
	 * @return void
	 */
	private function check_pot_freshness(): void {
		$pot = $this->path( self::POT );
		if ( ! is_file( $pot ) ) {
			$this->failures[] = self::POT . ' is missing.';
			return;
		}

		$tmp = $this->temp_file( 'pot' );
		$cmd = sprintf(
			'i18n make-pot . %s --slug=%s --domain=%s --exclude=vendor,tests,bin,build,node_modules',
			escapeshellarg( $tmp ),
			self::SLUG,
			self::DOMAIN
		);
		if ( 0 !== $this->wp( $cmd ) ) {
			$this->failures[] = 'Failed to regenerate the POT for the freshness comparison.';
			@unlink( $tmp );
			return;
		}

		$committed = $this->pot_entry_keys( $pot );
		$fresh     = $this->pot_entry_keys( $tmp );
		@unlink( $tmp );

		$added   = array_diff( $fresh, $committed );
		$removed = array_diff( $committed, $fresh );
		if ( ! empty( $added ) || ! empty( $removed ) ) {
			$this->failures[] = sprintf(
				'%s is stale — %d new and %d removed source string(s). Run "composer i18n:pot".',
				self::POT,
				count( $added ),
				count( $removed )
			);
		}
	}

	/**
	 * Counts untranslated and fuzzy entries in the German PO.
	 *
	 * @return void
	 */
	private function check_translation_completeness(): void {
		$po = $this->path( self::PO_DE );
		if ( ! is_file( $po ) ) {
			$this->failures[] = self::PO_DE . ' is missing — German translation not initialised.';
			return;
		}

		$stats = $this->po_stats( $po );
		if ( $stats['untranslated'] > 0 || $stats['fuzzy'] > 0 ) {
			$this->failures[] = sprintf(
				'%s has %d untranslated and %d fuzzy entries.',
				self::PO_DE,
				$stats['untranslated'],
				$stats['fuzzy']
			);
		}
	}

	/**
	 * Rebuilds MO/JSON from the committed PO into a temp directory and compares
	 * them byte-for-byte against the committed artifacts.
	 *
	 * @return void
	 */
	private function check_artifact_sync(): void {
		$po = $this->path( self::PO_DE );
		if ( ! is_file( $po ) ) {
			return;
		}

		$committed = $this->collect_artifacts( $this->path( self::LANG_DIR ) );

		$tmp_dir = $this->temp_dir();
		copy( $po, $tmp_dir . '/' . basename( self::PO_DE ) );
		$this->wp( 'i18n make-mo ' . escapeshellarg( $tmp_dir ) . ' ' . escapeshellarg( $tmp_dir ) );
		$this->wp( 'i18n make-json ' . escapeshellarg( $tmp_dir ) . ' ' . escapeshellarg( $tmp_dir ) );
		$fresh = $this->collect_artifacts( $tmp_dir );

		$missing = array_diff( array_keys( $fresh ), array_keys( $committed ) );
		foreach ( $missing as $name ) {
			$this->failures[] = "Compiled artifact $name is missing — run 'composer i18n:build'.";
		}
		foreach ( $committed as $name => $hash ) {
			if ( isset( $fresh[ $name ] ) && $fresh[ $name ] !== $hash ) {
				$this->failures[] = "Compiled artifact $name is out of sync — run 'composer i18n:build'.";
			}
		}

		$this->rmdir_recursive( $tmp_dir );
	}

	/**
	 * Returns a map of artifact basename => content hash for MO/JSON files in a dir.
	 *
	 * @param string $dir Directory to scan.
	 * @return array<string,string>
	 */
	private function collect_artifacts( string $dir ): array {
		$map = array();
		foreach ( array_merge( glob( $dir . '/*.mo' ) ?: array(), glob( $dir . '/*.json' ) ?: array() ) as $file ) {
			$map[ basename( $file ) ] = md5_file( $file );
		}
		return $map;
	}

	/**
	 * Reads a PO file and counts untranslated and fuzzy entries (excluding header).
	 *
	 * @param string $file PO file path.
	 * @return array{untranslated:int,fuzzy:int}
	 */
	private function po_stats( string $file ): array {
		$untranslated = 0;
		$fuzzy        = 0;

		$content = file_get_contents( $file );
		$content = str_replace( "\r\n", "\n", (string) $content );
		$blocks  = preg_split( "/\n\n+/", trim( $content ) );

		foreach ( $blocks as $block ) {
			$lines      = explode( "\n", $block );
			$is_fuzzy   = false;
			$msgid      = null;
			$has_msgstr = false;
			$msgstr_all = '';
			$current    = null;

			foreach ( $lines as $line ) {
				if ( '' === $line ) {
					continue;
				}
				if ( '#' === $line[0] ) {
					if ( preg_match( '/^#,.*\bfuzzy\b/', $line ) ) {
						$is_fuzzy = true;
					}
					$current = null;
					continue;
				}
				if ( preg_match( '/^msgid\s+"(.*)"$/s', $line, $m ) ) {
					$msgid   = $m[1];
					$current = 'msgid';
					continue;
				}
				if ( preg_match( '/^msgid_plural\s+/', $line ) ) {
					$current = 'plural';
					continue;
				}
				if ( preg_match( '/^msgstr(?:\[\d+\])?\s+"(.*)"$/s', $line, $m ) ) {
					$has_msgstr  = true;
					$msgstr_all .= $m[1];
					$current     = 'msgstr';
					continue;
				}
				if ( preg_match( '/^"(.*)"$/s', $line, $m ) && 'msgstr' === $current ) {
					$msgstr_all .= $m[1];
				}
			}

			if ( null === $msgid || '' === $msgid ) {
				continue;
			}
			if ( $is_fuzzy ) {
				++$fuzzy;
			}
			if ( $has_msgstr && '' === $msgstr_all ) {
				++$untranslated;
			}
		}

		return array(
			'untranslated' => $untranslated,
			'fuzzy'        => $fuzzy,
		);
	}

	/**
	 * Returns the sorted set of translatable entry keys (context + msgid +
	 * msgid_plural) in a POT, ignoring order, references, headers and dates.
	 *
	 * Comparing this set — rather than the raw file — makes the freshness
	 * check independent of make-pot's file-scan order (which differs between
	 * Windows and Linux) and of cosmetic reference-line drift. It flags only
	 * genuine additions or removals of source strings.
	 *
	 * @param string $file POT file path.
	 * @return string[] Sorted, de-duplicated entry keys.
	 */
	private function pot_entry_keys( string $file ): array {
		$content = str_replace( "\r\n", "\n", (string) file_get_contents( $file ) );
		$blocks  = preg_split( "/\n\n+/", trim( $content ) );
		$keys    = array();

		foreach ( (array) $blocks as $block ) {
			$ctxt    = '';
			$id      = '';
			$plural  = '';
			$current = null;
			foreach ( explode( "\n", $block ) as $line ) {
				if ( '' === $line || '#' === $line[0] ) {
					$current = null;
					continue;
				}
				if ( preg_match( '/^msgctxt\s+"(.*)"$/s', $line, $m ) ) {
					$ctxt    = $m[1];
					$current = 'c';
				} elseif ( preg_match( '/^msgid_plural\s+"(.*)"$/s', $line, $m ) ) {
					$plural  = $m[1];
					$current = 'p';
				} elseif ( preg_match( '/^msgid\s+"(.*)"$/s', $line, $m ) ) {
					$id      = $m[1];
					$current = 'i';
				} elseif ( preg_match( '/^msgstr/', $line ) ) {
					$current = null;
				} elseif ( preg_match( '/^"(.*)"$/s', $line, $m ) ) {
					if ( 'i' === $current ) {
						$id .= $m[1];
					} elseif ( 'p' === $current ) {
						$plural .= $m[1];
					} elseif ( 'c' === $current ) {
						$ctxt .= $m[1];
					}
				}
			}
			if ( '' === $id ) {
				continue;
			}
			$keys[] = $ctxt . "\x01" . $id . "\x01" . $plural;
		}

		$keys = array_values( array_unique( $keys ) );
		sort( $keys );
		return $keys;
	}

	/**
	 * Runs a wp-cli sub-command from the plugin root, suppressing its output.
	 *
	 * @param string $args wp-cli arguments after the binary.
	 * @return int Exit code.
	 */
	private function wp( string $args ): int {
		$bin = $this->is_windows() ? 'vendor\\bin\\wp.bat' : 'vendor/bin/wp';
		$cmd = sprintf(
			'%s %s %s --path=%s 2>%s',
			escapeshellarg( $bin ),
			$args,
			'--quiet',
			escapeshellarg( $this->root ),
			$this->is_windows() ? 'NUL' : '/dev/null'
		);
		$cwd = getcwd();
		chdir( $this->root );
		$code = 0;
		$out  = array();
		exec( $cmd, $out, $code );
		chdir( (string) $cwd );
		return $code;
	}

	/**
	 * Joins a relative path onto the plugin root.
	 *
	 * @param string $relative Relative path.
	 * @return string
	 */
	private function path( string $relative ): string {
		return $this->root . '/' . $relative;
	}

	/**
	 * Creates a uniquely named temporary file and returns its path.
	 *
	 * @param string $ext File extension.
	 * @return string
	 */
	private function temp_file( string $ext ): string {
		return rtrim( sys_get_temp_dir(), '/\\' ) . '/rip-i18n-' . uniqid() . '.' . $ext;
	}

	/**
	 * Creates a uniquely named temporary directory and returns its path.
	 *
	 * @return string
	 */
	private function temp_dir(): string {
		$dir = rtrim( sys_get_temp_dir(), '/\\' ) . '/rip-i18n-' . uniqid();
		mkdir( $dir, 0777, true );
		return $dir;
	}

	/**
	 * Recursively removes a directory.
	 *
	 * @param string $dir Directory path.
	 * @return void
	 */
	private function rmdir_recursive( string $dir ): void {
		foreach ( glob( $dir . '/*' ) ?: array() as $file ) {
			is_dir( $file ) ? $this->rmdir_recursive( $file ) : @unlink( $file );
		}
		@rmdir( $dir );
	}

	/**
	 * Whether the current platform is Windows.
	 *
	 * @return bool
	 */
	private function is_windows(): bool {
		return 0 === stripos( PHP_OS, 'WIN' );
	}
}

exit( ( new I18nCheck( dirname( __DIR__ ) ) )->run() );
