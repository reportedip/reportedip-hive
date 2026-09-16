<?php
/**
 * Icon markup: every shipped inline SVG must actually draw its dots.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.59
 */

declare(strict_types=1);

namespace ReportedIP\Hive\Tests\Unit;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReportedIP\Hive\Tests\TestCase;

/**
 * Source inspection over the inline-SVG icon set.
 *
 * @since 2.1.59
 */
final class IconMarkupTest extends TestCase {

	/**
	 * Directories that ship markup.
	 *
	 * @var string[]
	 */
	private const ROOTS = array( 'admin', 'includes', 'templates', 'assets/js' );

	/**
	 * Extensions that can carry an inline SVG.
	 *
	 * @var string[]
	 */
	private const EXTENSIONS = array( 'php', 'js' );

	/**
	 * The icon set draws the dot of an "i", of a warning sign and of a list
	 * bullet as a line of length zero. A browser renders a zero-length line
	 * only when the stroke ends in a round or square cap; with the default
	 * butt cap it draws nothing, and the glyph loses its dot. Every such SVG
	 * therefore has to carry a cap.
	 */
	public function test_no_svg_draws_a_zero_length_line_without_a_stroke_cap(): void {
		$offenders = array();
		foreach ( $this->source_files() as $file ) {
			$source = (string) file_get_contents( $file );
			preg_match_all( '#<svg\b[^>]*?>.*?</svg>#s', $source, $svgs );
			foreach ( $svgs[0] as $svg ) {
				preg_match( '#<svg\b[^>]*?>#', $svg, $tag );
				if ( false !== strpos( (string) $tag[0], 'stroke-linecap' ) ) {
					continue;
				}
				preg_match_all( '#<line\b[^>]*?>#', $svg, $lines );
				foreach ( $lines[0] as $line ) {
					if ( $this->is_zero_length( (string) $line ) && false === strpos( (string) $line, 'stroke-linecap' ) ) {
						$offenders[] = basename( (string) $file ) . ': ' . $line;
					}
				}
			}
		}

		$this->assertSame( array(), $offenders, 'a zero-length line needs stroke-linecap="round" on the line or its svg' );
	}

	/**
	 * Whether a line element is shorter than half a user unit.
	 *
	 * @param string $line The `<line>` element.
	 * @return bool
	 */
	private function is_zero_length( string $line ): bool {
		preg_match_all( '#(x1|y1|x2|y2)\s*=\s*"(-?[0-9.]+)"#', $line, $attributes, PREG_SET_ORDER );
		$coordinates = array();
		foreach ( $attributes as $attribute ) {
			$coordinates[ $attribute[1] ] = (float) $attribute[2];
		}
		if ( 4 !== count( $coordinates ) ) {
			return false;
		}

		return hypot( $coordinates['x1'] - $coordinates['x2'], $coordinates['y1'] - $coordinates['y2'] ) < 0.5;
	}

	/**
	 * Every shipped PHP and JS file under the markup roots.
	 *
	 * @return string[]
	 */
	private function source_files(): array {
		$root  = dirname( __DIR__, 2 );
		$files = array();
		foreach ( self::ROOTS as $directory ) {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $root . '/' . $directory, FilesystemIterator::SKIP_DOTS )
			);
			foreach ( $iterator as $file ) {
				if ( in_array( strtolower( $file->getExtension() ), self::EXTENSIONS, true ) ) {
					$files[] = (string) $file->getPathname();
				}
			}
		}

		return $files;
	}
}
