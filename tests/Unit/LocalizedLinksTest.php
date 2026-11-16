<?php
/**
 * reportedip.com links follow the admin's language.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.9
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * A site run in German, French or Spanish sends its admin to the page in
 * that language; every other locale and every single-language path keeps
 * the English address.
 */
class LocalizedLinksTest extends TestCase {

	public function test_site_languages_get_their_prefix(): void {
		$this->assertSame( 'https://reportedip.com/de/pricing/?rc=hive-plugin#tor_blocking', \ReportedIP_Hive_Catalog::localize_url( 'https://reportedip.com/pricing/?rc=hive-plugin#tor_blocking', 'de_DE_formal' ) );
		$this->assertSame( 'https://reportedip.com/fr/products/wordpress-plugin/?rc=hive-plugin', \ReportedIP_Hive_Catalog::localize_url( 'https://reportedip.com/products/wordpress-plugin/?rc=hive-plugin', 'fr_FR' ) );
		$this->assertSame( 'https://reportedip.com/es/', \ReportedIP_Hive_Catalog::localize_url( 'https://reportedip.com', 'es_ES' ) );
		$this->assertSame( 'https://reportedip.com/de/dashboard/api-keys/?rc=hive-plugin', \ReportedIP_Hive_Catalog::localize_url( 'https://reportedip.com/dashboard/api-keys/?rc=hive-plugin', 'de_CH' ) );
	}

	public function test_other_locales_keep_english(): void {
		$url = 'https://reportedip.com/pricing/?rc=hive-plugin';
		$this->assertSame( $url, \ReportedIP_Hive_Catalog::localize_url( $url, 'en_US' ) );
		$this->assertSame( $url, \ReportedIP_Hive_Catalog::localize_url( $url, 'nl_NL' ) );
	}

	public function test_single_language_paths_and_other_hosts_stay(): void {
		foreach ( array(
			'https://reportedip.com/wp-json/reportedip/v2/',
			'https://reportedip.com/download/hive/?rc=hive-plugin',
			'https://reportedip.com/datenschutzerklaerung/',
			'https://reportedip.com/de/pricing/',
			'https://reportedip.com/agent/install.sh',
			'https://example.org/pricing/',
		) as $url ) {
			$this->assertSame( $url, \ReportedIP_Hive_Catalog::localize_url( $url, 'de_DE' ), $url );
		}
	}
}
