<?php
/**
 * Unit tests for the Decoy-Path-Block sensor.
 *
 * Covers the path matcher, filter-based extension, snippet generators.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.9
 */

namespace {

	if ( ! defined( 'REPORTEDIP_USER_AGENT_MAX_LENGTH' ) ) {
		define( 'REPORTEDIP_USER_AGENT_MAX_LENGTH', 50 );
	}
	if ( ! function_exists( 'wp_parse_url' ) ) {
		function wp_parse_url( $url, $component = -1 ) {
			return parse_url( $url, $component );
		}
	}
	if ( ! function_exists( 'apply_filters' ) ) {
		function apply_filters( $tag, $value ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return $value;
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-decoy-path-block.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class DecoyPathBlockTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_filters'] = array();
		}

		public function test_default_bait_paths_match() {
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/.env.backup' ) );
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/wp-config.old.php' ) );
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/db-dump-master.sql.php' ) );
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/admin-shell-console.php' ) );
		}

		public function test_normal_paths_do_not_match() {
			$this->assertFalse( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/wp-login.php' ) );
			$this->assertFalse( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/' ) );
			$this->assertFalse( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/wp-admin/admin.php' ) );
			$this->assertFalse( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '' ) );
		}

		public function test_query_string_and_trailing_slash_ignored() {
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/.env.backup?foo=bar' ) );
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/.env.backup/' ) );
		}

		public function test_case_insensitive() {
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/.ENV.Backup' ) );
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/Wp-Config.Old.PHP' ) );
		}

		public function test_subdir_prefix_match_for_multisite_subdirs() {
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/site-a/.env.backup' ) );
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/site-b/wp-config.old.php' ) );
			$this->assertFalse( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/site-a/wp-login.php' ) );
			$this->assertFalse(
				\ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/deep/nested/sub/admin-shell-console.php' ),
				'Deep nested paths must NOT match — only one subdir segment is allowed (consistent with the .htaccess/nginx regex).'
			);
		}

		public function test_nested_decoy_paths_match_with_and_without_subdir_prefix() {
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/.aws/credentials' ) );
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/site-a/.aws/credentials' ) );
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/.ssh/id_rsa' ) );
			$this->assertTrue(
				\ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/wp-content/.aws/credentials' ),
				'One-segment prefixes count — `wp-content` is itself a valid subdir name.'
			);
			$this->assertFalse(
				\ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/wp-content/uploads/.ssh/id_rsa' ),
				'Two-or-more-segment prefixes must not match — the rewrite regex only allows one optional subdir.'
			);
		}

		public function test_default_paths_count_matches_constant() {
			$paths = \ReportedIP_Hive_Decoy_Path_Block::decoy_paths();
			$this->assertGreaterThanOrEqual( 30, count( $paths ) );
		}

		public function test_htaccess_snippet_rewrites_to_index_not_forbidden() {
			$snippet = \ReportedIP_Hive_Decoy_Path_Block::htaccess_snippet();
			$this->assertStringContainsString( 'RewriteEngine On', $snippet );
			$this->assertStringContainsString( '\.env\.backup', $snippet );
			$this->assertStringContainsString( 'wp-config\.old\.php', $snippet );
			$this->assertStringContainsString( '/index.php', $snippet );
			$this->assertStringNotContainsString( '[F,L]', $snippet );
		}

		public function test_htaccess_block_lines_cover_subdir_prefix() {
			$lines    = \ReportedIP_Hive_Decoy_Path_Block::htaccess_block_lines();
			$combined = implode( "\n", $lines );
			$this->assertStringContainsString( '<IfModule mod_rewrite.c>', $combined );
			$this->assertStringContainsString( '(/[_0-9a-zA-Z-]+)?', $combined );
			$this->assertStringContainsString( '/index.php [L,QSA]', $combined );
		}

		public function test_nginx_snippet_rewrites_to_index_not_403() {
			$snippet = \ReportedIP_Hive_Decoy_Path_Block::nginx_snippet();
			$this->assertStringContainsString( 'location ~*', $snippet );
			$this->assertStringContainsString( 'rewrite ^ /index.php last;', $snippet );
			$this->assertStringNotContainsString( 'return 403', $snippet );
			$this->assertStringContainsString( '\.env\.backup', $snippet );
		}

		public function test_nginx_exact_match_snippet_emits_one_location_per_path() {
			$snippet = \ReportedIP_Hive_Decoy_Path_Block::nginx_snippet_exact_match();
			$this->assertStringContainsString( 'location = /.env.backup { rewrite ^ /index.php last; }', $snippet );
			$this->assertStringContainsString( 'location = /wp-config.old.php { rewrite ^ /index.php last; }', $snippet );
			$this->assertStringContainsString( 'location = /.aws/credentials { rewrite ^ /index.php last; }', $snippet );
			$this->assertStringNotContainsString( 'location ~', $snippet );
			$this->assertStringNotContainsString( 'return 403', $snippet );
		}
	}
}
