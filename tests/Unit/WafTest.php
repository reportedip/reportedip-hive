<?php
/**
 * Unit tests for the WAF request-inspection engine.
 *
 * Locks the security-critical core: pattern matching is correct, a malformed
 * delivered rule fails open (never hangs or fatals the request), and the
 * Paranoia-Level ceiling clamps the active rule set so free tiers never run
 * deeper levels than they are entitled to.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.2
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-rule-store.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-rule-sync.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-waf.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-block-ref.php';

	/**
	 * @covers \ReportedIP_Hive_WAF
	 */
	class WafTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options'] = array();
			$GLOBALS['wp_filters'] = array();
			\ReportedIP_Hive_Rule_Store::flush_cache();
		}

		private function waf(): \ReportedIP_Hive_WAF {
			return \ReportedIP_Hive_WAF::get_instance();
		}

		private function call_private( string $method, array $args ) {
			$ref = new \ReflectionMethod( \ReportedIP_Hive_WAF::class, $method );
			return $ref->invoke( $this->waf(), ...$args );
		}

		public function test_immediate_block_groups_cover_the_payload_attacks(): void {
			$groups = $this->call_private( 'immediate_block_groups', array() );

			foreach ( array( 'file_probe', 'path_traversal', 'php_injection', 'webshell', 'cmd_injection', 'log4shell' ) as $group ) {
				$this->assertContains( $group, $groups, "Group '$group' must block on the first hit" );
			}

			foreach ( array( 'sql_injection', 'xss', 'scanner_ua', 'rest_abuse' ) as $group ) {
				$this->assertNotContains(
					$group,
					$groups,
					"Group '$group' has a false-positive surface and must stay on the repeat-offender threshold"
				);
			}
		}

		public function test_immediate_block_groups_are_filterable(): void {
			add_filter(
				'reportedip_hive_waf_immediate_block_groups',
				static function ( $groups ) {
					$groups[] = 'sql_injection';
					return $groups;
				}
			);

			$this->assertContains( 'sql_injection', $this->call_private( 'immediate_block_groups', array() ) );
		}

		public function test_escalate_forwards_group_rule_and_severity(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-waf.php' );

			$fn_pos = strpos( $source, 'function escalate' );
			$this->assertNotFalse( $fn_pos );

			$body = substr( $source, $fn_pos, 1400 );
			$this->assertStringContainsString( "'severity'", $body, 'The rule severity must reach the threshold details' );
			$this->assertStringContainsString( 'immediate_block_groups', $body, 'The first-hit groups must be consulted here' );

			foreach ( array( 'handle_hit', 'record_dropin_hit' ) as $caller ) {
				$caller_pos = strpos( $source, 'function ' . $caller );
				$this->assertNotFalse( $caller_pos );
				$this->assertMatchesRegularExpression(
					'/\$this->escalate\(\s*\$ip,\s*\$group,\s*\$rule_id,\s*[^,]+,\s*\$severity\s*\)/',
					substr( $source, $caller_pos, 4000 ),
					"$caller() must pass the severity through"
				);
			}
		}

		public function test_matches_detects_sql_injection(): void {
			$pattern = '(?i)\bunion\b[\s\S]{0,80}?\bselect\b';
			$this->assertNotNull( $this->call_private( 'match_fragment', array( $pattern, 'id=1 UNION SELECT pwd FROM users' ) ) );
		}

		public function test_matches_ignores_clean_input(): void {
			$pattern = '(?i)\bunion\b[\s\S]{0,80}?\bselect\b';
			$this->assertNull( $this->call_private( 'match_fragment', array( $pattern, 'a perfectly ordinary search query' ) ) );
		}

		public function test_matches_escapes_tilde_delimiter(): void {
			$this->assertSame( 'foo~bar', $this->call_private( 'match_fragment', array( 'foo~bar', 'xx foo~bar yy' ) ) );
		}

		public function test_malformed_pattern_fails_open(): void {
			$this->assertNull( $this->call_private( 'match_fragment', array( '(unbalanced', 'anything at all' ) ) );
		}

		public function test_empty_pattern_never_matches(): void {
			$this->assertNull( $this->call_private( 'match_fragment', array( '', 'anything' ) ) );
		}

		public function test_required_targets_collapses_duplicates(): void {
			$rules = array(
				array( 'target' => 'uri' ),
				array( 'target' => 'uri' ),
				array( 'target' => 'ua' ),
				array(),
			);
			$targets = $this->call_private( 'required_targets', array( $rules ) );
			$this->assertArrayHasKey( 'uri', $targets );
			$this->assertArrayHasKey( 'ua', $targets );
			$this->assertArrayHasKey( 'all', $targets );
		}

		public function test_evaluate_matches_uri_target(): void {
			$rules = array(
				array( 'id' => 'trav', 'group' => 'path_traversal', 'pattern' => '\.\./', 'paranoia' => 1, 'target' => 'uri' ),
			);
			$hit = $this->waf()->evaluate( $rules, array( 'REQUEST_URI' => '/?f=../../etc/passwd' ), array(), null );
			$this->assertIsArray( $hit );
			$this->assertSame( 'trav', $hit['id'] );
		}

		public function test_evaluate_exposes_matched_fragment_for_logging(): void {
			$rules = array(
				array( 'id' => 'trav', 'group' => 'path_traversal', 'pattern' => '\.\./', 'paranoia' => 1, 'target' => 'uri' ),
			);
			$hit = $this->waf()->evaluate( $rules, array( 'REQUEST_URI' => '/?f=../../etc/passwd' ), array(), null );
			$this->assertIsArray( $hit );
			$this->assertArrayHasKey( 'matched', $hit, 'A hit must carry the substring that tripped the rule.' );
			$this->assertSame( '../', $hit['matched'], 'Matched fragment must be the actual offending value.' );
			$this->assertSame( 'uri', $hit['matched_target'], 'Matched target must record which subject matched.' );
		}

		public function test_evaluate_decodes_encoded_traversal_in_uri(): void {
			$rules = array(
				array( 'id' => 'trav', 'group' => 'path_traversal', 'pattern' => '\.\./', 'paranoia' => 1, 'target' => 'uri' ),
			);
			$hit = $this->waf()->evaluate( $rules, array( 'REQUEST_URI' => '/?f=%2e%2e%2fetc' ), array(), null );
			$this->assertIsArray( $hit );
		}

		public function test_evaluate_matches_body_and_raw(): void {
			$rules = array(
				array( 'id' => 'sqli', 'group' => 'sql_injection', 'pattern' => '(?i)\bunion\b[\s\S]{0,80}?\bselect\b', 'paranoia' => 1, 'target' => 'body' ),
			);
			$hit_post = $this->waf()->evaluate( $rules, array(), array( 'q' => '1 UNION SELECT pw' ), null );
			$this->assertIsArray( $hit_post );
			$hit_raw = $this->waf()->evaluate( $rules, array(), array(), '{"q":"1 union select pw"}' );
			$this->assertIsArray( $hit_raw );
		}

		/**
		 * A percent-encoded injection smuggled inside a JSON body (the wp2shell
		 * blind path encodes `author_exclude` fully, so `SLEEP(` arrives as
		 * `SLEEP%283%29`) must be caught by the same signature that sees the raw
		 * form. Locks the decoded-body variant added in 2.1.25 — without it the
		 * literal `\(` in the timing rule never matches the encoded stream.
		 */
		public function test_evaluate_decodes_encoded_sqli_in_json_body(): void {
			$rules   = array(
				array( 'id' => 'timing', 'group' => 'sql_injection', 'pattern' => '(?i)\b(?:sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(', 'paranoia' => 2, 'target' => 'body' ),
			);
			$encoded = '{"path":"/wp/v2/posts/999999?author_exclude=0%29%20OR%20SLEEP%283%29--%20-"}';
			$hit     = $this->waf()->evaluate( $rules, array(), array(), $encoded );
			$this->assertIsArray( $hit, 'A percent-encoded SLEEP() in a JSON body must be decoded and matched.' );
			$this->assertSame( 'timing', $hit['id'] );
		}

		/**
		 * The REST batch route-confusion primitive (wp2shell / CVE-2026-63030)
		 * carries a sub-request with a deliberately malformed `path` to desync
		 * $matches from $validation. The `waf_rest_batch_desync` signature covers
		 * the whole class of path values `wp_parse_url()` rejects — not two
		 * literals — so switching the primer token (`///`, `//`, `////`, any
		 * `scheme://` with an empty host) does not evade it, while legitimate
		 * routes, protocol-relative URLs and absolute URLs pass.
		 */
		public function test_evaluate_matches_rest_batch_desync_primer(): void {
			$rule  = array( 'id' => 'waf_rest_batch_desync', 'group' => 'rest_abuse', 'pattern' => '(?i)"path"\s*:\s*"(?:/{2,}(?![a-z0-9])|[a-z][a-z0-9+.\-]*:/{2,}(?:[:/?#]|"))', 'paranoia' => 1, 'target' => 'body' );
			$rules = array( $rule );
			foreach ( array( '///', '//', '////', 'http://:', 'https://', 'gopher://:' ) as $primer ) {
				$body = '{"requests":[{"method":"POST","path":"' . $primer . '"},{"method":"POST","path":"/wp/v2/posts"}]}';
				$this->assertIsArray( $this->waf()->evaluate( $rules, array(), array(), $body ), "Malformed primer '{$primer}' must be blocked." );
			}
			foreach ( array( '/wp/v2/posts', '//cdn.example.com/logo.png', 'https://example.com/callback' ) as $ok ) {
				$body = '{"method":"POST","path":"' . $ok . '"}';
				$this->assertNull( $this->waf()->evaluate( $rules, array(), array(), $body ), "Legitimate path '{$ok}' must not trip the rule." );
			}
		}

		/**
		 * The structural invariant of the batch route confusion is a sub-request
		 * whose `body` is itself a batch (`"body":{…"requests":[`). An attacker
		 * cannot drop that nesting without losing the desync, so
		 * `waf_rest_batch_nested` catches variants that reorder keys or omit the
		 * malformed primer, while a normal nested resource body passes.
		 */
		public function test_evaluate_matches_rest_batch_nested_body(): void {
			$rules = array(
				array( 'id' => 'waf_rest_batch_nested', 'group' => 'rest_abuse', 'pattern' => '(?i)"body"\s*:\s*\{[^{}]{0,120}?"requests"\s*:\s*\[', 'paranoia' => 1, 'target' => 'body' ),
			);
			$reordered = '{"requests":[{"method":"POST","path":"/wp/v2/posts","body":{"foo":1,"requests":[{"path":"/x"}]}}]}';
			$no_primer = '{"requests":[{"method":"POST","path":"/wp/v2/posts","body":{"requests":[{"method":"GET","path":"/wp/v2/posts"}]}}]}';
			$this->assertIsArray( $this->waf()->evaluate( $rules, array(), array(), $reordered ), 'A batch nested in a sub-request body (reordered keys) must be blocked.' );
			$this->assertIsArray( $this->waf()->evaluate( $rules, array(), array(), $no_primer ), 'A batch nested in a sub-request body must be blocked even without a malformed primer.' );
			$legit = '{"requests":[{"method":"POST","path":"/wc/v3/orders","body":{"line_items":[{"product_id":1}]}}]}';
			$this->assertNull( $this->waf()->evaluate( $rules, array(), array(), $legit ), 'A normal nested resource body must not trip the rule.' );
		}

		/**
		 * Return the bundled baseline rule with the given id.
		 *
		 * @param string $id Rule id.
		 * @return array<string,mixed> The rule.
		 */
		private function baseline_rule( string $id ): array {
			$baseline = include dirname( __DIR__, 2 ) . '/data/rulesets/waf-baseline.php';
			foreach ( $baseline['rules'] as $rule ) {
				if ( $id === $rule['id'] ) {
					return $rule;
				}
			}
			$this->fail( "Baseline rule '{$id}' is missing." );
		}

		/**
		 * The XSS2Shell login primitive (CVE-2026-64638) smuggles markup through
		 * `sanitize_user()` / `strip_tags()` in the `log` field. `sanitize_user()`
		 * strips angle brackets, so a login value carrying one is never
		 * legitimate, which makes this rule false-positive-free by value range
		 * rather than by pattern luck.
		 *
		 * The value scan must stop at BOTH separators: the engine body subject
		 * concatenates `flatten($_POST)` (space separated) with the raw and
		 * decoded body (`&` separated). A scan that only stops at `&` runs past
		 * the username into `pwd=` and blocks every password containing a `<`.
		 */
		public function test_evaluate_blocks_login_markup_injection(): void {
			$rules   = array( $this->baseline_rule( 'waf_xss_login_markup' ) );
			$payload = '< area id=ajaxurl href=/?rest_route=/&_method=GET&_jsonp=alert>';

			$attacks = array(
				'flattened post'      => ' log=' . $payload . ' pwd=x wp-submit=Log In',
				'raw urlencoded body' => 'log=' . $payload . '&pwd=x',
				'prefixed username'   => ' log=admin< area id=ajaxurl href=/x> pwd=y',
				'tab separator'       => " log=<\tarea id=ajaxurl> pwd=y",
				'no space at all'     => ' log=<area id=ajaxurl> pwd=y',
				'lost-password form'  => ' user_login=< area id=ajaxurl href=/x> redirect_to=',
			);
			foreach ( $attacks as $label => $body ) {
				$this->assertIsArray( $this->waf()->evaluate( $rules, array(), array(), $body ), "Login markup injection ({$label}) must be blocked." );
			}

			$legit = array(
				'ordinary login'       => ' log=admin pwd=Str0ng!Pass wp-submit=Log In',
				'email as username'    => ' log=1@reportedip.com pwd=abc wp-submit=Log In',
				'username with space'  => ' log=Anna Meier pwd=x wp-submit=Log In',
				'password holds an <'  => ' log=redakteur pwd=A<b7!xQ#z wp-submit=Log In',
				'password holds <<>>'  => ' log=shop-admin pwd=<<Sommer2026>> wp-submit=Log In',
				'raw body, < in pwd'   => 'log=redakteur&pwd=A<b7&wp-submit=Log In',
				'redirect_to with amp' => ' log=admin pwd=x redirect_to=https://site.de/wp-admin/post.php?post=12&action=edit',
			);
			foreach ( $legit as $label => $body ) {
				$this->assertNull( $this->waf()->evaluate( $rules, array(), array(), $body ), "Legitimate login ({$label}) must not trip the rule." );
			}
		}

		/**
		 * The clobbering primitive is the bug class, not the advisory: an HTML
		 * element that survived `strip_tags()` because of the whitespace after
		 * `<`, carrying an `id`/`name` attribute so it can overwrite a JavaScript
		 * global. Requiring that attribute is what keeps prose, code samples and
		 * comments explaining HTML out of the match set. A bare `< tag >` cannot
		 * clobber anything and is not worth a block.
		 */
		public function test_evaluate_blocks_clobbering_tag_differential(): void {
			$rules = array( $this->baseline_rule( 'waf_xss_tag_differential' ) );

			$attacks = array(
				'area clobbers ajaxurl'   => ' log=< area id=ajaxurl href=/x>',
				'div clobbers by id'      => ' log=< div id=color-picker class=reset-pass-submit>',
				'attribute before id'     => ' log=< area href=/x id=ajaxurl>',
				'name instead of id'      => ' log=< img name=ajaxurl src=/x>',
				'same trick in a comment' => ' comment=< form id=ajaxurl action=//evil.tld>',
			);
			foreach ( $attacks as $label => $body ) {
				$this->assertIsArray( $this->waf()->evaluate( $rules, array(), array(), $body ), "Clobbering markup ({$label}) must be blocked." );
			}

			$legit = array(
				'math in prose'     => ' comment=I think 5 < 6 and 9 > 2 really',
				'letter comparison' => ' comment=if a < b then c is smaller',
				'for loop'          => ' comment=for (i = 0; i < n; i++) { doIt(); }',
				'java generics'     => ' comment=List< String > list = new ArrayList<>();',
				'ordinary inline'   => ' comment=<a href="https://x.de">Link</a> und <strong>fett</strong>',
				'explaining html'   => ' comment=Schreib < a href = "url" > fuer einen Link',
				'talking about br'  => ' message=Ich habe < br > im Editor gesehen, was tun?',
				'css selector'      => ' comment=Der Selektor div > p gilt, und width < 600px',
				'json with angles'  => '{"title":"Beitrag","content":"Text mit < und > Zeichen"}',
			);
			foreach ( $legit as $label => $body ) {
				$this->assertNull( $this->waf()->evaluate( $rules, array(), array(), $body ), "Legitimate content ({$label}) must not trip the rule." );
			}
		}

		/**
		 * Same-Origin Method Execution rides the REST JSONP callback, which core
		 * validates as `[a-zA-Z0-9_.]`, permissive enough for property traversal
		 * such as `window.opener.approve.click`. A namespaced callback like
		 * `myApp.render` is ordinary and must survive.
		 */
		public function test_evaluate_blocks_jsonp_some_callback(): void {
			$rules = array(
				$this->baseline_rule( 'waf_xss_jsonp_some' ),
				$this->baseline_rule( 'waf_xss_jsonp_sink' ),
			);

			$attacks = array(
				'/?rest_route=/&_method=GET&_jsonp=window.opener.approve.click',
				'/?rest_route=/&_jsonp=parent.document.forms.0.submit',
				'/wp-json/wp/v2/posts?_jsonp=top.location.assign',
				'/?rest_route=/&_method=GET&_jsonp=alert',
			);
			foreach ( $attacks as $uri ) {
				$this->assertIsArray( $this->waf()->evaluate( $rules, array( 'REQUEST_URI' => $uri ), array(), null ), "SOME callback '{$uri}' must be blocked." );
			}

			$legit = array(
				'/?rest_route=/wp/v2/posts&_jsonp=jQuery31004572',
				'/?rest_route=/wp/v2/posts&_jsonp=myApp.renderPosts',
				'/wp-json/wp/v2/pages?_jsonp=callback42',
			);
			foreach ( $legit as $uri ) {
				$this->assertNull( $this->waf()->evaluate( $rules, array( 'REQUEST_URI' => $uri ), array(), null ), "Ordinary JSONP callback '{$uri}' must not trip the rule." );
			}
		}

		/**
		 * Every reason key the WAF can emit via GROUP_REASON must resolve to a
		 * concrete category in Block_Ref::CATEGORY_MAP, or a real block renders as
		 * a generic `BLOCKED-xxxx` reference the admin cannot triage. Guards the
		 * group→reason→category chain against future drift.
		 */
		public function test_every_waf_reason_key_has_a_block_ref_category(): void {
			foreach ( \ReportedIP_Hive_WAF::GROUP_REASON as $group => $reason ) {
				$this->assertArrayHasKey(
					$reason,
					\ReportedIP_Hive_Block_Ref::CATEGORY_MAP,
					"WAF group '{$group}' maps to reason '{$reason}', which is missing from Block_Ref::CATEGORY_MAP."
				);
			}
		}

		public function test_evaluate_returns_null_for_clean_request(): void {
			$rules = array(
				array( 'id' => 'sqli', 'group' => 'sql_injection', 'pattern' => '(?i)\bunion\b[\s\S]{0,80}?\bselect\b', 'paranoia' => 1, 'target' => 'all' ),
			);
			$hit = $this->waf()->evaluate( $rules, array( 'REQUEST_URI' => '/shop?page=2' ), array( 'name' => 'Jane' ), null );
			$this->assertNull( $hit );
		}

		public function test_evaluate_short_circuits_on_first_hit(): void {
			$rules = array(
				array( 'id' => 'first', 'group' => 'xss', 'pattern' => '(?i)<script', 'paranoia' => 1, 'target' => 'all' ),
				array( 'id' => 'second', 'group' => 'xss', 'pattern' => '(?i)<script', 'paranoia' => 1, 'target' => 'all' ),
			);
			$hit = $this->waf()->evaluate( $rules, array( 'REQUEST_URI' => '/?x=<script>' ), array(), null );
			$this->assertSame( 'first', $hit['id'] );
		}

		public function test_paranoia_cap_is_one_without_priority(): void {
			$this->assertSame( 1, $this->waf()->paranoia_cap() );
		}

		public function test_active_rules_drop_levels_above_cap(): void {
			\ReportedIP_Hive_Rule_Store::set(
				'waf',
				array(
					'key'     => 'waf',
					'version' => 9,
					'rules'   => array(
						array( 'id' => 'pl1', 'group' => 'xss', 'pattern' => '(?i)<script', 'paranoia' => 1, 'target' => 'all' ),
						array( 'id' => 'pl2', 'group' => 'xss', 'pattern' => '(?i)<svg', 'paranoia' => 2, 'target' => 'all' ),
						array( 'id' => 'pl3', 'group' => 'xss', 'pattern' => '(?i)<math', 'paranoia' => 3, 'target' => 'all' ),
					),
				)
			);

			$active = $this->waf()->get_active_rules();
			$ids    = array_map(
				static function ( $rule ) {
					return $rule['id'];
				},
				$active
			);
			$this->assertSame( array( 'pl1' ), $ids );
		}

		public function test_active_rules_skip_rules_without_pattern(): void {
			\ReportedIP_Hive_Rule_Store::set(
				'waf',
				array(
					'key'     => 'waf',
					'version' => 9,
					'rules'   => array(
						array( 'id' => 'ok', 'group' => 'xss', 'pattern' => '(?i)<script', 'paranoia' => 1, 'target' => 'all' ),
						array( 'id' => 'broken', 'group' => 'xss', 'paranoia' => 1, 'target' => 'all' ),
					),
				)
			);
			$this->assertCount( 1, $this->waf()->get_active_rules() );
		}

		public function test_resolve_route_pretty_permalink_strips_prefix(): void {
			$this->assertSame(
				'/reportedip/v2/report',
				$this->call_private( 'resolve_rest_route', array( '/wp-json/reportedip/v2/report?x=1', null, 'wp-json' ) )
			);
		}

		public function test_resolve_route_pretty_permalink_subdirectory_install(): void {
			$this->assertSame(
				'/reportedip/v2/check',
				$this->call_private( 'resolve_rest_route', array( '/blog/wp-json/reportedip/v2/check', null, 'wp-json' ) )
			);
		}

		public function test_resolve_route_plain_permalink_on_rest_entry(): void {
			$this->assertSame(
				'/reportedip/v2/report',
				$this->call_private( 'resolve_rest_route', array( '/index.php?rest_route=/reportedip/v2/report', '/reportedip/v2/report', 'wp-json' ) )
			);
			$this->assertSame(
				'/reportedip/v2',
				$this->call_private( 'resolve_rest_route', array( '/?rest_route=/reportedip/v2', '/reportedip/v2', 'wp-json' ) )
			);
		}

		public function test_resolve_route_ignores_non_rest_request(): void {
			$this->assertSame(
				'',
				$this->call_private( 'resolve_rest_route', array( '/shop?page=2', null, 'wp-json' ) )
			);
		}

		/**
		 * Anti-smuggle: a decoy bypass token in an unrelated query parameter on a
		 * non-REST endpoint must NOT resolve to a route, or the WAF could be
		 * disabled globally with `POST /xmlrpc.php?x=/reportedip/v2`.
		 */
		public function test_resolve_route_rejects_query_string_smuggle(): void {
			$this->assertSame(
				'',
				$this->call_private( 'resolve_rest_route', array( '/xmlrpc.php?x=/reportedip/v2', null, 'wp-json' ) )
			);
		}

		/**
		 * Anti-smuggle: a `rest_route` decoy carried on a real PHP endpoint that
		 * is NOT the REST entry script must be ignored, so an attacker cannot
		 * append `?rest_route=/reportedip/v2` to `/xmlrpc.php` to skip the WAF.
		 */
		public function test_resolve_route_rejects_rest_route_decoy_on_other_script(): void {
			$this->assertSame(
				'',
				$this->call_private( 'resolve_rest_route', array( '/xmlrpc.php?rest_route=/reportedip/v2', '/reportedip/v2', 'wp-json' ) )
			);
		}

		public function test_route_in_bypass_list_anchored_prefix_match(): void {
			$this->assertTrue(
				$this->call_private( 'route_in_bypass_list', array( '/reportedip/v2/report', array( '/reportedip/v2' ) ) )
			);
			$this->assertFalse(
				$this->call_private( 'route_in_bypass_list', array( '/wp/v2/posts', array( '/reportedip/v2' ) ) )
			);
		}

		public function test_route_in_bypass_list_ignores_empty_inputs(): void {
			$this->assertFalse( $this->call_private( 'route_in_bypass_list', array( '', array( '/reportedip/v2' ) ) ) );
			$this->assertFalse( $this->call_private( 'route_in_bypass_list', array( '/reportedip/v2', array( '' ) ) ) );
		}

		public function test_path_prefix_matches_request_path(): void {
			$this->assertTrue( $this->call_private( 'path_prefix_matches', array( '/kontakt', '', '/kontakt/form' ) ) );
		}

		public function test_path_prefix_matches_rest_route_on_plain_permalink(): void {
			$this->assertTrue(
				$this->call_private( 'path_prefix_matches', array( '/wp-json/reportedip/v2', '/reportedip/v2/report', '/index.php' ) )
			);
		}

		public function test_path_prefix_ignores_unrelated_path(): void {
			$this->assertFalse( $this->call_private( 'path_prefix_matches', array( '/wp-json/reportedip/v2', '', '/xmlrpc.php' ) ) );
		}

		public function test_ip_scope_matches_exact_only_without_database(): void {
			$this->assertTrue( $this->call_private( 'ip_scope_matches', array( '203.0.113.7', '203.0.113.7' ) ) );
			$this->assertFalse( $this->call_private( 'ip_scope_matches', array( '203.0.113.7', '203.0.113.8' ) ) );
		}

		public function test_exception_location_matches_path_scope(): void {
			$exception = (object) array(
				'path_prefix' => '/kontakt',
				'ip_address'  => '',
			);
			$this->assertTrue( $this->call_private( 'exception_location_matches', array( $exception, '', '/kontakt', '1.2.3.4' ) ) );
			$this->assertFalse( $this->call_private( 'exception_location_matches', array( $exception, '', '/shop', '1.2.3.4' ) ) );
		}

		public function test_hit_excepted_by_rule_scope_on_path(): void {
			$exception = (object) array(
				'scope'       => 'rule',
				'rule_id'     => 'waf_sqli_union',
				'path_prefix' => '/kontakt',
				'ip_address'  => '',
			);
			$hit = array(
				'id'    => 'waf_sqli_union',
				'group' => 'sql_injection',
			);
			$this->assertTrue( $this->call_private( 'hit_is_excepted', array( array( $exception ), '', '/kontakt', '1.2.3.4', $hit ) ) );
			$this->assertFalse( $this->call_private( 'hit_is_excepted', array( array( $exception ), '', '/shop', '1.2.3.4', $hit ) ) );
		}

		public function test_hit_not_excepted_for_different_rule(): void {
			$exception = (object) array(
				'scope'       => 'rule',
				'rule_id'     => 'waf_xss_onerror',
				'path_prefix' => '',
				'ip_address'  => '',
			);
			$hit = array(
				'id'    => 'waf_sqli_union',
				'group' => 'sql_injection',
			);
			$this->assertFalse( $this->call_private( 'hit_is_excepted', array( array( $exception ), '', '/kontakt', '1.2.3.4', $hit ) ) );
		}

		public function test_hit_excepted_by_group_scope(): void {
			$exception = (object) array(
				'scope'       => 'group',
				'rule_id'     => 'sql_injection',
				'path_prefix' => '',
				'ip_address'  => '',
			);
			$hit = array(
				'id'    => 'waf_sqli_union',
				'group' => 'sql_injection',
			);
			$this->assertTrue( $this->call_private( 'hit_is_excepted', array( array( $exception ), '', '/anywhere', '1.2.3.4', $hit ) ) );
		}

		public function test_request_fully_excepted_by_all_scope_on_path(): void {
			$exception = (object) array(
				'scope'       => 'all',
				'rule_id'     => null,
				'path_prefix' => '/wp-json/reportedip/v2',
				'ip_address'  => '',
			);
			$this->assertTrue(
				$this->call_private(
					'request_is_fully_excepted',
					array( array( $exception ), '/reportedip/v2/report', '/wp-json/reportedip/v2/report', '1.2.3.4' )
				)
			);
			$this->assertFalse(
				$this->call_private( 'request_is_fully_excepted', array( array( $exception ), '', '/shop', '1.2.3.4' ) )
			);
		}

		public function test_rule_scope_does_not_fully_except_request(): void {
			$exception = (object) array(
				'scope'       => 'rule',
				'rule_id'     => 'waf_sqli_union',
				'path_prefix' => '',
				'ip_address'  => '',
			);
			$this->assertFalse(
				$this->call_private( 'request_is_fully_excepted', array( array( $exception ), '', '/kontakt', '1.2.3.4' ) )
			);
		}
	}
}
