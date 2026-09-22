<?php
/**
 * Tools page: server setup, rules, data and diagnostics in four tabs.
 *
 * Listed in the menu in expert mode only, always reachable by URL because
 * readiness issues link here.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.56
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Renders the tools page.
 *
 * @since 2.1.56
 */
class ReportedIP_Hive_Tools_Page {

	/**
	 * Page slug.
	 *
	 * @var string
	 */
	const PAGE_SLUG = 'reportedip-hive-tools';

	/**
	 * Render the page.
	 *
	 * @return void
	 */
	public function render_page() {
		$tabs   = array(
			'server'   => __( 'Server', 'reportedip-hive' ),
			'rules'    => __( 'Rules', 'reportedip-hive' ),
			'data'     => __( 'Data', 'reportedip-hive' ),
			'diagnose' => __( 'Diagnostics', 'reportedip-hive' ),
		);
		$active = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'server'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- tab selection only
		if ( ! isset( $tabs[ $active ] ) ) {
			$active = 'server';
		}
		ReportedIP_Hive_Admin_Settings::render_page_header( __( 'Tools', 'reportedip-hive' ), __( 'Server setup, rule delivery, data and diagnostics', 'reportedip-hive' ) );
		echo '<nav class="rip-nav-tabs">';
		foreach ( $tabs as $slug => $label ) {
			printf(
				'<a href="%1$s" class="rip-nav-tabs__tab%2$s">%3$s</a>',
				esc_url( ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=' . self::PAGE_SLUG . '&tab=' . $slug ) ),
				$active === $slug ? ' rip-nav-tabs__tab--active' : '',
				esc_html( $label )
			);
		}
		echo '</nav><div class="rip-content">';
		$firewall = ReportedIP_Hive_Admin_Firewall::get_instance();
		switch ( $active ) {
			case 'rules':
				$firewall->render_rule_sync_tab();
				$firewall->render_waf_exceptions_box();
				ReportedIP_Hive_Admin_Settings::render_hardening_mode_tab();
				break;
			case 'data':
				ReportedIP_Hive_Settings_Import_Export::get_instance()->render_panel();
				ReportedIP_Hive_Admin_Settings::render_maintenance_panel();
				ReportedIP_Hive_Admin_Settings::render_uninstall_card();
				break;
			case 'diagnose':
				ReportedIP_Hive_Admin_Settings::render_diagnostics_panel();
				self::render_selftest_panel();
				break;
			case 'server':
			default:
				$firewall->render_waf_dropin_box();
				$firewall->render_server_tab();
		}
		echo '</div>';
		ReportedIP_Hive_Admin_Settings::render_page_footer();
	}

	/**
	 * Self-test run identifiers, in the order the operator sees them.
	 *
	 * @var string[]
	 */
	const SELFTEST_RUNS = array( 'visitor', 'replay', 'bot' );

	/**
	 * Anchor field name the self-test judges. Its own identifier, so the run
	 * never depends on which surfaces happen to be armed right now.
	 */
	const SELFTEST_DECOY = 'rip_selftest_anchor';

	/**
	 * Proof field name the self-test judges.
	 */
	const SELFTEST_FIELD = 'rip_selftest_proof';

	/**
	 * How long the collected run results stay readable, in seconds.
	 */
	const SELFTEST_TTL = 300;

	/**
	 * Read the current state of the form protection off the running site.
	 *
	 * Everything impure lives here so {@see selftest_inventory()} stays a plain
	 * mapping from values to rows.
	 *
	 * @return array<string, mixed>
	 * @since  2.1.58
	 */
	public static function selftest_state() {
		$proof    = ReportedIP_Hive_Form_Proof::get_instance();
		$adapters = ReportedIP_Hive_Form_Adapters::get_instance();
		$names    = ReportedIP_Hive_Form_Adapters::names();
		$mode     = ReportedIP_Hive_Mode_Manager::get_instance();
		$rows     = array();

		foreach ( ReportedIP_Hive_Form_Adapters::ADAPTERS as $slug => $spec ) {
			$status = $mode->feature_status( $spec['feature'] );

			$rows[ $slug ] = array(
				'name'     => isset( $names[ $slug ] ) ? $names[ $slug ] : $slug,
				'detected' => $adapters->detected( $slug ),
				'covered'  => ! empty( $status['available'] ),
				'option'   => (bool) ReportedIP_Hive_Option_Routing::get( $spec['option'], false ),
			);
		}

		/** This filter is documented in includes/class-form-proof.php */
		$grace = (int) apply_filters( 'reportedip_hive_form_adapters_grace', ReportedIP_Hive_Form_Proof::ADAPTER_GRACE );
		$since = (int) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_Form_Proof::OPT_ADAPTERS_SINCE, 0 );
		$until = $since > 0 ? $since + max( 0, min( ReportedIP_Hive_Form_Proof::ADAPTER_GRACE_MAX, $grace ) ) : 0;

		return array(
			'enabled'         => $proof->is_enabled(),
			'killswitch'      => defined( 'REPORTEDIP_HIVE_DISABLE_FORM_PROOF' ) && REPORTEDIP_HIVE_DISABLE_FORM_PROOF,
			'pow_covered'     => $proof->pow_available(),
			'pow_option'      => (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_Form_Proof::OPT_POW, false ),
			'secure'          => ReportedIP_Hive_Form_Proof::connection_is_secure(),
			'pow_grace'       => $proof->pow_enabled() && ! $proof->pow_required(),
			'adapters'        => $rows,
			'adapters_strict' => $proof->adapters_strict(),
			'adapters_until'  => $until,
			'until_text'      => $until > 0 ? ReportedIP_Hive::format_local_datetime( gmdate( 'Y-m-d H:i:s', $until ) ) : '',
		);
	}

	/**
	 * Turn the state of the form protection into one row per surface.
	 *
	 * Pure, because the interesting part of a stock take is the combinations:
	 * an adapter can be inactive because the plugin is missing, because the
	 * plan does not cover it, because its own switch is off, or because the
	 * whole layer is off, and each of those needs a different sentence.
	 *
	 * @param array<string, mixed> $state State from {@see selftest_state()}.
	 * @return array<int, array<string, string>>
	 * @since  2.1.58
	 */
	public static function selftest_inventory( array $state ) {
		$enabled = ! empty( $state['enabled'] );
		$rows    = array(
			self::selftest_layer_row( $enabled, ! empty( $state['killswitch'] ) ),
			self::selftest_pow_row( $state, $enabled ),
		);

		$adapters = isset( $state['adapters'] ) ? (array) $state['adapters'] : array();

		foreach ( $adapters as $adapter ) {
			$rows[] = self::selftest_adapter_row( (array) $adapter, $enabled );
		}

		$rows[] = self::selftest_grace_row( $state );

		return $rows;
	}

	/**
	 * Row for the execution proof itself.
	 *
	 * @param bool $enabled    Whether the layer is on.
	 * @param bool $killswitch Whether the wp-config constant switches it off.
	 * @return array<string, string>
	 * @since  2.1.58
	 */
	private static function selftest_layer_row( $enabled, $killswitch ) {
		$label = __( 'Execution proof', 'reportedip-hive' );

		if ( $killswitch ) {
			return self::selftest_row( $label, 'danger', __( 'Off', 'reportedip-hive' ), __( 'The constant REPORTEDIP_HIVE_DISABLE_FORM_PROOF is set in wp-config.php and switches the whole layer off, whatever the settings say.', 'reportedip-hive' ) );
		}

		if ( ! $enabled ) {
			return self::selftest_row( $label, 'warning', __( 'Off', 'reportedip-hive' ), __( 'The master switch on the Protection page is off, so no form carries an anchor.', 'reportedip-hive' ) );
		}

		return self::selftest_row( $label, 'success', __( 'On', 'reportedip-hive' ), __( 'Every protected form carries the hidden anchor.', 'reportedip-hive' ) );
	}

	/**
	 * Row for the computation check.
	 *
	 * @param array<string, mixed> $state   State from {@see selftest_state()}.
	 * @param bool                 $enabled Whether the layer is on.
	 * @return array<string, string>
	 * @since  2.1.58
	 */
	private static function selftest_pow_row( array $state, $enabled ) {
		$label = __( 'Computation check', 'reportedip-hive' );

		if ( empty( $state['pow_covered'] ) ) {
			return self::selftest_row( $label, 'info', __( 'Not in your plan', 'reportedip-hive' ), __( 'The computation check is part of the Professional plan. Without it the hidden field carries a plain marker, which a script can copy out of the page.', 'reportedip-hive' ) );
		}

		if ( empty( $state['pow_option'] ) ) {
			return self::selftest_row( $label, 'warning', __( 'Off', 'reportedip-hive' ), __( 'The switch on the Protection page is off.', 'reportedip-hive' ) );
		}

		if ( ! $enabled ) {
			return self::selftest_row( $label, 'warning', __( 'Off', 'reportedip-hive' ), __( 'The execution proof is off for the whole site, so no task is handed out either.', 'reportedip-hive' ) );
		}

		if ( empty( $state['secure'] ) ) {
			return self::selftest_row( $label, 'warning', __( 'Off', 'reportedip-hive' ), __( 'This site is not reached over a secure connection, so no task is handed out. A browser can only work one out in a secure context, and demanding it here would turn every visitor into a suspect. The plain marker keeps deciding.', 'reportedip-hive' ) );
		}

		if ( ! empty( $state['pow_grace'] ) ) {
			return self::selftest_row( $label, 'info', __( 'Starting up', 'reportedip-hive' ), __( 'A task is handed out already, and the plain marker still passes for the first day, so pages served from a cache filled before the switch are not refused.', 'reportedip-hive' ) );
		}

		return self::selftest_row( $label, 'success', __( 'On', 'reportedip-hive' ), __( 'Every protected form hands out a task and each answer is good once.', 'reportedip-hive' ) );
	}

	/**
	 * Row for one form adapter.
	 *
	 * @param array<string, mixed> $adapter Adapter state.
	 * @param bool                 $enabled Whether the layer is on.
	 * @return array<string, string>
	 * @since  2.1.58
	 */
	private static function selftest_adapter_row( array $adapter, $enabled ) {
		$name  = isset( $adapter['name'] ) ? (string) $adapter['name'] : '';
		$label = sprintf(
			/* translators: %s: name of a form plugin */
			__( 'Form adapter: %s', 'reportedip-hive' ),
			$name
		);

		if ( empty( $adapter['detected'] ) ) {
			return self::selftest_row(
				$label,
				'info',
				__( 'Inactive', 'reportedip-hive' ),
				sprintf(
					/* translators: %s: name of a form plugin */
					__( '%s is not active on this site, so there is nothing to carry the anchor into.', 'reportedip-hive' ),
					$name
				)
			);
		}

		if ( empty( $adapter['covered'] ) ) {
			return self::selftest_row( $label, 'info', __( 'Inactive', 'reportedip-hive' ), __( 'The form plugin is here, your plan does not cover this adapter.', 'reportedip-hive' ) );
		}

		if ( empty( $adapter['option'] ) ) {
			return self::selftest_row( $label, 'warning', __( 'Inactive', 'reportedip-hive' ), __( 'The form plugin is here and your plan covers it, the switch on the Protection page is off.', 'reportedip-hive' ) );
		}

		if ( ! $enabled ) {
			return self::selftest_row( $label, 'warning', __( 'Inactive', 'reportedip-hive' ), __( 'The switch is on, the execution proof is off for the whole site.', 'reportedip-hive' ) );
		}

		return self::selftest_row( $label, 'success', __( 'Active', 'reportedip-hive' ), __( 'Submissions through this form plugin are judged like a comment.', 'reportedip-hive' ) );
	}

	/**
	 * Row for the grace after switching an adapter on.
	 *
	 * @param array<string, mixed> $state State from {@see selftest_state()}.
	 * @return array<string, string>
	 * @since  2.1.58
	 */
	private static function selftest_grace_row( array $state ) {
		$label = __( 'Adapter grace', 'reportedip-hive' );

		if ( empty( $state['adapters_until'] ) ) {
			return self::selftest_row( $label, 'info', __( 'Not running', 'reportedip-hive' ), __( 'No form adapter has been switched on, so there is no grace to wait out.', 'reportedip-hive' ) );
		}

		if ( ! empty( $state['adapters_strict'] ) ) {
			return self::selftest_row( $label, 'success', __( 'Elapsed', 'reportedip-hive' ), __( 'A submission that never carried our anchor is refused on the form adapters.', 'reportedip-hive' ) );
		}

		return self::selftest_row(
			$label,
			'warning',
			__( 'Running', 'reportedip-hive' ),
			sprintf(
				/* translators: %s: local date and time the grace ends */
				__( 'Until %s a submission without our anchor still passes on the form adapters, because a page cache filled before the switch cannot carry one.', 'reportedip-hive' ),
				isset( $state['until_text'] ) ? (string) $state['until_text'] : ''
			)
		);
	}

	/**
	 * Build one inventory row.
	 *
	 * @param string $label  Row label.
	 * @param string $badge  Badge modifier.
	 * @param string $status Short state.
	 * @param string $note   Reason or detail.
	 * @return array<string, string>
	 * @since  2.1.58
	 */
	private static function selftest_row( $label, $badge, $status, $note ) {
		return array(
			'label'  => (string) $label,
			'badge'  => (string) $badge,
			'status' => (string) $status,
			'note'   => (string) $note,
		);
	}

	/**
	 * What a run has to come back with.
	 *
	 * Without the computation check there is nothing to repeat, so a second
	 * submission passes like the first. Expecting a refusal there would be a
	 * test that lies about the site it runs on.
	 *
	 * @param string $run      Run identifier.
	 * @param bool   $required Whether a solved computation is demanded.
	 * @return string One of the four verdict constants.
	 * @since  2.1.58
	 */
	public static function selftest_expected( $run, $required ) {
		if ( 'bot' === $run ) {
			return ReportedIP_Hive_Form_Proof::TRIPPED;
		}

		if ( 'replay' === $run && $required ) {
			return ReportedIP_Hive_Form_Proof::FAILED;
		}

		return ReportedIP_Hive_Form_Proof::PROVED;
	}

	/**
	 * Fold the collected run results into one verdict. Pure.
	 *
	 * @param array<string, string> $actual   Verdict per run identifier.
	 * @param bool                  $required Whether a solved computation is demanded.
	 * @return array<string, mixed>
	 * @since  2.1.58
	 */
	public static function selftest_outcome( array $actual, $required ) {
		$rows     = array();
		$failed   = array();
		$complete = true;

		foreach ( self::SELFTEST_RUNS as $run ) {
			if ( ! isset( $actual[ $run ] ) ) {
				$complete = false;
				continue;
			}

			$expected = self::selftest_expected( $run, $required );
			$ok       = ( $expected === (string) $actual[ $run ] );

			if ( ! $ok ) {
				$failed[] = $run;
			}

			$rows[ $run ] = array(
				'expected' => $expected,
				'actual'   => (string) $actual[ $run ],
				'ok'       => $ok,
			);
		}

		return array(
			'complete' => $complete,
			'pass'     => $complete && empty( $failed ),
			'failed'   => $failed,
			'rows'     => $rows,
		);
	}

	/**
	 * The name of one run.
	 *
	 * @param string $run Run identifier.
	 * @return string
	 * @since  2.1.58
	 */
	public static function selftest_label( $run ) {
		$labels = array(
			'visitor' => __( 'Like a visitor', 'reportedip-hive' ),
			'replay'  => __( 'Like the same visitor twice', 'reportedip-hive' ),
			'bot'     => __( 'Like a bot', 'reportedip-hive' ),
		);

		return isset( $labels[ $run ] ) ? $labels[ $run ] : (string) $run;
	}

	/**
	 * The plain reading of one verdict.
	 *
	 * @param string $verdict Verdict constant.
	 * @return string
	 * @since  2.1.58
	 */
	public static function selftest_verdict_label( $verdict ) {
		$labels = array(
			ReportedIP_Hive_Form_Proof::PROVED  => __( 'let through', 'reportedip-hive' ),
			ReportedIP_Hive_Form_Proof::FAILED  => __( 'refused', 'reportedip-hive' ),
			ReportedIP_Hive_Form_Proof::TRIPPED => __( 'refused as a bot', 'reportedip-hive' ),
			ReportedIP_Hive_Form_Proof::ABSENT  => __( 'not ours to judge', 'reportedip-hive' ),
		);

		return isset( $labels[ $verdict ] ) ? $labels[ $verdict ] : (string) $verdict;
	}

	/**
	 * What one run means for the operator, in the words of the site rather
	 * than the words of the verdict.
	 *
	 * @param string $run      Run identifier.
	 * @param bool   $ok       Whether the verdict matched.
	 * @param bool   $required Whether a solved computation is demanded.
	 * @return string
	 * @since  2.1.58
	 */
	public static function selftest_meaning( $run, $ok, $required ) {
		if ( 'visitor' === $run ) {
			return $ok
				? __( 'A normal submission reached the site. Readers are not caught by the check.', 'reportedip-hive' )
				: __( 'A normal submission was refused. Visitors would be turned away on your forms too, so switch the computation check off on the Protection page until this reads correctly.', 'reportedip-hive' );
		}

		if ( 'replay' === $run ) {
			if ( ! $ok ) {
				return __( 'The repeated answer was not judged as expected. A copied answer may still be worth something on this site.', 'reportedip-hive' );
			}

			return $required
				? __( 'The same answer was refused the second time, so copying it out of the page buys a script nothing.', 'reportedip-hive' )
				: __( 'Without the computation check there is nothing to repeat, so a second submission passes like the first. Switching the check on closes that.', 'reportedip-hive' );
		}

		return $ok
			? __( 'A filled anchor field was refused, which is what a script that fills every input produces.', 'reportedip-hive' )
			: __( 'A filled anchor field was let through. That is the oldest part of the check, so it points at a changed installation rather than at a setting.', 'reportedip-hive' );
	}

	/**
	 * The closing line under the three runs.
	 *
	 * @param bool $pass Whether every run matched.
	 * @return string
	 * @since  2.1.58
	 */
	public static function selftest_summary( $pass ) {
		return $pass
			? __( 'All three runs came back as expected. The form protection is in force on this site.', 'reportedip-hive' )
			: __( 'At least one run came back differently than expected. The lines above say what that means for your forms.', 'reportedip-hive' );
	}

	/**
	 * The diagnostics card: the stock take, and the button that proves it.
	 *
	 * @return void
	 * @since  2.1.58
	 */
	public static function render_selftest_panel() {
		$proof = ReportedIP_Hive_Form_Proof::get_instance();
		$rows  = self::selftest_inventory( self::selftest_state() );

		self::enqueue_selftest_script( $proof );
		?>
		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
				<?php esc_html_e( 'Form protection self-test', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc"><?php esc_html_e( 'The form protection has no visible surface, so this card first shows what is switched on and then proves it. The run touches no real form: no mail goes out, no comment is filed and no entry is stored.', 'reportedip-hive' ); ?></p>

			<table class="rip-table">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'Check', 'reportedip-hive' ); ?></th>
						<th scope="col"><?php esc_html_e( 'State', 'reportedip-hive' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Detail', 'reportedip-hive' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $rows as $row ) : ?>
					<tr>
						<td><?php echo esc_html( $row['label'] ); ?></td>
						<td><span class="rip-badge rip-badge--<?php echo esc_attr( $row['badge'] ); ?>"><?php echo esc_html( $row['status'] ); ?></span></td>
						<td><?php echo esc_html( $row['note'] ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>

			<div class="rip-form-group">
				<button type="button" class="rip-button rip-button--secondary" id="rip-selftest-run">
					<?php esc_html_e( 'Run the self-test', 'reportedip-hive' ); ?>
				</button>
				<span id="rip-selftest-status" class="rip-help-text rip-ml-3 rip-hidden"></span>
			</div>

			<table class="rip-table rip-hidden" id="rip-selftest-results">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'Run', 'reportedip-hive' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Expected', 'reportedip-hive' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Result', 'reportedip-hive' ); ?></th>
						<th scope="col"><?php esc_html_e( 'What it means', 'reportedip-hive' ); ?></th>
					</tr>
				</thead>
				<tbody></tbody>
			</table>
			<div id="rip-selftest-summary"></div>
		</div>
		<?php
	}

	/**
	 * Register the self-test script and hand it the current challenge.
	 *
	 * The Tools page is never cached, so a value that depends on this request
	 * is safe here in a way it would not be inside a rendered form.
	 *
	 * @param ReportedIP_Hive_Form_Proof $proof Execution-proof layer.
	 * @return void
	 * @since  2.1.58
	 */
	private static function enqueue_selftest_script( $proof ) {
		wp_register_script(
			'reportedip-hive-form-proof-selftest',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/form-proof-selftest.js',
			array(),
			REPORTEDIP_HIVE_VERSION,
			true
		);

		$seed   = '';
		$bucket = 0;
		$bits   = 0;

		if ( $proof->pow_enabled() ) {
			$bucket = ReportedIP_Hive_Form_Proof::pow_bucket();
			$seed   = ReportedIP_Hive_Form_Proof::pow_seed( $bucket );
			$bits   = $proof->pow_bits();
		}

		wp_localize_script(
			'reportedip-hive-form-proof-selftest',
			'reportedipHiveSelfTest',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'action'  => 'reportedip_hive_form_proof_selftest',
				'nonce'   => wp_create_nonce( 'reportedip_hive_form_selftest' ),
				'runs'    => self::SELFTEST_RUNS,
				'seed'    => $seed,
				'bucket'  => (string) $bucket,
				'bits'    => $bits,
				'strings' => array(
					'running'  => __( 'Running the three passes...', 'reportedip-hive' ),
					'solving'  => __( 'Working out the task the way a visitor browser does...', 'reportedip-hive' ),
					'insecure' => __( 'This browser offers no Web Crypto, which usually means the page was not reached over a secure connection. The task cannot be worked out here.', 'reportedip-hive' ),
					'unsolved' => __( 'No answer was found within the attempt budget. Lower the difficulty with the reportedip_hive_form_proof_bits filter and try again.', 'reportedip-hive' ),
					'failed'   => __( 'The self-test could not be completed.', 'reportedip-hive' ),
				),
			)
		);

		wp_enqueue_script( 'reportedip-hive-form-proof-selftest' );
	}
}
