<?php
/**
 * Settings export/import singleton for ReportedIP Hive.
 *
 * Lets administrators download a JSON snapshot of every persisted plugin
 * setting and re-apply it on another site. Designed for agencies that
 * manage many WordPress installs and need to roll their preferred
 * configuration out without retyping every field.
 *
 * Sensitive credentials (API key, encrypted SMS provider config) are
 * excluded by default — there is an explicit opt-in checkbox guarded by
 * a warning. Per-user 2FA secrets (TOTP, WebAuthn, SMS number) are never
 * exported regardless of the toggle, because they are encrypted with a
 * site-specific key and would be useless on the target site anyway.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Owns the export, preview and apply pipeline for plugin settings.
 *
 * @since 1.2.0
 */
class ReportedIP_Hive_Settings_Import_Export {

	/**
	 * Schema version of the JSON envelope. Bump on breaking changes.
	 *
	 * @var int
	 */
	const SCHEMA_VERSION = 1;

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Settings_Import_Export|null
	 */
	private static $instance = null;

	/**
	 * Get singleton.
	 *
	 * @since  1.2.0
	 * @return ReportedIP_Hive_Settings_Import_Export
	 */
	public static function get_instance(): ReportedIP_Hive_Settings_Import_Export {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Wires AJAX endpoints. All endpoints are admin-only and nonce-protected.
	 *
	 * @since 1.2.0
	 */
	private function __construct() {
		add_action( 'wp_ajax_reportedip_hive_export_settings', array( $this, 'ajax_export' ) );
		add_action( 'wp_ajax_reportedip_hive_import_settings_preview', array( $this, 'ajax_preview' ) );
		add_action( 'wp_ajax_reportedip_hive_import_settings_apply', array( $this, 'ajax_apply' ) );
	}

	/**
	 * Section catalogue mapping each user-facing area to its option keys.
	 *
	 * Edit deliberately — adding a key here means it will appear in every
	 * future export. Removing a key without a migration is a breaking change.
	 *
	 * @since  1.2.0
	 * @return array<string, array{label:string, description:string, options:array<int,string>}>
	 */
	public static function sections(): array {
		return array(
			'general'          => array(
				'label'       => __( 'General & connection', 'reportedip-hive' ),
				'description' => __( 'Operation mode, API endpoint and proxy header.', 'reportedip-hive' ),
				'options'     => array(
					'reportedip_hive_operation_mode',
					'reportedip_hive_api_endpoint',
					'reportedip_hive_trusted_ip_header',
				),
			),
			'detection'        => array(
				'label'       => __( 'Detection & thresholds', 'reportedip-hive' ),
				'description' => __( 'What is monitored and at which limits.', 'reportedip-hive' ),
				'options'     => array(
					'reportedip_hive_monitor_failed_logins',
					'reportedip_hive_failed_login_threshold',
					'reportedip_hive_failed_login_timeframe',
					'reportedip_hive_monitor_comments',
					'reportedip_hive_comment_spam_threshold',
					'reportedip_hive_comment_spam_timeframe',
					'reportedip_hive_monitor_xmlrpc',
					'reportedip_hive_xmlrpc_threshold',
					'reportedip_hive_xmlrpc_timeframe',
					'reportedip_hive_disable_xmlrpc_multicall',
				),
			),
			'blocking'         => array(
				'label'       => __( 'Auto-blocking & report-only', 'reportedip-hive' ),
				'description' => __( 'How offenders are blocked and for how long.', 'reportedip-hive' ),
				'options'     => array(
					'reportedip_hive_auto_block',
					'reportedip_hive_block_duration',
					'reportedip_hive_block_threshold',
					'reportedip_hive_report_only_mode',
					'reportedip_hive_report_cooldown_hours',
					'reportedip_hive_blocked_page_contact_url',
				),
			),
			'notifications'    => array(
				'label'       => __( 'Notifications', 'reportedip-hive' ),
				'description' => __( 'Admin emails and cool-downs.', 'reportedip-hive' ),
				'options'     => array(
					'reportedip_hive_notify_admin',
					'reportedip_hive_notification_cooldown_minutes',
				),
			),
			'privacy_logs'     => array(
				'label'       => __( 'Privacy & logs', 'reportedip-hive' ),
				'description' => __( 'What we record and how long we keep it.', 'reportedip-hive' ),
				'options'     => array(
					'reportedip_hive_log_level',
					'reportedip_hive_minimal_logging',
					'reportedip_hive_detailed_logging',
					'reportedip_hive_log_user_agents',
					'reportedip_hive_log_referer_domains',
					'reportedip_hive_data_retention_days',
					'reportedip_hive_auto_anonymize_days',
					'reportedip_hive_delete_data_on_uninstall',
				),
			),
			'performance'      => array(
				'label'       => __( 'Performance & caching', 'reportedip-hive' ),
				'description' => __( 'API caching and rate limits.', 'reportedip-hive' ),
				'options'     => array(
					'reportedip_hive_enable_caching',
					'reportedip_hive_cache_duration',
					'reportedip_hive_negative_cache_duration',
					'reportedip_hive_max_api_calls_per_hour',
				),
			),
			'twofactor_global' => array(
				'label'       => __( 'Two-Factor — global policy', 'reportedip-hive' ),
				'description' => __( 'Site-wide 2FA settings (per-user secrets stay local).', 'reportedip-hive' ),
				'options'     => array(
					'reportedip_hive_2fa_enabled_global',
					'reportedip_hive_2fa_allowed_methods',
					'reportedip_hive_2fa_enforce_roles',
					'reportedip_hive_2fa_enforce_grace_days',
					'reportedip_hive_2fa_max_skips',
					'reportedip_hive_2fa_trusted_devices',
					'reportedip_hive_2fa_trusted_device_days',
					'reportedip_hive_2fa_frontend_onboarding',
					'reportedip_hive_2fa_notify_new_device',
					'reportedip_hive_2fa_xmlrpc_app_password_only',
					'reportedip_hive_2fa_extended_remember',
					'reportedip_hive_2fa_branded_login',
					'reportedip_hive_2fa_ip_allowlist',
					'reportedip_hive_2fa_sms_provider',
					'reportedip_hive_2fa_sms_avv_confirmed',
				),
			),
			'ip_lists'         => array(
				'label'       => __( 'IP lists', 'reportedip-hive' ),
				'description' => __( 'Whitelist + blocked IPs (manual entries only — runtime-blocked IPs stay site-local).', 'reportedip-hive' ),
				'options'     => array(),
			),
		);
	}

	/**
	 * Secret keys, exported only when the explicit opt-in is set.
	 *
	 * SMS provider config remains AES-256 encrypted with the site key.
	 * It will not decode on a different site, but is included so that
	 * an admin restoring a backup on the SAME site keeps SMS access.
	 *
	 * @since  1.2.0
	 * @return array<int, string>
	 */
	public static function secret_options(): array {
		return array(
			'reportedip_hive_api_key',
			'reportedip_hive_2fa_sms_provider_config_raw',
		);
	}

	/**
	 * Flat allowlist of every importable option key (sections + secrets).
	 *
	 * @since  1.2.0
	 * @return array<int, string>
	 */
	public static function importable_keys(): array {
		$keys = array();
		foreach ( self::sections() as $section ) {
			foreach ( $section['options'] as $key ) {
				$keys[] = $key;
			}
		}
		foreach ( self::secret_options() as $key ) {
			$keys[] = $key;
		}
		return array_values( array_unique( $keys ) );
	}

	/**
	 * Renders the import/export panel inside the Performance tab.
	 *
	 * @since 1.2.0
	 */
	public function render_panel(): void {
		?>
		<div class="rip-settings-section" id="rip-settings-portability">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
				<?php esc_html_e( 'Settings import & export', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc">
				<?php esc_html_e( 'Save your current configuration as a JSON file, or load configuration that was exported elsewhere. Useful for replicating settings across multiple sites.', 'reportedip-hive' ); ?>
			</p>

			<div class="rip-grid rip-grid-cols-2 rip-gap-4">
				<div class="rip-card">
					<div class="rip-card__header">
						<h3 class="rip-card__title"><?php esc_html_e( 'Export', 'reportedip-hive' ); ?></h3>
					</div>
					<div class="rip-card__body">
						<p class="rip-mb-3"><?php esc_html_e( 'Choose what to include. All sections are selected by default.', 'reportedip-hive' ); ?></p>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>" id="rip-export-form" class="rip-stack">
							<input type="hidden" name="action" value="reportedip_hive_export_settings" />
							<?php wp_nonce_field( 'reportedip_hive_settings_import', '_rip_ie_nonce' ); ?>

							<?php foreach ( self::sections() as $slug => $section ) : ?>
								<label class="rip-section-pick">
									<input type="checkbox" name="sections[]" value="<?php echo esc_attr( $slug ); ?>" checked />
									<span>
										<strong><?php echo esc_html( $section['label'] ); ?></strong>
										<span class="rip-help-text"><?php echo esc_html( $section['description'] ); ?></span>
									</span>
								</label>
							<?php endforeach; ?>

							<label class="rip-section-pick rip-section-pick--secret rip-mt-3">
								<input type="checkbox" name="include_secrets" value="1" />
								<span>
									<strong><?php esc_html_e( 'Include credentials', 'reportedip-hive' ); ?></strong>
									<span class="rip-help-text"><?php esc_html_e( 'Adds the API key and encrypted SMS-provider config. Treat the resulting file like a password — do not share or email it.', 'reportedip-hive' ); ?></span>
								</span>
							</label>

							<button type="submit" class="rip-button rip-button--primary rip-mt-3">
								<?php esc_html_e( 'Download JSON', 'reportedip-hive' ); ?>
							</button>
						</form>
					</div>
				</div>

				<div class="rip-card">
					<div class="rip-card__header">
						<h3 class="rip-card__title"><?php esc_html_e( 'Import', 'reportedip-hive' ); ?></h3>
					</div>
					<div class="rip-card__body">
						<p class="rip-mb-3"><?php esc_html_e( 'Upload a previously exported JSON file. We show a preview of every change before anything is written.', 'reportedip-hive' ); ?></p>
						<form method="post" enctype="multipart/form-data" id="rip-import-form" class="rip-stack">
							<?php wp_nonce_field( 'reportedip_hive_settings_import', '_rip_ie_nonce' ); ?>
							<input type="file" name="settings_file" accept="application/json,.json" id="rip-import-file" required />
							<button type="submit" class="rip-button rip-button--secondary rip-mt-3">
								<?php esc_html_e( 'Preview changes', 'reportedip-hive' ); ?>
							</button>
						</form>
						<div id="rip-import-preview" class="rip-mt-4"></div>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Verifies admin capability and AJAX nonce. Aborts with HTTP 403 otherwise.
	 *
	 * @since 1.2.0
	 */
	private function require_authorised_admin(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'reportedip-hive' ) ), 403 );
		}
		check_ajax_referer( 'reportedip_hive_settings_import', '_rip_ie_nonce' );
	}

	/**
	 * AJAX: streams a settings export as a JSON file download.
	 *
	 * @since 1.2.0
	 */
	public function ajax_export(): void {
		$this->require_authorised_admin();

		$requested_sections = isset( $_POST['sections'] ) && is_array( $_POST['sections'] )
			? array_map( 'sanitize_key', wp_unslash( $_POST['sections'] ) )
			: array_keys( self::sections() );

		$include_secrets = ! empty( $_POST['include_secrets'] );

		$payload = $this->build_export_payload( $requested_sections, $include_secrets );

		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="reportedip-hive-settings-' . gmdate( 'Y-m-d-Hi' ) . '.json"' );
		echo wp_json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		exit;
	}

	/**
	 * Builds the export envelope for the requested sections.
	 *
	 * @param array<int, string> $requested_sections Section slugs to include.
	 * @param bool               $include_secrets    Whether to emit credential keys.
	 * @return array<string, mixed>
	 * @since 1.2.0
	 */
	public function build_export_payload( array $requested_sections, bool $include_secrets ): array {
		$valid_sections = array_intersect( $requested_sections, array_keys( self::sections() ) );

		$options = array();
		foreach ( $valid_sections as $section_slug ) {
			$section = self::sections()[ $section_slug ];
			foreach ( $section['options'] as $key ) {
				$options[ $key ] = get_option( $key, null );
			}
		}

		if ( $include_secrets ) {
			foreach ( self::secret_options() as $key ) {
				$options[ $key ] = get_option( $key, null );
			}
		}

		$ip_lists = array();
		if ( in_array( 'ip_lists', $valid_sections, true ) && class_exists( 'ReportedIP_Hive_IP_Manager' ) ) {
			$ip_manager            = ReportedIP_Hive_IP_Manager::get_instance();
			$ip_lists['whitelist'] = array_map(
				static fn( $row ) => array(
					'ip_address' => is_object( $row ) ? $row->ip_address : ( $row['ip_address'] ?? '' ),
					'reason'     => is_object( $row ) ? ( $row->reason ?? '' ) : ( $row['reason'] ?? '' ),
					'expires_at' => is_object( $row ) ? ( $row->expires_at ?? null ) : ( $row['expires_at'] ?? null ),
				),
				(array) $ip_manager->get_whitelist( true )
			);
			$ip_lists['blocked']   = array_map(
				static fn( $row ) => array(
					'ip_address'    => is_object( $row ) ? $row->ip_address : ( $row['ip_address'] ?? '' ),
					'reason'        => is_object( $row ) ? ( $row->reason ?? '' ) : ( $row['reason'] ?? '' ),
					'block_type'    => is_object( $row ) ? ( $row->block_type ?? 'manual' ) : ( $row['block_type'] ?? 'manual' ),
					'blocked_until' => is_object( $row ) ? ( $row->blocked_until ?? null ) : ( $row['blocked_until'] ?? null ),
				),
				(array) $ip_manager->get_blocked_ips( true )
			);
			$ip_lists['blocked']   = array_values(
				array_filter(
					$ip_lists['blocked'],
					static fn( array $row ): bool => 'manual' === $row['block_type']
				)
			);
		}

		return array(
			'_meta'    => array(
				'plugin'           => 'reportedip-hive',
				'plugin_version'   => defined( 'REPORTEDIP_HIVE_VERSION' ) ? REPORTEDIP_HIVE_VERSION : 'unknown',
				'site_url'         => home_url(),
				'exported_at'      => gmdate( 'c' ),
				'schema_version'   => self::SCHEMA_VERSION,
				'sections'         => array_values( $valid_sections ),
				'includes_secrets' => $include_secrets,
			),
			'options'  => $options,
			'ip_lists' => (object) $ip_lists,
		);
	}

	/**
	 * AJAX: parses an uploaded JSON, returns a diff summary.
	 *
	 * @since 1.2.0
	 */
	public function ajax_preview(): void {
		$this->require_authorised_admin();

		$payload = $this->read_uploaded_payload();
		if ( is_wp_error( $payload ) ) {
			wp_send_json_error( array( 'message' => $payload->get_error_message() ), 400 );
		}

		wp_send_json_success(
			array(
				'meta'  => $payload['_meta'] ?? array(),
				'diffs' => $this->compute_diffs( $payload ),
			)
		);
	}

	/**
	 * AJAX: applies a previously previewed payload.
	 *
	 * Expects the same JSON file uploaded again (so the server never trusts
	 * client-side state). The user can pick which sections to commit.
	 *
	 * @since 1.2.0
	 */
	public function ajax_apply(): void {
		$this->require_authorised_admin();

		$payload = $this->read_uploaded_payload();
		if ( is_wp_error( $payload ) ) {
			wp_send_json_error( array( 'message' => $payload->get_error_message() ), 400 );
		}

		$selected_sections = isset( $_POST['sections'] ) && is_array( $_POST['sections'] )
			? array_map( 'sanitize_key', wp_unslash( $_POST['sections'] ) )
			: array_keys( self::sections() );

		$result = $this->apply_payload( $payload, $selected_sections );

		wp_send_json_success( $result );
	}

	/**
	 * Validates the uploaded JSON envelope and returns its decoded array form.
	 *
	 * Public so the setup wizard can reuse the same validation pipeline
	 * instead of duplicating size/JSON/schema checks.
	 *
	 * @param string $field_name Form field name (default 'settings_file').
	 * @return array<string, mixed>|WP_Error
	 * @since  1.2.0
	 */
	public function read_uploaded_payload( string $field_name = 'settings_file' ) {
		if ( empty( $_FILES[ $field_name ]['tmp_name'] ) || ! is_uploaded_file( (string) $_FILES[ $field_name ]['tmp_name'] ) ) {
			return new WP_Error( 'no_file', __( 'No file uploaded.', 'reportedip-hive' ) );
		}

		if ( (int) $_FILES[ $field_name ]['size'] > self::max_upload_bytes() ) {
			return new WP_Error( 'too_large', __( 'Settings file is larger than the allowed limit.', 'reportedip-hive' ) );
		}

		$raw = file_get_contents( (string) $_FILES[ $field_name ]['tmp_name'] );
		if ( false === $raw || '' === $raw ) {
			return new WP_Error( 'empty_file', __( 'Settings file is empty or unreadable.', 'reportedip-hive' ) );
		}

		$decoded = json_decode( $raw, true );
		if ( ! is_array( $decoded ) ) {
			return new WP_Error( 'invalid_json', __( 'Settings file is not valid JSON.', 'reportedip-hive' ) );
		}

		$meta = $decoded['_meta'] ?? array();
		if ( ( $meta['plugin'] ?? '' ) !== 'reportedip-hive' ) {
			return new WP_Error( 'wrong_plugin', __( 'This file does not belong to ReportedIP Hive.', 'reportedip-hive' ) );
		}
		if ( (int) ( $meta['schema_version'] ?? 0 ) !== self::SCHEMA_VERSION ) {
			return new WP_Error( 'schema_mismatch', __( 'Settings file uses an unsupported schema version.', 'reportedip-hive' ) );
		}

		return $decoded;
	}

	/**
	 * Returns the upload-size cap, falling back to a class-level default
	 * when the bootstrap constant has not been loaded (test harness).
	 *
	 * @since  1.2.0
	 * @return int
	 */
	private static function max_upload_bytes(): int {
		return defined( 'REPORTEDIP_MAX_SETTINGS_UPLOAD_SIZE' )
			? (int) REPORTEDIP_MAX_SETTINGS_UPLOAD_SIZE
			: 524288;
	}

	/**
	 * Builds a per-section diff between the payload and the current site.
	 *
	 * @param array<string, mixed> $payload Decoded JSON envelope.
	 * @return array<string, array<int, array{key:string, current:mixed, incoming:mixed, status:string}>>
	 * @since 1.2.0
	 */
	private function compute_diffs( array $payload ): array {
		$incoming = $payload['options'] ?? array();
		$diffs    = array();

		foreach ( self::sections() as $slug => $section ) {
			$rows = array();
			foreach ( $section['options'] as $key ) {
				if ( ! array_key_exists( $key, $incoming ) ) {
					continue;
				}
				$current = get_option( $key, null );
				$status  = $this->values_equal( $current, $incoming[ $key ] ) ? 'unchanged' : 'changed';
				$rows[]  = array(
					'key'      => $key,
					'current'  => $current,
					'incoming' => $incoming[ $key ],
					'status'   => $status,
				);
			}
			if ( $rows ) {
				$diffs[ $slug ] = $rows;
			}
		}

		if ( isset( $payload['ip_lists'] ) ) {
			$ip                = (array) ( is_object( $payload['ip_lists'] ) ? get_object_vars( $payload['ip_lists'] ) : $payload['ip_lists'] );
			$diffs['ip_lists'] = array(
				array(
					'key'      => 'whitelist',
					'current'  => '',
					'incoming' => count( (array) ( $ip['whitelist'] ?? array() ) ),
					'status'   => 'changed',
				),
				array(
					'key'      => 'blocked',
					'current'  => '',
					'incoming' => count( (array) ( $ip['blocked'] ?? array() ) ),
					'status'   => 'changed',
				),
			);
		}

		return $diffs;
	}

	/**
	 * Loose equality that survives the boolean / "0" / "" round-trip
	 * WordPress does on options.
	 *
	 * @param mixed $a Left value.
	 * @param mixed $b Right value.
	 * @return bool
	 * @since 1.2.0
	 */
	private function values_equal( $a, $b ): bool {
		if ( is_bool( $a ) || is_bool( $b ) ) {
			return (bool) $a === (bool) $b;
		}
		if ( is_scalar( $a ) && is_scalar( $b ) ) {
			return (string) $a === (string) $b;
		}
		return $a === $b;
	}

	/**
	 * Applies a validated payload, honouring the user's section selection.
	 *
	 * Public so the setup wizard can re-use the same code path.
	 *
	 * @param array<string, mixed> $payload           Decoded JSON envelope.
	 * @param array<int, string>   $selected_sections Section slugs to commit.
	 * @return array{written:int, skipped:int, ip_added:int, ip_skipped:int, errors:array<int,string>}
	 * @since 1.2.0
	 */
	public function apply_payload( array $payload, array $selected_sections ): array {
		$valid_sections   = array_intersect( $selected_sections, array_keys( self::sections() ) );
		$incoming         = $payload['options'] ?? array();
		$includes_secrets = ! empty( $payload['_meta']['includes_secrets'] );

		$allowed_keys = array();
		foreach ( $valid_sections as $section_slug ) {
			foreach ( self::sections()[ $section_slug ]['options'] as $key ) {
				$allowed_keys[ $key ] = true;
			}
		}
		if ( $includes_secrets ) {
			foreach ( self::secret_options() as $key ) {
				$allowed_keys[ $key ] = true;
			}
		}

		$written = 0;
		$skipped = 0;
		$errors  = array();

		foreach ( $incoming as $key => $value ) {
			if ( ! is_string( $key ) || ! isset( $allowed_keys[ $key ] ) ) {
				++$skipped;
				continue;
			}
			$ok = update_option( $key, $value );
			if ( false === $ok && get_option( $key ) !== $value ) {
				$errors[] = sprintf( /* translators: %s: option key */ __( 'Could not write %s.', 'reportedip-hive' ), $key );
				++$skipped;
				continue;
			}
			++$written;
		}

		$ip_added   = 0;
		$ip_skipped = 0;

		if ( in_array( 'ip_lists', $valid_sections, true ) && isset( $payload['ip_lists'] ) && class_exists( 'ReportedIP_Hive_IP_Manager' ) ) {
			$ip_manager = ReportedIP_Hive_IP_Manager::get_instance();
			$lists      = is_object( $payload['ip_lists'] ) ? get_object_vars( $payload['ip_lists'] ) : (array) $payload['ip_lists'];

			foreach ( (array) ( $lists['whitelist'] ?? array() ) as $row ) {
				$ip = is_array( $row ) ? ( $row['ip_address'] ?? '' ) : '';
				if ( '' === $ip || $ip_manager->is_whitelisted( $ip ) ) {
					++$ip_skipped;
					continue;
				}
				$ip_manager->whitelist_ip( $ip, isset( $row['reason'] ) ? (string) $row['reason'] : '', $row['expires_at'] ?? null );
				++$ip_added;
			}

			foreach ( (array) ( $lists['blocked'] ?? array() ) as $row ) {
				$ip = is_array( $row ) ? ( $row['ip_address'] ?? '' ) : '';
				if ( '' === $ip || $ip_manager->is_blocked( $ip ) ) {
					++$ip_skipped;
					continue;
				}
				$ip_manager->block_ip( $ip, isset( $row['reason'] ) ? (string) $row['reason'] : '', null, 'manual' );
				++$ip_added;
			}
		}

		if ( class_exists( 'ReportedIP_Hive_Logger' ) ) {
			$admin_ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
			ReportedIP_Hive_Logger::get_instance()->log_security_event(
				'settings_imported',
				$admin_ip,
				array(
					'sections' => array_values( $valid_sections ),
					'written'  => $written,
					'ip_added' => $ip_added,
					'user_id'  => get_current_user_id(),
					'source'   => isset( $payload['_meta']['site_url'] ) ? (string) $payload['_meta']['site_url'] : '',
				),
				'low'
			);
		}

		return array(
			'written'    => $written,
			'skipped'    => $skipped,
			'ip_added'   => $ip_added,
			'ip_skipped' => $ip_skipped,
			'errors'     => $errors,
		);
	}
}
