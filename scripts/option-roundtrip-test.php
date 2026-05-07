<?php
/**
 * Round-trip test for plugin option routing.
 *
 * Run via WP-CLI: `wp eval-file scripts/option-roundtrip-test.php`.
 * Verifies that for every option key on the test list:
 *   1. Option_Routing::set(...) persists to the expected storage scope
 *   2. Option_Routing::get(...) returns the exact value back
 *   3. On Multisite, network options land in sitemeta and site overrides in wp_options
 *   4. On single-site, all options land in wp_options
 *
 * Output: PASS/FAIL per key, with mismatch diff. Exit code != 0 on any failure.
 *
 * @package ReportedIP_Hive
 */

if ( ! class_exists( 'ReportedIP_Hive_Option_Routing' ) ) {
	echo "Plugin not loaded\n";
	exit( 1 );
}

$is_multisite = is_multisite();

// Network-scoped option keys (representative sample across all subsystems).
$network_keys = array(
	'reportedip_hive_operation_mode'                       => 'community',
	'reportedip_hive_api_key'                              => 'rt_test_apikey_' . wp_generate_password( 16, false ),
	'reportedip_hive_api_endpoint'                         => 'https://example.test/v2/',
	'reportedip_hive_failed_login_threshold'               => 7,
	'reportedip_hive_failed_login_timeframe'               => 22,
	'reportedip_hive_block_threshold'                      => 80,
	'reportedip_hive_block_duration'                       => 12,
	'reportedip_hive_auto_block'                           => true,
	'reportedip_hive_data_retention_days'                  => 45,
	'reportedip_hive_log_level'                            => 'debug',
	'reportedip_hive_detailed_logging'                     => true,
	'reportedip_hive_enable_caching'                       => false,
	'reportedip_hive_cache_duration'                       => 36,
	'reportedip_hive_max_api_calls_per_hour'               => 250,
	'reportedip_hive_notify_admin'                         => false,
	'reportedip_hive_notify_recipients'                    => 'a@b.test, c@d.test',
	'reportedip_hive_notify_from_name'                     => 'Hive Test',
	'reportedip_hive_notify_from_email'                    => 'hive@example.test',
	'reportedip_hive_report_only_mode'                     => true,
	'reportedip_hive_block_escalation_enabled'             => false,
	'reportedip_hive_block_ladder_minutes'                 => '10,30,60,1440',
	'reportedip_hive_block_ladder_reset_days'              => 14,
	'reportedip_hive_2fa_enabled_global'                   => true,
	'reportedip_hive_2fa_allowed_methods'                  => '["totp","email","sms"]',
	'reportedip_hive_2fa_enforce_roles'                    => '["editor","author"]',
	'reportedip_hive_2fa_enforce_super_admins'             => false,
	'reportedip_hive_2fa_enforce_grace_days'               => 9,
	'reportedip_hive_2fa_max_skips'                        => 4,
	'reportedip_hive_2fa_extended_remember'                => true,
	'reportedip_hive_2fa_branded_login'                    => true,
	'reportedip_hive_2fa_trusted_devices'                  => false,
	'reportedip_hive_2fa_trusted_device_days'              => 60,
	'reportedip_hive_2fa_xmlrpc_app_password_only'         => true,
	'reportedip_hive_2fa_sms_provider'                     => 'reportedip_relay',
	'reportedip_hive_2fa_sms_avv_confirmed'                => true,
	'reportedip_hive_2fa_reminder_enabled'                 => true,
	'reportedip_hive_2fa_reminder_hard_threshold'          => 3,
	'reportedip_hive_2fa_reminder_hard_roles'              => '["administrator","editor"]',
	'reportedip_hive_2fa_frontend_enabled'                 => true,
	'reportedip_hive_2fa_frontend_customer_optional'       => false,
	'reportedip_hive_2fa_frontend_onboarding'              => false,
	'reportedip_hive_2fa_frontend_slug'                    => 'rt-challenge',
	'reportedip_hive_2fa_frontend_setup_slug'              => 'rt-setup',
	'reportedip_hive_2fa_require_on_password_reset'        => false,
	'reportedip_hive_2fa_password_reset_excluded_methods'  => '["email","sms"]',
	'reportedip_hive_2fa_password_reset_block_email_only'  => false,
	'reportedip_hive_hide_login_enabled'                   => true,
	'reportedip_hive_hide_login_slug'                      => 'rt-secure',
	'reportedip_hive_hide_login_response_mode'             => '404',
	'reportedip_hive_monitor_failed_logins'                => false,
	'reportedip_hive_monitor_comments'                     => false,
	'reportedip_hive_monitor_xmlrpc'                       => false,
	'reportedip_hive_monitor_app_passwords'                => false,
	'reportedip_hive_monitor_rest_api'                     => false,
	'reportedip_hive_monitor_404_scans'                    => false,
	'reportedip_hive_monitor_geo_anomaly'                  => false,
	'reportedip_hive_monitor_woocommerce'                  => false,
	'reportedip_hive_geo_window_days'                      => 75,
	'reportedip_hive_geo_revoke_trusted_devices'           => true,
	'reportedip_hive_geo_report_to_api'                    => true,
	'reportedip_hive_app_password_threshold'               => 6,
	'reportedip_hive_app_password_timeframe'               => 25,
	'reportedip_hive_rest_threshold'                       => 220,
	'reportedip_hive_rest_timeframe'                       => 6,
	'reportedip_hive_rest_sensitive_threshold'             => 20,
	'reportedip_hive_rest_sensitive_timeframe'             => 4,
	'reportedip_hive_user_enum_threshold'                  => 12,
	'reportedip_hive_user_enum_timeframe'                  => 7,
	'reportedip_hive_scan_404_threshold'                   => 14,
	'reportedip_hive_scan_404_timeframe'                   => 3,
	'reportedip_hive_password_spray_threshold'             => 8,
	'reportedip_hive_password_spray_timeframe'             => 18,
	'reportedip_hive_password_policy_enabled'              => true,
	'reportedip_hive_password_min_length'                  => 14,
	'reportedip_hive_password_min_classes'                 => 4,
	'reportedip_hive_password_check_hibp'                  => true,
	'reportedip_hive_password_policy_all_users'            => true,
	'reportedip_hive_block_user_enumeration'               => false,
	'reportedip_hive_app_password_require_2fa'             => true,
	'reportedip_hive_xmlrpc_threshold'                     => 18,
	'reportedip_hive_xmlrpc_timeframe'                     => 80,
	'reportedip_hive_comment_spam_threshold'               => 8,
	'reportedip_hive_comment_spam_timeframe'               => 70,
	'reportedip_hive_negative_cache_duration'              => 3,
	'reportedip_hive_queue_max_age_days'                   => 11,
	'reportedip_hive_queue_warning_threshold'              => 60,
	'reportedip_hive_queue_critical_threshold'             => 240,
	'reportedip_hive_processing_timeout_minutes'           => 15,
	'reportedip_hive_report_cooldown_hours'                => 22,
	'reportedip_hive_disable_xmlrpc_multicall'             => false,
	'reportedip_hive_blocked_page_contact_url'             => 'https://example.test/contact',
	'reportedip_hive_trusted_ip_header'                    => 'HTTP_X_REAL_IP',
	'reportedip_hive_2fa_ip_allowlist'                     => "10.0.0.0/8\n192.168.1.5",
	'reportedip_hive_log_user_agents'                      => true,
	'reportedip_hive_minimal_logging'                      => true,
	'reportedip_hive_log_referer_domains'                  => true,
	'reportedip_hive_auto_anonymize_days'                  => 5,
	'reportedip_hive_notify_sync_to_api'                   => true,
	'reportedip_hive_2fa_notify_new_device'                => false,
	'reportedip_hive_api_stats'                            => array( 'total_calls' => 42, 'success_rate' => 99 ),
	'reportedip_hive_cache_stats'                          => array( 'hits' => 13, 'misses' => 7 ),
	'reportedip_hive_activated_at'                         => 1709123456,
);

$site_keys = array(
	'reportedip_hive_2fa_frontend_slug_site_override'       => 'site-rt-chal',
	'reportedip_hive_2fa_frontend_setup_slug_site_override' => 'site-rt-setup',
	'reportedip_hive_2fa_enforce_roles_extra'               => array( 'contributor' ),
);

$pass     = 0;
$fail     = 0;
$failures = array();

$normalize = function ( $v ) {
	if ( is_bool( $v ) ) {
		return $v ? '1' : '';
	}
	if ( is_int( $v ) ) {
		return (string) $v;
	}
	return $v;
};

$run = function ( $key, $expected, $expected_scope ) use ( &$pass, &$fail, &$failures, $is_multisite, $normalize ) {
	// Two-step write breaks the WP "value === default → no-op" early bail
	// in update_site_option that would otherwise miss legitimate writes when
	// a never-stored option happens to equal its WP default (e.g. false).
	$shim = is_bool( $expected ) ? ( ! $expected ) : '__rt_shim__';
	ReportedIP_Hive_Option_Routing::set( $key, $shim );
	ReportedIP_Hive_Option_Routing::set( $key, $expected );
	$got = ReportedIP_Hive_Option_Routing::get( $key, '__rt_unset__' );

	$on_disk_site = get_option( $key, '__missing__' );
	$on_disk_net  = $is_multisite ? get_site_option( $key, '__missing__' ) : '__n/a__';

	if ( $is_multisite ) {
		if ( 'site' === $expected_scope ) {
			$disk_pass = ( '__missing__' !== $on_disk_site );
		} else {
			$disk_pass = ( '__missing__' !== $on_disk_net );
		}
	} else {
		$disk_pass = ( '__missing__' !== $on_disk_site );
	}

	$expect_norm = $normalize( $expected );
	$got_norm    = $normalize( $got );
	$round_pass  = ( $got_norm == $expect_norm ); // loose equal: '1' == 1, '1' == true
	if ( $round_pass && $disk_pass ) {
		++$pass;
		return;
	}
	++$fail;
	$failures[] = array(
		'key'      => $key,
		'expected' => $expected,
		'got'      => $got,
		'disk_si'  => $on_disk_site,
		'disk_ne'  => $on_disk_net,
		'scope'    => $expected_scope,
		'reason'   => $round_pass ? 'wrong_disk_scope' : 'value_mismatch',
	);
};

echo "is_multisite=" . ( $is_multisite ? '1' : '0' ) . "\n";
echo "blog_id=" . get_current_blog_id() . "\n";

foreach ( $network_keys as $k => $v ) {
	$run( $k, $v, 'network' );
}
foreach ( $site_keys as $k => $v ) {
	$run( $k, $v, 'site' );
}

echo "PASS=$pass FAIL=$fail TOTAL=" . ( $pass + $fail ) . "\n";

if ( $fail > 0 ) {
	echo "FAILURES:\n";
	foreach ( $failures as $f ) {
		echo sprintf(
			"  %s [scope=%s]\n    expected=%s\n    got=%s\n    disk_site=%s disk_net=%s\n",
			$f['key'],
			$f['scope'],
			var_export( $f['expected'], true ),
			var_export( $f['got'], true ),
			var_export( $f['disk_si'], true ),
			var_export( $f['disk_ne'], true )
		);
	}
	exit( 1 );
}

exit( 0 );
