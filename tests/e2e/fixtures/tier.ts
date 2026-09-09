/**
 * Plan fixture.
 *
 * `Mode_Manager::get_cached_tier_or_default()` resolves the plan from three
 * sources, in this order: the `reportedip_hive_api_status` transient
 * (`userRole`, 5 min), the `reportedip_hive_relay_quota` transient (`tier`,
 * 12 h) and only then the durable `reportedip_hive_known_tier` option.
 *
 * A spec that drives the plan through the option alone therefore decides
 * nothing while either transient is warm, and in the dev stack they are warm
 * often: `docker/mu-plugins/rip-api-mock.php` answers the status and quota
 * routes with `reportedip_professional`. Whichever spec last triggered an API
 * call wins for the next five minutes. That is the cross-file flake that made
 * `registration-rules.spec.ts` fail on a plan assertion during the full run
 * while passing on its own.
 *
 * These snippets clear all three, so the plan is whatever the caller says.
 */

/** Force the free plan: no stored plan and no cached answer from the service. */
export const FORCE_FREE_PHP = [
	"ReportedIP_Hive_Option_Routing::delete('reportedip_hive_known_tier');",
	"delete_transient('reportedip_hive_api_status');",
	"delete_transient('reportedip_hive_relay_quota');",
].join(' ');

/**
 * Force a paid plan. Clears the cached service answers as well, so a stale
 * transient from another spec cannot silently downgrade the site.
 *
 * @param tier One of the Mode_Manager tier slugs, e.g. `professional`.
 */
export function forceTierPhp(tier: string): string {
	return [
		`ReportedIP_Hive_Option_Routing::set('reportedip_hive_known_tier', '${tier}');`,
		"delete_transient('reportedip_hive_api_status');",
		"delete_transient('reportedip_hive_relay_quota');",
	].join(' ');
}

/** WP-CLI equivalent for specs that drive the plan through `wp`, not `wp eval`. */
export const FORGET_CACHED_TIER_CLI = 'transient delete reportedip_hive_api_status reportedip_hive_relay_quota';
