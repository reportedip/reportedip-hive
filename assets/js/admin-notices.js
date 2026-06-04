/**
 * Persistent dismissal for Hive notices on pages outside the plugin's own
 * screens, where the full admin bundle (assets/js/admin.js) is not loaded.
 *
 * Bails when admin.js is present (its localized `reportedip_hive_ajax` object
 * exists) so the click handler never binds twice on plugin pages.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     2.0.1
 */
( function ( $ ) {
	'use strict';

	if ( typeof window.reportedip_hive_ajax !== 'undefined' ) {
		return;
	}

	$( document ).on( 'click', '.reportedip-dismissible .notice-dismiss', function () {
		var $notice  = $( this ).closest( '.reportedip-dismissible' );
		var noticeId = $notice.data( 'notice-id' );

		if ( ! noticeId || typeof reportedip_hive_notices === 'undefined' ) {
			return;
		}

		$.post( reportedip_hive_notices.ajax_url, {
			action: 'reportedip_hive_dismiss_notice',
			nonce: reportedip_hive_notices.nonce,
			notice_id: noticeId
		} );
	} );
}( jQuery ) );
