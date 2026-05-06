/**
 * Listener that converts a `reportedip_2fa_required` REST-API error
 * coming from the WooCommerce Cart/Checkout block into a hard redirect
 * to the themed challenge slug. The Store-API filter on the server
 * side returns the redirect URL inside the error payload — without
 * this listener the block would just surface the error message.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     1.7.0
 */

( function () {
	'use strict';

	if ( ! window.wp || ! window.wp.hooks ) {
		return;
	}

	function pickRedirectUrl( payload ) {
		if ( ! payload || typeof payload !== 'object' ) {
			return '';
		}
		var candidates = [
			payload.redirect_url,
			payload.data && payload.data.redirect_url,
			payload.error && payload.error.data && payload.error.data.redirect_url,
		];
		for ( var i = 0; i < candidates.length; i++ ) {
			if ( typeof candidates[ i ] === 'string' && candidates[ i ].length > 0 ) {
				return candidates[ i ];
			}
		}
		return '';
	}

	function maybeRedirect( payload ) {
		var code = ( payload && ( payload.code || ( payload.error && payload.error.code ) ) ) || '';
		if ( 'reportedip_2fa_required' !== code ) {
			return;
		}
		var url = pickRedirectUrl( payload );
		if ( url ) {
			window.location.assign( url );
		}
	}

	window.wp.hooks.addAction(
		'experimental__woocommerce_blocks-checkout-set-error-message',
		'reportedip-hive/2fa-redirect',
		function ( error ) { maybeRedirect( error ); }
	);

	window.wp.hooks.addFilter(
		'experimental__woocommerce_blocks-checkout-process-server-error',
		'reportedip-hive/2fa-redirect',
		function ( error ) {
			maybeRedirect( error );
			return error;
		}
	);
} )();
