/**
 * Form protection self-test: works out one task and drives the three passes.
 *
 * The page hands over a single task, so there is no stock to keep, no form to
 * watch and no submit event to catch. One answer is worked out, the first pass
 * spends it, the second pass sends the very same answer again to show that a
 * copy is worth nothing, and the third pass fills the anchor the way a script
 * that fills every input would.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     2.1.58
 */

( function () {
	'use strict';

	var LIMIT = 1 << 24;

	var config = window.reportedipHiveSelfTest;

	if ( ! config ) {
		return;
	}

	var button = document.getElementById( 'rip-selftest-run' );
	var status = document.getElementById( 'rip-selftest-status' );
	var table = document.getElementById( 'rip-selftest-results' );
	var summary = document.getElementById( 'rip-selftest-summary' );
	var body = table ? table.querySelector( 'tbody' ) : null;

	if ( ! button || ! status || ! table || ! body || ! summary ) {
		return;
	}

	function say( text ) {
		status.textContent = text;
		status.classList.remove( 'rip-hidden' );
	}

	function leadingZeroBits( bytes ) {
		var bits = 0;

		for ( var i = 0; i < bytes.length; i++ ) {
			var part = bytes[ i ];

			if ( part === 0 ) {
				bits += 8;
				continue;
			}

			while ( part < 128 ) {
				bits++;
				part <<= 1;
			}

			break;
		}

		return bits;
	}

	/**
	 * Work out one answer for the task the page carries.
	 *
	 * The counter starts somewhere random for the same reason it does on the
	 * public forms: every visitor sees the same starting value, so counting up
	 * from zero would have everyone find the same answer.
	 *
	 * @since 2.1.58
	 */
	async function solve() {
		if ( ! config.bits ) {
			return config.token + '.0';
		}

		var encoder = new TextEncoder();
		var slot = new Uint32Array( 1 );

		window.crypto.getRandomValues( slot );

		var nonce = slot[ 0 ];
		var spent = 0;

		while ( spent < LIMIT ) {
			var hex = ( nonce++ ).toString( 16 );
			var digest = await window.crypto.subtle.digest( 'SHA-256', encoder.encode( config.seed + hex ) );

			spent++;

			if ( leadingZeroBits( new Uint8Array( digest ) ) >= config.bits ) {
				return config.token + '.' + hex;
			}
		}

		return '';
	}

	function post( run, proof ) {
		var data = new URLSearchParams();

		data.append( 'action', config.action );
		data.append( 'nonce', config.nonce );
		data.append( 'run', run );
		data.append( 'proof', proof );

		return fetch( config.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			body: data
		} ).then( function ( response ) {
			return response.json();
		} );
	}

	function cell( row, text ) {
		var td = document.createElement( 'td' );

		td.textContent = text;
		row.appendChild( td );
	}

	function render( result ) {
		var row = document.createElement( 'tr' );
		var badge = document.createElement( 'span' );
		var verdict = document.createElement( 'td' );

		cell( row, result.label );
		cell( row, result.expected_label );

		badge.className = 'rip-badge rip-badge--' + ( result.ok ? 'success' : 'danger' );
		badge.textContent = result.actual_label;
		verdict.appendChild( badge );
		row.appendChild( verdict );

		cell( row, result.meaning );
		body.appendChild( row );
	}

	function finish( result ) {
		var box = document.createElement( 'div' );

		box.className = 'rip-alert rip-alert--' + ( result.pass ? 'success' : 'danger' );
		box.textContent = result.message;
		summary.appendChild( box );
	}

	async function run() {
		button.disabled = true;
		body.textContent = '';
		summary.textContent = '';
		table.classList.add( 'rip-hidden' );

		var proof = '1';

		if ( config.token ) {
			if ( config.bits && ( ! window.crypto || ! window.crypto.subtle || 'undefined' === typeof TextEncoder ) ) {
				say( config.strings.insecure );
				button.disabled = false;
				return;
			}

			say( config.strings.solving );

			try {
				proof = await solve();
			} catch ( error ) {
				proof = '';
			}

			if ( ! proof ) {
				say( config.strings.unsolved );
				button.disabled = false;
				return;
			}
		}

		say( config.strings.running );
		table.classList.remove( 'rip-hidden' );

		for ( var i = 0; i < config.runs.length; i++ ) {
			var answer = null;

			try {
				answer = await post( config.runs[ i ], proof );
			} catch ( error ) {
				answer = null;
			}

			if ( ! answer || ! answer.success || ! answer.data ) {
				say( ( answer && answer.data && answer.data.message ) || config.strings.failed );
				button.disabled = false;
				return;
			}

			render( answer.data );

			if ( answer.data.summary ) {
				finish( answer.data.summary );
			}
		}

		status.classList.add( 'rip-hidden' );
		button.disabled = false;
	}

	button.addEventListener( 'click', run );
}() );
