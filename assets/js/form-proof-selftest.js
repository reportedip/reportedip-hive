/**
 * Form protection self-test: drives the three passes.
 *
 * There is no form to watch and no submit event to catch. The first pass sends
 * the marker a browser writes, the second sends the very same value again,
 * and the third fills the anchor the way a script that fills every input
 * would.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     2.1.58
 */

( function () {
	'use strict';

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

		say( config.strings.running );
		table.classList.remove( 'rip-hidden' );

		for ( var i = 0; i < config.runs.length; i++ ) {
			var answer = null;

			try {
				answer = await post( config.runs[ i ], '1' );
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
