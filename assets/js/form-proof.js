/**
 * Form execution proof: adds the proof field to every form carrying an anchor.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     2.1.53
 */

( function () {
	'use strict';

	function arm( form ) {
		var anchor = form.querySelector( 'input.rip-fp-anchor' );

		if ( ! anchor || ! anchor.dataset.n ) {
			return;
		}

		if ( form.querySelector( 'input[name="' + anchor.dataset.n + '"]' ) ) {
			return;
		}

		var field = document.createElement( 'input' );
		field.type = 'hidden';
		field.name = anchor.dataset.n;
		field.value = '1';
		form.appendChild( field );
	}

	function scan() {
		var anchors = document.querySelectorAll( 'input.rip-fp-anchor' );

		for ( var i = 0; i < anchors.length; i++ ) {
			if ( anchors[ i ].form ) {
				arm( anchors[ i ].form );
			}
		}
	}

	document.addEventListener(
		'submit',
		function ( event ) {
			if ( event.target && event.target.querySelector ) {
				arm( event.target );
			}
		},
		true
	);

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', scan );
	} else {
		scan();
	}
}() );
