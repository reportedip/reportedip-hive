/**
 * Form execution proof: adds the proof field to every form carrying an anchor.
 *
 * With a challenge present the field carries a solved computation instead of a
 * plain marker, so the value cannot be copied out of the page. Without one the
 * behaviour is unchanged.
 *
 * Every form gets its own answer out of a small stock that is topped up in the
 * background. An answer is single-use on the server, so handing the same one to
 * two forms, or to one form twice, would have the second submission refused as
 * a replay. Answers are dealt out as soon as the first one is ready, so the
 * first submission is served even on a slow device; only a form that has
 * already been submitted draws again. When nothing is ready the field is
 * emptied rather than filled with a spent answer: a submission nobody could
 * answer for is honestly unproven.
 *
 * The field also carries how many seconds the form was on screen, appended
 * after a tilde. The clock starts in the browser and never in the markup, so a
 * page served from a cache filled days ago measures the same as a fresh one.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     2.1.53
 */

( function () {
	'use strict';

	var CHUNK = 256;
	var LIMIT = 1 << 24;

	var stock = [];
	var mining = false;
	var challenge = null;

	function field( form, name ) {
		var input = form.querySelector( 'input[name="' + name + '"]' );

		if ( ! input ) {
			input = document.createElement( 'input' );
			input.type = 'hidden';
			input.name = name;
			form.appendChild( input );
		}

		return input;
	}

	function anchorOf( form ) {
		var anchor = form.querySelector( 'input.rip-fp-anchor' );

		return anchor && anchor.dataset.n ? anchor : null;
	}

	/**
	 * Wall-clock milliseconds, read off the monotonic clock where there is one
	 * so a page that is open while the system clock is corrected still measures
	 * a sane duration. Absolute, because a start time may have to survive a
	 * reload in sessionStorage.
	 *
	 * @since 2.1.58
	 */
	function now() {
		if ( window.performance && window.performance.timeOrigin ) {
			return window.performance.timeOrigin + window.performance.now();
		}

		return Date.now();
	}

	function recall( key ) {
		try {
			return window.sessionStorage.getItem( key );
		} catch ( error ) {
			return null;
		}
	}

	function remember( key, value ) {
		try {
			window.sessionStorage.setItem( key, value );
		} catch ( error ) {
			return;
		}
	}

	/**
	 * Note the moment this form became visible, once. Kept per form, because
	 * two forms on one page are looked at for different lengths of time.
	 *
	 * @since 2.1.58
	 */
	function mark( anchor ) {
		if ( anchor.dataset.t ) {
			return;
		}

		anchor.dataset.t = now();
		remember( anchor.dataset.k, anchor.dataset.t );
	}

	/**
	 * Start the clock for one form. A start time left over from an earlier load
	 * of the same page wins, so a multi-step form that reloads in between keeps
	 * measuring from the first sight rather than from the last step.
	 *
	 * Without an IntersectionObserver the moment the script found the anchor
	 * has to do.
	 *
	 * @since 2.1.58
	 */
	function clock( anchor, index ) {
		anchor.dataset.k = 'ripfp:' + window.location.pathname + ':' + index;

		var earlier = recall( anchor.dataset.k );

		if ( earlier ) {
			anchor.dataset.t = earlier;
			return;
		}

		if ( ! window.IntersectionObserver || ! anchor.form ) {
			mark( anchor );
			return;
		}

		var watcher = new window.IntersectionObserver( function ( entries ) {
			for ( var i = 0; i < entries.length; i++ ) {
				if ( entries[ i ].isIntersecting ) {
					mark( anchor );
					watcher.disconnect();
				}
			}
		} );

		watcher.observe( anchor.form );
	}

	/**
	 * Start the clock on every anchored form on the page.
	 *
	 * @since 2.1.58
	 */
	function watch() {
		var anchors = document.querySelectorAll( 'input.rip-fp-anchor[data-n]' );

		for ( var i = 0; i < anchors.length; i++ ) {
			clock( anchors[ i ], i );
		}
	}

	/**
	 * Append the whole seconds the form was on screen to whatever the field
	 * already holds. A form nobody ever saw carries no suffix at all, which the
	 * server reads as an unmeasured submission rather than a fast one.
	 *
	 * @since 2.1.58
	 */
	function stamp( form, anchor ) {
		var start = parseFloat( anchor.dataset.t );

		if ( ! start ) {
			return;
		}

		var input = field( form, anchor.dataset.n );

		if ( ! input.value ) {
			return;
		}

		input.value += '~' + Math.max( 0, Math.min( 9999, Math.floor( ( now() - start ) / 1000 ) ) );
	}

	/**
	 * Hand one form an answer of its own, then ask for the stock to be topped
	 * up. An empty stock writes an empty field, which reads as unproven.
	 *
	 * @since 2.1.58
	 */
	function give( form, anchor ) {
		field( form, anchor.dataset.n ).value = stock.shift() || '';
		anchor.dataset.u = 'ready';
		refill();
	}

	/**
	 * Give every form that is still without one an answer. Called as soon as
	 * the first answer exists, so a visitor who submits straight away is served.
	 *
	 * @since 2.1.58
	 */
	function deal() {
		var anchors = document.querySelectorAll( 'input.rip-fp-anchor[data-s][data-n]' );

		for ( var i = 0; i < anchors.length; i++ ) {
			if ( stock.length && anchors[ i ].form && ! anchors[ i ].dataset.u ) {
				give( anchors[ i ].form, anchors[ i ] );
			}
		}
	}

	/**
	 * Plain markers do not depend on any computation, so they are written as
	 * soon as the page is there.
	 */
	function markers() {
		var anchors = document.querySelectorAll( 'input.rip-fp-anchor[data-n]:not([data-s])' );

		for ( var i = 0; i < anchors.length; i++ ) {
			if ( anchors[ i ].form ) {
				field( anchors[ i ].form, anchors[ i ].dataset.n ).value = '1';
			}
		}
	}

	/**
	 * A form that already holds an unused answer sends it. One that was
	 * submitted before, or never got one, draws now.
	 *
	 * @since 2.1.58
	 */
	function onSubmit( form ) {
		var anchor = anchorOf( form );

		if ( ! anchor ) {
			return;
		}

		if ( ! anchor.dataset.s ) {
			field( form, anchor.dataset.n ).value = '1';
		} else {
			if ( 'ready' !== anchor.dataset.u ) {
				give( form, anchor );
			}

			anchor.dataset.u = 'used';
			refill();
		}

		stamp( form, anchor );
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
	 * Start the counter somewhere random. Every visitor gets the same starting
	 * value for the period, so counting up from zero would have them all find
	 * the same first solution; the first submission would spend it and every
	 * other reader would look like a replay.
	 */
	function randomStart() {
		var slot = new Uint32Array( 1 );
		window.crypto.getRandomValues( slot );

		return slot[ 0 ];
	}

	async function solve() {
		var encoder = new TextEncoder();
		var nonce = randomStart();
		var spent = 0;

		try {
			while ( spent < LIMIT ) {
				var pending = [];
				var nonces = [];

				for ( var i = 0; i < CHUNK; i++ ) {
					var hex = ( nonce++ ).toString( 16 );
					nonces.push( hex );
					pending.push( window.crypto.subtle.digest( 'SHA-256', encoder.encode( challenge.seed + hex ) ) );
				}

				spent += CHUNK;

				var digests = await Promise.all( pending );

				for ( var j = 0; j < digests.length; j++ ) {
					if ( leadingZeroBits( new Uint8Array( digests[ j ] ) ) >= challenge.bits ) {
						return challenge.bucket + '.' + nonces[ j ];
					}
				}
			}
		} catch ( error ) {
			return null;
		}

		return null;
	}

	/**
	 * How many answers to keep ready. Two covers the common page with one form
	 * submitted twice, more forms want more.
	 *
	 * @since 2.1.58
	 */
	function wanted() {
		return Math.max( 2, document.querySelectorAll( 'input.rip-fp-anchor[data-s]' ).length );
	}

	async function refill() {
		if ( mining || ! challenge ) {
			return;
		}

		mining = true;

		try {
			while ( stock.length < wanted() ) {
				var answer = await solve();

				if ( ! answer ) {
					return;
				}

				stock.push( answer );
				deal();
			}
		} finally {
			mining = false;
		}
	}

	/**
	 * Read the challenge off any anchor on the page and start working on it.
	 * Without a secure context there is no `crypto.subtle`, so nothing is
	 * computed, no field is written, and the submission reads as one that never
	 * carried our field. That is the lenient path, by design.
	 */
	function start() {
		var anchor = document.querySelector( 'input.rip-fp-anchor[data-s]' );

		if ( ! anchor || ! window.crypto || ! window.crypto.subtle || 'undefined' === typeof TextEncoder ) {
			return;
		}

		challenge = {
			seed: anchor.dataset.s,
			bucket: anchor.dataset.b,
			bits: parseInt( anchor.dataset.d, 10 )
		};

		refill();
	}

	document.addEventListener(
		'submit',
		function ( event ) {
			if ( event.target && event.target.querySelector ) {
				onSubmit( event.target );
			}
		},
		true
	);

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', function () {
			watch();
			start();
			markers();
		} );
	} else {
		watch();
		start();
		markers();
	}
}() );
