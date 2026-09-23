/**
 * Form execution proof: adds the proof field to every form carrying an anchor.
 *
 * With a challenge in play the field carries a signed task fetched from this
 * site and the solution worked out for it, so the value cannot be copied out
 * of the page. Without one the behaviour is unchanged: a plain marker.
 *
 * The page carries nothing about the visitor, only the address of the
 * endpoint, so a full-page cache and a CDN may serve it unchanged to everyone.
 * The visitor's own task comes from a POST the caches never store. One task
 * is fetched per page and kept in sessionStorage until it expires, so a
 * second form on the page or a page change costs no second request.
 *
 * Every form gets its own answer out of a small stock that is topped up in
 * the background. An answer is single-use on the server, so handing the same
 * one to two forms, or to one form twice, would have the second submission
 * refused as a replay. Answers are dealt out as soon as the first one is
 * ready, so the first submission is served even on a slow device; only a form
 * that has already been submitted draws again. When nothing is ready the
 * field is emptied rather than filled with a spent answer: a submission
 * nobody could answer for is honestly unproven, and the form tells the sender
 * so; a reload fetches a fresh task.
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
	var STORE = 'ripfc:task';

	var stock = [];
	var mining = false;
	var fetching = false;
	var pausedUntil = 0;
	var bound = false;

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

	function forget( key ) {
		try {
			window.sessionStorage.removeItem( key );
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
		var anchors = document.querySelectorAll( 'input.rip-fp-anchor[data-e][data-n]' );

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
		var anchors = document.querySelectorAll( 'input.rip-fp-anchor[data-n]:not([data-e])' );

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

		if ( ! anchor.dataset.e ) {
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
	 * Start the counter somewhere random, so two tabs working on the same
	 * task do not find the same first solution.
	 */
	function randomStart() {
		var slot = new Uint32Array( 1 );
		window.crypto.getRandomValues( slot );

		return slot[ 0 ];
	}

	/**
	 * Whether a stored task can still be used. The server names the lifetime
	 * relative to its own clock and the browser turns it into a deadline on
	 * its own, so a device whose clock is minutes off is never sent to a
	 * refusal for a task that is perfectly good.
	 */
	function fresh( current ) {
		return !! ( current && current.token && current.until && current.until > Date.now() + 15000 );
	}

	/**
	 * The endpoint the first challenged anchor on the page names, on the
	 * scheme the page itself was loaded with. A site behind a proxy that
	 * terminates TLS (Cloudflare Flexible SSL, an unconfigured trusted-header
	 * setting) prints http addresses into an https page, and a fetch across
	 * schemes is blocked as mixed content before it ever leaves the browser.
	 */
	function endpoint() {
		var anchor = document.querySelector( 'input.rip-fp-anchor[data-e]' );

		if ( ! anchor ) {
			return '';
		}

		try {
			var url = new URL( anchor.dataset.e, window.location.href );

			if ( url.host === window.location.host ) {
				url.protocol = window.location.protocol;
			}

			return url.toString();
		} catch ( error ) {
			return anchor.dataset.e;
		}
	}

	/**
	 * Fetch a task from this site, or reuse the one kept from an earlier
	 * page. Resolves to null when none can be had; the field then stays
	 * empty and the form tells the sender to try again.
	 *
	 * A 429 pauses further requests for the time the server names, so a
	 * throttled network does not hammer the endpoint.
	 *
	 * @since 2.1.64
	 */
	function task() {
		var kept = null;

		try {
			kept = JSON.parse( recall( STORE ) || 'null' );
		} catch ( error ) {
			kept = null;
		}

		if ( fresh( kept ) ) {
			return Promise.resolve( kept );
		}

		forget( STORE );

		var url = endpoint();

		if ( ! url || ! window.fetch || Date.now() < pausedUntil ) {
			return Promise.resolve( null );
		}

		return window.fetch( url, {
			method: 'POST',
			credentials: 'same-origin',
			cache: 'no-store',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: ''
		} ).then( function ( response ) {
			if ( 429 === response.status ) {
				var wait = parseInt( response.headers.get( 'Retry-After' ), 10 );
				pausedUntil = Date.now() + ( isNaN( wait ) ? 30 : wait ) * 1000;

				return null;
			}

			if ( ! response.ok ) {
				return null;
			}

			return response.json();
		} ).then( function ( got ) {
			if ( got && got.token ) {
				got.until = Date.now() + ( parseInt( got.ttl, 10 ) || 0 ) * 1000;
			}

			if ( ! fresh( got ) ) {
				return null;
			}

			remember( STORE, JSON.stringify( got ) );

			return got;
		} ).catch( function () {
			return null;
		} );
	}

	/**
	 * Work out one answer for a task. A task of zero difficulty needs no
	 * arithmetic and no secure context, only the token itself.
	 */
	async function solve( current ) {
		if ( ! current.bits ) {
			return current.token + '.0';
		}

		if ( ! window.crypto || ! window.crypto.subtle || 'undefined' === typeof TextEncoder ) {
			return null;
		}

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
					pending.push( window.crypto.subtle.digest( 'SHA-256', encoder.encode( current.seed + hex ) ) );
				}

				spent += CHUNK;

				var digests = await Promise.all( pending );

				for ( var j = 0; j < digests.length; j++ ) {
					if ( leadingZeroBits( new Uint8Array( digests[ j ] ) ) >= current.bits ) {
						return current.token + '.' + nonces[ j ];
					}
				}
			}
		} catch ( error ) {
			return null;
		}

		return null;
	}

	/**
	 * How many answers to keep ready. One per challenged form on the page,
	 * because each answer spends its own single-use task.
	 *
	 * @since 2.1.58
	 */
	function wanted() {
		return Math.max( 1, document.querySelectorAll( 'input.rip-fp-anchor[data-e]' ).length );
	}

	/**
	 * Top the stock up. Every answer needs a task of its own, so each round
	 * fetches, solves, deals, and forgets the task it spent.
	 */
	async function refill() {
		if ( mining || fetching || ! endpoint() ) {
			return;
		}

		mining = true;

		try {
			while ( stock.length < wanted() ) {
				fetching = true;
				var current = await task();
				fetching = false;

				if ( ! current ) {
					return;
				}

				var answer = await solve( current );

				forget( STORE );

				if ( ! answer ) {
					return;
				}

				stock.push( answer );
				deal();
			}
		} finally {
			mining = false;
			fetching = false;
		}
	}

	function start() {
		refill();
	}

	/**
	 * Fill the field the way Gravity Forms expects it to be filled.
	 *
	 * Gravity Forms submits its forms itself and fires no submit event doing so,
	 * which is why the listener below never sees one. It publishes a filter for
	 * exactly this purpose and runs it before it collects the form, the same one
	 * its own invisible captcha uses.
	 *
	 * @since 2.1.63
	 */
	function gravity() {
		if ( bound || ! window.gform || ! window.gform.utils || ! window.gform.utils.addFilter ) {
			return;
		}

		bound = true;

		window.gform.utils.addFilter( 'gform/submission/pre_submission', function ( data ) {
			if ( data && data.form && ! data.abort ) {
				onSubmit( data.form );
			}

			return data;
		} );
	}

	/**
	 * Take in a form that reached the page after the first pass.
	 *
	 * A form rendered again after a failed validation, or loaded into a popup,
	 * arrives without a clock and without an answer of its own. The start time
	 * is remembered per form, so the clock picks up where it left off rather
	 * than starting over.
	 *
	 * @since 2.1.63
	 */
	function rearm() {
		watch();
		start();
		markers();
		gravity();
	}

	/**
	 * Wait until an answer is in stock, or until the hold runs out.
	 *
	 * @since 2.1.64
	 */
	function untilReady( anchor, limit ) {
		var deadline = Date.now() + limit;

		refill();

		return new Promise( function ( resolve ) {
			( function poll() {
				if ( stock.length || 'ready' === anchor.dataset.u || Date.now() > deadline ) {
					resolve();
					return;
				}

				window.setTimeout( poll, 50 );
			}() );
		} );
	}

	/**
	 * Send a form on, the way the visitor asked for it.
	 */
	function resubmit( form, submitter ) {
		if ( form.requestSubmit ) {
			if ( submitter ) {
				form.requestSubmit( submitter );
			} else {
				form.requestSubmit();
			}

			return;
		}

		form.submit();
	}

	/**
	 * A visitor who submits before the task has come back is not a bot, and
	 * an empty field would refuse them. The submit is held until an answer is
	 * in stock, at most HOLD milliseconds, and then sent on as the visitor
	 * sent it. A form that already holds an answer, or has been held once, is
	 * never held again.
	 *
	 * @since 2.1.64
	 */
	var HOLD = 8000;

	document.addEventListener(
		'submit',
		function ( event ) {
			var form = event.target;

			if ( ! form || ! form.querySelector ) {
				return;
			}

			var anchor = anchorOf( form );

			if ( anchor && anchor.dataset.e && 'ready' !== anchor.dataset.u && ! stock.length && ! anchor.dataset.w && endpoint() ) {
				event.preventDefault();
				event.stopImmediatePropagation();

				anchor.dataset.w = 'held';

				var submitter = event.submitter || null;

				untilReady( anchor, HOLD ).then( function () {
					resubmit( form, submitter );
				} );

				return;
			}

			onSubmit( form );
		},
		true
	);

	document.addEventListener( 'gform/post_render', rearm );

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', rearm );
	} else {
		rearm();
	}
}() );
