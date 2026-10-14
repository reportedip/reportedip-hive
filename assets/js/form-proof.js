/**
 * Form execution proof: adds the proof field to every form carrying an anchor.
 *
 * The field carries a plain marker. It proves that a browser rendered the page
 * and ran this script, which a client posting straight at the form address
 * never does. The page carries nothing about the visitor, so a full-page cache
 * and a CDN may serve it unchanged to everyone.
 *
 * An anchor that names a task endpoint (`data-e`) is answered with the marker
 * as well. Such a page comes from a cache filled while a release or an add-on
 * handed out tasks, and the marker is what this plugin reads on its own.
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

	var bound = false;
	var jqueryBound = false;

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
	 * The marker does not depend on anything, so it is written as soon as the
	 * page is there.
	 */
	function markers() {
		var anchors = document.querySelectorAll( 'input.rip-fp-anchor[data-n]' );

		for ( var i = 0; i < anchors.length; i++ ) {
			if ( anchors[ i ].form ) {
				field( anchors[ i ].form, anchors[ i ].dataset.n ).value = '1';
			}
		}
	}

	/**
	 * Write the marker afresh and append the measured duration.
	 *
	 * @since 2.1.58
	 */
	function onSubmit( form ) {
		var anchor = anchorOf( form );

		if ( ! anchor ) {
			return;
		}

		field( form, anchor.dataset.n ).value = '1';
		anchor.dataset.s = now();
		stamp( form, anchor );
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
	 * See a submission that jQuery started.
	 *
	 * A plugin that sends its form with `jQuery( form ).trigger( 'submit' )`
	 * (Ultimate Member does, on every button) runs only jQuery's own handlers
	 * and then calls the form's `submit()` method, which fires no event, so
	 * the listener below never sees the submission. This handler sees exactly
	 * those: a native submit reaches jQuery too, but with `isTrigger` unset,
	 * and is left to the listener so no submission is counted twice.
	 *
	 * Gravity Forms triggers the very same jQuery submit right after its own
	 * `pre_submission` filter has already stamped the form. A submission
	 * prepared within the last second is therefore the same submission and
	 * is sent as it is.
	 *
	 * @since 2.1.65
	 */
	function jquery() {
		if ( jqueryBound || ! window.jQuery || ! window.jQuery.fn || ! window.jQuery.fn.on ) {
			return;
		}

		jqueryBound = true;

		window.jQuery( document ).on( 'submit', 'form', function ( event ) {
			if ( ! event.isTrigger ) {
				return;
			}

			var anchor = anchorOf( this );

			if ( ! anchor || ( anchor.dataset.s && now() - parseFloat( anchor.dataset.s ) < 1000 ) ) {
				return;
			}

			onSubmit( this );
		} );
	}

	/**
	 * Take in a form that reached the page after the first pass.
	 *
	 * A form rendered again after a failed validation, or loaded into a popup,
	 * arrives without a clock and without a marker of its own. The start time
	 * is remembered per form, so the clock picks up where it left off rather
	 * than starting over.
	 *
	 * @since 2.1.63
	 */
	function rearm() {
		watch();
		markers();
		gravity();
		jquery();
	}

	document.addEventListener(
		'submit',
		function ( event ) {
			var form = event.target;

			if ( ! form || ! form.querySelector ) {
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
