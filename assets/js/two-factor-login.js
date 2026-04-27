/**
 * ReportedIP Hive — Two-Factor Login Page Script.
 *
 * Progressive-enhancement logic for wp-login.php:
 *   – auto-redirects the WP_Error page into the real challenge page
 *   – drives the WAI-ARIA tablist (arrow keys, Home/End, roving tabindex)
 *   – intercepts "Code senden / erneut senden" and routes it through the
 *     admin-ajax resend endpoint so the user never loses the challenge
 *   – keeps an inline cooldown countdown and aria-live status updates
 *   – blocks auto-submit on paste (outdated clipboard codes used to fail)
 *   – WebAuthn / Passkey assertion flow
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     1.3.0
 */

( function () {
	'use strict';

	var config = ( typeof reportedip2fa !== 'undefined' ) ? reportedip2fa : {};

	document.addEventListener( 'DOMContentLoaded', function () {
		initAutoRedirect();

		// Only wire challenge-specific logic when the challenge form exists.
		var form = document.getElementById( 'rip-2fa-form' );
		if ( form ) {
			initMethodTabs();
			initAutoSubmit();
			initResendButtons();
			initWebAuthnLogin();
		}
	} );

	/* ------------------------------------------------------------------ *
	 * Auto-redirect from the WP_Error page into the 2FA challenge.
	 * ------------------------------------------------------------------ */
	function initAutoRedirect() {
		if ( config.challengeRedirect ) {
			window.location.href = config.challengeRedirect;
			return;
		}
		var marker = document.getElementById( 'reportedip-2fa-redirect' );
		if ( marker ) {
			window.location.href = marker.getAttribute( 'data-url' )
				|| ( window.location.pathname + '?action=reportedip_2fa' );
		}
	}

	/* ------------------------------------------------------------------ *
	 * Tablist — ARIA Authoring Practices. Roving tabindex, arrow keys,
	 * Home/End, focus forwarded to the panel's first input on activation.
	 * ------------------------------------------------------------------ */
	function initMethodTabs() {
		var tablist = document.querySelector( '.rip-2fa-challenge__methods' );
		if ( ! tablist ) { return; }

		var tabs         = Array.prototype.slice.call( tablist.querySelectorAll( '[role="tab"]' ) );
		var panels       = Array.prototype.slice.call( document.querySelectorAll( '[role="tabpanel"]' ) );
		var methodInput  = document.getElementById( 'rip-2fa-method-input' );
		if ( ! tabs.length || ! panels.length ) { return; }

		function activate( tab, opts ) {
			var method = tab.getAttribute( 'data-method' );

			tabs.forEach( function ( t ) {
				var active = ( t === tab );
				t.classList.toggle( 'rip-2fa-challenge__method-tab--active', active );
				t.setAttribute( 'aria-selected', active ? 'true' : 'false' );
				t.setAttribute( 'tabindex', active ? '0' : '-1' );
			} );

			panels.forEach( function ( p ) {
				var active = ( p.getAttribute( 'data-panel' ) === method );
				p.classList.toggle( 'rip-2fa-challenge__panel--active', active );
				if ( active ) {
					p.removeAttribute( 'hidden' );
				} else {
					p.setAttribute( 'hidden', '' );
				}

				// Only the active panel submits a reportedip_2fa_code. Same-named
				// inputs in hidden panels would otherwise win in PHP's $_POST
				// because the last one in DOM order takes precedence. The
				// webauthn hidden input keeps its sentinel when active.
				var codeInputs = p.querySelectorAll( 'input[name="reportedip_2fa_code"]' );
				codeInputs.forEach( function ( inp ) {
					inp.disabled = ! active;
					if ( ! active && inp.type !== 'hidden' ) {
						inp.value = '';
					}
				} );
			} );

			if ( methodInput ) { methodInput.value = method; }

			if ( opts && opts.focus ) {
				tab.focus();
			}

			// Forward focus into the now-visible panel's primary input (or
			// primary button for passkey). This keeps keyboard users on the
			// happy path after a tab switch.
			if ( opts && opts.moveIntoPanel ) {
				var activePanel = document.querySelector( '.rip-2fa-challenge__panel--active' );
				if ( activePanel ) {
					var target = activePanel.querySelector( 'input[type="text"]:not([hidden])' )
						|| activePanel.querySelector( 'button:not([hidden])' );
					if ( target ) {
						// Only focus the text input if its phase is visible.
						var phase = target.closest( '.rip-2fa-challenge__phase' );
						if ( phase && phase.hasAttribute( 'hidden' ) ) {
							var altBtn = activePanel.querySelector( '.rip-2fa-challenge__phase:not([hidden]) button' );
							if ( altBtn ) { target = altBtn; }
						}
						// Use rAF so the hidden attribute is honoured by AT.
						window.requestAnimationFrame( function () { target.focus(); } );
					}
				}
			}
		}

		tabs.forEach( function ( tab, idx ) {
			tab.addEventListener( 'click', function () { activate( tab, { moveIntoPanel: true } ); } );

			tab.addEventListener( 'keydown', function ( e ) {
				var key = e.key;
				var next = null;
				if ( key === 'ArrowRight' || key === 'ArrowDown' ) {
					next = tabs[ ( idx + 1 ) % tabs.length ];
				} else if ( key === 'ArrowLeft' || key === 'ArrowUp' ) {
					next = tabs[ ( idx - 1 + tabs.length ) % tabs.length ];
				} else if ( key === 'Home' ) {
					next = tabs[ 0 ];
				} else if ( key === 'End' ) {
					next = tabs[ tabs.length - 1 ];
				}
				if ( next ) {
					e.preventDefault();
					activate( next, { focus: true } );
				}
			} );
		} );

		// Initial sync — disable non-active panel inputs so the server gets the
		// code from the tab the user is actually on.
		var currentTab = tabs.find( function ( t ) { return t.getAttribute( 'aria-selected' ) === 'true'; } ) || tabs[ 0 ];
		if ( currentTab ) { activate( currentTab, {} ); }
	}

	/* ------------------------------------------------------------------ *
	 * Numeric-only sanitisation + auto-submit once the 6th digit is typed.
	 * Paste never auto-submits (outdated clipboard codes were causing
	 * "Invalid code" errors before the user could sanity-check them).
	 * ------------------------------------------------------------------ */
	function initAutoSubmit() {
		var inputs = document.querySelectorAll( '#rip-2fa-code-totp, #rip-2fa-code-email, #rip-2fa-code-sms' );
		var form   = document.getElementById( 'rip-2fa-form' );
		if ( ! form || ! inputs.length ) { return; }

		var pastedRecently = false;

		inputs.forEach( function ( input ) {
			input.addEventListener( 'paste', function ( e ) {
				var pasted = ( e.clipboardData || window.clipboardData ).getData( 'text' ) || '';
				pasted = pasted.replace( /[^0-9]/g, '' ).substring( 0, 6 );
				e.preventDefault();
				this.value = pasted;
				pastedRecently = true;
				setTimeout( function () { pastedRecently = false; }, 300 );
			} );

			input.addEventListener( 'input', function ( e ) {
				this.value = this.value.replace( /[^0-9]/g, '' );
				if ( this.value.length === 6 && ! pastedRecently && e.inputType !== 'insertFromPaste' ) {
					form.submit();
				}
			} );
		} );
	}

	/* ------------------------------------------------------------------ *
	 * Resend buttons (Phase-1 "Code senden" + Phase-2 "Erneut senden").
	 * AJAX first, fall back to a real navigation if fetch fails so users
	 * without JS still get the legacy redirect-based flow via the anchor
	 * fallback URL stored on each button.
	 * ------------------------------------------------------------------ */
	function initResendButtons() {
		var buttons = document.querySelectorAll( '[data-resend-method]' );
		if ( ! buttons.length ) { return; }

		var live = document.getElementById( 'rip-2fa-live' );

		buttons.forEach( function ( btn ) {
			var cooldown = parseInt( btn.getAttribute( 'data-cooldown' ), 10 ) || 0;
			if ( cooldown > 0 && btn.classList.contains( 'rip-2fa-challenge__resend-link' ) ) {
				runCooldown( btn, cooldown );
			}

			btn.addEventListener( 'click', function ( e ) {
				e.preventDefault();
				if ( btn.disabled ) { return; }

				var method       = btn.getAttribute( 'data-resend-method' );
				var fallbackUrl  = btn.getAttribute( 'data-fallback-url' );
				var originalText = btn.innerHTML;

				btn.disabled = true;
				btn.classList.add( 'rip-2fa-challenge__resend-link--disabled' );
				btn.setAttribute( 'aria-busy', 'true' );
				setLiveMessage( live, '', '' );

				resendRequest( method )
					.then( function ( data ) {
						btn.innerHTML = originalText;
						btn.removeAttribute( 'aria-busy' );

						showPhaseCode( method, data && data.destination );
						var msg = ( data && data.message ) || ( config.strings && config.strings.newCodeSent ) || 'New code sent.';
						setLiveMessage( live, msg, 'success' );

						var wait = data && data.cooldown ? parseInt( data.cooldown, 10 ) : 60;
						runCooldown( btn, wait );
					} )
					.catch( function ( err ) {
						btn.innerHTML = originalText;
						btn.removeAttribute( 'aria-busy' );
						btn.disabled = false;
						btn.classList.remove( 'rip-2fa-challenge__resend-link--disabled' );

						if ( err && err.fallback && fallbackUrl ) {
							window.location.href = fallbackUrl;
							return;
						}
						var msg = ( err && err.message ) || ( config.strings && config.strings.sendingFailed ) || 'Sending failed.';
						setLiveMessage( live, msg, 'error' );
					} );
			} );
		} );
	}

	function resendRequest( method ) {
		var url = config.ajaxUrl || '/wp-admin/admin-ajax.php';
		var body = new URLSearchParams();
		body.append( 'action', 'reportedip_2fa_resend' );
		body.append( 'method', method );

		if ( typeof fetch !== 'function' ) {
			return Promise.reject( { fallback: true } );
		}

		return fetch( url, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
			body: body.toString(),
		} )
		.then( function ( r ) {
			return r.json().then( function ( j ) { return { status: r.status, json: j }; } );
		} )
		.then( function ( res ) {
			if ( res.json && res.json.success ) {
				return res.json.data || {};
			}
			var err = ( res.json && res.json.data ) || {};
			// 403 = session expired — the user has to restart login.
			if ( res.status === 403 ) {
				err.fallback = false;
				err.message = err.message || ( config.strings && config.strings.sessionExpired ) || 'Your session has expired. Please sign in again.';
			}
			throw err;
		} )
		.catch( function ( err ) {
			// Network-level failure → fall back to the link navigation.
			if ( err && err.message ) { throw err; }
			throw { fallback: true };
		} );
	}

	function showPhaseCode( method, destination ) {
		var panel = document.querySelector( '[data-panel="' + method + '"]' );
		if ( ! panel ) { return; }
		panel.setAttribute( 'data-code-sent', '1' );

		var request = panel.querySelector( '[data-phase="request"]' );
		var code    = panel.querySelector( '[data-phase="code"]' );
		if ( request ) { request.setAttribute( 'hidden', '' ); }
		if ( code ) {
			code.removeAttribute( 'hidden' );
			var input = code.querySelector( 'input[type="text"]' );
			if ( input ) {
				input.value = '';
				window.requestAnimationFrame( function () { input.focus(); } );
			}
			if ( destination ) {
				var el = code.querySelector( method === 'email' ? '[data-destination-email]' : '[data-destination-sms]' );
				if ( el ) { el.textContent = destination; }
			}
		}
	}

	function setLiveMessage( live, message, tone ) {
		if ( ! live ) { return; }
		live.textContent = message || '';
		live.classList.remove( 'rip-2fa-challenge__live--success', 'rip-2fa-challenge__live--error' );
		if ( tone === 'success' ) { live.classList.add( 'rip-2fa-challenge__live--success' ); }
		if ( tone === 'error' )   { live.classList.add( 'rip-2fa-challenge__live--error' ); }
	}

	function runCooldown( btn, seconds ) {
		if ( ! seconds || seconds <= 0 ) {
			btn.disabled = false;
			btn.classList.remove( 'rip-2fa-challenge__resend-link--disabled' );
			return;
		}
		var timerEl  = btn.parentElement ? btn.parentElement.querySelector( '.rip-2fa-challenge__timer' ) : null;
		var remain   = seconds;

		btn.disabled = true;
		btn.classList.add( 'rip-2fa-challenge__resend-link--disabled' );
		if ( timerEl ) {
			timerEl.style.display = 'inline';
			timerEl.textContent = formatTimer( remain );
		}

		var interval = setInterval( function () {
			remain -= 1;
			if ( remain <= 0 ) {
				clearInterval( interval );
				btn.disabled = false;
				btn.classList.remove( 'rip-2fa-challenge__resend-link--disabled' );
				if ( timerEl ) { timerEl.style.display = 'none'; timerEl.textContent = ''; }
			} else if ( timerEl ) {
				timerEl.textContent = formatTimer( remain );
			}
		}, 1000 );
	}

	function formatTimer( seconds ) {
		var m = Math.floor( seconds / 60 );
		var s = seconds % 60;
		return '(' + ( m > 0 ? m + ':' : '' ) + ( s < 10 ? '0' : '' ) + s + ')';
	}

	/* ------------------------------------------------------------------ *
	 * WebAuthn assertion flow.
	 * ------------------------------------------------------------------ */
	function initWebAuthnLogin() {
		var btn = document.getElementById( 'rip-2fa-webauthn-login' );
		if ( ! btn || ! window.PublicKeyCredential || ! navigator.credentials ) { return; }
		var status      = document.getElementById( 'rip-2fa-webauthn-status' );
		var form        = document.getElementById( 'rip-2fa-form' );
		var methodInput = document.getElementById( 'rip-2fa-method-input' );
		var codeInput   = document.getElementById( 'rip-2fa-code-webauthn' );

		btn.addEventListener( 'click', function () {
			if ( status ) { status.textContent = ( config.strings && config.strings.passkeyRequesting ) || 'Passkey request in progress…'; }
			var data = new FormData();
			data.append( 'action', 'reportedip_hive_2fa_webauthn_login_options' );
			fetch( ajaxUrl(), { method: 'POST', body: data, credentials: 'same-origin' } )
				.then( function ( r ) { return r.json(); } )
				.then( function ( res ) {
					if ( ! res || ! res.success ) {
						throw new Error( ( res && res.data && res.data.message ) || ( config.strings && config.strings.passkeyOptionsFailed ) || 'Failed to fetch passkey options.' );
					}
					return navigator.credentials.get( { publicKey: buildAssertionOptions( res.data.publicKey ) } );
				} )
				.then( function ( assertion ) {
					var payload = new FormData();
					payload.append( 'action', 'reportedip_hive_2fa_webauthn_login_verify' );
					payload.append( 'credential', JSON.stringify( serialiseAssertion( assertion ) ) );
					return fetch( ajaxUrl(), { method: 'POST', body: payload, credentials: 'same-origin' } ).then( function ( r ) { return r.json(); } );
				} )
				.then( function ( res ) {
					if ( ! res || ! res.success ) {
						throw new Error( ( res && res.data && res.data.message ) || ( config.strings && config.strings.passkeyVerifyFailed ) || 'Verification failed.' );
					}
					if ( methodInput ) { methodInput.value = 'webauthn'; }
					if ( codeInput ) { codeInput.value = 'webauthn-ok'; }
					if ( form ) { form.submit(); }
				} )
				.catch( function ( err ) {
					if ( status ) { status.textContent = err && err.message ? err.message : ( config.strings && config.strings.passkeyCancelled ) || 'Passkey login cancelled.'; }
				} );
		} );

		function ajaxUrl() {
			return ( config.ajaxUrl || window.ajaxurl || '/wp-admin/admin-ajax.php' );
		}
		function buildAssertionOptions( pk ) {
			return {
				challenge:        b64urlDecode( pk.challenge ),
				rpId:             pk.rpId,
				timeout:          pk.timeout,
				userVerification: pk.userVerification,
				allowCredentials: ( pk.allowCredentials || [] ).map( function ( c ) {
					return { type: 'public-key', id: b64urlDecode( c.id ), transports: c.transports };
				} ),
			};
		}
		function serialiseAssertion( a ) {
			return {
				id:    a.id,
				type:  a.type,
				rawId: b64urlEncode( a.rawId ),
				response: {
					clientDataJSON:    b64urlEncode( a.response.clientDataJSON ),
					authenticatorData: b64urlEncode( a.response.authenticatorData ),
					signature:         b64urlEncode( a.response.signature ),
					userHandle:        a.response.userHandle ? b64urlEncode( a.response.userHandle ) : null,
				},
			};
		}
	}

	function b64urlEncode( buffer ) {
		var bytes = new Uint8Array( buffer );
		var s = '';
		for ( var i = 0; i < bytes.length; i++ ) { s += String.fromCharCode( bytes[ i ] ); }
		return btoa( s ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
	}
	function b64urlDecode( s ) {
		s = s.replace( /-/g, '+' ).replace( /_/g, '/' );
		while ( s.length % 4 ) { s += '='; }
		var bin = atob( s );
		var out = new Uint8Array( bin.length );
		for ( var i = 0; i < bin.length; i++ ) { out[ i ] = bin.charCodeAt( i ); }
		return out.buffer;
	}
} )();
