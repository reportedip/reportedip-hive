/**
 * ReportedIP Hive — Security-key / passkey manager.
 *
 * Drives the key-manager card (templates/partials/webauthn-key-manager.php):
 *   – lists the user's WebAuthn credentials via AJAX
 *   – inline rename and per-key delete (with last-key confirmation)
 *   – "add key" flow: name prompt first, then the registration ceremony
 *     with an authenticator hint (security-key vs. platform)
 *
 * Config arrives via wp_localize_script as `reportedip2faKeys`:
 *   { ajaxUrl, nonce, userId, strings: {…} }
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     2.1.34
 */

( function () {
	'use strict';

	var config = ( typeof reportedip2faKeys !== 'undefined' ) ? reportedip2faKeys : {};

	var ICONS = {
		key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" aria-hidden="true"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
		device: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" aria-hidden="true"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>',
	};

	document.addEventListener( 'DOMContentLoaded', function () {
		var root = document.getElementById( 'rip-webauthn-key-manager' );
		if ( ! root ) { return; }
		initKeyManager( root );
	} );

	function str( key, fallback ) {
		return ( config.strings && config.strings[ key ] ) || fallback;
	}

	function post( action, fields ) {
		var body = new FormData();
		body.append( 'action', action );
		body.append( 'nonce', config.nonce || '' );
		body.append( 'user_id', config.userId || '' );
		Object.keys( fields || {} ).forEach( function ( k ) {
			body.append( k, fields[ k ] );
		} );
		return fetch( config.ajaxUrl || window.ajaxurl || '/wp-admin/admin-ajax.php', {
			method: 'POST',
			body: body,
			credentials: 'same-origin',
		} ).then( function ( r ) { return r.json(); } );
	}

	function initKeyManager( root ) {
		var table       = document.getElementById( 'rip-webauthn-keys-table' );
		var tbody       = table ? table.querySelector( 'tbody' ) : null;
		var empty       = document.getElementById( 'rip-webauthn-keys-empty' );
		var status      = document.getElementById( 'rip-webauthn-keys-status' );
		var addToggle   = document.getElementById( 'rip-webauthn-add-toggle' );
		var addForm     = document.getElementById( 'rip-webauthn-add-form' );
		var addStatus   = document.getElementById( 'rip-webauthn-add-status' );
		var nameInput   = document.getElementById( 'rip-webauthn-key-name' );
		var upgradeNote = document.getElementById( 'rip-webauthn-upgrade-note' );
		var advanced    = root.getAttribute( 'data-advanced' ) === '1';

		if ( ! tbody ) { return; }

		function setStatus( el, message, tone ) {
			if ( ! el ) { return; }
			el.textContent = message || '';
			el.className = 'rip-2fa-inline-status' + ( tone ? ' rip-2fa-inline-status--' + tone : '' );
		}

		function render( keys ) {
			tbody.innerHTML = '';
			var hasKeys = keys && keys.length > 0;
			if ( table ) { table.hidden = ! hasKeys; }
			if ( empty ) { empty.hidden = hasKeys; }

			// Free tier: the first key is included, more keys are Business.
			var canAdd = advanced || ! hasKeys;
			if ( addToggle ) { addToggle.hidden = ! canAdd; }
			if ( ! canAdd && addForm ) { addForm.hidden = true; }
			if ( upgradeNote ) { upgradeNote.hidden = canAdd; }

			if ( ! hasKeys ) { return; }

			keys.forEach( function ( key ) {
				var tr = document.createElement( 'tr' );
				tr.setAttribute( 'data-credential-id', key.id );

				var isRoaming = key.icon
					? key.icon === 'key'
					: ( key.transports || [] ).some( function ( t ) {
						return t === 'usb' || t === 'nfc' || t === 'ble' || t === 'smart-card';
					} );

				tr.appendChild( nameCell( key ) );
				tr.appendChild( cellHtml(
					( isRoaming ? ICONS.key : ICONS.device )
					+ '<span class="rip-webauthn-keys__type-label">'
					+ escapeHtml( isRoaming ? str( 'typeSecurityKey', 'Security key' ) : str( 'typePasskey', 'Passkey' ) )
					+ '</span>'
				) );
				tr.appendChild( cellText( key.created_at || '' ) );
				tr.appendChild( cellText( key.last_used || str( 'never', 'Never' ) ) );
				tr.appendChild( actionsCell( key ) );
				tbody.appendChild( tr );
			} );
		}

		function cellText( text ) {
			var td = document.createElement( 'td' );
			td.textContent = text;
			return td;
		}

		function cellHtml( html ) {
			var td = document.createElement( 'td' );
			td.className = 'rip-webauthn-keys__type';
			td.innerHTML = html;
			return td;
		}

		function nameCell( key ) {
			var td   = document.createElement( 'td' );
			var span = document.createElement( 'span' );
			span.className   = 'rip-webauthn-keys__name';
			span.textContent = key.name;
			td.appendChild( span );
			if ( key.model ) {
				var model = document.createElement( 'span' );
				model.className   = 'rip-webauthn-keys__model';
				model.textContent = key.model;
				td.appendChild( model );
			}
			return td;
		}

		function actionsCell( key ) {
			var td = document.createElement( 'td' );
			td.className = 'rip-webauthn-keys__actions';

			var rename = document.createElement( 'button' );
			rename.type = 'button';
			rename.className = 'rip-button rip-button--ghost rip-button--sm';
			rename.textContent = str( 'rename', 'Rename' );
			rename.addEventListener( 'click', function () { startRename( td.parentElement, key ); } );

			var remove = document.createElement( 'button' );
			remove.type = 'button';
			remove.className = 'rip-button rip-button--danger rip-button--sm';
			remove.textContent = str( 'remove', 'Remove' );
			remove.addEventListener( 'click', function () { deleteKey( key ); } );

			td.appendChild( rename );
			td.appendChild( remove );
			return td;
		}

		function startRename( tr, key ) {
			var cell = tr.querySelector( 'td' );
			cell.innerHTML = '';

			var input = document.createElement( 'input' );
			input.type = 'text';
			input.className = 'rip-input rip-webauthn-keys__rename-input';
			input.maxLength = 64;
			input.value = key.name;

			var save = document.createElement( 'button' );
			save.type = 'button';
			save.className = 'rip-button rip-button--primary rip-button--sm';
			save.textContent = str( 'save', 'Save' );
			save.addEventListener( 'click', function () {
				var name = input.value.trim();
				if ( ! name ) { return; }
				post( 'reportedip_hive_2fa_webauthn_rename_key', { credential_id: key.id, name: name } )
					.then( function ( res ) {
						if ( res && res.success ) {
							render( res.data.keys || [] );
							setStatus( status, str( 'renamed', 'Key renamed.' ), 'success' );
						} else {
							setStatus( status, ( res && res.data && res.data.message ) || str( 'error', 'Something went wrong.' ), 'error' );
						}
					} )
					.catch( function () { setStatus( status, str( 'networkError', 'Network error.' ), 'error' ); } );
			} );

			input.addEventListener( 'keydown', function ( e ) {
				if ( e.key === 'Enter' ) { e.preventDefault(); save.click(); }
				if ( e.key === 'Escape' ) { load(); }
			} );

			cell.appendChild( input );
			cell.appendChild( save );
			input.focus();
			input.select();
		}

		function deleteKey( key ) {
			if ( ! window.confirm( str( 'confirmRemove', 'Remove this security key? You will no longer be able to sign in with it.' ) ) ) {
				return;
			}
			post( 'reportedip_hive_2fa_webauthn_delete_key', { credential_id: key.id } )
				.then( function ( res ) {
					if ( res && res.success ) {
						render( res.data.keys || [] );
						setStatus(
							status,
							res.data.method_disabled
								? str( 'methodDisabled', 'Last key removed — the passkey method is now disabled for this account.' )
								: str( 'removed', 'Key removed.' ),
							'success'
						);
					} else {
						setStatus( status, ( res && res.data && res.data.message ) || str( 'error', 'Something went wrong.' ), 'error' );
					}
				} )
				.catch( function () { setStatus( status, str( 'networkError', 'Network error.' ), 'error' ); } );
		}

		function load() {
			post( 'reportedip_hive_2fa_webauthn_list_keys', {} )
				.then( function ( res ) {
					if ( res && res.success ) { render( res.data.keys || [] ); }
				} )
				.catch( function () { setStatus( status, str( 'networkError', 'Network error.' ), 'error' ); } );
		}

		if ( addToggle && addForm ) {
			addToggle.addEventListener( 'click', function () {
				addForm.hidden = ! addForm.hidden;
				if ( ! addForm.hidden && nameInput ) { nameInput.focus(); }
			} );
		}

		// A touched YubiKey with no active WebAuthn dialog "types" its Yubico
		// OTP (ModHex) into the focused field. Catch it on the name input,
		// clear it and explain instead of letting it look like a broken key.
		if ( nameInput ) {
			nameInput.addEventListener( 'input', function () {
				if ( this.value.length >= 32 && /[cbdefghijklnrtuv]{32,64}$/.test( this.value.trim() ) ) {
					this.value = '';
					setStatus( addStatus, str( 'otpDetected', 'That was the key\'s one-time password — touch the key only when the browser asks for it.' ), 'error' );
				}
			} );
		}

		Array.prototype.forEach.call( document.querySelectorAll( '.rip-webauthn-add-run' ), function ( btn ) {
			btn.addEventListener( 'click', function () {
				registerKey( btn.getAttribute( 'data-hint' ) || '' );
			} );
		} );

		function registerKey( hint ) {
			if ( ! ( window.PublicKeyCredential && navigator.credentials && navigator.credentials.create ) ) {
				setStatus( addStatus, str( 'unsupported', 'This browser does not support security keys.' ), 'error' );
				return;
			}
			var name = ( nameInput && nameInput.value.trim() )
				|| ( hint === 'client-device' ? str( 'defaultPasskeyName', 'This device' ) : str( 'defaultKeyName', 'Security key' ) );

			setStatus( addStatus, str( 'waitingForKey', 'Waiting for your security key — insert and touch it now.' ) );

			post( 'reportedip_hive_2fa_webauthn_register_options', { hint: hint } )
				.then( function ( res ) {
					if ( ! res || ! res.success ) {
						throw new Error( ( res && res.data && res.data.message ) || str( 'error', 'Something went wrong.' ) );
					}
					var pk = res.data.publicKey;
					return navigator.credentials.create( { publicKey: {
						challenge: b64urlDecode( pk.challenge ),
						rp: pk.rp,
						user: { id: b64urlDecode( pk.user.id ), name: pk.user.name, displayName: pk.user.displayName },
						pubKeyCredParams: pk.pubKeyCredParams,
						authenticatorSelection: pk.authenticatorSelection,
						hints: pk.hints && pk.hints.length ? pk.hints : undefined,
						timeout: pk.timeout,
						attestation: pk.attestation,
						excludeCredentials: ( pk.excludeCredentials || [] ).map( function ( c ) {
							return { type: c.type, id: b64urlDecode( c.id ), transports: c.transports };
						} ),
					} } );
				} )
				.then( function ( cred ) {
					var payload = {
						id: cred.id,
						type: cred.type,
						rawId: b64urlEncode( cred.rawId ),
						response: {
							clientDataJSON: b64urlEncode( cred.response.clientDataJSON ),
							attestationObject: b64urlEncode( cred.response.attestationObject ),
						},
						transports: cred.response.getTransports ? cred.response.getTransports() : [],
					};
					return post( 'reportedip_hive_2fa_webauthn_register_verify', {
						credential: JSON.stringify( payload ),
						name: name,
					} );
				} )
				.then( function ( res ) {
					if ( res && res.success ) {
						setStatus( addStatus, res.data && res.data.message, 'success' );
						if ( nameInput ) { nameInput.value = ''; }
						if ( addForm ) { addForm.hidden = true; }
						load();
					} else {
						setStatus( addStatus, ( res && res.data && res.data.message ) || str( 'error', 'Something went wrong.' ), 'error' );
					}
				} )
				.catch( function ( err ) {
					var message;
					if ( err && err.name === 'InvalidStateError' ) {
						message = str( 'alreadyRegistered', 'This key is already registered on this account.' );
					} else if ( err && err.name === 'NotAllowedError' ) {
						message = str( 'cancelled', 'The request timed out or was cancelled. Insert your key and touch it — on a phone, hold it against the back (NFC).' );
					} else {
						message = ( err && err.message ) || str( 'error', 'Something went wrong.' );
					}
					setStatus( addStatus, message, 'error' );
				} );
		}

		load();
	}

	function escapeHtml( s ) {
		return String( s ).replace( /[&<>"']/g, function ( c ) {
			return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ c ];
		} );
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
