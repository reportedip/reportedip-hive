/**
 * ReportedIP Hive — Two-Factor Onboarding Wizard.
 *
 * Client-side step navigation + AJAX orchestration for the 5-step onboarding:
 *   1. Welcome  2. Choose method(s)  3. Setup per method  4. Recovery  5. Done
 *
 * Reuses existing AJAX endpoints from class-two-factor-admin.php for TOTP/Email
 * setup and recovery-code generation.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     1.4.0
 */
(function ($, I18N) {
	'use strict';

	if (!I18N) {
		return;
	}

	var state = {
		currentStep: 1,
		selectedMethods: [],
		setupQueue: [],
		setupIndex: -1,
		totpSecret: '',
		recoveryCodes: [],
		confirmedMethods: [],
	};

	function $qs(sel) { return document.querySelector(sel); }
	function $qsa(sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); }

	function setStatus(el, msg, type) {
		if (!el) { return; }
		el.textContent = msg || '';
		el.className = 'rip-2fa-inline-status' + (type ? ' rip-2fa-inline-status--' + type : '');
	}

	var cooldownIntervals = {};

	function startCooldown(btn, seconds, labelTemplate) {
		if (!btn || !labelTemplate) { return; }
		var key = btn.id || ('btn-' + Math.random());
		if (cooldownIntervals[key]) { clearInterval(cooldownIntervals[key]); }
		var defaultLabel = btn.getAttribute('data-default-label') || btn.textContent;
		var remaining = seconds;
		btn.disabled = true;
		btn.dataset.cooldown = '1';
		btn.textContent = labelTemplate.replace('%d', remaining);
		cooldownIntervals[key] = setInterval(function () {
			remaining -= 1;
			if (remaining <= 0) {
				clearInterval(cooldownIntervals[key]);
				delete cooldownIntervals[key];
				delete btn.dataset.cooldown;
				btn.textContent = defaultLabel;
				if (btn.id === 'rip-2fa-sms-send') {
					validatePhoneInput();
				} else {
					btn.disabled = false;
				}
				return;
			}
			btn.textContent = labelTemplate.replace('%d', remaining);
		}, 1000);
	}

	function clearCooldown(btn) {
		if (!btn) { return; }
		var key = btn.id;
		if (cooldownIntervals[key]) {
			clearInterval(cooldownIntervals[key]);
			delete cooldownIntervals[key];
		}
		delete btn.dataset.cooldown;
		var defaultLabel = btn.getAttribute('data-default-label');
		if (defaultLabel) { btn.textContent = defaultLabel; }
	}

	var deliveryIntervals = {};

	function startDeliveryTimer(el, seconds, template) {
		if (!el || !template) { return; }
		var key = el.id || ('el-' + Math.random());
		if (deliveryIntervals[key]) { clearInterval(deliveryIntervals[key]); }
		el.hidden = false;
		var remaining = seconds;
		el.textContent = template.replace('%d', remaining);
		deliveryIntervals[key] = setInterval(function () {
			remaining -= 1;
			if (remaining <= 0) {
				clearInterval(deliveryIntervals[key]);
				delete deliveryIntervals[key];
				el.hidden = true;
				el.textContent = '';
				return;
			}
			el.textContent = template.replace('%d', remaining);
		}, 1000);
	}

	function clearDeliveryTimer(el) {
		if (!el) { return; }
		var key = el.id;
		if (deliveryIntervals[key]) {
			clearInterval(deliveryIntervals[key]);
			delete deliveryIntervals[key];
		}
		el.hidden = true;
		el.textContent = '';
	}

	var PHONE_E164 = /^\+[1-9]\d{6,14}$/;

	function validatePhoneInput() {
		var input   = $qs('#rip-2fa-sms-number');
		var btn     = $qs('#rip-2fa-sms-send');
		var consent = !!($qs('#rip-2fa-sms-consent') || {}).checked;
		if (!input) { return false; }
		var wrap = (input.parentNode && input.parentNode.classList && input.parentNode.classList.contains('rip-input-wrap'))
			? input.parentNode : null;
		var indic = wrap ? wrap.querySelector('.rip-input-validity') : null;
		var raw   = (input.value || '').replace(/[\s().\-\/]/g, '');
		var hasInput = raw.length > 0;
		var valid    = PHONE_E164.test(raw);
		if (wrap) {
			wrap.classList.toggle('rip-input-wrap--valid',   valid && hasInput);
			wrap.classList.toggle('rip-input-wrap--invalid', !valid && hasInput);
		}
		if (indic) { indic.textContent = !hasInput ? '' : (valid ? '\u2713' : '\u2715'); }
		if (btn && !btn.dataset.cooldown) { btn.disabled = !(valid && consent); }
		return valid;
	}

	function goToStep(n) {
		state.currentStep = n;
		$qsa('.rip-2fa-step').forEach(function (el) {
			var step = parseInt(el.getAttribute('data-step'), 10);
			el.hidden = step !== n;
		});
		$qsa('.rip-wizard__step').forEach(function (el) {
			var step = parseInt(el.getAttribute('data-step'), 10);
			el.classList.toggle('rip-wizard__step--active', step === n);
			el.classList.toggle('rip-wizard__step--completed', step < n);
		});
		window.scrollTo({ top: 0, behavior: 'smooth' });
	}

	// ---------- Step 1 → 2 navigation ----------
	$qsa('[data-goto-step]').forEach(function (btn) {
		btn.addEventListener('click', function () {
			var target = parseInt(btn.getAttribute('data-goto-step'), 10);
			if (!isNaN(target)) { goToStep(target); }
		});
	});

	// ---------- Step 2: method selection ----------
	$qsa('.rip-2fa-methods .rip-mode-card').forEach(function (card) {
		card.addEventListener('click', function (e) {
			e.preventDefault();
			var method = card.getAttribute('data-method');
			var cb = card.querySelector('.rip-2fa-method-check');
			if (!cb) { return; }
			cb.checked = !cb.checked;
			card.classList.toggle('rip-mode-card--selected', cb.checked);

			var selected = $qsa('.rip-2fa-method-check:checked').map(function (c) { return c.value; });
			state.selectedMethods = selected;
			var continueBtn = $qs('#rip-2fa-methods-continue');
			if (continueBtn) { continueBtn.disabled = selected.length === 0; }
		});
	});

	$(document).on('click', '#rip-2fa-methods-continue', function () {
		if (state.selectedMethods.length === 0) { return; }
		state.setupQueue = state.selectedMethods.slice();
		state.setupIndex = -1;
		state.confirmedMethods = [];
		// Reset the done-panel + titles so a second run doesn't display stale success.
		var doneBox = $qs('#rip-2fa-setup-done');
		if (doneBox) { doneBox.hidden = true; }
		var t = document.querySelector('.rip-2fa-step[data-step="3"] .rip-wizard__title');
		var s = document.querySelector('.rip-2fa-step[data-step="3"] .rip-wizard__subtitle');
		if (t && t.dataset.defaultTitle) { t.textContent = t.dataset.defaultTitle; }
		if (s && s.dataset.defaultSubtitle) { s.textContent = s.dataset.defaultSubtitle; }
		var cont = $qs('#rip-2fa-setup-continue');
		if (cont) { cont.disabled = true; }
		advanceSetup();
		goToStep(3);
	});

	// ---------- Step 3: setup orchestration ----------
	function advanceSetup() {
		$qsa('.rip-2fa-setup-panel').forEach(function (p) { p.hidden = true; });
		state.setupIndex += 1;

		if (state.setupIndex >= state.setupQueue.length) {
			showSetupDone();
			return;
		}

		var method = state.setupQueue[state.setupIndex];
		var panel = document.querySelector('[data-method-panel="' + method + '"]');
		if (panel) {
			panel.hidden = false;
		}

		if (method === 'totp') { startTotpSetup(); }
		else if (method === 'email') { resetEmailPanel(); }
		else if (method === 'webauthn') { startWebAuthnSetup(); }
		else if (method === 'sms') { resetSmsPanel(); }
	}

	function showSetupDone() {
		var title = document.querySelector('.rip-2fa-step[data-step="3"] .rip-wizard__title');
		var sub   = document.querySelector('.rip-2fa-step[data-step="3"] .rip-wizard__subtitle');
		var done  = $qs('#rip-2fa-setup-done');
		var list  = $qs('#rip-2fa-setup-done-methods');

		if (title && title.dataset.doneTitle) { title.textContent = title.dataset.doneTitle; }
		if (sub && sub.dataset.doneSubtitle) { sub.textContent = sub.dataset.doneSubtitle; }
		if (done) { done.hidden = false; }
		if (list) {
			var labels = state.confirmedMethods.map(function (m) {
				return ({
					totp:     I18N.strings.methodTotp     || 'Authenticator app',
					email:    I18N.strings.methodEmail    || 'Email code',
					webauthn: I18N.strings.methodWebauthn || 'Passkey',
					sms:      I18N.strings.methodSms      || 'SMS'
				})[m] || m.toUpperCase();
			});
			list.textContent = labels.length ? ('✓ ' + labels.join('  ·  ✓ ')) : '';
		}

		var cont = $qs('#rip-2fa-setup-continue');
		if (cont) { cont.disabled = false; cont.focus(); }
	}

	// ===== TOTP =====
	function startTotpSetup() {
		setStatus($qs('#rip-2fa-totp-status'), I18N.strings.sending);
		$.post(I18N.ajaxUrl, {
			action: 'reportedip_hive_2fa_setup_totp',
			nonce: I18N.nonce,
			user_id: I18N.userId,
		}).done(function (res) {
			if (!res || !res.success) {
				setStatus($qs('#rip-2fa-totp-status'), (res && res.data && res.data.message) || I18N.strings.networkError, 'error');
				return;
			}
			state.totpSecret = res.data.secret || '';
			var qrUri = res.data.uri || res.data.qr_uri || '';
			var secretInput = $qs('#rip-2fa-secret-display');
			if (secretInput) { secretInput.value = state.totpSecret; }
			renderQR(qrUri);
			setStatus($qs('#rip-2fa-totp-status'), '');
		}).fail(function () {
			setStatus($qs('#rip-2fa-totp-status'), I18N.strings.networkError, 'error');
		});
	}

	function renderQR(uri) {
		var target = $qs('#rip-2fa-qr-canvas');
		if (!target || !uri) { return; }
		target.innerHTML = '';

		// Primary: qrcode-generator@1.4.x (global `qrcode()` factory).
		if (typeof qrcode === 'function') {
			var qr = qrcode(0, 'M');
			qr.addData(uri);
			qr.make();
			target.innerHTML = qr.createSvgTag(5, 0);
			return;
		}

		// Fallback: davidshimjs-qrcodejs (`new QRCode(el, opts)`).
		if (typeof QRCode !== 'undefined') {
			/* eslint-disable no-new */
			new QRCode(target, { text: uri, width: 220, height: 220, correctLevel: QRCode.CorrectLevel.M });
			return;
		}

		target.innerHTML = '<div class="rip-alert rip-alert--error">' + ( I18N.strings.qrLibMissing || 'QR code library is missing. Please reload the page.' ) + '</div>';
	}

	$(document).on('click', '#rip-2fa-secret-copy', function () {
		var val = ($qs('#rip-2fa-secret-display') || {}).value || '';
		copyToClipboard(val);
		this.textContent = I18N.strings.copied;
	});

	$(document).on('click', '#rip-2fa-totp-confirm', function () {
		var code = (($qs('#rip-2fa-totp-verify') || {}).value || '').replace(/\D/g, '');
		if (code.length !== 6) { return; }
		setStatus($qs('#rip-2fa-totp-status'), I18N.strings.verifying);
		$.post(I18N.ajaxUrl, {
			action: 'reportedip_hive_2fa_confirm_totp',
			nonce: I18N.nonce,
			user_id: I18N.userId,
			code: code,
		}).done(function (res) {
			if (res && res.success) {
				state.confirmedMethods.push('totp');
				setStatus($qs('#rip-2fa-totp-status'), res.data && res.data.message, 'success');
				setTimeout(advanceSetup, 600);
			} else {
				setStatus($qs('#rip-2fa-totp-status'), (res && res.data && res.data.message) || I18N.strings.invalid, 'error');
			}
		}).fail(function () {
			setStatus($qs('#rip-2fa-totp-status'), I18N.strings.networkError, 'error');
		});
	});

	// ===== Email =====
	function resetEmailPanel() {
		setStatus($qs('#rip-2fa-email-send-status'), '');
		setStatus($qs('#rip-2fa-email-verify-status'), '');
		var inp = $qs('#rip-2fa-email-verify');
		if (inp) { inp.value = ''; }
		clearCooldown($qs('#rip-2fa-email-send'));
	}

	$(document).on('click', '#rip-2fa-email-send', function () {
		var btn = this;
		if (btn.dataset.cooldown) { return; }
		setStatus($qs('#rip-2fa-email-send-status'), I18N.strings.sending);
		$.post(I18N.ajaxUrl, {
			action: 'reportedip_hive_2fa_setup_email',
			nonce: I18N.nonce,
			user_id: I18N.userId,
			step: 'send',
		}).done(function (res) {
			if (res && res.success) {
				setStatus($qs('#rip-2fa-email-send-status'), res.data && res.data.message || I18N.strings.sent, 'success');
				startCooldown(btn, 60, I18N.strings.resendIn);
			} else {
				setStatus($qs('#rip-2fa-email-send-status'), (res && res.data && res.data.message) || I18N.strings.networkError, 'error');
			}
		}).fail(function () {
			setStatus($qs('#rip-2fa-email-send-status'), I18N.strings.networkError, 'error');
		});
	});

	$(document).on('click', '#rip-2fa-email-confirm', function () {
		var code = (($qs('#rip-2fa-email-verify') || {}).value || '').replace(/\D/g, '');
		if (code.length !== 6) { return; }
		setStatus($qs('#rip-2fa-email-verify-status'), I18N.strings.verifying);
		$.post(I18N.ajaxUrl, {
			action: 'reportedip_hive_2fa_setup_email',
			nonce: I18N.nonce,
			user_id: I18N.userId,
			step: 'verify',
			code: code,
		}).done(function (res) {
			if (res && res.success) {
				state.confirmedMethods.push('email');
				setStatus($qs('#rip-2fa-email-verify-status'), res.data && res.data.message, 'success');
				setTimeout(advanceSetup, 600);
			} else {
				setStatus($qs('#rip-2fa-email-verify-status'), (res && res.data && res.data.message) || I18N.strings.invalid, 'error');
			}
		}).fail(function () {
			setStatus($qs('#rip-2fa-email-verify-status'), I18N.strings.networkError, 'error');
		});
	});

	// WebAuthn / Passkey — full registration ceremony against the server class.
	function startWebAuthnSetup() {
		var status = $qs('#rip-2fa-webauthn-status');
		if (!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create)) {
			if (status) { status.textContent = I18N.strings.passkeyUnsupport; status.className = 'rip-2fa-inline-status rip-2fa-inline-status--error'; }
			return;
		}
		if (status) { status.textContent = ''; }
	}

	$(document).on('click', '#rip-2fa-webauthn-register', function () {
		var status = $qs('#rip-2fa-webauthn-status');
		if (!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create)) {
			if (status) { status.textContent = I18N.strings.passkeyUnsupport; status.className = 'rip-2fa-inline-status rip-2fa-inline-status--error'; }
			return;
		}
		if (status) { status.textContent = I18N.strings.passkeyCreating || 'Creating passkey…'; status.className = 'rip-2fa-inline-status'; }

		$.post(I18N.ajaxUrl, {
			action: 'reportedip_hive_2fa_webauthn_register_options',
			nonce: I18N.nonce,
			user_id: I18N.userId,
		}).done(function (res) {
			if (!res || !res.success) {
				if (status) { status.textContent = (res && res.data && res.data.message) || I18N.strings.networkError; status.className = 'rip-2fa-inline-status rip-2fa-inline-status--error'; }
				return;
			}
			var pk = res.data.publicKey;
			var opts = {
				challenge: b64urlDecode(pk.challenge),
				rp:        pk.rp,
				user:      { id: b64urlDecode(pk.user.id), name: pk.user.name, displayName: pk.user.displayName },
				pubKeyCredParams: pk.pubKeyCredParams,
				authenticatorSelection: pk.authenticatorSelection,
				timeout:   pk.timeout,
				attestation: pk.attestation,
				excludeCredentials: (pk.excludeCredentials || []).map(function (c) { return { type: c.type, id: b64urlDecode(c.id), transports: c.transports }; }),
			};
			navigator.credentials.create({ publicKey: opts })
				.then(function (cred) {
					var payload = {
						id:    cred.id,
						type:  cred.type,
						rawId: b64urlEncode(cred.rawId),
						response: {
							clientDataJSON:    b64urlEncode(cred.response.clientDataJSON),
							attestationObject: b64urlEncode(cred.response.attestationObject),
						},
						transports: cred.response.getTransports ? cred.response.getTransports() : [],
					};
					return $.post(I18N.ajaxUrl, {
						action: 'reportedip_hive_2fa_webauthn_register_verify',
						nonce: I18N.nonce,
						user_id: I18N.userId,
						credential: JSON.stringify(payload),
						name: 'Passkey',
					});
				})
				.then(function (res2) {
					if (res2 && res2.success) {
						state.confirmedMethods.push('webauthn');
						if (status) { status.textContent = res2.data && res2.data.message || 'OK'; status.className = 'rip-2fa-inline-status rip-2fa-inline-status--success'; }
						setTimeout(advanceSetup, 600);
					} else {
						if (status) { status.textContent = (res2 && res2.data && res2.data.message) || I18N.strings.invalid; status.className = 'rip-2fa-inline-status rip-2fa-inline-status--error'; }
					}
				})
				.catch(function (err) {
					// InvalidStateError = user's authenticator already holds a
					// credential for this RP. Treat as "already set up" — not a
					// real error — and move on so the user isn't stuck.
					if (err && (err.name === 'InvalidStateError' || (err.message || '').indexOf('already registered') !== -1)) {
						if (state.confirmedMethods.indexOf('webauthn') === -1) { state.confirmedMethods.push('webauthn'); }
						if (status) {
							status.textContent = I18N.strings.passkeyDuplicate || 'This passkey is already registered on your account. You can continue with the next method.';
							status.className = 'rip-2fa-inline-status rip-2fa-inline-status--success';
						}
						setTimeout(advanceSetup, 1200);
						return;
					}
					// NotAllowedError = user rejected/cancelled the browser dialog.
					var friendly = (err && err.name === 'NotAllowedError')
						? (I18N.strings.passkeyCancelled || 'Passkey creation was cancelled. You can try again or choose another method.')
						: ((err && err.message) ? err.message : 'Passkey creation failed.');
					if (status) { status.textContent = friendly; status.className = 'rip-2fa-inline-status rip-2fa-inline-status--error'; }
				});
		}).fail(function () {
			if (status) { status.textContent = I18N.strings.networkError; status.className = 'rip-2fa-inline-status rip-2fa-inline-status--error'; }
		});
	});

	function b64urlEncode(buffer) {
		var bytes = new Uint8Array(buffer);
		var s = '';
		for (var i = 0; i < bytes.length; i++) { s += String.fromCharCode(bytes[i]); }
		return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	}
	function b64urlDecode(s) {
		s = s.replace(/-/g, '+').replace(/_/g, '/');
		while (s.length % 4) { s += '='; }
		var bin = atob(s);
		var out = new Uint8Array(bin.length);
		for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
		return out.buffer;
	}

	// SMS setup — two-step (register phone + dispatch code → verify submitted code).
	function resetSmsPanel() {
		setStatus($qs('#rip-2fa-sms-status'), '');
		setStatus($qs('#rip-2fa-sms-send-status'), '');
		var n = $qs('#rip-2fa-sms-number'); if (n) { n.value = ''; }
		var c = $qs('#rip-2fa-sms-consent'); if (c) { c.checked = false; }
		var v = $qs('#rip-2fa-sms-verify'); if (v) { v.value = ''; }
		var wrap = n && n.parentNode && n.parentNode.classList && n.parentNode.classList.contains('rip-input-wrap')
			? n.parentNode : null;
		if (wrap) {
			wrap.classList.remove('rip-input-wrap--valid', 'rip-input-wrap--invalid');
			var indic = wrap.querySelector('.rip-input-validity');
			if (indic) { indic.textContent = ''; }
		}
		clearCooldown($qs('#rip-2fa-sms-send'));
		clearDeliveryTimer($qs('#rip-2fa-sms-delivery-timer'));
		var btn = $qs('#rip-2fa-sms-send');
		if (btn) { btn.disabled = true; }
	}

	$(document).on('input',  '#rip-2fa-sms-number',  validatePhoneInput);
	$(document).on('change', '#rip-2fa-sms-consent', validatePhoneInput);

	$(document).on('click', '#rip-2fa-sms-send', function () {
		var btn = this;
		if (btn.dataset.cooldown) { return; }
		if (!validatePhoneInput()) { return; }
		var consent = !!($qs('#rip-2fa-sms-consent') || {}).checked;
		if (!consent) { return; }
		var phone = (($qs('#rip-2fa-sms-number') || {}).value || '').replace(/[\s().\-\/]/g, '');

		setStatus($qs('#rip-2fa-sms-send-status'), I18N.strings.sending);
		$.post(I18N.ajaxUrl, {
			action: 'reportedip_hive_2fa_setup_sms',
			nonce: I18N.nonce,
			user_id: I18N.userId,
			step: 'register',
			phone: phone,
			consent: '1',
		}).done(function (res) {
			if (res && res.success) {
				setStatus($qs('#rip-2fa-sms-send-status'), (res.data && res.data.message) || I18N.strings.sent, 'success');
				startCooldown(btn, 60, I18N.strings.resendIn);
				startDeliveryTimer($qs('#rip-2fa-sms-delivery-timer'), 60, I18N.strings.smsDeliveryWait);
			} else {
				setStatus($qs('#rip-2fa-sms-send-status'), (res && res.data && res.data.message) || I18N.strings.networkError, 'error');
			}
		}).fail(function () {
			setStatus($qs('#rip-2fa-sms-send-status'), I18N.strings.networkError, 'error');
		});
	});

	$(document).on('click', '#rip-2fa-sms-confirm', function () {
		var code = (($qs('#rip-2fa-sms-verify') || {}).value || '').replace(/\D/g, '');
		if (code.length !== 6) { return; }
		setStatus($qs('#rip-2fa-sms-status'), I18N.strings.verifying);
		$.post(I18N.ajaxUrl, {
			action: 'reportedip_hive_2fa_setup_sms',
			nonce: I18N.nonce,
			user_id: I18N.userId,
			step: 'verify',
			code: code,
		}).done(function (res) {
			if (res && res.success) {
				state.confirmedMethods.push('sms');
				setStatus($qs('#rip-2fa-sms-status'), (res.data && res.data.message) || '', 'success');
				setTimeout(advanceSetup, 600);
			} else {
				setStatus($qs('#rip-2fa-sms-status'), (res && res.data && res.data.message) || I18N.strings.invalid, 'error');
			}
		}).fail(function () {
			setStatus($qs('#rip-2fa-sms-status'), I18N.strings.networkError, 'error');
		});
	});

	// ---------- Step 3 → 4 ----------
	$(document).on('click', '#rip-2fa-setup-continue', function () {
		loadRecoveryCodes();
		goToStep(4);
	});

	// ---------- Step 4: recovery codes ----------
	function loadRecoveryCodes() {
		var grid = $qs('#rip-2fa-recovery-codes');
		if (!grid) { return; }
		grid.innerHTML = '<p>' + I18N.strings.sending + '</p>';
		$.post(I18N.ajaxUrl, {
			action: 'reportedip_hive_2fa_regenerate_recovery',
			nonce: I18N.nonce,
			user_id: I18N.userId,
		}).done(function (res) {
			if (res && res.success && res.data && res.data.codes) {
				state.recoveryCodes = res.data.codes;
				renderRecoveryCodes(state.recoveryCodes);
			} else {
				var errMsg = (res && res.data && res.data.message) || I18N.strings.networkError;
				var errP = document.createElement('p');
				errP.className = 'rip-alert rip-alert--error';
				errP.textContent = errMsg;
				grid.innerHTML = '';
				grid.appendChild(errP);
			}
		}).fail(function () {
			grid.innerHTML = '<p class="rip-alert rip-alert--error">' + I18N.strings.networkError + '</p>';
		});
	}

	function renderRecoveryCodes(codes) {
		var grid = $qs('#rip-2fa-recovery-codes');
		if (!grid) { return; }
		grid.innerHTML = '';
		codes.forEach(function (code) {
			var div = document.createElement('code');
			div.className = 'rip-2fa-recovery-code';
			div.textContent = code;
			grid.appendChild(div);
		});
	}

	$(document).on('click', '#rip-2fa-recovery-copy', function () {
		copyToClipboard(state.recoveryCodes.join('\n'));
		flashButton(this, I18N.strings.copied);
	});

	$(document).on('click', '#rip-2fa-recovery-download', function () {
		var blob = new Blob([state.recoveryCodes.join('\n')], { type: 'text/plain' });
		var a = document.createElement('a');
		a.href = URL.createObjectURL(blob);
		a.download = 'reportedip-recovery-codes.txt';
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		flashButton(this, (I18N.strings.downloaded || 'Downloaded') + ' ✓');
	});

	function flashButton(btn, tempText) {
		var icon = btn.querySelector('svg');
		var original = icon ? btn.innerHTML : btn.textContent;
		btn.textContent = tempText;
		btn.classList.add('rip-button--success');
		setTimeout(function () {
			if (icon) { btn.innerHTML = original; }
			else { btn.textContent = original; }
			btn.classList.remove('rip-button--success');
		}, 1500);
	}

	$(document).on('click', '#rip-2fa-recovery-print', function () {
		var w = window.open('', 'RecoveryCodes', 'width=600,height=600');
		if (!w) { return; }
		w.document.write('<html><head><title>Recovery Codes</title></head><body><h1>ReportedIP Recovery Codes</h1><pre style="font-size:16px">' + state.recoveryCodes.join('\n') + '</pre></body></html>');
		w.document.close();
		w.print();
	});

	$(document).on('change', '#rip-2fa-recovery-acknowledged', function () {
		var btn = $qs('#rip-2fa-recovery-continue');
		if (btn) { btn.disabled = !this.checked; }
	});

	$(document).on('click', '#rip-2fa-recovery-continue', function () {
		var methods = $qs('#rip-2fa-summary-methods');
		var recovery = $qs('#rip-2fa-summary-recovery');
		if (methods) { methods.textContent = state.confirmedMethods.join(', ').toUpperCase() || '—'; }
		if (recovery) { recovery.textContent = state.recoveryCodes.length + ' Codes'; }
		goToStep(5);
	});

	// ---------- Skip button ----------
	$(document).on('click', '#rip-2fa-skip', function (e) {
		e.preventDefault();
		var confirmMsg = this.getAttribute('data-confirm') || I18N.strings.confirmSkip;
		if (!window.confirm(confirmMsg)) { return; }
		$.post(I18N.ajaxUrl, {
			action: 'reportedip_hive_2fa_onboarding_skip',
			nonce: I18N.nonce,
			redirect_to: I18N.dashboardUrl,
		}).done(function (res) {
			if (res && res.success && res.data && res.data.redirect) {
				window.location.href = res.data.redirect;
			} else if (res && res.data && res.data.message) {
				alert(res.data.message);
			}
		}).fail(function () {
			window.location.href = I18N.dashboardUrl;
		});
	});

	// ---------- Helpers ----------
	function copyToClipboard(text) {
		if (navigator.clipboard && navigator.clipboard.writeText) {
			navigator.clipboard.writeText(text);
			return;
		}
		var ta = document.createElement('textarea');
		ta.value = text;
		ta.style.position = 'fixed';
		ta.style.opacity = '0';
		document.body.appendChild(ta);
		ta.select();
		try { document.execCommand('copy'); } catch (e) { /* noop */ }
		document.body.removeChild(ta);
	}

	// Auto-submit on 6-digit code inputs.
	$(document).on('input', '.rip-2fa-code-input', function () {
		var cleaned = this.value.replace(/\D/g, '').slice(0, 6);
		if (cleaned !== this.value) { this.value = cleaned; }
	});

})(jQuery, window.reportedip2faOnboarding);
