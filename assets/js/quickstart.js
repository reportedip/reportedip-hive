/**
 * Quickstart page: mode cards, key check, activation.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     2.1.54
 */

(function ($) {
	'use strict';

	var cfg = window.reportedipQuickstart || {};
	var RANK = { free: 0, contributor: 0, professional: 1, business: 2, enterprise: 2 };

	var Quickstart = {
		validatedKey: cfg.savedApiKey || '',
		tier: (cfg.tier || 'free').toLowerCase(),

		init: function () {
			$(document).on('click', '.rip-mode-card', this.onModeClick.bind(this));
			$(document).on('click', '#rip-validate-key', this.onValidateKey.bind(this));
			$(document).on('keypress', '#rip-api-key', function (e) {
				if (e.which === 13) { e.preventDefault(); $('#rip-validate-key').trigger('click'); }
			});
			$(document).on('input', '#rip-api-key', function () {
				Quickstart.validatedKey = '';
				$('#rip-api-key-status').empty();
				$(this).removeClass('rip-input--valid rip-input--invalid');
			});
			$(document).on('click', '#rip-quickstart-activate', function (e) { e.preventDefault(); Quickstart.activate(false); });
			$(document).on('click', '#rip-quickstart-expert', function (e) { e.preventDefault(); Quickstart.activate(true); });
			$(document).on('click', '#rip-quickstart-import-toggle', function () { $('#rip-quickstart-import-form').toggleClass('rip-hidden'); });
			$(document).on('submit', '#rip-quickstart-import-form', this.onImport.bind(this));
			this.renderFeatureLocks();
		},

		/**
		 * One line of key-check feedback, as a design-system alert so the
		 * verdict carries weight instead of reading as a hint.
		 *
		 * @param {string} state success or error.
		 * @param {string} html  Already escaped text.
		 * @return {string} Markup.
		 */
		statusHtml: function (state, html) {
			var alert = state === 'success' ? 'rip-alert--success' : 'rip-alert--danger';
			return '<div class="rip-alert ' + alert + '"><span class="rip-input-status--' + state + '">' + html + '</span></div>';
		},

		mode: function () {
			return $('#rip-selected-mode').val() === 'local' ? 'local' : 'community';
		},

		onModeClick: function (e) {
			var $card = $(e.currentTarget);
			$('.rip-mode-card').removeClass('rip-mode-card--selected');
			$card.addClass('rip-mode-card--selected');
			$('#rip-selected-mode').val($card.data('mode'));
			$('#rip-api-key-card').toggleClass('rip-is-hidden', $card.data('mode') !== 'community');
			this.renderFeatureLocks();
		},

		/**
		 * Grey out rows above the effective tier. Local Shield never
		 * unlocks paid rows because the recommendation treats it as free.
		 */
		renderFeatureLocks: function () {
			var effective = this.mode() === 'community' ? this.tier : 'free';
			var rank = RANK[effective] || 0;
			$('#rip-quickstart-features li').each(function () {
				var rowRank = RANK[$(this).data('tier')] || 0;
				$(this).toggleClass('rip-quickstart__feature--locked', rowRank > rank);
			});
		},

		onValidateKey: function (e) {
			e.preventDefault();
			var $button = $(e.currentTarget);
			var $input = $('#rip-api-key');
			var $status = $('#rip-api-key-status');
			var key = ($input.val() || '').trim();
			var s = cfg.strings || {};

			if (!key) {
				$status.html(Quickstart.statusHtml('error', $('<span>').text(s.missingKey).html()));
				return;
			}
			$button.prop('disabled', true);
			$status.html('<span class="rip-input-status--loading">' + s.validating + '</span>');

			$.post(cfg.ajaxUrl, { action: 'reportedip_quickstart_validate_key', nonce: cfg.nonce, api_key: key })
				.done(function (r) {
					if (r && r.success && r.data && r.data.valid) {
						Quickstart.validatedKey = key;
						Quickstart.tier = (r.data.tier || 'free').toLowerCase();
						var text = s.valid + ' · ' + $('<span>').text(r.data.tier_label).html();
						if (r.data.domains_limit !== null && r.data.domains_limit > 0) {
							text += ' · ' + s.domains.replace('%1$s', r.data.domains_used).replace('%2$s', r.data.domains_limit);
						}
						$status.html(Quickstart.statusHtml('success', text));
						$input.addClass('rip-input--valid').removeClass('rip-input--invalid');
						if (r.data.tier_badge_html) { $('#rip-quickstart-tier-badge').html(r.data.tier_badge_html); }
						Quickstart.renderFeatureLocks();
						if (RANK[Quickstart.tier] >= 1) { $('#rip-quickstart-teaser').remove(); }
					} else {
						var msg = (r && r.data && r.data.message) ? r.data.message : s.invalid;
						$status.html(Quickstart.statusHtml('error', $('<span>').text(msg).html()));
						$input.addClass('rip-input--invalid').removeClass('rip-input--valid');
					}
				})
				.fail(function () {
					$status.html(Quickstart.statusHtml('error', $('<span>').text(s.error).html()));
				})
				.always(function () { $button.prop('disabled', false); });
		},

		activate: function (expert) {
			var $button = $('#rip-quickstart-activate');
			var s = cfg.strings || {};
			var mode = this.mode();
			if (mode === 'community' && !this.validatedKey) {
				$('#rip-quickstart-note').removeClass('rip-is-hidden').text(s.keyRequired);
				$('#rip-api-key-status').html(Quickstart.statusHtml('error', $('<span>').text(s.keyRequired).html()));
				$('#rip-api-key').addClass('rip-input--invalid').removeClass('rip-input--valid');
				$('#rip-api-key-card')[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
				$('#rip-api-key').trigger('focus');
				return;
			}
			$('#rip-quickstart-note').addClass('rip-is-hidden').text('');
			var label = $button.text();
			$button.prop('disabled', true).text(s.activating);
			$.post(cfg.ajaxUrl, {
				action: 'reportedip_quickstart_activate',
				nonce: cfg.nonce,
				mode: mode,
				twofa_admins: $('#rip-quickstart-2fa').is(':checked') ? 1 : 0,
				badge: $('#rip-quickstart-badge').is(':checked') ? 1 : 0,
				notify: $('#rip-quickstart-notify').is(':checked') ? 1 : 0,
				expert: expert ? 1 : 0
			}).done(function (r) {
				if (r && r.success && r.data && r.data.redirect_url) {
					window.location.href = r.data.redirect_url;
					return;
				}
				$button.prop('disabled', false).text(label);
				$('#rip-quickstart-note').removeClass('rip-is-hidden').text((r && r.data && r.data.message) || s.error);
			}).fail(function () {
				$button.prop('disabled', false).text(label);
				$('#rip-quickstart-note').removeClass('rip-is-hidden').text(s.error);
			});
		},

		onImport: function (e) {
			e.preventDefault();
			var form = e.currentTarget;
			var $status = $('#rip-quickstart-import-status');
			var fd = new FormData(form);
			fd.append('action', 'reportedip_quickstart_import');
			$status.text('...');
			fetch(cfg.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: fd })
				.then(function (r) { return r.json().catch(function () { return null; }); })
				.then(function (resp) {
					if (resp && resp.success && resp.data && resp.data.redirect_url) {
						window.location.href = resp.data.redirect_url;
					} else {
						$status.text((resp && resp.data && resp.data.message) || (cfg.strings || {}).error || '');
					}
				})
				.catch(function () { $status.text((cfg.strings || {}).error || ''); });
		}
	};

	$(function () { Quickstart.init(); });
})(jQuery);
