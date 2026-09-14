/**
 * Badges tab: live preview of the one-click footer badge and the banner
 * builder that turns a template plus a few choices into a shortcode.
 * Both previews render the same `rip-hive-banner` element the front end
 * uses, so what the admin sees is what visitors get.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     2.1.57
 */
(function () {
	'use strict';

	var data = window.ripBadgesData || {};
	var strings = data.strings || {};

	function byId(id) {
		return document.getElementById(id);
	}

	function checkedValue(name) {
		var el = document.querySelector('input[name="' + name + '"]:checked');
		return el ? el.value : '';
	}

	function copyToClipboard(text, btn) {
		var orig = btn.textContent;
		var done = function () {
			btn.textContent = strings.copied || 'Copied!';
			setTimeout(function () {
				btn.textContent = orig;
			}, 1400);
		};
		var fallback = function () {
			window.prompt(strings.prompt || 'Copy this shortcode:', text);
		};
		if (navigator.clipboard && navigator.clipboard.writeText) {
			navigator.clipboard.writeText(text).then(done, fallback);
		} else {
			fallback();
		}
	}

	function initFooterPreview() {
		var wrap = byId('rip-auto-footer-preview');
		var initial = wrap ? wrap.querySelector('rip-hive-banner') : null;
		if (!initial) {
			return;
		}
		var blueprint = initial.cloneNode(true);
		var rerender = function () {
			var fresh = blueprint.cloneNode(true);
			fresh.setAttribute('data-variant', checkedValue('reportedip_hive_auto_footer_variant') || 'badge');
			wrap.replaceChildren(fresh);
			wrap.dataset.align = checkedValue('reportedip_hive_auto_footer_align') || 'center';
		};
		document.querySelectorAll('input[name="reportedip_hive_auto_footer_variant"], input[name="reportedip_hive_auto_footer_align"]').forEach(function (radio) {
			radio.addEventListener('change', rerender);
		});
	}

	function initBuilder() {
		var root = byId('rip-badge-builder');
		var preview = byId('rip-cust-preview');
		var shortcodeEl = byId('rip-cust-shortcode');
		if (!root || !preview || !shortcodeEl) {
			return;
		}

		var typeGroup = byId('rip-cust-type-group');
		var presets = root.querySelectorAll('.rip-badge-preset');

		var formatNumber = function (n) {
			try {
				return new Intl.NumberFormat().format(n);
			} catch (e) {
				return String(n);
			}
		};

		var attrEscape = function (s) {
			return String(s).replace(/"/g, '\\"');
		};

		var colour = function (id) {
			var el = byId(id);
			return el.dataset.empty === '1' ? '' : el.value;
		};

		var readState = function () {
			return {
				variant: byId('rip-cust-variant').value,
				type: byId('rip-cust-type').value,
				tone: byId('rip-cust-tone').value,
				theme: checkedValue('rip-cust-theme') || 'dark',
				align: checkedValue('rip-cust-align') || 'center',
				bg1: colour('rip-cust-bg1'),
				bg2: colour('rip-cust-bg2'),
				color: colour('rip-cust-color'),
				border: colour('rip-cust-border'),
				intro: byId('rip-cust-intro').value.trim(),
				label: byId('rip-cust-label').value.trim(),
				live: byId('rip-cust-live').checked
			};
		};

		var showsNumber = function (variant) {
			return variant === 'stat' || variant === 'banner';
		};

		var resolveBg = function (state) {
			if (!state.bg1) {
				return '';
			}
			return state.bg2 ? state.bg1 + ',' + state.bg2 : state.bg1;
		};

		var resolveHeadlineNoun = function (state) {
			var tone = (data.tones || {})[state.tone] || { headline: 'Protected by ReportedIP Hive', noun: null };
			var stat = (data.statLabels || {})[state.type] || { label: '', fallback: 'Active threat protection' };
			return {
				headline: state.intro || tone.headline,
				noun: state.label || (tone.noun !== null ? tone.noun : stat.label),
				fallback: stat.fallback
			};
		};

		var renderBanner = function (state) {
			var hn = resolveHeadlineNoun(state);
			var sample = (data.sampleValues || {})[state.type] || 0;
			var hasValue = sample > 0;
			var metricText = hasValue ? formatNumber(sample) + ' ' + hn.noun : hn.fallback;
			var href = (data.siteUrl || 'https://reportedip.com') + '/?utm_source=hive&utm_medium=admin-customizer&utm_campaign=protected&utm_content=' + state.variant;

			var banner = document.createElement('rip-hive-banner');
			banner.setAttribute('data-variant', state.variant);
			banner.setAttribute('data-tone', state.tone);
			banner.setAttribute('data-stat', state.type);
			banner.setAttribute('data-value', hasValue ? String(sample) : '');
			banner.setAttribute('data-headline', hn.headline);
			banner.setAttribute('data-noun', hn.noun);
			banner.setAttribute('data-metric-text', metricText);
			banner.setAttribute('data-mode', 'community');
			banner.setAttribute('data-theme', state.theme);
			banner.setAttribute('data-bg', resolveBg(state));
			banner.setAttribute('data-color', state.color);
			banner.setAttribute('data-border', state.border);
			banner.setAttribute('data-live', state.live ? 'true' : 'false');
			banner.setAttribute('data-href', href);

			var fallback = document.createElement('a');
			fallback.href = href;
			fallback.rel = 'noopener';
			fallback.className = 'rip-hive-fallback-link';
			fallback.textContent = hn.headline + ', ' + metricText;
			banner.appendChild(fallback);

			preview.replaceChildren(banner);
			preview.dataset.align = state.align;
		};

		var buildShortcode = function (state) {
			var tag = 'reportedip_' + state.variant;
			var defaultTone = (data.variantTones || {})[state.variant] || 'protect';
			var bg = resolveBg(state);
			var attrs = [];
			if (showsNumber(state.variant) && state.type !== 'attacks_total') {
				attrs.push('type="' + state.type + '"');
			}
			if (state.tone !== defaultTone) {
				attrs.push('tone="' + state.tone + '"');
			}
			if (state.theme !== 'dark') {
				attrs.push('theme="' + state.theme + '"');
			}
			if (state.align !== 'left') {
				attrs.push('align="' + state.align + '"');
			}
			if (bg) {
				attrs.push('bg="' + bg + '"');
			}
			if (state.color) {
				attrs.push('color="' + state.color + '"');
			}
			if (state.border) {
				attrs.push('border="' + state.border + '"');
			}
			if (state.intro) {
				attrs.push('intro="' + attrEscape(state.intro) + '"');
			}
			if (state.label) {
				attrs.push('label="' + attrEscape(state.label) + '"');
			}
			if (!state.live) {
				attrs.push('live="false"');
			}
			return attrs.length ? '[' + tag + ' ' + attrs.join(' ') + ']' : '[' + tag + ']';
		};

		var markPreset = function (state) {
			presets.forEach(function (btn) {
				var match = btn.dataset.variant === state.variant && btn.dataset.tone === state.tone && (!showsNumber(state.variant) || btn.dataset.type === state.type);
				btn.classList.toggle('rip-badge-preset--active', match);
				btn.setAttribute('aria-pressed', match ? 'true' : 'false');
			});
		};

		var update = function () {
			var state = readState();
			if (typeGroup) {
				typeGroup.hidden = !showsNumber(state.variant);
			}
			renderBanner(state);
			shortcodeEl.textContent = buildShortcode(state);
			markPreset(state);
		};

		root.querySelectorAll('input, select').forEach(function (el) {
			el.addEventListener('input', function (e) {
				if (e.target && e.target.type === 'color') {
					e.target.dataset.empty = '0';
				}
				update();
			});
			el.addEventListener('change', update);
		});

		root.querySelectorAll('.rip-cust-clear').forEach(function (btn) {
			btn.addEventListener('click', function () {
				var input = byId(btn.dataset.target);
				if (input) {
					input.dataset.empty = '1';
					update();
				}
			});
		});

		presets.forEach(function (btn) {
			btn.addEventListener('click', function () {
				byId('rip-cust-variant').value = btn.dataset.variant;
				byId('rip-cust-type').value = btn.dataset.type;
				byId('rip-cust-tone').value = btn.dataset.tone;
				update();
			});
		});

		var copyBtn = byId('rip-cust-copy');
		if (copyBtn) {
			copyBtn.addEventListener('click', function () {
				copyToClipboard(shortcodeEl.textContent, copyBtn);
			});
		}

		update();
	}

	initFooterPreview();
	initBuilder();
})();
