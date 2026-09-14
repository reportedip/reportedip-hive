/**
 * Protection page: client-side search over the registry fields and the
 * preset radio group. No server roundtrip; everything the filter needs is
 * in `data-search` attributes rendered by the page.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     2.1.56
 */
(function () {
	'use strict';

	var input = document.getElementById('rip-protection-search');
	var empty = document.getElementById('rip-protection-no-results');
	if (!input) {
		return;
	}

	function highlight(field, term) {
		var label = field.querySelector('.rip-label');
		if (!label) {
			return;
		}
		if (!label.dataset.text) {
			label.dataset.text = label.textContent;
		}
		var text = label.dataset.text;
		var idx = term ? text.toLowerCase().indexOf(term) : -1;
		if (idx < 0) {
			label.textContent = text;
			return;
		}
		label.textContent = '';
		label.appendChild(document.createTextNode(text.slice(0, idx)));
		var mark = document.createElement('mark');
		mark.textContent = text.slice(idx, idx + term.length);
		label.appendChild(mark);
		label.appendChild(document.createTextNode(text.slice(idx + term.length)));
	}

	function filter() {
		var term = input.value.trim().toLowerCase();
		var hits = 0;
		document.querySelectorAll('.rip-protection__section').forEach(function (section) {
			var sectionHits = 0;
			section.querySelectorAll('.rip-protection__field').forEach(function (field) {
				var match = !term || (field.dataset.search || '').indexOf(term) >= 0;
				field.classList.toggle('rip-hidden', !match);
				highlight(field, match ? term : '');
				if (match) {
					sectionHits += 1;
				}
			});
			if (term) {
				section.classList.toggle('rip-hidden', sectionHits === 0);
				if (sectionHits > 0) {
					section.open = true;
				}
			} else {
				section.classList.remove('rip-hidden');
			}
			hits += sectionHits;
		});
		if (empty) {
			empty.classList.toggle('rip-hidden', !term || hits > 0);
		}
	}

	input.addEventListener('input', filter);

	var presets = document.querySelectorAll('input[name="rip_protection_level"]');
	['failed_login_threshold', 'failed_login_timeframe', 'block_duration', 'block_threshold'].forEach(function (short) {
		var el = document.getElementById('rip-field-' + short);
		if (!el) {
			return;
		}
		el.addEventListener('input', function () {
			presets.forEach(function (radio) {
				radio.checked = radio.value === 'custom';
			});
		});
	});
})();
