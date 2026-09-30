/**
 * Protection page: tab switching, hash handling, search across tabs, the
 * on/off text next to a switch, the preset coupling and two guards (an
 * invalid field inside a closed details block, the reset confirmation).
 * No server roundtrip; everything the filter needs is in `data-search`.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     2.1.56
 */
(function () {
	'use strict';

	var root = document.querySelector('.rip-protection');
	if (!root) {
		return;
	}
	var tabs = root.querySelectorAll('.rip-protection__tabs .rip-nav-tabs__tab');
	var panels = root.querySelectorAll('.rip-protection__panel');
	var input = document.getElementById('rip-protection-search');
	var empty = document.getElementById('rip-protection-no-results');

	function activate(slug, pushUrl) {
		panels.forEach(function (panel) {
			panel.classList.toggle('rip-hidden', panel.dataset.tab !== slug);
		});
		tabs.forEach(function (tab) {
			tab.classList.toggle('rip-nav-tabs__tab--active', tab.dataset.tab === slug);
		});
		if (pushUrl && window.history && window.history.replaceState) {
			var url = new URL(window.location.href);
			url.searchParams.set('tab', slug);
			window.history.replaceState(null, '', url.toString());
		}
	}

	tabs.forEach(function (tab) {
		tab.addEventListener('click', function (event) {
			event.preventDefault();
			activate(tab.dataset.tab, true);
		});
	});

	function reveal() {
		var target = location.hash ? document.getElementById(location.hash.slice(1)) : null;
		if (!target) {
			return;
		}
		var panel = target.closest('.rip-protection__panel');
		if (panel) {
			activate(panel.dataset.tab, false);
		}
		var details = target.closest('details');
		if (details) {
			details.open = true;
		}
		target.scrollIntoView();
	}

	reveal();
	window.addEventListener('hashchange', reveal);

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
		root.classList.toggle('rip-protection--searching', term !== '');
		root.querySelectorAll('.rip-protection__section').forEach(function (section) {
			var sectionHits = 0;
			section.querySelectorAll('.rip-protection__field').forEach(function (field) {
				var match = !term || (field.dataset.search || '').indexOf(term) >= 0;
				field.classList.toggle('rip-hidden', !match);
				highlight(field, match && term ? term : '');
				if (match) {
					sectionHits += 1;
					var details = field.closest('details');
					if (term && details) {
						details.open = true;
					}
				}
			});
			section.classList.toggle('rip-hidden', term !== '' && sectionHits === 0);
			hits += sectionHits;
		});
		if (term) {
			panels.forEach(function (panel) {
				panel.classList.toggle('rip-hidden', panel.querySelectorAll('.rip-protection__section:not(.rip-hidden)').length === 0);
			});
		} else {
			var active = root.querySelector('.rip-nav-tabs__tab--active');
			activate(active ? active.dataset.tab : panels[0].dataset.tab, false);
			root.querySelectorAll('.rip-protection__details').forEach(function (details) {
				details.open = details.hasAttribute('data-open');
			});
		}
		if (empty) {
			empty.classList.toggle('rip-hidden', !term || hits > 0);
		}
	}

	root.querySelectorAll('.rip-protection__details[open]').forEach(function (details) {
		details.setAttribute('data-open', '');
	});
	if (input) {
		input.addEventListener('input', filter);
	}

	root.addEventListener('change', function (event) {
		var box = event.target;
		if (!box.classList || !box.classList.contains('rip-toggle__input')) {
			return;
		}
		var state = box.closest('.rip-protection__control');
		state = state ? state.querySelector('.rip-protection__state') : null;
		if (state) {
			state.textContent = box.checked ? state.dataset.on : state.dataset.off;
		}
	});

	panels.forEach(function (panel) {
		panel.addEventListener('invalid', function (event) {
			var details = event.target.closest('details');
			if (details) {
				details.open = true;
			}
		}, true);
	});

	root.querySelectorAll('.rip-protection__reset').forEach(function (button) {
		button.addEventListener('click', function (event) {
			if (!window.confirm(button.dataset.confirm)) {
				event.preventDefault();
			}
		});
	});

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
