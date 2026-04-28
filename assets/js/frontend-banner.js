/**
 * Frontend Web Component <rip-hive-banner>: renders community-trust badges
 * and stat banners inside a Shadow Root so themes cannot override the
 * presentation. The Light-DOM <a href> fallback (server-rendered) remains
 * crawlable for search engines and visible without JavaScript.
 *
 * Reads `data-headline` and `data-noun` (server-side, already translated)
 * to render tone-aware marketing text. Animates the value up from zero on
 * first viewport intersection and shows a pulsing "live" dot — both effects
 * respect the user's `prefers-reduced-motion` setting.
 *
 * Custom-theme attributes (`data-bg`, `data-color`, `data-border`) feed CSS
 * variables on the host element so site owners can match their brand
 * without losing the theme-isolation guarantee.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     1.3.0
 */
( () => {
	'use strict';

	if ( typeof window === 'undefined' || ! window.customElements || ! window.HTMLElement ) {
		return;
	}

	if ( window.customElements.get( 'rip-hive-banner' ) ) {
		return;
	}

	const LOGO_SVG = '<svg viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">'
		+ '<path d="M24 4L8 12v12c0 11 7.7 21.3 16 24 8.3-2.7 16-13 16-24V12L24 4z" fill="currentColor" opacity="0.18"/>'
		+ '<path d="M24 4L8 12v12c0 11 7.7 21.3 16 24 8.3-2.7 16-13 16-24V12L24 4zm0 4.2l12 6v10c0 8.4-6 16.3-12 18.5-6-2.2-12-10.1-12-18.5v-10l12-6z" fill="currentColor"/>'
		+ '<path d="M21 28l-5-5 1.8-1.8 3.2 3.2 7.2-7.2L30 19l-9 9z" fill="currentColor"/>'
		+ '</svg>';

	const BASE_STYLES = `
		:host {
			all: initial;
			display: inline-block;
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
			line-height: 1.35;
			--rip-bg: linear-gradient(135deg, #4F46E5, #7C3AED);
			--rip-fg: #ffffff;
			--rip-border: transparent;
			--rip-border-width: 1px;
			--rip-radius: 14px;
			--rip-live: #10B981;
			--rip-pad-y: 14px;
			--rip-pad-x: 20px;
			--rip-gap: 14px;
			--rip-shadow: 0 2px 4px rgba(15, 23, 42, .08), 0 4px 12px rgba(15, 23, 42, .06);
			--rip-shadow-hover: 0 6px 12px rgba(15, 23, 42, .12), 0 12px 24px rgba(15, 23, 42, .12);
			--rip-ease: cubic-bezier(.2, .8, .2, 1);
		}
		:host([hidden]) { display: none; }
		a {
			display: inline-flex;
			align-items: center;
			gap: var(--rip-gap);
			padding: var(--rip-pad-y) var(--rip-pad-x);
			text-decoration: none;
			color: var(--rip-fg);
			background: var(--rip-bg);
			border-radius: var(--rip-radius);
			border: var(--rip-border-width) solid var(--rip-border);
			box-shadow: var(--rip-shadow);
			transition: transform .22s var(--rip-ease), box-shadow .22s var(--rip-ease), background-position .35s var(--rip-ease);
			background-size: 180% 180%;
			background-position: 0% 0%;
			will-change: transform;
		}
		a:hover {
			transform: translateY(-2px);
			box-shadow: var(--rip-shadow-hover);
			background-position: 100% 100%;
		}
		a:active { transform: translateY(0); transition-duration: .1s; }
		a:focus-visible { outline: 2px solid var(--rip-fg); outline-offset: 3px; }
		.logo {
			width: 36px;
			height: 36px;
			flex-shrink: 0;
			color: var(--rip-fg);
			display: inline-flex;
			align-items: center;
			justify-content: center;
		}
		.logo svg { width: 100%; height: 100%; display: block; fill: currentColor; }
		.text { display: flex; flex-direction: column; min-width: 0; gap: 2px; }
		.headline {
			font-size: 13px;
			font-weight: 600;
			letter-spacing: .005em;
			opacity: .94;
		}
		.metric { display: inline-flex; align-items: baseline; gap: 8px; }
		.num {
			font-size: 24px;
			font-weight: 700;
			letter-spacing: -.015em;
			font-variant-numeric: tabular-nums;
			line-height: 1.1;
		}
		.lbl { font-size: 12px; opacity: .9; letter-spacing: .01em; }
		.title {
			font-size: 14px;
			font-weight: 600;
			letter-spacing: .005em;
		}
		.subtitle {
			font-size: 11px;
			opacity: .82;
			letter-spacing: .04em;
			text-transform: uppercase;
		}
		.live-dot {
			display: inline-block;
			width: 8px;
			height: 8px;
			border-radius: 50%;
			background: var(--rip-live);
			box-shadow: 0 0 0 0 var(--rip-live);
			animation: rip-pulse 2.4s var(--rip-ease) infinite;
			flex-shrink: 0;
			align-self: center;
			position: relative;
			top: -1px;
		}
		@keyframes rip-pulse {
			0%   { box-shadow: 0 0 0 0 rgba(16, 185, 129, .55); }
			70%  { box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); }
			100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
		}
		:host([data-theme="light"]) {
			--rip-bg: #ffffff;
			--rip-fg: #4F46E5;
			--rip-border: #E5E7EB;
			--rip-shadow: 0 1px 2px rgba(15, 23, 42, .06), 0 2px 6px rgba(15, 23, 42, .04);
			--rip-shadow-hover: 0 4px 8px rgba(15, 23, 42, .08), 0 12px 24px rgba(79, 70, 229, .14);
		}
		:host([data-theme="light"]) a:hover { border-color: #C7D2FE; }
		:host([data-variant="badge"]) {
			--rip-pad-y: 8px;
			--rip-pad-x: 14px;
			--rip-gap: 8px;
		}
		:host([data-variant="badge"]) .logo { width: 20px; height: 20px; }
		:host([data-variant="badge"]) .num { display: none; }
		:host([data-variant="badge"]) .headline { display: none; }
		:host([data-variant="badge"]) .lbl { font-size: 13px; font-weight: 500; opacity: 1; letter-spacing: 0; }
		:host([data-variant="badge"]) .live-dot { display: none; }
		:host([data-variant="stat"]) {
			--rip-pad-y: 16px;
			--rip-pad-x: 22px;
		}
		:host([data-variant="banner"]) {
			--rip-pad-y: 18px;
			--rip-pad-x: 24px;
			--rip-gap: 18px;
		}
		:host([data-variant="banner"]) .num { font-size: 28px; }
		:host([data-variant="banner"]) .headline { font-size: 14px; }
		:host([data-variant="shield"]) {
			--rip-pad-y: 10px;
			--rip-pad-x: 10px;
			--rip-radius: 999px;
		}
		:host([data-variant="shield"]) .text { display: none; }
		:host([data-variant="shield"]) .logo { width: 26px; height: 26px; }
		:host([data-variant="shield"]) .live-dot { display: none; }
		:host([data-variant="shield"]) a:hover { transform: translateY(-2px) scale(1.04); }
		@media (max-width: 480px) {
			:host([data-variant="banner"]) {
				--rip-pad-y: 14px;
				--rip-pad-x: 18px;
				--rip-gap: 12px;
			}
			:host([data-variant="banner"]) .num { font-size: 22px; }
			:host([data-variant="stat"]) .num { font-size: 20px; }
			.logo { width: 28px; height: 28px; }
		}
		@media (prefers-reduced-motion: reduce) {
			.live-dot { animation: none; }
			a, a:hover { transition: none; transform: none; background-position: 0% 0%; }
		}
	`;

	const formatter = ( () => {
		try {
			return new Intl.NumberFormat();
		} catch ( e ) {
			return null;
		}
	} )();

	const formatNumber = ( n ) => {
		if ( ! Number.isFinite( n ) || n <= 0 ) {
			return '';
		}
		const i = Math.floor( n );
		return formatter ? formatter.format( i ) : String( i ).replace( /\B(?=(\d{3})+(?!\d))/g, ',' );
	};

	const escapeText = ( s ) => String( s == null ? '' : s )
		.replace( /&/g, '&amp;' )
		.replace( /</g, '&lt;' )
		.replace( />/g, '&gt;' )
		.replace( /"/g, '&quot;' );

	const buildBgStyle = ( raw ) => {
		if ( ! raw ) {
			return '';
		}
		if ( raw.indexOf( ',' ) === -1 ) {
			return raw;
		}
		const parts = raw.split( ',' ).map( ( s ) => s.trim() );
		return `linear-gradient(135deg, ${ parts[ 0 ] }, ${ parts[ 1 ] || parts[ 0 ] })`;
	};

	const easeOutCubic = ( t ) => 1 - Math.pow( 1 - t, 3 );

	const prefersReducedMotion = () => window.matchMedia
		&& window.matchMedia( '(prefers-reduced-motion: reduce)' ).matches;

	class RipHiveBanner extends HTMLElement {
		connectedCallback() {
			if ( this._mounted ) {
				return;
			}
			this._mounted = true;

			const variant = this.getAttribute( 'data-variant' ) || 'badge';
			const valueAttr = this.getAttribute( 'data-value' ) || '';
			const target = parseInt( valueAttr, 10 );
			const hasNumber = Number.isFinite( target ) && target > 0;
			const headline = this.getAttribute( 'data-headline' ) || 'Protected by ReportedIP Hive';
			const noun = this.getAttribute( 'data-noun' ) || '';
			const metricText = this.getAttribute( 'data-metric-text' ) || headline;
			const href = this.getAttribute( 'data-href' ) || 'https://reportedip.de/';
			const live = this.getAttribute( 'data-live' ) !== 'false';

			this.applyCustomTheme();

			const aria = hasNumber
				? `${ headline } — ${ formatNumber( target ) } ${ noun }`
				: `${ headline } — ${ metricText }`;

			const root = this.attachShadow( { mode: 'open' } );
			root.innerHTML = `<style>${ BASE_STYLES }</style>`
				+ `<a href="${ escapeText( href ) }" rel="noopener" target="_blank" aria-label="${ escapeText( aria ) }">`
				+ this.renderBody( variant, hasNumber, headline, noun, metricText, live )
				+ '</a>';

			this.hideFallback();

			if ( hasNumber && variant !== 'badge' && variant !== 'shield' ) {
				this.scheduleCountUp( root, target, noun );
			}
		}

		applyCustomTheme() {
			const bg = this.getAttribute( 'data-bg' );
			const color = this.getAttribute( 'data-color' );
			const border = this.getAttribute( 'data-border' );
			if ( bg ) {
				this.style.setProperty( '--rip-bg', buildBgStyle( bg ) );
			}
			if ( color ) {
				this.style.setProperty( '--rip-fg', color );
			}
			if ( border && border !== 'none' ) {
				this.style.setProperty( '--rip-border', border );
				this.style.setProperty( '--rip-border-width', '2px' );
			}
		}

		renderBody( variant, hasNumber, headline, noun, metricText, live ) {
			if ( variant === 'shield' ) {
				return `<span class="logo" aria-hidden="true">${ LOGO_SVG }</span>`;
			}

			if ( variant === 'badge' ) {
				return `<span class="logo" aria-hidden="true">${ LOGO_SVG }</span>`
					+ `<span class="text"><span class="lbl">${ escapeText( headline ) }</span></span>`;
			}

			const liveDot = live && hasNumber ? '<span class="live-dot" aria-hidden="true"></span>' : '';
			const metric = hasNumber
				? `<span class="metric">${ liveDot }<span class="num" data-num>${ escapeText( formatNumber( 0 ) || '0' ) }</span> <span class="lbl">${ escapeText( noun ) }</span></span>`
				: `<span class="metric"><span class="lbl">${ escapeText( metricText ) }</span></span>`;

			return `<span class="logo" aria-hidden="true">${ LOGO_SVG }</span>`
				+ `<span class="text"><span class="headline">${ escapeText( headline ) }</span>${ metric }</span>`;
		}

		hideFallback() {
			const fallback = this.querySelector( '.rip-hive-fallback-link' );
			if ( ! fallback ) {
				return;
			}
			fallback.setAttribute( 'aria-hidden', 'true' );
			Object.assign( fallback.style, {
				position: 'absolute',
				width: '1px',
				height: '1px',
				overflow: 'hidden',
				clip: 'rect(0 0 0 0)',
				whiteSpace: 'nowrap',
				border: '0',
				padding: '0',
				margin: '-1px',
			} );
		}

		scheduleCountUp( root, target, noun ) {
			const numEl = root.querySelector( '[data-num]' );
			if ( ! numEl ) {
				return;
			}

			if ( prefersReducedMotion() ) {
				numEl.textContent = formatNumber( target );
				return;
			}

			if ( ! ( 'IntersectionObserver' in window ) ) {
				numEl.textContent = formatNumber( target );
				return;
			}

			const observer = new IntersectionObserver( ( entries ) => {
				entries.forEach( ( entry ) => {
					if ( entry.isIntersecting && ! this._animated ) {
						this._animated = true;
						this.runCountUp( numEl, target );
						observer.disconnect();
					}
				} );
			}, { threshold: 0.25 } );
			observer.observe( this );
		}

		runCountUp( numEl, target ) {
			const duration = 1400;
			const start = performance.now();
			const tick = ( now ) => {
				const elapsed = now - start;
				const progress = Math.min( 1, elapsed / duration );
				const current = target * easeOutCubic( progress );
				numEl.textContent = formatNumber( current );
				if ( progress < 1 ) {
					requestAnimationFrame( tick );
				} else {
					numEl.textContent = formatNumber( target );
				}
			};
			requestAnimationFrame( tick );
		}
	}

	window.customElements.define( 'rip-hive-banner', RipHiveBanner );
} )();
