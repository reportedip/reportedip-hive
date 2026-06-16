/**
 * ReportedIP Hive — Charts Module.
 *
 * Provides chart rendering for the dashboard using Chart.js.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     1.1.0
 */

(function($) {
    'use strict';

    /**
     * Charts Handler
     */
    var ReportedIPCharts = {
        /**
         * Chart instances
         */
        charts: {},

        /**
         * Chart colors (loaded from CSS design system variables)
         */
        colors: {},

        /**
         * Initialize charts
         */
        init: function() {
            if (typeof Chart === 'undefined') {
                console.warn('ReportedIP Charts: Chart.js not loaded');
                return;
            }

            // Read colors from CSS design system variables
            var style = getComputedStyle(document.documentElement);
            this.colors = {
                primary: style.getPropertyValue('--rip-primary').trim() || '#4F46E5',
                primaryLight: style.getPropertyValue('--rip-primary-100').trim() || 'rgba(79, 70, 229, 0.1)',
                success: style.getPropertyValue('--rip-success').trim() || '#10B981',
                successLight: style.getPropertyValue('--rip-success-bg').trim() || 'rgba(16, 185, 129, 0.1)',
                danger: style.getPropertyValue('--rip-danger').trim() || '#EF4444',
                dangerLight: style.getPropertyValue('--rip-danger-bg').trim() || 'rgba(239, 68, 68, 0.1)',
                warning: style.getPropertyValue('--rip-warning').trim() || '#F59E0B',
                warningLight: style.getPropertyValue('--rip-warning-bg').trim() || 'rgba(245, 158, 11, 0.1)',
                info: style.getPropertyValue('--rip-info').trim() || '#3B82F6',
                infoLight: style.getPropertyValue('--rip-info-bg').trim() || 'rgba(59, 130, 246, 0.1)',
                gray: style.getPropertyValue('--rip-gray-500').trim() || '#6B7280',
                grayLight: 'rgba(107, 114, 128, 0.1)',
                gray400: style.getPropertyValue('--rip-gray-400').trim() || '#9CA3AF',
                gray200: style.getPropertyValue('--rip-gray-200').trim() || '#E5E7EB'
            };

            // Categorical color per threat family (keys match the PHP taxonomy)
            this.familyColors = {
                login:    this.colors.danger,
                firewall: this.colors.primary,
                scanner:  this.colors.warning,
                bot:      this.colors.info,
                recon:    this.colors.success,
                spam:     this.colors.gray,
                anomaly:  style.getPropertyValue('--rip-primary-light').trim() || '#818CF8'
            };

            // Severity scale, most-to-least serious
            this.severityColors = {
                critical: this.colors.danger,
                high:     this.colors.warning,
                medium:   this.colors.info,
                low:      this.colors.gray
            };

            // Set global Chart.js defaults
            this.setChartDefaults();

            // Initialize charts if canvas elements exist
            this.initSecurityEventsChart();
            this.initThreatDistributionChart();
            this.initWafGroupsChart();
            this.initSeverityChart();
        },

        /**
         * Resolve a categorical color for a threat-family key.
         */
        familyColor: function(key) {
            return (this.familyColors && this.familyColors[key]) || this.colors.gray;
        },

        /**
         * Set global Chart.js defaults
         */
        setChartDefaults: function() {
            Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';
            Chart.defaults.font.size = 12;
            Chart.defaults.color = this.colors.gray;
            Chart.defaults.plugins.legend.display = true;
            Chart.defaults.plugins.legend.position = 'bottom';
            Chart.defaults.plugins.tooltip.backgroundColor = getComputedStyle(document.documentElement).getPropertyValue('--rip-gray-800').trim() || '#1F2937';
            Chart.defaults.plugins.tooltip.titleColor = '#fff';
            Chart.defaults.plugins.tooltip.bodyColor = '#fff';
            Chart.defaults.plugins.tooltip.borderColor = getComputedStyle(document.documentElement).getPropertyValue('--rip-gray-700').trim() || '#374151';
            Chart.defaults.plugins.tooltip.borderWidth = 1;
            Chart.defaults.plugins.tooltip.cornerRadius = 8;
            Chart.defaults.plugins.tooltip.padding = 12;
        },

        /**
         * Initialize Security Events Line Chart
         */
        initSecurityEventsChart: function() {
            var canvas = document.getElementById('rip-security-events-chart');
            if (!canvas) return;

            var ctx = canvas.getContext('2d');
            var data = this.getChartData('securityEvents');
            var families = data.families || [];

            // Only chart families that actually have events in the window
            var active = families.filter(function(f) {
                return (f.data || []).reduce(function(a, b) { return a + b; }, 0) > 0;
            });

            if (!data.labels || data.labels.length === 0 || active.length === 0) {
                this.showEmptyState(canvas, 'No security events recorded yet');
                return;
            }

            if (this.charts.securityEvents) {
                this.charts.securityEvents.destroy();
            }

            var self = this;
            var datasets = active.map(function(family) {
                var color = self.familyColor(family.key);
                return {
                    label: family.label,
                    data: family.data || [],
                    borderColor: color,
                    backgroundColor: self.hexToRgba(color, 0.15),
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointRadius: 0,
                    pointHoverRadius: 5,
                    pointHoverBackgroundColor: color,
                    pointHoverBorderColor: '#fff',
                    pointHoverBorderWidth: 2
                };
            });

            this.charts.securityEvents = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.labels || [],
                    datasets: datasets
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {
                        mode: 'index',
                        intersect: false
                    },
                    plugins: {
                        legend: {
                            display: true,
                            position: 'bottom',
                            labels: {
                                usePointStyle: true,
                                padding: 16,
                                font: {
                                    size: 12
                                }
                            }
                        },
                        tooltip: {
                            mode: 'index',
                            intersect: false
                        }
                    },
                    scales: {
                        x: {
                            stacked: true,
                            grid: {
                                display: false
                            },
                            ticks: {
                                maxRotation: 0,
                                autoSkip: true,
                                maxTicksLimit: 12
                            }
                        },
                        y: {
                            stacked: true,
                            beginAtZero: true,
                            grid: {
                                color: 'rgba(0, 0, 0, 0.05)'
                            },
                            ticks: {
                                precision: 0
                            }
                        }
                    }
                }
            });
        },

        /**
         * Initialize Threat Distribution Doughnut Chart
         */
        initThreatDistributionChart: function() {
            var canvas = document.getElementById('rip-threat-distribution-chart');
            if (!canvas) return;

            var ctx = canvas.getContext('2d');
            var data = this.getChartData('threatDistribution');

            // Show empty state if all values are zero
            var total = (data.values || []).reduce(function(a, b) { return a + b; }, 0);
            if (total === 0) {
                this.showEmptyState(canvas, 'No threats detected yet');
                return;
            }

            // Destroy existing chart if it exists
            if (this.charts.threatDistribution) {
                this.charts.threatDistribution.destroy();
            }

            var self = this;
            var bgColors = (data.keys || []).map(function(key) {
                return self.familyColor(key);
            });

            this.charts.threatDistribution = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: data.labels || [],
                    datasets: [{
                        data: data.values || [],
                        backgroundColor: bgColors,
                        borderWidth: 0,
                        hoverOffset: 10
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '65%',
                    plugins: {
                        legend: {
                            display: true,
                            position: 'right',
                            labels: {
                                usePointStyle: true,
                                padding: 15,
                                font: {
                                    size: 12
                                }
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    var label = context.label || '';
                                    var value = context.parsed || 0;
                                    var total = context.dataset.data.reduce(function(a, b) {
                                        return a + b;
                                    }, 0);
                                    var percentage = total > 0 ? Math.round((value / total) * 100) : 0;
                                    return label + ': ' + value + ' (' + percentage + '%)';
                                }
                            }
                        }
                    }
                }
            });
        },

        /**
         * Initialize WAF rule-group horizontal bar chart
         */
        initWafGroupsChart: function() {
            var data = this.getChartData('wafGroups');
            this.initBarChart('rip-waf-groups-chart', 'wafGroups', {
                labels: data.labels || [],
                values: data.values || [],
                colors: this.familyColor('firewall'),
                horizontal: true,
                emptyMsg: 'No firewall hits in this period'
            });
        },

        /**
         * Initialize severity-breakdown bar chart
         */
        initSeverityChart: function() {
            var data = this.getChartData('severity');
            var strings = reportedipCharts.strings || {};
            var order = ['critical', 'high', 'medium', 'low'];
            var self = this;
            this.initBarChart('rip-severity-chart', 'severity', {
                labels: [
                    strings.critical || 'Critical',
                    strings.high || 'High',
                    strings.medium || 'Medium',
                    strings.low || 'Low'
                ],
                values: order.map(function(k) { return (data && data[k]) ? data[k] : 0; }),
                colors: order.map(function(k) { return self.severityColors[k]; }),
                horizontal: false,
                emptyMsg: 'No threats detected yet'
            });
        },

        /**
         * Shared bar-chart renderer for the WAF and severity charts.
         *
         * @param {string} canvasId Target canvas element id.
         * @param {string} chartKey Key under this.charts for destroy/re-init.
         * @param {object} cfg      {labels, values, colors, horizontal, emptyMsg}.
         */
        initBarChart: function(canvasId, chartKey, cfg) {
            var canvas = document.getElementById(canvasId);
            if (!canvas) return;

            var values = cfg.values || [];
            var total = values.reduce(function(a, b) { return a + b; }, 0);
            if (!cfg.labels || cfg.labels.length === 0 || total === 0) {
                this.showEmptyState(canvas, cfg.emptyMsg);
                return;
            }

            if (this.charts[chartKey]) {
                this.charts[chartKey].destroy();
            }

            var valueAxis = {
                beginAtZero: true,
                grid: { color: 'rgba(0, 0, 0, 0.05)' },
                ticks: { precision: 0 }
            };
            var categoryAxis = { grid: { display: false } };

            this.charts[chartKey] = new Chart(canvas.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: cfg.labels,
                    datasets: [{
                        label: (reportedipCharts.strings && reportedipCharts.strings.events) || 'Events',
                        data: values,
                        backgroundColor: cfg.colors,
                        borderWidth: 0,
                        maxBarThickness: cfg.horizontal ? 22 : 48
                    }]
                },
                options: {
                    indexAxis: cfg.horizontal ? 'y' : 'x',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: cfg.horizontal
                        ? { x: valueAxis, y: categoryAxis }
                        : { x: categoryAxis, y: valueAxis }
                }
            });
        },

        /**
         * Convert a #rrggbb color to an rgba() string with the given alpha.
         * Returns the input unchanged when it is not a hex color.
         */
        hexToRgba: function(hex, alpha) {
            if (typeof hex !== 'string' || hex.charAt(0) !== '#') {
                return hex;
            }
            var h = hex.replace('#', '');
            if (h.length === 3) {
                h = h.charAt(0) + h.charAt(0) + h.charAt(1) + h.charAt(1) + h.charAt(2) + h.charAt(2);
            }
            var r = parseInt(h.substring(0, 2), 16);
            var g = parseInt(h.substring(2, 4), 16);
            var b = parseInt(h.substring(4, 6), 16);
            return 'rgba(' + r + ', ' + g + ', ' + b + ', ' + alpha + ')';
        },

        /**
         * Show empty state message instead of an empty chart
         */
        showEmptyState: function(canvas, message) {
            var container = canvas.parentElement;
            canvas.style.display = 'none';
            var emptyDiv = document.createElement('div');
            emptyDiv.className = 'rip-chart-empty';
            emptyDiv.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:48px;height:48px;margin-bottom:12px;opacity:0.3"><path d="M3 3v18h18"/><path d="M7 16l4-4 4 4 5-5"/></svg>' +
                '<p style="margin:0;color:var(--rip-gray-400,#9CA3AF);font-size:14px;">' + message + '</p>';
            emptyDiv.style.cssText = 'display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;min-height:200px;';
            container.appendChild(emptyDiv);
        },

        /**
         * Get chart data from localized script or fetch via AJAX
         */
        getChartData: function(chartType) {
            if (typeof reportedipCharts !== 'undefined' && reportedipCharts.data && reportedipCharts.data[chartType]) {
                return reportedipCharts.data[chartType];
            }
            return {};
        },

        /**
         * Destroy all charts
         */
        destroyAll: function() {
            for (var key in this.charts) {
                if (this.charts.hasOwnProperty(key) && this.charts[key]) {
                    this.charts[key].destroy();
                }
            }
            this.charts = {};
        },

        /**
         * Load chart data for a specific period via AJAX
         */
        loadPeriod: function(days) {
            var self = this;

            if (typeof reportedipCharts === 'undefined' || !reportedipCharts.ajaxUrl) {
                return;
            }

            $.ajax({
                url: reportedipCharts.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'reportedip_get_chart_data',
                    nonce: reportedipCharts.nonce,
                    days: days
                },
                success: function(response) {
                    if (response.success && response.data) {
                        // Remove empty states if present
                        $('.rip-chart-empty').remove();
                        $('canvas', '.rip-chart-card__body').show();

                        // Destroy existing charts and re-init with new data
                        self.destroyAll();

                        // Update localized data
                        reportedipCharts.data = response.data;

                        // Re-init charts
                        self.initSecurityEventsChart();
                        self.initThreatDistributionChart();
                        self.initWafGroupsChart();
                        self.initSeverityChart();
                    }
                }
            });
        }
    };

    // Initialize on document ready
    $(document).ready(function() {
        // Small delay to ensure Chart.js is fully loaded
        setTimeout(function() {
            ReportedIPCharts.init();
        }, 100);

        // Time period selector (7 Days / 30 Days buttons)
        $(document).on('click', '.rip-time-selector__btn', function() {
            var $btn = $(this);
            var days = $btn.data('period') || 7;

            // Update active state
            $btn.siblings().removeClass('rip-time-selector__btn--active');
            $btn.addClass('rip-time-selector__btn--active');

            // Load new data
            ReportedIPCharts.loadPeriod(days);
        });
    });

    // Expose to global scope
    window.ReportedIPCharts = ReportedIPCharts;

})(jQuery);
