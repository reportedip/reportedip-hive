/**
 * ReportedIP Hive — Charts Module.
 *
 * Provides chart rendering for the dashboard using Chart.js.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
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

            // Set global Chart.js defaults
            this.setChartDefaults();

            // Initialize charts if canvas elements exist
            this.initSecurityEventsChart();
            this.initThreatDistributionChart();
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

            // Show empty state if no data
            if (!data.labels || data.labels.length === 0) {
                this.showEmptyState(canvas, 'No security events recorded yet');
                return;
            }

            // Destroy existing chart if it exists
            if (this.charts.securityEvents) {
                this.charts.securityEvents.destroy();
            }

            this.charts.securityEvents = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.labels || [],
                    datasets: [
                        {
                            label: reportedipCharts.strings.failedLogins || 'Failed Logins',
                            data: data.failedLogins || [],
                            borderColor: this.colors.danger,
                            backgroundColor: this.colors.dangerLight,
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4,
                            pointRadius: 0,
                            pointHoverRadius: 6,
                            pointHoverBackgroundColor: this.colors.danger,
                            pointHoverBorderColor: '#fff',
                            pointHoverBorderWidth: 2
                        },
                        {
                            label: reportedipCharts.strings.blockedIPs || 'Blocked IPs',
                            data: data.blockedIPs || [],
                            borderColor: this.colors.warning,
                            backgroundColor: this.colors.warningLight,
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4,
                            pointRadius: 0,
                            pointHoverRadius: 6,
                            pointHoverBackgroundColor: this.colors.warning,
                            pointHoverBorderColor: '#fff',
                            pointHoverBorderWidth: 2
                        },
                        {
                            label: reportedipCharts.strings.commentSpam || 'Comment Spam',
                            data: data.commentSpam || [],
                            borderColor: this.colors.info,
                            backgroundColor: this.colors.infoLight,
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4,
                            pointRadius: 0,
                            pointHoverRadius: 6,
                            pointHoverBackgroundColor: this.colors.info,
                            pointHoverBorderColor: '#fff',
                            pointHoverBorderWidth: 2
                        }
                    ]
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
                                padding: 20,
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
                            grid: {
                                display: false
                            },
                            ticks: {
                                maxRotation: 0
                            }
                        },
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: 'rgba(0, 0, 0, 0.05)'
                            },
                            ticks: {
                                stepSize: 1,
                                callback: function(value) {
                                    if (Number.isInteger(value)) {
                                        return value;
                                    }
                                }
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

            this.charts.threatDistribution = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: data.labels || [
                        reportedipCharts.strings.failedLogins || 'Failed Logins',
                        reportedipCharts.strings.commentSpam || 'Comment Spam',
                        reportedipCharts.strings.xmlrpcAbuse || 'XMLRPC Abuse',
                        reportedipCharts.strings.adminScanning || 'Admin Scanning'
                    ],
                    datasets: [{
                        data: data.values || [0, 0, 0, 0],
                        backgroundColor: [
                            this.colors.danger,
                            this.colors.info,
                            this.colors.warning,
                            this.colors.primary
                        ],
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
