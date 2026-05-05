/**
 * MediaFuzzer Fuzzing Charts
 * Initializes and updates Chart.js charts for the fuzzing dashboard.
 */

// Chart instances are created in the fuzzing.html template.
// This file provides helper utilities for chart management.

function createFuzzChart(canvasId) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return null;

  return new Chart(ctx.getContext('2d'), {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Coverage %',
          data: [],
          borderColor: 'rgba(54, 162, 235, 1)',
          backgroundColor: 'rgba(54, 162, 235, 0.1)',
          fill: true,
          yAxisID: 'y',
          tension: 0.3,
          pointRadius: 0,
        },
        {
          label: 'Unique Crashes',
          data: [],
          borderColor: 'rgba(255, 99, 132, 1)',
          backgroundColor: 'rgba(255, 99, 132, 0.1)',
          fill: true,
          yAxisID: 'y1',
          tension: 0.3,
          pointRadius: 2,
          pointBackgroundColor: 'rgba(255, 99, 132, 1)',
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {mode: 'index', intersect: false},
      plugins: {
        legend: {position: 'top'},
      },
      scales: {
        x: {
          title: {display: true, text: 'Time (s)'},
          ticks: {maxTicksLimit: 20}
        },
        y: {
          type: 'linear',
          display: true,
          position: 'left',
          title: {display: true, text: 'Coverage'},
          min: 0,
          ticks: {
            callback: function(value) {
              return (value * 100).toFixed(2) + '%';
            }
          }
        },
        y1: {
          type: 'linear',
          display: true,
          position: 'right',
          title: {display: true, text: 'Crashes'},
          min: 0,
          grid: {drawOnChartArea: false}
        }
      }
    }
  });
}

function updateFuzzChart(chart, label, coverage, crashes) {
  if (!chart) return;

  // Avoid duplicate labels
  const labels = chart.data.labels;
  if (labels.length > 0 && labels[labels.length - 1] === label) return;

  chart.data.labels.push(label);
  chart.data.datasets[0].data.push(coverage);
  chart.data.datasets[1].data.push(crashes);

  // Keep last 200 data points for performance
  const maxPoints = 200;
  if (chart.data.labels.length > maxPoints) {
    chart.data.labels = chart.data.labels.slice(-maxPoints);
    chart.data.datasets[0].data = chart.data.datasets[0].data.slice(-maxPoints);
    chart.data.datasets[1].data = chart.data.datasets[1].data.slice(-maxPoints);
  }

  chart.update('none');
}
