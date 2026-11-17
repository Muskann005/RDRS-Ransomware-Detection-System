
"use strict";

const API_BASE = "";

let threatChart = null;
let cpuChart = null;
let entropyChart = null;

// API HELPER

async function fetchAPI(endpoint) {
    const response = await fetch(`${API_BASE}${endpoint}`);

    if (!response.ok) {
        throw new Error(
            `API request failed: ${endpoint} (${response.status})`
        );
    }

    return await response.json();
}

// GENERAL HELPERS

function safeValue(value) {
    if (value === null || value === undefined || value === "") {
        return "--";
    }

    return String(value);
}

function setText(id, value) {
    const element = document.getElementById(id);

    if (element) {
        element.textContent = safeValue(value);
    }
}

function formatDate(value) {
    if (!value) return "--";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleString();
}

function setConnectionStatus(connected) {
    const element = document.getElementById("connection-status");

    if (!element) return;

    element.textContent = connected
        ? "● API Connected"
        : "● API Disconnected";

    element.style.color = connected
        ? "#22c55e"
        : "#ef4444";
}

// THREAT SCORE CHART

function updateThreatChart(score) {
    const canvas = document.getElementById("threatChart");

    if (!canvas || typeof Chart === "undefined") return;

    const value = Number(score) || 0;

    if (threatChart) {
        threatChart.data.datasets[0].data = [value];
        threatChart.update();
        return;
    }

    threatChart = new Chart(canvas, {
        type: "bar",

        data: {
            labels: ["Latest Threat Score"],

            datasets: [{
                label: "Threat Score",
                data: [value],
                backgroundColor: "#38bdf8",
                borderRadius: 8
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: true,

            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        color: "#91a0b8"
                    },
                    grid: {
                        color: "#26344c"
                    }
                },

                x: {
                    ticks: {
                        color: "#91a0b8"
                    },
                    grid: {
                        display: false
                    }
                }
            },

            plugins: {
                legend: {
                    labels: {
                        color: "#e5edf8"
                    }
                }
            }
        }
    });
}

// SYSTEM STATUS

async function loadStatus() {
    const data = await fetchAPI("/status");

    setText("threat-score", data.threat_score);
    setText("threat-level", data.threat_level);

    const counts = data.database_counts || {};

    setText("total-events", counts.events);
    setText("total-alerts", counts.alerts);

    const process = data.latest_process;

    if (process) {
        setText("process-name", process.name);
        setText("process-pid", process.pid);

        setText(
            "cpu-usage",
            process.cpu_percent !== null &&
            process.cpu_percent !== undefined
                ? `${process.cpu_percent}%`
                : "--"
        );

        setText(
            "memory-usage",
            process.memory_bytes !== null &&
            process.memory_bytes !== undefined
                ? `${(
                    process.memory_bytes / (1024 * 1024)
                ).toFixed(2)} MB`
                : "--"
        );
    }

    updateThreatChart(data.threat_score);

    return data;
}

// FILE EVENTS TABLE

function renderEventsTable(events) {
    const table = document.getElementById("events-table");

    if (!table) return;

    table.replaceChildren();

    if (!events.length) {
        const row = table.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 5;
        cell.textContent = "No file events recorded.";

        return;
    }

    events.slice(0, 15).forEach(event => {
        const row = table.insertRow();

        const values = [
            formatDate(event.timestamp),
            safeValue(event.event_type),
            safeValue(event.file_path || event.input_data),
            safeValue(event.entropy_score),
            safeValue(event.status)
        ];

        values.forEach(value => {
            const cell = row.insertCell();
            cell.textContent = value;
        });
    });
}

// TOP MODIFIED FILES

function renderTopModifiedFiles(events) {
    const table = document.getElementById("top-files-table");

    if (!table) return;

    const counts = new Map();

    events.forEach(event => {
        const eventType = String(
            event.event_type || ""
        ).toUpperCase();

        const filePath = String(
            event.file_path || ""
        ).trim();

        if (eventType !== "MODIFIED" || !filePath) {
            return;
        }

        const normalizedPath = filePath.replace(/\\/g, "/");

        counts.set(
            normalizedPath,
            (counts.get(normalizedPath) || 0) + 1
        );
    });

    const ranked = Array.from(counts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

    table.replaceChildren();

    if (!ranked.length) {
        const row = table.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 2;
        cell.textContent = "No modified files recorded.";

        return;
    }

    ranked.forEach(([filePath, count]) => {
        const row = table.insertRow();

        const fileCell = row.insertCell();
        const countCell = row.insertCell();

        fileCell.textContent = filePath;
        countCell.textContent = String(count);
    });
}

// ENTROPY CHART

function updateEntropyChart(events) {
    const canvas = document.getElementById("entropyChart");

    if (!canvas || typeof Chart === "undefined") return;

    const records = events
        .filter(event =>
            event.entropy_score !== null &&
            event.entropy_score !== undefined &&
            !Number.isNaN(Number(event.entropy_score))
        )
        .slice(0, 30)
        .reverse();

    const labels = records.map(event => {
        const date = new Date(event.timestamp);

        return Number.isNaN(date.getTime())
            ? "--"
            : date.toLocaleTimeString();
    });

    const values = records.map(event =>
        Number(event.entropy_score)
    );

    if (entropyChart) {
        entropyChart.data.labels = labels;
        entropyChart.data.datasets[0].data = values;
        entropyChart.update();
        return;
    }

    entropyChart = new Chart(canvas, {
        type: "line",

        data: {
            labels: labels,

            datasets: [{
                label: "Entropy Score",
                data: values,
                borderColor: "#4EAA9A",
                backgroundColor: "rgba(78, 170, 154, 0.15)",
                borderWidth: 2,
                pointBackgroundColor: "#4EAA9A",
                pointRadius: 3,
                pointHoverRadius: 5,
                fill: true,
                tension: 0.3
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: true,

            interaction: {
                intersect: false,
                mode: "index"
            },

            scales: {
                y: {
                    beginAtZero: true,
                    min: 0,
                    max: 8,

                    title: {
                        display: true,
                        text: "Entropy (0–8)",
                        color: "#A6B2C5"
                    },

                    ticks: {
                        color: "#A6B2C5"
                    },

                    grid: {
                        color: "rgba(166, 178, 197, 0.12)"
                    }
                },

                x: {
                    ticks: {
                        color: "#A6B2C5",
                        maxTicksLimit: 8
                    },

                    grid: {
                        display: false
                    }
                }
            },

            plugins: {
                legend: {
                    labels: {
                        color: "#E5EAF2"
                    }
                }
            }
        }
    });
}

// LOAD FILE EVENTS

async function loadEvents() {
    const events = await fetchAPI("/events");

    if (!Array.isArray(events)) {
        throw new Error("Invalid event data received from API.");
    }

    renderEventsTable(events);
    renderTopModifiedFiles(events);
    updateEntropyChart(events);
}

// ALERTS

async function loadAlerts() {
    const alerts = await fetchAPI("/alerts");

    const table = document.getElementById("alerts-table");

    if (!table) return;

    table.replaceChildren();

    if (!alerts.length) {
        const row = table.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 4;
        cell.textContent = "No alerts recorded.";

        return;
    }

    alerts.slice(0, 15).forEach(alert => {
        const row = table.insertRow();

        const values = [
            formatDate(alert.timestamp),
            safeValue(alert.severity),
            safeValue(alert.message),
            safeValue(alert.status)
        ];

        values.forEach(value => {
            const cell = row.insertCell();
            cell.textContent = value;
        });
    });
}

// INCIDENTS

async function loadIncidents() {
    const report = await fetchAPI("/reports");

    const incidents = report.recent_incidents || [];

    const table = document.getElementById("incidents-table");

    if (!table) return;

    table.replaceChildren();

    if (!incidents.length) {
        const row = table.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 5;
        cell.textContent = "No incidents recorded.";

        return;
    }

    incidents.forEach(incident => {
        const row = table.insertRow();

        const values = [
            formatDate(incident.timestamp),
            safeValue(incident.severity),
            safeValue(incident.score),
            safeValue(incident.summary),
            safeValue(incident.status)
        ];

        values.forEach(value => {
            const cell = row.insertCell();
            cell.textContent = value;
        });
    });
}

// PROCESS CPU CHART

async function loadCPUChart() {
    const canvas = document.getElementById("cpuChart");

    if (!canvas || typeof Chart === "undefined") return;

    try {
        const processes = await fetchAPI("/processes");

        if (!Array.isArray(processes)) {
            throw new Error("Invalid process data received from API.");
        }

        const validRecords = processes.filter(process =>
            process &&
            process.pid !== null &&
            process.pid !== undefined &&
            process.timestamp &&
            process.cpu_percent !== null &&
            process.cpu_percent !== undefined &&
            !Number.isNaN(Number(process.cpu_percent))
        );

        if (validRecords.length === 0) {
            if (cpuChart) {
                cpuChart.data.labels = [];
                cpuChart.data.datasets[0].data = [];
                cpuChart.update();
            }

            return;
        }

        const newestRecord = validRecords.reduce((latest, current) =>
            new Date(current.timestamp) > new Date(latest.timestamp)
                ? current
                : latest
        );

        const selectedPid = newestRecord.pid;

        const history = validRecords
            .filter(process =>
                String(process.pid) === String(selectedPid)
            )
            .sort((a, b) =>
                new Date(a.timestamp) - new Date(b.timestamp)
            )
            .slice(-30);

        const labels = history.map(process =>
            new Date(process.timestamp).toLocaleTimeString()
        );

        const values = history.map(process =>
            Number(process.cpu_percent)
        );

        const processName = newestRecord.name || "Process";

        const datasetLabel =
            `${processName} (PID ${selectedPid}) CPU Usage (%)`;

        if (cpuChart) {
            cpuChart.data.labels = labels;
            cpuChart.data.datasets[0].label = datasetLabel;
            cpuChart.data.datasets[0].data = values;
            cpuChart.update();
            return;
        }

        cpuChart = new Chart(canvas, {
            type: "line",

            data: {
                labels: labels,

                datasets: [{
                    label: datasetLabel,
                    data: values,
                    borderColor: "#38BDF8",
                    backgroundColor: "rgba(56, 189, 248, 0.12)",
                    borderWidth: 3,
                    pointBackgroundColor: "#7DD3FC",
                    pointBorderColor: "#FFFFFF",
                    pointRadius: 3,
                    pointHoverRadius: 6,
                    fill: true,
                    tension: 0.35
                }]
            },

            options: {
                responsive: true,
                maintainAspectRatio: true,

                interaction: {
                    intersect: false,
                    mode: "index"
                },

                scales: {
                    y: {
                        beginAtZero: true,

                        title: {
                            display: true,
                            text: "CPU Usage (%)",
                            color: "#A9C5DC"
                        },

                        ticks: {
                            color: "#A9C5DC"
                        },

                        grid: {
                            color: "rgba(169, 197, 220, 0.12)"
                        }
                    },

                    x: {
                        title: {
                            display: true,
                            text: "Time",
                            color: "#A9C5DC"
                        },

                        ticks: {
                            color: "#A9C5DC",
                            maxTicksLimit: 8
                        },

                        grid: {
                            display: false
                        }
                    }
                },

                plugins: {
                    legend: {
                        labels: {
                            color: "#F0F9FF"
                        }
                    }
                }
            }
        });

    } catch (error) {
        console.error("CPU chart loading failed:", error);
        throw error;
    }
}

// SETTINGS

async function loadSettings() {
    try {
        const data = await fetchAPI("/settings");

        const settings = data.settings || {};
        const simulation = settings.simulation || {};
        const processMonitoring = settings.process_monitoring || {};

        setText(
            "simulation-status",
            simulation.enabled === true
                ? "Enabled"
                : simulation.enabled === false
                    ? "Disabled"
                    : "Not configured"
        );

        const threshold = processMonitoring.cpu_spike_threshold;

        setText(
            "cpu-threshold",
            threshold !== null && threshold !== undefined
                ? `${threshold}%`
                : "Not configured"
        );

    } catch (error) {
        console.error("Settings loading failed:", error);

        setText("simulation-status", "Unable to load");
        setText("cpu-threshold", "Unable to load");

        throw error;
    }
}

// JSON REPORT DOWNLOAD

async function downloadReport() {
    try {
        const report = await fetchAPI("/reports");

        const blob = new Blob(
            [JSON.stringify(report, null, 4)],
            { type: "application/json" }
        );

        const url = URL.createObjectURL(blob);

        const link = document.createElement("a");

        link.href = url;
        link.download = "rdrs_report.json";

        document.body.appendChild(link);
        link.click();
        link.remove();

        URL.revokeObjectURL(url);

    } catch (error) {
        console.error("JSON report download failed:", error);

        alert("Unable to download JSON report: " + error.message);
    }
}

// CSV REPORT DOWNLOAD

function downloadCSVReport() {
    const link = document.createElement("a");

    link.href = `${API_BASE}/reports/csv`;
    link.download = "rdrs_report.csv";

    document.body.appendChild(link);
    link.click();
    link.remove();
}

// DASHBOARD REFRESH

async function refreshDashboard() {
    try {
        await Promise.all([
            loadStatus(),
            loadEvents(),
            loadAlerts(),
            loadIncidents(),
            loadCPUChart(),
            loadSettings()
        ]);

        setConnectionStatus(true);

        setText(
            "last-updated",
            "Last updated: " + new Date().toLocaleTimeString()
        );

    } catch (error) {
        console.error("Dashboard error:", error);
        setConnectionStatus(false);
    }
}

// START DASHBOARD

document.addEventListener("DOMContentLoaded", () => {
    refreshDashboard();

    setInterval(refreshDashboard, 15000);
});
