let timeChartInst, ipChartInst, statusChartInst;

async function uploadFile() {
    const fileInput = document.getElementById('logFile');
    if (!fileInput.files.length) return alert('Select a file first.');

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    try {
        const response = await fetch('/upload', { method: 'POST', body: formData });
        const data = await response.json();
        
        if (data.error) throw new Error(data.error);

        updateDashboard(data);
        document.getElementById('dashboard').style.display = 'block';
        document.getElementById('exportBtn').disabled = false;
    } catch (err) {
        alert('Error processing logs: ' + err.message);
    }
}

function updateDashboard(data) {
    // Update Stats
    document.getElementById('s-total').innerText = data.stats.total;
    document.getElementById('s-parsed').innerText = data.stats.parsed;
    document.getElementById('s-unmapped').innerText = data.stats.unmapped;
    document.getElementById('s-dupes').innerText = data.stats.duplicates;
    document.getElementById('s-ips').innerText = data.stats.unique_ips;
    document.getElementById('s-anomalies').innerText = data.stats.anomalies;

    // Render Table
    const tbody = document.querySelector('#eventsTable tbody');
    tbody.innerHTML = '';
    data.records.forEach(rec => {
        const tr = document.createElement('tr');
        if (rec.anomaly) tr.className = 'anomaly-row';
        tr.innerHTML = `
            <td>${rec.timestamp || '-'}</td>
            <td>${rec.source_type || 'unknown'}</td>
            <td>${rec.src_ip || '-'}</td>
            <td>${rec.severity || '-'}</td>
            <td>${rec.action || '-'}</td>
            <td style="font-family: monospace; font-size: 0.85em;">${rec.event_template || '-'}</td>
            <td>${rec.parse_status}</td>
        `;
        tbody.appendChild(tr);
    });

    // Render Charts
    renderCharts(data);
}

function renderCharts(data) {
    Chart.defaults.color = '#fff';
    
    // Events Over Time (Line)
    if(timeChartInst) timeChartInst.destroy();
    timeChartInst = new Chart(document.getElementById('timeChart'), {
        type: 'line',
        data: {
            labels: Object.keys(data.charts.time_series),
            datasets: [{ label: 'Events/Minute', data: Object.values(data.charts.time_series), borderColor: '#e14eca', tension: 0.1 }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: 'Events Over Time' } } }
    });

    // Top IPs (Bar)
    if(ipChartInst) ipChartInst.destroy();
    ipChartInst = new Chart(document.getElementById('ipChart'), {
        type: 'bar',
        data: {
            labels: Object.keys(data.charts.top_ips),
            datasets: [{ label: 'Count', data: Object.values(data.charts.top_ips), backgroundColor: '#00f2c3' }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: 'Top Source IPs' } } }
    });

    // Parse Status (Pie)
    if(statusChartInst) statusChartInst.destroy();
    statusChartInst = new Chart(document.getElementById('statusChart'), {
        type: 'doughnut',
        data: {
            labels: ['Parsed', 'Unmapped'],
            datasets: [{ data: [data.stats.parsed, data.stats.unmapped], backgroundColor: ['#00f2c3', '#ff5b5b'] }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: 'Parse Status' } } }
    });
}