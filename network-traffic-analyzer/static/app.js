// 网络流量分析平台 - 前端应用
const API_BASE = '/api/v1';
let currentDatasetId = null;
let currentPage = 1;
const pageSize = 50;
let datasetRefreshTimer = null;
let dashboardDatasetId = '';

// ===== 认证相关 =====
function getAuthToken() {
    return localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token');
}

function getUsername() {
    return localStorage.getItem('username') || sessionStorage.getItem('username');
}

// 检查登录状态
async function checkAuth() {
    const token = getAuthToken();
    if (!token) {
        window.location.href = '/static/login.html';
        return false;
    }
    
    try {
        const response = await fetch(`${API_BASE}/auth/verify`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!response.ok) {
            localStorage.removeItem('auth_token');
            localStorage.removeItem('username');
            sessionStorage.removeItem('auth_token');
            sessionStorage.removeItem('username');
            window.location.href = '/static/login.html';
            return false;
        }
        
        const data = await response.json();
        // 更新显示的用户名
        const displayEl = document.getElementById('display-username');
        if (displayEl) {
            displayEl.textContent = data.display_name || data.username;
        }
        
        return true;
    } catch (error) {
        console.error('Auth check failed:', error);
        window.location.href = '/static/login.html';
        return false;
    }
}

// 登出
async function logout() {
    const token = getAuthToken();
    
    try {
        await fetch(`${API_BASE}/auth/logout`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
    } catch (error) {
        console.error('Logout error:', error);
    }
    
    localStorage.removeItem('auth_token');
    localStorage.removeItem('username');
    sessionStorage.removeItem('auth_token');
    sessionStorage.removeItem('username');
    
    window.location.href = '/static/login.html';
}

// 页面导航
document.querySelectorAll('.sidebar .nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const page = link.dataset.page;
        navigateToPage(page);
    });
});

function navigateToPage(page) {
    // 更新侧边栏激活状态
    document.querySelectorAll('.sidebar .nav-link').forEach(link => {
        link.classList.remove('active');
    });
    document.querySelector(`[data-page="${page}"]`).classList.add('active');
    
    // 显示对应页面
    document.querySelectorAll('#page-content > div').forEach(div => {
        div.classList.remove('active');
    });
    document.getElementById(`page-${page}`).classList.add('active');
    
    // 加载页面数据
    loadPageData(page);

    if (page === 'datasets') {
        startDatasetAutoRefresh();
    } else {
        stopDatasetAutoRefresh();
    }
}

function loadPageData(page) {
    switch(page) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'datasets':
            loadDatasets();
            break;
        case 'flows':
            loadDatasetOptions('flow-dataset');
            break;
        case 'dns':
            loadDatasetOptions('dns-dataset');
            break;
        case 'alerts':
            loadAlerts();
            break;
        case 'rules':
            loadRules();
            break;
    }
}

function startDatasetAutoRefresh() {
    stopDatasetAutoRefresh();
    datasetRefreshTimer = setInterval(() => {
        loadDatasets(true);
    }, 5000);
}

function stopDatasetAutoRefresh() {
    if (datasetRefreshTimer) {
        clearInterval(datasetRefreshTimer);
        datasetRefreshTimer = null;
    }
}

// Toast通知
function showToast(message, type = 'info') {
    const toastHtml = `
        <div class="toast align-items-center text-bg-${type} border-0" role="alert">
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;
    const container = document.getElementById('toast-container');
    container.insertAdjacentHTML('beforeend', toastHtml);
    const toastEl = container.lastElementChild;
    const toast = new bootstrap.Toast(toastEl, { delay: 3000 });
    toast.show();
    toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
}

// 仪表盘
async function loadDashboard() {
    try {
        const selected = document.getElementById('dashboard-dataset')?.value || '';
        dashboardDatasetId = selected;
        const query = selected ? `?dataset_id=${encodeURIComponent(selected)}` : '';
        const response = await fetch(`${API_BASE}/dashboard${query}`);
        const data = await response.json();
        
        // 更新统计卡片
        document.getElementById('stat-datasets').textContent = data.total_datasets;
        document.getElementById('stat-flows').textContent = formatNumber(data.total_flows);
        document.getElementById('stat-bytes').textContent = formatBytes(data.total_bytes);
        document.getElementById('stat-alerts').textContent = data.total_alerts;
        
        // 协议分布
        renderProtocolStats(data.protocol_distribution);
        
        // 告警分布
        renderAlertStats(data.alerts_by_type, data.alerts_by_severity);
        
        // Top IPs
        renderTopIPs(data.top_src_ips);
        
        // Top 域名
        renderTopDomains(data.top_domains);
        
    } catch (error) {
        showToast('加载仪表盘失败: ' + error.message, 'danger');
    }
}

function renderProtocolStats(data) {
    const container = document.getElementById('protocol-stats');
    let html = '';

    if (!data || Object.keys(data).length === 0) {
        container.innerHTML = '<p class="text-muted mb-0">暂无数据，请先导入PCAP</p>';
        return;
    }

    const total = Object.values(data).reduce((a, b) => a + b, 0);
    if (!total) {
        container.innerHTML = '<p class="text-muted mb-0">暂无数据，请先导入PCAP</p>';
        return;
    }
    
    for (const [proto, count] of Object.entries(data)) {
        const percent = ((count / total) * 100).toFixed(1);
        html += `
            <div class="mb-3">
                <div class="d-flex justify-content-between mb-1">
                    <span>${proto}</span>
                    <span>${formatNumber(count)} (${percent}%)</span>
                </div>
                <div class="progress">
                    <div class="progress-bar" style="width: ${percent}%"></div>
                </div>
            </div>
        `;
    }
    
    container.innerHTML = html || '<p class="text-muted mb-0">暂无数据</p>';
}

function renderAlertStats(data, severityData) {
    const container = document.getElementById('alert-stats');
    let html = '';
    
    const typeNames = {
        'port_scan': '端口扫描',
        'brute_force': '暴力破解',
        'dns_tunnel': 'DNS隧道',
        'c2_beacon': 'C2通信',
        'suspicious_dns': '可疑DNS'
    };
    
    if (severityData && Object.keys(severityData).length > 0) {
        const severityLabels = {
            critical: '严重',
            high: '高',
            medium: '中',
            low: '低',
            unknown: '未知'
        };
        const severityColors = {
            critical: 'danger',
            high: 'warning',
            medium: 'info',
            low: 'success',
            unknown: 'secondary'
        };

        html += '<div class="mb-2"><small class="text-muted">按严重程度</small></div>';
        for (const [severity, count] of Object.entries(severityData)) {
            html += `
                <div class="d-flex justify-content-between mb-2">
                    <span>${severityLabels[severity] || severity}</span>
                    <span class="badge bg-${severityColors[severity] || 'secondary'}">${count}</span>
                </div>
            `;
        }
    }

    if (data && Object.keys(data).length > 0) {
        html += '<div class="mt-3 mb-2"><small class="text-muted">按类型</small></div>';
        for (const [type, count] of Object.entries(data)) {
            html += `
                <div class="d-flex justify-content-between mb-2">
                    <span>${typeNames[type] || type}</span>
                    <span class="badge bg-danger">${count}</span>
                </div>
            `;
        }
    }

    container.innerHTML = html || '<p class="text-muted mb-0">暂无告警</p>';
}

function renderTopIPs(data) {
    const container = document.getElementById('top-src-ips');
    if (!data || data.length === 0) {
        container.innerHTML = '<p class="text-muted mb-0">暂无数据</p>';
        return;
    }

    let html = '<div class="list-group list-group-flush">';

    data.forEach((item, index) => {
        html += `
            <div class="list-group-item bg-transparent border-secondary d-flex justify-content-between align-items-center">
                <button class="btn btn-link p-0 text-start text-decoration-none" onclick="jumpToFlows('${item.ip}')">
                    #${index + 1} ${item.ip}
                </button>
                <span class="text-muted">${formatBytes(item.bytes)}</span>
            </div>
        `;
    });

    html += '</div>';
    container.innerHTML = html;
}

function renderTopDomains(data) {
    const container = document.getElementById('top-domains');
    if (!data || data.length === 0) {
        container.innerHTML = '<p class="text-muted mb-0">暂无数据</p>';
        return;
    }

    let html = '<div class="list-group list-group-flush">';

    data.forEach((item, index) => {
        html += `
            <div class="list-group-item bg-transparent border-secondary d-flex justify-content-between align-items-center">
                <button class="btn btn-link p-0 text-start text-decoration-none" onclick="jumpToDns('${item.domain}')">
                    #${index + 1} ${item.domain}
                </button>
                <span class="badge bg-primary">${item.count}</span>
            </div>
        `;
    });

    html += '</div>';
    container.innerHTML = html;
}

// 数据集管理
async function loadDatasets(silent = false) {
    try {
        const response = await fetch(`${API_BASE}/datasets?limit=100`);
        const data = await response.json();
        
        const tbody = document.getElementById('datasets-table');
        tbody.innerHTML = '';
        
        data.items.forEach(dataset => {
            const row = `
                <tr>
                    <td><strong>${dataset.name}</strong></td>
                    <td><small class="text-muted">${dataset.filename}</small></td>
                    <td>${formatBytes(dataset.file_size)}</td>
                    <td>${renderStatus(dataset.status, dataset.progress)}</td>
                    <td>${formatNumber(dataset.total_flows)}</td>
                    <td><small>${formatDateTime(dataset.start_time)} ~ ${formatDateTime(dataset.end_time)}</small></td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary" onclick="viewDataset('${dataset.id}')">
                            <i class="bi bi-eye"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-info" onclick="exportReport('${dataset.id}')">
                            <i class="bi bi-download"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="deleteDataset('${dataset.id}')">
                            <i class="bi bi-trash"></i>
                        </button>
                    </td>
                </tr>
            `;
            tbody.innerHTML += row;
        });
        
    } catch (error) {
        if (!silent) {
            showToast('加载数据集失败: ' + error.message, 'danger');
        }
    }
}

async function viewDataset(id) {
    try {
        const [datasetResp, statsResp] = await Promise.all([
            fetch(`${API_BASE}/datasets/${id}`),
            fetch(`${API_BASE}/datasets/${id}/stats`)
        ]);

        if (!datasetResp.ok) {
            throw new Error('获取数据集失败');
        }

        const dataset = await datasetResp.json();
        const stats = statsResp.ok ? await statsResp.json() : null;

        document.getElementById('detail-name').textContent = dataset.name || '-';
        document.getElementById('detail-filename').textContent = dataset.filename || '-';
        document.getElementById('detail-status').innerHTML = renderStatus(dataset.status, dataset.progress);
        document.getElementById('detail-size').textContent = formatBytes(dataset.file_size || 0);
        document.getElementById('detail-created').textContent = formatDateTime(dataset.created_at);
        document.getElementById('detail-time-range').textContent = `${formatDateTime(dataset.start_time)} ~ ${formatDateTime(dataset.end_time)}`;

        document.getElementById('detail-flows').textContent = formatNumber(dataset.total_flows || 0);
        document.getElementById('detail-packets').textContent = formatNumber(dataset.total_packets || 0);
        document.getElementById('detail-bytes').textContent = formatBytes(dataset.total_bytes || 0);
        document.getElementById('detail-unique-ips').textContent = stats ? formatNumber((stats.unique_src_ips || 0) + (stats.unique_dst_ips || 0)) : '-';

        renderKeyValueList('detail-protocols', stats?.protocol_distribution, '暂无数据');
        renderTopList('detail-top-talkers', stats?.top_talkers, (item, idx) => `#${idx + 1} ${item.ip} (${formatBytes(item.bytes)})`);
        renderTopList('detail-top-ports', stats?.top_ports, (item, idx) => `#${idx + 1} ${item.port} (${formatNumber(item.count)})`);

        const modal = new bootstrap.Modal(document.getElementById('datasetDetailModal'));
        modal.show();
    } catch (error) {
        showToast('加载数据集详情失败: ' + error.message, 'danger');
    }
}

function renderKeyValueList(containerId, data, emptyText) {
    const container = document.getElementById(containerId);
    if (!data || Object.keys(data).length === 0) {
        container.innerHTML = `<p class="text-muted mb-0">${emptyText}</p>`;
        return;
    }

    let html = '<div class="list-group list-group-flush">';
    for (const [key, value] of Object.entries(data)) {
        html += `
            <div class="list-group-item bg-transparent border-secondary d-flex justify-content-between align-items-center">
                <span>${key}</span>
                <span class="badge bg-primary">${formatNumber(value)}</span>
            </div>
        `;
    }
    html += '</div>';
    container.innerHTML = html;
}

function renderTopList(containerId, items, renderItem) {
    const container = document.getElementById(containerId);
    if (!items || items.length === 0) {
        container.innerHTML = '<p class="text-muted mb-0">暂无数据</p>';
        return;
    }

    let html = '<div class="list-group list-group-flush">';
    items.forEach((item, index) => {
        html += `
            <div class="list-group-item bg-transparent border-secondary">
                ${renderItem(item, index)}
            </div>
        `;
    });
    html += '</div>';
    container.innerHTML = html;
}

function renderStatus(status, progress) {
    const statusMap = {
        'pending': '<span class="badge bg-secondary">待处理</span>',
        'running': `<span class="badge bg-primary">处理中 ${progress.toFixed(0)}%</span>`,
        'done': '<span class="badge bg-success">已完成</span>',
        'failed': '<span class="badge bg-danger">失败</span>'
    };
    return statusMap[status] || status;
}

// 上传PCAP
function showUploadModal() {
    const modal = new bootstrap.Modal(document.getElementById('uploadModal'));
    modal.show();
}

document.getElementById('upload-zone').addEventListener('click', () => {
    document.getElementById('upload-file').click();
});

document.getElementById('upload-file').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
        document.getElementById('upload-filename').textContent = file.name;
    }
});

// 拖拽上传
const uploadZone = document.getElementById('upload-zone');
uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.classList.add('dragover');
});

uploadZone.addEventListener('dragleave', () => {
    uploadZone.classList.remove('dragover');
});

uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) {
        document.getElementById('upload-file').files = e.dataTransfer.files;
        document.getElementById('upload-filename').textContent = file.name;
    }
});

async function uploadPcap() {
    const fileInput = document.getElementById('upload-file');
    const file = fileInput.files[0];
    
    if (!file) {
        showToast('请选择文件', 'warning');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    const name = document.getElementById('upload-name').value;
    if (name) {
        formData.append('name', name);
    }
    
    document.getElementById('upload-progress').style.display = 'block';
    document.getElementById('upload-btn').disabled = true;
    
    try {
        const xhr = new XMLHttpRequest();
        
        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
                const percent = (e.loaded / e.total) * 100;
                document.getElementById('upload-progress-bar').style.width = percent + '%';
                document.getElementById('upload-percent').textContent = percent.toFixed(0) + '%';
            }
        });
        
        xhr.addEventListener('load', () => {
            if (xhr.status === 200) {
                showToast('上传成功，正在解析...', 'success');
                bootstrap.Modal.getInstance(document.getElementById('uploadModal')).hide();
                setTimeout(() => loadDatasets(), 2000);
            } else {
                showToast('上传失败: ' + xhr.statusText, 'danger');
            }
            document.getElementById('upload-btn').disabled = false;
        });
        
        xhr.open('POST', `${API_BASE}/datasets/import`);
        xhr.send(formData);
        
    } catch (error) {
        showToast('上传失败: ' + error.message, 'danger');
        document.getElementById('upload-btn').disabled = false;
    }
}

async function deleteDataset(id) {
    if (!confirm('确定要删除此数据集吗？')) return;
    
    try {
        await fetch(`${API_BASE}/datasets/${id}`, { method: 'DELETE' });
        showToast('删除成功', 'success');
        loadDatasets();
    } catch (error) {
        showToast('删除失败: ' + error.message, 'danger');
    }
}

function exportReport(id) {
    window.open(`${API_BASE}/export/report/${id}/html`, '_blank');
}

// 流量查询
async function loadDatasetOptions(selectId, options = {}) {
    try {
        const response = await fetch(`${API_BASE}/datasets?limit=100`);
        const data = await response.json();
        const onlyDone = options.onlyDone !== undefined ? options.onlyDone : true;
        const includeAll = options.includeAll !== undefined ? options.includeAll : true;
        const selectedValue = options.selectedValue || '';

        const select = document.getElementById(selectId);
        select.innerHTML = includeAll ? '<option value="">所有数据集</option>' : '';
        
        data.items.forEach(dataset => {
            if (!onlyDone || dataset.status === 'done') {
                select.innerHTML += `<option value="${dataset.id}">${dataset.name}</option>`;
            }
        });

        if (selectedValue) {
            select.value = selectedValue;
        }

        return data;
    } catch (error) {
        console.error('加载数据集选项失败:', error);
    }
}

async function jumpToFlows(srcIp) {
    const datasetId = dashboardDatasetId;
    navigateToPage('flows');
    await loadDatasetOptions('flow-dataset', { selectedValue: datasetId });
    document.getElementById('flow-src-ip').value = srcIp;
    searchFlows();
}

async function jumpToDns(domain) {
    const datasetId = dashboardDatasetId;
    navigateToPage('dns');
    await loadDatasetOptions('dns-dataset', { selectedValue: datasetId });
    document.getElementById('dns-query-name').value = domain;
    searchDns();
}

async function searchFlows() {
    const params = new URLSearchParams();
    
    const dataset = document.getElementById('flow-dataset').value;
    if (dataset) params.append('dataset_id', dataset);
    
    const srcIp = document.getElementById('flow-src-ip').value;
    if (srcIp) params.append('src_ip', srcIp);
    
    const dstIp = document.getElementById('flow-dst-ip').value;
    if (dstIp) params.append('dst_ip', dstIp);
    
    const dstPort = document.getElementById('flow-dst-port').value;
    if (dstPort) params.append('dst_port', dstPort);
    
    const protocol = document.getElementById('flow-protocol').value;
    if (protocol) params.append('protocol', protocol);
    
    params.append('limit', pageSize);
    params.append('offset', (currentPage - 1) * pageSize);
    
    try {
        const response = await fetch(`${API_BASE}/flows?${params}`);
        const data = await response.json();
        
        renderFlowsTable(data.items);
        document.getElementById('flows-count').textContent = `共 ${data.total} 条`;
        
    } catch (error) {
        showToast('查询失败: ' + error.message, 'danger');
    }
}

function renderFlowsTable(flows) {
    const tbody = document.getElementById('flows-table');
    tbody.innerHTML = '';
    
    flows.forEach(flow => {
        const proto = flow.protocol === 6 ? 'TCP' : flow.protocol === 17 ? 'UDP' : flow.protocol === 1 ? 'ICMP' : 'Other';
        const protoClass = proto.toLowerCase();
        
        const row = `
            <tr>
                <td><small>${formatDateTime(flow.ts_start)}</small></td>
                <td><code>${flow.src_ip}:${flow.src_port}</code></td>
                <td><code>${flow.dst_ip}:${flow.dst_port}</code></td>
                <td><span class="protocol-badge protocol-${protoClass}">${proto}</span></td>
                <td>${flow.packets_up + flow.packets_down}</td>
                <td>${formatBytes(flow.bytes_up + flow.bytes_down)}</td>
                <td><span class="badge bg-secondary">${flow.state}</span></td>
                <td>${flow.app_protocol || '-'}</td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
}

// DNS查询
async function searchDns() {
    const params = new URLSearchParams();
    
    const dataset = document.getElementById('dns-dataset').value;
    if (dataset) params.append('dataset_id', dataset);
    
    const queryName = document.getElementById('dns-query-name').value;
    if (queryName) params.append('query_name', queryName);
    
    const queryType = document.getElementById('dns-query-type').value;
    if (queryType) params.append('query_type', queryType);
    
    const responseCode = document.getElementById('dns-response-code').value;
    if (responseCode) params.append('response_code', responseCode);
    
    params.append('limit', 100);
    
    try {
        const response = await fetch(`${API_BASE}/dns?${params}`);
        const data = await response.json();
        
        renderDnsTable(data.items);
        
    } catch (error) {
        showToast('查询失败: ' + error.message, 'danger');
    }
}

function renderDnsTable(events) {
    const tbody = document.getElementById('dns-table');
    tbody.innerHTML = '';
    
    events.forEach(event => {
        const row = `
            <tr>
                <td><small>${formatDateTime(event.timestamp)}</small></td>
                <td><code>${event.src_ip}</code></td>
                <td>${event.query_name}</td>
                <td><span class="badge bg-info">${event.query_type || '-'}</span></td>
                <td>${event.response_code || '-'}</td>
                <td>${event.entropy ? event.entropy.toFixed(2) : '-'}</td>
                <td>${event.subdomain_count}</td>
            </tr>
        `;
        tbody.innerHTML += row;
    });
}

// 告警管理
async function loadAlerts() {
    const params = new URLSearchParams();
    
    const severity = document.getElementById('alert-severity-filter').value;
    if (severity) params.append('severity', severity);
    
    const type = document.getElementById('alert-type-filter').value;
    if (type) params.append('alert_type', type);
    
    params.append('limit', 50);
    
    try {
        const response = await fetch(`${API_BASE}/alerts?${params}`);
        const data = await response.json();
        
        renderAlerts(data.items);
        
    } catch (error) {
        showToast('加载告警失败: ' + error.message, 'danger');
    }
}

function renderAlerts(alerts) {
    const container = document.getElementById('alerts-list');
    container.innerHTML = '';
    
    alerts.forEach(alert => {
        const severityClass = alert.severity || 'medium';
        
        const item = `
            <div class="alert-item ${severityClass}">
                <div class="d-flex justify-content-between align-items-start mb-2">
                    <div>
                        <span class="badge badge-${severityClass} me-2">${alert.severity?.toUpperCase() || 'UNKNOWN'}</span>
                        <span class="badge bg-secondary">${alert.alert_type}</span>
                    </div>
                    <small class="text-muted">${formatDateTime(alert.ts_start)}</small>
                </div>
                <h6>${alert.title}</h6>
                <p class="mb-2">${alert.description}</p>
                <div class="d-flex justify-content-between">
                    <div>
                        <small class="text-muted">评分: ${alert.score.toFixed(1)}</small>
                        ${alert.src_ip ? `<small class="text-muted ms-3">源: <code>${alert.src_ip}</code></small>` : ''}
                    </div>
                    <div>
                        <button class="btn btn-sm btn-outline-success" onclick="closeAlert(${alert.id})">
                            <i class="bi bi-check"></i> 关闭
                        </button>
                        <button class="btn btn-sm btn-outline-warning" onclick="markFalsePositive(${alert.id})">
                            误报
                        </button>
                    </div>
                </div>
            </div>
        `;
        container.innerHTML += item;
    });
}

async function closeAlert(id) {
    try {
        await fetch(`${API_BASE}/alerts/${id}/close`, { method: 'POST' });
        showToast('告警已关闭', 'success');
        loadAlerts();
    } catch (error) {
        showToast('操作失败: ' + error.message, 'danger');
    }
}

async function markFalsePositive(id) {
    try {
        await fetch(`${API_BASE}/alerts/${id}/false-positive`, { method: 'POST' });
        showToast('已标记为误报', 'success');
        loadAlerts();
    } catch (error) {
        showToast('操作失败: ' + error.message, 'danger');
    }
}

// 规则管理
async function loadRules() {
    try {
        const response = await fetch(`${API_BASE}/rules`);
        const rules = await response.json();
        
        const container = document.getElementById('rules-list');
        container.innerHTML = '';
        
        rules.forEach(rule => {
            const card = `
                <div class="col-md-6">
                    <div class="card p-4">
                        <div class="d-flex justify-content-between align-items-start mb-3">
                            <h5>${rule.name}</h5>
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" id="rule-${rule.rule_id}" 
                                       ${rule.enabled ? 'checked' : ''} 
                                       onchange="toggleRule('${rule.rule_id}', this.checked)">
                            </div>
                        </div>
                        <p class="text-muted mb-3">${rule.description || '暂无描述'}</p>
                        <div>
                            <span class="badge bg-secondary me-2">${rule.alert_type}</span>
                            <span class="badge badge-${rule.severity}">${rule.severity}</span>
                        </div>
                    </div>
                </div>
            `;
            container.innerHTML += card;
        });
        
    } catch (error) {
        showToast('加载规则失败: ' + error.message, 'danger');
    }
}

async function toggleRule(ruleId, enabled) {
    try {
        const endpoint = enabled ? 'enable' : 'disable';
        await fetch(`${API_BASE}/rules/${ruleId}/${endpoint}`, { method: 'POST' });
        showToast(`规则已${enabled ? '启用' : '禁用'}`, 'success');
    } catch (error) {
        showToast('操作失败: ' + error.message, 'danger');
    }
}

window.showAddRuleModal = function() {
    console.log('showAddRuleModal called');
    const modalEl = document.getElementById('addRuleModal');
    console.log('Modal element:', modalEl);
    
    if (!modalEl) {
        console.error('Modal element not found!');
        return;
    }
    
    // 清空表单
    document.getElementById('new-rule-id').value = '';
    document.getElementById('new-rule-name').value = '';
    document.getElementById('new-rule-description').value = '';
    document.getElementById('new-rule-alert-type').value = 'anomaly';
    document.getElementById('new-rule-severity').value = 'medium';
    document.getElementById('new-rule-enabled').checked = true;
    
    const modal = new bootstrap.Modal(modalEl);
    modal.show();
}

window.addRule = async function() {
    const ruleId = document.getElementById('new-rule-id').value.trim();
    const name = document.getElementById('new-rule-name').value.trim();
    const description = document.getElementById('new-rule-description').value.trim();
    const alertType = document.getElementById('new-rule-alert-type').value;
    const severity = document.getElementById('new-rule-severity').value;
    const enabled = document.getElementById('new-rule-enabled').checked;

    if (!ruleId || !name) {
        showToast('请填写规则ID和名称', 'warning');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/rules`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                rule_id: ruleId,
                name: name,
                description: description,
                alert_type: alertType,
                severity: severity,
                enabled: enabled
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || '添加规则失败');
        }

        showToast('规则添加成功', 'success');
        bootstrap.Modal.getInstance(document.getElementById('addRuleModal')).hide();
        loadRules();
    } catch (error) {
        showToast('添加规则失败: ' + error.message, 'danger');
    }
}

// 工具函数
function formatNumber(num) {
    return new Intl.NumberFormat('zh-CN').format(num);
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
}

function formatDateTime(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleString('zh-CN', { 
        year: 'numeric', 
        month: '2-digit', 
        day: '2-digit', 
        hour: '2-digit', 
        minute: '2-digit' 
    });
}

// 初始化
document.addEventListener('DOMContentLoaded', async () => {
    // 首先检查登录状态
    const isAuthenticated = await checkAuth();
    if (!isAuthenticated) {
        return; // 未登录，已跳转到登录页
    }
    
    loadDatasetOptions('dashboard-dataset', { includeAll: true, onlyDone: false }).then(() => {
        const dashboardSelect = document.getElementById('dashboard-dataset');
        if (dashboardSelect) {
            dashboardSelect.addEventListener('change', () => loadDashboard());
        }
    });
    loadDashboard();

    // 绑定新增规则按钮
    const addRuleBtn = document.getElementById('btn-add-rule');
    if (addRuleBtn) {
        addRuleBtn.addEventListener('click', function() {
            const modalEl = document.getElementById('addRuleModal');
            if (modalEl) {
                // 清空表单
                document.getElementById('new-rule-id').value = '';
                document.getElementById('new-rule-name').value = '';
                document.getElementById('new-rule-description').value = '';
                document.getElementById('new-rule-alert-type').value = 'anomaly';
                document.getElementById('new-rule-severity').value = 'medium';
                document.getElementById('new-rule-enabled').checked = true;
                
                const modal = new bootstrap.Modal(modalEl);
                modal.show();
            } else {
                alert('模态框元素未找到');
            }
        });
    }
});

// 定期刷新数据集状态
setInterval(() => {
    const currentPageEl = document.querySelector('#page-datasets.active');
    if (currentPageEl) {
        loadDatasets();
    }
}, 5000);
