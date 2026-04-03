// Expose UI-level functions to window immediately for global onclick access
window.pingESP = pingESP;
window.resetAll = resetAll;
window.deployDFA = deployDFA;
window.switchProtocol = switchProtocol;
window.triggerEvent = triggerEvent;
window.viewSummary = () => {
    log('Navigating to Detailed Forensic Summary...', 'l-sys');
    showToast('Loading Analytics...', 'analytics');
    setTimeout(() => navigate('record.html'), 800);
};

const PROTOCOL_CONFIG = {
    TCP: {
        id: "TCP",
        title: "TCP_CORE_V4",
        desc: "Monitoring connection establishment and data flow sequences",
        states: { 0: 'CLOSED', 1: 'SYN_SENT', 2: 'SYN_RCVD', 3: 'ESTABLISHED', 4: 'FIN_WAIT', 5: 'TIME_WAIT', 6: 'FLOOD', 9: 'TRAP' },
        nodes: [0, 1, 2, 3, 4, 5, 6, 9],
        categories: [
            { label: "Handshake", events: ["TCP_SYN", "TCP_SYNACK", "TCP_ACK"], type: "normal" },
            { label: "Termination", events: ["TCP_FIN", "TCP_RST"], type: "normal" },
            { label: "Flood Attack", events: ["TCP_SYN"], type: "alert" },
            { label: "Reset Violation", events: ["TCP_RST"], type: "violation" }
        ]
    },
    HTTP: {
        id: "HTTP",
        title: "HTTP_API_WATCH",
        desc: "Analyzing RESTful headers, verb patterns and response signatures",
        states: { 0: 'IDLE', 1: 'GET_SENT', 2: 'POST_SENT', 3: 'AUTH_SENT', 4: 'RESPONDED', 7: 'DEL_FLOOD', 9: 'TRAP' },
        nodes: [0, 1, 2, 3, 4, 7, 9],
        categories: [
            { label: "API Methods", events: ["HTTP_GET", "HTTP_POST", "HTTP_RESP"], type: "normal" },
            { label: "Authentication", events: ["HTTP_AUTH"], type: "normal" },
            { label: "Flood Attack", events: ["HTTP_DELETE"], type: "alert" },
            { label: "Unauth Violation", events: ["HTTP_AUTH"], type: "violation" }
        ]
    },
    MQTT: {
        id: "MQTT",
        title: "MQTT_MOSQUITTO_CORE",
        desc: "Surveillance of client subscriptions and message broadcast stability",
        states: { 0: 'DISCONNECTED', 1: 'CONNECTING', 2: 'CONNECTED', 3: 'PUBLISHING', 4: 'PUBACK_WAIT', 5: 'ACTIVE', 8: 'PUB_FLOOD', 9: 'TRAP' },
        nodes: [0, 1, 2, 3, 4, 5, 8, 9],
        categories: [
            { label: "Session", events: ["MQTT_CONNECT", "MQTT_CONNACK", "MQTT_DISC"], type: "normal" },
            { label: "Publishing", events: ["MQTT_PUBLISH", "MQTT_PUBACK"], type: "normal" },
            { label: "Flood Attack", events: ["MQTT_PUBLISH"], type: "alert" },
            { label: "State Violation", events: ["MQTT_DISC"], type: "violation" }
        ]
    }
};

let activeProtocol = 'TCP';

/* ---- UI HELPERS ---- */

const getIp = () => document.getElementById('esp32-ip')?.value.trim() || '192.168.1.100';
const getTs = () => new Date().toLocaleTimeString('en-GB', { hour12: false });

function log(msg, cls = 'l-sys') {
    const d = document.getElementById('terminal-output');
    if (!d) return;
    const wrap = document.createElement('div');
    wrap.className = "py-0.5 border-b border-outline/5 last:border-0";

    let colorCls = "text-on-surface-variant";
    if (cls === 'l-ok') colorCls = "text-primary font-medium";
    if (cls === 'l-vio') colorCls = "text-error font-bold";
    if (cls === 'l-int') colorCls = "text-secondary font-bold italic";

    wrap.innerHTML = `<span class="opacity-30 mr-2">[${getTs()}]</span> <span class="${colorCls}">${msg}</span>`;
    d.appendChild(wrap);
    d.scrollTop = d.scrollHeight;
}

function showToast(msg, icon) {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.querySelector('.material-symbols-outlined').innerText = icon;
    toast.querySelector('span:last-child').innerText = msg;
    toast.classList.remove('translate-y-20', 'opacity-0');
    setTimeout(() => toast.classList.add('translate-y-20', 'opacity-0'), 2500);
}

/* ---- CORE ACTIONS (UI LEVEL) ---- */

async function pingESP() {
    log('Initiating system heartbeat check...', 'l-sys');
    const res = await apiPingESP(getIp()); // Call the API function from api.js
    if (res.ok) {
        res.states.forEach(s => updateUI(s.dfa, s.state, 'ok'));
        log('ESP32 online and synced.', 'l-ok');
        showToast('Heartbeat Received', 'check_circle');
    } else {
        log(`Connection failed: ${res.error}`, 'l-vio');
        showToast('ESP32 Unreachable', 'error');
    }
}

async function resetAll() {
    log('Sending global DFA reset signal...', 'l-sys');
    const res = await apiResetAll(getIp()); 
    if (res.ok) {
        ['TCP', 'HTTP', 'MQTT'].forEach(d => updateUI(d, 0, 'ok'));
        document.getElementById('alert-banner')?.classList.add('hidden');
        log('All state machines reset to q0.', 'l-ok');
        showToast('All DFAs Reset', 'refresh');
    } else {
        log(`Reset failed: ${res.error}`, 'l-vio');
    }
}

async function triggerEvent(event) {
    const res = await apiTriggerEvent(event, getIp());
    if (res.ok) {
        res.results.forEach(r => {
            updateUI(r.dfa, r.to, r.status, r.severity);
            
            if (r.status === 'intrusion' || r.status === 'violation') {
                recordAttack({
                    event: event,
                    dfa: r.dfa,
                    from: r.from,
                    to: r.to,
                    status: r.status,
                    severity: r.severity
                });
                renderRecentAttacks();
            }

            const logCls = r.status === 'intrusion' ? 'l-int' : (r.status === 'violation' ? 'l-vio' : 'l-ok');
            const badge = `<span class="px-1.5 py-0.5 rounded text-[8px] font-bold mr-2 bg-${r.dfa.toLowerCase()}-container text-on-${r.dfa.toLowerCase()}-container">${r.dfa}</span>`;
            log(`${badge} ${event} | q${r.from} → q${r.to} [${r.status.toUpperCase()}]`, logCls);
        });
    } else {
        log(`Trigger failed: ${res.error}`, 'l-vio');
    }
}

async function deployDFA() {
    log('Broadcasting global DFA configuration...', 'l-sys');
    const res = await apiDeployDFA(getIp());
    if (res.ok) {
        log('DFA Logic successfully deployed to ESP32 core.', 'l-ok');
        showToast('DFA Deployed', 'rocket_launch');
    } else {
        log(`Deployment failed: ${res.error}`, 'l-vio');
        showToast('Deployment Failed', 'error');
    }
}

async function syncHardwareLogs() {
    const ip = getIp();
    try {
        const res = await apiFetchHardwareLogs(ip);
        if (res.ok && res.log.length > 0) {
            const d = document.getElementById('terminal-output');
            if (d) {
                // Keep minimal layout and append logs
                if (res.log.some(l => l.includes('[BOOT]') || l.includes('[RESET]'))) {
                     d.innerHTML = '<p class="text-primary/40 text-[10px] uppercase font-bold mb-2">--- Hardware Log Stream ---</p>';
                }
                res.log.forEach(line => {
                    const wrap = document.createElement('div');
                    wrap.className = "py-0.5 border-b border-outline/5 last:border-0 font-mono text-[11px]";
                    let colorCls = "text-on-surface-variant";
                    if (line.includes('[!]')) colorCls = "text-error font-bold";
                    if (line.includes('[!!!]')) colorCls = "text-secondary font-bold italic";
                    if (line.includes('[BOOT]') || line.includes('[RESET]')) colorCls = "text-primary font-medium";
                    wrap.innerHTML = `<span class="${colorCls}">${line}</span>`;
                    d.appendChild(wrap);
                });
                d.scrollTop = d.scrollHeight;
            }
        }
    } catch (e) {
        console.warn('[SYS] Log sync current failure.');
    }
}

/* ---- UI UPDATES ---- */

function updateUI(dfa, state, status, severity = 'LOW') {
    if (dfa !== activeProtocol) return;

    const config = PROTOCOL_CONFIG[dfa];
    const stateBig = document.getElementById('state-big');
    const stateName = document.getElementById('state-name-label');
    const banner = document.getElementById('alert-banner');
    const violationCount = document.getElementById('violation-count');

    if (stateBig) {
        stateBig.innerText = `q${state}`;
        stateBig.className = "font-headline font-black text-7xl md:text-8xl text-primary tracking-tighter transition-all duration-500";
        if (status === 'intrusion' || status === 'violation') {
            stateBig.classList.add(status === 'intrusion' ? 'text-secondary' : 'text-error', 'animate-pulse');
        }
    }

    if (stateName) stateName.innerText = config.states[state] || `STATE_Q${state}`;
    if (banner && (status === 'intrusion' || status === 'violation')) banner.classList.remove('hidden');
    if (violationCount && status === 'violation') violationCount.innerText = parseInt(violationCount.innerText) + 1;

    createMiniNodes(dfa, state, status);
    const activeLabel = document.getElementById('active-state-label');
    if (activeLabel) activeLabel.innerText = `${config.states[state] || 'q' + state} (q${state})`;
    
    renderRecentAttacks();
}

function renderRecentAttacks() {
    const tbody = document.getElementById('records-table-body');
    if (!tbody) return;

    const recent = getRecentAttacks(5);
    tbody.innerHTML = '';

    if (recent.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-8 text-center text-on-surface-variant/40 italic">No security incidents recorded.</td></tr>`;
        return;
    }

    recent.forEach(entry => {
        const tr = document.createElement('tr');
        tr.className = "hover:bg-primary/5 transition-colors group border-b border-outline/5";
        
        const time = new Date(entry.time).toLocaleTimeString('en-GB', { hour12: false });
        const typeCls = entry.type === 'intrusion' ? 'bg-secondary-container text-on-secondary-container' : 'bg-error-container text-on-error-container';
        
        tr.innerHTML = `
            <td class="px-4 py-2 text-on-surface-variant">${time}</td>
            <td class="px-4 py-2 font-medium text-on-surface">${entry.event.replace(entry.protocol + '_', '')}</td>
            <td class="px-4 py-2 text-on-surface-variant">${entry.protocol}</td>
            <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-md text-[9px] font-bold uppercase ${typeCls}">${entry.type}</span></td>
            <td class="px-4 py-2 text-right"><button onclick="window.location.href='record.html'" class="text-primary hover:underline font-bold">Details</button></td>
        `;
        tbody.appendChild(tr);
    });
}

function createMiniNodes(dfa, activeState = 0, status = 'ok') {
    const container = document.getElementById('mini-nodes');
    if (!container) return;
    const nodes = PROTOCOL_CONFIG[dfa].nodes;
    container.innerHTML = '';

    nodes.forEach(n => {
        const div = document.createElement('div');
        const isActive = n === activeState;
        const isTrap = n === 9;
        const isWarn = n === 6 || n === 7 || n === 8;

        let bgCls = "bg-surface-container-highest text-on-surface-variant/40 border-outline/10";
        if (isActive) {
            bgCls = "bg-primary text-on-primary border-primary ring-4 ring-primary/20 scale-110";
            if (status === 'intrusion') bgCls = "bg-secondary text-white border-secondary ring-4 ring-secondary/20";
            if (status === 'violation' || isTrap) bgCls = "bg-error text-white border-error ring-4 ring-error/20";
        } else if (isTrap) {
            bgCls = "bg-error/10 text-error border-error/20";
        } else if (isWarn) {
            bgCls = "bg-secondary/10 text-secondary border-secondary/20";
        }

        div.className = `w-7 h-7 rounded-full flex items-center justify-center text-[9px] font-bold border transition-all duration-300 ${bgCls}`;
        div.innerText = isTrap ? 'T' : n;
        container.appendChild(div);
    });
}

function switchProtocol(protocolKey) {
    activeProtocol = protocolKey;
    const config = PROTOCOL_CONFIG[protocolKey];

    // Sidebar Active State
    document.querySelectorAll('#protocol-nav a').forEach(l => {
        const isMatch = l.innerText.includes(protocolKey);
        l.className = isMatch ?
            "flex items-center gap-4 py-3 px-6 bg-primary/10 text-primary border-r-4 border-primary font-bold text-xs uppercase tracking-widest transition-all rounded-l-xl cursor-pointer" :
            "flex items-center gap-4 py-3 px-6 text-on-surface-variant hover:bg-surface-container-highest transition-all text-xs uppercase tracking-widest font-bold rounded-l-xl mx-2 cursor-pointer";
    });

    const title = document.getElementById('engine-title');
    const desc = document.getElementById('engine-desc');
    const badge = document.getElementById('protocol-badge');
    const simTitle = document.getElementById('sim-title');

    if (title) title.innerText = config.title;
    if (desc) desc.innerText = config.desc;
    if (badge) badge.innerText = protocolKey + "_PROC";
    if (simTitle) simTitle.innerText = `${protocolKey} Session Control`;

    // Build Categorized Buttons
    const catContainer = document.getElementById('sim-categories');
    if (catContainer) {
        catContainer.innerHTML = '';
        config.categories.forEach(cat => {
            const wrap = document.createElement('div');
            wrap.className = "p-3 bg-surface-container/50 rounded-xl border border-outline/5";

            const label = document.createElement('p');
            label.className = "text-[9px] font-bold uppercase tracking-widest text-on-surface-variant mb-2 opacity-60";
            label.innerText = cat.label;
            wrap.appendChild(label);

            const btnGrid = document.createElement('div');
            btnGrid.className = "flex flex-wrap gap-2";

            cat.events.forEach(ev => {
                const btn = document.createElement('button');
                let btnCls = "px-3 py-1.5 rounded-lg border text-[10px] font-bold tracking-tighter uppercase transition-all ";
                if (cat.type === 'normal') btnCls += "bg-surface-container-low border-outline/10 text-on-surface hover:border-primary hover:text-primary";
                if (cat.type === 'alert') btnCls += "bg-secondary/10 border-secondary/20 text-secondary hover:bg-secondary hover:text-white";
                if (cat.type === 'violation') btnCls += "bg-error/10 border-error/20 text-error hover:bg-error hover:text-white";

                btn.className = btnCls;
                btn.innerText = ev.replace(protocolKey + '_', '');
                btn.onclick = () => triggerEvent(ev);
                btnGrid.appendChild(btn);
            });
            wrap.appendChild(btnGrid);
            catContainer.appendChild(wrap);
        });
    }

    createMiniNodes(protocolKey);
    updateUI(protocolKey, 0, 'ok');
}

/* ---- INITIALIZATION ---- */

window.addEventListener('load', () => {
    // Check for protocol redirect in URL
    const urlParams = new URLSearchParams(window.location.search);
    const requestedProtocol = urlParams.get('protocol');
    if (requestedProtocol && PROTOCOL_CONFIG[requestedProtocol]) {
        switchProtocol(requestedProtocol);
    } else {
        switchProtocol('TCP');
    }

    pingESP(); // Initial Sync
    renderRecentAttacks();
    initTheme(); // Sync UI with saved preference

    // Start hardware log sync every 8 seconds
    setInterval(syncHardwareLogs, 8000);
});
