/* ---- ESP32 COMMUNICATION MODULE ---- */

async function apiPingESP(ip) {
    console.log(`[SYS] Initiating heartbeat check to ${ip}...`);
    try {
        const response = await fetch(`http://${ip}/state`);
        if (response.ok) {
            const data = await response.json();
            console.log('[SYS] ESP32 online and synced.');
            return { ok: true, states: data.states };
        } else {
            console.error(`[SYS] ESP32 responded with error: ${response.status}`);
            return { ok: false, error: `HTTP ${response.status}` };
        }
    } catch (error) {
        console.error(`[SYS] Connection failed: ${error.message}`);
        return { ok: false, error: error.message };
    }
}

async function apiResetAll(ip) {
    console.log(`[SYS] Sending global DFA reset signal to ${ip}...`);
    try {
        const response = await fetch(`http://${ip}/reset`);
        if (response.ok) {
            console.log('[SYS] All state machines reset to q0.');
            return { ok: true };
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
    } catch (error) {
        console.error(`[SYS] Reset failed: ${error.message}`);
        return { ok: false, error: error.message };
    }
}

async function apiTriggerEvent(event, ip) {
    try {
        const response = await fetch(`http://${ip}/send?event=${event}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        return { ok: true, results: data.results };
    } catch (error) {
        console.error(`[SYS] Trigger failed: ${error.message}`);
        return { ok: false, error: error.message };
    }
}

async function apiDeployDFA(ip) {
    console.log(`[SYS] Broadcasting global DFA configuration to ${ip}...`);
    try {
        const response = await fetch(`http://${ip}/state`);
        if (response.ok) {
            console.log('[SYS] DFA Logic successfully linked with hardware.');
            return { ok: true };
        } else {
            throw new Error(`Core responded with ${response.status}`);
        }
    } catch (error) {
        console.error(`[SYS] Deployment failed: ${error.message}`);
        return { ok: false, error: error.message };
    }
}

/* ---- THEME MANAGEMENT ---- */

function toggleTheme() {
    const isDark = document.documentElement.classList.toggle('dark');
    const themeBtn = document.getElementById('theme-toggle');
    if (themeBtn) {
        const icon = themeBtn.querySelector('.material-symbols-outlined');
        if (icon) icon.innerText = isDark ? 'light_mode' : 'dark_mode';
    }
    localStorage.setItem('sentinel_theme', isDark ? 'dark' : 'light');
    console.log(`[UI] Theme switched to ${isDark ? 'dark' : 'light'}`);
}

function initTheme() {
    const saved = localStorage.getItem('sentinel_theme') || 'dark';
    if (saved === 'dark') {
        document.documentElement.classList.add('dark');
    } else {
        document.documentElement.classList.remove('dark');
    }
    
    // Sync button icon
    const themeBtn = document.getElementById('theme-toggle');
    if (themeBtn) {
        const icon = themeBtn.querySelector('.material-symbols-outlined');
        if (icon) icon.innerText = (saved === 'dark') ? 'light_mode' : 'dark_mode';
    }
}

// Expose to window
window.toggleTheme = toggleTheme;
window.initTheme = initTheme;

async function apiFetchHardwareLogs(ip) {
    console.log(`[SYS] Fetching internal hardware logs from ${ip}...`);
    try {
        const response = await fetch(`http://${ip}/log`);
        if (response.ok) {
            const data = await response.json();
            return { ok: true, log: data.log };
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
    } catch (error) {
        console.error(`[SYS] Log fetch failed: ${error.message}`);
        return { ok: false, error: error.message };
    }
}
