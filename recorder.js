/* ---- ATTACK RECORDER MODULE ---- */

// Initialize logs from localStorage or default to empty array
let ATTACK_LOG = JSON.parse(localStorage.getItem('attack_log') || '[]');

/**
 * Record a security incident and update the global statistics.
 * @param {Object} entry - The incident data (event, dfa, from, to, status, severity)
 */
function recordAttack({ event, dfa, from, to, status, severity }) {
    // Only record violations or intrusions
    if (status !== 'intrusion' && status !== 'violation') return;

    const entry = {
        time: new Date().toISOString(),
        event,
        protocol: dfa,
        from_state: from,
        to_state: to,
        type: status,
        severity: severity || 'LOW'
    };

    // Update Logs
    ATTACK_LOG.push(entry);
    localStorage.setItem('attack_log', JSON.stringify(ATTACK_LOG));

    // Update Stats (for the dashboard bento grid)
    let stats = JSON.parse(localStorage.getItem('sentinel_stats') || '{"total":0, "intrusions":0, "violations":0, "protocols":{"TCP":0,"HTTP":0,"MQTT":0}}');
    stats.total++;
    if (status === 'intrusion') stats.intrusions++;
    if (status === 'violation') stats.violations++;
    stats.protocols[dfa] = (stats.protocols[dfa] || 0) + 1;
    localStorage.setItem('sentinel_stats', JSON.stringify(stats));

    console.warn(`[RECORDER] ${status.toUpperCase()} logged for ${dfa}:`, entry);
}

/**
 * Get a summary of all recorded attacks.
 */
function getAttackSummary() {
    return JSON.parse(localStorage.getItem('sentinel_stats') || '{"total":0, "intrusions":0, "violations":0, "protocols":{"TCP":0,"HTTP":0,"MQTT":0}}');
}

/**
 * Clear all security history.
 */
function clearAttacks() {
    ATTACK_LOG = [];
    localStorage.removeItem('attack_log');
    localStorage.removeItem('sentinel_stats');
    console.log('[RECORDER] All security history cleared.');
}

/**
 * Get the latest N attacks from the log.
 * @param {number} count - Number of latest records to fetch.
 */
function getRecentAttacks(count = 5) {
    const log = JSON.parse(localStorage.getItem('attack_log') || '[]');
    return log.slice(-count).reverse();
}

/**
 * Export the attack log as a JSON file.
 */
function exportAttacks() {
    if (ATTACK_LOG.length === 0) {
        alert("No logs to export.");
        return;
    }
    const blob = new Blob([JSON.stringify(ATTACK_LOG, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `sentinel_forensics_${new Date().getTime()}.json`;
    a.click();
}

// Expose to window for global access from HTML onclick handlers
window.recordAttack = recordAttack;
window.exportAttacks = exportAttacks;
window.clearAttacks = clearAttacks;
window.getAttackSummary = getAttackSummary;
window.getRecentAttacks = getRecentAttacks;
