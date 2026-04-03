// Expose to window immediately for global onclick access
window.filterRecords = filterRecords;
window.searchRecords = searchRecords;
window.clearStats = clearStats;
window.exportAttacks = exportAttacks;

/**
 * Update the metrics cards on the Analytics page.
 */
function loadStats() {
    const stats = getAttackSummary();

    const totalEl = document.getElementById('stat-total-attacks');
    const intrusionsEl = document.getElementById('stat-intrusions');
    const violationsEl = document.getElementById('stat-violations');
    const freqEl = document.getElementById('stat-freq-protocol');
    const percEl = document.getElementById('stat-intrusion-perc');

    if (totalEl) totalEl.innerText = stats.total.toLocaleString();
    if (intrusionsEl) intrusionsEl.innerText = stats.intrusions.toLocaleString();
    if (violationsEl) violationsEl.innerText = stats.violations.toLocaleString();

    if (percEl && stats.total > 0) {
        const perc = Math.round((stats.intrusions / stats.total) * 100);
        percEl.innerText = `${perc}% of total`;
    }

    // Calc most frequent protocol
    if (freqEl) {
        let maxVal = -1;
        let freqProto = "None";
        for (const [p, count] of Object.entries(stats.protocols)) {
            if (count > maxVal) {
                maxVal = count;
                freqProto = p;
            }
        }
        freqEl.innerText = maxVal > 0 ? freqProto : "---";
    }
}

/**
 * Render the incident table.
 */
function renderAttackLog() {
    const log = JSON.parse(localStorage.getItem('attack_log') || '[]');
    const tbody = document.getElementById('records-table-body');
    if (!tbody) return;

    tbody.innerHTML = '';

    if (log.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="py-20 text-center text-on-surface-variant/40 italic font-medium">No security incidents recorded yet. Use the Console to trigger simulation events.</td></tr>`;
        return;
    }

    // Show latest first
    [...log].reverse().forEach(entry => {
        const tr = document.createElement('tr');
        tr.className = "hover:bg-primary/5 transition-colors group border-b border-outline/5";

        const time = new Date(entry.time).toLocaleTimeString('en-GB', { hour12: false });
        const typeCls = entry.type === 'intrusion' ? 'bg-secondary-container text-on-secondary-container' : 'bg-error-container text-on-error-container';
        let severityCls = 'bg-primary/10 text-primary border-primary/20';
        if (entry.severity === 'CRITICAL') severityCls = 'bg-error/20 text-error border-error/40 font-black';
        else if (entry.severity === 'HIGH' || entry.type === 'violation') severityCls = 'bg-error/10 text-error border-error/20';
        else if (entry.severity === 'MEDIUM') severityCls = 'bg-tertiary/10 text-tertiary border-tertiary/20';

        tr.innerHTML = `
            <td class="py-4 px-3 font-mono text-[11px] opacity-60">${time}</td>
            <td class="py-4 px-3"><span class="px-2 py-0.5 rounded bg-surface-container-highest text-[10px] font-bold uppercase tracking-tight">${entry.protocol}</span></td>
            <td class="py-4 px-3 font-bold text-xs">${entry.event.replace(entry.protocol + '_', '')}</td>
            <td class="py-4 px-3 font-mono text-[10px] opacity-50">q${entry.from_state} → q${entry.to_state}</td>
            <td class="py-4 px-3"><span class="px-2 py-0.5 rounded-md text-[9px] font-bold uppercase ${typeCls}">${entry.type}</span></td>
            <td class="py-4 px-3"><span class="px-2 py-1 rounded border text-[8px] font-bold uppercase ${severityCls}">${entry.severity || 'LOW'}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

/**
 * Search/Filter logic for the table.
 */
function searchRecords() {
    const input = document.getElementById('record-search');
    if (!input) return;
    const filter = input.value.toUpperCase();
    const table = document.getElementById('records-table');
    if (!table) return;
    const tr = table.getElementsByTagName('tr');

    for (let i = 1; i < tr.length; i++) {
        const rowText = tr[i].textContent || tr[i].innerText;
        if (rowText.toUpperCase().indexOf(filter) > -1) {
            tr[i].style.display = "";
        } else {
            tr[i].style.display = "none";
        }
    }
}

/**
 * Filter by protocol.
 */
function filterRecords(protocol) {
    const table = document.getElementById('records-table');
    if (!table) return;
    const rows = table.getElementsByTagName('tr');

    // Update Sidebar Active State
    const nav = document.getElementById('record-nav');
    if (nav) {
        const links = nav.querySelectorAll('a');
        links.forEach(l => {
            if (l.innerText.includes(protocol)) {
                l.className = "flex items-center gap-3 px-4 py-3 bg-primary/10 text-primary border-l-4 border-primary font-bold font-['Inter'] uppercase text-[10px] tracking-widest cursor-pointer";
            } else {
                l.className = "text-on-surface-variant hover:text-primary px-4 py-3 flex items-center gap-3 font-['Inter'] uppercase text-[10px] tracking-widest font-semibold hover:bg-surface-container-highest transition-all cursor-pointer";
            }
        });
    }

    // Filtering
    for (let i = 1; i < rows.length; i++) {
        const protocolCell = rows[i].getElementsByTagName('td')[1];
        if (protocolCell) {
            const text = protocolCell.textContent || protocolCell.innerText;
            if (protocol === 'ALL' || text.includes(protocol)) {
                rows[i].style.display = "";
            } else {
                rows[i].style.display = "none";
            }
        }
    }
}

/**
 * Clear stats with confirmation.
 */
function clearStats() {
    if (confirm('Are you sure you want to clear all security records and metrics history?')) {
        clearAttacks();
        loadStats();
        renderAttackLog();
        showToast('History Cleared', 'delete_sweep');
    }
}

/**
 * Toast helper for Analytics page.
 */
function showToast(msg, icon) {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.querySelector('.material-symbols-outlined').innerText = icon;
    toast.querySelector('span:last-child').innerText = msg;
    toast.classList.remove('translate-y-20', 'opacity-0');
    setTimeout(() => toast.classList.add('translate-y-20', 'opacity-0'), 2500);
}

/* ---- INITIALIZATION ---- */

window.addEventListener('load', () => {
    loadStats();
    renderAttackLog();
    initTheme(); // Sync UI with saved preference
    if (document.getElementById('record-nav')) filterRecords('ALL');
});

// React to storage changes from other tabs
window.addEventListener('storage', (e) => {
    if (e.key === 'sentinel_stats') loadStats();
    if (e.key === 'attack_log') renderAttackLog();
});
