/* ---- ATTACK RECORDER MODULE ---- */

import { recordAttack, getAttackSummary, clearAttacks, exportAttacks } from './recorder.js';

export function showAttackSummary() {
    const summary = getAttackSummary();
    console.table(summary);
}

export function downloadAttackLog() {
    exportAttacks();
}

export function resetAttackLog() {
    clearAttacks();
}
