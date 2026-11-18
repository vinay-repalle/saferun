import { useSyncExternalStore } from 'react'

// Keyboard shortcuts: a single letter activates the link or button carrying that data-key (the same attribute that draws the "[P]" hint, so hint and
// behaviour cannot drift apart). "?" or the footer button switches them off and on; the choice is remembered. Single-key shortcuts must
// always be switchable (WCAG 2.1.4), because speech input and assistive tech can fire them by accident.
const STORE = 'saferun-shortcuts'
const listeners = new Set()

const read = () => { try { return window.localStorage.getItem(STORE) !== 'off' } catch { return true } }
let enabled = read()
const apply = () => { document.documentElement.dataset.shortcuts = enabled ? 'on' : 'off' }
apply()

export function setShortcuts(on) {
  enabled = on
  try { window.localStorage.setItem(STORE, on ? 'on' : 'off') } catch { /* storage unavailable: the choice lasts for this visit only */ }
  apply()
  listeners.forEach((l) => l())
}
export const toggleShortcuts = () => setShortcuts(!enabled)
export const shortcutsOn = () => enabled

/** Whether shortcuts are on (re-renders when switched). */
export function useShortcutsEnabled() {
  return useSyncExternalStore((cb) => { listeners.add(cb); return () => listeners.delete(cb) }, shortcutsOn, () => true)
}

const TYPING = 'input, textarea, select, [contenteditable=""], [contenteditable="true"]'

/** The window key handler. Ignores typing in fields, Ctrl/Cmd/Alt combinations (browser shortcuts) and held-down repeats. */
export function onShortcutKey(e) {
  if (e.defaultPrevented || e.repeat || e.ctrlKey || e.metaKey || e.altKey) return
  if (e.target instanceof Element && e.target.closest(TYPING)) return
  if (e.key === '?') { toggleShortcuts(); return }
  if (!enabled || e.key.length !== 1) return
  const key = e.key.toUpperCase()
  const link = [...document.querySelectorAll('a[data-key], button[data-key]')].find((a) => a.dataset.key === key)
  if (link) { e.preventDefault(); link.click() }
}
