import { useEffect, useRef, useState } from 'react'
import './CommandBlock.css'

/** A shell command with a copy button. The "$" prompt is drawn by CSS so it is never copied. */
export function CommandBlock({ command, label }) {
  const [state, setState] = useState('idle')
  const timer = useRef(null)
  useEffect(() => () => clearTimeout(timer.current), [])

  async function copy() {
    try {
      await navigator.clipboard.writeText(command)
      setState('copied')
    } catch {
      setState('failed')
    }
    clearTimeout(timer.current)
    timer.current = setTimeout(() => setState('idle'), 1800)
  }

  return (
    <div className="cmd">
      <code className="cmd-text">{command}</code>
      <button type="button" className="cmd-copy" onClick={copy} aria-label={`Copy command: ${label || command}`}>
        {state === 'copied' ? 'Copied' : state === 'failed' ? 'Press Ctrl+C' : 'Copy'}
      </button>
      <span className="sr-only" role="status">{state === 'copied' ? 'Command copied to clipboard' : ''}</span>
    </div>
  )
}
