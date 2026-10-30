import './FlowDiagram.css'

/** Code enters SafeRun, is analysed in isolation, and leaves as a report. Pure SVG; the motion is CSS and stops under prefers-reduced-motion. */
export function FlowDiagram() {
  return (
    <svg className="flow" viewBox="0 0 560 150" role="img" aria-label="Project files enter SafeRun, are analysed inside an isolated container, and a security report comes out">
      <defs>
        <marker id="flow-arr" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 8 4 0 8z" className="flow-fill" /></marker>
        <clipPath id="flow-clip"><rect x="190" y="24" width="186" height="102" rx="2" /></clipPath>
        <linearGradient id="flow-beam" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#5b9bff" stopOpacity="0" /><stop offset="1" stopColor="#5b9bff" stopOpacity=".35" /></linearGradient>
      </defs>
      <g className="flow-box"><rect x="6" y="38" width="108" height="74" rx="3" /></g>
      <text x="60" y="30" className="flow-cap" textAnchor="middle">your project</text>
      <text x="22" y="64" className="flow-mono">app.py</text><text x="22" y="82" className="flow-mono">index.js</text><text x="22" y="100" className="flow-mono">package-lock</text>
      <path d="M116 75h56" className="flow-line" markerEnd="url(#flow-arr)" />
      <rect className="flow-pk pk-1" x="116" y="72" width="6" height="6" /><rect className="flow-pk pk-2" x="116" y="72" width="6" height="6" /><rect className="flow-pk pk-3" x="116" y="72" width="6" height="6" />
      <rect x="178" y="12" width="210" height="126" rx="3" className="flow-iso" />
      <rect x="190" y="24" width="186" height="102" rx="2" className="flow-inner" />
      <g clipPath="url(#flow-clip)"><rect className="flow-scan" x="190" y="24" width="186" height="26" fill="url(#flow-beam)" /></g>
      <text x="283" y="8" className="flow-cap" textAnchor="middle">isolated analyzer</text>
      <path d="M283 42l-18 7v11c0 10 7.5 16 18 21 10.5-5 18-11 18-21V49l-18-7Z" className="flow-shield" />
      <path d="M277 53v18l15-9-15-9Z" className="flow-tick" />
      <text x="283" y="102" className="flow-mono" textAnchor="middle">no network · read-only</text>
      <text x="283" y="118" className="flow-mono flow-dim" textAnchor="middle">code is never executed</text>
      <path d="M390 75h56" className="flow-line" markerEnd="url(#flow-arr)" />
      <rect className="flow-pk pk-1 pk-out" x="390" y="72" width="6" height="6" /><rect className="flow-pk pk-2 pk-out" x="390" y="72" width="6" height="6" /><rect className="flow-pk pk-3 pk-out" x="390" y="72" width="6" height="6" />
      <g className="flow-box"><rect x="452" y="38" width="102" height="74" rx="3" /></g>
      <rect className="flow-hl hl-1" x="458" y="51" width="90" height="18" /><rect className="flow-hl hl-2" x="458" y="69" width="90" height="18" /><rect className="flow-hl hl-3" x="458" y="87" width="90" height="18" />
      <text x="503" y="30" className="flow-cap" textAnchor="middle">report</text>
      <text x="466" y="64" className="flow-mono flow-ok">PASS</text><text x="466" y="82" className="flow-mono flow-warn">WARNING</text><text x="466" y="100" className="flow-mono flow-bad">FAIL</text>
    </svg>
  )
}
