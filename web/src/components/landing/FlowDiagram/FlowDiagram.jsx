import './FlowDiagram.css'

// Crosshair (+) drawn centred on a corner, 4 units each way.
const plus = (x, y) => `M${x - 4} ${y}h8M${x} ${y - 4}v8`
const CORNERS = [[6, 38], [114, 38], [6, 112], [114, 112], [178, 12], [388, 12], [178, 138], [388, 138], [452, 38], [554, 38], [452, 112], [554, 112]].map(([x, y]) => plus(x, y)).join('')
// Scale along the bottom edge: a tick every 20 units, a number every 100, like the border of a drawing sheet.
const TICKS = Array.from({ length: 28 }, (_, i) => `M${6 + i * 20} 150v${i % 5 === 0 ? 7 : 4}`).join('')

/** Code enters SafeRun, is analysed in isolation, and leaves as a report. Pure SVG, drawn as a blueprint (1px ink lines, hatching, callouts, a scale along the bottom); the motion is CSS and stops under prefers-reduced-motion. */
export function FlowDiagram() {
  return (
    <svg className="flow" viewBox="-2 0 564 170" role="img" aria-label="Project files enter SafeRun, are analysed inside an isolated container, and a security report comes out">
      <defs>
        <marker id="flow-arr" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 8 4 0 8z" className="flow-fill" /></marker>
        <clipPath id="flow-clip"><rect x="190" y="24" width="186" height="102" /></clipPath>
        <pattern id="flow-hatch" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><path d="M0 0V4" className="flow-hatch" /></pattern>
      </defs>
      <g className="flow-box"><rect x="6" y="38" width="108" height="74" /></g>
      <text x="60" y="30" className="flow-cap" textAnchor="middle">your project</text>
      <text x="22" y="64" className="flow-mono">app.py</text><text x="22" y="82" className="flow-mono">setup.py</text><text x="22" y="100" className="flow-mono">requirements</text>
      <path d="M116 75h56" className="flow-line" markerEnd="url(#flow-arr)" />
      <rect className="flow-pk pk-1" x="116" y="72" width="6" height="6" /><rect className="flow-pk pk-2" x="116" y="72" width="6" height="6" /><rect className="flow-pk pk-3" x="116" y="72" width="6" height="6" />
      <rect x="178" y="12" width="210" height="126" className="flow-iso" />
      <rect x="190" y="24" width="186" height="102" className="flow-inner" />
      <g clipPath="url(#flow-clip)"><g className="flow-scan"><rect x="190" y="24" width="186" height="26" fill="url(#flow-hatch)" stroke="none" /><path d="M190 50h186" className="flow-edge" /></g></g>
      <text x="283" y="8" className="flow-cap" textAnchor="middle">isolated analyzer</text>
      <path d="M283 42l-18 7v11c0 10 7.5 16 18 21 10.5-5 18-11 18-21V49l-18-7Z" className="flow-shield" />
      <path d="M277 53v18l15-9-15-9Z" className="flow-tick" />
      <text x="283" y="102" className="flow-mono" textAnchor="middle">no network · read-only</text>
      <text x="283" y="118" className="flow-mono flow-dim" textAnchor="middle">code is never executed</text>
      <path d="M390 75h56" className="flow-line" markerEnd="url(#flow-arr)" />
      <rect className="flow-pk pk-1 pk-out" x="390" y="72" width="6" height="6" /><rect className="flow-pk pk-2 pk-out" x="390" y="72" width="6" height="6" /><rect className="flow-pk pk-3 pk-out" x="390" y="72" width="6" height="6" />
      <g className="flow-box"><rect x="452" y="38" width="102" height="74" /></g>
      <rect className="flow-hl hl-1" x="458" y="51" width="90" height="18" /><rect className="flow-hl hl-2" x="458" y="69" width="90" height="18" /><rect className="flow-hl hl-3" x="458" y="87" width="90" height="18" />
      <text x="503" y="30" className="flow-cap" textAnchor="middle">report</text>
      <text x="466" y="64" className="flow-mono flow-ok">PASS</text><text x="466" y="82" className="flow-mono flow-warn">WARNING</text><text x="466" y="100" className="flow-mono flow-bad">FAIL</text>

      {/* drafting furniture: corner crosshairs, three numbered callouts with leader lines, and a scale along the bottom */}
      <path className="flow-xh" d={CORNERS} />
      <g className="flow-call">
        <path d="M110 16V38" /><circle cx="110" cy="11" r="5" /><text x="110" y="13.4" textAnchor="middle" className="flow-no">1</text><text x="119" y="13.4">SOURCE</text>
        <path d="M399 50H388" /><circle cx="404" cy="50" r="5" /><text x="404" y="52.4" textAnchor="middle" className="flow-no">2</text><text x="412" y="52.4">ANALYZER</text>
        <path d="M540 16V38" /><circle cx="540" cy="11" r="5" /><text x="540" y="13.4" textAnchor="middle" className="flow-no">3</text><text x="531" y="13.4" textAnchor="end">VERDICT</text>
      </g>
      <path className="flow-scale" d={'M6 150H554' + TICKS} />
      <g className="flow-coords">{[0, 1, 2, 3, 4, 5].map((n) => <text key={n} x={6 + n * 100} y="166" textAnchor="middle">{String(n * 100).padStart(3, '0')}</text>)}</g>
    </svg>
  )
}
