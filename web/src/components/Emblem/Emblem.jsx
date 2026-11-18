import './Emblem.css'

const SHIELD = 'M120 14 40 44v84c0 62 36 108 80 130 44-22 80-68 80-130V44L120 14Z'
const INNER = 'M120 32 54 56v70c0 54 30 92 66 112 36-20 66-58 66-112V56l-66-24Z'

/**
 * The hero emblem: SafeRun drawn as a patent / CAD drawing. A shield of plates, an isolation ring around the "run" core, circuit traces that end
 * in nodes (nothing leaves: the analyzer has no network), a hatched scan band, three verdict dots and inspection brackets, with dimension lines,
 * a centre line and numbered callouts. Decorative 1px line art; the small solid mark (Mark) stays the logo for the navbar and the tab.
 * All motion is CSS and stops with prefers-reduced-motion.
 */
export function Emblem({ className = '' }) {
  return (
    <svg className={'em ' + className} viewBox="-114 -8 468 304" width="468" height="304" aria-hidden="true">
      <defs>
        <pattern id="em-hatch" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><path d="M0 0V4" className="hatch" /></pattern>
        <pattern id="em-hatch-wide" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><path d="M0 0V6" className="hatch" /></pattern>
        <clipPath id="em-clip"><path d={INNER} /></clipPath>
      </defs>

      {/* centre line (dash-dot) */}
      <path className="d t1 axis" pathLength="1" d="M120 -6V8M120 264v10" />
      {/* inspection brackets */}
      <path className="d t1 dim" pathLength="1" d="M0 22V0h22M218 0h22v22M240 258v22h-22M22 280H0v-22" />
      {/* shield: outer wall, inner wall, plates */}
      <path className="d t1" pathLength="1" d={SHIELD} />
      <path className="d t2 dim" pathLength="1" d={INNER} />
      <path className="d t3 dim" pathLength="1" d="M54 56l66 26 66-26M54 126l20 10M186 126l-20 10M120 82V94M120 186v52M74 196l46 22 46-22" />
      {/* circuit traces, mirrored; each ends in a closed node */}
      <path className="d t4" pathLength="1" d="M40 92H16V68H6M40 134H10v28M48 180H30v22H18" />
      <path className="d t4" pathLength="1" d="M200 92h24V68h10M200 134h30v28M192 180h18v22h12" />
      <circle className="node n1" cx="6" cy="68" r="3" /><circle className="node n2" cx="10" cy="162" r="3" /><circle className="node n3" cx="18" cy="202" r="3" />
      <circle className="node n1" cx="234" cy="68" r="3" /><circle className="node n2" cx="230" cy="162" r="3" /><circle className="node n3" cx="222" cy="202" r="3" />
      {/* isolation ring around the core, with its two cardinal ticks */}
      <g className="em-ring">
        <circle className="d t5 dim" pathLength="1" cx="120" cy="140" r="56" strokeDasharray="1.4 6" />
        <circle className="d t5" pathLength="1" cx="120" cy="140" r="46" />
      </g>
      <path className="d t5 dim" pathLength="1" d="M60 140h8M172 140h8" />
      {/* scan band: hatched, with a hard leading edge, clipped to the inner shield */}
      <g clipPath="url(#em-clip)"><g className="em-scan"><rect x="50" y="34" width="140" height="34" fill="url(#em-hatch)" stroke="none" /><path d="M50 68H190" /></g></g>
      {/* the "run" core */}
      <path className="core" d="M110 120v40l36-20-36-20Z" />
      {/* verdict dots */}
      <circle className="vd pass" cx="106" cy="226" r="3.5" /><circle className="vd warn" cx="120" cy="230" r="3.5" /><circle className="vd fail" cx="134" cy="226" r="3.5" />

      {/* dimension lines: height on the left, width under the tip */}
      <path className="d t6 dim" pathLength="1" d="M-14 14V258M-19 14h10M-19 258h10" />
      <text className="lbl dimtxt" x="-19" y="140" transform="rotate(-90 -19 140)" textAnchor="middle">H 244</text>
      <path className="d t6 dim" pathLength="1" d="M40 278H200M40 273v10M200 273v10" />
      <text className="lbl dimtxt" x="120" y="292" textAnchor="middle">W 160</text>

      {/* callouts: leader, end dot, numbered label */}
      <path className="d t6 lead" pathLength="1" d="M200 108H252" /><circle className="lead-dot" cx="200" cy="108" r="1.8" />
      <path className="d t6 lead" pathLength="1" d="M163 124.3H252" /><circle className="lead-dot" cx="163" cy="124.3" r="1.8" />
      <path className="d t6 lead" pathLength="1" d="M234 68l12-14h6" /><circle className="lead-dot" cx="234" cy="68" r="1.8" />
      <path className="d t6 lead" pathLength="1" d="M137 226H252" /><circle className="lead-dot" cx="137" cy="226" r="1.8" />
      <text className="lbl" x="256" y="56"><tspan className="no">1</tspan> NO NETWORK</text>
      <text className="lbl" x="256" y="111"><tspan className="no">2</tspan> READ-ONLY SHELL</text>
      <text className="lbl" x="256" y="127"><tspan className="no">3</tspan> ISOLATION RING</text>
      <text className="lbl" x="256" y="229"><tspan className="no">4</tspan> VERDICT NODES</text>
    </svg>
  )
}
