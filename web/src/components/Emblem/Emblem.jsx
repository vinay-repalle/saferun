import './Emblem.css'

const SHIELD = 'M120 14 40 44v84c0 62 36 108 80 130 44-22 80-68 80-130V44L120 14Z'
const INNER = 'M120 32 54 56v70c0 54 30 92 66 112 36-20 66-58 66-112V56l-66-24Z'

/**
 * The hero emblem: SafeRun drawn as a technical diagram. A shield of plates, an isolation ring around the "run" core, circuit traces that end
 * in nodes (nothing leaves: the analyzer has no network), a scan beam, three verdict dots and inspection brackets. Decorative line art; the
 * small solid mark (Mark) stays the logo for the navbar and the tab. All motion is CSS and stops with prefers-reduced-motion.
 */
export function Emblem({ className = '' }) {
  return (
    <svg className={'em ' + className} viewBox="-4 -4 248 288" width="248" height="288" aria-hidden="true">
      <defs>
        <radialGradient id="em-glow" cx="50%" cy="50%" r="50%"><stop offset="0" stopColor="#5b9bff" stopOpacity=".38" /><stop offset="1" stopColor="#5b9bff" stopOpacity="0" /></radialGradient>
        <linearGradient id="em-beam" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#5b9bff" stopOpacity="0" /><stop offset="1" stopColor="#5b9bff" stopOpacity=".5" /></linearGradient>
        <clipPath id="em-clip"><path d={INNER} /></clipPath>
      </defs>
      <circle className="glow" cx="120" cy="140" r="86" />

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
      {/* isolation ring around the core */}
      <g className="em-ring">
        <circle className="d t5 dim" pathLength="1" cx="120" cy="140" r="56" strokeDasharray="1.4 6" />
        <circle className="d t5" pathLength="1" cx="120" cy="140" r="46" />
      </g>
      {/* scan beam, clipped to the inner shield */}
      <g clipPath="url(#em-clip)"><rect className="em-scan" x="50" y="34" width="140" height="34" fill="url(#em-beam)" /></g>
      {/* the "run" core */}
      <path className="core" d="M110 120v40l36-20-36-20Z" />
      {/* verdict dots */}
      <circle className="vd pass" cx="106" cy="226" r="3.5" /><circle className="vd warn" cx="120" cy="230" r="3.5" /><circle className="vd fail" cx="134" cy="226" r="3.5" />
    </svg>
  )
}
