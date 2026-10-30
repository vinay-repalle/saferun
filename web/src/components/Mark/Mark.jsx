/** The SafeRun logo mark: a solid shield with a play-button cut-out ("safe" + "run"), framed by scan brackets. Decorative; the brand name always sits next to it. */
export function Mark({ size = 26, className = '' }) {
  return (
    <svg className={'mark ' + className} viewBox="0 0 56 64" width={size} height={size * 64 / 56} aria-hidden="true">
      <path className="m-body" fillRule="evenodd" fill="currentColor" d="M28 3 6 11v21c0 14 10 24 22 29 12-5 22-15 22-29V11L28 3ZM21 21.500v21l19-10.500-19-10.500Z" />
      <path className="m-frame" pathLength="1" fill="none" stroke="currentColor" strokeWidth="2.5" strokeOpacity=".55" d="M0 14V2h12M44 2h12v12M56 50v12H44M12 62H0V50" />
    </svg>
  )
}
