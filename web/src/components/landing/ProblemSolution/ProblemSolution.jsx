import { Section, SectionHead } from '../../Section/Section'
import './ProblemSolution.css'

const WITHOUT = [
  'An install script or import can run as soon as you try the project.',
  'Credential-like files travel with the folder.',
  'Dependencies may carry known vulnerabilities nobody looked up.',
  'A syntax error is found only when it crashes.',
]
const WITH = [
  'Static verification only: syntax checks and analyzers read the files, they do not run your program.',
  'Credential-like files are withheld from the analysis and the sandbox.',
  'Lockfile dependencies are matched against a local vulnerability database.',
  'One normalized report and a verdict, with an exit code for scripts.',
]

export function ProblemSolution() {
  return (
    <Section id="product">
      <SectionHead n="01" title="Running unknown code is" accent="a leap of faith." sub="Code from an AI assistant, a forum or a download usually gets run first and read second." />
      <div className="split stag">
        <div className="panel panel-bad"><h3>Without a check</h3><ul>{WITHOUT.map((t) => <li key={t}>{t}</li>)}</ul></div>
        <div className="panel panel-good"><h3>With SafeRun</h3><ul>{WITH.map((t) => <li key={t}>{t}</li>)}</ul></div>
      </div>
      <p className="split-note">SafeRun checks what it can check. A passing scan lowers risk; it is not proof that code is safe.</p>
    </Section>
  )
}
