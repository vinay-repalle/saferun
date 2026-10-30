import { CheckCoverage } from '../CheckCoverage/CheckCoverage'
import { FindingsTable } from '../FindingsTable/FindingsTable'
import { GapsPanel } from '../GapsPanel/GapsPanel'
import { UpgradePlan } from '../UpgradePlan/UpgradePlan'
import { VerdictCard } from '../VerdictCard/VerdictCard'

export function ReportView({ report }) {
  return (
    <div className="stack">
      <VerdictCard report={report} />
      <CheckCoverage report={report} />
      <UpgradePlan report={report} />
      <FindingsTable report={report} />
      <GapsPanel report={report} />
    </div>
  )
}
