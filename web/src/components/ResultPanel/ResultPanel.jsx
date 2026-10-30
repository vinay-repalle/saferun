import { ArchiveCard } from '../ArchiveCard/ArchiveCard'
import { ReportView } from '../ReportView/ReportView'
import { describeCode } from '../../utils/errors'
import { isSupportedReport, txt } from '../../utils/report'
/** What to show once a job has finished: the report, a refused archive, or "no verdict". */
export function ResultPanel({ job, name, onReset }) {
  const head = (
    <div className="card-head"><h2>Result for “{name}”</h2><button onClick={onReset}>Clear and delete result</button></div>
  )
  if (job.status === 'done') {
    if (!isSupportedReport(job.report)) return <div className="card error" role="alert">{head}<p>The server returned a report in an unsupported format, so it is not shown.</p></div>
    return <div className="stack">{head}{job.archive && <ArchiveCard a={job.archive} />}<ReportView report={job.report} /></div>
  }
  const rejected = job.status === 'rejected'
  return (
    <div className="card error" role="alert">
      {head}
      <h3>{rejected ? 'Archive refused' : 'No verdict'}</h3>
      <p>{describeCode(job.error?.code ?? '', txt(job.error?.message ?? 'The scan did not complete.', 200))}</p>
      <p className="fine">{rejected ? 'Nothing was scanned. The archive was not executed.' : 'This is not a pass: the project was not validated.'}</p>
    </div>
  )
}
