import { txt } from '../../utils/report'
import './StatusBadge.css'

const STATUS_LABEL = { not_applicable: 'not applicable' }

export function StatusBadge({ status }) {
  return <span className={`badge st-${txt(status, 20).replace(/[^a-z_]/g, '')}`}>{STATUS_LABEL[status] ?? txt(status, 20)}</span>
}
