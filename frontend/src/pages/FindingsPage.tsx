import { useEffect, useState, useCallback } from 'react'
import { useParams } from 'react-router-dom'
import { ShieldAlert, Loader2 } from 'lucide-react'
import { listFindings, updateFinding, deleteFinding } from '@/api/findings'
import { listFirmware } from '@/api/firmware'
import type { Finding, FindingUpdate, Severity, FindingStatus, FindingSource, FirmwareDetail } from '@/types'
import FindingsList from '@/components/findings/FindingsList'
import FindingDetail from '@/components/findings/FindingDetail'
import ReportExport from '@/components/findings/ReportExport'

export default function FindingsPage() {
  const { projectId } = useParams<{ projectId: string }>()

  const [findings, setFindings] = useState<Finding[]>([])
  const [firmwareVersions, setFirmwareVersions] = useState<FirmwareDetail[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null)
  const [statusFilter, setStatusFilter] = useState<FindingStatus | null>(null)
  const [sourceFilter, setSourceFilter] = useState<FindingSource | null>(null)
  const [firmwareFilter, setFirmwareFilter] = useState<string | null>(null)

  const fetchFindings = useCallback(async () => {
    if (!projectId) return
    try {
      const params: Record<string, string> = {}
      if (severityFilter) params.severity = severityFilter
      if (statusFilter) params.status = statusFilter
      if (sourceFilter) params.source = sourceFilter
      if (firmwareFilter) params.firmware_id = firmwareFilter
      const data = await listFindings(projectId, params)
      setFindings(data)
    } catch (err) {
      console.error('Failed to load findings:', err)
    } finally {
      setLoading(false)
    }
  }, [projectId, severityFilter, statusFilter, sourceFilter, firmwareFilter])

  useEffect(() => {
    fetchFindings()
  }, [fetchFindings])

  useEffect(() => {
    if (!projectId) return
    listFirmware(projectId)
      .then(setFirmwareVersions)
      .catch((err) => console.error('Failed to load firmware versions:', err))
  }, [projectId])

  const handleSelect = useCallback((finding: Finding) => {
    setSelectedId((prev) => (prev === finding.id ? null : finding.id))
  }, [])

  const handleUpdate = useCallback(
    async (findingId: string, updates: FindingUpdate) => {
      if (!projectId) return
      const updated = await updateFinding(projectId, findingId, updates)
      setFindings((prev) =>
        prev.map((f) => (f.id === findingId ? updated : f)),
      )
    },
    [projectId],
  )

  const handleDelete = useCallback(
    async (findingId: string) => {
      if (!projectId) return
      await deleteFinding(projectId, findingId)
      setFindings((prev) => prev.filter((f) => f.id !== findingId))
      if (selectedId === findingId) setSelectedId(null)
    },
    [projectId, selectedId],
  )

  const selectedFinding = findings.find((f) => f.id === selectedId) ?? null

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-12 justify-center text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
        <span>Loading findings...</span>
      </div>
    )
  }

  return (
    <div className="-m-6 flex h-[calc(100vh-3.5rem)]">
      {/* Left panel: findings list */}
      <div className="flex w-96 shrink-0 flex-col border-r border-border">
        <div className="flex items-center gap-2 border-b border-border px-4 py-2">
          <ShieldAlert className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Findings</span>
          <div className="ml-auto">
            {projectId && <ReportExport projectId={projectId} />}
          </div>
        </div>
        <div className="flex-1 overflow-y-auto px-3 py-2">
          <FindingsList
            findings={findings}
            selectedId={selectedId}
            onSelect={handleSelect}
            severityFilter={severityFilter}
            statusFilter={statusFilter}
            sourceFilter={sourceFilter}
            firmwareVersions={firmwareVersions}
            firmwareFilter={firmwareFilter}
            onSeverityFilter={setSeverityFilter}
            onStatusFilter={setStatusFilter}
            onSourceFilter={setSourceFilter}
            onFirmwareFilter={setFirmwareFilter}
          />
        </div>
      </div>

      {/* Center panel: finding detail */}
      <div className="flex min-w-0 flex-1 flex-col">
        {selectedFinding ? (
          <div className="flex-1 overflow-y-auto p-6">
            <FindingDetail
              key={selectedFinding.id}
              finding={selectedFinding}
              firmwareVersions={firmwareVersions}
              onUpdate={handleUpdate}
              onDelete={handleDelete}
            />
          </div>
        ) : (
          <div className="flex flex-1 flex-col items-center justify-center text-muted-foreground">
            <ShieldAlert className="mb-3 h-12 w-12" />
            <p className="text-sm">Select a finding to view details</p>
          </div>
        )}
      </div>
    </div>
  )
}
