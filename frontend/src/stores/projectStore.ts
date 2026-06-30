import { create } from 'zustand'
import type { Project, ProjectDetail } from '@/types'
import { listProjects, getProject, createProject, deleteProject } from '@/api/projects'
import { uploadFirmware as apiFirmwareUpload, unpackFirmware as apiUnpackFirmware } from '@/api/firmware'
import { resolveActiveFirmwareId } from '@/utils/firmware'

interface ProjectState {
  projects: Project[]
  currentProject: ProjectDetail | null
  // The firmware version currently selected for viewing/analysis across all
  // tabs. Null when no project is loaded or the project has no firmware.
  activeFirmwareId: string | null
  loading: boolean
  creating: boolean
  uploading: boolean
  unpacking: boolean
  uploadProgress: number
  error: string | null
}

interface ProjectActions {
  fetchProjects: () => Promise<void>
  fetchProject: (id: string) => Promise<void>
  createProject: (name: string, description?: string) => Promise<ProjectDetail>
  removeProject: (id: string) => Promise<void>
  uploadFirmware: (projectId: string, file: File, versionLabel?: string) => Promise<void>
  unpackFirmware: (projectId: string, firmwareId: string) => Promise<void>
  setActiveFirmware: (firmwareId: string | null) => void
  clearError: () => void
  clearCurrentProject: () => void
}

export const useProjectStore = create<ProjectState & ProjectActions>((set, get) => ({
  projects: [],
  currentProject: null,
  activeFirmwareId: null,
  loading: false,
  creating: false,
  uploading: false,
  unpacking: false,
  uploadProgress: 0,
  error: null,

  fetchProjects: async () => {
    set({ loading: true, error: null })
    try {
      const projects = await listProjects()
      set({ projects, loading: false })
    } catch (e) {
      set({ loading: false, error: extractError(e) })
    }
  },

  fetchProject: async (id) => {
    set({ loading: true, error: null })
    try {
      const project = await getProject(id)
      // Switching projects resets the selection; reloading the same one keeps
      // it if still valid. Default = newest loadable version.
      const prevActive = get().currentProject?.id === id ? get().activeFirmwareId : null
      set({
        currentProject: project,
        activeFirmwareId: resolveActiveFirmwareId(prevActive, project.firmware),
        loading: false,
      })
    } catch (e) {
      set({ loading: false, error: extractError(e) })
    }
  },

  createProject: async (name, description) => {
    set({ creating: true, error: null })
    try {
      const project = await createProject({ name, description })
      set((s) => ({ projects: [projectFromDetail(project), ...s.projects], creating: false }))
      return project
    } catch (e) {
      set({ creating: false, error: extractError(e) })
      throw e
    }
  },

  removeProject: async (id) => {
    try {
      await deleteProject(id)
      set((s) => ({
        projects: s.projects.filter((p) => p.id !== id),
        currentProject: s.currentProject?.id === id ? null : s.currentProject,
        activeFirmwareId: s.currentProject?.id === id ? null : s.activeFirmwareId,
      }))
    } catch (e) {
      set({ error: extractError(e) })
    }
  },

  uploadFirmware: async (projectId, file, versionLabel) => {
    set({ uploading: true, uploadProgress: 0, error: null })
    try {
      await apiFirmwareUpload(projectId, file, versionLabel, (pct) => set({ uploadProgress: pct }))
      // Refresh project to get firmware info
      const project = await getProject(projectId)
      set({
        uploading: false,
        uploadProgress: 100,
        currentProject: project,
        activeFirmwareId: resolveActiveFirmwareId(get().activeFirmwareId, project.firmware),
      })
      // Sync into projects list
      syncProjectInList(set, get, project)
    } catch (e) {
      set({ uploading: false, error: extractError(e) })
      throw e
    }
  },

  unpackFirmware: async (projectId, firmwareId) => {
    set({ unpacking: true, error: null })
    try {
      await apiUnpackFirmware(projectId, firmwareId)
      // Endpoint returns 202 immediately; refresh project to show "unpacking" status
      const project = await getProject(projectId)
      set({
        unpacking: false,
        currentProject: project,
        activeFirmwareId: resolveActiveFirmwareId(get().activeFirmwareId, project.firmware),
      })
      syncProjectInList(set, get, project)
    } catch (e) {
      set({ unpacking: false, error: extractError(e) })
      throw e
    }
  },

  setActiveFirmware: (firmwareId) => set({ activeFirmwareId: firmwareId }),
  clearError: () => set({ error: null }),
  clearCurrentProject: () => set({ currentProject: null, activeFirmwareId: null }),
}))

function projectFromDetail(d: ProjectDetail): Project {
  const { firmware: _, ...project } = d
  return project
}

function syncProjectInList(
  set: (fn: (s: ProjectState) => Partial<ProjectState>) => void,
  get: () => ProjectState,
  detail: ProjectDetail,
) {
  const base = projectFromDetail(detail)
  const existing = get().projects.find((p) => p.id === base.id)
  if (existing) {
    set((s) => ({ projects: s.projects.map((p) => (p.id === base.id ? base : p)) }))
  }
}

function extractError(e: unknown): string {
  if (e && typeof e === 'object' && 'response' in e) {
    const resp = (e as { response?: { data?: { detail?: string } } }).response
    if (resp?.data?.detail) return resp.data.detail
  }
  if (e instanceof Error) return e.message
  return 'An unexpected error occurred'
}
