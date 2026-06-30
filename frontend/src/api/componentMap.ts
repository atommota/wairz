import apiClient from './client'
import type { ComponentGraph } from '@/types'

export async function getComponentMap(
  projectId: string,
  firmwareId?: string,
): Promise<ComponentGraph> {
  const { data } = await apiClient.get<ComponentGraph>(
    `/projects/${projectId}/component-map`,
    { params: { firmware_id: firmwareId } },
  )
  return data
}
