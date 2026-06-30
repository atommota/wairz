import apiClient from './client'
import type { DirectoryListing, FileContent, FileInfo } from '@/types'

export async function listDirectory(
  projectId: string,
  path: string = '',
  firmwareId?: string,
): Promise<DirectoryListing> {
  const { data } = await apiClient.get<DirectoryListing>(
    `/projects/${projectId}/files`,
    { params: { path, firmware_id: firmwareId } },
  )
  return data
}

export async function readFile(
  projectId: string,
  path: string,
  offset?: number,
  length?: number,
  format?: string,
  firmwareId?: string,
): Promise<FileContent> {
  const { data } = await apiClient.get<FileContent>(
    `/projects/${projectId}/files/read`,
    { params: { path, offset, length, format, firmware_id: firmwareId } },
  )
  return data
}

export async function getFileInfo(
  projectId: string,
  path: string,
  firmwareId?: string,
): Promise<FileInfo> {
  const { data } = await apiClient.get<FileInfo>(
    `/projects/${projectId}/files/info`,
    { params: { path, firmware_id: firmwareId } },
  )
  return data
}
