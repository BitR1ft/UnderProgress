import axios from 'axios';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api';

const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
});

apiClient.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

export const authApi = {
  login: (credentials: { username: string; password: string }) =>
    apiClient.post('/auth/login', credentials),
  
  register: (data: { username: string; email: string; password: string }) =>
    apiClient.post('/auth/register', data),
  
  logout: () => apiClient.post('/auth/logout'),
  
  getCurrentUser: () => apiClient.get('/auth/me'),
  
  refreshToken: () => apiClient.post('/auth/refresh'),
};

export interface Project {
  id: string;
  name: string;
  description?: string;
  target: string;
  status: string;
  enable_subdomain_enum: boolean;
  enable_port_scan: boolean;
  enable_web_crawl: boolean;
  enable_tech_detection: boolean;
  enable_vuln_scan: boolean;
  enable_nuclei: boolean;
  enable_auto_exploit: boolean;
  created_at: string;
  updated_at: string;
  user_id: string;
}

export interface CreateProjectDto {
  name: string;
  description?: string;
  target: string;
  enable_subdomain_enum?: boolean;
  enable_port_scan?: boolean;
  enable_web_crawl?: boolean;
  enable_tech_detection?: boolean;
  enable_vuln_scan?: boolean;
  enable_nuclei?: boolean;
  enable_auto_exploit?: boolean;
}

export const projectsApi = {
  getAll: () => apiClient.get<Project[]>('/projects'),
  
  getById: (id: string) => apiClient.get<Project>(`/projects/${id}`),
  
  create: (data: CreateProjectDto) => apiClient.post<Project>('/projects', data),
  
  update: (id: string, data: Partial<CreateProjectDto>) =>
    apiClient.put<Project>(`/projects/${id}`, data),
  
  delete: (id: string) => apiClient.delete(`/projects/${id}`),
  
  start: (id: string) => apiClient.post(`/projects/${id}/start`),
  
  stop: (id: string) => apiClient.post(`/projects/${id}/stop`),
};

// Graph types
export interface GraphNode {
  id: string;
  labels: string[];
  properties: Record<string, any>;
}

export interface GraphRelationship {
  id: string;
  type: string;
  startNode: string;
  endNode: string;
  properties: Record<string, any>;
}

export interface AttackSurfaceData {
  nodes: GraphNode[];
  relationships: GraphRelationship[];
}

export interface GraphStats {
  node_counts: Record<string, number>;
  total_nodes: number;
}

export const graphApi = {
  getAttackSurface: (projectId: string) =>
    apiClient.get<{ success: boolean; project_id: string; data: AttackSurfaceData }>(`/graph/attack-surface/${projectId}`),

  getVulnerabilities: (projectId: string, severity?: string) =>
    apiClient.get(`/graph/vulnerabilities/${projectId}`, { params: severity ? { severity } : {} }),

  getTechnologies: (projectId: string, withCves?: boolean) =>
    apiClient.get(`/graph/technologies/${projectId}`, { params: withCves ? { with_cves: true } : {} }),

  getStats: (projectId: string) =>
    apiClient.get<{ success: boolean; project_id: string } & GraphStats>(`/graph/stats/${projectId}`),

  getHealth: () =>
    apiClient.get('/graph/health'),
};

export default apiClient;
