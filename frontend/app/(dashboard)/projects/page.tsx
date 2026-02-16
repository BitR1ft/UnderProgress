'use client';

import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useProjects, useDeleteProject } from '@/hooks/useProjects';

export default function ProjectsPage() {
  const router = useRouter();
  const { data: projects, isLoading, error } = useProjects();
  const deleteProject = useDeleteProject();

  const handleDelete = async (projectId: string) => {
    if (!confirm('Are you sure you want to delete this project?')) {
      return;
    }
    try {
      await deleteProject.mutateAsync(projectId);
    } catch {
      alert('Failed to delete project');
    }
  };

  const getStatusColor = (status: string) => {
    const colors: Record<string, string> = {
      draft: 'bg-gray-500',
      queued: 'bg-yellow-500',
      running: 'bg-blue-500',
      completed: 'bg-green-500',
      failed: 'bg-red-500',
      paused: 'bg-orange-500',
    };
    return colors[status] || 'bg-gray-500';
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-white text-xl">Loading projects...</div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">My Projects</h1>
          <p className="text-gray-400">Manage your penetration testing projects</p>
        </div>
        <Link
          href="/projects/new"
          className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors"
        >
          + New Project
        </Link>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500 text-red-500 px-4 py-3 rounded mb-6">
          Failed to load projects
        </div>
      )}

      {!projects || projects.length === 0 ? (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
          <div className="text-6xl mb-4">📁</div>
          <h3 className="text-2xl font-semibold text-white mb-2">
            No Projects Yet
          </h3>
          <p className="text-gray-400 mb-6">
            Create your first project to get started
          </p>
          <Link
            href="/projects/new"
            className="inline-block px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors"
          >
            Create Project
          </Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-6">
          {projects.map((project) => (
            <div
              key={project.id}
              className="bg-gray-800 border border-gray-700 rounded-lg p-6 hover:border-gray-600 transition-colors"
            >
              <div className="flex justify-between items-start">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-xl font-semibold text-white">
                      {project.name}
                    </h3>
                    <span
                      className={`px-2 py-1 text-xs font-semibold text-white rounded ${getStatusColor(
                        project.status
                      )}`}
                    >
                      {project.status.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-gray-400 mb-2">
                    Target: <span className="text-blue-400">{project.target}</span>
                  </p>
                  {project.description && (
                    <p className="text-gray-500 text-sm">{project.description}</p>
                  )}
                  <p className="text-gray-600 text-sm mt-2">
                    Created: {new Date(project.created_at).toLocaleDateString()}
                  </p>
                </div>
                <div className="flex gap-2">
                  <Link
                    href={`/projects/${project.id}`}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors text-sm"
                  >
                    View
                  </Link>
                  <button
                    onClick={() => handleDelete(project.id)}
                    className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors text-sm"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
