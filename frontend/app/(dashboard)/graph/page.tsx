'use client';

import { useSearchParams } from 'next/navigation';
import { Network } from 'lucide-react';
import Link from 'next/link';

export default function GraphExplorerPage() {
  const searchParams = useSearchParams();
  const projectId = searchParams.get('project_id');

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Attack Surface Graph Explorer</h1>
        <p className="text-gray-400">Visualize discovered assets and their relationships</p>
      </div>

      <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
        <Network className="h-16 w-16 text-gray-600 mx-auto mb-4" />
        {projectId ? (
          <>
            <h3 className="text-xl font-semibold text-white mb-2">
              Graph Explorer
            </h3>
            <p className="text-gray-400 mb-4">
              Viewing graph for project <span className="text-blue-400">{projectId}</span>
            </p>
            <p className="text-gray-500 text-sm mb-6">
              The interactive graph visualization will be built in a future update.
            </p>
            <Link
              href={`/projects/${projectId}`}
              className="inline-block px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white font-semibold rounded-lg transition-colors"
            >
              ← Back to Project
            </Link>
          </>
        ) : (
          <>
            <h3 className="text-xl font-semibold text-white mb-2">
              Select a Project
            </h3>
            <p className="text-gray-400 mb-6">
              Select a project to view its attack surface graph
            </p>
            <Link
              href="/projects"
              className="inline-block px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors"
            >
              Browse Projects
            </Link>
          </>
        )}
      </div>
    </div>
  );
}
