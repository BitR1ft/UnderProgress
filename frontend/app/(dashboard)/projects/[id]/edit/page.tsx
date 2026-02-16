'use client';

import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { ArrowLeft } from 'lucide-react';
import { useProject, useUpdateProject } from '@/hooks/useProjects';
import { ProjectForm } from '@/components/forms/ProjectForm';
import type { ProjectFormData } from '@/lib/validations';

export default function EditProjectPage() {
  const params = useParams();
  const router = useRouter();
  const id = params.id as string;
  const { data: project, isLoading: projectLoading } = useProject(id);
  const updateProject = useUpdateProject(id);

  const handleSubmit = async (data: ProjectFormData) => {
    try {
      await updateProject.mutateAsync(data);
      router.push(`/projects/${id}`);
    } catch (err: any) {
      if (err.response?.status === 401) {
        router.push('/auth/login');
      }
    }
  };

  if (projectLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-white text-xl">Loading project...</div>
      </div>
    );
  }

  if (!project) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <div className="text-red-400 text-xl mb-4">Project not found</div>
        <Link href="/projects" className="text-blue-400 hover:text-blue-300">
          ← Back to Projects
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-4xl">
      <Link
        href={`/projects/${id}`}
        className="inline-flex items-center gap-2 text-gray-400 hover:text-white mb-6 transition-colors"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Project
      </Link>

      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Edit Project</h1>
        <p className="text-gray-400">Update your project configuration</p>
      </div>

      <ProjectForm
        onSubmit={handleSubmit}
        isLoading={updateProject.isPending}
        defaultValues={{
          name: project.name,
          description: project.description || '',
          target: project.target,
          enable_subdomain_enum: project.enable_subdomain_enum,
          enable_port_scan: project.enable_port_scan,
          enable_web_crawl: project.enable_web_crawl,
          enable_tech_detection: project.enable_tech_detection,
          enable_vuln_scan: project.enable_vuln_scan,
          enable_nuclei: project.enable_nuclei,
          enable_auto_exploit: project.enable_auto_exploit,
        }}
        error={(updateProject.error as any)?.response?.data?.detail || updateProject.error?.message}
      />
    </div>
  );
}
