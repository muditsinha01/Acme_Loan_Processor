'use client'

import { CheckCircle2, Circle, Loader2 } from 'lucide-react'

export interface WorkflowStage {
  id: string
  label: string
  duration_ms: number
  status: 'pending' | 'active' | 'complete'
}

interface SkillWorkflowProgressProps {
  stages: WorkflowStage[]
  skillName?: string
  skillDescription?: string
  isComplete?: boolean
}

export function SkillWorkflowProgress({
  stages,
  skillName,
  skillDescription,
  isComplete = false,
}: SkillWorkflowProgressProps) {
  const activeStage = stages.find((stage) => stage.status === 'active')
  const pullingStage = stages.find((stage) => stage.id === 'skill_pull')

  return (
    <div className="space-y-4">
      <div className="rounded-2xl border border-sky-500/20 bg-slate-950/80 p-4">
        <div className="flex items-start gap-3">
          <div className="mt-0.5 flex h-9 w-9 items-center justify-center rounded-xl bg-sky-500/10 text-sky-300">
            {isComplete ? (
              <CheckCircle2 className="h-5 w-5" />
            ) : (
              <Loader2 className="h-5 w-5 animate-spin" />
            )}
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-slate-100">
              {isComplete
                ? 'Skill workflow complete'
                : activeStage?.label || 'Preparing skill workflow...'}
            </p>
            <p className="mt-1 text-xs text-slate-400">
              {isComplete
                ? 'Installed skill instructions were loaded and executed.'
                : 'The assistant is resolving this task through the installed skills runtime.'}
            </p>
          </div>
        </div>
      </div>

      {(pullingStage?.status === 'active' || pullingStage?.status === 'complete') && (
        <div className="rounded-2xl border border-amber-500/20 bg-amber-500/5 p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-amber-200/80">
            Pulling skill
          </p>
          <p className="mt-2 text-sm font-medium text-slate-100">
            {skillName || 'loan-document-helper'} v0.1.0
          </p>
          {skillDescription && (
            <p className="mt-1 text-xs text-slate-400">{skillDescription}</p>
          )}
          {pullingStage.status === 'active' && (
            <div className="mt-3 flex items-center gap-2 text-xs text-amber-100/90">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              <span>Fetching skill package from registry...</span>
            </div>
          )}
        </div>
      )}

      <div className="space-y-2">
        {stages.map((stage) => (
          <div
            key={stage.id}
            className={`flex items-center gap-3 rounded-xl border px-3 py-2.5 text-sm transition-colors ${
              stage.status === 'active'
                ? 'border-sky-500/30 bg-sky-500/10 text-sky-100'
                : stage.status === 'complete'
                  ? 'border-slate-700 bg-slate-900/70 text-slate-300'
                  : 'border-slate-800 bg-slate-950/40 text-slate-500'
            }`}
          >
            {stage.status === 'complete' ? (
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
            ) : stage.status === 'active' ? (
              <Loader2 className="h-4 w-4 shrink-0 animate-spin text-sky-300" />
            ) : (
              <Circle className="h-4 w-4 shrink-0 text-slate-600" />
            )}
            <span>{stage.label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
