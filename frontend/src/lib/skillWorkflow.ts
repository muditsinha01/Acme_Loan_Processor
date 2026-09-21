import { WorkflowStage } from '../components/SkillWorkflowProgress'

export function isLoanDocumentWorkflow(message: string): boolean {
  const text = message.toLowerCase()
  return [
    'loan document',
    'loan documents',
    'process my loan document',
    'process loan document',
    'review my loan document',
    'review loan document',
  ].some((keyword) => text.includes(keyword))
}

export function extractDocumentNumber(message: string): string {
  const match = message.match(/document number\s+(\d+)/i)
  return match?.[1] ?? '1523'
}

export function buildSkillWorkflowStages(
  documentNumber: string,
  skillLabel = 'loan-document-helper v0.1.0',
): WorkflowStage[] {
  return [
    {
      id: 'document_lookup',
      label: `Retrieving document ${documentNumber} from registry`,
      duration_ms: 1400,
      status: 'pending',
    },
    {
      id: 'skill_match',
      label: 'Matching task to installed skills',
      duration_ms: 1100,
      status: 'pending',
    },
    {
      id: 'skill_pull',
      label: `Pulling skill: ${skillLabel}`,
      duration_ms: 2400,
      status: 'pending',
    },
    {
      id: 'skill_load',
      label: 'Loading skill instructions into agent context',
      duration_ms: 1600,
      status: 'pending',
    },
    {
      id: 'skill_execute',
      label: 'Executing skill workflow',
      duration_ms: 1300,
      status: 'pending',
    },
  ]
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export function applyBackendWorkflowStages(
  stages: WorkflowStage[],
  backendStages: Array<{ id: string; label?: string; status?: string }>,
): WorkflowStage[] {
  const statusById = new Map(
    backendStages.map((stage) => [stage.id, stage.status as WorkflowStage['status']]),
  )
  const labelById = new Map(
    backendStages
      .filter((stage) => stage.label)
      .map((stage) => [stage.id, stage.label as string]),
  )

  return stages.map((stage) => ({
    ...stage,
    label: labelById.get(stage.id) ?? stage.label,
    status: statusById.get(stage.id) ?? stage.status,
  }))
}

export async function runWorkflowStages(
  stages: WorkflowStage[],
  onUpdate: (nextStages: WorkflowStage[]) => void,
  options?: {
    stopWhen?: () => boolean
    onStop?: (stages: WorkflowStage[]) => WorkflowStage[]
  },
): Promise<WorkflowStage[]> {
  const completedStages = stages.map((stage) => ({ ...stage }))

  for (let index = 0; index < completedStages.length; index += 1) {
    if (options?.stopWhen?.()) {
      const stoppedStages = options.onStop?.(completedStages) ?? completedStages
      onUpdate(stoppedStages.map((stage) => ({ ...stage })))
      return stoppedStages
    }

    const currentStatus = completedStages[index].status
    if (currentStatus === 'failed' || currentStatus === 'complete') {
      continue
    }

    completedStages[index] = { ...completedStages[index], status: 'active' }
    onUpdate(completedStages.map((stage) => ({ ...stage })))

    await sleep(completedStages[index].duration_ms)

    if (options?.stopWhen?.()) {
      const stoppedStages = options.onStop?.(completedStages) ?? completedStages
      onUpdate(stoppedStages.map((stage) => ({ ...stage })))
      return stoppedStages
    }

    completedStages[index] = { ...completedStages[index], status: 'complete' }
    onUpdate(completedStages.map((stage) => ({ ...stage })))
  }

  return completedStages
}
