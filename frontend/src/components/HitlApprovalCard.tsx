'use client'

import { AlertTriangle, CheckCircle2, Loader2, ShieldAlert, XCircle } from 'lucide-react'

export interface HitlOperation {
  id: string
  label: string
  risk: string
}

export interface HitlRequestInfo {
  required: boolean
  approved: boolean
  policy_id?: string
  kind?: string
  title?: string
  summary?: string
  operations?: HitlOperation[]
  status?: string
  proposals?: Record<string, string>
}

interface HitlApprovalCardProps {
  hitl: HitlRequestInfo
  originalMessage: string
  isSubmitting?: boolean
  onApprove: () => void
  onReject: () => void
}

function riskStyles(risk: string): string {
  switch (risk) {
    case 'critical':
      return 'border-rose-200 bg-rose-50 text-rose-800'
    case 'high':
      return 'border-amber-200 bg-amber-50 text-amber-900'
    case 'medium':
      return 'border-orange-200 bg-orange-50 text-orange-900'
    case 'info':
      return 'border-emerald-200 bg-emerald-50 text-emerald-900'
    default:
      return 'border-slate-200 bg-slate-50 text-slate-700'
  }
}

export function HitlApprovalCard({
  hitl,
  originalMessage,
  isSubmitting = false,
  onApprove,
  onReject,
}: HitlApprovalCardProps) {
  const pending = hitl.required && !hitl.approved && hitl.status !== 'rejected'
  const rejected = hitl.status === 'rejected'
  const approved = hitl.approved || hitl.status === 'approved'

  return (
    <div className="space-y-4">
      <div
        className={`rounded-2xl border p-4 ${
          pending
            ? 'border-amber-300/80 bg-gradient-to-br from-amber-50 to-orange-50'
            : approved
              ? 'border-emerald-300/80 bg-gradient-to-br from-emerald-50 to-teal-50'
              : 'border-slate-200 bg-slate-50'
        }`}
      >
        <div className="flex items-start gap-3">
          <div
            className={`mt-0.5 flex h-10 w-10 items-center justify-center rounded-xl ${
              pending
                ? 'bg-amber-500/15 text-amber-700'
                : approved
                  ? 'bg-emerald-500/15 text-emerald-700'
                  : 'bg-slate-200 text-slate-600'
            }`}
          >
            {pending ? (
              <ShieldAlert className="h-5 w-5" />
            ) : approved ? (
              <CheckCircle2 className="h-5 w-5" />
            ) : (
              <XCircle className="h-5 w-5" />
            )}
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-sm font-semibold text-slate-900">
                {hitl.title || 'Human approval required'}
              </p>
              {hitl.policy_id && (
                <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">
                  {hitl.policy_id}
                </span>
              )}
            </div>
            <p className="mt-1 text-sm leading-relaxed text-slate-600">
              {hitl.summary ||
                'A human must review this action before the agent can continue.'}
            </p>
            {pending && (
              <p className="mt-2 text-xs text-slate-500">
                Request: <span className="font-medium text-slate-700">{originalMessage}</span>
              </p>
            )}
          </div>
        </div>

        {hitl.operations && hitl.operations.length > 0 && (
          <div className="mt-4 space-y-2">
            <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">
              {pending ? 'Pending operations' : 'Operations'}
            </p>
            {hitl.operations.map((operation) => (
              <div
                key={operation.id}
                className={`flex items-center justify-between gap-3 rounded-xl border px-3 py-2.5 text-sm ${riskStyles(operation.risk)}`}
              >
                <div className="flex items-center gap-2">
                  {pending ? (
                    <AlertTriangle className="h-4 w-4 shrink-0 opacity-80" />
                  ) : (
                    <CheckCircle2 className="h-4 w-4 shrink-0 opacity-80" />
                  )}
                  <span className="font-medium">{operation.label}</span>
                </div>
                <span className="text-[10px] font-semibold uppercase tracking-[0.14em] opacity-70">
                  {operation.risk}
                </span>
              </div>
            ))}
          </div>
        )}

        {pending && (
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={onApprove}
              disabled={isSubmitting}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Applying with approval…
                </>
              ) : (
                'Approve & continue'
              )}
            </button>
            <button
              type="button"
              onClick={onReject}
              disabled={isSubmitting}
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-300 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
            >
              Reject
            </button>
          </div>
        )}

        {rejected && (
          <p className="mt-4 text-sm font-medium text-slate-700">
            Request rejected. No changes were applied.
          </p>
        )}
      </div>
    </div>
  )
}
