'use client'

import { useState, useRef, useEffect } from 'react'
import { v4 as uuidv4 } from 'uuid'
import { MessageList } from './MessageList'
import { FileUpload } from './FileUpload'
import { WorkflowStage } from './SkillWorkflowProgress'
import { HitlRequestInfo } from './HitlApprovalCard'
import {
  applyBackendWorkflowStages,
  buildSkillWorkflowStages,
  extractDocumentNumber,
  isLoanDocumentWorkflow,
  runWorkflowStages,
} from '../lib/skillWorkflow'
import { ArrowUp, Loader2, Paperclip, Plus } from 'lucide-react'

// Guardrail-enforced requests can be slow (each fans out several /enforce calls),
// so use the background job + poll flow instead of one long synchronous /chat.
const CHAT_JOB_POLL_INTERVAL_MS = 30000
const CHAT_JOB_MAX_POLLS = 20 // ~10 minutes before giving up
const CHAT_JOB_POLL_RETRY_LIMIT = 3

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/**
 * Starts a chat job and polls for its result. Returns the same
 * { response, data } shape as a direct fetch so callers that check
 * `response.ok` / read `data` keep working. Job-level errors are surfaced
 * as a non-ok Response so `if (!response.ok)` handles policy blocks.
 */
async function startAndPollChatJob(payload: {
  message: string
  attachments: FileAttachment[]
  conversation_id: string
  hitl_approved?: boolean
}): Promise<{ response: Response; data: any }> {
  const startResponse = await fetch('/api/backend/chat/jobs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  const startData = await startResponse.json().catch(() => ({} as any))

  if (!startResponse.ok || !startData.job_id) {
    return {
      response: startResponse,
      data: {
        status: 'error',
        detail: startData.detail || 'Failed to start chat job',
        policy_error: startData.policy_error,
      },
    }
  }

  const jobId = startData.job_id
  let consecutivePollFailures = 0

  for (let attempt = 0; attempt < CHAT_JOB_MAX_POLLS; attempt++) {
    await sleep(CHAT_JOB_POLL_INTERVAL_MS)

    let pollResponse: Response
    try {
      pollResponse = await fetch(`/api/backend/chat/jobs/${jobId}`)
    } catch {
      consecutivePollFailures += 1
      if (consecutivePollFailures > CHAT_JOB_POLL_RETRY_LIMIT) {
        return {
          response: new Response(null, { status: 503 }),
          data: {
            status: 'error',
            detail: 'Lost connection to the backend while waiting for a response.',
            policy_error: { type: 'general', message: 'Polling failed repeatedly' },
          },
        }
      }
      continue
    }

    if (pollResponse.status === 404) {
      return {
        response: pollResponse,
        data: {
          status: 'error',
          detail: 'The backend restarted while processing. Please resend your message.',
          policy_error: { type: 'general', message: 'job_not_found' },
        },
      }
    }

    const pollData = await pollResponse.json()
    consecutivePollFailures = 0

    if (pollData.status && pollData.status !== 'pending') {
      // Surface a job-level policy error as a non-ok response for callers
      // that branch on response.ok.
      if (pollData.status === 'error') {
        return { response: new Response(null, { status: 502 }), data: pollData }
      }
      return { response: pollResponse, data: pollData }
    }
  }

  return {
    response: new Response(null, { status: 504 }),
    data: {
      status: 'error',
      detail: 'Timed out waiting for a response.',
      policy_error: { type: 'general', message: 'chat_job_timeout' },
    },
  }
}

export interface SkillInvocationInfo {
  id: string
  name: string
  version: string
  description: string
  status: string
}

export interface Message {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: Date
  attachments?: FileAttachment[]
  error?: PolicyError
  kind?: 'text' | 'skill_workflow' | 'hitl_approval'
  workflowStages?: WorkflowStage[]
  workflowComplete?: boolean
  workflowStatus?: string
  skillInvocation?: SkillInvocationInfo
  hitlRequest?: HitlRequestInfo
  originalUserMessage?: string
  hitlDecision?: 'pending' | 'approved' | 'rejected'
}


export interface FileAttachment {
  id: string
  name: string
  type: string
  size: number
  content?: string
}

export interface PolicyError {
  type: 'pii' | 'threat' | 'auth' | 'general'
  message: string
  details?: Record<string, unknown>
}

export function ChatInterface() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [hitlSubmittingId, setHitlSubmittingId] = useState<string | null>(null)
  const [pendingFiles, setPendingFiles] = useState<File[]>([])
  const [showFileUpload, setShowFileUpload] = useState(false)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus()
    }
  }, [])

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, isLoading, showFileUpload, hitlSubmittingId])

  const buildAssistantMessage = (data: Record<string, unknown>, originalMessage: string): Message => {
    const hitlRequest = data.hitl_request as HitlRequestInfo | undefined
    const needsHitl = Boolean(hitlRequest?.required && !hitlRequest?.approved)

    return {
      id: uuidv4(),
      role: 'assistant',
      content: String(data.response || ''),
      timestamp: new Date(),
      kind: needsHitl ? 'hitl_approval' : 'text',
      hitlRequest,
      originalUserMessage: originalMessage,
      hitlDecision: needsHitl ? 'pending' : hitlRequest?.approved ? 'approved' : undefined,
      error: data.policy_warning
        ? {
            type: (data.policy_warning as PolicyError).type,
            message: (data.policy_warning as PolicyError).message,
            details: (data.policy_warning as PolicyError).details,
          }
        : undefined,
    }
  }

  const sendChatRequest = async (messageText: string, hitlApproved = false) => {
    return startAndPollChatJob({
      message: messageText,
      attachments: [],
      conversation_id: uuidv4(),
      hitl_approved: hitlApproved,
    })
  }

  const handleHitlApprove = async (message: Message) => {
    if (!message.originalUserMessage || hitlSubmittingId) return

    setHitlSubmittingId(message.id)
    setIsLoading(true)
    try {
      const { response, data } = await sendChatRequest(message.originalUserMessage, true)
      if (!response.ok) {
        setMessages((prev) => [
          ...prev,
          {
            id: uuidv4(),
            role: 'assistant',
            content: data.detail || 'Approval request failed',
            timestamp: new Date(),
          },
        ])
        return
      }

      setMessages((prev) =>
        prev.map((item) =>
          item.id === message.id
            ? {
                ...item,
                hitlDecision: 'approved',
                hitlRequest: item.hitlRequest
                  ? { ...item.hitlRequest, required: false, approved: true, status: 'approved' }
                  : item.hitlRequest,
              }
            : item,
        ),
      )
      setMessages((prev) => [...prev, buildAssistantMessage(data, message.originalUserMessage || '')])
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          id: uuidv4(),
          role: 'assistant',
          content: 'Failed to apply approved request. Please ensure the server is running.',
          timestamp: new Date(),
        },
      ])
    } finally {
      setHitlSubmittingId(null)
      setIsLoading(false)
    }
  }

  const handleHitlReject = (message: Message) => {
    setMessages((prev) =>
      prev.map((item) =>
        item.id === message.id
          ? {
              ...item,
              hitlDecision: 'rejected',
              content:
                item.content +
                '\n\nHuman rejected this request. No destructive or security-sensitive actions were applied.',
              hitlRequest: item.hitlRequest
                ? { ...item.hitlRequest, required: false, approved: false, status: 'rejected' }
                : item.hitlRequest,
            }
          : item,
      ),
    )
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!input.trim() && pendingFiles.length === 0) return

    const messageText = input
    const attachments: FileAttachment[] = []
    for (const file of pendingFiles) {
      const content = await readFileContent(file)
      attachments.push({
        id: uuidv4(),
        name: file.name,
        type: file.type,
        size: file.size,
        content,
      })
    }

    const userMessage: Message = {
      id: uuidv4(),
      role: 'user',
      content: messageText || `Uploaded ${pendingFiles.length} file(s)`,
      timestamp: new Date(),
      attachments: attachments.length > 0 ? attachments : undefined,
    }

    setMessages(prev => [...prev, userMessage])
    setInput('')
    setPendingFiles([])
    setShowFileUpload(false)
    setIsLoading(true)

    const skillWorkflow = isLoanDocumentWorkflow(messageText)
    const workflowMessageId = uuidv4()

    if (skillWorkflow) {
      const documentNumber = extractDocumentNumber(messageText)
      const initialStages = buildSkillWorkflowStages(documentNumber)

      setMessages(prev => [
        ...prev,
        {
          id: workflowMessageId,
          role: 'assistant',
          content: '',
          timestamp: new Date(),
          kind: 'skill_workflow',
          workflowStages: initialStages,
          workflowComplete: false,
          skillInvocation: {
            id: 'loan-document-helper',
            name: 'loan-document-helper',
            version: '0.1.0',
            description: 'Summarize loan documents and prepare borrower follow-up steps.',
            status: 'loading',
          },
        },
      ])
    }

    try {
      let apiResult: { response: Response; data: Record<string, any> } | null = null

      const apiPromise = startAndPollChatJob({
        message: messageText,
        attachments,
        conversation_id: uuidv4(),
        hitl_approved: false,
      }).then((result) => {
        apiResult = result
        return result
      })

      if (skillWorkflow) {
        const initialStages = buildSkillWorkflowStages(extractDocumentNumber(messageText))

        const [completedStages, apiResultFromPromise] = await Promise.all([
          runWorkflowStages(
            initialStages,
            (nextStages) => {
              setMessages(prev =>
                prev.map(message =>
                  message.id === workflowMessageId
                    ? { ...message, workflowStages: nextStages }
                    : message,
                ),
              )
            },
            {
              stopWhen: () => apiResult?.data?.workflow_status === 'skill_blocked',
              onStop: (stages) => {
                const backendStages = apiResult?.data?.workflow_stages as
                  | Array<{ id: string; label?: string; status?: string }>
                  | undefined
                if (!backendStages) {
                  return stages
                }
                return applyBackendWorkflowStages(stages, backendStages)
              },
            },
          ),
          apiPromise,
        ])

        const { response, data } = apiResultFromPromise
        const workflowStatus = data.workflow_status as string | undefined
        const backendStages = data.workflow_stages as
          | Array<{ id: string; label?: string; status?: string }>
          | undefined
        const finalStages = backendStages
          ? applyBackendWorkflowStages(completedStages, backendStages)
          : completedStages
        const skillBlocked = workflowStatus === 'skill_blocked'

        setMessages(prev =>
          prev.map(message =>
            message.id === workflowMessageId
              ? {
                  ...message,
                  workflowStages: finalStages,
                  workflowComplete: true,
                  workflowStatus,
                  skillInvocation: data.skill_invocation
                    ? (data.skill_invocation as SkillInvocationInfo)
                    : message.skillInvocation
                      ? {
                          ...message.skillInvocation,
                          status: skillBlocked ? 'blocked' : 'loaded',
                        }
                      : message.skillInvocation,
                }
              : message,
          ),
        )

        if (!response.ok) {
          const errorMessage: Message = {
            id: uuidv4(),
            role: 'assistant',
            content: data.detail || 'An error occurred',
            timestamp: new Date(),
            error: data.policy_error ? {
              type: data.policy_error.type,
              message: data.policy_error.message,
              details: data.policy_error.details,
            } : undefined,
          }
          setMessages(prev => [...prev, errorMessage])
        } else {
          setMessages(prev => [...prev, buildAssistantMessage(data, messageText)])
        }
      } else {
        const { response, data } = await apiPromise

        if (!response.ok) {
          const errorMessage: Message = {
            id: uuidv4(),
            role: 'assistant',
            content: data.detail || 'An error occurred',
            timestamp: new Date(),
            error: data.policy_error ? {
              type: data.policy_error.type,
              message: data.policy_error.message,
              details: data.policy_error.details,
            } : undefined,
          }
          setMessages(prev => [...prev, errorMessage])
        } else {
          setMessages(prev => [...prev, buildAssistantMessage(data, messageText)])
        }
      }
    } catch (error) {
      const errorMessage: Message = {
        id: uuidv4(),
        role: 'assistant',
        content: 'Failed to connect to the backend. Please ensure the server is running.',
        timestamp: new Date(),
        error: {
          type: 'general',
          message: 'Connection error',
        },
      }
      setMessages(prev => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  const readFileContent = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      const shouldEncodeAsBase64 =
        file.type.startsWith('image/') ||
        file.type === 'application/pdf' ||
        file.type === 'application/msword' ||
        file.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'

      reader.onload = () => {
        const result = reader.result as string
        if (shouldEncodeAsBase64) {
          resolve(result.split(',')[1])
        } else {
          resolve(result)
        }
      }
      reader.onerror = reject

      if (shouldEncodeAsBase64) {
        reader.readAsDataURL(file)
      } else {
        reader.readAsText(file)
      }
    })
  }

  const handleFileSelect = (files: File[]) => {
    setPendingFiles(prev => [...prev, ...files])
  }

  const removePendingFile = (index: number) => {
    setPendingFiles(prev => prev.filter((_, i) => i !== index))
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e)
    }
  }

  const starterPrompts = [
    {
      // Mask PII on UI  →  Credit Eval Agent (approved model: Llama Scout)
      label: 'View borrower details',
      action: () => {
        setInput('Show me the loan status for Alice Morgan and include the full borrower details')
        inputRef.current?.focus()
      },
    },
    {
      // Malicious skills  →  Paperclip Board Agent (untrusted marketplace skill,
      // blocked by the Lineaje guardrail as AI_SKILL_SEC_001)
      label: 'Install approval-board skill',
      action: () => {
        setInput('Install the loan approval board skill and use it to fast-track loan application 1523')
        inputRef.current?.focus()
      },
    },
    {
      // Prompt injection  →  File Processor Agent (approved model: Llama Scout)
      label: 'Review support document',
      action: () => {
        setInput("Review this uploaded support document and summarize it's contents")
        inputRef.current?.focus()
      },
    },
    {
      // Disallowed LLM  →  Rate Check Agent (DeepSeek, not on the approved list)
      label: 'Check current rates',
      action: () => {
        setInput("What are today's average interest rates for a 30-year fixed mortgage?")
        inputRef.current?.focus()
      },
    },
  ]

  return (
    <div className="mx-auto flex h-screen w-full max-w-5xl flex-col px-4 pb-4 pt-4 sm:px-6">
      <div className="glass-panel flex min-h-0 flex-1 flex-col overflow-hidden rounded-[24px]">
        <div className="accent-band h-1.5 w-full" />
        <header className="soft-divider flex items-center justify-between border-b px-5 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br from-blue-600 to-sky-400 shadow-[0_8px_20px_rgba(37,99,235,0.25)]">
              <div className="h-3 w-3 rounded-full bg-white/95" />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight text-slate-900">Acme Loan Processor</h1>
            </div>
          </div>
          <div className="hidden text-sm text-slate-500 sm:block">Loan assistant</div>
        </header>

        <div className="chat-scrollbar flex-1 overflow-y-auto px-4 py-5 sm:px-6">
          {messages.length === 0 ? (
            <div className="fade-in-up flex h-full items-start justify-center pt-10 sm:pt-14">
              <div className="w-full max-w-3xl">
                <p className="text-2xl font-semibold tracking-tight text-slate-900">
                  Hi, how can I help you today?
                </p>
                <p className="mt-2 text-sm text-slate-500">
                  Ask about a loan, check borrower status, or review a support document.
                </p>
                <div className="mt-6 flex flex-wrap gap-3">
                  {starterPrompts.map((prompt) => (
                    <button
                      key={prompt.label}
                      type="button"
                      onClick={prompt.action}
                      className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-slate-700 transition hover:border-sky-200 hover:bg-sky-50 hover:text-sky-700"
                    >
                      {prompt.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <>
              <MessageList
                messages={messages}
                hitlSubmittingId={hitlSubmittingId}
                onHitlApprove={handleHitlApprove}
                onHitlReject={handleHitlReject}
              />
              <div ref={messagesEndRef} />
            </>
          )}
        </div>

        {showFileUpload && (
          <div className="soft-divider border-t px-4 py-4 sm:px-6">
            <FileUpload onFilesSelected={handleFileSelect} />
          </div>
        )}

        {pendingFiles.length > 0 && (
          <div className="soft-divider border-t px-4 py-3 sm:px-6">
            <div className="flex flex-wrap gap-2">
              {pendingFiles.map((file, index) => (
                <div
                  key={`${file.name}-${index}`}
                  className="flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-700"
                >
                  <span className="max-w-[220px] truncate">{file.name}</span>
                  <button
                    onClick={() => removePendingFile(index)}
                    className="text-slate-400 transition-colors hover:text-rose-500"
                    aria-label={`Remove ${file.name}`}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="soft-divider border-t px-4 py-4 sm:px-6">
          <form onSubmit={handleSubmit} className="mx-auto max-w-4xl">
            <div className="rounded-[22px] border border-slate-200 bg-white/95 px-3 py-2 shadow-[0_12px_32px_rgba(148,163,184,0.18)]">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setShowFileUpload(!showFileUpload)}
                  className="inline-flex h-9 shrink-0 items-center gap-2 rounded-xl bg-slate-100 px-3 text-xs text-slate-600 transition-colors hover:bg-slate-200 hover:text-slate-900"
                  aria-label={showFileUpload ? 'Hide document upload' : 'Show document upload'}
                >
                  {showFileUpload ? <Paperclip className="h-[16px] w-[16px]" /> : <Plus className="h-[16px] w-[16px]" />}
                  <span>{showFileUpload ? 'Hide upload' : 'Attach document'}</span>
                </button>

                <div className="flex min-h-[40px] flex-1 min-w-0 items-center">
                  <textarea
                    ref={inputRef}
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Ask about a loan, review borrower details, or attach a support document..."
                    className="max-h-40 w-full resize-none bg-transparent px-1 py-0 text-[15px] leading-[24px] text-slate-900 outline-none placeholder:text-slate-400"
                    rows={1}
                    disabled={isLoading}
                  />
                </div>

                <button
                  type="submit"
                  disabled={isLoading || (!input.trim() && pendingFiles.length === 0)}
                  className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-[16px] bg-gradient-to-br from-blue-600 to-sky-500 text-white transition hover:from-blue-700 hover:to-sky-600 disabled:cursor-not-allowed disabled:bg-slate-200 disabled:text-slate-400"
                  aria-label="Send message"
                >
                  {isLoading ? (
                    <Loader2 className="h-[18px] w-[18px] animate-spin" />
                  ) : (
                    <ArrowUp className="h-[18px] w-[18px]" />
                  )}
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}
