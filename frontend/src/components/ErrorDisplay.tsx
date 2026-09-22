'use client'

import { PolicyError } from './ChatInterface'
import { AlertTriangle, Shield, Eye, Lock, AlertCircle } from 'lucide-react'

interface ErrorDisplayProps {
  error: PolicyError
}

export function ErrorDisplay({ error }: ErrorDisplayProps) {
  // Light-theme (bright-white UI) colors: dark, high-contrast text on soft
  // tinted backgrounds so blocked/error messages are clearly readable.
  const getErrorConfig = (type: PolicyError['type']) => {
    switch (type) {
      case 'pii':
        return {
          icon: Eye,
          title: 'PII Detected',
          bgColor: 'bg-red-50',
          borderColor: 'border-red-300',
          iconColor: 'text-red-600',
          titleColor: 'text-red-700',
        }
      case 'threat':
        return {
          icon: AlertTriangle,
          title: 'Security Threat Detected',
          bgColor: 'bg-orange-50',
          borderColor: 'border-orange-300',
          iconColor: 'text-orange-600',
          titleColor: 'text-orange-700',
        }
      case 'auth':
        return {
          icon: Lock,
          title: 'Authorization Error',
          bgColor: 'bg-amber-50',
          borderColor: 'border-amber-300',
          iconColor: 'text-amber-600',
          titleColor: 'text-amber-700',
        }
      default:
        // Generic errors + guardrail policy blocks land here.
        return {
          icon: AlertCircle,
          title: 'Blocked by policy',
          bgColor: 'bg-rose-50',
          borderColor: 'border-rose-300',
          iconColor: 'text-rose-600',
          titleColor: 'text-rose-700',
        }
    }
  }

  const config = getErrorConfig(error.type)
  const Icon = config.icon

  return (
    <div
      className={`${config.bgColor} ${config.borderColor} rounded-[20px] border p-4`}
    >
      <div className="flex items-start gap-3">
        <div className={`flex-shrink-0 ${config.iconColor}`}>
          <Shield className="w-5 h-5" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <Icon className={`w-4 h-4 ${config.iconColor}`} />
            <h4 className={`font-semibold ${config.titleColor}`}>
              {config.title}
            </h4>
          </div>
          <p className="text-slate-800 text-sm leading-relaxed">{error.message}</p>

          {error.details && Object.keys(error.details).length > 0 && (
            <div className="mt-3 text-xs">
              <details className="cursor-pointer">
                <summary className="text-slate-600 hover:text-slate-900">
                  View Details
                </summary>
                <pre className="mt-2 overflow-x-auto rounded-xl bg-slate-100 p-3 text-slate-700">
                  {JSON.stringify(error.details, null, 2)}
                </pre>
              </details>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
