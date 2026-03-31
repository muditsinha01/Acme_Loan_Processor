import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Acme Loan Assistant',
  description: 'Lightweight AI assistant for document review and loan-related chat',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
