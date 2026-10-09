import { create } from 'zustand'

// Tiny UI state: one transient message at a time. Server state lives in React
// Query; this only carries already-localized confirmation text.
export type ToastSeverity = 'success' | 'info' | 'error'

interface ToastState {
  id: number
  message: string | null
  severity: ToastSeverity
  show: (message: string, severity?: ToastSeverity) => void
  hide: () => void
}

export const useToast = create<ToastState>((set) => ({
  id: 0,
  message: null,
  severity: 'success',
  show: (message, severity = 'success') =>
    set((s) => ({ id: s.id + 1, message, severity })),
  hide: () => set({ message: null }),
}))
