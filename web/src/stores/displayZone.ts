import { create } from 'zustand'

// The time zone the server shows times in (GET /me -> server.display_timezone), the same
// one the server-rendered pages and the audit log use. Not a preference of the person
// and never persisted: AccountShell sets it from each GET /me answer.

interface DisplayZoneState {
  zone: string | null
  setZone: (zone: string | null) => void
}

export const useDisplayZone = create<DisplayZoneState>((set) => ({
  zone: null,
  setZone: (zone) => set({ zone }),
}))
