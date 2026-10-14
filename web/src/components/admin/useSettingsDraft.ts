import { useState, type SetStateAction } from 'react'

/** Keep edits in memory when another settings section refreshes the shared revision. */
export function useSettingsDraft<T>(revision: number, value: T, extraDirty = false) {
  const [state, setState] = useState({ revision, initial: value, value })
  const dirty = extraDirty || JSON.stringify(state.value) !== JSON.stringify(state.initial)
  const unchanged = JSON.stringify(value) === JSON.stringify(state.initial)
  if (revision !== state.revision && (!dirty || (unchanged && !extraDirty))) {
    setState({ revision, initial: value, value: dirty ? state.value : value })
  }
  return {
    revision: state.revision,
    value: state.value,
    dirty,
    stale: revision !== state.revision && dirty,
    setValue: (next: SetStateAction<T>) => setState((previous) => ({
      ...previous,
      value: typeof next === 'function' ? (next as (previous: T) => T)(previous.value) : next,
    })),
    accept: (nextRevision: number, nextValue: T) => setState({ revision: nextRevision, initial: nextValue, value: nextValue }),
    reset: () => setState({ revision, initial: value, value }),
  }
}
