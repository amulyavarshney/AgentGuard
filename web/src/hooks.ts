import { useCallback, useEffect, useState } from 'react'

export function useFetch<T>(fetcher: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const reload = useCallback(() => {
    setLoading(true)
    setError(null)
    fetcher()
      .then(setData)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, deps) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    reload()
  }, [reload])

  return { data, loading, error, reload }
}

export function formatTime(iso: string) {
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

export function decisionClass(decision: string) {
  switch (decision) {
    case 'allow':
      return 'decision allow'
    case 'block':
      return 'decision block'
    case 'require_approval':
      return 'decision approval'
    case 'pause_and_escalate':
      return 'decision escalate'
    default:
      return 'decision'
  }
}
