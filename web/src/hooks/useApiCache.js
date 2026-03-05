/**
 * Stale-While-Revalidate cache for API data.
 *
 * How it works:
 *   1. On mount, the hook returns the LAST cached value instantly (no spinner).
 *   2. A fresh fetch runs in the background.
 *   3. When the response arrives, state + cache are updated silently.
 *
 * The cache lives in a module-level Map so it survives React unmount/remount
 * (i.e. tab switches).  No external dependencies — just React.
 */
import { useState, useEffect, useCallback, useRef } from 'react'

// Module-level store — persists across component mounts
const _cache = new Map()

/**
 * @param {string}   key       Unique cache key (e.g. 'dashboard', 'alerts')
 * @param {Function} fetcher   Async function that returns the data
 * @param {Object}   opts
 * @param {Array}    opts.deps Extra deps that should re-trigger the fetch
 * @param {*}        opts.fallback Default value when nothing is cached yet
 * @returns {{ data, loading, refresh }}
 */
export function useApiCache(key, fetcher, { deps = [], fallback = null } = {}) {
    const cached = _cache.get(key)
    const [data, setData] = useState(cached !== undefined ? cached : fallback)
    const [loading, setLoading] = useState(cached === undefined)  // Only show spinner on cold start
    const fetcherRef = useRef(fetcher)
    fetcherRef.current = fetcher

    const refresh = useCallback(async () => {
        // If we already have cached data, don't flash a spinner — just
        // silently update when the response arrives (stale-while-revalidate).
        if (!_cache.has(key)) setLoading(true)

        try {
            const result = await fetcherRef.current()
            _cache.set(key, result)
            setData(result)
        } catch {
            // Silently ignore — keep showing stale data
        } finally {
            setLoading(false)
        }
    }, [key])

    useEffect(() => {
        refresh()
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [key, refresh, ...deps])

    return { data, loading, refresh }
}

/**
 * Invalidate a specific cache key (useful after mutations like delete).
 */
export function invalidateCache(key) {
    _cache.delete(key)
}

/**
 * Clear the entire cache (e.g. on session switch).
 */
export function clearCache() {
    _cache.clear()
}
