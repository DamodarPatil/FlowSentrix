import { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react'

const API = 'http://localhost:8000'

const SessionContext = createContext({
    sessionId: null,
    sessionInfo: null,
    loadSession: () => { },
    unloadSession: () => { },
})

export const useSession = () => useContext(SessionContext)

export const SessionProvider = ({ children }) => {
    const [sessionId, setSessionId] = useState(null)
    const [sessionInfo, setSessionInfo] = useState(null)
    const [warning, setWarning] = useState('')
    const pollRef = useRef(null)

    const unloadSession = useCallback(() => {
        setSessionId(null)
        setSessionInfo(null)
        if (pollRef.current) {
            clearInterval(pollRef.current)
            pollRef.current = null
        }
    }, [])

    const loadSession = useCallback(async (id) => {
        try {
            const res = await fetch(`${API}/api/sessions/${id}/check`)
            const data = await res.json()
            if (data.exists) {
                setSessionId(data.id)
                setSessionInfo({
                    id: data.id,
                    interface: data.interface,
                    start_time: data.start_time,
                })
                setWarning('')
            }
        } catch (e) { /* api offline */ }
    }, [])

    // Poll for session validity while a session is loaded
    useEffect(() => {
        if (!sessionId) return

        const check = async () => {
            try {
                const res = await fetch(`${API}/api/sessions/${sessionId}/check`)
                const data = await res.json()
                if (!data.exists) {
                    setWarning(`Session #${sessionId} is no longer available — it may have been deleted`)
                    unloadSession()
                }
            } catch (e) { /* api offline, keep session */ }
        }

        pollRef.current = setInterval(check, 10000)
        return () => {
            if (pollRef.current) {
                clearInterval(pollRef.current)
                pollRef.current = null
            }
        }
    }, [sessionId, unloadSession])

    // Auto-dismiss warning after 6s
    useEffect(() => {
        if (!warning) return
        const t = setTimeout(() => setWarning(''), 6000)
        return () => clearTimeout(t)
    }, [warning])

    return (
        <SessionContext.Provider value={{ sessionId, sessionInfo, loadSession, unloadSession }}>
            {children}

            {/* Warning toast for deleted session */}
            {warning && (
                <div style={{
                    position: 'fixed', bottom: '1.5rem', left: '50%', transform: 'translateX(-50%)',
                    padding: '0.75rem 1.25rem', borderRadius: '12px',
                    background: 'rgba(255,42,42,0.12)', border: '1px solid rgba(255,42,42,0.3)',
                    backdropFilter: 'blur(16px)', color: '#ff6b9d',
                    fontSize: '0.82rem', fontWeight: 600, zIndex: 9999,
                    display: 'flex', alignItems: 'center', gap: '0.5rem',
                    animation: 'fadeIn 0.3s ease',
                    maxWidth: '600px',
                }}>
                    ⚠ {warning}
                    <button
                        onClick={() => setWarning('')}
                        style={{
                            background: 'none', border: 'none', color: '#ff6b9d',
                            cursor: 'pointer', fontSize: '1rem', padding: '0 0.25rem',
                            marginLeft: '0.5rem',
                        }}
                    >✕</button>
                </div>
            )}
        </SessionContext.Provider>
    )
}

export default SessionContext
