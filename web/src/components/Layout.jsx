import { Outlet, useLocation } from 'react-router-dom'
import { useSession } from '../context/SessionContext'
import Sidebar from './Sidebar'
import { X, Database } from 'lucide-react'

const Layout = () => {
    const { sessionId, sessionInfo, unloadSession } = useSession()
    const location = useLocation()
    const isCaptureRoute = location.pathname === '/capture'

    const fmtTime = (isoStr) => {
        if (!isoStr) return ''
        const d = new Date(isoStr)
        const pad = n => String(n).padStart(2, '0')
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
    }

    return (
        <div className="layout">
            <Sidebar />
            <main className="main-content fade-in">
                {/* Session banner — shown when a session is loaded (except on Capture page) */}
                {sessionId && !isCaptureRoute && (
                    <div style={{
                        display: 'flex', alignItems: 'center', gap: '0.75rem',
                        padding: '0.6rem 1.25rem',
                        marginBottom: '1rem',
                        borderRadius: '12px',
                        background: 'linear-gradient(135deg, rgba(188,19,254,0.08), rgba(0,243,255,0.05))',
                        border: '1px solid rgba(188,19,254,0.2)',
                        backdropFilter: 'blur(8px)',
                        animation: 'fadeIn 0.3s ease',
                    }}>
                        <div style={{
                            width: '30px', height: '30px', borderRadius: '8px',
                            background: 'rgba(188,19,254,0.15)', border: '1px solid rgba(188,19,254,0.3)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            flexShrink: 0,
                        }}>
                            <Database size={14} color="#bc13fe" />
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                            <span style={{
                                fontSize: '0.78rem', fontWeight: 700, color: '#bc13fe',
                                letterSpacing: '0.03em',
                            }}>
                                SESSION #{sessionId}
                            </span>
                            {sessionInfo && (
                                <span style={{ fontSize: '0.75rem', color: '#8b8b9b', marginLeft: '0.75rem' }}>
                                    {sessionInfo.interface && <span style={{ fontFamily: 'monospace', color: '#00f3ff' }}>{sessionInfo.interface}</span>}
                                    {sessionInfo.start_time && <span style={{ marginLeft: '0.5rem' }}>· {fmtTime(sessionInfo.start_time)}</span>}
                                </span>
                            )}
                            <span style={{ fontSize: '0.72rem', color: '#5a5a6e', marginLeft: '0.75rem' }}>
                                Viewing session data only
                            </span>
                        </div>
                        <button
                            onClick={unloadSession}
                            style={{
                                display: 'flex', alignItems: 'center', gap: '0.3rem',
                                padding: '0.35rem 0.75rem', borderRadius: '6px',
                                background: 'rgba(255,255,255,0.06)',
                                border: '1px solid rgba(255,255,255,0.1)',
                                color: '#8b8b9b', cursor: 'pointer',
                                fontSize: '0.72rem', fontWeight: 600,
                                transition: 'all 0.15s',
                                flexShrink: 0,
                            }}
                            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,42,42,0.12)'; e.currentTarget.style.color = '#ff6b9d'; e.currentTarget.style.borderColor = 'rgba(255,42,42,0.25)' }}
                            onMouseLeave={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.06)'; e.currentTarget.style.color = '#8b8b9b'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)' }}
                        >
                            <X size={12} />
                            Unload
                        </button>
                    </div>
                )}
                <Outlet />
            </main>
        </div>
    )
}

export default Layout
