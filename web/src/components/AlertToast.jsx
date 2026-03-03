import { useState, useEffect, useRef, useCallback } from 'react'
import { AlertTriangle, Shield, Zap, X, ChevronRight } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

const API = 'http://localhost:8000'
const TOAST_DURATION = 8000 // ms

const SEV_CONFIG = {
    high: {
        color: '#ff2a2a',
        glow: 'rgba(255,42,42,0.3)',
        bg: 'rgba(255,42,42,0.08)',
        border: 'rgba(255,42,42,0.35)',
        label: 'CRITICAL',
        icon: Zap,
        pulse: '#ff2a2a',
    },
    medium: {
        color: '#ffaa00',
        glow: 'rgba(255,170,0,0.3)',
        bg: 'rgba(255,170,0,0.08)',
        border: 'rgba(255,170,0,0.35)',
        label: 'WARNING',
        icon: Shield,
        pulse: '#ffaa00',
    },
    low: {
        color: '#00f3ff',
        glow: 'rgba(0,243,255,0.25)',
        bg: 'rgba(0,243,255,0.06)',
        border: 'rgba(0,243,255,0.25)',
        label: 'INFO',
        icon: AlertTriangle,
        pulse: '#00f3ff',
    },
}

const Toast = ({ toast, onDismiss }) => {
    const navigate = useNavigate()
    const [progress, setProgress] = useState(100)
    const [entering, setEntering] = useState(true)
    const [leaving, setLeaving] = useState(false)
    const intervalRef = useRef(null)

    const cfg = SEV_CONFIG[toast.severity] || SEV_CONFIG.low
    const Icon = cfg.icon

    const handleDismiss = useCallback(() => {
        setLeaving(true)
        setTimeout(() => onDismiss(toast.id), 350)
    }, [toast.id, onDismiss])

    useEffect(() => {
        // Entrance animation
        const entranceTimer = setTimeout(() => setEntering(false), 50)

        // Progress bar countdown
        const step = 100 / (TOAST_DURATION / 50)
        intervalRef.current = setInterval(() => {
            setProgress(p => {
                if (p <= 0) {
                    clearInterval(intervalRef.current)
                    handleDismiss()
                    return 0
                }
                return p - step
            })
        }, 50)

        return () => {
            clearTimeout(entranceTimer)
            clearInterval(intervalRef.current)
        }
    }, [handleDismiss])

    const pauseProgress = () => clearInterval(intervalRef.current)
    const resumeProgress = () => {
        const step = 100 / (TOAST_DURATION / 50)
        intervalRef.current = setInterval(() => {
            setProgress(p => {
                if (p <= 0) { handleDismiss(); return 0 }
                return p - step
            })
        }, 50)
    }

    return (
        <div
            onMouseEnter={pauseProgress}
            onMouseLeave={resumeProgress}
            style={{
                position: 'relative',
                background: `linear-gradient(135deg, ${cfg.bg}, rgba(10,10,16,0.95))`,
                border: `1px solid ${cfg.border}`,
                borderRadius: '12px',
                padding: '1rem 1rem 0.85rem',
                width: '340px',
                boxShadow: `0 0 30px ${cfg.glow}, 0 8px 32px rgba(0,0,0,0.6)`,
                backdropFilter: 'blur(20px)',
                overflow: 'hidden',
                cursor: 'default',
                transition: 'all 0.35s cubic-bezier(0.34, 1.56, 0.64, 1)',
                opacity: entering || leaving ? 0 : 1,
                transform: entering ? 'translateX(120%)' : leaving ? 'translateX(120%)' : 'translateX(0)',
            }}
        >
            {/* Scanline shimmer */}
            <div style={{
                position: 'absolute', inset: 0, pointerEvents: 'none',
                background: `repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,255,255,0.012) 2px, rgba(255,255,255,0.012) 4px)`,
                borderRadius: '12px',
            }} />

            {/* Glowing left accent bar */}
            <div style={{
                position: 'absolute', left: 0, top: 0, bottom: 0, width: '3px',
                background: `linear-gradient(to bottom, ${cfg.color}00, ${cfg.color}, ${cfg.color}00)`,
                borderRadius: '3px 0 0 3px',
            }} />

            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.65rem', marginBottom: '0.4rem' }}>
                {/* Pulsing icon */}
                <div style={{
                    width: '32px', height: '32px', borderRadius: '8px', flexShrink: 0,
                    background: `${cfg.color}20`, border: `1px solid ${cfg.color}40`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    boxShadow: `0 0 12px ${cfg.glow}`,
                    animation: toast.severity === 'high' ? 'toastPulse 1s ease-in-out infinite' : 'none',
                }}>
                    <Icon size={16} color={cfg.color} />
                </div>

                <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '2px' }}>
                        <span style={{
                            fontSize: '0.6rem', fontWeight: 800, letterSpacing: '0.12em',
                            color: cfg.color, textTransform: 'uppercase',
                            fontFamily: 'monospace',
                        }}>
                            ⬡ {cfg.label}
                        </span>
                        <span style={{ fontSize: '0.6rem', color: '#3d3d4e', marginLeft: 'auto', flexShrink: 0 }}>
                            {new Date().toLocaleTimeString()}
                        </span>
                    </div>
                    <div style={{
                        fontSize: '0.82rem', fontWeight: 600, color: '#e0e0e0',
                        lineHeight: 1.3, overflow: 'hidden', textOverflow: 'ellipsis',
                        display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
                    }}>
                        {toast.title}
                    </div>
                </div>

                {/* Dismiss button */}
                <button
                    onClick={() => handleDismiss()}
                    style={{
                        background: 'none', border: 'none', cursor: 'pointer',
                        color: '#3d3d4e', padding: '2px', borderRadius: '4px',
                        display: 'flex', alignItems: 'center', flexShrink: 0,
                        transition: 'color 0.15s',
                    }}
                    onMouseEnter={e => e.currentTarget.style.color = '#8b8b9b'}
                    onMouseLeave={e => e.currentTarget.style.color = '#3d3d4e'}
                >
                    <X size={14} />
                </button>
            </div>

            {/* Meta / source-dest */}
            <div style={{
                fontSize: '0.72rem', color: '#5a5a6e', fontFamily: 'monospace',
                marginLeft: '2.6rem', marginBottom: '0.65rem',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
                {toast.meta}
            </div>

            {/* View button */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '0.5rem' }}>
                <button
                    onClick={() => { navigate('/alerts'); handleDismiss() }}
                    style={{
                        display: 'flex', alignItems: 'center', gap: '4px',
                        fontSize: '0.7rem', fontWeight: 600, letterSpacing: '0.05em',
                        color: cfg.color, background: 'none', border: 'none',
                        cursor: 'pointer', padding: '2px 4px', borderRadius: '4px',
                        transition: 'opacity 0.15s',
                    }}
                    onMouseEnter={e => e.currentTarget.style.opacity = '0.7'}
                    onMouseLeave={e => e.currentTarget.style.opacity = '1'}
                >
                    View Alerts <ChevronRight size={12} />
                </button>
            </div>

            {/* Progress bar */}
            <div style={{
                position: 'absolute', bottom: 0, left: 0, right: 0, height: '2px',
                background: 'rgba(255,255,255,0.05)', borderRadius: '0 0 12px 12px',
            }}>
                <div style={{
                    height: '100%', width: `${progress}%`,
                    background: `linear-gradient(90deg, ${cfg.color}80, ${cfg.color})`,
                    borderRadius: '0 0 12px 12px',
                    boxShadow: `0 0 6px ${cfg.color}`,
                    transition: 'width 0.05s linear',
                }} />
            </div>
        </div>
    )
}

// ─── Global Toast Manager ──────────────────────────────────────
export const AlertToastProvider = () => {
    const [toasts, setToasts] = useState([])
    const lastAlertId = useRef(0)
    const initialLoad = useRef(true)

    const addToast = useCallback((alert) => {
        setToasts(prev => {
            const next = [{ ...alert, toastId: `${alert.id}-${Date.now()}` }, ...prev].slice(0, 5)
            return next
        })
    }, [])

    const dismissToast = useCallback((toastId) => {
        setToasts(prev => prev.filter(t => t.toastId !== toastId))
    }, [])

    useEffect(() => {
        const check = async () => {
            try {
                const res = await fetch(`${API}/api/alerts/latest`)
                const data = await res.json()
                if (!data.id) return

                if (initialLoad.current) {
                    // On first load, just record the latest ID — don't toast existing alerts
                    lastAlertId.current = data.id
                    initialLoad.current = false
                    return
                }

                if (data.id > lastAlertId.current) {
                    lastAlertId.current = data.id
                    addToast(data)
                }
            } catch (e) { /* api offline */ }
        }

        check()
        const id = setInterval(check, 5000)
        return () => clearInterval(id)
    }, [addToast])

    if (toasts.length === 0) return null

    return (
        <>
            {/* Keyframes injected once */}
            <style>{`
        @keyframes toastPulse {
          0%, 100% { box-shadow: 0 0 12px rgba(255,42,42,0.3); }
          50% { box-shadow: 0 0 24px rgba(255,42,42,0.7); }
        }
      `}</style>

            <div style={{
                position: 'fixed', bottom: '1.5rem', right: '1.5rem',
                display: 'flex', flexDirection: 'column', gap: '0.65rem',
                zIndex: 9999, alignItems: 'flex-end',
            }}>
                {toasts.map(t => (
                    <Toast key={t.toastId} toast={t} onDismiss={dismissToast} />
                ))}
            </div>
        </>
    )
}

export default AlertToastProvider
