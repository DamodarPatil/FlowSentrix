import { useState, useEffect, useCallback, useRef } from 'react'
import {
    Shield, Zap, AlertTriangle, Search, RefreshCw, Filter,
    Calendar, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight,
    Layers, List, Radio, ExternalLink
} from 'lucide-react'
import { useSession } from '../context/SessionContext'

const API = 'http://localhost:8000'

// ── Module-level cache for instant tab switches ──
const _alertsCache = new Map()

// ── Severity configuration ──
const SEV_CONFIG = {
    high: {
        color: '#ff2a2a', glow: 'rgba(255,42,42,0.15)',
        bg: 'rgba(255,42,42,0.06)', border: 'rgba(255,42,42,0.2)',
        label: 'CRITICAL', icon: AlertTriangle,
    },
    medium: {
        color: '#ffaa00', glow: 'rgba(255,170,0,0.15)',
        bg: 'rgba(255,170,0,0.06)', border: 'rgba(255,170,0,0.2)',
        label: 'WARNING', icon: AlertTriangle,
    },
    low: {
        color: '#00f3ff', glow: 'rgba(0,243,255,0.12)',
        bg: 'rgba(0,243,255,0.05)', border: 'rgba(0,243,255,0.18)',
        label: 'INFO', icon: AlertTriangle,
    },
}

// ── Shared styles ──
const inputStyle = {
    padding: '0.5rem 0.75rem',
    background: 'rgba(255,255,255,0.04)',
    border: '1px solid rgba(255,255,255,0.08)',
    borderRadius: '8px',
    color: '#fff',
    fontSize: '0.82rem',
    outline: 'none',
    transition: 'border-color 0.2s',
}

// ── Severity stat card ──
const SevCard = ({ label, count, sev, active, onClick }) => {
    const cfg = SEV_CONFIG[sev]
    const Icon = cfg.icon
    return (
        <div
            onClick={onClick}
            style={{
                flex: 1, minWidth: '140px',
                padding: '1.25rem 1.5rem',
                borderRadius: '14px',
                background: active
                    ? `linear-gradient(135deg, ${cfg.bg}, rgba(10,10,16,0.6))`
                    : 'rgba(255,255,255,0.03)',
                border: `1px solid ${active ? cfg.border : 'rgba(255,255,255,0.06)'}`,
                backdropFilter: 'blur(12px)',
                cursor: 'pointer',
                transition: 'all 0.25s ease',
                position: 'relative',
                overflow: 'hidden',
            }}
        >
            {/* Decorative glow when active */}
            {active && <div style={{
                position: 'absolute', top: '-50%', right: '-30%',
                width: '120px', height: '120px', borderRadius: '50%',
                background: `radial-gradient(circle, ${cfg.glow}, transparent 70%)`,
                pointerEvents: 'none',
            }} />}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                <span style={{
                    fontSize: '0.7rem', fontWeight: 600, color: active ? cfg.color : '#5a5a6e',
                    textTransform: 'uppercase', letterSpacing: '0.08em',
                }}>{label}</span>
                <div style={{
                    width: '34px', height: '34px', borderRadius: '10px',
                    background: `${cfg.color}15`, border: `1px solid ${cfg.color}25`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                    <Icon size={16} color={cfg.color} />
                </div>
            </div>
            <div style={{
                fontSize: '2rem', fontWeight: 700, color: active ? '#fff' : '#8b8b9b',
                lineHeight: 1, fontFamily: "'Outfit', sans-serif",
            }}>
                {count.toLocaleString()}
            </div>
        </div>
    )
}

// ── Category badge ──
const CategoryBadge = ({ category }) => {
    if (!category) return <span style={{ color: '#2a2a3a', fontSize: '0.72rem' }}>—</span>
    return (
        <span style={{
            fontSize: '0.65rem', fontWeight: 600, padding: '3px 8px', borderRadius: '4px',
            background: 'rgba(188,19,254,0.08)', color: '#bc13fe',
            border: '1px solid rgba(188,19,254,0.2)',
            letterSpacing: '0.03em', whiteSpace: 'nowrap',
            maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis',
            display: 'inline-block',
        }}>
            {category}
        </span>
    )
}

// ── Action badge ──
const ActionBadge = ({ action }) => {
    const isBlocked = action === 'blocked'
    return (
        <span style={{
            fontSize: '0.65rem', fontWeight: 700, padding: '2px 8px', borderRadius: '4px',
            background: isBlocked ? 'rgba(255,42,42,0.12)' : 'rgba(0,255,115,0.08)',
            color: isBlocked ? '#ff2a2a' : '#00ff73',
            border: `1px solid ${isBlocked ? 'rgba(255,42,42,0.25)' : 'rgba(0,255,115,0.2)'}`,
            letterSpacing: '0.05em', textTransform: 'uppercase',
        }}>
            {isBlocked ? '✕ BLOCKED' : '✓ ALLOWED'}
        </span>
    )
}

// ── Protocol badge ──
const PROTO_COLORS = {
    TCP: '#bc13fe', UDP: '#ffaa00', ICMP: '#fff59d', GRE: '#80deea',
}
const ProtoBadge = ({ proto }) => {
    if (!proto) return null
    const color = PROTO_COLORS[proto] || '#8b8b9b'
    return (
        <span style={{
            fontSize: '0.65rem', fontWeight: 700, padding: '2px 8px', borderRadius: '4px',
            color, background: `${color}12`, border: `1px solid ${color}30`,
            letterSpacing: '0.04em', fontFamily: 'monospace',
        }}>
            {proto}
        </span>
    )
}

// ── Relative time helper ──
const relativeTime = (isoStr) => {
    if (!isoStr) return '—'
    const now = new Date()
    const d = new Date(isoStr)
    const diffMs = now - d
    const diffSec = Math.floor(diffMs / 1000)
    if (diffSec < 5) return 'just now'
    if (diffSec < 60) return `${diffSec}s ago`
    const diffMin = Math.floor(diffSec / 60)
    if (diffMin < 60) return `${diffMin}m ago`
    const diffHr = Math.floor(diffMin / 60)
    if (diffHr < 24) return `${diffHr}h ago`
    const diffDay = Math.floor(diffHr / 24)
    if (diffDay < 7) return `${diffDay}d ago`
    // Fallback to date
    const pad = n => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

const fmtTime = (isoStr) => {
    if (!isoStr) return '—'
    const d = new Date(isoStr)
    const pad = n => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

// ═══════════════════════════════════════════════════════════════
// Alerts Page Component
// ═══════════════════════════════════════════════════════════════
const Alerts = () => {
    const { sessionId } = useSession()
    const cacheKey = `alerts-${sessionId || 0}`
    const cached = _alertsCache.get(cacheKey)

    const [alerts, setAlerts] = useState(cached?.alerts || [])
    const [loading, setLoading] = useState(!cached)
    const [isLive, setIsLive] = useState(false)

    // Counts
    const [totalCount, setTotalCount] = useState(cached?.totalCount || 0)
    const [highCount, setHighCount] = useState(cached?.highCount || 0)
    const [mediumCount, setMediumCount] = useState(cached?.mediumCount || 0)
    const [lowCount, setLowCount] = useState(cached?.lowCount || 0)
    const [allProtocols, setAllProtocols] = useState(cached?.protocols || [])
    const [totalPages, setTotalPages] = useState(cached?.totalPages || 1)

    // Filters
    const [search, setSearch] = useState('')
    const [severity, setSeverity] = useState('')
    const [proto, setProto] = useState('')
    const [dateFrom, setDateFrom] = useState('')
    const [dateTo, setDateTo] = useState('')
    const [grouped, setGrouped] = useState(false)

    // Pagination
    const [page, setPage] = useState(1)
    const [perPage, setPerPage] = useState(50)

    // Expand
    const [expanded, setExpanded] = useState(null)

    // Live polling
    const intervalRef = useRef(null)

    const fetchAlerts = useCallback(async () => {
        if (!_alertsCache.has(cacheKey)) setLoading(true)
        try {
            const params = new URLSearchParams({
                page, per_page: perPage,
                severity, search, proto,
                date_from: dateFrom, date_to: dateTo,
                group: grouped,
            })
            if (sessionId) params.set('session_id', sessionId)
            const res = await fetch(`${API}/api/alerts?${params}`)
            const data = await res.json()
            setAlerts(data.alerts || [])
            setTotalCount(data.total_count || 0)
            setTotalPages(data.total_pages || 1)
            setHighCount(data.high_count || 0)
            setMediumCount(data.medium_count || 0)
            setLowCount(data.low_count || 0)
            setAllProtocols(data.protocols || [])
            // Cache default view
            if (!search && !severity && !proto && !dateFrom && !dateTo && !grouped && page === 1) {
                _alertsCache.set(cacheKey, {
                    alerts: data.alerts || [],
                    totalCount: data.total_count || 0,
                    totalPages: data.total_pages || 1,
                    highCount: data.high_count || 0,
                    mediumCount: data.medium_count || 0,
                    lowCount: data.low_count || 0,
                    protocols: data.protocols || [],
                })
            }
        } catch (e) { /* api offline */ }
        finally { setLoading(false) }
    }, [page, perPage, severity, search, proto, dateFrom, dateTo, grouped, sessionId, cacheKey])

    // Check capture status for live mode
    useEffect(() => {
        const checkLive = async () => {
            try {
                const res = await fetch(`${API}/api/capture/status`)
                const data = await res.json()
                setIsLive(data.state === 'capturing')
            } catch { setIsLive(false) }
        }
        checkLive()
        const id = setInterval(checkLive, 5000)
        return () => clearInterval(id)
    }, [])

    // Auto-refresh when live capture is running
    useEffect(() => {
        if (isLive) {
            intervalRef.current = setInterval(fetchAlerts, 5000)
        } else {
            if (intervalRef.current) clearInterval(intervalRef.current)
        }
        return () => { if (intervalRef.current) clearInterval(intervalRef.current) }
    }, [isLive, fetchAlerts])

    // Reset to page 1 when filters change
    useEffect(() => { setPage(1) }, [search, severity, proto, dateFrom, dateTo, perPage, grouped, sessionId])

    useEffect(() => { fetchAlerts() }, [fetchAlerts])

    const toggleExpand = (id) => setExpanded(prev => prev === id ? null : id)

    // Severity card click → toggle filter
    const toggleSeverityFilter = (sev) => {
        setSeverity(prev => prev === sev ? '' : sev)
    }

    // ── Date presets ──
    const setPreset = (label) => {
        const now = new Date()
        const pad = n => String(n).padStart(2, '0')
        const fmt = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
        const fmtFull = d => `${fmt(d)} ${pad(d.getHours())}:${pad(d.getMinutes())}`

        if (label === 'today') { setDateFrom(fmt(now)); setDateTo('') }
        else if (label === 'yesterday') { const y = new Date(now); y.setDate(y.getDate() - 1); setDateFrom(fmt(y)); setDateTo(fmt(y)) }
        else if (label === '7d') { const d = new Date(now); d.setDate(d.getDate() - 7); setDateFrom(fmt(d)); setDateTo('') }
        else if (label === '30d') { const d = new Date(now); d.setDate(d.getDate() - 30); setDateFrom(fmt(d)); setDateTo('') }
        else if (label === '1h') { const d = new Date(now.getTime() - 3600000); setDateFrom(fmtFull(d)); setDateTo('') }
        else if (label === 'all') { setDateFrom(''); setDateTo('') }
    }

    // ── Style helpers ──
    const presetBtnStyle = (active) => ({
        padding: '3px 10px', borderRadius: '6px', border: 'none',
        fontSize: '0.72rem', fontWeight: 600, cursor: 'pointer',
        background: active ? 'rgba(255,42,42,0.12)' : 'rgba(255,255,255,0.04)',
        color: active ? '#ff6b9d' : '#5a5a6e',
        transition: 'all 0.15s',
    })

    const pageBtnStyle = (disabled) => ({
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        width: '32px', height: '32px', borderRadius: '6px',
        border: '1px solid rgba(255,255,255,0.08)',
        background: 'rgba(255,255,255,0.04)',
        color: disabled ? '#2a2a3a' : '#8b8b9b',
        cursor: disabled ? 'default' : 'pointer',
        fontSize: '0.8rem', transition: 'all 0.15s',
        pointerEvents: disabled ? 'none' : 'auto',
    })

    const rangeStart = (page - 1) * perPage + 1
    const rangeEnd = Math.min(page * perPage, totalCount)

    const hasFilters = search || severity || proto || dateFrom || dateTo

    return (
        <>
            {/* ── Page Header ── */}
            <div className="page-header">
                <div>
                    <h1 className="page-title">Alerts</h1>
                    <p className="page-subtitle">
                        {totalCount.toLocaleString()} security events
                        {hasFilters && ' (filtered)'}
                    </p>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    {/* Live indicator */}
                    {isLive && (
                        <div style={{
                            display: 'flex', alignItems: 'center', gap: '0.5rem',
                            padding: '0.4rem 0.85rem', borderRadius: '50px',
                            background: 'rgba(255,42,42,0.08)',
                            border: '1px solid rgba(255,42,42,0.2)',
                            fontSize: '0.75rem', fontWeight: 600, color: '#ff6b9d',
                        }}>
                            <Radio size={13} style={{ animation: 'pulseGlow 2s ease-in-out infinite' }} />
                            LIVE
                        </div>
                    )}
                    {/* Group toggle */}
                    <button
                        onClick={() => setGrouped(g => !g)}
                        style={{
                            display: 'flex', alignItems: 'center', gap: '0.4rem',
                            padding: '0.45rem 0.9rem', borderRadius: '8px',
                            background: grouped ? 'rgba(188,19,254,0.12)' : 'rgba(255,255,255,0.04)',
                            border: `1px solid ${grouped ? 'rgba(188,19,254,0.25)' : 'rgba(255,255,255,0.08)'}`,
                            color: grouped ? '#bc13fe' : '#5a5a6e',
                            cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600,
                            transition: 'all 0.15s',
                        }}
                    >
                        {grouped ? <Layers size={13} /> : <List size={13} />}
                        {grouped ? 'Grouped' : 'Flat'}
                    </button>
                    {/* Refresh */}
                    <button
                        onClick={fetchAlerts}
                        style={{
                            display: 'flex', alignItems: 'center', gap: '0.4rem',
                            padding: '0.45rem 0.9rem', borderRadius: '8px',
                            background: 'rgba(255,42,42,0.08)', border: '1px solid rgba(255,42,42,0.18)',
                            color: '#ff6b9d', cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600,
                        }}
                    >
                        <RefreshCw size={13} />
                        Refresh
                    </button>
                </div>
            </div>

            {/* ── Severity Summary Cards ── */}
            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                <SevCard label="Critical" count={highCount} sev="high"
                    active={severity === 'high'} onClick={() => toggleSeverityFilter('high')} />
                <SevCard label="Warning" count={mediumCount} sev="medium"
                    active={severity === 'medium'} onClick={() => toggleSeverityFilter('medium')} />
                <SevCard label="Informational" count={lowCount} sev="low"
                    active={severity === 'low'} onClick={() => toggleSeverityFilter('low')} />
            </div>

            {/* ── Filters Row 1: Search + Protocol + Per Page ── */}
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                <div style={{ position: 'relative', flex: 1, minWidth: '200px' }}>
                    <Search size={15} style={{
                        position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)',
                        color: '#5a5a6e', pointerEvents: 'none',
                    }} />
                    <input
                        type="text"
                        placeholder="Search signature, IP address, or category…"
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        style={{ ...inputStyle, width: '100%', paddingLeft: '2.2rem', boxSizing: 'border-box' }}
                        onFocus={e => e.target.style.borderColor = 'rgba(255,42,42,0.4)'}
                        onBlur={e => e.target.style.borderColor = 'rgba(255,255,255,0.08)'}
                    />
                </div>

                <div style={{ position: 'relative' }}>
                    <Filter size={14} style={{
                        position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)',
                        color: '#5a5a6e', pointerEvents: 'none',
                    }} />
                    <select value={proto} onChange={e => setProto(e.target.value)}
                        style={{ ...inputStyle, paddingLeft: '2.2rem', color: proto ? '#ff6b9d' : '#5a5a6e', cursor: 'pointer' }}>
                        <option value="">All protocols</option>
                        {allProtocols.map(p => <option key={p} value={p}>{p}</option>)}
                    </select>
                </div>

                <select value={perPage} onChange={e => setPerPage(Number(e.target.value))}
                    style={{ ...inputStyle, color: '#8b8b9b', cursor: 'pointer' }}>
                    <option value={25}>25 / page</option>
                    <option value={50}>50 / page</option>
                    <option value={100}>100 / page</option>
                    <option value={200}>200 / page</option>
                </select>

                {hasFilters && (
                    <button onClick={() => { setSearch(''); setSeverity(''); setProto(''); setDateFrom(''); setDateTo('') }}
                        style={{
                            padding: '0.5rem 0.9rem', borderRadius: '8px',
                            background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)',
                            color: '#5a5a6e', cursor: 'pointer', fontSize: '0.78rem', fontWeight: 500,
                            transition: 'all 0.15s',
                        }}>
                        ✕ Clear All
                    </button>
                )}
            </div>

            {/* ── Filters Row 2: Date Range ── */}
            <div style={{
                display: 'flex', gap: '0.6rem', alignItems: 'center', flexWrap: 'wrap',
                marginTop: '-1rem',
            }}>
                <Calendar size={14} style={{ color: '#5a5a6e', flexShrink: 0 }} />
                <div style={{ display: 'flex', gap: '0.35rem' }}>
                    {[
                        ['1h', 'Last hour'], ['today', 'Today'], ['yesterday', 'Yesterday'],
                        ['7d', '7 days'], ['30d', '30 days'], ['all', 'All time'],
                    ].map(([key, label]) => (
                        <button key={key} onClick={() => setPreset(key)}
                            style={presetBtnStyle(!dateFrom && !dateTo && key === 'all')}>
                            {label}
                        </button>
                    ))}
                </div>

                <div style={{ width: '1px', height: '20px', background: 'rgba(255,255,255,0.08)', margin: '0 0.25rem' }} />

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <span style={{ fontSize: '0.72rem', color: '#5a5a6e' }}>From</span>
                    <input type="datetime-local" value={dateFrom} onChange={e => setDateFrom(e.target.value)}
                        style={{ ...inputStyle, fontSize: '0.78rem', padding: '4px 8px', colorScheme: 'dark' }} />
                    <span style={{ fontSize: '0.72rem', color: '#5a5a6e' }}>To</span>
                    <input type="datetime-local" value={dateTo} onChange={e => setDateTo(e.target.value)}
                        style={{ ...inputStyle, fontSize: '0.78rem', padding: '4px 8px', colorScheme: 'dark' }} />
                    {(dateFrom || dateTo) && (
                        <button onClick={() => { setDateFrom(''); setDateTo('') }}
                            style={{ fontSize: '0.7rem', color: '#5a5a6e', background: 'none', border: 'none', cursor: 'pointer', padding: '2px 6px' }}>
                            ✕ Clear
                        </button>
                    )}
                </div>
            </div>

            {/* ── Alert Cards / Table ── */}
            <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
                {loading ? (
                    <div style={{ padding: '3rem', textAlign: 'center', color: '#5a5a6e' }}>
                        <Shield size={32} style={{ marginBottom: '0.75rem', opacity: 0.3 }} />
                        <p>Loading alerts…</p>
                    </div>
                ) : alerts.length === 0 ? (
                    <div style={{ padding: '3rem', textAlign: 'center', color: '#5a5a6e' }}>
                        <Shield size={48} style={{ marginBottom: '0.75rem', opacity: 0.15 }} />
                        <p style={{ fontSize: '0.9rem', marginBottom: '0.3rem' }}>
                            {hasFilters ? 'No alerts match these filters' : 'No security alerts recorded'}
                        </p>
                        <p style={{ fontSize: '0.75rem', color: '#3d3d4e' }}>
                            {hasFilters ? 'Try adjusting your filter criteria' : 'Alerts from Suricata IDS will appear here during capture'}
                        </p>
                    </div>
                ) : grouped ? (
                    /* ── Grouped View ── */
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                        {alerts.map((a, i) => {
                            const cfg = SEV_CONFIG[a.severity] || SEV_CONFIG.low
                            const Icon = cfg.icon
                            return (
                                <div key={i} style={{
                                    padding: '1rem 1.25rem',
                                    borderBottom: '1px solid rgba(255,255,255,0.04)',
                                    borderLeft: `3px solid ${cfg.color}`,
                                    background: `linear-gradient(90deg, ${cfg.bg}, transparent 40%)`,
                                    transition: 'background 0.15s',
                                    cursor: 'default',
                                }}
                                    onMouseEnter={e => e.currentTarget.style.background = `linear-gradient(90deg, ${cfg.glow}, transparent 50%)`}
                                    onMouseLeave={e => e.currentTarget.style.background = `linear-gradient(90deg, ${cfg.bg}, transparent 40%)`}
                                >
                                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.85rem' }}>
                                        {/* Severity icon */}
                                        <div style={{
                                            width: '36px', height: '36px', borderRadius: '10px', flexShrink: 0,
                                            background: `${cfg.color}15`, border: `1px solid ${cfg.color}30`,
                                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                                            marginTop: '2px',
                                        }}>
                                            <Icon size={16} color={cfg.color} />
                                        </div>

                                        {/* Main content */}
                                        <div style={{ flex: 1, minWidth: 0 }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap', marginBottom: '0.3rem' }}>
                                                <span style={{
                                                    fontSize: '0.85rem', fontWeight: 600, color: '#e0e0e0',
                                                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                                    maxWidth: '500px',
                                                }}>
                                                    {a.signature}
                                                </span>
                                                <span style={{
                                                    fontSize: '0.68rem', fontWeight: 700, padding: '2px 10px',
                                                    borderRadius: '10px', fontFamily: 'monospace',
                                                    background: `${cfg.color}18`, color: cfg.color,
                                                    border: `1px solid ${cfg.color}30`,
                                                    display: 'inline-flex', alignItems: 'center', gap: '4px',
                                                }}>
                                                    ×{a.count}
                                                </span>
                                                <span className={`severity-badge ${a.severity}`} style={{ fontSize: '0.6rem' }}>
                                                    {cfg.label}
                                                </span>
                                            </div>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', flexWrap: 'wrap' }}>
                                                <CategoryBadge category={a.category} />
                                                <ProtoBadge proto={a.proto} />
                                                <span style={{ fontSize: '0.72rem', color: '#3d3d4e' }}>
                                                    First: {relativeTime(a.first_seen)}
                                                </span>
                                                <span style={{ fontSize: '0.72rem', color: '#3d3d4e' }}>
                                                    Last: {relativeTime(a.last_seen)}
                                                </span>
                                            </div>
                                            {/* IPs */}
                                            <div style={{ marginTop: '0.5rem', display: 'flex', gap: '1.5rem', flexWrap: 'wrap' }}>
                                                {a.src_ips && a.src_ips[0] && (
                                                    <div>
                                                        <span style={{ fontSize: '0.62rem', color: '#3d3d4e', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Sources</span>
                                                        <div style={{ fontSize: '0.75rem', color: '#8b8b9b', fontFamily: 'monospace', marginTop: '2px' }}>
                                                            {a.src_ips.join(', ')}
                                                        </div>
                                                    </div>
                                                )}
                                                {a.dst_ips && a.dst_ips[0] && (
                                                    <div>
                                                        <span style={{ fontSize: '0.62rem', color: '#3d3d4e', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Destinations</span>
                                                        <div style={{ fontSize: '0.75rem', color: '#8b8b9b', fontFamily: 'monospace', marginTop: '2px' }}>
                                                            {a.dst_ips.join(', ')}
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )
                        })}
                    </div>
                ) : (
                    /* ── Flat View (individual alert cards) ── */
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                        {alerts.map((a, i) => {
                            const cfg = SEV_CONFIG[a.severity] || SEV_CONFIG.low
                            const Icon = cfg.icon
                            const isExpanded = expanded === a.id
                            return (
                                <div key={a.id}>
                                    <div
                                        onClick={() => toggleExpand(a.id)}
                                        style={{
                                            padding: '0.85rem 1.25rem',
                                            borderBottom: '1px solid rgba(255,255,255,0.04)',
                                            borderLeft: `3px solid ${cfg.color}`,
                                            background: isExpanded
                                                ? `linear-gradient(90deg, ${cfg.glow}, transparent 50%)`
                                                : i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)',
                                            cursor: 'pointer',
                                            transition: 'background 0.15s',
                                        }}
                                        onMouseEnter={e => { if (!isExpanded) e.currentTarget.style.background = 'rgba(255,255,255,0.03)' }}
                                        onMouseLeave={e => { if (!isExpanded) e.currentTarget.style.background = i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)' }}
                                    >
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                                            {/* Severity icon */}
                                            <div style={{
                                                width: '32px', height: '32px', borderRadius: '8px', flexShrink: 0,
                                                background: `${cfg.color}15`, border: `1px solid ${cfg.color}30`,
                                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                            }}>
                                                <Icon size={14} color={cfg.color} />
                                            </div>

                                            {/* Signature + meta */}
                                            <div style={{ flex: 1, minWidth: 0 }}>
                                                <div style={{
                                                    fontSize: '0.82rem', fontWeight: 600, color: '#e0e0e0',
                                                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                                    marginBottom: '2px',
                                                }}>
                                                    {a.signature}
                                                </div>
                                                <div style={{
                                                    fontSize: '0.72rem', color: '#5a5a6e', fontFamily: 'monospace',
                                                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                                }}>
                                                    {a.meta}
                                                </div>
                                            </div>

                                            {/* Badges */}
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexShrink: 0 }}>
                                                <CategoryBadge category={a.category} />
                                                <ProtoBadge proto={a.proto} />
                                                <ActionBadge action={a.action} />
                                                <span className={`severity-badge ${a.severity}`}>{cfg.label}</span>
                                                <span style={{
                                                    fontSize: '0.72rem', color: '#3d3d4e', whiteSpace: 'nowrap',
                                                    minWidth: '60px', textAlign: 'right',
                                                }}>
                                                    {relativeTime(a.timestamp)}
                                                </span>
                                            </div>
                                        </div>
                                    </div>

                                    {/* ── Expanded detail row ── */}
                                    {isExpanded && (
                                        <div style={{
                                            padding: '1rem 1.25rem 1.25rem 3.5rem',
                                            borderBottom: '1px solid rgba(255,255,255,0.06)',
                                            borderLeft: `3px solid ${cfg.color}`,
                                            background: `linear-gradient(135deg, ${cfg.bg}, transparent 60%)`,
                                        }}>
                                            <div style={{ display: 'flex', gap: '2.5rem', flexWrap: 'wrap' }}>
                                                {[
                                                    ['Alert ID', `#${a.id}`],
                                                    ['Signature', a.signature],
                                                    ['Category', a.category || '—'],
                                                    ['Severity', cfg.label],
                                                    ['Source IP', a.src_ip],
                                                    ['Source Port', a.src_port || '—'],
                                                    ['Destination IP', a.dst_ip],
                                                    ['Destination Port', a.dst_port || '—'],
                                                    ['Protocol', a.proto || '—'],
                                                    ['Action', a.action],
                                                    ['Timestamp', fmtTime(a.timestamp)],
                                                ].map(([label, val]) => (
                                                    <div key={label} style={{ minWidth: '120px' }}>
                                                        <div style={{
                                                            fontSize: '0.62rem', color: '#3d3d4e', marginBottom: '3px',
                                                            textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600,
                                                        }}>{label}</div>
                                                        <div style={{
                                                            fontSize: '0.8rem', color: '#c0c0c0',
                                                            fontFamily: typeof val === 'string' && (val.includes('.') || val.includes(':')) ? 'monospace' : 'inherit',
                                                        }}>{val}</div>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )
                        })}
                    </div>
                )}

                {/* ── Pagination Bar ── */}
                {totalCount > 0 && (
                    <div style={{
                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                        padding: '0.75rem 1rem',
                        borderTop: '1px solid rgba(255,255,255,0.06)',
                        fontSize: '0.78rem', color: '#5a5a6e',
                    }}>
                        <span>
                            Showing <span style={{ color: '#e0e0e0' }}>{rangeStart.toLocaleString()}–{rangeEnd.toLocaleString()}</span> of{' '}
                            <span style={{ color: '#e0e0e0' }}>{totalCount.toLocaleString()}</span> alerts
                        </span>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            <button onClick={() => setPage(1)} style={pageBtnStyle(page === 1)}>
                                <ChevronsLeft size={14} />
                            </button>
                            <button onClick={() => setPage(p => Math.max(1, p - 1))} style={pageBtnStyle(page === 1)}>
                                <ChevronLeft size={14} />
                            </button>

                            {(() => {
                                const pages = []
                                let start = Math.max(1, page - 2)
                                let end = Math.min(totalPages, start + 4)
                                if (end - start < 4) start = Math.max(1, end - 4)
                                for (let i = start; i <= end; i++) pages.push(i)
                                return pages.map(p => (
                                    <button key={p} onClick={() => setPage(p)}
                                        style={{
                                            ...pageBtnStyle(false),
                                            background: p === page ? 'rgba(255,42,42,0.15)' : 'rgba(255,255,255,0.04)',
                                            color: p === page ? '#ff6b9d' : '#5a5a6e',
                                            border: p === page ? '1px solid rgba(255,42,42,0.25)' : '1px solid rgba(255,255,255,0.08)',
                                            fontWeight: p === page ? 700 : 400,
                                            fontSize: '0.75rem',
                                        }}>
                                        {p}
                                    </button>
                                ))
                            })()}

                            <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} style={pageBtnStyle(page === totalPages)}>
                                <ChevronRight size={14} />
                            </button>
                            <button onClick={() => setPage(totalPages)} style={pageBtnStyle(page === totalPages)}>
                                <ChevronsRight size={14} />
                            </button>

                            <span style={{ marginLeft: '0.5rem', fontSize: '0.72rem' }}>
                                Page {page} of {totalPages.toLocaleString()}
                            </span>
                        </div>
                    </div>
                )}
            </div>
        </>
    )
}

export default Alerts
