import { useState, useEffect, useCallback, useRef } from 'react'
import { Radio, Play, Square, MonitorSpeaker, AlertTriangle, CheckCircle, Waves, Activity } from 'lucide-react'

const API = 'http://localhost:8000'

// Protocol colors matching CLI
const PROTO_COLORS = {
    'TLSv1.2': '#00f3ff', 'TLSv1.3': '#00f3ff', 'TLSv1': '#00b8cc',
    'TCP': '#bc13fe', 'UDP': '#ffaa00', 'QUIC': '#00ff73',
    'HTTP': '#ff9500', 'HTTP/JSON': '#ff9500', 'DNS': '#6ec6ff',
    'SSLv2': '#ff6b9d', 'SSL': '#ff6b9d', 'SSHv2': '#c5e1a5', 'SSH': '#c5e1a5',
    'ICMP': '#fff59d', 'ICMPv6': '#fff59d', 'ARP': '#ffcc80',
    'MDNS': '#80deea', 'NTP': '#b39ddb', 'DHCP': '#ef9a9a',
}

const StatBox = ({ label, value, sub, color = '#e0e0e0' }) => (
    <div style={{
        flex: 1, minWidth: '140px',
        background: 'rgba(255,255,255,0.03)',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: '12px',
        padding: '1rem 1.25rem',
        textAlign: 'center',
    }}>
        <div style={{ fontSize: '0.72rem', color: '#5a5a6e', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.4rem' }}>
            {label}
        </div>
        <div style={{ fontSize: '1.6rem', fontWeight: 700, color, fontFamily: 'monospace', lineHeight: 1.1 }}>
            {value}
        </div>
        {sub && <div style={{ fontSize: '0.75rem', color: '#3d3d4e', marginTop: '0.2rem' }}>{sub}</div>}
    </div>
)

const Capture = () => {
    const [status, setStatus] = useState(null)
    const [interfaces, setInterfaces] = useState([])
    const [selectedIface, setSelectedIface] = useState('')
    const [actionError, setActionError] = useState('')
    const [actionLoading, setActionLoading] = useState(false)
    const [packets, setPackets] = useState([])      // What's rendered (frozen when scrolled up)
    const lastPacketId = useRef(0)
    const feedRef = useRef(null)
    const prevState = useRef(null)
    const isNearBottom = useRef(true)
    const pendingPackets = useRef([])                // Buffer: holds new packets while scrolled up

    // Flush pending packets into display
    const flushPending = useCallback(() => {
        if (pendingPackets.current.length === 0) return
        setPackets(prev => {
            const merged = [...prev, ...pendingPackets.current]
            pendingPackets.current = []
            return merged.length > 500 ? merged.slice(-500) : merged
        })
    }, [])

    // Fetch interfaces on mount
    useEffect(() => {
        fetch(`${API}/api/interfaces`)
            .then(r => r.json())
            .then(data => {
                setInterfaces(data.interfaces || [])
                const up = data.interfaces?.find(i => i.state === 'up' && i.name !== 'lo')
                if (up) setSelectedIface(up.name)
                else if (data.interfaces?.length) setSelectedIface(data.interfaces[0].name)
            })
            .catch(() => { })
    }, [])

    // Fetch status
    const fetchStatus = useCallback(async () => {
        try {
            const r = await fetch(`${API}/api/capture/status`)
            const data = await r.json()
            setStatus(data)
        } catch { }
    }, [])

    // Fetch packets (incremental) — buffers into pending, only renders if at bottom
    const fetchPackets = useCallback(async () => {
        try {
            const r = await fetch(`${API}/api/capture/packets?after_id=${lastPacketId.current}`)
            const data = await r.json()
            if (data.packets && data.packets.length > 0) {
                lastPacketId.current = data.packets[data.packets.length - 1].id
                if (isNearBottom.current) {
                    // At bottom: add directly to displayed packets
                    setPackets(prev => {
                        const merged = [...prev, ...data.packets]
                        return merged.length > 500 ? merged.slice(-500) : merged
                    })
                } else {
                    // Scrolled up: buffer silently, don't touch the display
                    pendingPackets.current.push(...data.packets)
                    // Cap pending buffer
                    if (pendingPackets.current.length > 500) {
                        pendingPackets.current = pendingPackets.current.slice(-500)
                    }
                }
            }
        } catch { }
    }, [])

    // Initial fetch
    useEffect(() => { fetchStatus() }, [fetchStatus])

    // Detect state transition: active → idle → drain remaining packets
    useEffect(() => {
        const wasActive = prevState.current === 'capturing' || prevState.current === 'stopping' || prevState.current === 'analyzing'
        const nowIdle = status?.state === 'idle'
        prevState.current = status?.state

        if (wasActive && nowIdle) {
            fetchPackets()
            setTimeout(fetchPackets, 500)
            setTimeout(fetchPackets, 1500)
        }
    }, [status?.state, fetchPackets])

    // Polling during capture
    useEffect(() => {
        const isActive = status?.state === 'capturing' || status?.state === 'stopping' || status?.state === 'analyzing'
        const statusInterval = isActive ? 1000 : 3000

        const statusTimer = setInterval(fetchStatus, statusInterval)
        let packetTimer = null
        if (isActive) {
            packetTimer = setInterval(fetchPackets, 500)
        }
        return () => {
            clearInterval(statusTimer)
            if (packetTimer) clearInterval(packetTimer)
        }
    }, [fetchStatus, fetchPackets, status?.state])

    // After packets state updates, scroll to bottom only if following
    useEffect(() => {
        if (isNearBottom.current && feedRef.current) {
            feedRef.current.scrollTop = feedRef.current.scrollHeight
        }
    }, [packets])

    const handleScroll = () => {
        if (!feedRef.current) return
        const { scrollTop, scrollHeight, clientHeight } = feedRef.current
        const wasNearBottom = isNearBottom.current
        isNearBottom.current = (scrollHeight - scrollTop - clientHeight) < 40

        // User just scrolled back to bottom → flush pending packets
        if (!wasNearBottom && isNearBottom.current) {
            flushPending()
        }
    }

    const handleStart = async () => {
        if (!selectedIface) { setActionError('Select an interface first'); return }
        setActionError('')
        setActionLoading(true)
        setPackets([])
        lastPacketId.current = 0
        isNearBottom.current = true
        try {
            const r = await fetch(`${API}/api/capture/start?interface=${encodeURIComponent(selectedIface)}`, { method: 'POST' })
            const data = await r.json()
            if (!data.ok) setActionError(data.error)
            fetchStatus()
        } catch (e) {
            setActionError('Failed to connect to API')
        } finally {
            setActionLoading(false)
        }
    }

    const handleStop = async () => {
        setActionError('')
        setActionLoading(true)
        try {
            const r = await fetch(`${API}/api/capture/stop`, { method: 'POST' })
            const data = await r.json()
            if (!data.ok) setActionError(data.error)
            fetchStatus()
        } catch (e) {
            setActionError('Failed to connect to API')
        } finally {
            setActionLoading(false)
        }
    }

    const isCapturing = status?.state === 'capturing'
    const isStopping = status?.state === 'stopping'
    const isAnalyzing = status?.state === 'analyzing'
    const isActive = isCapturing || isStopping || isAnalyzing
    const lastCap = status?.last_capture

    const stateConfig = {
        idle: { label: 'Idle', color: '#5a5a6e', bg: 'rgba(90,90,110,0.15)' },
        capturing: { label: '● LIVE', color: '#00ff73', bg: 'rgba(0,255,115,0.12)' },
        stopping: { label: '■ Stopping…', color: '#ffaa00', bg: 'rgba(255,170,0,0.12)' },
        analyzing: { label: '⟳ Analyzing…', color: '#00f3ff', bg: 'rgba(0,243,255,0.12)' },
    }
    const sc = stateConfig[status?.state] || stateConfig.idle
    const protoColor = (p) => PROTO_COLORS[p] || '#8b8b9b'

    const GRID = '60px 80px 75px 1fr 24px 1fr 60px 2.5fr'

    return (
        <>
            <div className="page-header">
                <div>
                    <h1 className="page-title">Capture</h1>
                    <p className="page-subtitle">
                        {isActive ? `Capturing on ${status.interface}` : 'Start and monitor live packet capture'}
                    </p>
                </div>
                <div style={{
                    display: 'inline-flex', alignItems: 'center', gap: '0.5rem',
                    padding: '0.5rem 1.2rem', borderRadius: '8px',
                    background: sc.bg, border: `1px solid ${sc.color}30`,
                    fontSize: '0.9rem', fontWeight: 600, color: sc.color,
                    ...(isCapturing ? { animation: 'glow-pulse 2s infinite' } : {}),
                }}>
                    {sc.label}
                </div>
            </div>

            {/* ── Controls Row ── */}
            <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '0.75rem', alignItems: 'stretch', flexWrap: 'wrap' }}>
                <div className="panel" style={{ flex: '0 0 auto', display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.85rem 1.2rem' }}>
                    <select
                        value={selectedIface}
                        onChange={e => setSelectedIface(e.target.value)}
                        disabled={isActive}
                        style={{
                            padding: '0.55rem 0.85rem',
                            background: isActive ? 'rgba(255,255,255,0.02)' : 'rgba(255,255,255,0.04)',
                            border: '1px solid rgba(255,255,255,0.08)',
                            borderRadius: '8px', color: isActive ? '#3d3d4e' : '#e0e0e0',
                            fontSize: '0.9rem', cursor: isActive ? 'not-allowed' : 'pointer',
                            outline: 'none', minWidth: '200px',
                        }}
                    >
                        <option value="">Select interface…</option>
                        <option value="any">any (all interfaces)</option>
                        {interfaces.map(iface => (
                            <option key={iface.name} value={iface.name}>
                                {iface.name}{iface.ip ? ` (${iface.ip})` : ''}{iface.state === 'up' ? ' ● UP' : ''}
                            </option>
                        ))}
                    </select>

                    {!isActive ? (
                        <button onClick={handleStart} disabled={actionLoading || !selectedIface}
                            style={{
                                display: 'flex', alignItems: 'center', gap: '0.5rem',
                                padding: '0.55rem 1.75rem', borderRadius: '8px', border: 'none',
                                background: 'linear-gradient(135deg, rgba(0,255,115,0.25), rgba(0,255,115,0.1))',
                                color: '#00ff73', fontSize: '0.95rem', fontWeight: 700,
                                cursor: selectedIface && !actionLoading ? 'pointer' : 'not-allowed',
                                opacity: selectedIface && !actionLoading ? 1 : 0.4,
                                whiteSpace: 'nowrap',
                            }}
                        >
                            <Play size={16} fill="#00ff73" />
                            Start
                        </button>
                    ) : (
                        <button onClick={handleStop} disabled={actionLoading || !isCapturing}
                            style={{
                                display: 'flex', alignItems: 'center', gap: '0.5rem',
                                padding: '0.55rem 1.75rem', borderRadius: '8px', border: 'none',
                                background: isCapturing ? 'linear-gradient(135deg, rgba(255,42,42,0.25), rgba(255,42,42,0.1))' : 'rgba(255,255,255,0.04)',
                                color: isCapturing ? '#ff2a2a' : '#5a5a6e',
                                fontSize: '0.95rem', fontWeight: 700,
                                cursor: isCapturing ? 'pointer' : 'not-allowed',
                                opacity: isCapturing ? 1 : 0.5,
                                whiteSpace: 'nowrap',
                            }}
                        >
                            <Square size={14} fill={isCapturing ? '#ff2a2a' : '#5a5a6e'} />
                            {isStopping ? 'Stopping…' : isAnalyzing ? 'Analyzing…' : 'Stop'}
                        </button>
                    )}
                </div>

                {/* Live stats bar */}
                {isActive && (
                    <div style={{ display: 'flex', gap: '0.5rem', flex: 1, minWidth: '300px' }}>
                        <StatBox label="Packets" value={status.pcap_packets?.toLocaleString() || '0'} color="#00f3ff" />
                        <StatBox label="Data" value={status.pcap_bytes_display || '0 B'} color="#bc13fe" />
                        <StatBox label="Duration" value={status.duration_display || '0s'} color="#ffaa00" />
                        <StatBox label="PPS" value={status.pps?.toLocaleString() || '0'} sub="pkts/sec" color="#00ff73" />
                    </div>
                )}
            </div>

            {/* Error */}
            {actionError && (
                <div style={{
                    marginBottom: '0.75rem', padding: '0.75rem 1rem', borderRadius: '8px',
                    background: 'rgba(255,42,42,0.08)', border: '1px solid rgba(255,42,42,0.2)',
                    color: '#ff6b6b', fontSize: '0.9rem',
                    display: 'flex', alignItems: 'center', gap: '0.5rem',
                }}>
                    <AlertTriangle size={16} />
                    {actionError}
                </div>
            )}

            {/* Analyzing */}
            {isAnalyzing && (
                <div className="panel" style={{ marginBottom: '0.75rem', textAlign: 'center', padding: '1.5rem' }}>
                    <Waves size={28} style={{ color: '#00f3ff', marginBottom: '0.5rem', animation: 'pulse 1.5s infinite' }} />
                    <p style={{ color: '#00f3ff', fontWeight: 600, fontSize: '1rem' }}>Analyzing capture data…</p>
                    <p style={{ color: '#5a5a6e', fontSize: '0.85rem' }}>Reprocessing pcapng for accurate stats</p>
                </div>
            )}

            {/* ── Packet Feed ── */}
            {(isActive || packets.length > 0) && (
                <div className="panel" style={{ padding: 0, overflow: 'hidden', marginBottom: '0.75rem' }}>
                    <div className="panel-header">
                        <span className="panel-title">
                            <Activity size={16} style={{ color: '#00f3ff' }} />
                            Packet Feed
                            <span style={{ fontSize: '0.78rem', color: '#3d3d4e', marginLeft: '0.75rem' }}>
                                {packets.length} packets
                            </span>
                        </span>
                    </div>

                    {/* Column header */}
                    <div style={{
                        display: 'grid', gridTemplateColumns: GRID,
                        padding: '0.5rem 1rem',
                        borderBottom: '1px solid rgba(255,255,255,0.08)',
                        fontSize: '0.72rem', fontWeight: 600, color: '#5a5a6e',
                        textTransform: 'uppercase', letterSpacing: '0.08em',
                    }}>
                        <span>#</span>
                        <span>Time</span>
                        <span>Proto</span>
                        <span>Source</span>
                        <span></span>
                        <span>Destination</span>
                        <span style={{ textAlign: 'right', paddingRight: '1rem' }}>Len</span>
                        <span>Info</span>
                    </div>

                    {/* Scrollable feed — Wireshark style: stays where you scroll */}
                    <div
                        ref={feedRef}
                        onScroll={handleScroll}
                        style={{
                            maxHeight: '500px',
                            overflowY: 'auto',
                            overflowX: 'hidden',
                            fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
                            fontSize: '0.82rem',
                            lineHeight: '1.75',
                        }}
                    >
                        {packets.slice(-150).map((pkt, i) => {
                            const pc = protoColor(pkt.proto)
                            const isOut = pkt.direction === 'OUTGOING'
                            const isIn = pkt.direction === 'INCOMING'
                            return (
                                <div key={pkt.id} style={{
                                    display: 'grid', gridTemplateColumns: GRID,
                                    padding: '0.2rem 1rem',
                                    borderBottom: '1px solid rgba(255,255,255,0.02)',
                                    background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.015)',
                                    alignItems: 'center',
                                }}>
                                    <span style={{ color: '#5a5a6e' }}>{pkt.num}</span>
                                    <span style={{ color: '#6e6e82' }}>{pkt.time.toFixed(3)}s</span>
                                    <span style={{ color: pc, fontWeight: 700 }}>{pkt.proto}</span>
                                    <span style={{
                                        color: isOut ? '#00ff73' : '#e0e0e0',
                                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                    }}>{pkt.src}</span>
                                    <span style={{
                                        color: isOut ? '#00ff73' : isIn ? '#6ec6ff' : '#3d3d4e',
                                        fontWeight: 700, textAlign: 'center',
                                    }}>→</span>
                                    <span style={{
                                        color: isIn ? '#6ec6ff' : '#e0e0e0',
                                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                    }}>{pkt.dst}</span>
                                    <span style={{ color: '#6e6e82', textAlign: 'right', paddingRight: '1rem' }}>{pkt.length}</span>
                                    <span style={{
                                        color: '#8b8b9b', paddingLeft: '0.25rem',
                                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                    }}>{pkt.info}</span>
                                </div>
                            )
                        })}
                        {isCapturing && packets.length === 0 && (
                            <div style={{ padding: '2rem', textAlign: 'center', color: '#3d3d4e', fontSize: '0.9rem' }}>
                                Waiting for packets…
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* ── Last Capture Summary ── */}
            {!isActive && lastCap && (
                <div className="panel">
                    <div className="panel-header">
                        <span className="panel-title">
                            <CheckCircle size={18} style={{ color: '#00ff73' }} />
                            Capture Complete
                        </span>
                    </div>
                    <div style={{ padding: '1.25rem', display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                        <StatBox label="Packets" value={lastCap.packets?.toLocaleString() || '0'} color="#00f3ff" />
                        <StatBox label="Data" value={lastCap.bytes_display || '0 B'} color="#bc13fe" />
                        <StatBox label="Duration" value={lastCap.duration_display || '—'} color="#ffaa00" />
                        <StatBox label="Session" value={`#${lastCap.session_id || '—'}`} color="#6ec6ff" />
                    </div>
                    {lastCap.pcap_file && (
                        <div style={{
                            margin: '0 1.25rem 1.25rem', padding: '0.65rem 1rem', borderRadius: '8px',
                            background: 'rgba(0,243,255,0.05)', border: '1px solid rgba(0,243,255,0.1)',
                            fontSize: '0.85rem', color: '#5a5a6e',
                        }}>
                            📁 <span style={{ color: '#e0e0e0', fontFamily: 'monospace' }}>{lastCap.pcap_file}</span>
                        </div>
                    )}
                </div>
            )}

            {/* Empty state */}
            {!isActive && !lastCap && packets.length === 0 && (
                <div className="panel" style={{ textAlign: 'center', padding: '3rem 2rem' }}>
                    <MonitorSpeaker size={48} style={{ color: '#1a1a2e', marginBottom: '1rem' }} />
                    <p style={{ color: '#5a5a6e', marginBottom: '0.5rem', fontSize: '1rem' }}>No capture running</p>
                    <p style={{ color: '#3d3d4e', fontSize: '0.9rem' }}>
                        Select an interface and click <span style={{ color: '#00ff73' }}>Start</span> to begin capturing packets.
                    </p>
                    <p style={{ color: '#3d3d4e', fontSize: '0.82rem', marginTop: '0.75rem' }}>
                        ⚠ API must be started with <span style={{ color: '#ffaa00', fontFamily: 'monospace' }}>sudo</span> for capture to work.
                    </p>
                </div>
            )}

            <style>{`
                @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
                @keyframes glow-pulse {
                    0%, 100% { box-shadow: 0 0 8px rgba(0,255,115,0.2); }
                    50% { box-shadow: 0 0 20px rgba(0,255,115,0.4); }
                }
            `}</style>
        </>
    )
}

export default Capture
