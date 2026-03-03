import { useState, useEffect } from 'react'
import { Activity, Wifi, HardDrive, Cpu, ArrowUpRight, AlertTriangle, Search, X } from 'lucide-react'
import { Sparkline, PieChart } from '../components/Charts'
import { useSession } from '../context/SessionContext'

const API = 'http://localhost:8000'

const Dashboard = () => {
    const [stats, setStats] = useState(null)
    const [alerts, setAlerts] = useState([])
    const [apiOnline, setApiOnline] = useState(false)
    const { sessionId } = useSession()

    useEffect(() => {
        const fetchData = async () => {
            try {
                const sessionParam = sessionId ? `?session_id=${sessionId}` : ''
                const [statsRes, alertsRes] = await Promise.all([
                    fetch(`${API}/api/stats${sessionParam}`),
                    fetch(`${API}/api/alerts?per_page=10${sessionId ? `&session_id=${sessionId}` : ''}`),
                ])
                const statsData = await statsRes.json()
                const alertsData = await alertsRes.json()
                setStats(statsData)
                // Map new API fields to dashboard display format
                setAlerts((alertsData.alerts || []).map(a => ({
                    title: a.signature || a.title || 'Unknown Alert',
                    meta: a.meta || `${a.src_ip} → ${a.dst_ip}`,
                    severity: a.severity,
                    timestamp: a.timestamp,
                })))
                setApiOnline(true)
            } catch (e) {
                setApiOnline(false)
            }
        }
        fetchData()
        const interval = setInterval(fetchData, 5000)
        return () => clearInterval(interval)
    }, [sessionId])


    const pktVal = stats?.total_packets?.value || '0'
    const pktUnit = stats?.total_packets?.unit || ''
    const bytesVal = stats?.total_bytes?.value || '0'
    const bytesUnit = stats?.total_bytes?.unit || 'B'
    const sessions = stats?.session_count || 0
    const connections = stats?.connection_count || 0
    const protocols = stats?.protocols || []

    return (
        <>
            <div className="page-header">
                <div>
                    <h1 className="page-title">Dashboard</h1>
                    <p className="page-subtitle">System overview and monitoring status</p>
                </div>
                <div className="status-badge">
                    <Wifi size={16} className="icon" />
                    <span>{apiOnline ? 'Engine Online' : 'Engine Offline'}</span>
                    <div className={`status-dot ${apiOnline ? 'online' : ''}`}></div>
                </div>
            </div>

            {/* Stat Cards */}
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-card-top">
                        <span className="stat-label">Total Packets</span>
                        <div className="stat-icon cyan"><Activity size={20} /></div>
                    </div>
                    <div className="stat-value">{pktVal}{pktUnit && <span className="stat-unit">{pktUnit}</span>}</div>
                    <div className="stat-trend"><ArrowUpRight size={14} /> {connections.toLocaleString()} connections</div>
                    <Sparkline data={[30, 45, 35, 50, 65, 55, 70, 80, 72, 85, 90, 95]} color="#00f3ff" />
                </div>

                <div className="stat-card">
                    <div className="stat-card-top">
                        <span className="stat-label">Capture Sessions</span>
                        <div className="stat-icon purple"><Cpu size={20} /></div>
                    </div>
                    <div className="stat-value">{sessions}</div>
                    <div className="stat-trend"><ArrowUpRight size={14} /> {connections.toLocaleString()} total flows</div>
                    <Sparkline data={[20, 25, 30, 28, 35, 40, 38, 45, 50, 48, 55, 52]} color="#bc13fe" />
                </div>

                <div className="stat-card">
                    <div className="stat-card-top">
                        <span className="stat-label">Data Processed</span>
                        <div className="stat-icon green"><HardDrive size={20} /></div>
                    </div>
                    <div className="stat-value">{bytesVal}<span className="stat-unit">{bytesUnit}</span></div>
                    <div className="stat-trend"><ArrowUpRight size={14} /> Across all sessions</div>
                    <Sparkline data={[60, 62, 58, 65, 63, 67, 64, 68, 66, 70, 69, 71]} color="#00ff73" />
                </div>
            </div>

            {/* Protocol Distribution */}
            {protocols.length > 0 && (
                <div className="panel">
                    <div className="panel-header">
                        <span className="panel-title">
                            <Activity size={16} style={{ color: '#00f3ff' }} />
                            Protocol Distribution
                        </span>
                        <span className="alert-count-badge">{protocols.length} protocols</span>
                    </div>
                    <div className="proto-panel-body">
                        <PieChart
                            protocols={protocols}
                            centerLabel={pktVal}
                            centerSub={`${pktUnit} PKTS`}
                        />
                        <div className="proto-legend">
                            {protocols.map((p, i) => (
                                <div className="legend-row" key={i}>
                                    <div className="legend-dot" style={{ background: p.color }}></div>
                                    <span className="legend-name">{p.name}</span>
                                    <span className="legend-pct">{p.pct}%</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}

            {/* Recent Alerts */}
            <div className="panel">
                <div className="panel-header">
                    <span className="panel-title">
                        <AlertTriangle size={16} className="icon" />
                        Recent Alerts
                    </span>
                    <span className="alert-count-badge">{alerts.length} total</span>
                </div>
                <div className="alert-list">
                    {alerts.length === 0 && (
                        <div style={{ color: '#3d3d4e', fontSize: '0.85rem', padding: '1rem', textAlign: 'center' }}>
                            No alerts recorded yet
                        </div>
                    )}
                    {alerts.map((alert, i) => (
                        <div className={`alert-row ${alert.severity}`} key={i}>
                            <AlertTriangle size={18} className="alert-icon" />
                            <div className="alert-info">
                                <div className="alert-title">{alert.title}</div>
                                <div className="alert-meta">{alert.meta}</div>
                            </div>
                            <span className={`severity-badge ${alert.severity}`}>
                                {alert.severity.charAt(0).toUpperCase() + alert.severity.slice(1)}
                            </span>
                            <span className="alert-time">{alert.timestamp}</span>
                            <div className="alert-actions">
                                <button className="alert-btn analyze"><Search size={12} /> Analyze</button>
                                <button className="alert-btn dismiss"><X size={12} /> Dismiss</button>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </>
    )
}

export default Dashboard
