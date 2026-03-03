import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Network, Shield, Settings, Zap, Radio } from 'lucide-react'

const Sidebar = () => {
    return (
        <aside className="sidebar">
            <div className="sidebar-brand">
                <div className="sidebar-brand-icon">
                    <Zap size={22} />
                </div>
                <div className="sidebar-brand-text">
                    <h2>NetGuard</h2>
                    <span>Command Center</span>
                </div>
            </div>

            <nav className="sidebar-nav">
                <NavLink to="/capture" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                    <Radio size={18} />
                    Capture
                </NavLink>
                <NavLink to="/" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} end>
                    <LayoutDashboard size={18} />
                    Dashboard
                </NavLink>
                <NavLink to="/connections" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                    <Network size={18} />
                    Connections
                </NavLink>
                <NavLink to="/alerts" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                    <Shield size={18} />
                    Alerts
                </NavLink>
                <NavLink to="/settings" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                    <Settings size={18} />
                    Settings
                </NavLink>
            </nav>
        </aside>
    )
}

export default Sidebar
