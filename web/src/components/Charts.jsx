export const Sparkline = ({ data, color }) => {
    const w = 200, h = 60
    const max = Math.max(...data)
    const min = Math.min(...data)
    const range = max - min || 1
    const points = data.map((v, i) =>
        `${(i / (data.length - 1)) * w},${h - ((v - min) / range) * h}`
    ).join(' ')
    const fillPoints = `0,${h} ${points} ${w},${h}`

    return (
        <div className="sparkline-wrap">
            <svg width="100%" height="100%" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
                <defs>
                    <linearGradient id={`grad-${color}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={color} stopOpacity="0.4" />
                        <stop offset="100%" stopColor={color} stopOpacity="0" />
                    </linearGradient>
                </defs>
                <polygon points={fillPoints} fill={`url(#grad-${color})`} />
                <polyline points={points} fill="none" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke" />
            </svg>
        </div>
    )
}

export const PieChart = ({ protocols, centerLabel, centerSub }) => {
    const cx = 50, cy = 50, r = 42
    let cumAngle = -90
    const toRad = (deg) => (deg * Math.PI) / 180
    const slices = protocols.map((p) => {
        const angle = (p.pct / 100) * 360
        const start = cumAngle
        cumAngle += angle
        return { ...p, startAngle: start, endAngle: cumAngle }
    })
    return (
        <svg className="pie-chart-wrap" width="160" height="160" viewBox="0 0 100 100">
            {slices.map((s, i) => {
                const a1 = toRad(s.startAngle)
                const a2 = toRad(s.endAngle)
                const x1 = cx + r * Math.cos(a1)
                const y1 = cy + r * Math.sin(a1)
                const x2 = cx + r * Math.cos(a2)
                const y2 = cy + r * Math.sin(a2)
                const large = s.endAngle - s.startAngle > 180 ? 1 : 0
                const d = `M${cx},${cy} L${x1},${y1} A${r},${r} 0 ${large} 1 ${x2},${y2} Z`
                return (
                    <path key={i} d={d} fill={s.color}
                        style={{ filter: `drop-shadow(0 0 3px ${s.color}50)` }}
                    />
                )
            })}
            <circle cx={cx} cy={cy} r="22" fill="#0a0a10" />
            <text x={cx} y={cy - 2} textAnchor="middle" className="pie-center-text">{centerLabel}</text>
            <text x={cx} y={cy + 8} textAnchor="middle" className="pie-center-sub">{centerSub}</text>
        </svg>
    )
}
