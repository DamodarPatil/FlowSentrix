# NetGuard — Feature Roadmap

## Current Status
Core CLI engine is **complete** with packet capture, SQLite storage, Suricata IDS,
behavioral analysis, and session management. Web GUI dashboard (React + Vite) has
been started with a static layout using mock data.

---

## Phase 1: GUI for Existing Features (Current)
Build the web frontend for everything the CLI already does. No new backend logic needed.

### Dashboard Page ✅
- [x] Sidebar with navigation
- [x] Engine status badge (Running/Stopped)
- [x] Stat cards (Total Packets, Active Sessions, Data Processed)
- [x] Recent alerts panel (Suricata + behavioral)
- [x] Protocol distribution bars

### Backend API (FastAPI)
- [ ] `GET /api/stats` — packet count, session count, total bytes
- [ ] `GET /api/sessions` — list all capture sessions
- [ ] `GET /api/alerts?limit=N` — recent alerts
- [ ] `GET /api/protocols` — protocol breakdown
- [ ] `GET /api/connections?limit=N` — top connections/flows
- [ ] `POST /api/capture/start` — start capture
- [ ] `POST /api/capture/stop` — stop capture
- [ ] `GET /api/search?ip=X` / `?proto=X` / `?port=X` — search

### Additional GUI Pages
- [ ] **Sessions Page** — list/load/delete sessions
- [ ] **Live Traffic Page** — real-time packet stream
- [ ] **Alerts Page** — full alerts table with filters
- [ ] **Connections Page** — top flows table with sorting
- [ ] **Search Page** — search by IP, protocol, port
- [ ] **Settings Page** — interface, display, API key config

---

## Phase 2: IP Enrichment Module (New Backend Feature)
Add context and intelligence to every IP address so users can make informed decisions.

### `core/ip_enrichment.py` (New Module)
- [ ] **Reverse DNS** — `socket.getfqdn(ip)` to resolve domain names
- [ ] **GeoIP Lookup** — Country, city, coordinates (MaxMind GeoLite2 free DB)
- [ ] **ASN / Organization** — ISP and organization name (GeoLite2 ASN DB)
- [ ] **CDN Detection** — Identify Cloudflare, Akamai, AWS, Google, Azure IP ranges
- [ ] **Known Safe IPs** — Whitelist gateway, DNS servers, private/local IPs
- [ ] **Traffic History** — Query our DB for how often this IP has been seen

### CLI Commands
- [ ] `inspect <IP>` — Show full enriched profile of any IP

### GUI Integration
- [ ] Click any IP in the GUI → opens an IP detail panel with all enrichment data
- [ ] Geo-map visualization (optional, world map with alert locations)

---

## Phase 3: Active Response (New Backend Feature)
Allow users to take defensive actions directly from the tool.

### `core/response_engine.py` (New Module)
- [ ] **Block IP** — `iptables -A INPUT -s <IP> -j DROP` with safety checks
- [ ] **Unblock IP** — `iptables -D INPUT -s <IP> -j DROP`
- [ ] **List Blocked** — Show all currently blocked IPs with enrichment info
- [ ] **Safety Guards** — Prevent blocking: gateway, DNS, private IPs, whitelisted IPs

### CLI Commands
- [ ] `block <IP>` — Block with confirmation (shows enrichment first)
- [ ] `unblock <IP>` — Remove block
- [ ] `show blocked` — List all active blocks

### GUI Integration
- [ ] "Block" button on alert rows (shows enrichment + confirmation dialog)
- [ ] "Blocked IPs" management page
- [ ] Visual indicators on blocked IPs throughout the dashboard

---

## Phase 4: Visual Upgrades (Frontend Polish)
Enhance the dashboard with advanced visualizations after real data is flowing.

- [ ] **Sparklines** in stat cards (mini trend charts)
- [ ] **Live traffic time-series graph** (area chart, full width)
- [ ] **Donut chart** for protocol distribution
- [ ] **Actionable alert rows** (hover → quick actions)
- [ ] **Alert grouping** (accordion for same-IP alerts)
- [ ] **Network topology graph** (force-directed node graph, optional)
- [ ] **Dark/light theme toggle** (optional)

---

## Phase 5: Notifications & Reporting
- [ ] **Email alerts** for high-severity detections
- [ ] **Webhook/Slack integration** for real-time notifications
- [ ] **PDF report generation** — session summary with charts
- [ ] **Scheduled reports** — daily/weekly automated summaries

---

## Build Order Summary
```
Phase 1 → GUI for existing features (we are HERE)
Phase 2 → IP enrichment (know what you're looking at)
Phase 3 → Active response (block/unblock with confidence)
Phase 4 → Visual upgrades (sparklines, charts, maps)
Phase 5 → Notifications & reporting
```
