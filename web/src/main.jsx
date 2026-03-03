import React from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import './index.css'

import { SessionProvider } from './context/SessionContext'
import Layout from './components/Layout'
import AlertToastProvider from './components/AlertToast'
import Dashboard from './pages/Dashboard'
import Connections from './pages/Connections'
import Capture from './pages/Capture'
import Alerts from './pages/Alerts'
import Settings from './pages/Settings'

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <SessionProvider>
        <AlertToastProvider />
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/capture" element={<Capture />} />
            <Route path="/connections" element={<Connections />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/settings" element={<Settings />} />
          </Route>
        </Routes>
      </SessionProvider>
    </BrowserRouter>
  </React.StrictMode>,
)

