import { NavLink, Route, Routes } from 'react-router-dom'
import IPAnalyzer from './components/IPAnalyzer'
import ThreatDashboard from './components/ThreatDashboard'
import './App.css'

function App() {
  return (
    <div className="App">
      <header className="app-header">
        <h1 className="glitch" data-text="🛡️ Cerberus">
          🛡️ Cerberus
        </h1>
        <p className="subtitle">Threat Intelligence Correlation Engine</p>
      </header>

      <nav className="app-nav">
        <NavLink to="/" end className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
          Analyzer
        </NavLink>
        <NavLink to="/dashboard" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
          Dashboard
        </NavLink>
      </nav>

      <main className="app-main">
        <Routes>
          <Route path="/" element={<IPAnalyzer />} />
          <Route path="/dashboard" element={<ThreatDashboard />} />
        </Routes>
      </main>

      <footer className="app-footer">
        <p>Powered by AbuseIPDB and OpenAI</p>
      </footer>
    </div>
  )
}

export default App

