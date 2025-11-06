import { useState } from 'react'
import IPAnalyzer from './components/IPAnalyzer'
import './App.css'

function App() {
  return (
    <div className="App">
      <header className="app-header">
        <h1>🛡️ Cerberus</h1>
        <p className="subtitle">Threat Intelligence Correlation Engine</p>
      </header>
      <main className="app-main">
        <IPAnalyzer />
      </main>
      <footer className="app-footer">
        <p>Powered by VirusTotal, AlienVault OTX, and OpenAI</p>
      </footer>
    </div>
  )
}

export default App

