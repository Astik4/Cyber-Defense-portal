const { useState, useEffect, useCallback } = React;

const API_BASE = 'http://localhost:5000';

function Dashboard() {
  const [socket,       setSocket]      = useState(null);
  const [packets,      setPackets]     = useState([]);
  const [alerts,       setAlerts]      = useState([]);
  const [systemStatus, setSystemStatus]= useState('Initializing defense grid...');
  const [activeTab,    setActiveTab]   = useState('dashboard');
  const [isAdminAuthed,setAdminAuthed] = useState(false);

  // System stats for header + admin panel
  const [systemStats,  setSystemStats] = useState(null);

  // Scan state
  const [isScanning,   setIsScanning]  = useState(false);
  const [scanProgress, setScanProgress]= useState(0);
  const [scanStatus,   setScanStatus]  = useState('');
  const [scanThreats,  setScanThreats] = useState([]);

  // AI state
  const [aiInput,    setAiInput]    = useState('');
  const [aiResult,   setAiResult]   = useState(null);
  const [isAnalyzing,setIsAnalyzing]= useState(false);

  // Traffic graph  (last 30 samples)
  const [trafficData, setTrafficData] = useState(Array(30).fill({ volume: 5 }));

  // Live clock
  const [clock, setClock] = useState('');
  useEffect(() => {
    const tick = () => setClock(new Date().toLocaleTimeString('en-GB'));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  // System stats polling
  const fetchStats = useCallback(async () => {
    try {
      const res  = await fetch(`${API_BASE}/api/system_stats`);
      const data = await res.json();
      setSystemStats(data);
    } catch { /* silently ignore */ }
  }, []);

  useEffect(() => {
    fetchStats();
    const id = setInterval(fetchStats, 5000);
    return () => clearInterval(id);
  }, [fetchStats]);

  // WebSocket setup
  useEffect(() => {
    const sock = io(API_BASE);
    setSocket(sock);

    sock.on('connect',    ()  => setSystemStatus('DEFENSE GRID ONLINE'));
    sock.on('disconnect', ()  => setSystemStatus('CONNECTION LOST — RECONNECTING'));

    sock.on('new_packet', pkt => {
      setPackets(prev => [pkt, ...prev].slice(0, 50));
      setTrafficData(prev => {
        const vol = pkt.suspicious ? Math.floor(Math.random() * 40) + 60 : Math.floor(Math.random() * 35) + 10;
        return [...prev.slice(1), { volume: vol, suspicious: pkt.suspicious }];
      });
    });

    sock.on('new_alert', alert => {
      setAlerts(prev => [alert, ...prev].slice(0, 15));
    });

    sock.on('scan_progress', data => {
      setScanProgress(data.percent);
      setScanStatus(data.status);
      if (data.percent >= 100) setIsScanning(false);
    });

    sock.on('scan_threat', data => {
      setScanThreats(prev => {
        const existing = new Set(prev.map(t => t.name));
        return [...prev, ...data.threats.filter(t => !existing.has(t.name))];
      });
    });

    sock.on('scan_complete', data => {
      setScanStatus(`Scan Complete — Security Score: ${data.score}/100`);
      setIsScanning(false);
    });

    sock.on('admin_alert', data => {
      console.warn('[Admin Alert]', data.message);
    });

    return () => sock.close();
  }, []);

  const startDeepScan = async () => {
    if (isScanning) return;
    setIsScanning(true);
    setScanProgress(0);
    setScanThreats([]);
    setScanStatus('');
    try {
      await fetch(`${API_BASE}/api/scan`, { method: 'POST' });
    } catch {
      setIsScanning(false);
    }
  };

  const handleAiAnalysis = async () => {
    if (!aiInput.trim() || isAnalyzing) return;
    setIsAnalyzing(true);
    setAiResult(null);
    try {
      const res  = await fetch(`${API_BASE}/api/analyze`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ input: aiInput })
      });
      setAiResult(await res.json());
    } finally {
      setIsAnalyzing(false);
    }
  };

  const threatCount  = alerts.filter(a => a.severity === 'High' || a.severity === 'Critical').length;
  const isConnected  = systemStatus.includes('ONLINE');

  return (
    <div className="dashboard-layout fade-in">

      {/* ══ HEADER ══ */}
      <header className="header">
        {/* Logo */}
        <div className="logo-container">
          <div className="logo-icon">
            <i className="fa-solid fa-shield-halved"></i>
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
              <span className="logo-text">CYBERSHIELD</span>
              <span className="logo-version">SOC.02</span>
            </div>
          </div>
        </div>

        {/* Center stats */}
        <div className="header-center">
          <div className="header-stat">
            <span className="header-stat-value">{clock}</span>
            <span className="header-stat-label">System Time</span>
          </div>
          <div className="header-divider"/>
          <div className="header-stat">
            <span className="header-stat-value" style={{color: threatCount > 0 ? 'var(--danger)' : 'var(--success)'}}>
              {threatCount}
            </span>
            <span className="header-stat-label">Active Threats</span>
          </div>
          <div className="header-divider"/>
          <div className="header-stat">
            <span className="header-stat-value">{packets.length}</span>
            <span className="header-stat-label">Packets Buffered</span>
          </div>
          <div className="header-divider"/>
          {/* Tab navigation */}
          <nav className="nav-tabs">
            {['dashboard', 'admin'].map(tab => (
              <button
                key={tab}
                className={`nav-tab ${activeTab === tab ? 'active' : ''}`}
                onClick={() => setActiveTab(tab)}
              >
                {tab === 'dashboard'
                  ? <><i className="fa-solid fa-gauge-high"></i>&nbsp;Dashboard</>
                  : <><i className="fa-solid fa-user-shield"></i>&nbsp;Admin</>
                }
              </button>
            ))}
          </nav>
        </div>

        {/* Status */}
        <div className="system-status">
          <div className="status-indicator" style={{
            borderColor: isConnected ? 'rgba(0,230,118,0.3)' : 'rgba(255,23,68,0.3)',
            background:  isConnected ? 'rgba(0,230,118,0.06)' : 'rgba(255,23,68,0.06)',
          }}>
            <div className="status-dot" style={{ background: isConnected ? 'var(--success)' : 'var(--danger)' }}/>
            <span className="status-text" style={{ color: isConnected ? 'var(--success)' : 'var(--danger)' }}>
              {isConnected ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>
        </div>
      </header>

      {/* ══ DASHBOARD VIEW ══ */}
      {activeTab === 'dashboard' && (
        <>
          {/* Left: Packet Stream */}
          <div className="left-col">
            <LiveStreamWidget packets={packets} />
          </div>

          {/* Center: Graph + Scan */}
          <div className="center-col">
            <NetworkGraphWidget trafficData={trafficData} />
            <DeepScanWidget
              isScanning={isScanning}
              scanProgress={scanProgress}
              scanStatus={scanStatus}
              scanThreats={scanThreats}
              startDeepScan={startDeepScan}
            />
          </div>

          {/* Right: AI + Alerts */}
          <div className="right-col">
            <AIAnalyzerWidget
              aiInput={aiInput}
              setAiInput={setAiInput}
              handleAiAnalysis={handleAiAnalysis}
              isAnalyzing={isAnalyzing}
              aiResult={aiResult}
            />
            <AlertsWidget alerts={alerts} />
          </div>
        </>
      )}

      {/* ══ ADMIN VIEW ══ */}
      {activeTab === 'admin' && (
        <div style={{ gridColumn: '1 / -1', minHeight: 0, overflow: 'auto' }}>
          {!isAdminAuthed
            ? <AdminLogin onLoginSuccess={() => setAdminAuthed(true)} API_BASE={API_BASE} />
            : <AdminPanel systemStats={systemStats} />
          }
        </div>
      )}
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<Dashboard />);