const { useState, useEffect, useCallback } = React;
const { BrowserRouter, Routes, Route, Navigate, Link } = window.ReactRouterDOM;

const API_BASE = 'http://localhost:5000';

const ProtectedRoute = ({ isAuthenticated, children }) => {
  return isAuthenticated ? children : <Navigate to="/admin/login" replace />;
};

function DashboardView({
  packets,
  alerts,
  trafficData,
  systemStats,
  systemStatus,
  aiInput,
  setAiInput,
  handleAiAnalysis,
  isAnalyzing,
  aiResult,
  isScanning,
  scanProgress,
  scanStatus,
  scanThreats,
  startDeepScan
}) {
  const isConnected = systemStatus.includes('ONLINE');

  return (
    <div className="dashboard-layout fade-in">
      <header className="header">
        <div className="logo-container">
          <div className="logo-icon">
            <i className="fa-solid fa-shield-halved"></i>
          </div>
          <span className="logo-text">CYBERSHIELD</span>
        </div>

        <nav className="nav-tabs">
          <Link to="/dashboard" className="nav-tab active">Dashboard</Link>
          <Link to="/admin/login" className="nav-tab">Admin</Link>
        </nav>

        <div className="system-status">
          <div className="status-indicator">
            <div className="status-dot"></div>
            <span className="status-text">
              {isConnected ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>
        </div>
      </header>

      <div className="left-col">
        <LiveStreamWidget packets={packets} />
      </div>

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
    </div>
  );
}

function App() {
  const [packets, setPackets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [systemStats, setSystemStats] = useState(null);
  const [systemStatus, setSystemStatus] = useState('INITIALIZING...');
  const [isAuthenticated, setIsAuthenticated] = useState(
    localStorage.getItem('admin_auth') === 'true'
  );

  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState('');
  const [scanThreats, setScanThreats] = useState([]);
  const [aiInput, setAiInput] = useState('');
  const [aiResult, setAiResult] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [trafficData, setTrafficData] = useState(Array(20).fill({ volume: 5 }));

  const fetchStats = useCallback(async () => {
    const res = await fetch(`${API_BASE}/api/system_stats`);
    setSystemStats(await res.json());
  }, []);

  useEffect(() => {
    fetchStats();
    const id = setInterval(fetchStats, 5000);
    return () => clearInterval(id);
  }, [fetchStats]);

  useEffect(() => {
    const socket = io(API_BASE);

    socket.on('connect', () => setSystemStatus('ONLINE'));
    socket.on('disconnect', () => setSystemStatus('OFFLINE'));

    socket.on('new_packet', pkt => {
      setPackets(prev => [pkt, ...prev].slice(0, 50));
      setTrafficData(prev => [...prev.slice(1), { volume: pkt.suspicious ? 80 : 30 }]);
    });

    socket.on('new_alert', alert => {
      setAlerts(prev => [alert, ...prev].slice(0, 15));
    });

    socket.on('scan_progress', data => {
      setScanProgress(data.percent);
      setScanStatus(data.status);
      if (data.percent >= 100) setIsScanning(false);
    });

    socket.on('scan_threat', data => {
      setScanThreats(prev => [...prev, ...data.threats]);
    });

    return () => socket.close();
  }, []);

  const startDeepScan = async () => {
    setIsScanning(true);
    setScanThreats([]);
    await fetch(`${API_BASE}/api/scan`, { method: 'POST' });
  };

  const handleAiAnalysis = async () => {
    setIsAnalyzing(true);
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: aiInput })
    });
    setAiResult(await res.json());
    setIsAnalyzing(false);
  };

  const handleLoginSuccess = () => {
    localStorage.setItem('admin_auth', 'true');
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('admin_auth');
    setIsAuthenticated(false);
  };

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />

        <Route
          path="/dashboard"
          element={
            <DashboardView
              packets={packets}
              alerts={alerts}
              trafficData={trafficData}
              systemStats={systemStats}
              systemStatus={systemStatus}
              aiInput={aiInput}
              setAiInput={setAiInput}
              handleAiAnalysis={handleAiAnalysis}
              isAnalyzing={isAnalyzing}
              aiResult={aiResult}
              isScanning={isScanning}
              scanProgress={scanProgress}
              scanStatus={scanStatus}
              scanThreats={scanThreats}
              startDeepScan={startDeepScan}
            />
          }
        />

        <Route
          path="/admin/login"
          element={
            <AdminLogin
              API_BASE={API_BASE}
              onLoginSuccess={handleLoginSuccess}
            />
          }
        />

        <Route
          path="/admin/panel"
          element={
            <ProtectedRoute isAuthenticated={isAuthenticated}>
              <AdminPanel
                systemStats={systemStats}
                onLogout={handleLogout}
              />
            </ProtectedRoute>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
