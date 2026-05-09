const { useState, useEffect } = React;

const AdminPanel = ({ systemStats }) => {
  const [config,    setConfig]    = useState({ sniffing_paused: false, ai_enabled: true });
  const [blocklist, setBlocklist] = useState([]);
  const [banIp,     setBanIp]     = useState('');

  const fetchConfig = async () => {
    try {
      const res  = await fetch('/api/admin/config');
      const data = await res.json();
      setConfig(data.active_config || {});
      setBlocklist(data.blocked_ips || []);
    } catch (e) { console.error(e); }
  };

  useEffect(() => {
    fetchConfig();
    const iv = setInterval(fetchConfig, 3000);
    return () => clearInterval(iv);
  }, []);

  const toggle = async (key) => {
    const nv = !config[key];
    setConfig(p => ({ ...p, [key]: nv }));
    await fetch('/api/admin/config', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ [key]: nv })
    });
  };

  const handleBan = async () => {
    if (!banIp.trim()) return;
    await fetch('/api/admin/blocklist', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ ip: banIp.trim() })
    });
    setBanIp('');
    fetchConfig();
  };

  const auditLogs = [
    { time: '00:15:21', act: 'Firewall Rule Created',    user: 'admin'  },
    { time: '00:14:59', act: 'System Metrics Polled',    user: 'system' },
    { time: '00:12:05', act: 'Admin Login Success',       user: 'admin'  },
    { time: '00:08:44', act: 'AI Threat Engine Online',   user: 'system' },
    { time: '00:04:11', act: 'Deep Scan Initiated',       user: 'admin'  },
  ];

  const statColor = (pct) => pct > 80 ? 'var(--danger)' : pct > 60 ? 'var(--warning)' : 'var(--cyan)';

  return (
    <div className="admin-grid fade-in admin-theme">

      {/* Server Health — full width */}
      <div className="glass-panel" style={{ gridColumn: '1 / -1' }}>
        <div className="panel-header">
          <i className="fa-solid fa-server"></i>&nbsp; Server Health Overview
        </div>
        <div style={{ display: 'flex', gap: '16px' }}>
          {[
            { label: 'CPU Usage',   val: systemStats?.cpu_percent,    unit: '%' },
            { label: 'Memory',      val: systemStats?.memory_percent, unit: '%' },
            { label: 'Disk',        val: systemStats?.disk_percent,   unit: '%' },
            { label: 'TCP Conns',   val: systemStats?.net_connections, unit: '' },
          ].map(({ label, val, unit }) => (
            <div key={label} className="stat-box" style={{ flex: 1 }}>
              <div className="stat-label">{label}</div>
              <div className="stat-value" style={{ color: val != null && unit === '%' ? statColor(val) : 'var(--cyan)' }}>
                {val != null ? `${val}${unit}` : '---'}
              </div>
              {val != null && unit === '%' && (
                <div className="progress-bar" style={{ height: '3px', marginTop: '4px' }}>
                  <div className="progress-fill" style={{ width: `${val}%`, background: statColor(val) }} />
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Engine Config */}
      <div className="glass-panel">
        <div className="panel-header">
          <i className="fa-solid fa-gears"></i>&nbsp; Engine Config
        </div>
        <p style={{ fontSize: '11px', color: 'rgba(200,230,245,0.4)', marginBottom: '16px' }}>
          Global parameters for the backend daemon engine.
        </p>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          {[
            { label: 'Live Packet Mode', key: 'sniffing_paused', invert: true, activeLabel: 'ACTIVE', offLabel: 'PAUSED' },
            { label: 'AI Threat Engine', key: 'ai_enabled',       invert: false, activeLabel: 'ONLINE', offLabel: 'OFFLINE' },
          ].map(({ label, key, invert, activeLabel, offLabel }) => {
            const isOn = invert ? !config[key] : config[key];
            return (
              <div key={key} className="toggle-row">
                <span style={{ fontSize: '12px' }}>{label}</span>
                <button
                  className={`cyber-btn-sm ${isOn ? 'active' : 'danger active'}`}
                  onClick={() => toggle(key)}
                >
                  {isOn ? activeLabel : offLabel}
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* Countermeasures */}
      <div className="glass-panel">
        <div className="panel-header">
          <i className="fa-solid fa-shield-cat"></i>&nbsp; Countermeasures
        </div>
        <p style={{ fontSize: '11px', color: 'rgba(200,230,245,0.4)', marginBottom: '16px' }}>
          Deceptive traps and security hardening modules.
        </p>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          {[
            { label: 'Honeypot Protocols', status: 'DEPLOYED', cls: 'active' },
            { label: 'Reverse IP Tracing', status: 'OFFLINE',  cls: 'danger active' },
            { label: 'DB Auto-Encryption', status: 'STANDBY',  cls: '' },
          ].map(({ label, status, cls }) => (
            <div key={label} className="toggle-row">
              <span style={{ fontSize: '12px' }}>{label}</span>
              <button className={`cyber-btn-sm ${cls}`}>{status}</button>
            </div>
          ))}
        </div>
      </div>

      {/* Firewall Blocklist */}
      <div className="glass-panel">
        <div className="panel-header">
          <i className="fa-solid fa-shield-virus"></i>&nbsp; Firewall Blocklist
        </div>
        <div className="blocklist-input-row">
          <input
            className="ai-analyzer-input"
            placeholder="192.168.x.x"
            value={banIp}
            onChange={e => setBanIp(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleBan()}
          />
          <button className="ban-btn" onClick={handleBan}>BAN</button>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', flex: 1, overflowY: 'auto' }}>
          {blocklist.length === 0
            ? <div style={{ fontSize: '11px', color: 'rgba(200,230,245,0.3)', fontFamily: 'var(--font-mono)', padding: '6px 0' }}>No IPs currently blocked.</div>
            : blocklist.map((ip, i) => (
              <div key={i} className="blocked-ip">
                <span><i className="fa-solid fa-ban" style={{marginRight:'6px'}}></i>{ip}</span>
                <span style={{ fontSize: '9px', letterSpacing: '1px' }}>BLOCKED</span>
              </div>
            ))
          }
        </div>
      </div>

      {/* Audit Logs — full width */}
      <div className="glass-panel" style={{ gridColumn: '1 / -1' }}>
        <div className="panel-header">
          <i className="fa-solid fa-terminal"></i>&nbsp; System Audit Logs
        </div>
        <div className="audit-log-window">
          {auditLogs.map((log, i) => (
            <div key={i} className="audit-entry">
              <span className="audit-time">[{log.time}]</span>
              <span className="audit-user">{log.user}@root:~$</span>
              <span>{log.act}</span>
            </div>
          ))}
          <div className="audit-entry">
            <span className="audit-time">[{new Date().toTimeString().split(' ')[0]}]</span>
            <span className="audit-user">admin@root:~$</span>
            <span className="blink">_</span>
          </div>
        </div>
      </div>
    </div>
  );
};