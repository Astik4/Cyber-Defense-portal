const { useState, useEffect } = React;

const LiveStreamWidget = ({ packets }) => {
  const [isPaused, setIsPaused]           = useState(false);
  const [showOnlyThreats, setShowOnly]    = useState(false);
  const [displayed, setDisplayed]         = useState(packets);

  useEffect(() => {
    if (!isPaused) setDisplayed(packets);
  }, [packets, isPaused]);

  const filtered  = displayed.filter(p => showOnlyThreats ? p.suspicious : true);
  const threatCnt = displayed.filter(p => p.suspicious).length;

  return (
    <div className="glass-panel" style={{ flex: 1, minHeight: 0 }}>
      {/* Header */}
      <div className="panel-header flex-between" style={{ marginBottom: '10px' }}>
        <span><i className="fa-solid fa-satellite-dish"></i>&nbsp; Live Packet Stream</span>
        <span className="panel-badge" style={{
          color: threatCnt > 0 ? 'var(--danger)' : 'var(--success)',
          borderColor: 'currentColor'
        }}>
          {threatCnt > 0 ? `${threatCnt} THREATS` : 'CLEAR'}
        </span>
      </div>

      {/* Controls */}
      <div className="stream-controls">
        <button
          className={`cyber-btn-sm ${isPaused ? 'danger active' : ''}`}
          onClick={() => setIsPaused(p => !p)}
        >
          <i className={`fa-solid fa-${isPaused ? 'play' : 'pause'}`}></i>
          &nbsp;{isPaused ? 'RESUME' : 'PAUSE'}
        </button>
        <button
          className={`cyber-btn-sm ${showOnlyThreats ? 'active' : ''}`}
          onClick={() => setShowOnly(s => !s)}
        >
          <i className="fa-solid fa-filter"></i>
          &nbsp;{showOnlyThreats ? 'THREATS ONLY' : 'ALL TRAFFIC'}
        </button>
        {isPaused && (
          <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: '9px', color: 'var(--warning)', letterSpacing: '2px' }}>
            ⏸ PAUSED
          </span>
        )}
      </div>

      {/* Meta */}
      <div className="stream-meta">
        <span>Visible: <span style={{color:'var(--cyan)'}}>{filtered.length}</span></span>
        <span>Threats in buffer: <span style={{color: threatCnt > 0 ? 'var(--danger)' : 'var(--success)'}}>{threatCnt}</span></span>
      </div>

      {/* Table */}
      <div className="stream-header">
        <span>TIME</span>
        <span>SOURCE</span>
        <span>DESTINATION</span>
        <span>PROTO</span>
      </div>

      <div className="packet-stream">
        {filtered.length === 0 ? (
          <div className="empty-state">
            <i className={`fa-solid fa-${showOnlyThreats ? 'shield-halved' : 'satellite-dish'}`}></i>
            <span>{showOnlyThreats ? 'No threats detected' : 'Awaiting packet stream...'}</span>
          </div>
        ) : (
          filtered.map((pkt, i) => (
            <div
              key={i}
              className={`packet-item ${pkt.suspicious ? (pkt.severity === 'High' ? 'malicious' : 'suspicious') : ''}`}
            >
              <span>{pkt.timestamp}</span>
              <span title={pkt.source}>{pkt.source}</span>
              <span title={pkt.destination}>{pkt.destination}</span>
              <span>
                <span className={`proto-badge proto-${pkt.protocol}`}>{pkt.protocol}</span>
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};