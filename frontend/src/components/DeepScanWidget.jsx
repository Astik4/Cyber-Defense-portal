const DeepScanWidget = ({ isScanning, scanProgress, scanStatus, scanThreats, startDeepScan }) => {
  return (
    <div className="glass-panel action-center">
      <div className="panel-header">
        <i className="fa-solid fa-bolt"></i>&nbsp; Active Defense Grid
      </div>

      <div className="scan-btn-wrap">
        <button
          className={`cyber-btn ${isScanning ? 'scanning' : ''}`}
          onClick={startDeepScan}
          disabled={isScanning}
        >
          {isScanning
            ? <><i className="fa-solid fa-spinner fa-spin"></i>&nbsp; SCAN IN PROGRESS</>
            : <><i className="fa-solid fa-shield-virus"></i>&nbsp; Initiate Deep Threat Scan</>
          }
        </button>
      </div>

      {/* Progress */}
      {isScanning && (
        <div className="scan-progress-container fade-in">
          <div className="scan-status-row">
            <span style={{ maxWidth: '75%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {scanStatus || 'Initializing...'}
            </span>
            <span className="scan-pct">{scanProgress}%</span>
          </div>
          <div className="progress-bar">
            <div className="progress-fill" style={{ width: `${scanProgress}%` }} />
          </div>
        </div>
      )}

      {!isScanning && scanStatus && (
        <div className="fade-in" style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '10px',
          color: 'var(--cyan)',
          padding: '8px 0',
          letterSpacing: '0.5px'
        }}>
          <i className="fa-solid fa-check-circle" style={{marginRight:'6px', color:'var(--success)'}}></i>
          {scanStatus}
        </div>
      )}

      {/* Threats */}
      {scanThreats.length > 0 && (
        <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', marginTop: '10px' }}>
          <div className="threat-list-header">
            <i className="fa-solid fa-radiation" style={{marginRight:'6px'}}></i>
            {scanThreats.length} Anomal{scanThreats.length === 1 ? 'y' : 'ies'} Detected
          </div>
          <div className="threat-list">
            {scanThreats.map((threat, idx) => (
              <div
                key={idx}
                className={`threat-item fade-in ${threat.severity}`}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="threat-name">{threat.name}</div>
                  <div className="threat-action">
                    <i className="fa-solid fa-arrow-right" style={{marginRight:'4px', fontSize:'9px'}}></i>
                    {threat.action}
                  </div>
                </div>
                <button className="execute-btn">EXECUTE</button>
              </div>
            ))}
          </div>
        </div>
      )}

      {!isScanning && scanThreats.length === 0 && !scanStatus && (
        <div className="empty-state" style={{ flex: 1 }}>
          <i className="fa-solid fa-shield-halved"></i>
          <span>System secure — no threats detected</span>
        </div>
      )}
    </div>
  );
};