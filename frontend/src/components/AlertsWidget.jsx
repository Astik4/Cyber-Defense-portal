const AlertsWidget = ({ alerts }) => {
  return (
    <div className="glass-panel" style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
      <div className="panel-header">
        <i className="fa-solid fa-triangle-exclamation"></i>&nbsp; Live Alerts
        {alerts.length > 0 && (
          <span className="panel-badge" style={{ color: 'var(--danger)', borderColor: 'var(--danger)', marginLeft: 'auto' }}>
            {alerts.length}
          </span>
        )}
      </div>

      <div className="alerts-list">
        {alerts.length === 0 ? (
          <div className="empty-state" style={{ flex: 1 }}>
            <i className="fa-solid fa-shield-check"></i>
            <span>No active alerts</span>
          </div>
        ) : (
          alerts.map((alert, i) => (
            <div key={i} className={`alert-item severity-${alert.severity} fade-in`}>
              <div className="alert-meta">
                <span><i className="fa-regular fa-clock" style={{marginRight:'4px'}}></i>{alert.timestamp}</span>
                <span>SRC: {alert.source}</span>
              </div>
              <div className="alert-threat">{alert.threat}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};