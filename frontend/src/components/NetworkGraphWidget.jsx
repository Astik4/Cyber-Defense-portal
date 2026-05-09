const NetworkGraphWidget = ({ trafficData }) => {
  const maxVol = Math.max(...trafficData.map(d => d.volume), 1);

  const getBarClass = (d) => {
    if (d.volume > 80) return 'threat';
    if (d.volume > 50) return 'suspicious';
    return 'normal';
  };

  return (
    <div className="glass-panel" style={{ flex: 1, minHeight: 0 }}>
      <div className="panel-header">
        <i className="fa-solid fa-chart-line"></i>&nbsp; Network Traffic Load
        <span className="panel-badge text-dim" style={{ color: 'rgba(200,230,245,0.4)', borderColor: 'rgba(200,230,245,0.15)', fontSize: '9px' }}>
          LIVE · {trafficData.length} SAMPLES
        </span>
      </div>

      <div className="graph-wrapper">
        <div className="graph-container">
          {/* Grid lines */}
          {[25, 50, 75].map(pct => (
            <div key={pct} className="graph-gridline" style={{ bottom: `${pct}%` }} />
          ))}
          <div className="graph-axis-y" />
          <div className="graph-axis-x" />

          {trafficData.map((d, i) => (
            <div
              key={i}
              className={`graph-bar ${getBarClass(d)}`}
              style={{ height: `${(d.volume / maxVol) * 95}%` }}
              title={`Volume: ${d.volume}`}
            />
          ))}
        </div>

        <div className="graph-legend">
          <span><span className="legend-dot" style={{background:'var(--cyan)'}}></span>Normal</span>
          <span><span className="legend-dot" style={{background:'var(--warning)'}}></span>Suspicious</span>
          <span><span className="legend-dot" style={{background:'var(--danger)'}}></span>Threat</span>
        </div>
      </div>
    </div>
  );
};