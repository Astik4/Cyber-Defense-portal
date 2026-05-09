const AIAnalyzerWidget = ({ aiInput, setAiInput, handleAiAnalysis, isAnalyzing, aiResult }) => {
  const getSeverityClass = (sev) => {
    if (!sev) return '';
    if (sev === 'Critical' || sev === 'High') return 'Critical';
    return sev;
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) handleAiAnalysis();
  };

  return (
    <div className="glass-panel" style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
      <div className="panel-header">
        <i className="fa-solid fa-microchip"></i>&nbsp; Nexus AI Analyzer
      </div>

      <textarea
        className="ai-analyzer-input"
        rows={3}
        placeholder="Enter suspicious IP, domain, hash, or log snippet... (Ctrl+Enter to analyze)"
        value={aiInput}
        onChange={e => setAiInput(e.target.value)}
        onKeyDown={handleKeyDown}
        style={{ marginBottom: '10px', flexShrink: 0 }}
      />

      <button className="cyber-btn" onClick={handleAiAnalysis} disabled={isAnalyzing} style={{ flexShrink: 0 }}>
        {isAnalyzing
          ? <><i className="fa-solid fa-circle-nodes fa-spin"></i>&nbsp; Analyzing Neural Pathways...</>
          : <><i className="fa-solid fa-magnifying-glass"></i>&nbsp; Analyze Threat</>
        }
      </button>

      {aiResult && (
        <div className="ai-result fade-in" style={{ flex: 1, overflowY: 'auto', marginTop: '12px' }}>
          <div className="ai-result-header">
            <span className="ai-category">{aiResult.category}</span>
            <span className={`severity-badge ${getSeverityClass(aiResult.severity)}`}>
              {aiResult.severity}
            </span>
          </div>

          <div className="confidence-row">
            <span className="confidence-label">CONFIDENCE</span>
            <span className="confidence-val">{aiResult.confidence}</span>
          </div>

          <div className="ai-mitre">
            <i className="fa-solid fa-diagram-project" style={{marginRight:'6px'}}></i>
            {aiResult.mitre_mapping}
          </div>

          {aiResult.attack_type && (
            <div style={{ marginBottom: '8px', fontSize: '10px', color: 'rgba(200,230,245,0.5)' }}>
              <i className="fa-solid fa-skull-crossbones" style={{marginRight:'6px', color:'var(--warning)'}}></i>
              {aiResult.attack_type}
            </div>
          )}

          <p className="ai-explanation">{aiResult.explanation}</p>

          <div className="ai-action">
            <div className="ai-action-label">Recommended Action</div>
            {aiResult.recommended_action}
          </div>

          {aiResult.mitigation && aiResult.mitigation.length > 0 && (
            <div style={{ marginTop: '10px' }}>
              <div style={{ fontSize: '9px', letterSpacing: '2px', color: 'rgba(200,230,245,0.4)', marginBottom: '6px', textTransform: 'uppercase' }}>
                Mitigation Steps
              </div>
              {aiResult.mitigation.map((step, i) => (
                <div key={i} style={{ fontSize: '10px', color: 'rgba(200,230,245,0.6)', padding: '3px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', display: 'flex', gap: '8px' }}>
                  <span style={{ color: 'var(--cyan)', flexShrink: 0 }}>{String(i + 1).padStart(2, '0')}</span>
                  {step}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {!aiResult && !isAnalyzing && (
        <div className="empty-state" style={{ flex: 1 }}>
          <i className="fa-solid fa-microchip"></i>
          <span>Enter an indicator above to begin analysis</span>
        </div>
      )}
    </div>
  );
};