const { useState } = React;

const AdminLogin = ({ onLoginSuccess, API_BASE }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error,    setError]    = useState('');
  const [loading,  setLoading]  = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const res  = await fetch(`${API_BASE}/api/login`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ username, password })
      });
      const data = await res.json();

      if (res.ok && data.success) {
        onLoginSuccess();
      } else {
        setError(data.error || 'Authentication Failed. Access Denied.');
      }
    } catch {
      setError('Cannot reach backend server.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-wrap fade-in">
      <div className="glass-panel login-panel">
        <div className="login-icon">
          <i className="fa-solid fa-lock"></i>
        </div>
        <div className="login-title">RESTRICTED ACCESS</div>
        <div className="login-sub">Administrative credentials required to enter this sector.</div>

        <form className="login-form" onSubmit={handleLogin}>
          <div className="input-group">
            <i className="fa-solid fa-user"></i>
            <input
              type="text"
              className="login-input"
              placeholder="Username"
              value={username}
              onChange={e => setUsername(e.target.value)}
              required
              autoComplete="username"
            />
          </div>

          <div className="input-group">
            <i className="fa-solid fa-key"></i>
            <input
              type="password"
              className="login-input"
              placeholder="Password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              autoComplete="current-password"
            />
          </div>

          {error && (
            <div className="error-msg fade-in">
              <i className="fa-solid fa-triangle-exclamation"></i>
              {error}
            </div>
          )}

          <button type="submit" className="cyber-btn" disabled={loading} style={{ marginTop: '8px' }}>
            {loading
              ? <><i className="fa-solid fa-circle-notch fa-spin"></i>&nbsp; Authenticating...</>
              : <><i className="fa-solid fa-right-to-bracket"></i>&nbsp; Authorize</>
            }
          </button>
        </form>
      </div>
    </div>
  );
};