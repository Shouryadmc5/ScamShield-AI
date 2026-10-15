import { useState, type FormEvent } from 'react';
import './App.css';
import type { AnalyzeRequest, AnalyzeResponse, ApiErrorResponse } from './types';

const SAMPLE_PAYLOADS = [
  {
    label: '🚨 Bank Phish SMS',
    message: 'URGENT: Your Chase checking account has been suspended! Verify your credentials within 24 hours to restore access.',
    url: 'http://chase-security-verify.xyz/login',
  },
  {
    label: '🎁 Prize Winner Scam',
    message: 'Congratulations! You have won $5,000 in our unclaimed funds sweepstakes. Claim your refund immediately.',
    url: 'https://bit.ly/claim-prize-reward',
  },
  {
    label: '✅ Normal Message',
    message: 'Hey, are we still meeting for lunch at 1pm today? Let me know!',
    url: '',
  },
];

function App() {
  const [message, setMessage] = useState('');
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [result, setResult] = useState<AnalyzeResponse | null>(null);

  const handleAnalyze = async (e?: FormEvent) => {
    if (e) e.preventDefault();

    const trimmedMessage = message.trim();
    const trimmedUrl = url.trim();

    // Frontend validation: reject completely empty submissions
    if (!trimmedMessage && !trimmedUrl) {
      setErrorMessage('Please provide a message, a URL, or both to analyze.');
      setResult(null);
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);

    const payload: AnalyzeRequest = {
      message: trimmedMessage || undefined,
      url: trimmedUrl || undefined,
    };

    try {
      const apiBase = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/+$/, '');
      const endpoint = `${apiBase}/api/analyze`;

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        let errorDetail = `Server error (${response.status})`;
        try {
          const errorJson: ApiErrorResponse = await response.json();
          if (typeof errorJson.detail === 'string') {
            errorDetail = errorJson.detail;
          } else if (Array.isArray(errorJson.detail) && errorJson.detail[0]?.msg) {
            errorDetail = errorJson.detail[0].msg;
          }
        } catch {
          // If response body is not JSON, retain default error status
        }
        throw new Error(errorDetail);
      }

      const data: AnalyzeResponse = await response.json();
      setResult(data);
    } catch (err) {
      const errText = err instanceof Error ? err.message : 'Failed to reach ScamShield backend service.';
      setErrorMessage(errText);
      setResult(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handleClear = () => {
    setMessage('');
    setUrl('');
    setErrorMessage(null);
    setResult(null);
  };

  const loadSample = (sample: { message: string; url: string }) => {
    setMessage(sample.message);
    setUrl(sample.url);
    setErrorMessage(null);
    setResult(null);
  };

  const getRiskClass = (level?: string) => {
    switch (level) {
      case 'High':
        return 'risk-high';
      case 'Medium':
        return 'risk-medium';
      case 'Low':
      default:
        return 'risk-low';
    }
  };

  return (
    <div className="app-container">
      {/* Header */}
      <header className="app-header">
        <div className="brand-wrapper">
          <div className="brand-logo-title">
            <svg
              className="shield-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
            <div>
              <h1 className="brand-title">
                ScamShield <span>AI</span>
              </h1>
              <p className="brand-subtitle">Explainable Scam Message & Phishing URL Threat Inspection</p>
            </div>
          </div>
          <div className="brand-badge">SecOps Console v0.1</div>
        </div>
      </header>

      {/* Main Content */}
      <main className="main-content">
        {/* Input Card */}
        <section className="cyber-card" aria-label="Suspicious Input Form">
          <h2 className="card-heading">
            <svg
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
            Threat Analysis Input
          </h2>

          <form onSubmit={handleAnalyze} className="analysis-form">
            {/* Message Area */}
            <div className="input-group">
              <label htmlFor="message-input" className="input-label">
                <span>Suspicious Message Content</span>
                <span className="input-hint">SMS, email lure, WhatsApp, or chat snippet</span>
              </label>
              <textarea
                id="message-input"
                className="cyber-textarea"
                placeholder="Paste the suspicious message body here (e.g. 'URGENT: Your account will be closed...')"
                value={message}
                onChange={(e) => {
                  setMessage(e.target.value);
                  if (errorMessage) setErrorMessage(null);
                }}
                disabled={isLoading}
                rows={4}
              />
            </div>

            {/* URL Input */}
            <div className="input-group">
              <label htmlFor="url-input" className="input-label">
                <span>Target URL</span>
                <span className="input-hint">Links, shortened URLs, or suspicious domains</span>
              </label>
              <input
                id="url-input"
                type="text"
                className="cyber-input"
                placeholder="e.g. http://paypal-account-verify.xyz/update"
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value);
                  if (errorMessage) setErrorMessage(null);
                }}
                disabled={isLoading}
                autoComplete="off"
                spellCheck="false"
              />
            </div>

            {/* Quick Sample Chips */}
            <div className="quick-samples">
              <span className="samples-label">Load test sample:</span>
              {SAMPLE_PAYLOADS.map((sample, idx) => (
                <button
                  key={idx}
                  type="button"
                  className="sample-chip"
                  onClick={() => loadSample(sample)}
                  disabled={isLoading}
                >
                  {sample.label}
                </button>
              ))}
            </div>

            {/* Validation & Error Alert */}
            {errorMessage && (
              <div className="error-alert" role="alert">
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <span>{errorMessage}</span>
              </div>
            )}

            {/* Action Buttons */}
            <div className="form-actions">
              <button
                type="submit"
                className="btn-primary"
                disabled={isLoading || (!message.trim() && !url.trim())}
              >
                {isLoading ? (
                  <>
                    <span className="spinner" aria-hidden="true"></span>
                    <span>Analyzing Indicators...</span>
                  </>
                ) : (
                  <>
                    <svg
                      width="18"
                      height="18"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      aria-hidden="true"
                    >
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    </svg>
                    <span>Run Threat Analysis</span>
                  </>
                )}
              </button>

              <button
                type="button"
                className="btn-secondary"
                onClick={handleClear}
                disabled={isLoading || (!message && !url && !result && !errorMessage)}
              >
                Clear
              </button>
            </div>
          </form>
        </section>

        {/* Results Card */}
        {result && (
          <section className="cyber-card results-card" aria-label="Analysis Results">
            <div className="results-header-bar">
              <div className="score-badge-group">
                <div className={`score-circle ${getRiskClass(result.risk_level)}`}>
                  <span className="score-number">{result.risk_score}</span>
                  <span className="score-max">/100</span>
                </div>
                <div>
                  <span className={`risk-level-tag ${getRiskClass(result.risk_level)}`}>
                    {result.risk_level} Risk
                  </span>
                  <div className="risk-title">
                    {result.risk_level === 'High' && 'High Probability Scam Detected'}
                    {result.risk_level === 'Medium' && 'Suspicious Indicators Found'}
                    {result.risk_level === 'Low' && 'Low Threat Detected'}
                  </div>
                </div>
              </div>
            </div>

            {/* Detected Indicators */}
            <div>
              <h3 className="section-title">Detected Risk Indicators</h3>
              {result.indicators.length > 0 ? (
                <ul className="indicators-list">
                  {result.indicators.map((ind, i) => (
                    <li key={i} className={`indicator-item ${getRiskClass(result.risk_level)}`}>
                      <span className="indicator-bullet" aria-hidden="true">⚠</span>
                      <span>{ind}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="no-indicators-box">
                  No recognized phishing keywords, deceptive domain patterns, or urgency tactics identified.
                </div>
              )}
            </div>

            {/* Safe Recommendation */}
            <div className={`recommendation-box ${getRiskClass(result.risk_level)} risk-banner`}>
              <div className="rec-title">Recommended Action</div>
              <div className="rec-text">{result.recommendation}</div>
            </div>

            {/* Metadata */}
            <div className="results-meta">
              <span><strong>Inspection Method:</strong> {result.analysis_method}</span>
              <span>Safe local inspection (no URLs loaded)</span>
            </div>
          </section>
        )}
      </main>

      {/* Footer */}
      <footer className="app-footer">
        <p className="disclaimer-text">
          <strong>Security Disclaimer:</strong> Heuristic analysis provides rule-based probability scores and does not guarantee complete protection. Never enter confidential information on unverified domains.
        </p>
        <p className="footer-copy">ScamShield AI • Hackathon SecOps Edition</p>
      </footer>
    </div>
  );
}

export default App;
