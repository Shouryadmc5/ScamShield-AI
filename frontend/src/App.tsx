import { useRef, useState, type FormEvent } from 'react';
import './App.css';
import type { AnalyzeRequest, AnalyzeResponse, ApiErrorResponse } from './types';

type IndicatorCategory = {
  tag: string;
  type: 'credential' | 'urgency' | 'brand' | 'url' | 'financial' | 'general';
};

type CaseHistoryLoad = {
  cases: InvestigationCase[];
  warning: string | null;
};

type InvestigationCase = {
  caseReference: string;
  generatedAt: string;
  message: string;
  url: string;
  result: AnalyzeResponse;
};

const CASE_HISTORY_KEY = 'scamshield.case-history.v1';
const MAX_SAVED_CASES = 30;

function getRiskLevel(score: number): AnalyzeResponse['risk_level'] {
  if (score >= 60) return 'High';
  if (score >= 30) return 'Medium';
  return 'Low';
}

function isAnalyzeResponse(value: unknown): value is AnalyzeResponse {
  if (!value || typeof value !== 'object') return false;
  const response = value as Partial<AnalyzeResponse>;
  return (
    typeof response.risk_score === 'number' &&
    Number.isInteger(response.risk_score) &&
    response.risk_score >= 0 &&
    response.risk_score <= 100 &&
    ['Low', 'Medium', 'High'].includes(response.risk_level ?? '') &&
    response.risk_level === getRiskLevel(response.risk_score) &&
    Array.isArray(response.indicators) &&
    response.indicators.every((indicator) => typeof indicator === 'string') &&
    typeof response.recommendation === 'string' &&
    typeof response.analysis_method === 'string'
  );
}

function isInvestigationCase(value: unknown): value is InvestigationCase {
  if (!value || typeof value !== 'object') return false;
  const savedCase = value as Partial<InvestigationCase>;
  return (
    typeof savedCase.caseReference === 'string' &&
    /^SS-[0-9A-F-]{36}$/.test(savedCase.caseReference) &&
    typeof savedCase.generatedAt === 'string' &&
    !Number.isNaN(Date.parse(savedCase.generatedAt)) &&
    typeof savedCase.message === 'string' &&
    savedCase.message.length <= 10000 &&
    typeof savedCase.url === 'string' &&
    savedCase.url.length <= 2048 &&
    isAnalyzeResponse(savedCase.result)
  );
}

function readCaseHistory(): CaseHistoryLoad {
  try {
    const rawHistory = localStorage.getItem(CASE_HISTORY_KEY);
    if (!rawHistory) return { cases: [], warning: null };
    const parsed: unknown = JSON.parse(rawHistory);
    if (!Array.isArray(parsed)) {
      return { cases: [], warning: 'Saved case history was malformed and has been ignored.' };
    }
    const cases = parsed.filter(isInvestigationCase).slice(0, MAX_SAVED_CASES);
    return {
      cases,
      warning: cases.length !== parsed.length
        ? 'Some invalid saved cases were ignored. You can clear history to remove the stored entries.'
        : null,
    };
  } catch {
    return {
      cases: [],
      warning: 'Saved case history could not be read. New cases may still be used during this visit.',
    };
  }
}

function getIndicatorExplanation(type: IndicatorCategory['type']) {
  switch (type) {
    case 'credential':
      return 'This signal relates to a request for login, identity, or verification details. Do not share passwords or one-time codes in response to an unexpected message.';
    case 'urgency':
      return 'This signal describes pressure to act quickly or a threatened consequence. Pause and verify the request through a trusted channel before acting.';
    case 'brand':
      return 'This signal suggests a brand reference or possible impersonation pattern. Check the actual domain and contact the organization using details you already trust.';
    case 'url':
      return 'This signal points to a link or domain pattern that may make the destination harder to assess. Do not open it until you have independently verified where it leads.';
    case 'financial':
      return 'This signal relates to a prize, payment, transfer, fee, or other financial claim. Verify unexpected money requests or offers independently before sending money or sharing payment details.';
    default:
      return 'The analysis marked this pattern as potentially relevant. Review it in context; an indicator is a warning signal, not proof that the message is fraudulent.';
  }
}

function getAnalysisMethodDetails(method: string) {
  if (method.startsWith('Nebius AI LLM (') && method.endsWith(')')) {
    return {
      label: 'Nebius model inference',
      detail: `Model reported by the backend: ${method.slice('Nebius AI LLM ('.length, -1)}.`,
    };
  }
  if (method.startsWith('Deterministic rule-based heuristics')) {
    if (method.includes('Nebius inference failed')) {
      return {
        label: 'Rule-based fallback',
        detail: 'Nebius inference did not complete; this result was produced by the local deterministic rules.',
      };
    }
    if (method.includes('Nebius not configured')) {
      return {
        label: 'Rule-based analysis',
        detail: 'Nebius inference is not configured; this result was produced by the local deterministic rules.',
      };
    }
    return {
      label: 'Rule-based analysis',
      detail: 'The API reports a deterministic rule-based result; it does not provide additional model status.',
    };
  }
  return {
    label: 'Analysis method reported by backend',
    detail: method,
  };
}

function createCaseReference() {
  return `SS-${crypto.randomUUID().toUpperCase()}`;
}

function safeReportText(value: string) {
  return [...value].filter((character) => {
    const code = character.charCodeAt(0);
    return code === 9 || code === 10 || code === 13 || (code >= 32 && (code < 127 || code > 159));
  }).join('');
}

function indentReportBlock(value: string) {
  return safeReportText(value).replace(/\r\n?/g, '\n').split('\n').map((line) => `  ${line}`).join('\n');
}

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
  const [caseReference, setCaseReference] = useState<string | null>(null);
  const [reportGeneratedAt, setReportGeneratedAt] = useState<Date | null>(null);
  const [analyzedInputs, setAnalyzedInputs] = useState({ message: '', url: '' });
  const [historyLoad, setHistoryLoad] = useState<CaseHistoryLoad>(readCaseHistory);
  const caseHistory = historyLoad.cases;
  const caseHistoryRef = useRef(caseHistory);
  const [historySearch, setHistorySearch] = useState('');
  const [historyStorageAvailable, setHistoryStorageAvailable] = useState(true);

  const updateCaseHistory = (
    update: (previous: InvestigationCase[]) => InvestigationCase[],
    clearWarning = false,
  ) => {
    const nextCases = update(caseHistoryRef.current).slice(0, MAX_SAVED_CASES);
    caseHistoryRef.current = nextCases;
    setHistoryLoad((previous) => ({
      cases: nextCases,
      warning: clearWarning ? null : previous.warning,
    }));
    try {
      if (nextCases.length === 0) {
        localStorage.removeItem(CASE_HISTORY_KEY);
      } else {
        localStorage.setItem(CASE_HISTORY_KEY, JSON.stringify(nextCases));
      }
      setHistoryStorageAvailable(true);
    } catch {
      setHistoryStorageAvailable(false);
    }
  };

  const clearActiveCase = () => {
    setResult(null);
    setCaseReference(null);
    setReportGeneratedAt(null);
    setAnalyzedInputs({ message: '', url: '' });
  };

  const handleAnalyze = async (e?: FormEvent) => {
    if (e) e.preventDefault();

    const trimmedMessage = message.trim();
    const trimmedUrl = url.trim();

    // Frontend validation: reject completely empty submissions
    if (!trimmedMessage && !trimmedUrl) {
      setErrorMessage('Please provide a message, a URL, or both to analyze.');
      clearActiveCase();
      return;
    }

    if (trimmedMessage.length > 10000) {
      setErrorMessage('Message content exceeds maximum allowed length of 10,000 characters.');
      clearActiveCase();
      return;
    }

    if (trimmedUrl.length > 2048) {
      setErrorMessage('Target URL exceeds maximum allowed length of 2,048 characters.');
      clearActiveCase();
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);
    clearActiveCase();

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

      const responseData: unknown = await response.json();
      if (!isAnalyzeResponse(responseData)) {
        throw new Error('Received an invalid or malformed response structure from the analysis service.');
      }
      const data = responseData;
      const generatedAt = new Date();
      const reference = createCaseReference();
      const investigationCase: InvestigationCase = {
        caseReference: reference,
        generatedAt: generatedAt.toISOString(),
        message: trimmedMessage,
        url: trimmedUrl,
        result: data,
      };
      setResult(data);
      setCaseReference(reference);
      setReportGeneratedAt(generatedAt);
      setAnalyzedInputs({ message: trimmedMessage, url: trimmedUrl });
      updateCaseHistory((previous) => [
        investigationCase,
        ...previous.filter((savedCase) => savedCase.caseReference !== reference),
      ]);
    } catch (err) {
      const errText = err instanceof Error ? err.message : 'Failed to reach ScamShield backend service.';
      const userFacingError =
        errText === 'Failed to fetch' || errText.includes('NetworkError') || errText.includes('Load failed')
          ? 'Unable to connect to the ScamShield backend service. Please check your network connection or verify that the backend API is online.'
          : errText;
      setErrorMessage(userFacingError);
      clearActiveCase();
    } finally {
      setIsLoading(false);
    }
  };

  const handleClear = () => {
    setMessage('');
    setUrl('');
    setErrorMessage(null);
    clearActiveCase();
  };

  const loadSample = (sample: { message: string; url: string }) => {
    setMessage(sample.message);
    setUrl(sample.url);
    setErrorMessage(null);
    clearActiveCase();
  };

  const openSavedCase = (savedCase: InvestigationCase) => {
    setMessage(savedCase.message);
    setUrl(savedCase.url);
    setResult(savedCase.result);
    setCaseReference(savedCase.caseReference);
    setReportGeneratedAt(new Date(savedCase.generatedAt));
    setAnalyzedInputs({ message: savedCase.message, url: savedCase.url });
    setErrorMessage(null);
  };

  const deleteSavedCase = (reference: string) => {
    updateCaseHistory((previous) => previous.filter((savedCase) => savedCase.caseReference !== reference));
    if (caseReference === reference) clearActiveCase();
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

  const getIndicatorCategory = (indicator: string): IndicatorCategory => {
    const text = indicator.toLowerCase();
    if (text.includes('password') || text.includes('credential') || text.includes('otp') || text.includes('verification')) {
      return { tag: 'Credential Theft', type: 'credential' };
    }
    if (text.includes('urgency') || text.includes('deadline') || text.includes('suspended') || text.includes('closure') || text.includes('capitalization')) {
      return { tag: 'Urgency & Pressure', type: 'urgency' };
    }
    if (text.includes('spoofing') || text.includes('brand') || text.includes('subdomain') || text.includes('impersonat')) {
      return { tag: 'Brand Impersonation', type: 'brand' };
    }
    if (text.includes('shortener') || text.includes('ip address') || text.includes('scheme') || text.includes('unencrypted') || text.includes('domain') || text.includes('tld') || text.includes('@')) {
      return { tag: 'Deceptive URL / Link', type: 'url' };
    }
    if (text.includes('prize') || text.includes('refund') || text.includes('transfer') || text.includes('crypto') || text.includes('gift card') || text.includes('fee') || text.includes('invoice') || text.includes('bank details') || text.includes('payment')) {
      return { tag: 'Financial / Advance Fee', type: 'financial' };
    }
    return { tag: 'Suspicious Signal', type: 'general' };
  };

  const downloadReport = () => {
    if (!result || !caseReference || !reportGeneratedAt) return;

    const method = getAnalysisMethodDetails(result.analysis_method);
    const sourceTypes = [
      analyzedInputs.message ? 'Message' : null,
      analyzedInputs.url ? 'URL' : null,
    ].filter((source): source is string => source !== null);
    const evidence = result.indicators.length
      ? result.indicators.map((indicator, index) => {
          const category = getIndicatorCategory(indicator);
          return `${index + 1}. ${category.tag}\n   Observed indicator: ${indicator}\n   Explanation: ${getIndicatorExplanation(category.type)}`;
        }).join('\n\n')
      : 'No indicators were returned by the analysis method.';
    const reportText = [
      'SCAMSHIELD AI — INVESTIGATION REPORT',
      `Case reference: ${caseReference}`,
      `Generated: ${reportGeneratedAt.toLocaleString()}`,
      '',
      'RISK SUMMARY',
      `Risk level: ${result.risk_level}`,
      `Risk score: ${result.risk_score}/100 (not a probability)`,
      `Indicators returned: ${result.indicators.length}`,
      '',
      'SUBMITTED INPUTS',
      `Message:\n${indentReportBlock(analyzedInputs.message || '(not provided)')}`,
      '',
      `URL:\n${indentReportBlock(analyzedInputs.url || '(not provided)')}`,
      '',
      'EVIDENCE',
      indentReportBlock(evidence),
      '',
      'RECOMMENDED ACTION',
      indentReportBlock(result.recommendation),
      'Before acting, verify unexpected requests using a contact method you already trust. Never share passwords or one-time codes in response to an unsolicited message.',
      '',
      'ANALYSIS METHOD',
      indentReportBlock(method.label),
      indentReportBlock(method.detail),
      'This report was generated locally in your browser from the analysis result. No live URL or reputation checks were performed.',
      `Input types analyzed: ${sourceTypes.length ? sourceTypes.join(', ') : 'Not available'}`,
      '',
      'LIMITATION',
      'Automated analysis may be wrong or incomplete. Indicators are signals, not proof. Verify important requests independently.',
    ].join('\n');
    const reportBlob = new Blob([reportText], { type: 'text/plain;charset=utf-8' });
    const reportUrl = URL.createObjectURL(reportBlob);
    const downloadLink = document.createElement('a');
    downloadLink.href = reportUrl;
    downloadLink.download = `scamshield-report-${caseReference.toLowerCase()}.txt`;
    document.body.appendChild(downloadLink);
    downloadLink.click();
    downloadLink.remove();
    window.setTimeout(() => URL.revokeObjectURL(reportUrl), 1000);
  };

  const analysisMethod = result ? getAnalysisMethodDetails(result.analysis_method) : null;
  const isNebiusResult = result?.analysis_method.startsWith('Nebius AI LLM (') ?? false;
  const filteredCases = caseHistory.filter((savedCase) => {
    const query = historySearch.trim().toLowerCase();
    if (!query) return true;
    return [
      savedCase.caseReference,
      savedCase.result.risk_level,
      savedCase.result.analysis_method,
      savedCase.message,
      savedCase.url,
    ].some((field) => field.toLowerCase().includes(query));
  });

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
        <section className="cyber-card" aria-labelledby="input-heading">
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
            <span id="input-heading">Threat Analysis Input</span>
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
                maxLength={10000}
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
                maxLength={2048}
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
            {historyLoad.warning && (
              <p className="storage-warning" role="status">{historyLoad.warning}</p>
            )}

            {/* Action Buttons */}
            <div className="form-actions">
              <button
                type="submit"
                className="btn-primary"
                disabled={isLoading}
              >
                {isLoading ? (
                  <>
                    <span className="spinner" aria-hidden="true"></span>
                    <span>Analyzing indicators...</span>
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
            <div className="sr-only" aria-live="polite" role="status">
              {isLoading ? 'Analysis in progress. Your message and URL are being analyzed.' : ''}
            </div>
          </form>
        </section>

        <section className="cyber-card history-card" aria-labelledby="history-heading">
          <div className="history-header">
            <div>
              <h2 id="history-heading" className="card-heading">Recent cases</h2>
              <p className="history-privacy">
                Completed cases, including submitted text and URLs, are saved in this browser on this device only. They are not synced; delete individual cases or clear all history at any time.
              </p>
            </div>
            {(caseHistory.length > 0 || historyLoad.warning) && (
              <button
                type="button"
                className="btn-secondary"
                onClick={() => {
                  updateCaseHistory(() => [], true);
                  clearActiveCase();
                }}
              >
                Clear history
              </button>
            )}
          </div>
          {!historyStorageAvailable && (
            <p className="storage-warning" role="status">
              Browser storage is unavailable or full. New cases remain available for this session but may not be saved.
            </p>
          )}
          {caseHistory.length > 0 ? (
            <>
              <label htmlFor="history-search" className="sr-only">Search saved cases</label>
              <input
                id="history-search"
                className="cyber-input history-search"
                type="search"
                placeholder="Search case reference, risk level, or submitted text"
                value={historySearch}
                onChange={(event) => setHistorySearch(event.target.value)}
              />
              {filteredCases.length ? (
                <ul className="history-list">
                  {filteredCases.map((savedCase) => (
                    <li className="history-item" key={savedCase.caseReference}>
                      <button
                        type="button"
                        className="history-open"
                        aria-current={savedCase.caseReference === caseReference ? 'true' : undefined}
                        onClick={() => openSavedCase(savedCase)}
                      >
                        <span className="history-case-title">{savedCase.caseReference}</span>
                        <span className={`history-risk ${getRiskClass(savedCase.result.risk_level)}`}>
                          {savedCase.result.risk_level} · {savedCase.result.risk_score}/100
                        </span>
                        <span className="history-date">{new Date(savedCase.generatedAt).toLocaleString()}</span>
                        <span className="history-preview">
                          {(savedCase.message || savedCase.url || 'No input saved').slice(0, 120)}
                        </span>
                      </button>
                      <button
                        type="button"
                        className="history-delete"
                        aria-label={`Delete case ${savedCase.caseReference}`}
                        onClick={() => deleteSavedCase(savedCase.caseReference)}
                      >
                        Delete
                      </button>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="history-empty">No saved cases match this search.</p>
              )}
            </>
          ) : (
            <p className="history-empty">Completed investigations will appear here. No input is saved until an analysis finishes.</p>
          )}
        </section>

        {/* Results Card */}
        {result && (
          <section className="cyber-card results-card" aria-labelledby="report-title">
            <div className="report-toolbar">
              <div>
                <p className="report-eyebrow">Investigation report</p>
                <h2 id="report-title" className="report-title">Analysis findings</h2>
              </div>
              <button type="button" className="btn-secondary report-download" onClick={downloadReport}>
                <svg
                  width="17"
                  height="17"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                  <path d="m7 10 5 5 5-5" />
                  <path d="M12 15V3" />
                </svg>
                Download report
              </button>
            </div>
            <div className="case-meta">
              <span><strong>Case reference</strong> <code>{caseReference}</code></span>
              <span>Generated {reportGeneratedAt?.toLocaleString()}</span>
            </div>

            <div className="results-header-bar">
              <div className="score-badge-group">
                <div
                  className={`score-circle ${getRiskClass(result.risk_level)}`}
                  role="img"
                  aria-label={`Risk score ${result.risk_score} out of 100`}
                >
                  <span className="score-number">{result.risk_score}</span>
                  <span className="score-max">/100</span>
                </div>
                <div className="risk-header-details">
                  <div className="risk-tag-row">
                    <span className={`risk-level-tag ${getRiskClass(result.risk_level)}`}>
                      {result.risk_level} Risk Level
                    </span>
                    <span className="threat-indicator-count">
                      {result.indicators.length} {result.indicators.length === 1 ? 'Signal Flagged' : 'Signals Flagged'}
                    </span>
                  </div>
                  <div className="risk-title">
                    {result.risk_level === 'High' && 'High Risk Signals Detected'}
                    {result.risk_level === 'Medium' && 'Suspicious Indicators Found — Caution Advised'}
                    {result.risk_level === 'Low' && 'No or Few Risk Signals Detected'}
                  </div>
                </div>
              </div>

              {/* Visual Score Gauge Bar */}
              <div
                className="score-bar-container"
                role="img"
                aria-label={`Risk score ${result.risk_score} out of 100. Low is below 30, medium is 30 to 59, and high is 60 or above.`}
              >
                <div className="score-bar-track">
                  <div
                    className={`score-bar-fill ${getRiskClass(result.risk_level)}`}
                    style={{ width: `${Math.max(result.risk_score, 4)}%` }}
                  />
                </div>
                <div className="score-bar-labels">
                  <span>0 (Safe)</span>
                  <span>30 (Medium)</span>
                  <span>60+ (High)</span>
                </div>
              </div>
            </div>
            <p className="risk-explanation">
              {result.risk_level === 'High' &&
                'The score crossed the high-risk rule threshold. Treat this as a reason to pause and verify independently, not as proof of fraud.'}
              {result.risk_level === 'Medium' &&
                'The result contains signals that merit caution. Review the evidence and verify the request before acting.'}
              {result.risk_level === 'Low' &&
                'Few or no configured risk signals were returned. A low score does not prove the message or URL is safe.'}
            </p>
            <p className="score-context">Risk score is a triage rating, not a probability or guarantee.</p>

            {/* Detected Indicators */}
            <div className="indicators-section">
              <div className="section-header-row">
                <h3 className="section-title">Evidence and observed signals</h3>
                <span className="section-subtitle">Explanations describe each returned indicator; they are not independent verification.</span>
              </div>
              {result.indicators.length > 0 ? (
                <ul className="indicators-list">
                  {result.indicators.map((ind, i) => {
                    const cat = getIndicatorCategory(ind);
                    return (
                      <li key={`${ind}-${i}`} className={`indicator-item evidence-card ${getRiskClass(result.risk_level)}`}>
                        <span className="indicator-badge">{cat.tag}</span>
                        <div className="evidence-copy">
                          <h4 className="indicator-text">{ind}</h4>
                          <p>{getIndicatorExplanation(cat.type)}</p>
                        </div>
                      </li>
                    );
                  })}
                </ul>
              ) : (
                <div className="no-indicators-box" role="status">
                  <span className="check-icon" aria-hidden="true">✓</span>
                  <span>No indicators were returned by this analysis. This does not establish that the message or URL is safe.</span>
                </div>
              )}
            </div>

            <div className={`recommendation-box ${getRiskClass(result.risk_level)} risk-banner`}>
              <div className="rec-header">
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
                  <line x1="12" y1="16" x2="12" y2="12" />
                  <line x1="12" y1="8" x2="12.01" y2="8" />
                </svg>
                <h3 className="rec-title">Recommended safety action</h3>
              </div>
              <div className="rec-text">{result.recommendation}</div>
              <ul className="safety-actions">
                <li>Verify unexpected requests through an official app, website, or phone number you already trust.</li>
                <li>Do not share passwords, one-time codes, or payment details in response to an unsolicited request.</li>
                <li>Do not open links or attachments unless you have independently verified the sender and destination.</li>
              </ul>
            </div>

            <div className="analysis-method-panel">
              <div className="analysis-method-heading">
                <h3>Analysis method</h3>
                <span className={`method-badge ${isNebiusResult ? 'method-ai' : result.analysis_method.startsWith('Deterministic rule-based heuristics') ? 'method-rules' : 'method-other'}`}>
                  {analysisMethod?.label}
                </span>
              </div>
              <p>{analysisMethod?.detail}</p>
              <p className="privacy-note">
                This report is generated locally from the returned result. URLs are not opened or checked against live reputation services.
                When Nebius inference is enabled, the submitted message and URL are sent to Nebius for analysis.
              </p>
            </div>
          </section>
        )}
      </main>

      {/* Footer */}
      <footer className="app-footer">
        <p className="disclaimer-text">
          <strong>Security Disclaimer:</strong> Automated analysis can be wrong or incomplete. Scores are not probabilities, and indicators are not proof. Verify important requests independently.
        </p>
        <p className="footer-copy">ScamShield AI • Hackathon SecOps Edition</p>
      </footer>
    </div>
  );
}

export default App;
