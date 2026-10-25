import { Suspense, lazy, useEffect, useLayoutEffect, useRef, useState, type FormEvent } from 'react';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import Lenis from 'lenis';
import './App.css';
import type { AnalyzeRequest, AnalyzeResponse, ApiErrorResponse } from './types';

const HeroScene = lazy(() => import('./HeroScene'));

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
gsap.registerPlugin(ScrollTrigger);

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
  return { label: 'Analysis method reported by backend', detail: method };
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
    label: 'Bank account alert',
    message: 'URGENT: Your Chase checking account has been suspended! Verify your credentials within 24 hours to restore access.',
    url: 'http://chase-security-verify.xyz/login',
  },
  {
    label: 'Prize message',
    message: 'Congratulations! You have won $5,000 in our unclaimed funds sweepstakes. Claim your refund immediately.',
    url: 'https://bit.ly/claim-prize-reward',
  },
  { label: 'Ordinary message', message: 'Hey, are we still meeting for lunch at 1pm today? Let me know!', url: '' },
];

function scrollToAnalyzer(lenis: Lenis | null) {
  if (lenis) {
    lenis.scrollTo('#analyzer', { offset: -28, duration: 1.05 });
    return;
  }
  document.querySelector('#analyzer')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function App() {
  const pageRef = useRef<HTMLDivElement>(null);
  const lenisRef = useRef<Lenis | null>(null);
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
  const [reducedMotion, setReducedMotion] = useState(
    () => window.matchMedia('(prefers-reduced-motion: reduce)').matches,
  );

  useEffect(() => {
    const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
    const updatePreference = () => setReducedMotion(preference.matches);
    preference.addEventListener('change', updatePreference);
    return () => preference.removeEventListener('change', updatePreference);
  }, []);

  useEffect(() => {
    if (reducedMotion) return undefined;
    const lenis = new Lenis({ autoRaf: false, smoothWheel: true, lerp: 0.09 });
    lenisRef.current = lenis;
    const syncScrollTrigger = () => ScrollTrigger.update();
    const tick = (time: number) => lenis.raf(time * 1000);
    lenis.on('scroll', syncScrollTrigger);
    gsap.ticker.add(tick);
    gsap.ticker.lagSmoothing(0);
    return () => {
      lenis.off('scroll', syncScrollTrigger);
      gsap.ticker.remove(tick);
      lenis.destroy();
      lenisRef.current = null;
      ScrollTrigger.getAll().forEach((trigger) => trigger.kill());
    };
  }, [reducedMotion]);

  useLayoutEffect(() => {
    if (reducedMotion || !pageRef.current) return undefined;
    const context = gsap.context(() => {
      gsap.from('.hero-copy > *', {
        y: 34,
        opacity: 0,
        duration: 0.9,
        stagger: 0.11,
        ease: 'power3.out',
        delay: 0.15,
      });
      gsap.from('.hero-visual', {
        scale: 0.88,
        opacity: 0,
        duration: 1.2,
        ease: 'power3.out',
        delay: 0.25,
      });
      gsap.utils.toArray<HTMLElement>('[data-reveal]').forEach((element) => {
        gsap.from(element, {
          y: 44,
          opacity: 0,
          duration: 0.8,
          ease: 'power3.out',
          scrollTrigger: { trigger: element, start: 'top 84%', once: true },
        });
      });
      if (window.matchMedia('(min-width: 641px)').matches) {
        const story = gsap.timeline({
          scrollTrigger: {
            trigger: '.story-section',
            start: 'top top',
            end: '+=1750',
            pin: '.story-stage',
            scrub: 0.7,
            anticipatePin: 1,
          },
        });
        story
          .fromTo('.story-word', { yPercent: 80, opacity: 0.1 }, { yPercent: 0, opacity: 1, stagger: 0.12, duration: 0.8 })
          .fromTo('.story-step[data-step="1"]', { opacity: 0.25, x: 26 }, { opacity: 1, x: 0, duration: 0.45 }, 0.55)
          .fromTo('.story-signal', { scaleX: 0, transformOrigin: 'left center' }, { scaleX: 1, duration: 0.5 }, 0.95)
          .fromTo('.story-step[data-step="2"]', { opacity: 0.25, x: 26 }, { opacity: 1, x: 0, duration: 0.45 }, 1.1)
          .fromTo('.story-evidence', { y: 36, opacity: 0 }, { y: 0, opacity: 1, duration: 0.6 }, 1.55)
          .fromTo('.story-step[data-step="3"]', { opacity: 0.25, x: 26 }, { opacity: 1, x: 0, duration: 0.45 }, 1.9)
          .fromTo('.story-map-path', { strokeDasharray: 1, strokeDashoffset: 1 }, { strokeDashoffset: 0, duration: 0.9 }, 0.8)
          .fromTo('.story-map-node', { scale: 0.5, opacity: 0.3 }, { scale: 1, opacity: 1, stagger: 0.08, duration: 0.35 }, 1.25);
      } else {
        gsap.set('.story-step, .story-evidence', { opacity: 1, clearProps: 'transform' });
      }
      gsap.to('.hero-grid', {
        yPercent: 10,
        ease: 'none',
        scrollTrigger: { trigger: '.hero', start: 'top top', end: 'bottom top', scrub: true },
      });
    }, pageRef);
    return () => context.revert();
  }, [reducedMotion]);

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
      if (nextCases.length === 0) localStorage.removeItem(CASE_HISTORY_KEY);
      else localStorage.setItem(CASE_HISTORY_KEY, JSON.stringify(nextCases));
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

  const handleAnalyze = async (event?: FormEvent) => {
    event?.preventDefault();
    const trimmedMessage = message.trim();
    const trimmedUrl = url.trim();
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
      const response = await fetch(`${apiBase}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        let errorDetail = `Server error (${response.status})`;
        try {
          const errorJson: ApiErrorResponse = await response.json();
          if (typeof errorJson.detail === 'string') errorDetail = errorJson.detail;
          else if (Array.isArray(errorJson.detail) && errorJson.detail[0]?.msg) errorDetail = errorJson.detail[0].msg;
        } catch {
          // Non-JSON error bodies keep the status-based message.
        }
        throw new Error(errorDetail);
      }

      const responseData: unknown = await response.json();
      if (!isAnalyzeResponse(responseData)) {
        throw new Error('Received an invalid or malformed response structure from the analysis service.');
      }
      const generatedAt = new Date();
      const reference = createCaseReference();
      const investigationCase: InvestigationCase = {
        caseReference: reference,
        generatedAt: generatedAt.toISOString(),
        message: trimmedMessage,
        url: trimmedUrl,
        result: responseData,
      };
      setResult(responseData);
      setCaseReference(reference);
      setReportGeneratedAt(generatedAt);
      setAnalyzedInputs({ message: trimmedMessage, url: trimmedUrl });
      updateCaseHistory((previous) => [
        investigationCase,
        ...previous.filter((savedCase) => savedCase.caseReference !== reference),
      ]);
    } catch (error) {
      const errorText = error instanceof Error ? error.message : 'Failed to reach ScamShield backend service.';
      const userFacingError =
        errorText === 'Failed to fetch' || errorText.includes('NetworkError') || errorText.includes('Load failed')
          ? 'Unable to connect to the ScamShield backend service. Please check your network connection or verify that the backend API is online.'
          : errorText;
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
    scrollToAnalyzer(lenisRef.current);
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

  const getRiskClass = (level?: string) => `risk-${(level ?? 'Low').toLowerCase()}`;

  const getIndicatorCategory = (indicator: string): IndicatorCategory => {
    const text = indicator.toLowerCase();
    if (text.includes('password') || text.includes('credential') || text.includes('otp') || text.includes('verification')) {
      return { tag: 'Credential theft', type: 'credential' };
    }
    if (text.includes('urgency') || text.includes('deadline') || text.includes('suspended') || text.includes('closure') || text.includes('capitalization')) {
      return { tag: 'Urgency & pressure', type: 'urgency' };
    }
    if (text.includes('spoofing') || text.includes('brand') || text.includes('subdomain') || text.includes('impersonat')) {
      return { tag: 'Brand impersonation', type: 'brand' };
    }
    if (text.includes('shortener') || text.includes('ip address') || text.includes('scheme') || text.includes('unencrypted') || text.includes('domain') || text.includes('@')) {
      return { tag: 'URL structure', type: 'url' };
    }
    if (text.includes('prize') || text.includes('refund') || text.includes('transfer') || text.includes('crypto') || text.includes('gift card') || text.includes('fee') || text.includes('invoice') || text.includes('bank details') || text.includes('payment')) {
      return { tag: 'Financial request', type: 'financial' };
    }
    return { tag: 'Observed signal', type: 'general' };
  };

  const downloadReport = () => {
    if (!result || !caseReference || !reportGeneratedAt) return;
    const method = getAnalysisMethodDetails(result.analysis_method);
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
      '',
      'LIMITATION',
      'Automated analysis may be wrong or incomplete. Indicators are signals, not proof. Verify important requests independently.',
    ].join('\n');
    const reportUrl = URL.createObjectURL(new Blob([reportText], { type: 'text/plain;charset=utf-8' }));
    const downloadLink = document.createElement('a');
    downloadLink.href = reportUrl;
    downloadLink.download = `scamshield-report-${caseReference.toLowerCase()}.txt`;
    document.body.appendChild(downloadLink);
    downloadLink.click();
    downloadLink.remove();
    window.setTimeout(() => URL.revokeObjectURL(reportUrl), 1000);
  };

  const analysisMethod = result ? getAnalysisMethodDetails(result.analysis_method) : null;
  const filteredCases = caseHistory.filter((savedCase) => {
    const query = historySearch.trim().toLowerCase();
    return !query || [
      savedCase.caseReference,
      savedCase.result.risk_level,
      savedCase.result.analysis_method,
      savedCase.message,
      savedCase.url,
    ].some((field) => field.toLowerCase().includes(query));
  });

  return (
    <div className="site-shell" ref={pageRef}>
      <header className="site-header">
        <a className="wordmark" href="#top" aria-label="ScamShield home">
          <span className="wordmark-mark" aria-hidden="true"><i /><i /><i /></span>
          <span>SCAMSHIELD<span className="wordmark-period">.</span></span>
        </a>
        <nav className="top-nav" aria-label="Main navigation">
          <a href="#approach">Approach</a>
          <a href="#capabilities">Capabilities</a>
          <a href="#analyzer">Analyzer</a>
        </nav>
        <button type="button" className="nav-cta" onClick={() => scrollToAnalyzer(lenisRef.current)}>
          Analyze a message <span aria-hidden="true">↗</span>
        </button>
      </header>

      <main id="top">
        <section className="hero" aria-labelledby="hero-title">
          <div className="hero-atmosphere" aria-hidden="true" />
          <div className="hero-grid">
            <div className="hero-copy">
              <p className="eyebrow"><span className="eyebrow-dot" /> PERSONAL THREAT INSPECTION</p>
              <h1 id="hero-title"><span>Trust nothing.</span><br /><em>Verify everything.</em></h1>
              <p className="hero-intro">
                A message can sound right and still lead somewhere wrong. Slow it down, inspect the signals, and decide with more context.
              </p>
              <div className="hero-actions">
                <button type="button" className="button-primary" onClick={() => scrollToAnalyzer(lenisRef.current)}>
                  Analyze a message <span aria-hidden="true">↓</span>
                </button>
                <a className="text-link" href="#approach">See how it works <span aria-hidden="true">↘</span></a>
              </div>
              <div className="hero-footnote">
                <span className="status-ring" aria-hidden="true" />
                <span>Private by default. No live link checking.</span>
              </div>
            </div>
            <div className="hero-visual" aria-label="An abstract shield scans a suspicious signal">
              {!reducedMotion && (
                <Suspense fallback={<div className="scene-placeholder" aria-hidden="true" />}>
                  <HeroScene />
                </Suspense>
              )}
              {reducedMotion && <div className="static-shield" aria-hidden="true"><span>◇</span></div>}
              <div className="visual-coordinate coordinate-top">SIGNAL / 01</div>
              <div className="visual-coordinate coordinate-bottom">INSPECT BEFORE YOU ACT</div>
              <div className="visual-crosshair" aria-hidden="true">+</div>
            </div>
          </div>
          <div className="hero-index"><span>01 / 04</span><span>MESSAGE · DOMAIN · CONTEXT</span></div>
        </section>

        <section className="story-section" id="approach" aria-labelledby="story-title">
          <div className="story-stage">
            <div className="story-intro">
              <p className="eyebrow"><span className="eyebrow-number">01</span> THE MOMENT BEFORE THE CLICK</p>
              <h2 id="story-title" aria-label="A suspicious message. Three signals. One clearer decision.">
                <span className="story-word">A suspicious</span>
                <span className="story-word">message.</span>
                <span className="story-word story-accent">Three signals.</span>
              </h2>
            </div>
            <div className="story-process" aria-label="Illustrative analysis process">
              <svg className="story-map" viewBox="0 0 500 480" aria-hidden="true">
                <path className="story-map-path" d="M45 90 168 132 240 66 354 142 440 91M168 132l52 125 134-40 86 112M220 257l-88 126 172-15 136-109" />
                <path className="story-map-path story-map-path-accent" d="m240 66 14 191 134 55M45 90l87 293" />
                <circle className="story-map-node" cx="45" cy="90" r="4" />
                <circle className="story-map-node" cx="168" cy="132" r="5" />
                <circle className="story-map-node story-map-node-accent" cx="240" cy="66" r="6" />
                <circle className="story-map-node" cx="354" cy="142" r="4" />
                <circle className="story-map-node story-map-node-accent" cx="220" cy="257" r="6" />
                <circle className="story-map-node" cx="354" cy="217" r="4" />
                <circle className="story-map-node" cx="440" cy="91" r="4" />
                <circle className="story-map-node" cx="132" cy="383" r="4" />
                <circle className="story-map-node story-map-node-accent" cx="304" cy="368" r="5" />
                <circle className="story-map-node" cx="440" cy="329" r="4" />
              </svg>
              <div className="story-step" data-step="1">
                <span className="step-number">01</span>
                <div><h3>Read the request</h3><p>What is the message asking you to do?</p></div>
              </div>
              <div className="story-signal" aria-hidden="true"><span /></div>
              <div className="story-step" data-step="2">
                <span className="step-number">02</span>
                <div><h3>Inspect the structure</h3><p>Does the URL reveal the destination it implies?</p></div>
              </div>
              <div className="story-signal" aria-hidden="true"><span /></div>
              <div className="story-step" data-step="3">
                <span className="step-number">03</span>
                <div><h3>Make a clearer decision</h3><p>Review returned signals. Verify through a channel you trust.</p></div>
              </div>
              <div className="story-evidence" aria-label="Illustrative evidence example">
                <div className="evidence-label"><span /> ILLUSTRATIVE SIGNAL</div>
                <p>Account access pressure</p>
                <small>One observed pattern — not proof of fraud.</small>
              </div>
            </div>
            <div className="story-index">A PROCESS, NOT A PROMISE <span>02 — 04</span></div>
          </div>
        </section>

        <section className="preview-section" aria-labelledby="preview-title">
          <div className="section-heading" data-reveal>
            <p className="eyebrow"><span className="eyebrow-number">02</span> EXPLAINABLE BY DESIGN</p>
            <h2 id="preview-title">See the signal.<br /><em>Keep your judgment.</em></h2>
            <p>Results show the patterns returned by the analysis—not a verdict, guarantee, or live reputation check.</p>
          </div>
          <div className="preview-frame" data-reveal>
            <div className="preview-topbar">
              <div className="window-dots" aria-hidden="true"><i /><i /><i /></div>
              <span>SCAMSHIELD / INVESTIGATION VIEW</span>
              <span className="preview-live"><i /> INTERFACE PREVIEW</span>
            </div>
            <div className="preview-content">
              <div className="preview-input">
                <p className="preview-kicker">ILLUSTRATIVE MESSAGE</p>
                <p className="preview-message">“Your account needs attention. Sign in to review your security settings.”</p>
                <div className="preview-url"><span>↗</span> account-review.example.test</div>
                <p className="preview-disclaimer">Example content for interface illustration only. Not a live scan or actual analysis result.</p>
              </div>
              <div className="preview-result">
                <div className="preview-result-head">
                  <div><span className="preview-kicker">OBSERVED PATTERN</span><h3>Pressure to verify</h3></div>
                  <span className="preview-evidence-mark">01</span>
                </div>
                <p>This example demonstrates how a returned indicator can be explained in plain language. The analyzer does not confirm a sender’s identity.</p>
                <div className="preview-rule"><span /> VERIFY THROUGH A CHANNEL YOU ALREADY TRUST</div>
              </div>
            </div>
          </div>
          <p className="preview-caption" data-reveal><span>FIG. 01</span> The product view is illustrative; only analysis submitted through the live analyzer produces a case result.</p>
        </section>

        <section className="capabilities-section" id="capabilities" aria-labelledby="capabilities-title">
          <div className="capabilities-heading" data-reveal>
            <p className="eyebrow"><span className="eyebrow-number">03</span> WHAT GETS EXAMINED</p>
            <h2 id="capabilities-title">Four ways to<br /><em>slow the moment down.</em></h2>
          </div>
          <div className="capability-list">
            <article className="capability-row" data-reveal>
              <span className="capability-index">A / 01</span>
              <div className="capability-glyph glyph-message" aria-hidden="true"><span /><span /><span /></div>
              <div className="capability-copy"><h3>Message patterns</h3><p>Pressure, credential requests, financial lures, and combinations of signals—read in context, not as single magic words.</p></div>
              <span className="capability-arrow" aria-hidden="true">↗</span>
            </article>
            <article className="capability-row" data-reveal>
              <span className="capability-index">A / 02</span>
              <div className="capability-glyph glyph-url" aria-hidden="true"><span>://</span><i /></div>
              <div className="capability-copy"><h3>URL structure</h3><p>Host, scheme, and deceptive structure are inspected without opening the URL or following redirects.</p></div>
              <span className="capability-arrow" aria-hidden="true">↗</span>
            </article>
            <article className="capability-row" data-reveal>
              <span className="capability-index">A / 03</span>
              <div className="capability-glyph glyph-evidence" aria-hidden="true"><i /><i /><i /></div>
              <div className="capability-copy"><h3>Evidence, in plain language</h3><p>Returned indicators are shown with explanations. An indicator is a signal to review—not independent verification.</p></div>
              <span className="capability-arrow" aria-hidden="true">↗</span>
            </article>
            <article className="capability-row" data-reveal>
              <span className="capability-index">A / 04</span>
              <div className="capability-glyph glyph-action" aria-hidden="true"><span>↗</span><i /></div>
              <div className="capability-copy"><h3>Safer next steps</h3><p>Practical recommendations help you pause, avoid sharing sensitive details, and verify requests through trusted channels.</p></div>
              <span className="capability-arrow" aria-hidden="true">↗</span>
            </article>
          </div>
        </section>

        <section className="analyzer-section" id="analyzer" aria-labelledby="analyzer-title">
          <div className="analyzer-intro" data-reveal>
            <p className="eyebrow"><span className="eyebrow-number">04</span> YOUR TURN</p>
            <h2 id="analyzer-title">Pause the message.<br /><em>Put it under a light.</em></h2>
            <p>Analysis uses local rules unless Nebius inference is explicitly configured on the backend. Submitted data is not sent to report-generation services.</p>
            <div className="analyzer-note"><span className="status-ring" /> URLs are inspected passively. They are never opened here.</div>
          </div>
          <div className="analyzer-workspace">
            <div className="analyzer-bar"><span>SCAMSHIELD / ANALYZER</span><span>PRIVATE SESSION <i /></span></div>
            <form className="analysis-form" onSubmit={handleAnalyze}>
              <div className="input-group">
                <label className="input-label" htmlFor="message-input"><span>Message content</span><span className="input-hint">SMS / email / chat</span></label>
                <textarea
                  id="message-input"
                  className="cyber-textarea"
                  placeholder="Paste a suspicious message here"
                  value={message}
                  maxLength={10000}
                  onChange={(event) => {
                    setMessage(event.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  disabled={isLoading}
                />
              </div>
              <div className="input-group">
                <label className="input-label" htmlFor="url-input"><span>Target URL</span><span className="input-hint">Optional · never opened</span></label>
                <input
                  id="url-input"
                  className="cyber-input"
                  type="text"
                  placeholder="https://example.com/verify"
                  value={url}
                  maxLength={2048}
                  onChange={(event) => {
                    setUrl(event.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  disabled={isLoading}
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
              <div className="quick-samples">
                <span className="samples-label">TRY AN EXAMPLE</span>
                {SAMPLE_PAYLOADS.map((sample) => (
                  <button key={sample.label} type="button" className="sample-chip" onClick={() => loadSample(sample)} disabled={isLoading}>
                    {sample.label}
                  </button>
                ))}
              </div>
              {errorMessage && <div className="error-alert" role="alert">{errorMessage}</div>}
              {historyLoad.warning && <p className="storage-warning" role="status">{historyLoad.warning}</p>}
              <div className="form-actions">
                <button type="submit" className="button-primary analyze-button" disabled={isLoading}>
                  {isLoading ? <><span className="spinner" aria-hidden="true" /> Inspecting signals...</> : <>Analyze message <span aria-hidden="true">↗</span></>}
                </button>
                <button type="button" className="button-quiet" onClick={handleClear} disabled={isLoading || (!message && !url && !result && !errorMessage)}>Clear</button>
              </div>
              <div className="sr-only" aria-live="polite" role="status">
                {isLoading ? 'Analysis in progress. Your message and URL are being analyzed.' : ''}
              </div>
            </form>

            {result && (
              <section className="analysis-result" aria-labelledby="report-title" aria-live="polite">
                <div className="result-topline"><span>INVESTIGATION REPORT</span><span>{caseReference}</span></div>
                <div className="result-summary">
                  <div className={`result-score ${getRiskClass(result.risk_level)}`}><strong>{result.risk_score}</strong><span>/ 100</span></div>
                  <div><p className="preview-kicker">RISK LEVEL</p><h3 id="report-title">{result.risk_level}</h3><p>Score is a triage rating, not a probability.</p></div>
                </div>
                <p className="result-explanation">
                  {result.risk_level === 'High' && 'The score crossed the high-risk rule threshold. Pause and verify independently; this is not proof of fraud.'}
                  {result.risk_level === 'Medium' && 'The result contains signals that merit caution. Review the evidence and verify before acting.'}
                  {result.risk_level === 'Low' && 'Few or no configured risk signals were returned. A low score does not prove this is safe.'}
                </p>
                <div className="result-block">
                  <div className="result-block-heading"><h4>Evidence & observed signals</h4><span>{result.indicators.length.toString().padStart(2, '0')}</span></div>
                  {result.indicators.length > 0 ? (
                    <ul className="evidence-list">
                      {result.indicators.map((indicator, index) => {
                        const category = getIndicatorCategory(indicator);
                        return <li key={`${indicator}-${index}`}><span>{category.tag}</span><div><strong>{indicator}</strong><p>{getIndicatorExplanation(category.type)}</p></div></li>;
                      })}
                    </ul>
                  ) : <p className="no-indicators">No indicators were returned. This does not establish that the message or URL is safe.</p>}
                </div>
                <div className="result-block recommendation">
                  <div className="result-block-heading"><h4>Recommended safety action</h4><span>↗</span></div>
                  <p>{result.recommendation}</p>
                  <ul>
                    <li>Verify unexpected requests through an official channel you already trust.</li>
                    <li>Do not share passwords, one-time codes, or payment details in response to unsolicited requests.</li>
                  </ul>
                </div>
                <div className="result-method"><span>ANALYSIS METHOD</span><strong>{analysisMethod?.label}</strong><p>{analysisMethod?.detail}</p></div>
                <div className="result-actions">
                  <button type="button" className="button-primary" onClick={downloadReport}>Download local report <span aria-hidden="true">↓</span></button>
                  <span>Generated {reportGeneratedAt?.toLocaleString()}</span>
                </div>
                <p className="result-limit">Automated analysis can be wrong or incomplete. No live URL reputation check was performed.</p>
              </section>
            )}
          </div>
        </section>

        <section className="history-section" aria-labelledby="history-title">
          <div className="history-heading">
            <div><p className="eyebrow">LOCAL CASE FILES</p><h2 id="history-title">Keep what matters.<br /><em>Clear what doesn’t.</em></h2></div>
            <p>Saved in this browser on this device only. Not synced or encrypted. Delete cases individually or clear all history.</p>
          </div>
          {!historyStorageAvailable && <p className="storage-warning" role="status">Browser storage is unavailable or full. New cases may only remain available during this visit.</p>}
          {caseHistory.length > 0 ? (
            <div className="case-history">
              <div className="history-controls">
                <label className="sr-only" htmlFor="history-search">Search saved cases</label>
                <input id="history-search" className="cyber-input" type="search" placeholder="Search case reference or submitted text" value={historySearch} onChange={(event) => setHistorySearch(event.target.value)} />
                <button className="button-quiet" type="button" onClick={() => { updateCaseHistory(() => [], true); clearActiveCase(); }}>Clear history</button>
              </div>
              {filteredCases.length ? (
                <ul className="history-list">
                  {filteredCases.map((savedCase) => (
                    <li className="history-item" key={savedCase.caseReference}>
                      <button type="button" className="history-open" aria-current={savedCase.caseReference === caseReference ? 'true' : undefined} onClick={() => openSavedCase(savedCase)}>
                        <span>{savedCase.caseReference}</span><strong className={getRiskClass(savedCase.result.risk_level)}>{savedCase.result.risk_level} · {savedCase.result.risk_score}/100</strong>
                        <small>{new Date(savedCase.generatedAt).toLocaleString()}</small>
                        <span className="history-preview">{(savedCase.message || savedCase.url || 'No input saved').slice(0, 120)}</span>
                      </button>
                      <button type="button" className="history-delete" aria-label={`Delete case ${savedCase.caseReference}`} onClick={() => deleteSavedCase(savedCase.caseReference)}>Delete</button>
                    </li>
                  ))}
                </ul>
              ) : <p className="history-empty">No saved cases match this search.</p>}
            </div>
          ) : (
            <div className="history-empty history-empty-large"><span>∅</span><p>{historyLoad.warning ? 'No valid saved cases are available.' : 'Completed investigations will appear here. Nothing is stored until an analysis finishes.'}</p>{historyLoad.warning && <button className="button-quiet" type="button" onClick={() => updateCaseHistory(() => [], true)}>Clear malformed history</button>}</div>
          )}
        </section>

        <section className="closing-section" data-reveal>
          <span className="closing-mark" aria-hidden="true">S<span>.</span></span>
          <p className="eyebrow">A MOMENT TO CHECK IS A MOMENT WELL SPENT</p>
          <h2>Trust nothing.<br /><em>Verify everything.</em></h2>
          <button type="button" className="button-primary" onClick={() => scrollToAnalyzer(lenisRef.current)}>Inspect a message <span aria-hidden="true">↑</span></button>
        </section>
      </main>

      <footer className="site-footer">
        <a className="wordmark" href="#top"><span className="wordmark-mark" aria-hidden="true"><i /><i /><i /></span><span>SCAMSHIELD<span className="wordmark-period">.</span></span></a>
        <p>Analysis can be wrong or incomplete. Signals are not proof. Verify important requests independently.</p>
        <a href="#top" className="footer-top">BACK TO TOP ↑</a>
      </footer>
    </div>
  );
}

export default App;
