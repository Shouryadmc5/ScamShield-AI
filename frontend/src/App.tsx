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
  const behavior = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';
  document.querySelector('#analyzer')?.scrollIntoView({ behavior, block: 'start' });
}

function BrandLockup() {
  return (
    <>
      <img className="wordmark-mark" src="/scamshield-mark.svg" alt="" />
      <span className="wordmark-name">SCAMSHIELD</span>
      <span className="wordmark-ai">AI</span>
    </>
  );
}

function App() {
  const pageRef = useRef<HTMLDivElement>(null);
  const lenisRef = useRef<Lenis | null>(null);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
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
    return () => {
      lenis.off('scroll', syncScrollTrigger);
      gsap.ticker.remove(tick);
      lenis.destroy();
      lenisRef.current = null;
    };
  }, [reducedMotion]);

  useLayoutEffect(() => {
    if (reducedMotion || !pageRef.current) return undefined;
    let revertStoryMedia = () => {};
    const context = gsap.context(() => {
      gsap.utils.toArray<HTMLElement>('[data-reveal]').forEach((element) => {
        gsap.from(element, {
          y: 30,
          opacity: 0,
          duration: 0.7,
          ease: 'power3.out',
          scrollTrigger: { trigger: element, start: 'top 86%', once: true },
        });
      });
      gsap.from('.signal-note', {
        x: 16,
        opacity: 0,
        duration: 0.6,
        stagger: 0.12,
        ease: 'power2.out',
        scrollTrigger: { trigger: '.investigation-scene', start: 'top 78%', once: true },
      });
      const storyMedia = gsap.matchMedia();
      revertStoryMedia = () => storyMedia.revert();
      storyMedia.add('(min-width: 901px) and (prefers-reduced-motion: no-preference)', () => {
        const storySection = pageRef.current?.querySelector<HTMLElement>('.story-section');
        const viewport = storySection?.querySelector<HTMLElement>('.story-track-frame');
        const track = storySection?.querySelector<HTMLElement>('.story-track');
        if (!storySection || !viewport || !track) return undefined;

        storySection.classList.add('is-guided');
        const horizontalDistance = () => Math.max(0, track.scrollWidth - viewport.clientWidth);
        gsap.to(track, {
          x: () => -horizontalDistance(),
          ease: 'none',
          scrollTrigger: {
            trigger: storySection,
            pin: viewport,
            start: 'top top',
            end: () => `+=${horizontalDistance()}`,
            scrub: 0.65,
            anticipatePin: 1,
            invalidateOnRefresh: true,
          },
        });
        gsap.fromTo('.story-progress-fill', { scaleX: 0 }, {
          scaleX: 1,
          transformOrigin: 'left center',
          ease: 'none',
          scrollTrigger: {
            trigger: storySection,
            start: 'top top',
            end: () => `+=${horizontalDistance()}`,
            scrub: 0.65,
            invalidateOnRefresh: true,
          },
        });
        return () => storySection.classList.remove('is-guided');
      });
    }, pageRef);
    return () => {
      revertStoryMedia();
      context.revert();
    };
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
          <BrandLockup />
        </a>
        <nav className={`top-nav${isMenuOpen ? ' is-open' : ''}`} id="main-navigation" aria-label="Main navigation">
          <a href="#approach" onClick={() => setIsMenuOpen(false)}>Scenarios</a>
          <a href="#investigation" onClick={() => setIsMenuOpen(false)}>Investigation</a>
          <a href="#capabilities" onClick={() => setIsMenuOpen(false)}>Capabilities</a>
          <a href="#analyzer" onClick={() => setIsMenuOpen(false)}>Analyzer</a>
        </nav>
        <button
          type="button"
          className="menu-toggle"
          aria-label={isMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
          aria-expanded={isMenuOpen}
          aria-controls="main-navigation"
          onClick={() => setIsMenuOpen((isOpen) => !isOpen)}
        >
          <span /><span />
        </button>
        <button type="button" className="nav-cta" onClick={() => { setIsMenuOpen(false); scrollToAnalyzer(lenisRef.current); }}>
          Analyze a message <span aria-hidden="true">↗</span>
        </button>
      </header>

      <main id="top">
        <section className="hero hero-cinematic" aria-labelledby="hero-title">
          <div className="hero-atmosphere" aria-hidden="true" />
          <div className="hero-grain" aria-hidden="true" />
          <div className="hero-grid">
            <div className="hero-copy">
              <p className="eyebrow"><span className="eyebrow-dot" /> A MOMENT BEFORE THE CLICK</p>
              <h1 id="hero-title"><span>It looks</span><br /><em>like someone</em><br /><span>you know.</span></h1>
              <p className="hero-intro">
                A familiar name. A sudden deadline. A link that leads somewhere else. Take a closer look before you answer.
              </p>
              <div className="hero-actions">
                <button type="button" className="button-primary" onClick={() => scrollToAnalyzer(lenisRef.current)}>
                  Inspect a message <span aria-hidden="true">↓</span>
                </button>
                <a className="text-link" href="#approach">Enter the story <span aria-hidden="true">↘</span></a>
              </div>
              <div className="hero-footnote">
                <span className="status-ring" aria-hidden="true" />
                <span>URLs are inspected passively, never opened.</span>
              </div>
            </div>
            <div className="hero-visual" role="img" aria-label="A shield framed by an illustrative suspicious message">
              {!reducedMotion && (
                <Suspense fallback={<div className="scene-placeholder" aria-hidden="true" />}>
                  <HeroScene />
                </Suspense>
              )}
              {reducedMotion && (
                <div className="static-shield" aria-hidden="true">
                  <img src="/scamshield-mark.svg" alt="" />
                </div>
              )}
              <div className="hero-orbit-label">01 / THE INTERRUPTION</div>
              <div className="hero-signal-card" aria-label="Illustrative bank alert scenario">
                <div className="signal-card-top"><span className="signal-bank-mark">N</span><span>NOTICE / SAMPLE</span><span>09:41</span></div>
                <p>Unusual activity detected. Confirm your account now to avoid a temporary hold.</p>
                <div className="signal-card-url"><span>northstar-secure.example</span><i aria-hidden="true">↗</i></div>
                <small>ILLUSTRATIVE MESSAGE — NOT A LIVE ALERT</small>
              </div>
              <div className="hero-coordinate">SCAMSHIELD / FIELD NOTES 001</div>
            </div>
          </div>
          <a className="hero-scroll-cue" href="#approach"><span>SCROLL TO FOLLOW THE SIGNAL</span><i aria-hidden="true" /></a>
        </section>

        <section className="story-section" id="approach" aria-label="Three illustrative scam scenarios">
          <div className="story-track-frame">
            <div className="story-track">
              <article className="scenario-panel scenario-bank" aria-labelledby="scenario-bank-title">
                <div className="scenario-copy">
                  <p className="eyebrow"><span>01</span> THE MESSAGE THAT CAN'T WAIT</p>
                  <h2 id="scenario-bank-title">A bank alert.<br /><em>A borrowed sense of urgency.</em></h2>
                  <p>A message may use a familiar institution and a short deadline to push you into acting before you verify who sent it.</p>
                  <div className="scenario-takeaway"><span>LOOK CLOSER</span><strong>Urgency is a reason to pause—not a reason to rush.</strong></div>
                </div>
                <div className="scenario-art bank-art" aria-label="Illustrative phone message with an unverified account warning">
                  <div className="scenario-art-label">RECREATED MESSAGE / 01</div>
                  <div className="phone-shell">
                    <div className="phone-top"><span>9:41</span><span>•••</span></div>
                    <div className="message-thread-head"><span className="bank-avatar">N</span><span><strong>Northstar Bank</strong><small>Possible sender name</small></span><i>›</i></div>
                    <div className="message-bubble">
                      <p>We noticed a problem with your account. <mark>Confirm your details today</mark> or access may be paused.</p>
                      <span className="message-link">northstar-secure.example</span>
                    </div>
                    <span className="scenario-stamp">ILLUSTRATIVE</span>
                  </div>
                  <div className="art-note"><span>01</span> The displayed sender name alone does not verify identity.</div>
                </div>
              </article>

              <article className="scenario-panel scenario-email" aria-labelledby="scenario-email-title">
                <div className="scenario-copy">
                  <p className="eyebrow"><span>02</span> THE LINK THAT LOOKS CLOSE ENOUGH</p>
                  <h2 id="scenario-email-title">A familiar brand.<br /><em>An unfamiliar destination.</em></h2>
                  <p>Look past the display name. The address itself may reveal a different host, an odd subdomain, or a link that hides its destination.</p>
                  <div className="scenario-takeaway"><span>LOOK CLOSER</span><strong>Read the domain before you follow the link.</strong></div>
                </div>
                <div className="scenario-art email-art" aria-label="Illustrative phishing email with a mismatched sender and destination">
                  <div className="scenario-art-label">RECREATED EMAIL / 02</div>
                  <div className="mail-window">
                    <div className="mail-toolbar"><span /><span /><span /><i>INBOX / 01</i></div>
                    <div className="mail-content">
                      <p className="mail-subject">Your shared document is ready</p>
                      <div className="mail-sender"><span className="sender-avatar">D</span><div><strong>Drive Support</strong><small>From: notify@drive-access.review.example</small></div></div>
                      <p>A document was shared with you. Sign in to review the file and confirm access.</p>
                      <div className="mail-cta">OPEN SHARED FILE <span>↗</span></div>
                      <div className="mail-destination"><span>LINK PREVIEW</span><strong>drive-access.review.example</strong><small>Not verified by this illustration</small></div>
                    </div>
                    <span className="scenario-stamp">ILLUSTRATIVE</span>
                  </div>
                  <div className="art-note"><span>02</span> Display names and link previews are not proof of legitimacy.</div>
                </div>
              </article>

              <article className="scenario-panel scenario-payment" aria-labelledby="scenario-payment-title">
                <div className="scenario-copy">
                  <p className="eyebrow"><span>03</span> THE REQUEST THAT SHOULD STAY SECRET</p>
                  <h2 id="scenario-payment-title">A trusted voice.<br /><em>An unusual payment.</em></h2>
                  <p>Impersonation can turn familiarity into pressure. Unexpected transfers, gift cards, or secrecy deserve independent confirmation.</p>
                  <div className="scenario-takeaway"><span>LOOK CLOSER</span><strong>Verify out-of-pattern requests using a known number.</strong></div>
                </div>
                <div className="scenario-art payment-art" aria-label="Illustrative chat requesting an unusual payment">
                  <div className="scenario-art-label">RECREATED CHAT / 03</div>
                  <div className="chat-window">
                    <div className="chat-header"><span className="chat-avatar">JM</span><span><strong>Jordan M.</strong><small>Work chat · unverified</small></span><i>•••</i></div>
                    <div className="chat-day">TODAY / 10:18 AM</div>
                    <div className="chat-bubble received">Can you help me with something quickly?</div>
                    <div className="chat-bubble received">I'm tied up. <mark>Please keep this between us</mark> and pick up a few gift cards.</div>
                    <div className="chat-bubble sent">I'll call you on the number I already have.</div>
                    <div className="chat-warning"><span>!</span> Unexpected payment + secrecy = verify first.</div>
                    <span className="scenario-stamp">ILLUSTRATIVE</span>
                  </div>
                  <div className="art-note"><span>03</span> Confirm the request through a separate trusted channel.</div>
                </div>
              </article>
            </div>
            <div className="story-progress" aria-hidden="true"><span className="story-progress-fill" /></div>
            <div className="story-progress-label"><span>THREE MOMENTS TO PAUSE</span><span>01 — 03</span></div>
          </div>
        </section>

        <section className="investigation-section" id="investigation" aria-labelledby="investigation-title">
          <div className="investigation-intro" data-reveal>
            <p className="eyebrow"><span>THE SIGNAL BENEATH THE STORY</span></p>
            <h2 id="investigation-title">Take the message<br />apart. <em>Not the truth.</em></h2>
            <p>Here, one invented message is annotated to show the kinds of details worth checking. These highlights are a visual explanation—not a live scan or result.</p>
          </div>
          <div className="investigation-scene" data-reveal>
            <div className="investigation-paper">
              <div className="paper-label"><span>CASE STUDY / RECREATED</span><span>NOT A LIVE ANALYSIS</span></div>
              <p className="paper-from">From: Northstar Account Team &lt;notice@northstar-account.example&gt;</p>
              <h3>Immediate action required</h3>
              <p>Your account access has been restricted. <mark className="mark-urgency">Confirm your details today</mark> to avoid further interruption.</p>
              <div className="paper-link"><span>REVIEW ACCOUNT</span><strong>northstar-secure.example</strong><i aria-hidden="true">↗</i></div>
              <div className="paper-footer">This message is a fictional example created for the page.</div>
            </div>
            <div className="signal-notes">
              <div className="signal-note"><span className="signal-note-index">01</span><div><strong>A name can be copied</strong><p>A familiar sender label does not authenticate the sender.</p></div></div>
              <div className="signal-note"><span className="signal-note-index">02</span><div><strong>Pressure narrows attention</strong><p>A deadline can make a routine check feel urgent.</p></div></div>
              <div className="signal-note"><span className="signal-note-index">03</span><div><strong>The destination deserves a second look</strong><p>Read the visible host carefully. This example does not open or resolve it.</p></div></div>
            </div>
          </div>
          <div className="investigation-thread" aria-hidden="true"><span /></div>
        </section>

        <section className="assessment-section" aria-labelledby="assessment-title">
          <div className="assessment-copy" data-reveal>
            <p className="eyebrow"><span>FROM SIGNALS TO A CLEARER VIEW</span></p>
            <h2 id="assessment-title">A useful result<br />shows its <em>working.</em></h2>
            <p>ScamShield returns a risk level, a triage score, observed indicators, and a recommendation. Treat them as context—not proof or a guarantee.</p>
            <p className="assessment-disclaimer">Interface structure only. No score, risk level, or indicators are being generated in this illustration.</p>
          </div>
          <div className="assessment-board" data-reveal aria-label="Illustration of the fields in an analysis report, with no sample result values">
            <div className="assessment-board-head"><span>ANALYSIS OUTPUT</span><span>VALUES ONLY AFTER SUBMISSION</span></div>
            <div className="assessment-row"><span>01</span><div><small>RISK LEVEL</small><strong>Returned by the analyzer</strong></div><i>—</i></div>
            <div className="assessment-row"><span>02</span><div><small>RISK SCORE</small><strong>Returned by the analyzer · not a probability</strong></div><i>—</i></div>
            <div className="assessment-row"><span>03</span><div><small>EVIDENCE</small><strong>Indicators provided by the response</strong></div><i>—</i></div>
            <div className="assessment-row"><span>04</span><div><small>RECOMMENDATION</small><strong>Next step provided by the response</strong></div><i>—</i></div>
            <div className="assessment-foot"><span className="status-ring" /> No result is shown until you submit a message or URL.</div>
          </div>
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
          <div className="analyzer-workspace" aria-busy={isLoading}>
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
        <a className="wordmark" href="#top" aria-label="ScamShield home"><BrandLockup /></a>
        <p>Analysis can be wrong or incomplete. Signals are not proof. Verify important requests independently.</p>
        <a href="#top" className="footer-top">BACK TO TOP ↑</a>
      </footer>
    </div>
  );
}

export default App;
