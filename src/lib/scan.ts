import type { ScanResponse, ScanResult, SourceId, Verdict } from '@/types';
import { analyzeLocally } from './localAnalysis';

const SCAN_URL = 'https://scamshield-uv8u.onrender.com/scan';
const USER_ID = 'user_123';
const BACKEND_TIMEOUT_MS = 4000;

const PREFIX_MAP: Record<SourceId, string> = {
  sms: '[SMS]',
  upi: '[UPI]',
  voice: '[CALL]',
  link: '[LINK]',
};

function normalizeVerdict(value: string | undefined): Verdict {
  const v = (value ?? '').toLowerCase();
  if (v.includes('block') || v.includes('alert') || v.includes('high') || v.includes('danger') || v.includes('scam')) {
    return 'block';
  }
  if (v.includes('verify') || v.includes('caution') || v.includes('amber') || v.includes('medium') || v.includes('warn')) {
    return 'verify';
  }
  if (v.includes('safe') || v.includes('low') || v.includes('clean') || v.includes('legit')) {
    return 'safe';
  }
  return 'verify';
}

function deriveVerdictFromScore(score: number): Verdict {
  if (score >= 70) return 'block';
  if (score >= 35) return 'verify';
  return 'safe';
}

function extractActions(res: ScanResponse): string[] {
  if (Array.isArray(res.actions) && res.actions.length > 0) {
    return res.actions;
  }
  if (Array.isArray(res.recommendations) && res.recommendations.length > 0) {
    return res.recommendations;
  }
  if (res.recommendation) {
    return [res.recommendation];
  }
  return [];
}

const FALLBACK_ACTIONS: Record<Verdict, string[]> = {
  block: [
    'Do not click any links in the message.',
    'Never enter your UPI PIN or OTP for this request.',
    'Block the sender and report as spam.',
    'Call the Cyber Crime Helpline 1930 immediately.',
  ],
  verify: [
    'Do not share any OTP, PIN, or personal details yet.',
    'Verify the sender through the official app or helpline.',
    'Do not click links or accept UPI collect requests from unknown numbers.',
    'If in doubt, call 1930 before taking any action.',
  ],
  safe: [
    'No strong scam signals detected, but stay alert.',
    'Never share OTP or UPI PIN with anyone.',
    'If anything feels off, call 1930 to confirm.',
  ],
};

async function fetchFromBackend(
  source: SourceId,
  text: string,
  timeoutMs: number,
): Promise<ScanResult> {
  const prefix = PREFIX_MAP[source] ?? '[SMS]';
  const body = JSON.stringify({ user_id: USER_ID, text: `${prefix} ${text}` });

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  let res: ScanResponse;
  try {
    const resp = await fetch(SCAN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!resp.ok) {
      throw new Error(`Server returned ${resp.status}`);
    }
    res = (await resp.json()) as ScanResponse;
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }

  const score = res.risk_score ?? res.risk ?? res.score ?? 0;
  const verdict = res.verdict ? normalizeVerdict(res.verdict) : deriveVerdictFromScore(score);
  const explanation =
    res.explanation ?? res.details ?? res.message ?? res.warning ?? '';

  let actions = extractActions(res);
  if (actions.length === 0) {
    actions = FALLBACK_ACTIONS[verdict];
  }

  return {
    risk_score: Math.max(0, Math.min(100, Math.round(score))),
    verdict,
    explanation,
    actions,
  };
}

export async function scanMessage(source: SourceId, text: string): Promise<ScanResult> {
  try {
    return await fetchFromBackend(source, text, BACKEND_TIMEOUT_MS);
  } catch (err) {
    // Backend sleeping, slow, or unreachable — fall back to local heuristics
    const local = analyzeLocally(source, text);

    let reason = 'The cloud scanner was unavailable';
    if (err instanceof DOMException && err.name === 'AbortError') {
      reason = 'The cloud scanner took too long to respond';
    }

    local.explanation =
      `${reason}, so ScamShield analysed this message on-device using threat heuristics. ` +
      local.explanation;

    return { ...local, local_analysis: true };
  }
}

export function verdictLabel(v: Verdict): string {
  switch (v) {
    case 'block':
      return 'Block & Alert';
    case 'verify':
      return 'Verify Carefully';
    case 'safe':
      return 'Safe';
  }
}
