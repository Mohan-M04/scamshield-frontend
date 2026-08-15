import type { SourceId, Verdict } from '@/types';

interface Signal {
  text: string;
  weight: number;
  category: 'urgency' | 'phishing' | 'upi' | 'impersonation' | 'reward' | 'threat' | 'personal';
}

const SIGNALS: Signal[] = [
  // Urgency / pressure
  { text: 'urgent', weight: 12, category: 'urgency' },
  { text: 'immediately', weight: 10, category: 'urgency' },
  { text: 'today', weight: 6, category: 'urgency' },
  { text: 'within', weight: 6, category: 'urgency' },
  { text: 'last day', weight: 8, category: 'urgency' },
  { text: 'final notice', weight: 10, category: 'urgency' },
  { text: 'expire', weight: 8, category: 'urgency' },
  { text: 'expired', weight: 8, category: 'urgency' },
  { text: 'block', weight: 8, category: 'urgency' },
  { text: 'blocked', weight: 8, category: 'urgency' },
  { text: 'suspend', weight: 8, category: 'urgency' },
  { text: 'disconnected', weight: 10, category: 'urgency' },
  { text: 'disconnect', weight: 10, category: 'urgency' },
  { text: 'deadline', weight: 7, category: 'urgency' },
  { text: 'last warning', weight: 10, category: 'urgency' },

  // Phishing links
  { text: 'http://', weight: 14, category: 'phishing' },
  { text: 'https://', weight: 6, category: 'phishing' },
  { text: 'bit.ly', weight: 10, category: 'phishing' },
  { text: 'tinyurl', weight: 10, category: 'phishing' },
  { text: '.xyz', weight: 12, category: 'phishing' },
  { text: '.top', weight: 10, category: 'phishing' },
  { text: '.click', weight: 10, category: 'phishing' },
  { text: '.gq', weight: 10, category: 'phishing' },
  { text: '.tk', weight: 10, category: 'phishing' },
  { text: '.ml', weight: 10, category: 'phishing' },
  { text: 'verify', weight: 8, category: 'phishing' },
  { text: 'kyc', weight: 12, category: 'phishing' },
  { text: 'update now', weight: 8, category: 'phishing' },
  { text: 'click here', weight: 8, category: 'phishing' },
  { text: 'login', weight: 6, category: 'phishing' },
  { text: 'link', weight: 4, category: 'phishing' },

  // UPI / payment traps
  { text: 'upi', weight: 10, category: 'upi' },
  { text: 'pin', weight: 12, category: 'upi' },
  { text: 'otp', weight: 12, category: 'upi' },
  { text: 'collect request', weight: 14, category: 'upi' },
  { text: 'processing fee', weight: 12, category: 'upi' },
  { text: 'cashback', weight: 10, category: 'upi' },
  { text: 'refund', weight: 6, category: 'upi' },
  { text: 'payment', weight: 6, category: 'upi' },
  { text: 'pay', weight: 4, category: 'upi' },
  { text: 'rs.', weight: 4, category: 'upi' },
  { text: '₹', weight: 4, category: 'upi' },
  { text: 'scan', weight: 6, category: 'upi' },
  { text: 'qr', weight: 8, category: 'upi' },
  { text: 'lucky draw', weight: 12, category: 'upi' },
  { text: 'won', weight: 8, category: 'upi' },
  { text: 'winner', weight: 10, category: 'upi' },
  { text: 'prize', weight: 10, category: 'upi' },
  { text: 'gift', weight: 8, category: 'upi' },
  { text: 'claim', weight: 8, category: 'upi' },

  // Impersonation
  { text: 'sbi', weight: 8, category: 'impersonation' },
  { text: 'bank', weight: 6, category: 'impersonation' },
  { text: 'customer', weight: 4, category: 'impersonation' },
  { text: 'electricity', weight: 8, category: 'impersonation' },
  { text: 'bescom', weight: 8, category: 'impersonation' },
  { text: 'police', weight: 10, category: 'impersonation' },
  { text: 'inspector', weight: 12, category: 'impersonation' },
  { text: 'cyber crime', weight: 14, category: 'impersonation' },
  { text: 'customs', weight: 10, category: 'impersonation' },
  { text: 'income tax', weight: 10, category: 'impersonation' },
  { text: 'government', weight: 6, category: 'impersonation' },
  { text: 'officer', weight: 8, category: 'impersonation' },
  { text: 'department', weight: 6, category: 'impersonation' },
  { text: 'helpline', weight: 4, category: 'impersonation' },
  { text: 'manager', weight: 6, category: 'impersonation' },

  // Threats / coercion
  { text: 'arrest', weight: 14, category: 'threat' },
  { text: 'digital arrest', weight: 16, category: 'threat' },
  { text: 'warrant', weight: 12, category: 'threat' },
  { text: 'legal action', weight: 10, category: 'threat' },
  { text: 'legal case', weight: 10, category: 'threat' },
  { text: 'court', weight: 8, category: 'threat' },
  { text: 'case against', weight: 10, category: 'threat' },
  { text: 'money laundering', weight: 12, category: 'threat' },
  { text: 'do not disconnect', weight: 12, category: 'threat' },
  { text: 'stay on the line', weight: 12, category: 'threat' },

  // Personal info harvesting
  { text: 'aadhaar', weight: 10, category: 'personal' },
  { text: 'pan', weight: 8, category: 'personal' },
  { text: 'otp', weight: 12, category: 'personal' },
  { text: 'cvv', weight: 12, category: 'personal' },
  { text: 'password', weight: 12, category: 'personal' },
  { text: 'account details', weight: 10, category: 'personal' },
  { text: 'bank details', weight: 10, category: 'personal' },
  { text: 'personal details', weight: 8, category: 'personal' },
  { text: 'share', weight: 4, category: 'personal' },
];

const SOURCE_BOOST: Record<SourceId, Partial<Record<Signal['category'], number>>> = {
  sms: { phishing: 1.3, urgency: 1.2 },
  upi: { upi: 1.4, reward: 1.3 },
  voice: { threat: 1.4, impersonation: 1.3 },
  link: { phishing: 1.5 },
};

const VERDICT_THRESHOLDS = { block: 70, verify: 35 } as const;

const ACTIONS_BY_CATEGORY: Record<Signal['category'], string[]> = {
  urgency: [
    'Do not rush. Scammers create fake deadlines to pressure you.',
    'Take a moment to verify through the official app or helpline.',
  ],
  phishing: [
    'Do not click any links in the message.',
    'Never enter your login or banking details on a page you reached from a message.',
  ],
  upi: [
    'Never enter your UPI PIN to receive money — PIN is only for sending.',
    'Do not accept UPI collect requests from unknown people.',
  ],
  reward: [
    'You did not win any lottery or cashback you did not enter. This is a common scam.',
    'Never pay a "processing fee" or "registration fee" to claim a prize.',
  ],
  threat: [
    'No real police officer demands money or details over the phone. Hang up immediately.',
    'Do not stay on the line or share any information under threat.',
  ],
  impersonation: [
    'Verify the sender through the official website or app — not the contact details in the message.',
    'Call the official helpline directly from a known, trusted number.',
  ],
  personal: [
    'Never share your OTP, PIN, Aadhaar, CVV, or passwords with anyone.',
    'No bank or government office asks for these details over a call or message.',
  ],
};

const UNIVERSAL_ACTIONS = [
  'If money or personal details were already shared, call the Cyber Crime Helpline 1930 immediately.',
];

const VERDICT_LABEL: Record<Verdict, string> = {
  block: 'Block & Alert',
  verify: 'Verify Carefully',
  safe: 'Safe',
};

export interface LocalAnalysis {
  risk_score: number;
  verdict: Verdict;
  explanation: string;
  actions: string[];
}

export function analyzeLocally(source: SourceId, rawText: string): LocalAnalysis {
  const text = rawText.toLowerCase();
  const boost = SOURCE_BOOST[source] ?? {};
  const matchedCategories = new Set<Signal['category']>();
  const hits: { signal: Signal; count: number }[] = [];

  let score = 0;

  for (const signal of SIGNALS) {
    let count = 0;
    let idx = text.indexOf(signal.text);
    while (idx !== -1) {
      count++;
      idx = text.indexOf(signal.text, idx + signal.text.length);
    }
    if (count > 0) {
      const multiplier = boost[signal.category] ?? 1;
      score += signal.weight * multiplier * Math.min(count, 3);
      matchedCategories.add(signal.category);
      hits.push({ signal, count });
    }
  }

  // Multiple categories compound — a message hitting urgency + phishing + upi is almost certainly a scam
  if (matchedCategories.size >= 3) score *= 1.15;
  if (matchedCategories.size >= 5) score *= 1.1;

  // ALL CAPS sections are a strong urgency tell
  const capsRatio = rawText.replace(/[^A-Za-z]/g, '').length > 0
    ? (rawText.match(/[A-Z]{4,}/g) ?? []).join('').length / rawText.replace(/[^A-Za-z]/g, '').length
    : 0;
  if (capsRatio > 0.25) score += 8;

  // Phone numbers with urgency are suspicious
  if (/\b\d{10}\b/.test(rawText) && matchedCategories.has('urgency')) score += 6;

  score = Math.max(0, Math.min(100, Math.round(score)));

  const verdict: Verdict =
    score >= VERDICT_THRESHOLDS.block ? 'block' : score >= VERDICT_THRESHOLDS.verify ? 'verify' : 'safe';

  // Build explanation
  const topHits = hits.sort((a, b) => b.signal.weight - a.signal.weight).slice(0, 5);
  const categoryNames: Record<Signal['category'], string> = {
    urgency: 'urgency and pressure tactics',
    phishing: 'suspicious phishing links',
    upi: 'UPI payment traps',
    reward: 'fake prize or reward bait',
    threat: 'coercion and legal threats',
    impersonation: 'impersonation of a bank, government, or authority',
    personal: 'requests for sensitive personal information',
  };

  let explanation: string;
  if (topHits.length === 0) {
    explanation =
      'No strong scam patterns were detected in this message. While it appears safe, always stay cautious — never share OTPs or UPI PINs with anyone, and verify independently if anything feels off.';
  } else {
    const detected = [...matchedCategories]
      .map((c) => categoryNames[c])
      .join(', ');
    const keywords = topHits.map((h) => `"${h.signal.text}"`).join(', ');
    explanation = `This message was flagged for ${detected}. Key indicators found: ${keywords}. The combination of these signals is typical of fraudulent messages designed to create panic or temptation so you act before thinking. Treat this message with caution and follow the checklist below.`;
  }

  // Build actions from matched categories, deduped, capped
  const actionSet = new Set<string>();
  for (const cat of matchedCategories) {
    for (const a of ACTIONS_BY_CATEGORY[cat]) actionSet.add(a);
  }
  if (matchedCategories.size === 0) {
    actionSet.add('No strong scam signals detected, but stay alert.');
    actionSet.add('Never share OTP or UPI PIN with anyone.');
  }
  for (const a of UNIVERSAL_ACTIONS) actionSet.add(a);
  let actions = [...actionSet];
  if (actions.length > 6) actions = actions.slice(0, 6);

  return {
    risk_score: score,
    verdict,
    explanation,
    actions,
  };
}

export function localVerdictLabel(v: Verdict): string {
  return VERDICT_LABEL[v];
}
