const { checkUrlReputation } = require('./reputation');

// Phishing urgency / coercion patterns
const COERCIVE_PATTERNS = [
  { term: 'action required', category: 'Urgency', weight: 2 },
  { term: 'immediate action', category: 'Urgency', weight: 3 },
  { term: 'account suspended', category: 'Security Threat', weight: 3 },
  { term: 'suspended temporarily', category: 'Security Threat', weight: 2 },
  { term: 'verify your identity', category: 'Credential Harvesting', weight: 2 },
  { term: 'verify your account', category: 'Credential Harvesting', weight: 2 },
  { term: 'verify identity', category: 'Credential Harvesting', weight: 2 },
  { term: 'verify account', category: 'Credential Harvesting', weight: 2 },
  { term: 'login within 24 hours', category: 'Urgency', weight: 3 },
  { term: 'unauthorized transaction', category: 'Financial Alert', weight: 2 },
  { term: 'security breach', category: 'Security Threat', weight: 2 },
  { term: 'security alert', category: 'Security Threat', weight: 1 },
  { term: 'deactivated', category: 'Security Threat', weight: 2 },
  { term: 'unpaid invoice', category: 'Financial Coercion', weight: 2 },
  { term: 'refund confirmation', category: 'Financial Coercion', weight: 1 },
  { term: 'click here to verify', category: 'Action Requirement', weight: 2 },
  { term: 'click here', category: 'Action Requirement', weight: 2 },
  { term: 'click link', category: 'Action Requirement', weight: 2 },
  { term: 'click below', category: 'Action Requirement', weight: 2 },
  { term: 'reset password', category: 'Credential Harvesting', weight: 2 },
  { term: 'log in', category: 'Action Requirement', weight: 1 },
  { term: 'login', category: 'Action Requirement', weight: 1 },
  { term: 'update account', category: 'Credential Harvesting', weight: 2 },
  { term: 'payment required', category: 'Financial Coercion', weight: 2 },
  { term: 'important notice', category: 'Urgency', weight: 1 },
  { term: 'confirm details', category: 'Credential Harvesting', weight: 2 },
  { term: 'dear customer', category: 'Generic Greeting', weight: 1 },
  { term: 'dear user', category: 'Generic Greeting', weight: 1 }
];

/**
 * Extracts URLs from a text block.
 */
function extractUrls(text) {
  if (!text || typeof text !== 'string') return [];
  
  // URL matching regex
  const urlRegex = /(https?:\/\/[^\s<>"]+|www\.[^\s<>"]+)/gi;
  const matches = text.match(urlRegex) || [];
  
  // Clean URLs (remove trailing punctuation like dots or commas)
  return [...new Set(matches.map(url => {
    let cleanUrl = url;
    if (cleanUrl.startsWith('www.')) {
      cleanUrl = 'http://' + cleanUrl;
    }
    // Remove trailing punctuation that might get caught in regex
    return cleanUrl.replace(/[.,;:)!]+$/, '');
  }))];
}

/**
 * Analyzes email text for phishing markers and checks embedded link reputation.
 */
function analyzeEmail(text) {
  if (!text || typeof text !== 'string' || text.trim() === '') {
    return {
      status: 'safe',
      score: 0,
      indicators: [],
      links: [],
      summary: 'Empty email text.'
    };
  }

  const normalizedText = text.toLowerCase();
  const indicators = [];
  let threatScore = 0;

  // Helper to construct flexible keyword matching regex (allows up to 3 words in between)
  function makeFlexibleRegex(term) {
    const words = term.split(' ');
    if (words.length <= 1) {
      return new RegExp(`\\b${term}\\b`, 'gi');
    }
    const pattern = words.map(w => `\\b${w}\\b`).join('(?:\\s+\\w+){0,3}\\s+');
    return new RegExp(pattern, 'gi');
  }

  // 1. Scan for coercive keywords
  COERCIVE_PATTERNS.forEach(pattern => {
    const regex = makeFlexibleRegex(pattern.term);
    const matches = normalizedText.match(regex);
    if (matches && matches.length > 0) {
      indicators.push({
        type: pattern.category,
        phrase: pattern.term,
        count: matches.length,
        weight: pattern.weight
      });
      threatScore += pattern.weight * matches.length;
    }
  });

  // 2. Extract and analyze links
  const extractedLinks = extractUrls(text);
  const linksAnalysis = extractedLinks.map(url => {
    const rep = checkUrlReputation(url);
    if (rep.status === 'malicious') {
      threatScore += 5; // Heavily penalize emails containing malicious URLs
    }
    return {
      url,
      status: rep.status,
      reason: rep.reason,
      details: rep.details
    };
  });

  // 3. Determine overall security state
  let status = 'safe';
  let summary = 'No indicators of phishing detected. Links appear clean.';

  const hasMaliciousLinks = linksAnalysis.some(l => l.status === 'malicious');
  
  if (hasMaliciousLinks) {
    status = 'malicious';
    summary = 'HIGH RISK: Email contains verified malicious links or lookalike domains.';
  } else if (threatScore >= 1) {
    status = 'suspicious';
    summary = 'SUSPICIOUS: Urgent/coercive language or call-to-actions detected. Verify details carefully.';
  } else {
    status = 'safe';
    summary = 'No indicators of phishing detected. Links appear clean.';
  }

  return {
    status,
    threatScore,
    indicators,
    links: linksAnalysis,
    summary
  };
}

module.exports = {
  analyzeEmail,
  extractUrls
};
