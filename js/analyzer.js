import { getFirstHeader, extractEmailDomain, extractExcerpt, normalizeInput, parseHeaders, parseHtmlAnchors } from "./emailParser.js";
import { analyzeUrls } from "./urlAnalyzer.js";
import { HEADER_RULES, RULES } from "./rules.js";
import { scoreFindings } from "./scoring.js";

export const MAX_INPUT_LENGTH = 120000;

export function analyzeEmail(input) {
  const text = normalizeInput(input, MAX_INPUT_LENGTH);
  const findings = [];

  for (const rule of RULES) {
    if (rule.negativePatterns?.some((pattern) => pattern.test(text))) continue;
    const match = firstPatternMatch(text, rule.patterns);
    if (match) {
      findings.push({
        id: rule.id,
        category: rule.category,
        label: rule.label,
        points: rule.points,
        group: rule.group,
        explanation: rule.explanation,
        action: rule.action,
        evidence: extractExcerpt(text, match.index || 0, match[0]),
        observation: "Matched wording in pasted content"
      });
    }
  }

  const headers = parseHeaders(text);
  findings.push(...analyzeHeaders(headers));
  findings.push(...analyzeUrls(text, parseHtmlAnchors(text)));

  const result = scoreFindings(findings);
  return {
    ...result,
    limits: [
      "This score reflects detected warning signs, not the probability that an email is malicious.",
      "Links are inspected statically. The tool does not visit, expand, preview, or reputation-check URLs.",
      "Attachments are not inspected. Attachment findings are inferred only from text that mentions filenames or macros.",
      "Pasted headers can be incomplete or forged. The tool only reports authentication results explicitly present in the pasted text."
    ],
    metadata: {
      length: text.length,
      truncated: String(input || "").length > MAX_INPUT_LENGTH,
      headerFieldsFound: Object.keys(headers).length
    }
  };
}

function firstPatternMatch(text, patterns = []) {
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    const match = pattern.exec(text);
    if (match) return match;
  }
  return null;
}

function analyzeHeaders(headers) {
  const findings = [];
  const fromDomain = extractEmailDomain(getFirstHeader(headers, "from"));
  const replyToDomain = extractEmailDomain(getFirstHeader(headers, "reply-to"));
  const returnPathDomain = extractEmailDomain(getFirstHeader(headers, "return-path"));
  const toDomain = extractEmailDomain(getFirstHeader(headers, "to"));
  const deliveredToDomain = extractEmailDomain(getFirstHeader(headers, "delivered-to"));
  const listUnsubscribeDomain = extractHeaderUrlDomain(getFirstHeader(headers, "list-unsubscribe"));
  if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
    findings.push(headerFinding(HEADER_RULES.replyToMismatch, `${fromDomain} -> ${replyToDomain}`));
  }
  if (fromDomain && listUnsubscribeDomain && !sameDomainOrSubdomain(fromDomain, listUnsubscribeDomain)) {
    findings.push(headerFinding(HEADER_RULES.listUnsubscribeMismatch, `${fromDomain} -> ${listUnsubscribeDomain}`));
  }
  if (fromDomain && returnPathDomain && !sameDomainOrSubdomain(fromDomain, returnPathDomain)) {
    findings.push(headerFinding(HEADER_RULES.returnPathMismatch, `${fromDomain} -> ${returnPathDomain}`));
  }
  if (toDomain && deliveredToDomain && toDomain !== deliveredToDomain) {
    findings.push(headerFinding(HEADER_RULES.recipientMismatch, `${toDomain} -> ${deliveredToDomain}`));
  }
  if (hasObfuscatedRecipientHeader(getFirstHeader(headers, "to")) || hasObfuscatedRecipientHeader((headers.cc || []).join(" "))) {
    findings.push(headerFinding(HEADER_RULES.recipientObfuscation, "Recipient headers contain unusual domains, long bracketed tokens, or embedded markup."));
  }

  const authText = [
    ...(headers["received-spf"] || []),
    ...(headers["authentication-results"] || [])
  ].join(" ").toLowerCase();

  if (/\bspf=(?:fail|softfail|permerror)\b/.test(authText) || /\bfail\b/.test((headers["received-spf"] || []).join(" ").toLowerCase())) {
    findings.push(headerFinding(HEADER_RULES.spfFail, "The pasted headers report SPF failure or soft failure."));
  }
  if (/\bdkim=(?:fail|permerror)\b/.test(authText)) {
    findings.push(headerFinding(HEADER_RULES.dkimFail, "The pasted headers report DKIM failure."));
  }
  if (/\bdmarc=(?:fail|permerror)\b/.test(authText)) {
    findings.push(headerFinding(HEADER_RULES.dmarcFail, "The pasted headers report DMARC failure."));
  }
  return findings;
}

function sameDomainOrSubdomain(a, b) {
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}

function extractHeaderUrlDomain(value) {
  const match = String(value || "").match(/https?:\/\/([^/\s>]+)/i);
  return match ? match[1].toLowerCase().replace(/[),.;]+$/g, "") : "";
}

function hasObfuscatedRecipientHeader(value) {
  const text = String(value || "");
  return text.length > 240 ||
    /@\w+\.email\.[a-z]{2,}/i.test(text) ||
    /@[A-Z0-9_]{12,}/i.test(text) ||
    /\[[A-Z_]{20,}\]/i.test(text) ||
    /<\s*(strong|em|br|div|span|table)\b/i.test(text);
}

function headerFinding(rule, evidence) {
  return {
    id: rule.id,
    category: rule.category,
    label: rule.label,
    points: rule.points,
    group: rule.group,
    explanation: rule.explanation,
    action: rule.action,
    evidence,
    observation: "Reported in pasted headers"
  };
}
