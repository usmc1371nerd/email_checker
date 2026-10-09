import { URL_RULES } from "./rules.js";

const SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "cutt.ly",
  "rebrand.ly",
  "s.id",
  "shorturl.at"
]);

const URL_PATTERN = /\b(?:https?:\/\/|www\.)[^\s<>"')]+/gi;
const IPV4_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function cleanUrl(value) {
  const raw = String(value || "").trim().replace(/[),.;!?]+$/g, "");
  return raw.endsWith("]") && !raw.includes("[") ? raw.slice(0, -1) : raw;
}

export function parseUrl(value) {
  const raw = cleanUrl(value);
  if (!raw) return null;
  try {
    return new URL(/^www\./i.test(raw) ? `https://${raw}` : raw);
  } catch {
    return null;
  }
}

export function extractPlainTextUrls(input) {
  const matches = String(input || "").match(URL_PATTERN) || [];
  return Array.from(new Set(matches.map(cleanUrl))).slice(0, 80);
}

export function hostnameLooksLikeIp(hostname) {
  const host = hostname.replace(/^\[|\]$/g, "");
  return IPV4_PATTERN.test(host) || host.includes(":");
}

function hasSuspiciousStructure(url) {
  const host = url.hostname.toLowerCase();
  const decoded = safeDecode(`${url.pathname}${url.search}`);
  return url.username !== "" ||
    url.href.includes("@") ||
    /xn--/.test(host) ||
    /%[0-9a-f]{2}/i.test(url.href) ||
    /(login|verify|secure|account|password|mfa|signin|wallet|invoice)/i.test(decoded) ||
    host.split(".").length >= 5 ||
    /(?:login|verify|secure|account|password|mfa|signin)[.-]/i.test(host);
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function displayedTextHost(text) {
  const displayUrl = parseUrl(text);
  if (displayUrl) return displayUrl.hostname.toLowerCase();
  const domainMatch = String(text || "").match(/\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/i);
  return domainMatch ? domainMatch[1].toLowerCase() : "";
}

function sameHostOrSubdomain(a, b) {
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}

export function analyzeUrls(input, anchors = []) {
  const findings = [];
  const seenRules = new Set();
  const urls = [
    ...extractPlainTextUrls(input).map((url) => ({ source: "plain text URL", url })),
    ...anchors.map((anchor) => ({ source: "HTML link href", url: anchor.href, text: anchor.text }))
  ];

  for (const item of urls) {
    const parsed = parseUrl(item.url);
    if (!parsed) continue;
    const host = parsed.hostname.toLowerCase();

    if (SHORTENERS.has(host) && !seenRules.has(URL_RULES.shortener.id)) {
      findings.push(toFinding(URL_RULES.shortener, item.url, item.source));
      seenRules.add(URL_RULES.shortener.id);
    }

    if (hostnameLooksLikeIp(host) && !seenRules.has(URL_RULES.rawIp.id)) {
      findings.push(toFinding(URL_RULES.rawIp, item.url, item.source));
      seenRules.add(URL_RULES.rawIp.id);
    }

    if (hasSuspiciousStructure(parsed) && !seenRules.has(URL_RULES.suspiciousStructure.id)) {
      findings.push(toFinding(URL_RULES.suspiciousStructure, item.url, item.source));
      seenRules.add(URL_RULES.suspiciousStructure.id);
    }

    if (parsed.protocol === "http:" && !seenRules.has(URL_RULES.insecureHttp.id)) {
      findings.push(toFinding(URL_RULES.insecureHttp, item.url, item.source));
      seenRules.add(URL_RULES.insecureHttp.id);
    }

    if (item.text && !seenRules.has(URL_RULES.misleadingText.id)) {
      const shownHost = displayedTextHost(item.text);
      if (shownHost && !sameHostOrSubdomain(shownHost, host)) {
        findings.push(toFinding(URL_RULES.misleadingText, `${item.text} -> ${item.url}`, "HTML link text and href"));
        seenRules.add(URL_RULES.misleadingText.id);
      }
    }
  }

  return findings;
}

function toFinding(rule, evidence, source) {
  return {
    id: rule.id,
    category: rule.category,
    label: rule.label,
    points: rule.points,
    group: rule.group,
    explanation: rule.explanation,
    action: rule.action,
    evidence: String(evidence || "").slice(0, 180),
    observation: source
  };
}
