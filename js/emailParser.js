const HEADER_NAMES = new Set([
  "from",
  "reply-to",
  "return-path",
  "subject",
  "to",
  "cc",
  "bcc",
  "delivered-to",
  "sender",
  "x-original-sender",
  "list-unsubscribe",
  "priority",
  "importance",
  "sensitivity",
  "received-spf",
  "authentication-results",
  "dkim-signature"
]);

export function normalizeInput(input, maxLength = 50000) {
  const text = String(input || "").replace(/\r\n?/g, "\n");
  return text.length > maxLength ? text.slice(0, maxLength) : text;
}

export function parseHeaders(input) {
  const lines = normalizeInput(input).split("\n");
  const unfolded = [];
  for (const line of lines) {
    if (/^\s/.test(line) && unfolded.length) {
      unfolded[unfolded.length - 1] += ` ${line.trim()}`;
    } else if (/^[A-Za-z0-9-]+:\s*/.test(line)) {
      unfolded.push(line.trim());
    } else if (line.trim() === "") {
      if (unfolded.length) break;
    } else if (unfolded.length) {
      break;
    }
  }

  const headers = {};
  for (const line of unfolded) {
    const index = line.indexOf(":");
    const name = line.slice(0, index).toLowerCase();
    const value = line.slice(index + 1).trim();
    if (HEADER_NAMES.has(name)) {
      headers[name] = headers[name] || [];
      headers[name].push(value);
    }
  }
  return headers;
}

export function getFirstHeader(headers, name) {
  const values = headers[name.toLowerCase()];
  return values && values.length ? values[0] : "";
}

export function extractEmailDomain(value) {
  const normalized = String(value || "").replace(/\\([@.])/g, "$1");
  const emailMatch = normalized.match(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/i);
  return emailMatch ? emailMatch[1].toLowerCase().replace(/[>\].,;]+$/g, "") : "";
}

export function extractExcerpt(text, matchIndex, matchText, radius = 44) {
  const start = Math.max(0, matchIndex - radius);
  const end = Math.min(text.length, matchIndex + matchText.length + radius);
  const excerpt = text.slice(start, end).replace(/\s+/g, " ").trim();
  const clipped = `${start > 0 ? "... " : ""}${excerpt}${end < text.length ? " ..." : ""}`;
  return clipped.length > 170 ? `${clipped.slice(0, 167)}...` : clipped;
}

export function parseHtmlAnchors(input) {
  const text = normalizeInput(input);
  if (!/<a[\s>]/i.test(text)) return [];
  if (typeof DOMParser === "undefined") return parseAnchorsFallback(text);
  const parser = new DOMParser();
  const doc = parser.parseFromString(text, "text/html");
  return Array.from(doc.querySelectorAll("a[href]")).slice(0, 80).map((anchor) => ({
    text: (anchor.textContent || "").replace(/\s+/g, " ").trim().slice(0, 240),
    href: anchor.getAttribute("href") || ""
  }));
}

function parseAnchorsFallback(text) {
  const anchors = [];
  const pattern = /<a\b[^>]*\bhref\s*=\s*(["'])(.*?)\1[^>]*>([\s\S]*?)<\/a>/gi;
  let match;
  while ((match = pattern.exec(text)) && anchors.length < 80) {
    anchors.push({
      href: match[2],
      text: match[3].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 240)
    });
  }
  return anchors;
}
