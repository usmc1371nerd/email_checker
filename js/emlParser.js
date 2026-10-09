export const MAX_EML_FILE_BYTES = 2 * 1024 * 1024;

const TEXT_PART_LIMIT = 120000;

export function parseEmlForAnalysis(rawInput) {
  const raw = normalize(String(rawInput || ""));
  const top = splitHeaderBlock(raw);
  const topHeaders = parseHeaderFields(top.headers);
  const boundary = getBoundary(getHeader(topHeaders, "content-type"));
  const chunks = [
    "----- LOADED EML HEADERS -----",
    top.headers
  ];
  const warnings = [];
  const filenames = collectFilenames(topHeaders);

  const partCount = collectMimeEntity(topHeaders, top.body, chunks, filenames, 0);
  if (boundary && !partCount) warnings.push("The .eml file had a MIME boundary, but no message parts could be extracted.");
  if (shouldIncludeRawFallback(top.body, chunks)) {
    chunks.push("----- RAW EML BODY FALLBACK -----", top.body.slice(0, 50000));
  }

  const uniqueFilenames = Array.from(new Set(filenames.filter(Boolean))).slice(0, 40);
  if (uniqueFilenames.length) {
    chunks.push("----- MENTIONED ATTACHMENT FILENAMES -----", uniqueFilenames.join("\n"));
  }

  const analysisText = chunks.join("\n\n").slice(0, TEXT_PART_LIMIT);
  if (analysisText.length >= TEXT_PART_LIMIT) warnings.push("The extracted .eml text was shortened to keep analysis responsive.");

  return {
    analysisText,
    warnings,
    metadata: {
      hasMimeBoundary: Boolean(boundary),
      attachmentFilenames: uniqueFilenames.length
    }
  };
}

function shouldIncludeRawFallback(body, chunks) {
  const text = String(body || "");
  if (!text.trim()) return false;
  const alreadyHasBody = chunks.some((chunk) => /DECODED HTML PART|DECODED TEXT PART|EML BODY/.test(chunk));
  if (!alreadyHasBody) return true;
  return /<a\b|<img\b|type=["']?image|font-size\s*:|opacity\s*:|display\s*:\s*none|visibility\s*:\s*hidden/i.test(text) &&
    !chunks.join("\n").includes("RAW EML BODY FALLBACK");
}

function collectMimeEntity(headers, body, chunks, filenames, depth) {
  if (depth > 5) return 0;
  const contentType = getHeader(headers, "content-type").toLowerCase();
  const boundary = getBoundary(contentType);
  let collected = 0;

  if (boundary) {
    const parts = splitMimeParts(body, boundary).slice(0, 60);
    for (const part of parts) {
      const parsed = splitHeaderBlock(part);
      const partHeaders = parseHeaderFields(parsed.headers);
      filenames.push(...collectFilenames(partHeaders));
      collected += collectMimeEntity(partHeaders, parsed.body, chunks, filenames, depth + 1);
    }
    return collected;
  }

  const disposition = getHeader(headers, "content-disposition").toLowerCase();
  if (disposition.includes("attachment") && !contentType.startsWith("text/")) return 0;
  if (contentType && !/^text\/plain\b|^text\/html\b/i.test(contentType)) return 0;

  const decoded = decodePartBody(body, getHeader(headers, "content-transfer-encoding"));
  if (!decoded.trim()) return 0;
  if (contentType.startsWith("text/html")) {
    chunks.push("----- DECODED HTML PART -----", decoded);
    chunks.push("----- HTML TEXT CONTENT -----", htmlToText(decoded));
  } else {
    chunks.push(depth === 0 ? "----- EML BODY -----" : "----- DECODED TEXT PART -----", decoded);
  }
  return 1;
}

function normalize(value) {
  return value.replace(/\r\n?/g, "\n");
}

function splitHeaderBlock(value) {
  const match = value.match(/\n\s*\n/);
  if (!match || typeof match.index !== "number") return { headers: "", body: value };
  return {
    headers: value.slice(0, match.index).trimEnd(),
    body: value.slice(match.index + match[0].length)
  };
}

function parseHeaderFields(headerText) {
  const fields = [];
  const lines = normalize(headerText).split("\n");
  for (const line of lines) {
    if (/^\s/.test(line) && fields.length) {
      fields[fields.length - 1].value += ` ${line.trim()}`;
      continue;
    }
    const separator = line.indexOf(":");
    if (separator > 0) {
      fields.push({
        name: line.slice(0, separator).toLowerCase(),
        value: line.slice(separator + 1).trim()
      });
    }
  }
  return fields;
}

function getHeader(fields, name) {
  const found = fields.find((field) => field.name === name.toLowerCase());
  return found ? found.value : "";
}

function getBoundary(contentType) {
  const match = String(contentType || "").match(/boundary=(?:"([^"]+)"|([^;\s]+))/i);
  return match ? (match[1] || match[2]) : "";
}

function splitMimeParts(body, boundary) {
  const marker = `--${boundary}`;
  return normalize(body)
    .split(marker)
    .slice(1)
    .filter((part) => !part.trim().startsWith("--"))
    .map((part) => part.replace(/^\n/, "").trimEnd());
}

function decodePartBody(body, transferEncoding) {
  const encoding = String(transferEncoding || "").toLowerCase();
  if (encoding.includes("base64")) return decodeBase64(body);
  if (encoding.includes("quoted-printable")) return decodeQuotedPrintable(body);
  return normalize(body).trim();
}

function decodeBase64(value) {
  const cleaned = String(value || "").replace(/[^A-Za-z0-9+/=]/g, "");
  try {
    if (typeof atob === "function") return decodeUtf8Binary(atob(cleaned)).trim();
    if (typeof Buffer !== "undefined") return Buffer.from(cleaned, "base64").toString("utf8").trim();
  } catch {
    return String(value || "").trim();
  }
  return String(value || "").trim();
}

function decodeUtf8Binary(binary) {
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  if (typeof TextDecoder !== "undefined") return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  return binary;
}

function decodeQuotedPrintable(value) {
  const withoutSoftBreaks = normalize(value).replace(/=\n/g, "");
  const bytes = [];
  for (let index = 0; index < withoutSoftBreaks.length; index += 1) {
    const char = withoutSoftBreaks[index];
    if (char === "=" && /[0-9A-Fa-f]{2}/.test(withoutSoftBreaks.slice(index + 1, index + 3))) {
      bytes.push(parseInt(withoutSoftBreaks.slice(index + 1, index + 3), 16));
      index += 2;
    } else {
      bytes.push(char.charCodeAt(0));
    }
  }
  if (typeof TextDecoder !== "undefined") return new TextDecoder("utf-8", { fatal: false }).decode(Uint8Array.from(bytes)).trim();
  return String.fromCharCode(...bytes).trim();
}

function collectFilenames(fields) {
  const values = [
    getHeader(fields, "content-type"),
    getHeader(fields, "content-disposition")
  ];
  return values.flatMap((value) => {
    const names = [];
    const pattern = /(?:filename|name)\*?=(?:"([^"]+)"|([^;\s]+))/gi;
    let match;
    while ((match = pattern.exec(value))) {
      names.push(decodeRfc5987(match[1] || match[2]).replace(/^utf-8''/i, ""));
    }
    return names;
  });
}

function decodeRfc5987(value) {
  try {
    return decodeURIComponent(String(value || ""));
  } catch {
    return String(value || "");
  }
}

function htmlToText(html) {
  if (typeof DOMParser !== "undefined") {
    const doc = new DOMParser().parseFromString(html, "text/html");
    return (doc.body.textContent || "").replace(/\s+/g, " ").trim();
  }
  return String(html || "").replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}
