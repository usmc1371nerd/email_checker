import { analyzeEmail } from "../js/analyzer.js";
import { parseEmlForAnalysis } from "../js/emlParser.js";
import { classify } from "../js/scoring.js";

const tests = [];

function test(name, fn) {
  tests.push({ name, fn });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function has(result, id) {
  return result.findings.some((finding) => finding.id === id);
}

function notHas(result, id) {
  return !has(result, id);
}

test("urgency language positive and routine deadline negative", () => {
  assert(has(analyzeEmail("Urgent action required immediately."), "urgency-language"), "detects urgency");
  assert(notHas(analyzeEmail("This is a routine deadline for training registration."), "urgency-language"), "does not flag routine deadline");
});

test("account suspension threat", () => {
  assert(has(analyzeEmail("Your account will be suspended within 24 hours."), "account-suspension-threat"), "detects suspension");
});

test("password request positive and awareness negative", () => {
  assert(has(analyzeEmail("Please reply with your password."), "password-request"), "detects direct password request");
  assert(notHas(analyzeEmail("Password awareness reminder: never share your password."), "password-request"), "does not flag education");
});

test("mfa code request", () => {
  assert(has(analyzeEmail("Send your MFA verification code to continue."), "mfa-code-request"), "detects mfa request");
});

test("financial fraud signals", () => {
  const result = analyzeEmail("Please buy gift cards and keep this confidential. Use this new account for the wire.");
  assert(has(result, "gift-card-request"), "detects gift card");
  assert(has(result, "bank-detail-change"), "detects bank change");
  assert(has(result, "secrecy-instruction"), "detects secrecy");
});

test("invoice alone remains weak but detectable", () => {
  const result = analyzeEmail("Attached invoice for your records.");
  assert(has(result, "unexpected-invoice"), "detects invoice wording");
  assert(result.score <= 15, "invoice alone stays low");
});

test("credential harvesting language", () => {
  assert(has(analyzeEmail("Click the link below to login and restore access."), "credential-harvesting-language"), "detects credential flow");
});

test("misleading displayed anchor text", () => {
  const html = '<a href="https://example.net/login">https://example.com</a>';
  assert(has(analyzeEmail(html), "misleading-link-text"), "detects mismatched href");
});

test("shorteners, IPv4, IPv6, malformed URLs, and suspicious structure", () => {
  assert(has(analyzeEmail("Open https://bit.ly/demo"), "shortened-url"), "detects shortener");
  assert(has(analyzeEmail("Open http://192.0.2.1/login"), "raw-ip-url"), "detects ipv4");
  assert(has(analyzeEmail("Open http://[2001:db8::1]/"), "raw-ip-url"), "detects ipv6");
  assert(has(analyzeEmail("Open https://secure.example.com.account-check.invalid/login"), "suspicious-url-structure"), "detects suspicious structure");
  assert(notHas(analyzeEmail("Broken hxxp://example"), "suspicious-url-structure"), "ignores malformed non-url");
});

test("pasted header parsing, folded headers, auth failures, and missing headers", () => {
  const text = `From: Sender <sender@example.com>
Reply-To: Other <other@example.net>
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=example.net;
 dkim=fail header.d=example.net; dmarc=fail
Subject: Test

Body`;
  const result = analyzeEmail(text);
  assert(has(result, "reply-to-domain-mismatch"), "detects reply-to mismatch");
  assert(has(result, "reported-spf-failure"), "detects spf failure");
  assert(has(result, "reported-dkim-failure"), "detects dkim failure");
  assert(has(result, "reported-dmarc-failure"), "detects dmarc failure");
  assert(notHas(analyzeEmail("Subject: hello\n\nNo auth headers"), "reported-dmarc-failure"), "missing headers do not add risk");
});

test("attachment references and macro requests", () => {
  const result = analyzeEmail("Open invoice.pdf.exe and enable macros. Disable antivirus if blocked.");
  assert(has(result, "suspicious-attachment-filename"), "detects double extension");
  assert(has(result, "executable-attachment-reference"), "detects executable");
  assert(has(result, "enable-macros-request"), "detects macros");
});

test("html/script injection text is inert for engine and does not inflate score", () => {
  const result = analyzeEmail('<img src="https://example.invalid/pixel"><script>throw new Error("bad")</script><svg onload="alert(1)"></svg>');
  assert(result.score >= 0, "returns predictable result");
  assert(result.score <= 100, "score bounded");
});

test("huge repeated input is bounded and deduplicated", () => {
  const result = analyzeEmail("urgent action required immediately ".repeat(20000));
  assert(result.score <= 100, "score capped");
  assert(result.findings.filter((finding) => finding.id === "urgency-language").length === 1, "deduplicated");
});

test("scoring thresholds are reproducible", () => {
  assert(classify(0).label === "No Significant Warning Signs", "0 threshold");
  assert(classify(15).label === "Some Warning Signs", "15 threshold");
  assert(classify(35).label === "Elevated Concern", "35 threshold");
  assert(classify(60).label === "High Concern", "60 threshold");
  assert(classify(80).label === "Very High Concern", "80 threshold");
  assert(analyzeEmail("Send your MFA code. Send your MFA code.").score === analyzeEmail("Send your MFA code.").score, "reproducible dedupe");
});

test("empty input behavior is predictable at engine level", () => {
  const result = analyzeEmail("");
  assert(result.score === 0, "empty input score zero");
  assert(result.findings.length === 0, "empty input no findings");
});

test("blocked account deletion email scores above zero", () => {
  const text = `----- LOADED EML HEADERS -----
Delivered-To: person@gmail.example
Return-Path: return@example.biz
Subject: We have blocked your account. Your photos and videos will be deleted on Thu, 08 Oct 2026. Renew your free subscription now!
From: Person <person@odd.example.biz>
To: person@aol.example
List-Unsubscribe: <http://odd.example.biz/LEAVE=To>

Body`;
  const result = analyzeEmail(text);
  assert(result.score >= 35, "obvious pressure email should not score zero");
  assert(has(result, "account-suspension-threat"), "detects blocked account");
  assert(has(result, "data-deletion-threat"), "detects deletion threat");
  assert(has(result, "credential-harvesting-language"), "detects renewal pressure");
  assert(has(result, "plain-http-url"), "detects plain http link");
});

test("lottery donation scam scores high enough for concern", () => {
  const eml = `Delivered-To: person@gmail.example
Return-Path: <deni.hendrawan@cimahikota.go.id>
Subject: Congratulations
To: Recipients <deni.hendrawan@cimahikota.go.id>
From: "Mavis" <deni.hendrawan@cimahikota.go.id>
Reply-To: mmavislyk@gmail.example
Content-Type: text/plain; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable

How are you doing, I am Mrs. Mavis Wanczyk, the Mega Millions jackpot winner of $758 million. I have chosen to donate a total of $3,500,000 to five randomly selected individuals. Your email was selected through a random drawing.

Please find your donation code below:

DONATION CODE: FE209387

Kindly reply with the donation code to proceed.`;
  const parsed = parseEmlForAnalysis(eml);
  const result = analyzeEmail(parsed.analysisText);
  assert(result.score >= 60, "lottery donation scam should be high concern");
  assert(has(result, "lottery-prize-winner-claim"), "detects lottery prize lure");
  assert(has(result, "unexpected-large-money-offer"), "detects large money offer");
  assert(has(result, "reply-with-code-request"), "detects reply with code");
  assert(has(result, "reply-to-domain-mismatch"), "detects reply-to mismatch");
});

test("obfuscated image-link promotion scam scores very high", () => {
  const eml = `Delivered-To: person@gmail.example
Return-Path: <promo@unrelated.example>
FrOm: |WELCOME TO |ENDURANCE| AUTO AFFILIATES <sender@getscip.example>
To: "[person@gmail.example]" <person@gmail.example@random.email.example>
CC: "[TOKEN_WITH_A_VERY_LONG_BRACKETED_VALUE_FOR_FILTER_NOISE]" <person@gmail.example@943YTHUTU8T24.email.example>
Sensitivity: confidential
Priority: urgent
Importance: high
Subject:Endurance Promo - $3OO off any NEWplan?
List-Unsubscribe: <https://magic.email.britannica.example/unsub?email=person@gmail.example>
Content-Type: multipart/alternative; boundary="b3"

<title>Unrelated news padding</title>
--b3
Content-Type: text/html; charset="UTF-8"

<center><a href="https://to-cooking44.s3.us-east-1.amazonaws.example/f40.html#gsdcl.php?32=abc"><Input type="image" src="https://to-cooking44.s3.us-east-1.amazonaws.example/photo.jpg"></a></center>
<p style="font-size: 6px; opacity: 0.1;">U-R-G-E-NT LAST CALL: $3OO OFF VEHICLE PR0TECTI0N</p>
--b3--`;
  const parsed = parseEmlForAnalysis(eml);
  const result = analyzeEmail(parsed.analysisText);
  assert(result.score >= 80, "obfuscated promo scam should be very high concern");
  assert(has(result, "hidden-or-tiny-content"), "detects hidden content");
  assert(has(result, "image-based-link"), "detects image link");
  assert(has(result, "obfuscated-promo-text"), "detects obfuscated promo");
  assert(has(result, "obfuscated-recipient-header"), "detects recipient obfuscation");
  assert(has(result, "list-unsubscribe-domain-mismatch"), "detects unsubscribe mismatch");
});

test("eml parser keeps headers and body for simple messages", () => {
  const parsed = parseEmlForAnalysis("From: sender@example.com\nSubject: Test\n\nClick https://example.invalid/login");
  assert(parsed.analysisText.includes("From: sender@example.com"), "keeps headers");
  assert(parsed.analysisText.includes("https://example.invalid/login"), "keeps body");
});

test("eml parser decodes multipart text and html", () => {
  const eml = `From: Example <sender@example.com>
Subject: Multipart
Content-Type: multipart/alternative; boundary="b1"

--b1
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: quoted-printable

Please verify your account=2E
--b1
Content-Type: text/html; charset=UTF-8

<a href="https://example.net/login">https://example.com</a>
--b1--`;
  const parsed = parseEmlForAnalysis(eml);
  assert(parsed.analysisText.includes("Please verify your account."), "decodes quoted printable");
  assert(parsed.analysisText.includes("https://example.net/login"), "keeps html href");
});

test("eml parser includes attachment filenames for text-only inference", () => {
  const eml = `From: sender@example.com
Subject: Attachment
Content-Type: multipart/mixed; boundary="b2"

--b2
Content-Type: text/plain

See attached.
--b2
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"

AA==
--b2--`;
  const parsed = parseEmlForAnalysis(eml);
  assert(parsed.analysisText.includes("invoice.pdf.exe"), "includes attachment filename");
  assert(has(analyzeEmail(parsed.analysisText), "suspicious-attachment-filename"), "filename feeds analyzer");
});

test("eml parser walks nested multipart messages", () => {
  const eml = `From: sender@example.com
Subject: Nested
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: multipart/alternative; boundary="inner"

--inner
Content-Type: text/plain

Reply with your password.
--inner--
--outer--`;
  const parsed = parseEmlForAnalysis(eml);
  assert(parsed.analysisText.includes("Reply with your password."), "extracts nested text");
  assert(has(analyzeEmail(parsed.analysisText), "password-request"), "nested text feeds analyzer");
});

async function run() {
  const output = typeof document !== "undefined" ? document.querySelector("#test-output") : null;
  const lines = [];
  let passed = 0;
  for (const item of tests) {
    try {
      await item.fn();
      passed += 1;
      lines.push(`PASS ${item.name}`);
    } catch (error) {
      lines.push(`FAIL ${item.name}: ${error.message}`);
    }
  }
  const summary = `${passed}/${tests.length} tests passed`;
  lines.push(summary);
  if (output) output.textContent = lines.join("\n");
  if (typeof console !== "undefined") console.log(lines.join("\n"));
  if (passed !== tests.length) {
    throw new Error(summary);
  }
  return summary;
}

run().catch((error) => {
  if (typeof console !== "undefined") console.error(error);
  if (typeof process !== "undefined") process.exitCode = 1;
});
