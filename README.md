# Cyber Scout Phishing Analyzer

A static, privacy-first educational phishing triage tool for Cyber Scout Labs.

The analyzer runs entirely in the visitor's browser. It can load a downloaded `.eml` email file, extract common headers and message text locally, and check for common warning signs in language, URLs, mentioned attachments, and pasted headers. Users can still paste redacted email text when they do not have an `.eml` file. It is not a malware scanner, sender verification system, URL reputation service, or definitive safety decision.

## Architecture

- Static HTML, CSS, and vanilla ES modules.
- No framework, backend, database, accounts, cookies, analytics, telemetry, remote fonts, CDN scripts, or network lookups.
- `.eml` files are read locally with the browser `FileReader` API; they are not uploaded.
- No use of `fetch`, XHR, WebSockets, beacons, local storage, session storage, IndexedDB, or URL query persistence.
- Email-derived content is rendered with DOM APIs and `textContent`, not unsafe HTML insertion.

## Getting Started

Because the app uses ES modules, open it through a local static server:

```sh
python3 -m http.server 8080
```

Then visit:

```text
http://localhost:8080/
```

From this directory, tests can be opened in a browser at:

```text
http://localhost:8080/tests/analyzer.test.html
```

The same test runner can also be executed with Node:

```sh
npm test
```

## Deploying to Hostinger

This is a static site. For Hostinger, publish the repository root to the subdomain's document root, commonly `public_html/<subdomain>` or the folder Hostinger assigns to that subdomain.

If using Hostinger's GitHub deployment, set the publish/output directory to the repository root:

```text
.
```

No build command is required.

## File Layout

```text
index.html
css/styles.css
js/app.js
js/analyzer.js
js/rules.js
js/scoring.js
js/emailParser.js
js/urlAnalyzer.js
js/emlParser.js
tests/analyzer.test.html
tests/testRunner.js
SECURITY.md
README.md
```

No license file is included because a license was not specified. Common options include MIT for permissive reuse, Apache-2.0 for permissive reuse with patent language, or a proprietary/all-rights-reserved notice.

## Scoring Model

The warning-sign score is a transparent, rule-based point sum. Each rule is counted at most once per analyzed email. Group totals are capped, then the final score is capped at 100.

This score reflects detected warning signs, not the probability that an email is malicious.

### Rule Weights

| Indicator | Points |
|---|---:|
| Urgency language | 5 |
| Urgent or high-importance header | 5 |
| Account suspension threat | 10 |
| Threat of deleted data | 15 |
| Password request | 25 |
| MFA / verification-code request | 30 |
| Gift-card request | 20 |
| Bank-detail change request | 25 |
| Suspicious URL structure | 10 |
| Plain HTTP link | 5 |
| Shortened URL | 5 |
| Raw-IP URL | 15 |
| Misleading link text | 25 |
| Potential impersonation | 15 |
| Hidden or tiny email content | 20 |
| Image-based linked call to action | 15 |
| Obfuscated promotional wording | 10 |
| Suspicious attachment filename | 15 |
| Executable attachment reference | 25 |
| Request to enable macros | 25 |
| Unexpected invoice indicator | 10 |
| Lottery, prize, or jackpot claim | 25 |
| Unexpected large-money offer | 20 |
| Reply-with-code instruction | 15 |
| Credential-harvesting language | 20 |
| Sender / Reply-To domain mismatch | 10 |
| List-Unsubscribe domain mismatch | 10 |
| Sender / Return-Path domain mismatch | 10 |
| Recipient header mismatch | 10 |
| Obfuscated recipient header | 15 |
| Reported SPF failure | 10 |
| Reported DKIM failure | 10 |
| Reported DMARC failure | 15 |

### Group Caps

| Group | Cap |
|---|---:|
| Social engineering | 30 |
| Credentials | 60 |
| Financial fraud | 55 |
| URL indicators | 55 |
| Attachment indicators | 50 |
| Pasted header indicators | 45 |
| HTML indicators | 35 |

### Ranges

| Score | Label |
|---:|---|
| 0-14 | No Significant Warning Signs |
| 15-34 | Some Warning Signs |
| 35-59 | Elevated Concern |
| 60-79 | High Concern |
| 80-100 | Very High Concern |

## Extension Guide

Rules live in `js/rules.js` and should include a stable `id`, category, label, explanation, point value, group, matching conditions, and recommended action. Keep rules conservative and deterministic. Avoid expressions with catastrophic backtracking risk and add both positive and negative tests for new rules.

URL handling lives in `js/urlAnalyzer.js`. It uses the built-in `URL` API where possible and does not claim accurate registrable domains because no public-suffix library is bundled.

Header parsing lives in `js/emailParser.js`. It reads common pasted header fields and folded continuations, but does not independently verify SPF, DKIM, or DMARC.

`.eml` loading lives in `js/emlParser.js`. It extracts top-level headers, decodes common text/plain and text/html MIME parts, preserves HTML anchors for passive URL inspection, and includes mentioned attachment filenames for text-only attachment indicators. It does not inspect attachment bytes.

## Privacy Model

The application analyzes loaded or pasted content in browser memory. It does not transmit submitted email contents, extracted URLs, headers, filenames, or results to Cyber Scout Labs. It does not persist pasted input, loaded file contents, or results.

Static hosting providers may still process ordinary website-access metadata, such as requests for `index.html`, CSS, and JavaScript files. That metadata is separate from the submitted email content, which this application does not upload.

## Limitations

- The tool is educational triage, not a definitive determination.
- It cannot confirm whether a URL is malicious.
- It does not expand short links, perform DNS lookups, fetch web pages, or use reputation feeds.
- It cannot inspect actual attachments.
- It only extracts common `.eml` text and HTML parts; unusual encodings or nested message formats may not be fully decoded.
- It cannot independently authenticate a sender.
- Loaded or pasted headers may be incomplete or forged.
- A zero score does not mean an email is safe.
