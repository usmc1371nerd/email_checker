# Security Notes

## Threat Model

The primary untrusted input is loaded or pasted email content. It may include hostile HTML, scripts, SVG, event-handler attributes, malformed URLs, misleading anchors, unusual MIME structures, unusually large text, or forged headers.

The app must preserve these properties:

- Loaded or pasted email content is not uploaded by the application.
- Loaded or pasted email content and analysis results are not saved in browser storage.
- Email-derived links are never fetched, expanded, previewed, or made clickable in results.
- Email-derived markup is never inserted into the live DOM as HTML.
- Loaded `.eml` files are read locally with the browser `FileReader` API and are not uploaded.
- Large and malformed inputs produce bounded, predictable behavior.

## Safe DOM Handling

The renderer creates elements with `document.createElement` and inserts email-derived values with `textContent` or text nodes. It does not use `innerHTML` for pasted content.

Literal HTML email is parsed inertly with `DOMParser` only to extract anchor text and `href` attributes. Parsed nodes are not attached to the live page. The Node test fallback uses bounded string extraction and does not execute markup.

## Non-Persistence

The app does not use cookies, `localStorage`, `sessionStorage`, IndexedDB, URL query parameters, analytics, or telemetry. `Clear Email` resets input, consent, errors, results, and the current in-memory display state.

Loaded `.eml` contents remain in browser memory until cleared, the page is refreshed, or the tab is closed. The visitor is responsible for choosing a redacted file and reviewing the extracted text before analysis.

## URL Safety

URL analysis is passive. The app uses string extraction and the built-in `URL` API. It does not fetch URLs, expand shorteners, probe hosts, perform DNS checks, load images from pasted HTML, or call reputation services.

Extracted URLs are displayed as inert text. The only external link in the site is the static footer navigation link to `https://cyberscoutlabs.com`.

## Header Handling

Loaded or pasted headers are treated as user-supplied text. The analyzer reports explicit SPF, DKIM, and DMARC failure strings from that text but does not independently verify authentication. Missing authentication results do not reduce or increase risk.

## Suggested Host-Side Headers

Static HTML cannot reliably enforce HTTP response headers by itself. On the hosting provider, consider:

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

Test these headers with the deployed host because some static providers have their own syntax.

## Known Limitations

- Browser extensions, compromised devices, or custom enterprise monitoring may observe page activity outside this app's control.
- The hosting provider may log ordinary requests for static site files.
- The analyzer cannot inspect attachment bytes or confirm sender identity.
- `.eml` parsing handles common text and HTML MIME parts, but may not fully decode unusual encodings, encrypted messages, or deeply nested message formats.
- The rule set is conservative and incomplete; attackers may evade it.
- False positives and false negatives are expected.
