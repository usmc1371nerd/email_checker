import { analyzeEmail, MAX_INPUT_LENGTH } from "./analyzer.js";
import { MAX_EML_FILE_BYTES, parseEmlForAnalysis } from "./emlParser.js";

const form = document.querySelector("#analyzer-form");
const consent = document.querySelector("#consent");
const fileInput = document.querySelector("#eml-file");
const input = document.querySelector("#email-input");
const analyzeButton = document.querySelector("#analyze-button");
const clearButton = document.querySelector("#clear-button");
const error = document.querySelector("#input-error");
const count = document.querySelector("#char-count");
const results = document.querySelector("#results");
const emptyResults = document.querySelector("#empty-results");
const status = document.querySelector("#status");

function updateControls() {
  const hasText = input.value.trim().length > 0;
  fileInput.disabled = !consent.checked;
  analyzeButton.disabled = !consent.checked || !hasText;
  count.textContent = `${input.value.length.toLocaleString()} / ${MAX_INPUT_LENGTH.toLocaleString()}`;
}

function setError(message) {
  error.textContent = message;
  input.toggleAttribute("aria-invalid", Boolean(message));
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  setError("");
  const text = input.value.trim();
  if (!consent.checked) {
    setError("Please acknowledge the privacy and safety notice before analyzing.");
    consent.focus();
    return;
  }
  if (!text) {
    setError("Paste a redacted email before running analysis.");
    input.focus();
    return;
  }
  if (input.value.length > MAX_INPUT_LENGTH) {
    setError("The email content is too long. Please shorten it to 120,000 characters or fewer.");
    input.focus();
    return;
  }
  renderResults(analyzeEmail(input.value));
});

consent.addEventListener("change", updateControls);
input.addEventListener("input", () => {
  updateControls();
  if (error.textContent) setError("");
});

clearButton.addEventListener("click", () => {
  input.value = "";
  fileInput.value = "";
  consent.checked = false;
  results.hidden = true;
  results.replaceChildren();
  emptyResults.hidden = false;
  status.textContent = "Email content, acknowledgment, and results cleared.";
  setError("");
  updateControls();
  input.focus();
});

fileInput.addEventListener("change", () => {
  setError("");
  if (!consent.checked) {
    fileInput.value = "";
    setError("Please acknowledge the privacy and safety notice before loading a file.");
    consent.focus();
    return;
  }
  const file = fileInput.files && fileInput.files[0];
  if (!file) return;
  if (file.size > MAX_EML_FILE_BYTES) {
    fileInput.value = "";
    setError("That .eml file is larger than 2 MB. Please use a smaller redacted message file.");
    return;
  }

  const reader = new FileReader();
  reader.addEventListener("load", () => {
    const parsed = parseEmlForAnalysis(reader.result || "");
    input.value = parsed.analysisText;
    results.hidden = true;
    results.replaceChildren();
    emptyResults.hidden = false;
    updateControls();
    const warningText = parsed.warnings.length ? ` ${parsed.warnings.join(" ")}` : "";
    status.textContent = `Loaded ${file.name} locally. Review the extracted text before analysis.${warningText}`;
  });
  reader.addEventListener("error", () => {
    setError("The file could not be read. Please try downloading the email again as an .eml file.");
  });
  reader.readAsText(file);
});

function renderResults(result) {
  results.replaceChildren();
  emptyResults.hidden = true;
  results.hidden = false;
  results.className = `results tone-${result.classification.tone}`;

  const summary = el("div", "score-summary");
  const score = el("div", "score-number");
  score.append(el("span", "", String(result.score)), el("small", "", "/100"));
  const text = el("div", "score-text");
  text.append(
    el("p", "result-label", result.classification.label),
    el("p", "", result.classification.interpretation),
    el("p", "score-note", "This score reflects detected warning signs, not the probability that an email is malicious.")
  );
  summary.append(score, text);
  results.append(summary);

  const next = el("section", "next-steps");
  next.append(el("h3", "", "What You Should Do Next"));
  const list = el("ul");
  [
    "Do not click suspicious links or open suspicious attachments merely to test them.",
    "Do not share passwords, security-question answers, or MFA codes.",
    "Independently access an organization's official website/app or use verified contact information, not details supplied in the suspicious email.",
    "For work-related messages, contact IT/security through established channels.",
    "If credentials were entered on a suspicious site, change them through the real service and contact the relevant provider/security team."
  ].forEach((item) => list.append(el("li", "", item)));
  next.append(list);
  results.append(next);

  const findingsTitle = el("h3", "", `${result.findings.length} Distinct Finding${result.findings.length === 1 ? "" : "s"}`);
  results.append(findingsTitle);

  if (!result.findings.length) {
    results.append(el("p", "no-findings", "No significant warning signs were detected by these checks. This does not guarantee the email is legitimate."));
  } else {
    const cards = el("div", "finding-list");
    for (const finding of result.findings) {
      const details = el("details", "finding-card");
      const summaryLine = el("summary");
      summaryLine.append(el("span", "finding-name", finding.label), el("span", "points", `+${finding.points}`));
      const body = el("div", "finding-body");
      body.append(
        metaRow("Category", finding.category),
        metaRow("Observation", finding.observation),
        metaRow("Evidence", finding.evidence || "No excerpt available"),
        metaRow("Why it matters", finding.explanation),
        metaRow("Recommended action", finding.action)
      );
      details.append(summaryLine, body);
      cards.append(details);
    }
    results.append(cards);
  }

  const limits = el("section", "limits");
  limits.append(el("h3", "", "Limits of This Check"));
  const limitsList = el("ul");
  result.limits.forEach((item) => limitsList.append(el("li", "", item)));
  if (result.metadata.truncated) limitsList.append(el("li", "", "The input was truncated to the maximum analysis length."));
  limits.append(limitsList);
  results.append(limits);
  status.textContent = `Analysis complete. ${result.classification.label}. Score ${result.score} out of 100 with ${result.findings.length} findings.`;
}

function metaRow(label, value) {
  const row = el("p", "meta-row");
  row.append(el("strong", "", `${label}: `), document.createTextNode(value));
  return row;
}

function el(tag, className = "", text = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

updateControls();
