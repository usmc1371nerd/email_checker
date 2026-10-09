import { GROUP_CAPS, MAX_SCORE } from "./rules.js";

export function scoreFindings(findings) {
  const byId = new Map();
  for (const finding of findings) {
    if (!byId.has(finding.id)) byId.set(finding.id, finding);
  }

  const unique = Array.from(byId.values());
  const groupTotals = {};
  const cappedGroupTotals = {};
  for (const finding of unique) {
    groupTotals[finding.group] = (groupTotals[finding.group] || 0) + finding.points;
  }
  for (const [group, total] of Object.entries(groupTotals)) {
    cappedGroupTotals[group] = Math.min(total, GROUP_CAPS[group] || total);
  }
  const rawTotal = Object.values(cappedGroupTotals).reduce((sum, value) => sum + value, 0);
  const score = Math.min(MAX_SCORE, rawTotal);
  return {
    score,
    rawTotal,
    findings: unique,
    groupTotals,
    cappedGroupTotals,
    classification: classify(score)
  };
}

export function classify(score) {
  if (score <= 14) {
    return {
      label: "No Significant Warning Signs",
      tone: "low",
      interpretation: "No significant warning signs were detected by these checks. This does not guarantee the email is legitimate."
    };
  }
  if (score <= 34) {
    return {
      label: "Some Warning Signs",
      tone: "some",
      interpretation: "The message contains a few warning signs. Slow down and verify important requests independently."
    };
  }
  if (score <= 59) {
    return {
      label: "Elevated Concern",
      tone: "elevated",
      interpretation: "Several warning signs were detected. Avoid links or attachments until you verify the sender."
    };
  }
  if (score <= 79) {
    return {
      label: "High Concern",
      tone: "high",
      interpretation: "The message has strong warning signs often seen in phishing or fraud attempts."
    };
  }
  return {
    label: "Very High Concern",
    tone: "very-high",
    interpretation: "The message combines serious warning signs. Treat it as untrusted unless verified through established channels."
  };
}
