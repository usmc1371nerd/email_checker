export const RULES = [
  {
    id: "urgency-language",
    category: "Social engineering",
    label: "Urgency language",
    points: 5,
    group: "social",
    explanation: "Attackers often add time pressure so people act before checking details.",
    action: "Pause and verify the request through a trusted channel before taking action.",
    patterns: [
      /\b(act now|immediately|urgent action|final notice|within (?:\d+|24|48) hours|expires today|limited time|renew .{0,30}now)\b/i,
      /\b(your immediate attention|respond immediately|as soon as possible|will be deleted on|will be deleted today)\b/i
    ],
    negativePatterns: [
      /\b(routine deadline|project deadline|registration deadline|deadline for feedback|scheduled maintenance)\b/i
    ]
  },
  {
    id: "urgent-priority-header",
    category: "Pasted header indicators",
    label: "Urgent or high-importance header",
    points: 5,
    group: "headers",
    explanation: "The pasted headers mark the message as urgent or high importance. This can be legitimate, but it is also used to pressure recipients.",
    action: "Do not let priority labels override normal verification steps.",
    patterns: [
      /^(priority|importance):\s*(urgent|high)\b/im,
      /^sensitivity:\s*confidential\b/im
    ]
  },
  {
    id: "account-suspension-threat",
    category: "Social engineering",
    label: "Account suspension threat",
    points: 10,
    group: "social",
    explanation: "Threats of suspension or closure are common pressure tactics.",
    action: "Open the service directly from a saved bookmark or official app instead of using email links.",
    patterns: [
      /\b(account|mailbox|profile|service|subscription).{0,40}\b(suspend(?:ed)?|disable(?:d)?|close(?:d)?|locked|blocked|terminated|deleted)\b/i,
      /\b(suspend(?:ed)?|disable(?:d)?|close(?:d)?|locked|blocked|terminated|deleted).{0,40}\b(account|mailbox|profile|service|subscription)\b/i
    ]
  },
  {
    id: "data-deletion-threat",
    category: "Social engineering",
    label: "Threat of deleted data",
    points: 15,
    group: "social",
    explanation: "Threats that photos, videos, files, or messages will be deleted are pressure tactics designed to rush a decision.",
    action: "Do not use links in the email. Check the account through the official website or app.",
    patterns: [
      /\b(photos?|videos?|files?|messages?|data|account).{0,45}\b(will be|are about to be|may be).{0,25}\b(deleted|removed|erased)\b/i,
      /\b(deleted|removed|erased).{0,45}\b(photos?|videos?|files?|messages?|data)\b/i
    ]
  },
  {
    id: "password-request",
    category: "Credentials and identity theft",
    label: "Password request",
    points: 25,
    group: "credentials",
    explanation: "Legitimate organizations should not ask you to send or reveal your password by email.",
    action: "Do not share passwords. Change passwords only from the real website or app.",
    patterns: [
      /\b(send|share|provide|reply with|confirm|submit|enter|update|verify).{0,45}\b(password|passcode|login credential|credentials)\b/i,
      /\b(password|passcode|login credential|credentials).{0,45}\b(send|share|provide|reply with|confirm|submit|enter|update|verify)\b/i
    ],
    negativePatterns: [
      /\b(password awareness|password policy|never share your password|do not share your password|password training)\b/i
    ]
  },
  {
    id: "mfa-code-request",
    category: "Credentials and identity theft",
    label: "MFA or verification-code request",
    points: 30,
    group: "credentials",
    explanation: "Requests for MFA, OTP, or verification codes can let an attacker bypass account protection.",
    action: "Never share verification codes. Enter them only when you initiated the sign-in on the real service.",
    patterns: [
      /\b(send|share|provide|reply with|confirm|submit|enter).{0,45}\b(mfa|2fa|otp|one[- ]time password|verification code|security code|authenticator code)\b/i,
      /\b(mfa|2fa|otp|one[- ]time password|verification code|security code|authenticator code).{0,45}\b(send|share|provide|reply with|confirm|submit|enter)\b/i
    ],
    negativePatterns: [
      /\b(never share|do not share|don't share|will not ask).{0,45}\b(mfa|2fa|otp|one[- ]time password|verification code|security code|authenticator code)\b/i,
      /\b(mfa|2fa|otp|one[- ]time password|verification code|security code|authenticator code).{0,45}\b(awareness|training|policy|never share|do not share|don't share)\b/i
    ]
  },
  {
    id: "gift-card-request",
    category: "Financial fraud",
    label: "Gift-card request",
    points: 20,
    group: "financial",
    explanation: "Gift-card purchases are a common payment method in impersonation scams.",
    action: "Do not buy gift cards for an email request. Confirm with the person through a known phone number.",
    patterns: [
      /\b(gift cards?|prepaid cards?|steam card|apple card|google play card).{0,60}\b(buy|purchase|send|scratch|codes?)\b/i,
      /\b(buy|purchase|send).{0,60}\b(gift cards?|prepaid cards?|steam card|apple card|google play card|codes?)\b/i
    ]
  },
  {
    id: "bank-detail-change",
    category: "Financial fraud",
    label: "Bank-detail change request",
    points: 25,
    group: "financial",
    explanation: "Invoice redirection and bank-detail changes are frequent business email compromise patterns.",
    action: "Verify payment changes using a known phone number or established finance workflow.",
    patterns: [
      /\b(change|update|replace|new).{0,35}\b(bank|banking|wire|ach|routing|payment details|remittance)\b/i,
      /\b(use this new account|redirect payment|updated wire instructions)\b/i
    ]
  },
  {
    id: "secrecy-instruction",
    category: "Financial fraud",
    label: "Secrecy instruction",
    points: 10,
    group: "financial",
    explanation: "Scammers may ask you to keep a request confidential to bypass normal checks.",
    action: "Do not bypass approval steps. Ask a trusted colleague or contact the organization directly.",
    patterns: [/\b(keep this confidential|do not tell anyone|between us|discreet|secret)\b/i]
  },
  {
    id: "unexpected-invoice",
    category: "Financial fraud",
    label: "Unexpected invoice indicator",
    points: 10,
    group: "financial",
    explanation: "Unexpected invoices can be legitimate, but combined with payment pressure they deserve extra review.",
    action: "Confirm the invoice through your normal purchasing or accounting process.",
    patterns: [/\b(unexpected invoice|overdue invoice|past due invoice|attached invoice|invoice due|payment overdue)\b/i]
  },
  {
    id: "lottery-prize-winner-claim",
    category: "Financial fraud",
    label: "Lottery, prize, or jackpot claim",
    points: 25,
    group: "financial",
    explanation: "Unexpected jackpot, lottery, prize, inheritance, or large donation claims are common advance-fee scam lures.",
    action: "Do not reply or provide information. Verify any unexpected prize through an official source you find independently.",
    patterns: [
      /\b(congratulations|congrats).{0,80}\b(winner|selected|prize|jackpot|lottery|sweepstakes|donation)\b/i,
      /\b(jackpot winner|mega millions|lottery winner|prize winner|randomly selected|random drawing|selected individuals?)\b/i
    ]
  },
  {
    id: "unexpected-large-money-offer",
    category: "Financial fraud",
    label: "Unexpected large-money offer",
    points: 20,
    group: "financial",
    explanation: "Unexpected promises of very large payments or donations are a frequent fraud pattern.",
    action: "Treat unsolicited money offers as untrusted. Do not send personal details, fees, codes, or banking information.",
    patterns: [
      /(?:\$|usd\s*)\s?\d[\d,.]{4,}\s?(?:million|m|usd|dollars)?/i,
      /\b(donate|donation|beneficiary|funds?|grant).{0,60}(?:\$|usd\s*)\s?\d[\d,.]{3,}/i
    ]
  },
  {
    id: "reply-with-code-request",
    category: "Financial fraud",
    label: "Reply-with-code instruction",
    points: 15,
    group: "financial",
    explanation: "Scam messages often ask recipients to reply with a code to continue the lure and move the conversation forward.",
    action: "Do not reply with codes or personal information. Report or delete the message.",
    patterns: [
      /\b(reply|respond).{0,40}\b(code|donation code|claim code|reference code).{0,40}\b(proceed|continue|claim|process)\b/i,
      /\b(donation code|claim code|reference code)\b/i
    ]
  },
  {
    id: "impersonation-cue",
    category: "Social engineering",
    label: "Potential impersonation",
    points: 15,
    group: "social",
    explanation: "Messages that invoke authority figures or service providers may be trying to borrow trust.",
    action: "Verify the sender through a known channel before acting.",
    patterns: [/\b(ceo|chief executive|cfo|payroll|it department|help desk|security team|bank|service provider|microsoft 365|office 365|dhl|fedex|ups|usps)\b/i]
  },
  {
    id: "credential-harvesting-language",
    category: "Credentials and identity theft",
    label: "Credential-harvesting language",
    points: 20,
    group: "credentials",
    explanation: "Language pushing you to sign in through a supplied link can indicate credential harvesting.",
    action: "Do not use the email link. Navigate independently to the official service.",
    patterns: [
      /\b(click|tap|open|visit).{0,45}\b(sign in|login|log in|verify your account|validate your account|restore access)\b/i,
      /\b(sign in|login|log in|verify your account|validate your account|restore access).{0,45}\b(link|portal|below|button)\b/i,
      /\b(renew|restore|recover|keep).{0,35}\b(account|subscription|access|storage)\b/i
    ]
  },
  {
    id: "hidden-or-tiny-content",
    category: "HTML indicators",
    label: "Hidden or tiny email content",
    points: 20,
    group: "html",
    explanation: "The email contains text styled to be very small or low visibility. Spam and scam campaigns use this to confuse filters and readers.",
    action: "Treat hidden or near-invisible content as suspicious and avoid interacting with the message.",
    patterns: [
      /\bfont-size\s*:\s*(?:[0-7](?:\.\d+)?px|0)\b/i,
      /\bopacity\s*:\s*0(?:\.\d+)?\b/i,
      /\bdisplay\s*:\s*none\b|\bvisibility\s*:\s*hidden\b/i
    ]
  },
  {
    id: "image-based-link",
    category: "HTML indicators",
    label: "Image-based linked call to action",
    points: 15,
    group: "html",
    explanation: "The email uses a linked image or image input as the main call to action. This can hide destination details from the reader.",
    action: "Do not click image buttons in unexpected messages. Visit the organization directly if needed.",
    patterns: [
      /<a\b[^>]*href=["'][^"']+["'][^>]*>[\s\S]{0,500}<(?:img|input)\b[^>]*(?:type=["']image["']|src=)/i
    ]
  },
  {
    id: "obfuscated-promo-text",
    category: "Social engineering",
    label: "Obfuscated promotional wording",
    points: 10,
    group: "social",
    explanation: "The message uses odd spelling or character substitutions in promotional wording, which is common in spam meant to evade filters.",
    action: "Be cautious with promotions that use strange spelling, spacing, or mixed-in unrelated text.",
    patterns: [
      /\$\s?\d+[oO0]{2}\b/i,
      /\b(pr0tecti0n|newplan|last call).{0,60}\b(vehicle|auto|promo|off)\b/i
    ]
  },
  {
    id: "suspicious-attachment-filename",
    category: "Attachment indicators",
    label: "Suspicious attachment filename",
    points: 15,
    group: "attachments",
    explanation: "The message mentions a filename pattern often used to disguise risky attachments.",
    action: "Do not open unexpected attachments. Ask the sender through a separate trusted channel.",
    patterns: [/\b[\w.-]+\.(?:pdf|docx?|xlsx?|jpg|png)\.(?:exe|scr|js|vbs|bat|cmd|ps1|hta|lnk|msi)\b/i]
  },
  {
    id: "executable-attachment-reference",
    category: "Attachment indicators",
    label: "Executable attachment reference",
    points: 25,
    group: "attachments",
    explanation: "The message references an executable or script attachment. This tool cannot inspect attachments.",
    action: "Do not open executable attachments from email unless your organization has verified them.",
    patterns: [/\b[\w.-]+\.(?:exe|scr|js|vbs|bat|cmd|ps1|hta|lnk|msi)\b/i]
  },
  {
    id: "enable-macros-request",
    category: "Attachment indicators",
    label: "Request to enable macros or active content",
    points: 25,
    group: "attachments",
    explanation: "Requests to enable macros, active content, or disable protections are serious warning signs.",
    action: "Do not enable macros or disable security tools because an email asks you to.",
    patterns: [/\b(enable macros|enable content|enable editing|disable antivirus|turn off antivirus|allow active content)\b/i]
  }
];

export const URL_RULES = {
  suspiciousStructure: {
    id: "suspicious-url-structure",
    category: "URL indicators",
    label: "Suspicious URL structure",
    points: 10,
    group: "urls",
    explanation: "The message contains a URL with structure commonly used to mislead readers.",
    action: "Treat the link as untrusted. Use the organization's official website or app instead."
  },
  shortener: {
    id: "shortened-url",
    category: "URL indicators",
    label: "Shortened URL",
    points: 5,
    group: "urls",
    explanation: "Shortened links hide the final destination. This tool does not expand or visit them.",
    action: "Do not open shortened links from unexpected messages."
  },
  rawIp: {
    id: "raw-ip-url",
    category: "URL indicators",
    label: "Raw-IP URL",
    points: 15,
    group: "urls",
    explanation: "A link uses an IP address instead of a normal hostname.",
    action: "Avoid opening raw-IP links unless you can independently verify why they are expected."
  },
  misleadingText: {
    id: "misleading-link-text",
    category: "URL indicators",
    label: "Misleading displayed link text",
    points: 25,
    group: "urls",
    explanation: "The visible link text appears to name a different destination than the actual href.",
    action: "Do not click the link. Navigate independently to the real service."
  },
  insecureHttp: {
    id: "plain-http-url",
    category: "URL indicators",
    label: "Plain HTTP link",
    points: 5,
    group: "urls",
    explanation: "The message contains a plain HTTP link. This is not proof of phishing, but it provides less protection than HTTPS.",
    action: "Avoid using email-supplied links. Navigate independently to the official service."
  }
};

export const HEADER_RULES = {
  replyToMismatch: {
    id: "reply-to-domain-mismatch",
    category: "Pasted header indicators",
    label: "Sender / Reply-To domain mismatch",
    points: 10,
    group: "headers",
    explanation: "The pasted headers show replies going to a different domain than the From address.",
    action: "Confirm the sender using a known address or contact method."
  },
  listUnsubscribeMismatch: {
    id: "list-unsubscribe-domain-mismatch",
    category: "Pasted header indicators",
    label: "List-Unsubscribe domain mismatch",
    points: 10,
    group: "headers",
    explanation: "The unsubscribe link points to a different domain than the visible sender domain. This can occur with mailing platforms, but it is suspicious when combined with other odd headers.",
    action: "Avoid using unsubscribe links in suspicious messages. Mark as spam instead."
  },
  returnPathMismatch: {
    id: "return-path-domain-mismatch",
    category: "Pasted header indicators",
    label: "Sender / Return-Path domain mismatch",
    points: 10,
    group: "headers",
    explanation: "The pasted headers show a From address and bounce path that do not line up. This can happen legitimately, but it is worth checking when other warning signs are present.",
    action: "Verify the sender through a known website, app, or saved contact."
  },
  recipientMismatch: {
    id: "recipient-header-mismatch",
    category: "Pasted header indicators",
    label: "Recipient header mismatch",
    points: 10,
    group: "headers",
    explanation: "The visible To address differs from the delivered mailbox in the pasted headers. Bulk mail and forwarding can explain this, but phishing often uses confusing recipient headers.",
    action: "Be cautious if the message also pressures you to act or use links."
  },
  recipientObfuscation: {
    id: "obfuscated-recipient-header",
    category: "Pasted header indicators",
    label: "Obfuscated recipient header",
    points: 15,
    group: "headers",
    explanation: "The recipient fields contain unusual domains, bracketed tokens, or very long inserted text. This is common in bulk spam and filter-evasion attempts.",
    action: "Treat confusing recipient fields as a warning sign, especially when the message asks you to click links."
  },
  spfFail: {
    id: "reported-spf-failure",
    category: "Pasted header indicators",
    label: "Reported SPF failure",
    points: 10,
    group: "headers",
    explanation: "The pasted headers report an SPF failure. This tool does not independently verify SPF.",
    action: "Treat this as a reason to verify the message through another channel."
  },
  dkimFail: {
    id: "reported-dkim-failure",
    category: "Pasted header indicators",
    label: "Reported DKIM failure",
    points: 10,
    group: "headers",
    explanation: "The pasted headers report a DKIM failure. Header text can be forged.",
    action: "Do not rely on pasted headers alone. Verify independently."
  },
  dmarcFail: {
    id: "reported-dmarc-failure",
    category: "Pasted header indicators",
    label: "Reported DMARC failure",
    points: 15,
    group: "headers",
    explanation: "The pasted headers report a DMARC failure. This is not an independent authentication check.",
    action: "Be cautious and verify the sender using trusted contact information."
  }
};

export const GROUP_CAPS = {
  social: 30,
  credentials: 60,
  financial: 55,
  urls: 55,
  attachments: 50,
  headers: 45,
  html: 35
};

export const MAX_SCORE = 100;
