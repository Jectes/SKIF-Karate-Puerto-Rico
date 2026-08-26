(function attachAuthSecurity(root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.SKIFAuthSecurity = Object.freeze(api);
}(typeof window !== 'undefined' ? window : globalThis, function buildAuthSecurity() {
  'use strict';

  const COMMON_PASSWORDS = new Set([
    'password', 'password1', 'password123', '123456789', '1234567890',
    'qwerty', 'qwerty123', 'letmein', 'welcome', 'welcome1', 'admin',
    'administrator', 'iloveyou', 'monkey', 'dragon', 'football', 'baseball',
    'abc123', 'trustno1', 'changeme', 'secret', 'sunshine', 'princess',
    'karate', 'karate123', 'shotokan', 'shotokan123', 'skif', 'skif123',
  ]);

  const SEQUENCE_SOURCES = [
    '0123456789',
    'abcdefghijklmnopqrstuvwxyz',
    'qwertyuiop',
    'asdfghjkl',
    'zxcvbnm',
  ];

  function clampInteger(value, fallback, minimum, maximum) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(maximum, Math.max(minimum, parsed));
  }

  function normalizeNfc(value) {
    const text = String(value ?? '');
    try {
      return text.normalize('NFC');
    } catch {
      return text;
    }
  }

  function codePointLength(value) {
    return Array.from(normalizeNfc(value)).length;
  }

  function getPolicy(config = {}) {
    const minimumLength = clampInteger(config.passwordMinimumLength, 15, 12, 128);
    const maximumLength = clampInteger(
      config.passwordMaximumLength,
      128,
      Math.max(64, minimumLength),
      256,
    );
    return Object.freeze({
      minimumLength,
      maximumLength,
      requireUppercase: config.passwordRequireUppercase !== false,
      requireLowercase: config.passwordRequireLowercase !== false,
      requireNumber: config.passwordRequireNumber !== false,
      requireSymbol: config.passwordRequireSymbol !== false,
      rejectTripleRepeats: config.passwordRejectTripleRepeats !== false,
      rejectSequences: config.passwordRejectSequences !== false,
      rejectPersonalInfo: config.passwordRejectPersonalInfo !== false,
      rejectCommonPasswords: config.passwordRejectCommonPasswords !== false,
    });
  }

  function containsSequence(value, runLength = 4) {
    const text = normalizeNfc(value).toLowerCase();
    for (const source of SEQUENCE_SOURCES) {
      const reversed = Array.from(source).reverse().join('');
      for (let index = 0; index <= source.length - runLength; index += 1) {
        if (text.includes(source.slice(index, index + runLength))) return true;
        if (text.includes(reversed.slice(index, index + runLength))) return true;
      }
    }
    return false;
  }

  function contextTokens(context = {}) {
    const emailLocal = String(context.email || '').split('@')[0];
    const combined = `${emailLocal} ${String(context.fullName || '')}`.toLowerCase();
    return combined
      .split(/[^\p{L}\p{N}]+/u)
      .map((token) => token.trim())
      .filter((token) => Array.from(token).length >= 4);
  }

  function isCommonOrContextPassword(value) {
    const compact = normalizeNfc(value).toLowerCase().replace(/\s+/g, '');
    if (COMMON_PASSWORDS.has(compact)) return true;
    return /^(password|welcome|letmein|admin|qwerty|karate|shotokan|skif)[!@#$%^&*()_+\-=.[\]{};:'"|<>?,/`~0-9]*$/i.test(compact);
  }

  function evaluatePassword(value, context = {}, config = {}) {
    const policy = getPolicy(config);
    const password = normalizeNfc(value);
    const length = codePointLength(password);
    const lower = password.toLowerCase();
    const personalTokens = contextTokens(context);

    const ruleResults = {
      length: length >= policy.minimumLength && length <= policy.maximumLength,
      uppercase: !policy.requireUppercase || /\p{Lu}/u.test(password),
      lowercase: !policy.requireLowercase || /\p{Ll}/u.test(password),
      number: !policy.requireNumber || /\p{N}/u.test(password),
      symbol: !policy.requireSymbol || /[^\p{L}\p{N}\s]/u.test(password),
      repeats: !policy.rejectTripleRepeats || !/(.)\1\1/u.test(password),
      sequences: !policy.rejectSequences || !containsSequence(password),
      personal: !policy.rejectPersonalInfo || !personalTokens.some((token) => lower.includes(token)),
      common: !policy.rejectCommonPasswords || !isCommonOrContextPassword(password),
    };

    const rules = [
      { key: 'length', label: `${policy.minimumLength}–${policy.maximumLength} characters`, met: ruleResults.length },
      { key: 'uppercase', label: 'At least one uppercase letter', met: ruleResults.uppercase },
      { key: 'lowercase', label: 'At least one lowercase letter', met: ruleResults.lowercase },
      { key: 'number', label: 'At least one number', met: ruleResults.number },
      { key: 'symbol', label: 'At least one special character', met: ruleResults.symbol },
      { key: 'repeats', label: 'No three identical characters in a row', met: ruleResults.repeats },
      { key: 'sequences', label: 'No obvious four-character sequence', met: ruleResults.sequences },
      { key: 'personal', label: 'Does not contain your name or email name', met: ruleResults.personal },
      { key: 'common', label: 'Not a common or dojo-themed password', met: ruleResults.common },
    ];

    const requiredKeys = Object.keys(ruleResults);
    const valid = requiredKeys.every((key) => ruleResults[key]);
    const diversity = [
      /\p{Lu}/u.test(password),
      /\p{Ll}/u.test(password),
      /\p{N}/u.test(password),
      /[^\p{L}\p{N}\s]/u.test(password),
    ].filter(Boolean).length;

    let score = 0;
    if (length > 0) score = 1;
    if (length >= 12 && diversity >= 2) score = 2;
    if (length >= policy.minimumLength && diversity >= 3 && ruleResults.repeats && ruleResults.sequences) score = 3;
    if (valid) score = 4;

    const labels = ['Not entered', 'Weak', 'Fair', 'Strong', 'Excellent'];
    return Object.freeze({
      password,
      valid,
      score,
      label: labels[score],
      rules,
      policy,
      firstFailure: rules.find((rule) => !rule.met)?.label || '',
    });
  }

  function normalizeEmail(value) {
    return String(value ?? '').trim().toLowerCase().slice(0, 254);
  }

  function normalizeDisplayName(value) {
    return normalizeNfc(value)
      .replace(/[\u0000-\u001F\u007F]/g, '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 120);
  }

  function isValidEmail(value) {
    const email = normalizeEmail(value);
    return email.length >= 3 && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  return {
    codePointLength,
    containsSequence,
    evaluatePassword,
    getPolicy,
    isValidEmail,
    normalizeDisplayName,
    normalizeEmail,
    normalizeNfc,
  };
}));
