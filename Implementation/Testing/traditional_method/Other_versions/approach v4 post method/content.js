// content.js
// XSS patterns including obfuscation detection
const xssPatterns = [
  /<script\b[^>]*>[\s\S]*?(?:<\/script>|$)/i,
  /javascript:/i,
  /on\w+\s*=\s*["'].*?["']/i,
  /<video\b[^>]*onerror\s*=\s*["'].*?["'][^>]*>/i,
  /<form\b[^>]*formaction\s*=\s*["'].*?["'][^>]*>/i,
  /<svg\b[^>]*onload\s*=\s*["'].*?["'][^>]*>/i,
  /document\.(cookie|write|location)/i,
  /<[^>]+\s+(?:(?:onfocusin)|(?:oncontentvisibilityautostatechange)|(?:onerror)|(?:onfocus)|(?:onload))\s*=\s*(["']?)\s*alert\(1\)/i,
  /eval\s*\(/i,
  /unescape\s*\(/i,
  /decodeURIComponent\s*\(/i,
  /atob\s*\(/i,
  /String\.fromCharCode\s*\(/i,
  /&#x?[0-9a-f]+;/i,
  /%[0-9a-f]{2}/i,
  /(?:\\x[0-9a-f]{2})|(?:\\u[0-9a-f]{4})/i,
  /<[^>]+(\s+\w+\s*=\s*["']?.*?(prompt|alert|confirm)\(.*\).*?["']?)+[^>]*>/i,
  /\w+\s*=\s*["']?.*?(prompt|alert|confirm)\(.*\).*?["']?/i
];

// Wait for DOMPurify to be available
function waitForDOMPurify(callback) {
  if (typeof DOMPurify !== 'undefined') {
    callback();
  } else {
    setTimeout(() => waitForDOMPurify(callback), 50);
  }
}

// Decode common obfuscation techniques
function decodeObfuscation(content) {
  let decoded = content;
  try {
    const textarea = document.createElement('textarea');
    textarea.innerHTML = decoded;
    decoded = textarea.value;
    decoded = decodeURIComponent(decoded.replace(/\+/g, ' '));
    if (/^[A-Za-z0-9+/=]+$/.test(decoded)) {
      decoded = atob(decoded);
    }
    decoded = decoded.replace(/\\x([0-9A-Fa-f]{2})|\\u([0-9A-Fa-f]{4})/g, (_, hex, unicode) => {
      return String.fromCharCode(parseInt(hex || unicode, 16));
    });
  } catch (e) {
    console.warn("Obfuscation decoding error:", e);
  }
  return decoded;
}

// Intercept fetch requests
const originalFetch = window.fetch;
window.fetch = async function (resource, options = {}) {
  let detectedAttacks = [];
  if (options.method === "POST" && options.body) {
    let body = options.body;
    if (typeof body === "string") {
      const decodedBody = decodeObfuscation(body);
      if (xssPatterns.some(pattern => pattern.test(decodedBody))) {
        const sanitizedBody = DOMPurify.sanitize(decodedBody, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
        detectedAttacks.push({
          type: "POST XSS (Fetch)",
          effector: "fetch body",
          originalPayload: body,
          decodedPayload: decodedBody,
          sanitizedPayload: sanitizedBody,
          url: resource,
          time: new Date().toLocaleString()
        });
        options.body = sanitizedBody;
      }
    } else if (body instanceof FormData) {
      const newFormData = new FormData();
      for (let [key, value] of body.entries()) {
        const decodedValue = decodeObfuscation(value);
        if (xssPatterns.some(pattern => pattern.test(decodedValue))) {
          const sanitizedValue = DOMPurify.sanitize(decodedValue, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
          detectedAttacks.push({
            type: "POST XSS (Fetch FormData)",
            effector: key,
            originalPayload: value,
            decodedPayload: decodedValue,
            sanitizedPayload: sanitizedValue,
            url: resource,
            time: new Date().toLocaleString()
          });
          newFormData.append(key, sanitizedValue);
        } else {
          newFormData.append(key, value);
        }
      }
      options.body = newFormData;
    }
  }

  if (detectedAttacks.length > 0) {
    browser.runtime.sendMessage({ action: "xssDetected", attacks: detectedAttacks });
  }
  return originalFetch(resource, options);
};

// Intercept XMLHttpRequest
const originalOpen = XMLHttpRequest.prototype.open;
const originalSend = XMLHttpRequest.prototype.send;

XMLHttpRequest.prototype.open = function (method, url, ...args) {
  this._method = method;
  this._url = url;
  return originalOpen.call(this, method, url, ...args);
};

XMLHttpRequest.prototype.send = function (body) {
  let detectedAttacks = [];
  if (this._method === "POST" && body) {
    const decodedBody = decodeObfuscation(body);
    if (xssPatterns.some(pattern => pattern.test(decodedBody))) {
      const sanitizedBody = DOMPurify.sanitize(decodedBody, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
      detectedAttacks.push({
        type: "POST XSS (XHR)",
        effector: "xhr body",
        originalPayload: body,
        decodedPayload: decodedBody,
        sanitizedPayload: sanitizedBody,
        url: this._url,
        time: new Date().toLocaleString()
      });
      body = sanitizedBody;
    }
  }

  if (detectedAttacks.length > 0) {
    browser.runtime.sendMessage({ action: "xssDetected", attacks: detectedAttacks });
  }
  return originalSend.call(this, body);
};

function detectAndSanitizeXSS() {
  let detectedAttacks = [];

  // Process and sanitize elements using DOMPurify
  function processElement(element) {
    if (!element || !element.innerHTML) return;

    const originalContent = element.innerHTML;
    let decodedContent = decodeObfuscation(originalContent);
    let foundAttack = false;

    xssPatterns.forEach(pattern => {
      if (pattern.test(originalContent) || pattern.test(decodedContent)) {
        foundAttack = true;
      }
    });

    if (foundAttack) {
      const sanitizedContent = DOMPurify.sanitize(decodedContent, {
        FORBID_TAGS: ['script'],
        FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onsubmit', 'formaction']
      });

      if (sanitizedContent !== originalContent) {
        element.innerHTML = sanitizedContent;
        detectedAttacks.push({
          type: "DOM XSS (Obfuscated)",
          effector: element.tagName,
          originalPayload: originalContent,
          decodedPayload: decodedContent,
          sanitizedPayload: sanitizedContent,
          url: window.location.href,
          time: new Date().toLocaleString()
        });
      }
    }
  }

  // Scan and sanitize URL parameters
  let urlParams = new URLSearchParams(window.location.search);
  urlParams.forEach((value, key) => {
    const decodedValue = decodeObfuscation(value);
    xssPatterns.forEach(pattern => {
      if (pattern.test(value) || pattern.test(decodedValue)) {
        const sanitizedValue = DOMPurify.sanitize(decodedValue, {
          ALLOWED_TAGS: [],
          ALLOWED_ATTR: []
        });
        detectedAttacks.push({
          type: "Reflected XSS (Obfuscated)",
          effector: key,
          originalPayload: value,
          decodedPayload: decodedValue,
          sanitizedPayload: sanitizedValue,
          url: window.location.href,
          time: new Date().toLocaleString()
        });
        urlParams.set(key, sanitizedValue);
        const newUrl = `${window.location.origin}${window.location.pathname}?${urlParams.toString()}${window.location.hash}`;
        window.location.replace(newUrl);
      }
    });
  });

  // Initial DOM scan
  function initialScan() {
    if (!document.body) return;
    document.body.querySelectorAll("*").forEach(processElement);
  }

  // Setup MutationObserver
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (mutation.type === 'childList') {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            processElement(node);
            node.querySelectorAll("*").forEach(processElement);
          }
        });
      }
    });

    if (detectedAttacks.length > 0) {
      browser.runtime.sendMessage({ action: "xssDetected", attacks: detectedAttacks });
      detectedAttacks = [];
    }
  });

  // Initialize when DOM and DOMPurify are ready
  function initialize() {
    if (!document.body) {
      setTimeout(initialize, 50);
      return;
    }

    initialScan();
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  waitForDOMPurify(() => {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initialize);
    } else {
      initialize();
    }

    if (detectedAttacks.length > 0) {
      browser.runtime.sendMessage({ action: "xssDetected", attacks: detectedAttacks });
    }
  });
}

try {
  detectAndSanitizeXSS();
} catch (error) {
  console.error("[XSS Protection Error]", error);
}