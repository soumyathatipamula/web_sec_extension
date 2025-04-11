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
  // Obfuscation patterns
  /eval\s*\(/i,                          // Detects eval() usage
  /unescape\s*\(/i,                      // Detects unescape()
  /decodeURIComponent\s*\(/i,            // Detects decodeURIComponent()
  /atob\s*\(/i,                          // Detects base64 decoding
  /String\.fromCharCode\s*\(/i,          // Detects char code construction
  /&#x?[0-9a-f]+;/i,                    // Detects HTML entity encoding
  /%[0-9a-f]{2}/i,                      // Detects URL encoding
  /(?:\\x[0-9a-f]{2})|(?:\\u[0-9a-f]{4})/i, // Detects hex/unicode escapes
  /<[^>]+(\s+\w+\s*=\s*["']?.*?(prompt|alert|confirm)\(.*\).*?["']?)+[^>]*>/i, // Generalized tag with prompt/alert/confirm
  /\w+\s*=\s*["']?.*?(prompt|alert|confirm)\(.*\).*?["']?/i, //for attribute based attacks.
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
    // Decode HTML entities
    const textarea = document.createElement('textarea');
    textarea.innerHTML = decoded;
    decoded = textarea.value;

    // Decode URL encoding
    decoded = decodeURIComponent(decoded.replace(/\+/g, ' '));

    // Decode base64 if present
    if (/^[A-Za-z0-9+/=]+$/.test(decoded)) {
      decoded = atob(decoded);
    }

    // Decode hex/unicode escapes
    decoded = decoded.replace(/\\x([0-9A-Fa-f]{2})|\\u([0-9A-Fa-f]{4})/g, (_, hex, unicode) => {
      return String.fromCharCode(parseInt(hex || unicode, 16));
    });
  } catch (e) {
    console.warn("Obfuscation decoding error:", e);
  }
  return decoded;
}

function detectAndSanitizeXSS() {
  // If redirected and marker exists, clean up the URL without reloading
  (function cleanRedirectMarker() {
    const url = new URL(window.location.href);
    const params = url.searchParams;
    if (params.has("__xss_sanitized_redirect")) {
      params.delete("__xss_sanitized_redirect");
      url.search = params.toString();
      window.history.replaceState({}, document.title, url.toString());
    }
  })();

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
        // element.style.border = "2px solid yellow";
        // element.style.background = "rgba(255, 99, 71, 0.2)";
        
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
        urlParams.set("__xss_sanitized_redirect", "1"); // Trigger background redirect
        const newUrl = `${window.location.origin}${window.location.pathname}?${urlParams.toString()}${window.location.hash}`;
        window.location.replace(newUrl); // Trigger the redirect

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
      chrome.runtime.sendMessage({ 
        action: "xssDetected", 
        attacks: detectedAttacks 
      });
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
      chrome.runtime.sendMessage({ 
        action: "xssDetected", 
        attacks: detectedAttacks 
      });
    }
  });
}

try {
  detectAndSanitizeXSS();
} catch (error) {
  console.error("[XSS Protection Error]", error);
}