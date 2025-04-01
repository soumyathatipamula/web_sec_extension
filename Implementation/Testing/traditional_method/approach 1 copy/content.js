// content.js
const xssPatterns = [
  /<script\b[^>]*>[\s\S]*?(?:<\/script>|$)/i,
  /javascript:/i,
  /on\w+\s*=\s*["'].*?["']/i,
  /<video\b[^>]*onerror\s*=\s*["'].*?["'][^>]*>/i,
  /<form\b[^>]*formaction\s*=\s*["'].*?["'][^>]*>/i,
  /<svg\b[^>]*onload\s*=\s*["'].*?["'][^>]*>/i,
  /document\.(cookie|write|location)/i,
  /<[^>]+\s+(?:(?:onfocusin)|(?:oncontentvisibilityautostatechange)|(?:onerror)|(?:onfocus)|(?:onload))\s*=\s*(["']?)\s*alert\(1\)/i,
];

const allowList = [
  'google.com',
  'www.google.com',
];

function isAllowedDomain() {
  const hostname = window.location.hostname;
  return allowList.some(domain => hostname === domain || hostname.endsWith('.' + domain));
}

function waitForDOMPurify(callback) {
  if (typeof DOMPurify !== 'undefined') {
    callback();
  } else {
    setTimeout(() => waitForDOMPurify(callback), 50);
  }
}

function detectAndSanitizeXSS() {
  if (isAllowedDomain()) {
    console.log("[XSS Protection] Skipping allowed domain:", window.location.hostname);
    return;
  }

  let detectedAttacks = [];

  const sanitizeConfig = {
    ALLOWED_TAGS: ['div', 'span', 'p', 'a', 'b', 'i', 'u', 'strong', 'em', 'img', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href', 'title', 'style', 'src', 'alt'],
    FORBID_TAGS: ['script', 'iframe', 'object', 'embed', 'form'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onsubmit', 'formaction', 'javascript'],
    ADD_ATTR: ['target'],
    WHOLE_DOCUMENT: true, // Sanitize entire document
    RETURN_DOM_FRAGMENT: false,
    SANITIZE_DOM: true
  };

  // Sanitize and process DOM content
  function processElement(element) {
    if (!element || !element.innerHTML) return;
    
    const originalContent = element.innerHTML;
    let foundAttack = false;
    
    xssPatterns.forEach(pattern => {
      if (pattern.test(originalContent)) {
        foundAttack = true;
      }
    });
    
    const sanitizedContent = DOMPurify.sanitize(originalContent, sanitizeConfig);
    if (sanitizedContent !== originalContent) {
      element.innerHTML = sanitizedContent;
      if (foundAttack) {
        element.style.border = "2px solid yellow";
        element.style.background = "rgba(255, 99, 71, 0.2)";
        
        detectedAttacks.push({
          type: "DOM XSS",
          effector: element.tagName,
          originalPayload: originalContent.substring(0, 200),
          sanitizedPayload: sanitizedContent.substring(0, 200),
          url: window.location.href,
          time: new Date().toLocaleString()
        });
      }
    }
  }

  // Sanitize URL parameters
  let urlParams = new URLSearchParams(window.location.search);
  urlParams.forEach((value, key) => {
    let foundAttack = false;
    xssPatterns.forEach(pattern => {
      if (pattern.test(value)) {
        foundAttack = true;
      }
    });
    
    const sanitizedValue = DOMPurify.sanitize(value, {
      ALLOWED_TAGS: [],
      ALLOWED_ATTR: [],
      RETURN_TRUSTED_TYPE: false
    });
    
    if (sanitizedValue !== value) {
      urlParams.set(key, sanitizedValue);
      const newUrl = `${window.location.pathname}?${urlParams.toString()}${window.location.hash}`;
      window.history.replaceState({}, document.title, newUrl);
      
      if (foundAttack) {
        detectedAttacks.push({
          type: "Reflected XSS",
          effector: key,
          originalPayload: value,
          sanitizedPayload: sanitizedValue,
          url: window.location.href,
          time: new Date().toLocaleString()
        });
      }
    }
  });

  // Override document.write to sanitize content before writing
  const originalDocumentWrite = document.write;
  document.write = function(content) {
    const sanitized = DOMPurify.sanitize(content, sanitizeConfig);
    if (sanitized !== content) {
      detectedAttacks.push({
        type: "Document Write XSS",
        effector: "document.write",
        originalPayload: content.substring(0, 200),
        sanitizedPayload: sanitized.substring(0, 200),
        url: window.location.href,
        time: new Date().toLocaleString()
      });
    }
    originalDocumentWrite.call(document, sanitized);
  };

  // Initial sanitization of entire document
  function sanitizeDocument() {
    if (!document.documentElement) return;
    const originalHTML = document.documentElement.innerHTML;
    const sanitizedHTML = DOMPurify.sanitize(originalHTML, sanitizeConfig);
    
    if (sanitizedHTML !== originalHTML) {
      document.documentElement.innerHTML = sanitizedHTML;
      let foundAttack = false;
      xssPatterns.forEach(pattern => {
        if (pattern.test(originalHTML)) {
          foundAttack = true;
        }
      });
      
      if (foundAttack) {
        detectedAttacks.push({
          type: "Full Document XSS",
          effector: "document",
          originalPayload: originalHTML.substring(0, 200),
          sanitizedPayload: sanitizedHTML.substring(0, 200),
          url: window.location.href,
          time: new Date().toLocaleString()
        });
      }
    }
  }

  // Setup MutationObserver for dynamic content
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

  function initialize() {
    if (!document.documentElement) {
      setTimeout(initialize, 50);
      return;
    }
    
    sanitizeDocument();
    observer.observe(document.documentElement, {
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