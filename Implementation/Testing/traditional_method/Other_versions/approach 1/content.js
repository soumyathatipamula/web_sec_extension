// content.js
// XSS patterns
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

// Wait for DOMPurify to be available
function waitForDOMPurify(callback) {
  if (typeof DOMPurify !== 'undefined') {
    callback();
  } else {
    setTimeout(() => waitForDOMPurify(callback), 50);
  }
}

function detectAndSanitizeXSS() {
  let detectedAttacks = [];
  
  // Process and sanitize elements using DOMPurify
  function processElement(element) {
    if (!element || !element.innerHTML) return;
    
    const originalContent = element.innerHTML;
    let foundAttack = false;
    
    xssPatterns.forEach(pattern => {
      if (pattern.test(originalContent)) {
        foundAttack = true;
      }
    });
    
    if (foundAttack) {
      const sanitizedContent = DOMPurify.sanitize(originalContent, {
        FORBID_TAGS: ['script'],
        FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onsubmit', 'formaction']
      });
      
      if (sanitizedContent !== originalContent) {
        element.innerHTML = sanitizedContent;
        element.style.border = "2px solid yellow";
        element.style.background = "rgba(255, 99, 71, 0.2)";
        
        detectedAttacks.push({
          type: "DOM XSS",
          effector: element.tagName,
          originalPayload: originalContent,
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
    xssPatterns.forEach(pattern => {
      if (pattern.test(value)) {
        const sanitizedValue = DOMPurify.sanitize(value, {
          ALLOWED_TAGS: [],
          ALLOWED_ATTR: []
        });
        detectedAttacks.push({
          type: "Reflected XSS",
          effector: key,
          originalPayload: value,
          sanitizedPayload: sanitizedValue,
          url: window.location.href,
          time: new Date().toLocaleString()
        });
        urlParams.set(key, sanitizedValue);
        const newUrl = `${window.location.pathname}?${urlParams.toString()}${window.location.hash}`;
        window.history.replaceState({}, document.title, newUrl);
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