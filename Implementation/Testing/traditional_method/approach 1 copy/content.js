// content.js

// New async function to check XSS via API
async function checkXSS(text) {
  try {
    let response = await fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text })
    });
    let result = await response.json();
    return result.malicious;
  } catch (error) {
    console.error("[XSS API Check Error]", error);
    return false; // Default to false if API fails
  }
}

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
  
  // Process and sanitize elements using DOMPurify and API check
  async function processElement(element) {
    if (!element || !element.innerHTML) return;
    
    const originalContent = element.innerHTML;
    const isMalicious = await checkXSS(originalContent);
    
    if (isMalicious) {
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
          time: new Date().toLocaleString(),
          detectionMethod: "API"
        });
      }
    }
  }

  // Scan and sanitize URL parameters with API check
  async function scanURLParams() {
    let urlParams = new URLSearchParams(window.location.search);
    for (let [key, value] of urlParams) {
      const isMalicious = await checkXSS(value);
      
      if (isMalicious) {
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
          time: new Date().toLocaleString(),
          detectionMethod: "API"
        });
        urlParams.set(key, sanitizedValue);
        const newUrl = `${window.location.pathname}?${urlParams.toString()}${window.location.hash}`;
        window.history.replaceState({}, document.title, newUrl);
      }
    }
  }

  // Initial scan for DOM and URL parameters
  async function initialScan() {
    if (!document.body) return;

    // Scan DOM elements
    const elements = document.body.querySelectorAll("*");
    for (let element of elements) {
      await processElement(element);
    }

    // Scan URL parameters
    await scanURLParams();

    // Send detected attacks to background script
    if (detectedAttacks.length > 0) {
      chrome.runtime.sendMessage({ 
        action: "xssDetected", 
        attacks: detectedAttacks 
      });
    }
  }

  // Initialize when DOM and DOMPurify are ready
  function initialize() {
    if (!document.body) {
      setTimeout(initialize, 50);
      return;
    }
    
    initialScan();
  }

  waitForDOMPurify(() => {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initialize);
    } else {
      initialize();
    }
  });
}

try {
  detectAndSanitizeXSS();
} catch (error) {
  console.error("[XSS Protection Error]", error);
}