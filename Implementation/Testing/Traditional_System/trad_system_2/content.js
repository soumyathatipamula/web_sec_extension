const xssPatterns = [
    /<script\b[^>]*>[\s\S]*?<\/script>/i,
    /javascript:/i,
    /on\w+\s*=\s*["'].*?["']/i,
    /<video\b[^>]*onerror\s*=\s*["'].*?["'][^>]*>/i,
    /<form\b[^>]*formaction\s*=\s*["'].*?["'][^>]*>/i,
    /<svg\b[^>]*onload\s*=\s*["'].*?["'][^>]*>/i,
    /document\.(cookie|write|location)/i,
    /<[^>]+\s+(?:(?:onfocusin)|(?:oncontentvisibilityautostatechange)|(?:onerror)|(?:onfocus)|(?:onload))\s*=\s*(["']?)\s*alert\(1\)/i,
    /eval\(/i,
    /&#x?[\da-f]{1,6};/i
  ];
  
  const phishingPatterns = [/phish/, /login-verify/, /bank-secure/];
  
  function detectThreats() {
    let detectedAttacks = [];
  
    // URL Parameter Scanning (Reflected XSS and Phishing)
    let url = window.location.href;
    let urlParams = new URLSearchParams(window.location.search);
    urlParams.forEach((value, key) => {
      xssPatterns.forEach(pattern => {
        if (pattern.test(value)) {
          detectedAttacks.push({ type: "Reflected XSS", effector: key, payload: value, url: url, time: new Date().toLocaleString() });
        }
      });
    });
    phishingPatterns.forEach(pattern => {
      if (pattern.test(url)) {
        detectedAttacks.push({ type: "Phishing URL", url: url, time: new Date().toLocaleString() });
      }
    });
  
    // DOM-based XSS with DOMPurify
    let originalHTML = document.body.innerHTML;
    let sanitizedHTML = DOMPurify.sanitize(originalHTML, {
      RETURN_DOM: false,
      ADD_TAGS: ["my-custom-tag"],
      FORBID_ATTR: ["onerror", "onload"]
    });
    if (originalHTML !== sanitizedHTML) {
      detectedAttacks.push({
        type: "DOM XSS",
        effector: "Body",
        payload: originalHTML,
        sanitized: sanitizedHTML,
        url: url,
        time: new Date().toLocaleString()
      });
    }
  
    // Anomaly Detection via MutationObserver
    let mutationCount = 0;
    const observer = new MutationObserver((mutations) => {
      mutationCount += mutations.length;
      if (mutationCount > 50) {
        detectedAttacks.push({
          type: "Anomaly",
          effector: "Excessive DOM Mutations",
          payload: `${mutationCount} mutations detected`,
          url: url,
          time: new Date().toLocaleString()
        });
        observer.disconnect();
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  
    // Send detected attacks
    if (detectedAttacks.length > 0) {
      chrome.runtime.sendMessage({ action: detectedAttacks[0].type === "Phishing URL" ? "phishingDetected" : "xssDetected", attacks: detectedAttacks });
    }
  }
  
  // Sanitize Page on User Request
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "sanitizePage") {
      document.body.innerHTML = DOMPurify.sanitize(document.body.innerHTML);
    }
  });
  
  // Run Detection
  detectThreats();