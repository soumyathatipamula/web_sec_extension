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
  
  function sanitizeUrl(url) {
    const urlObj = new URL(url, window.location.origin); // Handle relative URLs
    const xssPatterns = [/javascript:/i, /<script/i, /on\w+=/i];
    let sanitizedSearch = urlObj.search;
    xssPatterns.forEach(pattern => {
      sanitizedSearch = sanitizedSearch.replace(pattern, "");
    });
    urlObj.search = sanitizedSearch;
    return urlObj.href.replace(/#.*/g, "");
  }
  
  function detectAndSanitize() {
    let detectedAttacks = [];
    let url = window.location.href;
  
    // Request URL Sanitization (pre-DOM)
    let sanitizedUrl = sanitizeUrl(url);
    if (sanitizedUrl !== url) {
      detectedAttacks.push({ type: "Reflected XSS", effector: "URL", payload: url, sanitized: sanitizedUrl, time: new Date().toLocaleString() });
      window.location.href = sanitizedUrl; // Redirect to sanitized URL
    }
  
    // DOM-based XSS Detection and Sanitization
    let originalHTML = document.body.innerHTML;
    let sanitizedHTML = DOMPurify.sanitize(originalHTML, {
      RETURN_DOM: false,
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
  
    // Response URL Sanitization (e.g., <a>, <script src>)
    document.querySelectorAll("a[href], script[src], img[src]").forEach(element => {
      const originalUrl = element.getAttribute(element.tagName === "A" ? "href" : "src");
      const sanitizedUrl = sanitizeUrl(originalUrl);
      if (originalUrl !== sanitizedUrl) {
        element.setAttribute(element.tagName === "A" ? "href" : "src", sanitizedUrl);
        detectedAttacks.push({
          type: "Response URL XSS",
          effector: element.tagName,
          payload: originalUrl,
          sanitized: sanitizedUrl,
          url: window.location.href,
          time: new Date().toLocaleString()
        });
      }
    });
  
    // Phishing Detection
    phishingPatterns.forEach(pattern => {
      if (pattern.test(url)) {
        detectedAttacks.push({ type: "Phishing URL", url: url, time: new Date().toLocaleString() });
      }
    });
  
    // Anomaly Detection
    let mutationCount = 0;
    const observer = new MutationObserver((mutations) => {
      mutationCount += mutations.length;
      if (mutationCount > 50) {
        detectedAttacks.push({
          type: "Anomaly",
          effector: "Excessive DOM Mutations",
          payload: `${mutationCount} mutations`,
          url: url,
          time: new Date().toLocaleString()
        });
        observer.disconnect();
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  
    if (detectedAttacks.length > 0) {
      chrome.runtime.sendMessage({ 
        action: detectedAttacks[0].type === "Phishing URL" ? "phishingDetected" : "xssDetected", 
        attacks: detectedAttacks 
      });
    }
  }
  
  // Sanitize Page on User Request
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "sanitizePage") {
      document.body.innerHTML = DOMPurify.sanitize(document.body.innerHTML);
      document.querySelectorAll("a[href], script[src], img[src]").forEach(element => {
        const attr = element.tagName === "A" ? "href" : "src";
        element.setAttribute(attr, sanitizeUrl(element.getAttribute(attr)));
      });
    }
  });
  
  detectAndSanitize();