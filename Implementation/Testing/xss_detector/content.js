// Known XSS attack patterns (simplified version)
const xssPatterns = [
  /<script>.*?<\/script>/i,
  /javascript:/i,
  /on\w+\s*=\s*["'].*?["']/i,
  /<video\s+[^>]*onerror\s*=\s*["'].*?["'][^>]*>/i,
  /<form\s+[^>]*formaction\s*=\s*["'].*?["'][^>]*>/i,
  /<svg\s+[^>]*onload\s*=\s*["'].*?["'][^>]*>/i,
  /document\.(cookie|write|location)/i,
];

// Function to scan for XSS payloads
function detectXSS() {
  let detectedAttacks = [];
  let matchedElements = [];
  let found = false;
  // Scan URL parameters for reflected XSS
  let urlParams = new URLSearchParams(window.location.search);
  urlParams.forEach((value, key) => {
    xssPatterns.forEach(pattern => {
      if (pattern.test(value)) {
        detectedAttacks.push({type: "Reflected XSS", effector: key, payload: value, url: window.location.href });
      }
    });
  });

  // Scan DOM elements for DOM-based XSS
  document.body.querySelectorAll("*").forEach(element => {
    xssPatterns.forEach(pattern => {
      if (element.innerHTML && pattern.test(element.innerHTML)) {
        matchedElements.push(element);
        found = true;
      }
    });
  });

  if (found){let matchedElement = matchedElements.pop();
  matchedElement.style.border = "2px solid yellow";
  matchedElement.style.background = "tomato";

  detectedAttacks.push({ type: "DOM XSS", effector: matchedElement.tagName, payload: matchedElement.innerHTML, url: window.location.href});}

  // Send detected attacks to background script
  if (detectedAttacks.length > 0) {
    chrome.runtime.sendMessage({ action: "xssDetected", attacks: detectedAttacks });
  }
}

// Run XSS detection when the page loads
detectXSS();
