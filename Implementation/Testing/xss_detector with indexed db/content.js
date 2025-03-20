
// Known XSS attack patterns (simplified version)
const xssPatterns = [
  /<script\b[^>]*>[\s\S]*?<\/script>/i, // Matches <script> tags and their content
  /javascript:/i, // Matches "javascript:" protocol in URLs
  /on\w+\s*=\s*["'].*?["']/i, // Matches any inline event handler attribute with a quoted value
  /<video\b[^>]*onerror\s*=\s*["'].*?["'][^>]*>/i, // Matches a <video> tag with an onerror attribute
  /<form\b[^>]*formaction\s*=\s*["'].*?["'][^>]*>/i, // Matches a <form> tag with a formaction attribute
  /<svg\b[^>]*onload\s*=\s*["'].*?["'][^>]*>/i, // Matches an <svg> tag with an onload attribute
  /document\.(cookie|write|location)/i, // Matches dangerous document property usage
  /<[^>]+\s+(?:(?:onfocusin)|(?:oncontentvisibilityautostatechange)|(?:onerror)|(?:onfocus)|(?:onload))\s*=\s*(["']?)\s*alert\(1\)/i, // Matches tags with specific event handlers that immediately call alert(1)
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
        detectedAttacks.push({type: "Reflected XSS", effector: key, payload: value, url: window.location.href, Time: new Date().toLocaleString()});
        console.log("Sent the log to the background script");
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
  detectedAttacks.push({ type: "DOM XSS", effector: matchedElement.tagName, payload: matchedElement.innerHTML, url: window.location.href,Time: new Date().toLocaleString()});
  console.log("Sent the log to the background script");}

  // Send detected attacks to background script
  if (detectedAttacks.length > 0) {
    chrome.runtime.sendMessage({ action: "xssDetected", attacks: detectedAttacks });
  }
}

// Run XSS detection when the page loads
detectXSS();
