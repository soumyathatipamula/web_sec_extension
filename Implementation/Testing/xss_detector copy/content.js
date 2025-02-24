// Load attack patterns from storage
let attackPatterns = { TAGS: [], ATTRS: [], SVG: [], KEYWORDS: [] };

chrome.storage.local.get(["xssPatterns"], (data) => {
  if (data.xssPatterns) {
    attackPatterns = data.xssPatterns;
  }
});

// Function to detect XSS in attributes, script content, or input fields
function detectXSS(input) {
  for (let category in attackPatterns) {
    for (let pattern of attackPatterns[category]) {
      const regex = new RegExp(pattern, "i");
      if (regex.test(input)) {
        console.warn("[XSS DETECTED] Found in category:", category, "Payload:", input);
        sendAlert(input);
        return true;
      }
    }
  }
  return false;
}

// Monitor URL parameters for XSS payloads
function checkURLForXSS() {
  const urlParams = new URLSearchParams(window.location.search);
  for (let param of urlParams.values()) {
    detectXSS(param);
  }
}

// Monitor DOM mutations for malicious injections
const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    mutation.addedNodes.forEach((node) => {
      if (node.tagName) {
        detectXSS(node.outerHTML); // Check injected elements
      }
      if (node.nodeType === Node.TEXT_NODE) {
        detectXSS(node.textContent); // Check inserted script content
      }
    });
  });
});
observer.observe(document, { childList: true, subtree: true });

// Send alert to `background.js`
function sendAlert(payload) {
  chrome.runtime.sendMessage({ type: "XSS_DETECTED", payload: payload });
}

// Initial URL check
checkURLForXSS();
