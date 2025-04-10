// Register content scripts on install (Firefox-specific)
browser.runtime.onInstalled.addListener(() => {
  browser.contentScripts.register({
    matches: ["<all_urls>"],
    js: ["dompurify.js", "content.js"],
    runAt: "document_start"
  });
});

// Handle messages from content script
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "xssDetected") {
    let alertMessage = `XSS Detected and Sanitized! (${message.attacks.length} instance(s))`;

    browser.notifications.create("XSS attack detected notification", {
      type: "basic",
      iconUrl: "icon.png",
      title: "XSS Alert",
      message: alertMessage
    });

    storeInIDB(message.attacks);
  }
});

// Store attack details in IndexedDB
function storeInIDB(attacks) {
  let request = indexedDB.open("xssLogs", 1);

  request.onupgradeneeded = (event) => {
    let db = event.target.result;
    if (!db.objectStoreNames.contains("xssLogs")) {
      db.createObjectStore("xssLogs", { autoIncrement: true });
    }
  };

  request.onsuccess = (event) => {
    let db = event.target.result;
    let transaction = db.transaction("xssLogs", "readwrite");
    let objectStore = transaction.objectStore("xssLogs");

    attacks.forEach((attack) => {
      objectStore.add(attack);
    });

    transaction.oncomplete = () => console.log("Attack details stored in IndexedDB");
    transaction.onerror = (event) => console.log("Error storing attack details", event.target.error);
  };

  request.onerror = (event) => console.log("Error opening indexed DB", event.target.error);
};

// XSS patterns including obfuscation detection
const xssPatterns = [
  { regex: /<script\b[^>]*>[\s\S]*?(?:<\/script>|$)/i, description: "Script tag" },
  { regex: /javascript:/i, description: "Javascript protocol" },
  { regex: /on\w+\s*=\s*["'].*?["']/i, description: "Event handler" },
  { regex: /<video\b[^>]*onerror\s*=\s*["'].*?["'][^>]*>/i, description: "Video onerror" },
  { regex: /<form\b[^>]*formaction\s*=\s*["'].*?["'][^>]*>/i, description: "Form action" },
  { regex: /<svg\b[^>]*onload\s*=\s*["'].*?["'][^>]*>/i, description: "SVG onload" },
  { regex: /document\.(cookie|write|location)/i, description: "Document property" },
  { regex: /<[^>]+\s+(?:(?:onfocusin)|(?:oncontentvisibilityautostatechange)|(?:onerror)|(?:onfocus)|(?:onload))\s*=\s*(["']?)\s*alert\(1\)/i, description: "Specific event with alert" },
  { regex: /eval\s*\(/i, description: "Eval function" },
  { regex: /unescape\s*\(/i, description: "Unescape function" },
  { regex: /decodeURIComponent\s*\(/i, description: "DecodeURIComponent" },
  { regex: /atob\s*\(/i, description: "Base64 decode" },
  { regex: /String\.fromCharCode\s*\(/i, description: "Char code construction" },
  { regex: /&#x?[0-9a-f]+;/i, description: "HTML entity encoding" },
  { regex: /%[0-9a-f]{2}/i, description: "URL encoding" },
  { regex: /(?:\\x[0-9a-f]{2})|(?:\\u[0-9a-f]{4})/i, description: "Hex/Unicode escapes" },
  { regex: /<[^>]+(\s+\w+\s*=\s*["']?.*?(prompt|alert|confirm)\(.*\).*?["']?)+[^>]*>/i, description: "Tag with alert/prompt" },
  { regex: /\w+\s*=\s*["']?.*?(prompt|alert|confirm)\(.*\).*?["']?/i, description: "Attribute-based alert" }
];

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

// Intercept requests before they are sent
browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    try {
      const url = new URL(details.url);
      const params = new URLSearchParams(url.search);

      // Skip if already sanitized
      if (params.has("__xss_sanitized")) {
        return {};
      }

      let detectedAttacks = [];
      let modified = false;

      params.forEach((value, key) => {
        const decodedValue = decodeObfuscation(value);
        xssPatterns.forEach(pattern => {
          const originalMatch = value.match(pattern.regex);
          const decodedMatch = decodedValue.match(pattern.regex);

          if (originalMatch || decodedMatch) {
            const maliciousContent = originalMatch ? originalMatch[0] : decodedMatch[0];
            let sanitizedValue = value;

            // Special handling for script tags
            if (pattern.description === "Script tag" && maliciousContent.includes('<script')) {
              const scriptContentMatch = maliciousContent.match(/<script\b[^>]*>([\s\S]*?)(?:<\/script>|$)/i);
              if (scriptContentMatch) {
                const scriptContent = scriptContentMatch[1];
                const innerMatch = scriptContent.match(/(alert|prompt|confirm)\s*\([^)]*\)/i);
                if (innerMatch && scriptContent.trim() !== innerMatch[0].trim()) { // Ensure there's more than just the malicious content
                  sanitizedValue = value.replace(innerMatch[0], '');
                } else if (scriptContent.trim()) { // If there's content, remove it
                  sanitizedValue = value.replace(scriptContent, '');
                } else {
                  return; // Empty script tag, no need to sanitize further
                }
              }
            } else {
              sanitizedValue = value.replace(maliciousContent, '');
            }

            if (sanitizedValue !== value) { // Only log and modify if something was actually removed
              params.set(key, sanitizedValue);
              modified = true;
              detectedAttacks.push({
                type: "Reflected XSS (Pre-Request)",
                effector: key,
                originalPayload: value,
                decodedPayload: decodedValue,
                sanitizedPayload: sanitizedValue,
                removedContent: maliciousContent,
                trigger: pattern.description,
                url: details.url,
                time: new Date().toLocaleString()
              });
            }
          }
        });
      });

      if (modified) {
        params.set("__xss_sanitized", "1"); // Mark as sanitized to prevent loop
        url.search = params.toString();
        const redirectUrl = url.toString();
        if (detectedAttacks.length > 0) {
          storeInIDB(detectedAttacks);
          browser.notifications.create({
            type: "basic",
            iconUrl: "icon.png",
            title: "XSS Alert",
            message: `XSS Detected in Request! (${detectedAttacks.length} instance(s))`
          });
        }
        return { redirectUrl };
      }
    } catch (e) {
      console.warn("onBeforeRequest error:", e);
    }
    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);