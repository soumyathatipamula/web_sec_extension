// content.js
// XSS patterns including obfuscation detection
const xssPatterns = [
  /<script\b[^>]*>[\s\S]*?(?:<\/script>|$)/i,             // <script> blocks
  /javascript:(?!(?:false|void\(0\)|0))[^\n\r]*/i,       // javascript: pseudo-protocol (more specific)
  /vbscript:/i,                                            // vbscript: pseudo-protocol
  /data:text\/html(?:;[^,]*)?,[\s\S]*/i,                 // data:text/html with content
  /on\w+\s*=\s*(?:"[^"]*script:[^"]*"|'[^']*script:[^']*'|[^>\s]*script:[^>\s]*)/i, // on... handlers with script:
  /<\w+[^>]*?\s+on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)\s*(?:javascript:|vbscript:|data:)/i, // Tag with on... handler and pseudo-protocol
  /eval\s*\([^)]*\)/i,                                   // eval() with arguments (still broad, consider more context)
  /setTimeout\s*\([^)]*,\s*(?:"[^"]*"|'[^']*'|[^\s>]+)\s*\)/i, // setTimeout with string argument
  /setInterval\s*\([^)]*,\s*(?:"[^"]*"|'[^']*'|[^\s>]+)\s*\)/i, // setInterval with string argument
  /document\.write\s*\(/i,                                // document.write()
  // /document\.cookie/i,                                // Removed: Too common, legitimate use
  /innerHTML\s*=\s*(?:"[^"]*"|'[^']*'|<[^>]*>)/i,         // Assignment to innerHTML with HTML
  /outerHTML\s*=\s*(?:"[^"]*"|'[^']*'|<[^>]*>)/i,         // Assignment to outerHTML with HTML
  /execScript\s*\(/i,                                     // IE specific
  /unescape\s*\(/i,
  /atob\s*\(/i,
  /String\.fromCharCode\s*\(/i,
  /&#x?[0-9a-f]+;/i,
  /%[0-9a-f]{2}/i,
  /(?:\\x[0-9a-f]{2})|(?:\\u[0-9a-f]{4})/i,
  /<svg\b[^>]*?onload\s*=/i,
  /<iframe\b[^>]*?srcdoc\s*=/i,
  /<object\b[^>]*?data\s*=\s*["']?javascript:/i,
  /<embed\b[^>]*?src\s*=\s*["']?javascript:/i,
  /<form\b[^>]*?action\s*=\s*["']?javascript:/i,
  /<button\b[^>]*?formaction\s*=\s*["']?javascript:/i,
  /<input\b[^>]*?formaction\s*=\s*["']?javascript:/i,
  // /import\s*\(["'][^"']+["']\)/i,                   // Removed: Legitimate feature
  /\w+\s*=\s*["']?.*?(?:alert|prompt|confirm)\s*\(.*?\).*?["']?/i,
  // /data:text\/html/i,                                  // Already covered more specifically
  /srcdoc\s*=/i,
  /<iframe\b[^>]*?(?:sandbox)?[^>]*?>/i,                // More specific iframe check if no sandbox
  /style\s*=\s*["']?\s*expression\s*\(/i,
  /url\s*\(\s*["']?\s*javascript:/i
];

// Wait for DOMPurify to be available
function waitForDOMPurify(callback) {
  if (typeof DOMPurify !== 'undefined') {
      // Configure DOMPurify globally (optional but recommended)
      DOMPurify.setConfig({
          USE_PROFILES: { html: true }, // Use HTML profile by default
          FORBID_TAGS: ['style', 'form'], // More strict defaults
          FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onsubmit', 'formaction'] // Forbid common event handlers and style
          // ADD_ATTR: ['target'], // Example: Allow target attribute
      });
      console.log("DOMPurify loaded and configured.");
      callback();
  } else {
      console.log("Waiting for DOMPurify...");
      setTimeout(() => waitForDOMPurify(callback), 50);
  }
}

// Decode common obfuscation techniques
function decodeObfuscation(content) {
  if (typeof content !== 'string') return content;

  let decoded = content;
  let prevDecoded;
  let attempts = 0;
  const maxAttempts = 3; // Reduced max attempts to avoid over-decoding

  try {
      do {
          prevDecoded = decoded;

          // 1. HTML Entities (using browser's capability)
          try {
              const textarea = document.createElement('textarea');
              textarea.innerHTML = decoded;
              decoded = textarea.value;
          } catch (e) { /* Ignore if DOM methods fail */ }


          // 2. URL Decoding (Percent Encoding)
          decoded = decoded.replace(/\+/g, ' ');
          try {
              decoded = decodeURIComponent(decoded);
          } catch (e) { /* Invalid URI sequence */ }

          // 3. Base64 Decoding
          if (/^[A-Za-z0-9+/=]{4,}$/.test(decoded.trim()) && (decoded.trim().length % 4 === 0)) {
              try {
                  let tempDecoded = atob(decoded.trim());
                  // More conservative check after base64 decoding
                  if (/[<>"'`\(\)\{\}\s;=]|script:|on\w+=/.test(tempDecoded)) {
                      decoded = tempDecoded;
                  }
              } catch (e) { /* Not valid Base64 */ }
          }

          // 4. Hex/Unicode/Octal Escapes
          try {
              decoded = decoded.replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
              decoded = decoded.replace(/\\u([0-9A-Fa-f]{4})/g, (_, unicode) => String.fromCharCode(parseInt(unicode, 16)));
              decoded = decoded.replace(/\\([0-7]{1,3})/g, (_, octal) => String.fromCharCode(parseInt(octal, 8)));
          } catch (e) { /* Invalid escape */ }


          attempts++;
      } while (decoded !== prevDecoded && attempts < maxAttempts);

  } catch (e) {
      console.warn("Content script decodeObfuscation error:", e, "Original:", content);
      return content; // Return original on error
  }
  return decoded;
}

function detectAndSanitizeXSS() {

  let detectedAttacks = [];

  // Process and sanitize elements using DOMPurify
  let domScanDetectedAttacks = []; // Accumulate detections between observer calls

  function processElement(element) {
      if (!element || typeof element.innerHTML !== 'string' || !element.innerHTML) return;

      // Avoid reprocessing elements we might have already sanitized (basic check)
      if (element.dataset.sanitizedByExtension === 'true') return;

      const originalContent = element.innerHTML;
      let decodedContent = null; // Decode only if needed

      // Quick check for potentially malicious patterns
      if (/[<>"'`]|on\w+=|javascript:|data:text\/html/i.test(originalContent)) {
          decodedContent = decodeObfuscation(originalContent);
          if (xssPatterns.some(pattern => pattern.test(originalContent) || pattern.test(decodedContent))) {
              console.log("Potential DOM XSS found in element:", element.tagName);
              // Use DOMPurify to sanitize
              const sanitizedContent = DOMPurify.sanitize(decodedContent || originalContent, {
                // Use configured defaults or specify here
                // USE_PROFILES: { html: true }, // Default profile
                FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form'], // Example stricter config
                FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur', 'onsubmit', 'formaction', 'style']
            });

              // Only modify if DOMPurify actually changed something
              if (sanitizedContent !== originalContent) {
                  console.warn("Sanitizing DOM element:", element.tagName, "Original snippet:", originalContent.substring(0, 100));
                  element.innerHTML = sanitizedContent;
                  element.dataset.sanitizedByExtension = 'true'; // Mark element

                  domScanDetectedAttacks.push({
                      type: "DOM XSS Sanitized",
                      effector: element.tagName + (element.id ? `#${element.id}` : '') + (element.className ? `.${element.className.split(' ')[0]}` : ''),
                      originalPayload: originalContent.substring(0, 200),
                      decodedPayload: (decodedContent || originalContent).substring(0, 200),
                      sanitizedPayload: sanitizedContent.substring(0, 200),
                      url: window.location.href,
                      time: new Date().toLocaleString()
                  });
              }
          }
      }
      // Also check attributes (more complex, DOMPurify handles attributes during sanitize)
      // We rely on DOMPurify's attribute handling here.
  }

  // --- NEW: Monitor Input Fields ---
  function monitorInputFields() {
      console.log("Initializing input field monitoring.");
      document.body.addEventListener('input', (event) => {
          const target = event.target;
          if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA')) {
              const originalValue = target.value;
              if (!originalValue || originalValue.length < 5) return; // Skip empty or very short values

              // Quick check for potentially malicious patterns
              if (!/[<>"'`]|on\w+=|javascript:|data:text\/html/i.test(originalValue)) return;


              const decodedValue = decodeObfuscation(originalValue);

              // Use a more targeted set of patterns for input fields
              const inputXssPatterns = [
                  /javascript:/i,
                  /vbscript:/i,
                  /data:text\/html/i,
                  /on\w+\s*=/i,
                  /<script/i,
                  /eval\s*\(/i,
                  /setTimeout\s*\(/i,
                  /setInterval\s*\(/i,
                  /document\.write\s*\(/i,
                  /innerHTML\s*=/i,
                  /outerHTML\s*=/i
              ];

              if (inputXssPatterns.some(pattern => pattern.test(decodedValue))) {
                  console.warn(`Potential XSS detected in input field (${target.id || target.name || target.type}):`, originalValue.substring(0, 100));

                  // Send message to background for logging
                  browser.runtime.sendMessage({
                      action: "xssDetected",
                      attacks: [{
                          type: "Potential Input XSS",
                          effector: `Input (${target.tagName}${target.id ? '#'+target.id : ''}${target.name ? '.'+target.name : ''})`,
                          originalPayload: originalValue.substring(0, 200), // Log snippet
                          decodedPayload: decodedValue.substring(0, 200), // Log snippet
                          sanitizedPayload: "[Not Sanitized - Input Detected]", // Input sanitization is tricky, warn/log only
                          url: window.location.href,
                          time: new Date().toLocaleString()
                      }]
                  }).catch(err => console.error("Error sending input detection message:", err)); // Add catch for messaging errors

                  // Optional: Visual feedback (use carefully)
                  // target.style.boxShadow = '0 0 5px 2px red';
                  // setTimeout(() => { if(target) target.style.boxShadow = ''; }, 3000);
              }
          }
      }, true); // Use capture phase
  }


  // --- Initialization and Observation ---
  function initialScan() {
      if (!document.body) {
          console.log("Initial scan delayed: document.body not ready.");
          return;
      }
      console.log("Performing initial DOM scan...");
      const startTime = performance.now();
      document.body.querySelectorAll("*").forEach(processElement); // Scan all existing elements
      const endTime = performance.now();
      console.log(`Initial DOM scan completed in ${((endTime - startTime)/1000).toFixed(2)} seconds.`);

      // Send accumulated detections from initial scan
      if (domScanDetectedAttacks.length > 0) {
          console.log(`Sending ${domScanDetectedAttacks.length} detections from initial scan.`);
          browser.runtime.sendMessage({ action: "xssDetected", attacks: domScanDetectedAttacks })
              .catch(err => console.error("Error sending initial scan detections:", err));
          domScanDetectedAttacks = []; // Reset buffer
      }
  }

  // --- Mutation Observer Setup ---
  let debounceTimer; // Variable to hold the debounce timer

  const processMutations = (mutations) => {
      // This function contains your actual processing logic
      const startTime = performance.now();
      let processedNodeCount = 0;
      mutations.forEach((mutation) => {
          if (mutation.type === 'childList') {
              mutation.addedNodes.forEach(node => {
                  if (node.nodeType === Node.ELEMENT_NODE) {
                      // OPTIMIZATION: Only process the added node itself.
                      // Relies on `subtree: true` in observe() to catch mutations
                      // within this node later if they occur.
                      processElement(node);
                      processedNodeCount++;
                      // REMOVED: node.querySelectorAll("*").forEach(processElement);
                  }
              });
          } else if (mutation.type === 'attributes') {
              if(mutation.target && mutation.target.nodeType === Node.ELEMENT_NODE) {
                  // Check if the attribute value actually changed if old value is available
                  // This prevents reprocessing if an attribute is set to the same value
                  if (mutation.oldValue !== mutation.target.getAttribute(mutation.attributeName)) {
                      processElement(mutation.target);
                      processedNodeCount++;
                  }
              }
          }
      });

      // Send accumulated detections (moved inside the debounced function)
      if (domScanDetectedAttacks.length > 0) {
          const endTime = performance.now();
          console.log(`Debounced MutationObserver processed ${processedNodeCount} nodes in ${((endTime - startTime)/1000).toFixed(2)}s, sending ${domScanDetectedAttacks.length} detections.`); // Update log
          browser.runtime.sendMessage({ action: "xssDetected", attacks: domScanDetectedAttacks })
              .catch(err => console.error("Error sending observer detections:", err));
          domScanDetectedAttacks = []; // Reset buffer
      }
  };

  // Scan and sanitize URL parameters
  let urlParams = new URLSearchParams(window.location.search);
  urlParams.forEach((value, key) => {
      const decodedValue = decodeObfuscation(value);
        if (xssPatterns.some(pattern => pattern.test(value) || pattern.test(decodedValue))) {
            const sanitizedValue = DOMPurify.sanitize(decodedValue, {
                ALLOWED_TAGS: [],
                ALLOWED_ATTR: []
            });
            detectedAttacks.push({
                type: "Reflected XSS (Response)",
                effector: key,
                originalPayload: value,
                decodedPayload: decodedValue,
                sanitizedPayload: sanitizedValue,
                url: window.location.href,
                time: new Date().toLocaleString()
            });
            browser.runtime.sendMessage({
            action: "xssDetected",
            attacks: detectedAttacks
        });
            urlParams.set(key, sanitizedValue);
            const newUrl = `${window.location.origin}${window.location.pathname}?${urlParams.toString()}${window.location.hash}`;
            window.location.replace(newUrl); // Trigger the redirect
        }
  });

  // Setup MutationObserver
  const observer = new MutationObserver((mutations) => {
      // Clear the previous timer if mutations occur rapidly
      clearTimeout(debounceTimer);
      // Set a new timer to process mutations after a short delay (e.g., 100ms)
      debounceTimer = setTimeout(() => {
          // Use requestAnimationFrame for the actual processing
          window.requestAnimationFrame(() => processMutations(mutations));
      }, 100); // Adjust debounce delay (in ms) as needed
  });


  // Initialize when DOM and DOMPurify are ready
  function initialize() {
      if (!document.body) {
          console.log("Initialize check: document.body not ready, delaying...");
          setTimeout(initialize, 50); // Check again shortly
          return;
      }
      console.log("DOM ready, initializing XSS protection.");

      initialScan(); // Perform the initial scan of existing DOM

      // Start observing the body for changes
      observer.observe(document.body, {
          childList: true,     // Observe direct children additions/removals
          subtree: true,       // Observe all descendants
          attributes: true,   // Observe attribute changes
          attributeFilter: [   // <-- ADD THIS ARRAY
              'src', 'href', 'style', 'action', 'formaction', 'data',
              'srcdoc', 'background', 'poster',
              // Consider limiting these further based on common legitimate uses
              // For example, 'onload' and 'onerror' on <img> tags might be legitimate in some contexts
          ],
          attributeOldValue: true, // Keep if you need old values for comparison/logging
      });
      console.log("MutationObserver started with attribute filter.");

      monitorInputFields(); // Start monitoring input fields

      console.log("XSS Content Script Initialized and Monitoring. Version 1.3");
  }


  waitForDOMPurify(() => {
      if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', initialize);
      } else {
          initialize();
      }
  });
  if (detectedAttacks.length > 0) {
      browser.runtime.sendMessage({
          action: "xssDetected",
          attacks: detectedAttacks
      });
  }
}

try {
  detectAndSanitizeXSS();
} catch (error) {
  console.error("[XSS Protection Error]", error);
}