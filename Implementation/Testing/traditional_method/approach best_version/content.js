// content.js

// Ensure strict mode
'use strict';

// --- XSS Patterns (Consistent with background, potentially slightly adjusted for DOM context) ---
const xssPatterns = [
    /<script\b[^>]*>[\s\S]*?(?:<\/script>|$)/i,             // <script> blocks
    /javascript:/i,                                       // javascript: pseudo-protocol
    /vbscript:/i,                                         // vbscript: pseudo-protocol
    /data:/i,                                             // data: pseudo-protocol (potential vector)
    /on\w+\s*=\s*["'][^"']*?script:/i,                     // on... handlers with script:
    /on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/i,            // General on... handlers
    /<\w+[^>]*?\s+on\w+\s*=/i,                             // Tag with any on... handler attribute start
    /eval\s*\(/i,                                         // eval()
    /setTimeout\s*\(/i,                                    // setTimeout() potentially dangerous
    /setInterval\s*\(/i,                                   // setInterval() potentially dangerous
    /document\.write\s*\(/i,                               // document.write()
    /document\.cookie/i,                                  // Accessing document.cookie
    // /window\.location/i,                               // Avoid this one, too common
    /innerHTML\s*=/i,                                     // Assignment to innerHTML (sink - harder to catch reliably with regex)
    /outerHTML\s*=/i,                                     // Assignment to outerHTML (sink - harder to catch reliably with regex)
    /execScript\s*\(/i,                                    // IE specific
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
    /import\s*\(["'][^"']+["']\)/i,
    // Pattern to catch attribute values trying to execute alert/prompt/confirm
     /\w+\s*=\s*["']?.*?(?:alert|prompt|confirm)\s*\(.*?\).*?["']?/i,
    /data:text\/html/i,
    /srcdoc\s*=/i,
    /<\s*iframe/i,
    /style\s*=\s*["']?\s*expression\s*\(/i,
    /url\s*\(\s*["']?\s*javascript:/i
];

// Patterns specifically for checking user input fields (potentially less strict)
const inputXssPatterns = [
     /<script\b[^>]*>/i,             // Opening script tag is highly suspicious in input
     /on\w+\s*=\s*["']/i,            // Attempting to add event handlers
     /javascript:/i,               // javascript: protocol
     /<\w+\s+[^>]*?(?:alert|prompt|confirm)\s*\(/i, // Tag trying to execute functions
     /(?:alert|prompt|confirm)\s*\(/i // Direct function calls
     // Avoid overly broad patterns like simple HTML tags if they might be legitimate input
];


// --- Wait for DOMPurify ---
function waitForDOMPurify(callback) {
    if (typeof DOMPurify !== 'undefined') {
        // Configure DOMPurify globally (optional but recommended)
        DOMPurify.setConfig({
            USE_PROFILES: { html: true }, // Use HTML profile by default
            FORBID_TAGS: ['style', 'form'], // Example: Forbid style, form tags
            FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onsubmit', 'formaction'] // Forbid common event handlers
            // ADD_ATTR: ['target'], // Example: Allow target attribute
        });
        console.log("DOMPurify loaded and configured.");
        callback();
    } else {
        console.log("Waiting for DOMPurify...");
        setTimeout(() => waitForDOMPurify(callback), 50);
    }
}

// --- Decode Obfuscation (reuse from background, ensure consistency) ---
function decodeObfuscation(content) {
    if (typeof content !== 'string') return content;

    let decoded = content;
    let prevDecoded;
    let attempts = 0;
    const maxAttempts = 5; // Prevent infinite loops

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
                       if (/[<>"'`\(\)\{\}\s]|[a-zA-Z0-9]/.test(tempDecoded)) {
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

// --- Fetch/XHR Interception ---
const originalFetch = window.fetch;
window.fetch = async function (resource, options = {}) {
    let detectedAttacks = [];
    let modified = false;

    // Check URL in resource (if it's a string or URL object)
    let urlString = '';
    if (typeof resource === 'string') {
        urlString = resource;
    } else if (resource instanceof URL) {
        urlString = resource.href;
    } else if (resource instanceof Request) {
        urlString = resource.url;
    }

    // Basic check for javascript: in URL
    if (urlString && xssPatterns.some(pattern => pattern.test(decodeObfuscation(urlString)))) {
         detectedAttacks.push({
            type: "Fetch Request URL XSS",
            effector: "fetch URL",
            originalPayload: urlString.substring(0, 200),
            decodedPayload: decodeObfuscation(urlString).substring(0, 200),
            sanitizedPayload: "[Blocked Request]",
            url: urlString, // The target URL is the payload here
            time: new Date().toLocaleString()
         });
         modified = true; // Mark for potential blocking
    }

    // Check POST body
    if (!modified && options && options.method && options.method.toUpperCase() === "POST" && options.body) {
        let body = options.body;
        let originalBodyForLog = body; // Keep original for logging
        let sanitizedBody = null;

        try {
            if (typeof body === "string") {
                originalBodyForLog = body.substring(0, 500); // Log snippet
                const decodedBody = decodeObfuscation(body);
                if (xssPatterns.some(pattern => pattern.test(decodedBody))) {
                    sanitizedBody = DOMPurify.sanitize(decodedBody, { USE_PROFILES: { html: false }, ALLOWED_TAGS: [], ALLOWED_ATTR: [] }); // Strict sanitization
                    detectedAttacks.push({
                        type: "POST XSS (Fetch String)",
                        effector: "fetch body (string)",
                        originalPayload: originalBodyForLog,
                        decodedPayload: decodedBody.substring(0, 200),
                        sanitizedPayload: sanitizedBody.substring(0, 200),
                        url: urlString,
                        time: new Date().toLocaleString()
                    });
                    options.body = sanitizedBody; // Modify the request body
                    modified = true;
                }
            } else if (body instanceof FormData) {
                originalBodyForLog = "[FormData Object]"; // Cannot easily log FormData directly
                const newFormData = new FormData();
                let formDataModified = false;
                for (let [key, value] of body.entries()) {
                    if (typeof value === 'string') {
                         const decodedValue = decodeObfuscation(value);
                         if (xssPatterns.some(pattern => pattern.test(decodedValue))) {
                             const sanitizedValue = DOMPurify.sanitize(decodedValue, { USE_PROFILES: { html: false }, ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
                             detectedAttacks.push({
                                 type: "POST XSS (Fetch FormData)",
                                 effector: `Workspace body (FormData: ${key})`,
                                 originalPayload: value.substring(0, 200),
                                 decodedPayload: decodedValue.substring(0, 200),
                                 sanitizedPayload: sanitizedValue.substring(0, 200),
                                 url: urlString,
                                 time: new Date().toLocaleString()
                             });
                             newFormData.append(key, sanitizedValue);
                             formDataModified = true;
                         } else {
                             newFormData.append(key, value); // Keep original
                         }
                    } else {
                         newFormData.append(key, value); // Keep non-string values (e.g., File)
                    }
                }
                if (formDataModified) {
                    options.body = newFormData; // Replace with sanitized FormData
                    modified = true;
                }
            }
             // Add checks for Blob, ArrayBuffer etc. if needed
        } catch (e) {
            console.error("Error processing fetch body:", e);
        }
    }

    if (detectedAttacks.length > 0) {
        console.warn("XSS detected via fetch interception:", detectedAttacks);
        browser.runtime.sendMessage({ action: "xssDetected", attacks: detectedAttacks });
    }

    // If attack detected in URL, block the request entirely
    if (detectedAttacks.some(a => a.type === "Fetch Request URL XSS")) {
         console.error("Blocking fetch request due to malicious URL:", urlString);
         // Throw an error or return a rejected Promise to block fetch
         return Promise.reject(new Error("Blocked potentially malicious fetch request URL by extension."));
    }

    // Proceed with original (potentially modified) fetch
    return originalFetch.call(this, resource, options);
};

// --- Intercept XMLHttpRequest ---
const originalXhrOpen = XMLHttpRequest.prototype.open;
const originalXhrSend = XMLHttpRequest.prototype.send;

XMLHttpRequest.prototype.open = function (method, url, ...args) {
    this._requestMethod = method; // Store method/URL for send()
    this._requestUrl = url instanceof URL ? url.href : url;

    // Basic check for javascript: in URL during open
    if (xssPatterns.some(pattern => pattern.test(decodeObfuscation(this._requestUrl)))) {
        console.error("Blocking XHR open due to malicious URL:", this._requestUrl);
        // Set a flag to block in send, or try to abort here (might be too late)
        this._blockRequest = true;
         // Notify immediately
         browser.runtime.sendMessage({ action: "xssDetected", attacks: [{
            type: "XHR Request URL XSS",
            effector: "XHR URL",
            originalPayload: String(this._requestUrl).substring(0, 200),
            decodedPayload: decodeObfuscation(String(this._requestUrl)).substring(0, 200),
            sanitizedPayload: "[Blocked Request]",
            url: String(this._requestUrl),
            time: new Date().toLocaleString()
         }]});

         // Attempt to prevent further processing by throwing error (may not always work depending on browser)
         throw new Error("Blocked potentially malicious XHR request URL by extension.");
    } else {
         this._blockRequest = false;
    }


    try {
         return originalXhrOpen.apply(this, [method, url, ...args]);
    } catch (e) {
         // Handle potential errors if the throw above didn't stop it
         console.error("Error during original XHR open (potentially due to blocking):", e);
         // Rethrow or handle as needed
         throw e;
    }
};

XMLHttpRequest.prototype.send = function (body) {
     // If flagged for blocking during open, abort here
     if (this._blockRequest === true) {
         console.error("Aborting XHR send due to malicious URL detected during open.");
         // Cannot reliably throw here, try to abort
         if (this.abort) { this.abort(); }
         return; // Stop execution
     }

    let detectedAttacks = [];
    let modified = false;
    let originalBodyForLog = body;
    let sanitizedBody = body; // Start with original

    if (this._requestMethod && this._requestMethod.toUpperCase() === "POST" && body) {
        try {
            if (typeof body === "string") {
                originalBodyForLog = body.substring(0, 500); // Log snippet
                const decodedBody = decodeObfuscation(body);
                if (xssPatterns.some(pattern => pattern.test(decodedBody))) {
                    sanitizedBody = DOMPurify.sanitize(decodedBody, { USE_PROFILES: { html: false }, ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
                    detectedAttacks.push({
                        type: "POST XSS (XHR String)",
                        effector: "XHR body (string)",
                        originalPayload: originalBodyForLog,
                        decodedPayload: decodedBody.substring(0, 200),
                        sanitizedPayload: sanitizedBody.substring(0, 200),
                        url: this._requestUrl,
                        time: new Date().toLocaleString()
                    });
                    modified = true;
                }
            } else if (body instanceof FormData) {
                 // FormData sanitization in XHR send is tricky, often less common than fetch.
                 // Logging might be more practical here.
                 originalBodyForLog = "[FormData Object]";
                 // Basic check - iterate and decode/check values
                 let formDataModified = false;
                 for (let [key, value] of body.entries()) {
                     if (typeof value === 'string') {
                         const decodedValue = decodeObfuscation(value);
                         if (xssPatterns.some(pattern => pattern.test(decodedValue))) {
                              detectedAttacks.push({
                                 type: "POST XSS (XHR FormData)",
                                 effector: `XHR body (FormData: ${key})`,
                                 originalPayload: value.substring(0, 200),
                                 decodedPayload: decodedValue.substring(0, 200),
                                 sanitizedPayload: "[Sanitization Attempted - Check Logs]", // Indicate attempt
                                 url: this._requestUrl,
                                 time: new Date().toLocaleString()
                              });
                              formDataModified = true;
                              // Modification of FormData sent via XHR is complex/often impossible here.
                              // Focus on detection.
                         }
                     }
                 }
                 if (formDataModified) {
                     modified = true; // Mark as detected, even if not sanitized
                     // sanitizedBody = body; // Cannot easily replace FormData here
                 }
            }
             // Add checks for Blob, ArrayBuffer etc. if needed
        } catch (e) {
            console.error("Error processing XHR body:", e);
        }
    }

    if (detectedAttacks.length > 0) {
         console.warn("XSS detected via XHR interception:", detectedAttacks);
        browser.runtime.sendMessage({ action: "xssDetected", attacks: detectedAttacks });
    }

    // Call original send with original or sanitized body (if string modification was possible)
    return originalXhrSend.call(this, sanitizedBody);
};


// --- DOM Sanitization and Monitoring ---
let domScanDetectedAttacks = []; // Accumulate detections between observer calls

function processElement(element) {
    if (!element || typeof element.innerHTML !== 'string' || !element.innerHTML) return;

    // Avoid reprocessing elements we might have already sanitized (basic check)
    if (element.dataset.sanitizedByExtension === 'true') return;

    const originalContent = element.innerHTML;
    let decodedContent = null; // Decode only if needed

    // Quick check for obvious patterns first
    if (/[<>"'`]|on\w+=|javascript:/i.test(originalContent)) {
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

             // Quick check
             if (!/[<>"'`]|on\w+=|javascript:/i.test(originalValue)) return;


            const decodedValue = decodeObfuscation(originalValue);

            // Use the specific patterns for input fields
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

const observer = new MutationObserver((mutations) => {
    // Clear the previous timer if mutations occur rapidly
    clearTimeout(debounceTimer);
    // Set a new timer to process mutations after a short delay (e.g., 100ms)
    debounceTimer = setTimeout(() => {
        // Use requestAnimationFrame for the actual processing
        window.requestAnimationFrame(() => processMutations(mutations));
    }, 100); // Adjust debounce delay (in ms) as needed
});


// --- Main Initialization Function ---
function initialize() {
    if (!document.body) {
        console.log("Initialize check: document.body not ready, delaying...");
        setTimeout(initialize, 50); // Check again shortly
        return;
    }
    console.log("DOM ready, initializing XSS protection.");

    initialScan(); // Perform the initial scan of existing DOM

    // Start observing the body for changes
    // Start observing the body for changes
observer.observe(document.body, {
    childList: true,    // Observe direct children additions/removals
    subtree: true,      // Observe all descendants
    attributes: true,   // Observe attribute changes
    attributeFilter: [  // <-- ADD THIS ARRAY
         'src', 'href', 'style', 'action', 'formaction', 'data',
         'srcdoc', 'background', 'poster',
         // Add common event handlers explicitly if they might be added dynamically
         'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onsubmit'
         // Add other attributes if relevant to your specific concerns
    ],
    attributeOldValue: true, // Keep if you need old values for comparison/logging
});
console.log("MutationObserver started with attribute filter."); // Update log message
    console.log("MutationObserver started.");

    monitorInputFields(); // Start monitoring input fields

    console.log("XSS Content Script Initialized and Monitoring. Version 1.3");
}

// --- Entry Point ---
try {
    // Wait for DOMPurify first, then initialize based on document state
    waitForDOMPurify(() => {
        if (document.readyState === 'loading') {
            console.log("Document loading, adding DOMContentLoaded listener.");
            document.addEventListener('DOMContentLoaded', initialize);
        } else {
            console.log("Document already loaded, initializing directly.");
            initialize();
        }
    });
} catch (error) {
    console.error("[XSS Protection Content Script Error]", error);
    // Attempt to clean up observer if initialization failed badly
    if (observer) observer.disconnect();
}