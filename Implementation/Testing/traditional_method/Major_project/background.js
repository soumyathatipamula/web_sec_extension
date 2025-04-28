function handleXSSDetection(attacks) {
    if (!attacks || attacks.length === 0) {
        console.log("handleXSSDetection called with no attacks array or empty array.");
        return; // Avoid processing if no attacks
    }
        let alertMessage = `XSS Detected and Sanitized! (${attacks.length} instance(s))`;

    // Consider using unique IDs for notifications if they might overlap quickly
    browser.notifications.create(/*"xss-notification-" + Date.now(), */ { // Optional unique ID
        type: "basic",
        iconUrl: "assets/icon.png", // Ensure this path is correct relative to manifest.json
        title: "XSS Alert",
        message: alertMessage
    });

        storeInIDB(attacks);
}

// --- IndexedDB Storage Function (Unchanged) ---
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
        // Check if object store exists before trying to use it
        if (!db.objectStoreNames.contains("xssLogs")) {
             console.error("Object store 'xssLogs' not found during storage attempt.");
             db.close(); // Close the connection if store is missing
             return;
        }
        let transaction;
        try {
             transaction = db.transaction("xssLogs", "readwrite");
        } catch (e) {
             console.error("Error starting transaction:", e);
             db.close();
             return;
        }

        let objectStore = transaction.objectStore("xssLogs");

        attacks.forEach((attack) => {
            try {
                 objectStore.add(attack);
            } catch (e) {
                 console.error("Error adding attack to object store:", e, attack);
            }
        });

        transaction.oncomplete = () => console.log("Attack details stored in IndexedDB");
        transaction.onerror = (event) => console.error("Transaction error storing attack details", event.target.error); // Use console.error
    };

    request.onerror = (event) => console.error("Error opening indexed DB", event.target.error); // Use console.error
};


// --- Listener for Messages from Content Scripts ---
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "xssDetected") {
        console.log("Received xssDetected message from content script:", sender.tab ? "from tab " + sender.tab.url : "from the extension");
                handleXSSDetection(message.attacks); // Call the handler function
        // sendResponse({}); // Acknowledge receipt if needed by sender
        return true; // Indicate potential async response if using sendResponse
    }
    // Optional: Handle other message types if needed
});

// --- Intercept onBeforeRequest ---
browser.webRequest.onBeforeRequest.addListener(
    (details) => {
        const url = new URL(details.url);
        let detectedAttacks = [];
        let modified = false;
        let newUrl = null; // For GET redirection
        let newFormData = null; // For POST modification

        // Sanitize URL parameters (GET requests)
        const params = new URLSearchParams(url.search);
        let paramsModified = false;
        params.forEach((value, key) => {
            const decodedValue = decodeObfuscation(value); // Use the same decode function
            if (isXSSPayload(decodedValue)) { // Use the same check function
                const sanitizedValue = sanitizeValue(decodedValue); // Use the same sanitize function
                detectedAttacks.push({
                    type: "Reflected XSS (GET Request)",
                    effector: key,
                    originalPayload: value,
                    decodedPayload: decodedValue,
                    sanitizedPayload: sanitizedValue,
                    url: details.url,
                    time: new Date().toLocaleString()
                });
                params.set(key, sanitizedValue);
                paramsModified = true;
                modified = true; // Mark overall modification
            }
        });
        if (paramsModified) {
            newUrl = url.origin + url.pathname + '?' + params.toString() + url.hash;
        }


        // Handle POST requests (URL-encoded form data)
        if (details.method === "POST" && details.requestBody && details.requestBody.formData) {
            const formData = details.requestBody.formData;
            const tempFormData = {}; // Build new form data here
            let formDataModified = false;

            for (let [key, values] of Object.entries(formData)) {
                const sanitizedValues = [];
                let valueModified = false;
                values.forEach((value) => {
                    const decodedValue = decodeObfuscation(value);
                    if (isXSSPayload(decodedValue)) {
                        const sanitizedValue = sanitizeValue(decodedValue);
                        detectedAttacks.push({
                            type: "Reflected XSS (POST Request)",
                            effector: key,
                            originalPayload: value,
                            decodedPayload: decodedValue,
                            sanitizedPayload: sanitizedValue,
                            url: details.url,
                            time: new Date().toLocaleString()
                        });
                        sanitizedValues.push(sanitizedValue); // Add sanitized value
                        formDataModified = true;
                        valueModified = true;
                    } else {
                        sanitizedValues.push(value); // Keep original if no XSS
                    }
                });
                 tempFormData[key] = sanitizedValues; // Use the processed list of values
            }

            if (formDataModified) {
                newFormData = tempFormData; // Prepare the modified form data
                modified = true; // Mark overall modification
            }
        }

        // --- Perform Action if Modified ---
        if (modified) {
            console.log("XSS detected in webRequest, modifying request:", details.url);
            if (detectedAttacks.length > 0) {
                // *** CALL DIRECTLY *** No sendMessage needed here
                                handleXSSDetection(detectedAttacks);
            }

            if (newFormData) {
                // Log the data being sent *before* returning
                console.log("Preparing to send modified POST request body:", JSON.stringify(newFormData));
                // Return modified POST data
                 console.log("Modifying POST request body with sanitized data."); // Updated log message
                return { requestBody: { formData: newFormData } };
            } else if (newUrl) {
                // Return redirect for modified GET parameters
                 console.log("Redirecting GET request to:", newUrl);
                return { redirectUrl: newUrl };
            }
        }

        // No modification needed or detected
        return {};
    },
    { urls: ["<all_urls>"] },
    ["blocking", "requestBody"]
);

// --- Helper functions for XSS detection and sanitization (Keep these) ---
const xssPatterns = [
    /<script\b[^>]*>[\s\S]*?(?:<\/script>|$)/i,
    /javascript:/i,
    /on\w+\s*=\s*["'].*?["']/i,
    /eval\s*\(/i,
    /unescape\s*\(/i,
    /decodeURIComponent\s*\(/i,
    /atob\s*\(/i,
    /String\.fromCharCode\s*\(/i,
    /&#x?[0-9a-f]+;/i,
    /%[0-9a-f]{2}/i,
    /(?:\\x[0-9a-f]{2})|(?:\\u[0-9a-f]{4})/i,
    /<[^>]+\s+(?:(?:onfocusin)|(?:oncontentvisibilityautostatechange)|(?:onerror)|(?:onfocus)|(?:onload))\s*=\s*(["']?).*?\1/i,
    /document\.(cookie|write|location)/i,
    /(alert|confirm|prompt)\s*\(/i,
    // New patterns for advanced XSS
    /throw\s*[^;]*;/i, // Detect throw statements
    /window\.onerror\s*=/i, // Detect window.onerror assignments
    /print\s*\(/i // Detect print() calls
];


// Basic decode function (consider limitations for complex obfuscation)
function decodeObfuscation(content) {
    if (typeof content !== 'string') return content;

    let decoded = content;
    try {
        // 1. HTML Entities (basic)
        try {
            const textarea = document.createElement('textarea');
            textarea.innerHTML = decoded;
            decoded = textarea.value;
        } catch (domError) {
            console.warn("DOM-based decoding (textarea) not available in this context or failed.", domError);
        }

        // 2. URL Decoding
        decoded = decodeURIComponent(decoded.replace(/\+/g, ' '));

        // 3. Base64 Decoding (with XSS check)
        if (/^[A-Za-z0-9+/=]{4,}$/.test(decoded) && decoded.length % 4 === 0) {
            try {
                let tempDecoded = atob(decoded);
                if (/[<>"'`\(\)]/.test(tempDecoded) || /script|on\w+=|javascript:/i.test(tempDecoded)) {
                    decoded = tempDecoded;
                }
            } catch (e) { /* Not valid Base64, ignore */ }
        }

        // 4. Hex/Unicode Escapes
        decoded = decoded.replace(/\\x([0-9A-Fa-f]{2})|\\u([0-9A-Fa-f]{4})/g, (_, hex, unicode) => {
            try {
                return String.fromCharCode(parseInt(hex || unicode, 16));
            } catch (e) { return ''; }
        });

        // 5. Octal Escapes (e.g., \50 = '(', \51 = ')')
        decoded = decoded.replace(/\\([0-7]{1,3})/g, (_, octal) => {
            try {
                return String.fromCharCode(parseInt(octal, 8));
            } catch (e) { return ''; }
        });

    } catch (e) {
        console.warn("Generic obfuscation decoding error:", e, "Original:", content);
        return content;
    }
    return decoded;
}


function isXSSPayload(content) {
    if (typeof content !== 'string') return false;
    const isMatch = xssPatterns.some(pattern => {
        const match = pattern.test(content);
        if (match) {
            console.log(`XSS pattern matched: ${pattern.source} in content: ${content}`);
        }
        return match;
    });
    if (!isMatch && content.includes('script') || content.includes('onerror') || content.includes('throw')) {
        console.warn(`Potential undetected XSS payload: ${content}`);
    }
    return isMatch;
}

// Basic Sanitization - VERY LIMITED. DOMPurify in content script is much better.
// This background sanitation primarily aims to break simple script execution.
function sanitizeValue(content) {
    if (typeof content !== 'string') return '';
    let sanitized = content
        .replace(/<script[^>]*>[\s\S]*?(?:<\/script>|$)/gi, " none ")
        .replace(/<[^>]+>/g, (match) => {
            return match.replace(/on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, ' sanitized-event ');
        })
        .replace(/javascript:/gi, "sanitized-javascript:")
        .replace(/eval\s*\(/gi, "sanitized-eval(")
        .replace(/ VBScript:/gi, "sanitized-vbscript:")
        // New sanitization rules
        .replace(/throw\s*[^;]*;/gi, "sanitized-throw;")
        .replace(/window\.onerror\s*=/gi, "sanitized-onerror=")
        .replace(/print\s*\(/gi, "sanitized-print(")
        .replace(/<(?=.*?>)/g, '<')
        .replace(/>/g, '>');
    sanitized = sanitized
        .replace(/"/g, '"')
        .replace(/'/g, "'")
        .replace(/`/g, '`');
    return sanitized;
}

console.log("Background script loaded and listeners initialized."); // Add a log to confirm loading