// background.js
// Use browser.* for Firefox compatibility (also works in Chrome with polyfill if needed)
const reportedRequestAttacks = new Set(); // To track reported request attacks

browser.runtime.onInstalled.addListener(() => {
    browser.contentScripts.register({
        matches: ["<all_urls>"],
        js: ["dompurify.js", "content.js"],
        runAt: "document_start"
    });
});

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "xssDetected") {
        message.attacks.forEach(attack => {
            const alertMessage = `XSS Detected and Sanitized! (${attack.type})`;

            browser.notifications.create(`XSS attack detected notification - ${Date.now()}`, { // Make notification ID unique
                type: "basic",
                iconUrl: "icon.png",
                title: "XSS Alert",
                message: alertMessage
            });

            storeInIDB(attack); // Store each attack individually
        });
    }
});

function storeInIDB(attack) {
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

        objectStore.add(attack);

        transaction.oncomplete = () => console.log("Attack details stored in IndexedDB");
        transaction.onerror = (event) => console.log("Error storing attack details", event.target.error);
    };

    request.onerror = (event) => console.log("Error opening indexed DB", event.target.error);
};

// Intercept onBeforeRequest to sanitize GET and POST requests
browser.webRequest.onBeforeRequest.addListener(
    (details) => {
        const url = new URL(details.url);
        let detectedAttacks = [];
        let modified = false;

        // Sanitize URL parameters (GET requests)
        const params = new URLSearchParams(url.search);
        params.forEach((value, key) => {
            const decodedValue = decodeObfuscation(value);
            if (isXSSPayload(decodedValue)) {
                const sanitizedValue = sanitizeURLParameter(decodedValue); // Using context-specific sanitization
                const attackId = `request-get-${details.url}-${key}-${value}`;
                if (!reportedRequestAttacks.has(attackId)) {
                    detectedAttacks.push({
                        type: "Reflected XSS (GET)",
                        effector: key,
                        originalPayload: value,
                        decodedPayload: decodedValue,
                        sanitizedPayload: sanitizedValue,
                        url: details.url,
                        time: new Date().toLocaleString()
                    });
                    reportedRequestAttacks.add(attackId);
                    params.set(key, sanitizedValue);
                    modified = true;
                }
            }
        });

        // Handle POST requests (limited to URL-encoded form data in Manifest V2)
        if (details.method === "POST" && details.requestBody && details.requestBody.formData) {
            const formData = details.requestBody.formData;
            const newFormData = {};
            for (let [key, values] of Object.entries(formData)) {
                values.forEach((value) => {
                    const decodedValue = decodeObfuscation(value);
                    if (isXSSPayload(decodedValue)) {
                        const sanitizedValue = sanitizeHTMLContent(decodedValue); // Assuming POST data might be HTML content
                        const attackId = `request-post-${details.url}-${key}-${value}`;
                        if (!reportedRequestAttacks.has(attackId)) {
                            detectedAttacks.push({
                                type: "Reflected XSS (POST)",
                                effector: key,
                                originalPayload: value,
                                decodedPayload: decodedValue,
                                sanitizedPayload: sanitizedValue,
                                url: details.url,
                                time: new Date().toLocaleString()
                            });
                            reportedRequestAttacks.add(attackId);
                            newFormData[key] = [sanitizedValue]; // Replace with sanitized value
                            modified = true;
                        }
                    } else {
                        newFormData[key] = [value]; // Keep original if no XSS
                    }
                });
            }

            if (modified) {
                return {
                    requestBody: {
                        formData: newFormData
                    }
                };
            }
        }

        if (modified && detectedAttacks.length > 0) {
            detectedAttacks.forEach(attack => {
                browser.runtime.sendMessage({ action: "xssDetected", attacks: [attack] });
            });
            url.search = params.toString();
            return { redirectUrl: url.toString() };
        }

        return {}; // No modification needed
    },
    { urls: ["<all_urls>"] },
    ["blocking", "requestBody"] // Enable blocking and access to request body
);

// Reset the set periodically or when the extension is updated/reloaded
browser.runtime.onStartup.addListener(() => reportedRequestAttacks.clear());
browser.runtime.onInstalled.addListener(() => reportedRequestAttacks.clear());

// Helper functions for XSS detection and sanitization
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
    /(?:prompt|alert|confirm)\s*\(/i
];

function decodeObfuscation(content) {
    let decoded = content;
    try {
        if (content.includes('&') || content.includes('+')) {
            const textarea = document.createElement('textarea');
            textarea.innerHTML = decoded;
            decoded = textarea.value;
            decoded = decodeURIComponent(decoded.replace(/\+/g, ' '));
        }
        if (/^[A-Za-z0-9+/=]+$/.test(decoded)) {
            decoded = atob(decoded);
        }
        if (decoded.includes('\\x') || decoded.includes('\\u')) {
            decoded = decoded.replace(/\\x([0-9A-Fa-f]{2})|\\u([0-9A-Fa-f]{4})/g, (_, hex, unicode) => {
                return String.fromCharCode(parseInt(hex || unicode, 16));
            });
        }
    } catch (e) {
        console.warn("Obfuscation decoding error:", e);
    }
    return decoded;
}

function isXSSPayload(content) {
    return xssPatterns.some(pattern => pattern.test(content));
}

function sanitizeHTMLContent(content) {
    return DOMPurify.sanitize(content, {
        ALLOWED_TAGS: ['p', 'b', 'i', 'ul', 'ol', 'li', 'br', 'span', 'a', 'img', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
        ALLOWED_ATTR: ['href', 'title', 'src', 'alt', 'class', 'style', 'target', 'rel'],
        FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form', 'input', 'textarea', 'button'],
        FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onsubmit', 'formaction']
    });
}

function sanitizeURLParameter(content) {
    return DOMPurify.sanitize(content, {
        ALLOWED_TAGS: [],
        ALLOWED_ATTR: []
    });
}