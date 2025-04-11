// content.js
const xssPatterns = [
    /<script\b[^>]*>[\s\S]*?(?:<\/script>|$)/i,
    /javascript:/i,
    /on\w+\s*=\s*["'].*?["']/i,
    /<iframe\b[^>]*srcdoc\s*=\s*["'].*?["'][^>]*>/i,
    /<[^>]+\s+(?:onerror|onload|onclick|onmouseover|onsubmit|formaction)\s*=\s*(["']?).*?\1[^>]*>/i,
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

function waitForDOMPurify(callback) {
    if (typeof DOMPurify !== 'undefined') {
        callback();
    } else {
        setTimeout(() => waitForDOMPurify(callback), 50);
    }
}

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

const originalFetch = window.fetch;
window.fetch = async function (resource, options = {}) {
    let detectedAttacks = [];
    if (options.method === "POST" && options.body) {
        let body = options.body;
        if (typeof body === "string") {
            const decodedBody = decodeObfuscation(body);
            if (xssPatterns.some(pattern => pattern.test(decodedBody))) {
                const sanitizedBody = sanitizeHTMLContent(decodedBody); // Assuming fetch body might be HTML
                const attackId = `Workspace-${resource}-${body.substring(0, 50)}`; // Basic body snippet
                if (!sessionStorage.getItem(attackId)) {
                    detectedAttacks.push({
                        type: "POST XSS (Fetch)",
                        effector: "fetch body",
                        originalPayload: body,
                        decodedPayload: decodedBody,
                        sanitizedPayload: sanitizedBody,
                        url: resource,
                        time: new Date().toLocaleString()
                    });
                    sessionStorage.setItem(attackId, 'true');
                }
                options.body = sanitizedBody;
            }
        } else if (body instanceof FormData) {
            const formDataEntries = Array.from(body.entries());
            const formDataString = formDataEntries.map(([key, value]) => `${key}=${value.substring(0, 20)}`).join('&');
            for (let [key, value] of body.entries()) {
                const decodedValue = decodeObfuscation(value);
                if (xssPatterns.some(pattern => pattern.test(decodedValue))) {
                    const sanitizedValue = sanitizeHTMLContent(decodedValue); // Assuming form data might contain HTML
                    const attackId = `Workspace-form-${resource}-${key}-${value.substring(0, 20)}`;
                    if (!sessionStorage.getItem(attackId)) {
                        detectedAttacks.push({
                            type: "POST XSS (Fetch FormData)",
                            effector: key,
                            originalPayload: value,
                            decodedPayload: decodedValue,
                            sanitizedPayload: sanitizedValue,
                            url: resource,
                            time: new Date().toLocaleString()
                        });
                        sessionStorage.setItem(attackId, 'true');
                    }
                    newFormData.append(key, sanitizedValue);
                } else {
                    newFormData.append(key, value);
                }
            }
            options.body = newFormData;
        }
    }

    if (detectedAttacks.length > 0) {
        browser.runtime.sendMessage({ action: "xssDetected", attacks: detectedAttacks });
    }
    return originalFetch(resource, options);
};

const originalOpen = XMLHttpRequest.prototype.open;
const originalSend = XMLHttpRequest.prototype.send;

XMLHttpRequest.prototype.open = function (method, url, ...args) {
    this._method = method;
    this._url = url;
    return originalOpen.call(this, method, url, ...args);
};

XMLHttpRequest.prototype.send = function (body) {
    let detectedAttacks = [];
    if (this._method === "POST" && body) {
        const decodedBody = decodeObfuscation(body);
        if (xssPatterns.some(pattern => pattern.test(decodedBody))) {
            const sanitizedBody = sanitizeHTMLContent(decodedBody); // Assuming XHR body might be HTML
            const attackId = `xhr-${this._url}-${body.substring(0, 50)}`;
            if (!sessionStorage.getItem(attackId)) {
                detectedAttacks.push({
                    type: "POST XSS (XHR)",
                    effector: "xhr body",
                    originalPayload: body,
                    decodedPayload: decodedBody,
                    sanitizedPayload: sanitizedBody,
                    url: this._url,
                    time: new Date().toLocaleString()
                });
                sessionStorage.setItem(attackId, 'true');
            }
            body = sanitizedBody;
        }
    }

    if (detectedAttacks.length > 0) {
        browser.runtime.sendMessage({ action: "xssDetected", attacks: detectedAttacks });
    }
    return originalSend.call(this, body);
};

let lastDetectionTime = 0;
const detectionDebounceInterval = 500; // Adjust as needed

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

function detectAndSanitizeXSS() {
    let detectedAttacks = [];

    // DOMPurify Hooks Example
    DOMPurify.addHook('beforeSanitizeElements', (node) => {
        if (node.nodeName === 'img' && node.getAttribute('src') && node.getAttribute('src').toLowerCase().startsWith('javascript:')) {
            console.warn("Potential javascript: in image src:", node.getAttribute('src'));
            node.removeAttribute('src');
            return node;
        }
    });

    DOMPurify.addHook('afterSanitizeAttributes', (node) => {
        const onload = node.getAttribute('onload');
        if (onload && onload.toLowerCase().includes('alert(')) {
            console.warn("Suspicious onload attribute:", onload);
            node.removeAttribute('onload');
        }
    });

    function processElement(element) {
        if (!element || !element.innerHTML) return;

        const originalContent = element.innerHTML;
        let decodedContent = decodeObfuscation(originalContent);
        let foundAttack = false;

        xssPatterns.forEach(pattern => {
            if (pattern.test(originalContent) || pattern.test(decodedContent)) {
                foundAttack = true;
            }
        });

        if (foundAttack) {
            let sanitizedContent;
            // Very basic context detection based on tag name
            if (['p', 'div', 'span', 'li'].includes(element.tagName.toLowerCase())) {
                sanitizedContent = sanitizeHTMLContent(decodedContent);
            } else {
                sanitizedContent = DOMPurify.sanitize(decodedContent, { // Default restrictive sanitization
                    FORBID_TAGS: ['script'],
                    FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onsubmit', 'formaction']
                });
            }

            if (sanitizedContent !== originalContent) {
                const currentTime = Date.now();
                const attackId = `dom-${window.location.href}-${element.tagName}-${originalContent.substring(0, 50)}`;
                if (currentTime - lastDetectionTime > detectionDebounceInterval && !sessionStorage.getItem(attackId)) {
                    detectedAttacks.push({
                        type: "DOM XSS (Obfuscated)",
                        effector: element.tagName,
                        originalPayload: originalContent,
                        decodedPayload: decodedContent,
                        sanitizedPayload: sanitizedContent,
                        url: window.location.href,
                        time: new Date().toLocaleString()
                    });
                    lastDetectionTime = currentTime;
                    sessionStorage.setItem(attackId, 'true');
                }
            }
        }
    }

    let urlParams = new URLSearchParams(window.location.search);
    urlParams.forEach((value, key) => {
        const decodedValue = decodeObfuscation(value);
        xssPatterns.forEach(pattern => {
            if (pattern.test(value) || pattern.test(decodedValue)) {
                const sanitizedValue = sanitizeURLParameter(decodedValue);
                const attackId = `url-${window.location.href}-${key}-${value}`;
                if (!sessionStorage.getItem(attackId)) {
                    detectedAttacks.push({
                        type: "Reflected XSS (Obfuscated)",
                        effector: key,
                        originalPayload: value,
                        decodedPayload: decodedValue,
                        sanitizedPayload: sanitizedValue,
                        url: window.location.href,
                        time: new Date().toLocaleString()
                    });
                    sessionStorage.setItem(attackId, 'true');
                    urlParams.set(key, sanitizedValue);
                    const newUrl = `${window.location.origin}${window.location.pathname}?${urlParams.toString()}${window.location.hash}`;
                    window.location.replace(newUrl);
                }
            }
        });
    });

    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        processElement(node);
                        node.querySelectorAll("*").forEach(processElement);
                    }
                });
            }
        });

        if (detectedAttacks.length > 0) {
            browser.runtime.sendMessage({ action: "xssDetected", attacks: detectedAttacks });
            detectedAttacks = [];
        }
    });

    function initialize() {
        if (!document.body) {
            setTimeout(initialize, 50);
            return;
        }

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    waitForDOMPurify(() => {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initialize);
        } else {
            initialize();
        }

        if (detectedAttacks.length > 0) {
            browser.runtime.sendMessage({ action: "xssDetected", attacks: detectedAttacks });
        }
    });
}

try {
    detectAndSanitizeXSS();
} catch (error) {
    console.error("[XSS Protection Error]", error);
}