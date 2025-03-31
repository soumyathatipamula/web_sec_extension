
import DOMPurify from 'dompurify';

const xssPatterns = [
    /<script\b[^>]*>[\s\S]*?<\/script>/i,
    /javascript:/i,
    /on\w+\s*=\s*["'].*?["']/i,
    /<video\b[^>]*onerror\s*=\s*["'].*?["'][^>]*>/i,
    /<form\b[^>]*formaction\s*=\s*["'].*?["'][^>]*>/i,
    /<svg\b[^>]*onload\s*=\s*["'].*?["'][^>]*>/i,
    /document\.(cookie|write|location)/i,
    /<[^>]+\s+(?:(?:onfocusin)|(?:oncontentvisibilityautostatechange)|(?:onerror)|(?:onfocus)|(?:onload))\s*=\s*(["']?)\s*alert\(1\)/i,
    // Add more patterns here...
];

async function detectXSS() {
    let detectedAttacks = [];
    let matchedElements = [];
    let found = false;

    let urlParams = new URLSearchParams(window.location.search);
    urlParams.forEach((value, key) => {
        xssPatterns.forEach(pattern => {
            if (pattern.test(value)) {
                detectedAttacks.push({ type: "Reflected XSS", effector: key, payload: value, url: window.location.href, Time: new Date().toLocaleString() });
            }
        });
    });

    document.body.querySelectorAll("*").forEach(element => {
        if (element.innerHTML) {
            let sanitized = DOMPurify.sanitize(element.innerHTML);
            if (sanitized !== element.innerHTML) {
                detectedAttacks.push({ type: "DOM XSS", effector: element.tagName, payload: element.innerHTML, sanitized: sanitized, url: window.location.href, Time: new Date().toLocaleString() });
                element.innerHTML = sanitized;
            }
            for (let attribute of element.attributes) {
                let sanitizedAttribute = DOMPurify.sanitize(attribute.value, { FOR_ATTRIBUTE: true });
                if (sanitizedAttribute !== attribute.value) {
                    detectedAttacks.push({ type: "Attribute XSS", effector: element.tagName, payload: attribute.value, sanitized: sanitizedAttribute, url: window.location.href, Time: new Date().toLocaleString() });
                    attribute.value = sanitizedAttribute;
                }
            }
        }
    });

    if (detectedAttacks.length > 0) {
        chrome.runtime.sendMessage({ action: "xssDetected", attacks: detectedAttacks });
    }
}

detectXSS();

const observer = new MutationObserver(mutations => {
    for (let mutation of mutations) {
        if (mutation.type === 'childList') {
            for (let addedNode of mutation.addedNodes) {
                if (addedNode.nodeType === Node.ELEMENT_NODE) {
                    // Check for suspicious elements.
                }
            }
        }
    }
});
observer.observe(document.body, { childList: true, subtree: true });

function isPhishingUrl(url) {
    let phishingPatterns = [
        /paypal\.com[^a-zA-Z]/i,
        /bankofamerica\.com[^a-zA-Z]/i,
    ];

    for (let pattern of phishingPatterns) {
        if (pattern.test(url)) {
            return true;
        }
    }
    return false;
}