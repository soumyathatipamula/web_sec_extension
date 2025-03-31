// background.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "xssDetected") {
        let alertMessage = `XSS Detected! (${message.attacks.length} instance(s))`;

        chrome.notifications.create("XSS attack detected notification", {
            type: "basic",
            iconUrl: "icon.png",
            title: "XSS Alert",
            message: alertMessage
        });

        storeInIDB(message.attacks);
    }
});

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

        if (!db.objectStoreNames.contains("xssLogs")) {
            db.createObjectStore("xssLogs", { autoIncrement: true });
        }

        let transaction = db.transaction("xssLogs", "readwrite");
        let objectStore = transaction.objectStore("xssLogs");

        attacks.forEach((attack) => {
            objectStore.add(attack);
        });

        transaction.oncomplete = () => {
            console.log("Attack details stored in IndexedDB");
        };

        transaction.onerror = (event) => {
            console.log("Error storing attack details in IndexedDB", event.target.error);
        };
    };

    request.onerror = event => {
        console.log("Error opening indexed DB", event.target.error);
    };
}

chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        chrome.storage.local.get('blockingEnabled', function(data) {
            if (data.blockingEnabled) {
                // Implement your logic to detect and block malicious requests here.
                // Example (basic):
                if (details.url.includes("<script>")) {
                    return { cancel: true };
                }
            }
        });
    },
    { urls: ["<all_urls>"] },
    ["blocking"]
);

// content.js
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

// popup.js
Object.defineProperty(String.prototype, "capitalize", {
    value: function() {
        return this.charAt(0).toUpperCase() + this.slice(1);
    }
});

document.addEventListener("DOMContentLoaded", () => {
    const logList = document.getElementById("log-list");
    const clearBtn = document.getElementById("clear-log");
    const blockToggle = document.getElementById("block-toggle");

    let request = indexedDB.open("xssLogs", 1);

    request.onupgradeneeded = (event) => {
        let db = event.target.result;
        if (!db.objectStoreNames.contains("xssLogs")) {
            db.createObjectStore("xssLogs", { autoIncrement: true });
            console.log("Object store created using popup");
        }
    };

    request.onsuccess = event => {
        let db = event.target.result;

        let transaction = db.transaction("xssLogs", "readwrite");
        let objectstore = transaction.objectStore("xssLogs");

        objectstore.openCursor().onsuccess = event => {
            let cursor = event.target.result;
            if (cursor) {
                let main_li = document.createElement("li");
                let ul = document.createElement("ul");
                let log = cursor.value;
                for (let key in log) {
                    let li = document.createElement("li");
                    li.id = key;
                    li.textContent = `${key.capitalize()} : ${log[key]}`;
                    ul.appendChild(li);
                }
                main_li.appendChild(ul);
                logList.appendChild(main_li);
                cursor.continue();
            }
        };
    };

    request.onerror = event => {
        let ele = document.createElement("h3");
        ele = "Cannot Fetch the logs";
        console.log("Cannot fetch the logs", event.target.error);
    };

    clearBtn.addEventListener("click", () => {
        logList.innerHTML = "";
    });

    blockToggle.addEventListener('change', function() {
        if (this.checked) {
            chrome.storage.local.set({ blockingEnabled: true });
        } else {
            chrome.storage.local.set({ blockingEnabled: false });
        }
    });

    chrome.storage.local.get('blockingEnabled', function(data) {
        blockToggle.checked = !!data.blockingEnabled;
    });
});

// popup.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Alert Log</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <h2>XSS Attack Logs</h2>
    <ul id="log-list"></ul>
    <button id="clear-log">Clear Logs</button>
    <div>
        <label for="block-toggle">Enable Blocking:</label>
        <input type="checkbox" id="block-toggle">
    </div>
    <script src="popup.js"></script>
</body>
</html>

// style.css
body {
    font-family: Arial, sans-serif;
    width: 400px;
    padding: 10px;
}
h2 {
    font-size: 18px;
}
ul {
    list-style-type: none;
    padding: 0;
}
li {
    background: #ffdddd;
    padding: 5px;
    margin: 5px 0;
    border-radius: 4px;
}
button {
    margin-top: 10px;
    padding: 5px;
    background: red;
    color: white;
    border: none;
    cursor: pointer;
}

// manifest.json
{
    "manifest_version": 3,
    "name": "XSS Alert Extension",
    "version": "1.0",
    "description": "Detects XSS attacks and alerts users. its detecting and recording https request and response",
    "permissions": ["storage", "notifications", "tabs", "scripting", "downloads", "webRequest"],
    "background": {
        "service_worker": "background.js"
    },
    "host_permissions": ["<all_urls>"],
    "action": {
        "default_popup": "popup.html",
        "default_icon": {
            "16": "icon.png",
            "48": "icon.png",
            "128": "icon.png"
        }
    },
    "content_scripts": [
        {
            "matches": ["<all_urls>"],
            "js": ["dompurify.js", "content.js"]
        }
    ],
    "web_accessible_resources": [
        {
            "resources": ["dompurify.js"],
            "matches": ["<all_urls>"]
        }
    ]
}