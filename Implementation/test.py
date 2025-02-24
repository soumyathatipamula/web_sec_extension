# Reattempt to create the ZIP file with the updated CounterXSS extension files
import zipfile
import os

# Define the updated extension files again
files_final = {
    "manifest.json": """{
    "name": "CounterXSS",
    "version": "3.2",
    "description": "Detects and alerts on real XSS attacks",
    "manifest_version": 3,
    "action": {
        "default_icon": "icon.png",
        "default_popup": "popup.html"
    },
    "permissions": ["scripting", "tabs", "activeTab"],
    "host_permissions": ["<all_urls>"],
    "background": {
        "service_worker": "background.js"
    },
    "content_scripts": [
        {
            "matches": ["<all_urls>"],
            "js": ["content.js"]
        }
    ]
}""",

    "popup.html": """<!DOCTYPE html>
<html>
<head>
<title>CounterXSS</title>
<style>
body {
    background-color: linen;
    text-align: center;
}
h1 {
    color: maroon;
    margin-left: 40px;
} 
</style>
</head>
<body>
<h1>Background scanning active</h1>
<div>
    <button type="button" class="btn btn-danger" id="scanButton">Scan Again</button>
</div>
<script src="popup.js"></script>
</body>
</html>""",

    "popup.js": """document.getElementById("scanButton").addEventListener("click", function() {
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
        chrome.scripting.executeScript({
            target: { tabId: tabs[0].id },
            files: ["content.js"]
        });
    });
});""",

    "content.js": """const attackVectors = [
    /<script.*?>.*?<\\/script>/gi, 
    /javascript:/gi, 
    /on\\w+=/gi, 
    /<video[^>]*onerror=.*?>/gi, 
    /<form[^>]*formaction=.*?>/gi, 
    /<svg[^>]*onload=.*?>/gi, 
    /document\\.(cookie|write|location)/gi
];

function detectXSS() {
    let pageContent = document.body.innerHTML;
    let xssDetected = false;
    let foundMatches = [];

    attackVectors.forEach((pattern) => {
        let matches = pageContent.match(pattern);
        if (matches) {
            xssDetected = true;
            foundMatches = foundMatches.concat(matches);
            highlightMatches(pattern);
        }
    });

    if (xssDetected) {
        alert("🚨 XSS Attack Detected! Check console for details.");
        console.warn("XSS Detected:", foundMatches);
    }
}

function highlightMatches(pattern) {
    let elements = document.body.getElementsByTagName('*');
    for (let element of elements) {
        if (element.innerHTML.match(pattern)) {
            element.style.backgroundColor = "red";
        }
    }
}

detectXSS();""",

    "background.js": """chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url.startsWith("http")) {
        chrome.scripting.executeScript({
            target: { tabId: tabId },
            files: ["content.js"]
        }).catch(err => console.warn("Script injection failed:", err));
    }
});"""
}

# Create a zip file with the final extension version
zip_path_final = "CounterXSS_Final.zip"
with zipfile.ZipFile(zip_path_final, "w") as zipf:
    for filename, content in files_final.items():
        with open(filename, "w") as f:
            f.write(content)
        zipf.write(filename)
        os.remove(filename)

zip_path_final
