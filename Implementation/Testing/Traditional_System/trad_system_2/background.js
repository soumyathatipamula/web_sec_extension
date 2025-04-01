chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "xssDetected" || message.action === "phishingDetected" || message.action === "anomalyDetected") {
      let alertMessage = `${message.action.replace("Detected", "")} Detected! (${message.attacks.length} instance(s))`;
      chrome.notifications.create(`alert-${Date.now()}`, {
        type: "basic",
        iconUrl: "icon.png",
        title: `${message.action.replace("Detected", "")} Alert`,
        message: alertMessage,
        buttons: [{ title: "Sanitize Page" }, { title: "Ignore" }]
      }, (notificationId) => {
        chrome.notifications.onButtonClicked.addListener((notifId, btnIdx) => {
          if (notifId === notificationId && btnIdx === 0) {
            chrome.tabs.sendMessage(sender.tab.id, { action: "sanitizePage" });
          }
        });
      });
      storeInIDB(message.attacks);
  
      // Sanitize or block detected URLs
      message.attacks.forEach(attack => {
        if (attack.url && (attack.type === "Phishing URL" || attack.type === "Reflected XSS")) {
          const sanitizedUrl = sanitizeUrl(attack.url);
          if (sanitizedUrl !== attack.url) {
            chrome.declarativeNetRequest.updateDynamicRules({
              addRules: [{
                "id": Date.now(),
                "priority": 1,
                "action": { 
                  "type": "redirect", 
                  "redirect": { "url": sanitizedUrl } 
                },
                "condition": { "urlFilter": attack.url, "resourceTypes": ["main_frame", "script"] }
              }],
              removeRuleIds: []
            }, () => console.log(`Sanitized URL: ${attack.url} -> ${sanitizedUrl}`));
          } else {
            chrome.declarativeNetRequest.updateDynamicRules({
              addRules: [{
                "id": Date.now(),
                "priority": 1,
                "action": { "type": "block" },
                "condition": { "urlFilter": attack.url, "resourceTypes": ["main_frame", "script"] }
              }],
              removeRuleIds: []
            }, () => console.log(`Blocked URL: ${attack.url}`));
          }
        }
      });
    }
  });
  
  function sanitizeUrl(url) {
    // Basic URL sanitization: remove script-like fragments
    const urlObj = new URL(url);
    const xssPatterns = [/javascript:/i, /<script/i, /on\w+=/i];
    let sanitizedSearch = urlObj.search;
    xssPatterns.forEach(pattern => {
      sanitizedSearch = sanitizedSearch.replace(pattern, "");
    });
    urlObj.search = sanitizedSearch;
    return urlObj.href.replace(/#.*/g, ""); // Remove hash fragments
  }
  
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
      attacks.forEach((attack) => objectStore.add(attack));
      transaction.oncomplete = () => console.log("Stored in IndexedDB");
      transaction.onerror = (event) => console.error("Storage error:", event.target.error);
    };
    request.onerror = (event) => console.error("DB open error:", event.target.error);
  }
  
  // Initial rules
  chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [
      {
        "id": 1,
        "priority": 1,
        "action": { "type": "block" },
        "condition": { "urlFilter": "*phish*", "resourceTypes": ["main_frame"] }
      }
    ],
    removeRuleIds: []
  });