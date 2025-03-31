chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "xssDetected" || message.action === "phishingDetected" || message.action === "anomalyDetected") {
      let alertMessage = `${message.action.replace("Detected", "")} Detected! (${message.attacks.length} instance(s))`;
      chrome.notifications.create(`alert-${Date.now()}`, {
        type: "basic",
        iconUrl: "icon.png",
        title: `${message.action.replace("Detected", "")} Alert`,
        message: alertMessage,
        buttons: [
          { title: "Sanitize Page" },
          { title: "Ignore" }
        ]
      }, (notificationId) => {
        chrome.notifications.onButtonClicked.addListener((notifId, btnIdx) => {
          if (notifId === notificationId) {
            if (btnIdx === 0) {
              chrome.tabs.sendMessage(sender.tab.id, { action: "sanitizePage" });
            }
          }
        });
      });
      storeInIDB(message.attacks);
  
      // Add blocking rule for detected phishing/XSS URLs
      if (message.action === "phishingDetected" || message.action === "xssDetected") {
        message.attacks.forEach(attack => {
          if (attack.url) {
            chrome.declarativeNetRequest.updateDynamicRules({
              addRules: [{
                "id": Date.now(), // Unique ID based on timestamp
                "priority": 1,
                "action": { "type": "block" },
                "condition": { "urlFilter": attack.url, "resourceTypes": ["main_frame", "sub_frame", "script"] }
              }],
              removeRuleIds: [] // Add IDs to remove old rules if needed
            }, () => {
              console.log(`Blocked URL: ${attack.url}`);
            });
          }
        });
      }
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
      let transaction = db.transaction("xssLogs", "readwrite");
      let objectStore = transaction.objectStore("xssLogs");
      attacks.forEach((attack) => objectStore.add(attack));
      transaction.oncomplete = () => console.log("Stored in IndexedDB");
      transaction.onerror = (event) => console.error("Storage error:", event.target.error);
    };
    request.onerror = (event) => console.error("DB open error:", event.target.error);
  }
  
  // Initial rules for common phishing/XSS patterns
  chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [
      {
        "id": 1,
        "priority": 1,
        "action": { "type": "block" },
        "condition": { "urlFilter": "*phish*", "resourceTypes": ["main_frame"] }
      },
      {
        "id": 2,
        "priority": 1,
        "action": { "type": "block" },
        "condition": { "urlFilter": "*javascript:*", "resourceTypes": ["script"] }
      }
    ],
    removeRuleIds: []
  }, () => {
    console.log("Initial blocking rules applied");
  });