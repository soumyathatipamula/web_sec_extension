browser.runtime.onInstalled.addListener(() => {
  browser.contentScripts.register({
    matches: ["<all_urls>"],
    js: ["dompurify.js", "content.js"],
    runAt: "document_start"
  });
});

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "xssDetected") {
    let alertMessage = `XSS Detected and Sanitized! (${message.attacks.length} instance(s))`;

    browser.notifications.create("XSS attack detected notification", {
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
    let transaction = db.transaction("xssLogs", "readwrite");
    let objectStore = transaction.objectStore("xssLogs");

    attacks.forEach((attack) => {
      objectStore.add(attack);
    });

    transaction.oncomplete = () => console.log("Attack details stored in IndexedDB");
    transaction.onerror = (event) => console.log("Error storing attack details", event.target.error);
  };

  request.onerror = (event) => console.log("Error opening indexed DB", event.target.error);
}

// Intercept completed requests and redirect sanitized ones
browser.webRequest.onCompleted.addListener((details) => {
  try {
    const url = new URL(details.url);
    const params = new URLSearchParams(url.search);
    if (params.has("__xss_sanitized_redirect")) {
      params.delete("__xss_sanitized_redirect"); // avoid loop
      url.search = params.toString();
      browser.tabs.update(details.tabId, { url: url.toString() });
    }
  } catch (e) {
    console.warn("Redirect error:", e);
  }
}, {
  urls: ["<all_urls>"]
});