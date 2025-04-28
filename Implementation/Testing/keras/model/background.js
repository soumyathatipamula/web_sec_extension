chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "xssDetected") {
      const alertMessage = `XSS Detected! (${message.attacks.length} instance(s))`;
      
      chrome.notifications.create("xssNotification", {
        type: "basic",
        iconUrl: "icon.png",
        title: "XSS Alert",
        message: alertMessage,
        buttons: [{ title: "View Details" }]
      });
  
      storeInIDB(message.attacks);
    }
  });
  
  function storeInIDB(attacks) {
    const request = indexedDB.open("xssLogs", 1);
  
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains("xssLogs")) {
        db.createObjectStore("xssLogs", { autoIncrement: true });
      }
    };
  
    request.onsuccess = (event) => {
      const db = event.target.result;
      const transaction = db.transaction("xssLogs", "readwrite");
      const objectStore = transaction.objectStore("xssLogs");
  
      attacks.forEach((attack) => objectStore.add(attack));
  
      transaction.oncomplete = () => console.log("Attack details stored in IndexedDB");
      transaction.onerror = (event) => console.error("Error storing attack details:", event.target.error);
    };
  
    request.onerror = (event) => console.error("Error opening IndexedDB:", event.target.error);
  }
  
  chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    if (notificationId === "xssNotification" && buttonIndex === 0) {
      chrome.action.openPopup();
    }
  });