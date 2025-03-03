chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "xssDetected") {
      let alertMessage = `XSS Detected! (${message.attacks.length} instance(s))`;
      
      // Show a browser notification
      chrome.notifications.create("XSS attack detected notification",{
        type: "basic",
        iconUrl: "icon.png",
        title: "XSS Alert",
        message: alertMessage
      });
  
      // Store attack details in Chrome storage
      storeInIDB(message.attacks);
    }
  });


  function storeInIDB(attacks) {
    let request = indexedDB.open("XSS_logs", 1);

    request.onupgradeneeded = (event) =>{
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

      transaction.oncomplete = () => {
        console.log("Attack details stored in IndexedDB");
      };

      transaction.onerror = (event) => {
        console.log("Error storing attack details in IndexedDB", event.target.error);
      };

    };

    request.onerror = event => {
      console.log("Erroor opening indexed DB", event.target.error);
    };

  }