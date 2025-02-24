// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "XSS_DETECTED") {
      const attackDetails = {
          url: sender.tab ? sender.tab.url : "unknown",
          payload: message.payload,
          timestamp: new Date().toLocaleString()
      };

      // Store attack log in chrome.storage.local
      chrome.storage.local.get({ xssLogs: [] }, (data) => {
          let logs = data.xssLogs;
          logs.push(attackDetails);
          chrome.storage.local.set({ xssLogs: logs });
      });

      // Trigger a notification alert
      chrome.notifications.create({
          type: "basic",
          iconUrl: "icon.png",
          title: "XSS Attack Detected!",
          message: `Payload: ${message.payload}\nURL: ${attackDetails.url}`,
          priority: 2
      });

      console.warn("[XSS ALERT] Attack detected:", attackDetails);
  }
});
