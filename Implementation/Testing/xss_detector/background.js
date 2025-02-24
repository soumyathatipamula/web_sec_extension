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
      chrome.storage.local.get({ xssLogs: [] }, data => {
        let logs = data.xssLogs;
        logs.push(...message.attacks);
        savetojson(logs);
        chrome.storage.local.set({ xssLogs: logs });
      });
    }
  });


  function savetojson(attacklogs) {
    const jsonString = JSON.stringify(attacklogs, null, 2);
    const dataUrl = 'data:application/json;base64,' + btoa(jsonString);
  
    chrome.downloads.download({
      url: dataUrl,
      filename: 'xss-attacks.json',
      saveAs: true
    });
  }