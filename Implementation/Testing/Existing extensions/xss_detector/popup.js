document.addEventListener("DOMContentLoaded", () => {
    const logList = document.getElementById("log-list");
    const clearBtn = document.getElementById("clear-log");
  
    // Load stored logs
    chrome.storage.local.get({ xssLogs: [] }, data => {
      data.xssLogs.forEach(log => {
        let li = document.createElement("li");
        li.textContent = `[${log.type}] ${log.payload}`;
        logList.appendChild(li);
      });
    });
  
    // Clear logs when button is clicked
    clearBtn.addEventListener("click", () => {
      chrome.storage.local.set({ xssLogs: [] }, () => {
        logList.innerHTML = "";
      });
    });
  });
  