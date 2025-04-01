Object.defineProperty(String.prototype, "capitalize", {
    value: function() {
      return this.charAt(0).toUpperCase() + this.slice(1);
    }
  });
  
  document.addEventListener("DOMContentLoaded", () => {
    const logList = document.getElementById("log-list");
    const clearBtn = document.getElementById("clear-log");
    const whitelistInput = document.getElementById("whitelist-input");
    const addWhitelistBtn = document.getElementById("add-whitelist");
    const whitelistList = document.getElementById("whitelist-list");
  
    const request = indexedDB.open("xssLogs", 1);
  
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains("xssLogs")) {
        db.createObjectStore("xssLogs", { autoIncrement: true });
      }
    };
  
    request.onsuccess = (event) => {
      const db = event.target.result;
      const transaction = db.transaction("xssLogs", "readonly");
      const objectStore = transaction.objectStore("xssLogs");
  
      objectStore.openCursor().onsuccess = (event) => {
        const cursor = event.target.result;
        if (cursor) {
          const mainLi = document.createElement("li");
          const ul = document.createElement("ul");
          const log = cursor.value;
  
          for (let key in log) {
            const li = document.createElement("li");
            li.id = key;
            li.textContent = `${key.capitalize()}: ${log[key]}`;
            ul.appendChild(li);
          }
          mainLi.appendChild(ul);
          logList.appendChild(mainLi);
          cursor.continue();
        }
      };
    };
  
    request.onerror = (event) => {
      logList.innerHTML = "<h3>Cannot Fetch Logs</h3>";
      console.error("Cannot fetch logs:", event.target.error);
    };
  
    chrome.storage.sync.get("whitelist", (data) => {
      const whitelist = data.whitelist || [];
      whitelist.forEach(rule => {
        const li = document.createElement("li");
        li.textContent = rule;
        whitelistList.appendChild(li);
      });
    });
  
    addWhitelistBtn.addEventListener("click", () => {
      const rule = whitelistInput.value.trim();
      if (rule) {
        chrome.storage.sync.get("whitelist", (data) => {
          const whitelist = data.whitelist || [];
          if (!whitelist.includes(rule)) {
            whitelist.push(rule);
            chrome.storage.sync.set({ whitelist }, () => {
              const li = document.createElement("li");
              li.textContent = rule;
              whitelistList.appendChild(li);
              whitelistInput.value = "";
            });
          }
        });
      }
    });
  
    clearBtn.addEventListener("click", () => {
      const clearRequest = indexedDB.open("xssLogs", 1);
      clearRequest.onsuccess = (event) => {
        const db = event.target.result;
        const transaction = db.transaction("xssLogs", "readwrite");
        transaction.objectStore("xssLogs").clear();
        logList.innerHTML = "";
      };
    });
  });