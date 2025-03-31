Object.defineProperty(String.prototype, "capitalize", {
    value: function() {
      return this.charAt(0).toUpperCase() + this.slice(1);
    }
  });
  
  document.addEventListener("DOMContentLoaded", () => {
    const logList = document.getElementById("log-list");
    const clearBtn = document.getElementById("clear-log");
  
    let request = indexedDB.open("xssLogs", 1);
    request.onupgradeneeded = (event) => {
      let db = event.target.result;
      if (!db.objectStoreNames.contains("xssLogs")) {
        db.createObjectStore("xssLogs", { autoIncrement: true });
      }
    };
    request.onsuccess = (event) => {
      let db = event.target.result;
      let transaction = db.transaction("xssLogs", "readonly");
      let objectStore = transaction.objectStore("xssLogs");
      objectStore.openCursor().onsuccess = (event) => {
        let cursor = event.target.result;
        if (cursor) {
          let log = cursor.value;
          let mainLi = document.createElement("li");
          let ul = document.createElement("ul");
          for (let key in log) {
            let li = document.createElement("li");
            li.textContent = `${key.capitalize()}: ${log[key]}`;
            ul.appendChild(li);
          }
          mainLi.appendChild(ul);
          logList.appendChild(mainLi);
          cursor.continue();
        }
      };
    };
  
    clearBtn.addEventListener("click", () => {
      let request = indexedDB.open("xssLogs", 1);
      request.onsuccess = (event) => {
        let db = event.target.result;
        let transaction = db.transaction("xssLogs", "readwrite");
        transaction.objectStore("xssLogs").clear();
        logList.innerHTML = "";
      };
    });
  });