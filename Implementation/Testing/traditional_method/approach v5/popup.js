// popup.js (unchanged)
Object.defineProperty(String.prototype, "capitalize", {
  value: function() {
      return this.charAt(0).toUpperCase() + this.slice(1);
  }
});

document.addEventListener("DOMContentLoaded", () => {
  const exportBtn = document.getElementById("export-log");
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
      let transaction = db.transaction("xssLogs", "readwrite");
      let objectStore = transaction.objectStore("xssLogs");

      objectStore.openCursor().onsuccess = (event) => {
          let cursor = event.target.result;
          if (cursor) {
              let mainLi = document.createElement("li");
              let ul = document.createElement("ul");
              let log = cursor.value;

              for (let key in log) {
                  let li = document.createElement("li");
                  li.id = key;
                  li.textContent = `${key.capitalize()}: ${log[key]}`;
                  ul.appendChild(li);
              }
              mainLi.appendChild(ul);
              logList.insertBefore(mainLi, logList.firstChild);
              cursor.continue();
          }
      };
  };

  request.onerror = (event) => {
      console.log("Cannot fetch logs", event.target.error);
      logList.innerHTML = "<li>Error loading logs</li>";
  };

  clearBtn.addEventListener("click", () => {
      let request = indexedDB.open("xssLogs", 1);
      request.onsuccess = (event) => {
          let db = event.target.result;
          let transaction = db.transaction("xssLogs", "readwrite");
          let objectStore = transaction.objectStore("xssLogs");
          objectStore.clear();
          logList.innerHTML = "";
      };
  });


  exportBtn.addEventListener("click", () => {
      let request = indexedDB.open("xssLogs", 1);
      request.onsuccess = (event) => {
          let db = event.target.result;
          let transaction = db.transaction("xssLogs", "readonly");
          let objectStore = transaction.objectStore("xssLogs");

          let logs = [];
          objectStore.openCursor().onsuccess = (event) => {
              let cursor = event.target.result;
              if (cursor) {
                  logs.push(cursor.value);
                  cursor.continue();
              } else {
                  if (logs.length === 0) {
                      alert("No logs to export.");
                      return;
                  }

                  // Extract CSV headers dynamically
                  const headers = Object.keys(logs[0]);
                  const csvRows = [];

                  // Add header row
                  csvRows.push(headers.join(","));

                  // Add data rows
                  logs.forEach(log => {
                      const row = headers.map(field => {
                          const value = log[field] || "";
                          return `"${String(value).replace(/"/g, '""')}"`; // Escape quotes
                      });
                      csvRows.push(row.join(","));
                  });

                  const csvContent = csvRows.join("\n");
                  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `xss_logs_${new Date().toISOString().replace(/[:.]/g, "-")}.csv`;
                  a.click();
                  URL.revokeObjectURL(url);
              }
          };
      };
  });


});