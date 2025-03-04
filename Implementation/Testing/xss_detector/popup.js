document.addEventListener("DOMContentLoaded", () => {
    const logList = document.getElementById("log-list");
    const clearBtn = document.getElementById("clear-log");
  
    // Load stored logs
    // chrome.storage.local.get({ xssLogs: [] }, data => {
    //   data.xssLogs.forEach(log => {
    //     let li = document.createElement("li");
    //     li.textContent = `[${log.type}] ${log.effector}, ${log.payload}, ${log.url}`;
    //     // li.textContent = `Type: ${log.type}\nEffected Area: ${log.effector}\nPayload: ${log.payload}\nURL: ${log.url}`;
    //     logList.appendChild(li);
    //   });
    // });

    let request = indexedDB.open("xssLogs", 1);
    
    request.onsuccess = event => {
      let db = event.target.result;
      let transaction = db.transaction("xssLogs", "readwrite");
      let objectstore = transaction.objectStore("xssLogs");

      objectstore.openCursor().onsuccess = event => {
        let cursor = event.target.result;
        if (cursor) {
          let li = document.createElement("li");
          li.textContent = `[${cursor.value.type}] ${cursor.value.effector}, ${cursor.value.payload}, ${cursor.value.url}`;
          logList.appendChild(li);
          cursor.continue();
        }
      };
    };

    request.onerror = event => 
      {
        let ele = document.createElement("h3");
        ele = "Cannot Fetch the logs";
        console.log("Cannot fetch the logs", event.target.error);
      }
    ;




  
    // Clear logs when button is clicked
    clearBtn.addEventListener("click", () => {
        logList.innerHTML = "";
    });
  });
  