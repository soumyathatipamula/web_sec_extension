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
        console.log("Object store created using popup");
      }
    };
    
    request.onsuccess = event => {
      let db = event.target.result;

      // if (!db.objectStoreNames.contains("xssLogs")) {
      //   db.createObjectStore("xssLogs", { autoIncrement: true });
      // }

      let transaction = db.transaction("xssLogs", "readwrite");
      let objectstore = transaction.objectStore("xssLogs");

      objectstore.openCursor().onsuccess = event => {
        let cursor = event.target.result;
        if (cursor) {
          let main_li = document.createElement("li");
          let ul = document.createElement("ul");
          let log = cursor.value;
          for (let key in log) {
            let li = document.createElement("li");
            li.id = key;
            li.textContent = `${key.capitalize()} : ${log[key]}`;
            ul.appendChild(li);
          }
          main_li.appendChild(ul)
          logList.appendChild(main_li);
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
  