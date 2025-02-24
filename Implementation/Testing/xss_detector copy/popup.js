document.addEventListener("DOMContentLoaded", () => {
  const logsList = document.getElementById("logs-list");
  const clearLogsButton = document.getElementById("clearLogs");

  // Fetch logs from storage
  chrome.storage.local.get(["xssLogs"], (data) => {
      if (data.xssLogs && data.xssLogs.length > 0) {
          data.xssLogs.forEach((log) => {
              const listItem = document.createElement("li");
              listItem.innerHTML = `<strong>URL:</strong> ${log.url} <br> 
                                    <strong>Payload:</strong> ${log.payload} <br> 
                                    <strong>Time:</strong> ${log.timestamp} <br><hr>`;
              logsList.appendChild(listItem);
          });
      } else {
          logsList.innerHTML = "<p>No XSS attacks detected.</p>";
      }
  });

  // Clear logs on button click
  clearLogsButton.addEventListener("click", () => {
      chrome.storage.local.set({ xssLogs: [] }, () => {
          logsList.innerHTML = "<p>No XSS attacks detected.</p>";
      });
  });
});
