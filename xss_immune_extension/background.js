chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    let requestUrl = new URL(details.url);
    let requestBody = details.requestBody ? JSON.stringify(details.requestBody) : "";
    let storedScripts = localStorage.getItem("xss_scripts") || "[]";
    let scripts = JSON.parse(storedScripts);
    
    scripts.push({url: requestUrl.href, body: requestBody});
    localStorage.setItem("xss_scripts", JSON.stringify(scripts));
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestBody"]
);

chrome.webRequest.onCompleted.addListener(
  function(details) {
    fetch(details.url).then(response => response.text()).then(responseBody => {
      let storedScripts = JSON.parse(localStorage.getItem("xss_scripts") || "[]");
      for (let script of storedScripts) {
        if (similarityCheck(responseBody, script.body) > 0.7) {
          alert("Potential XSS attack detected on: " + script.url);
        }
      }
    });
  },
  { urls: ["<all_urls>"] }
);

function similarityCheck(text1, text2) {
  let tokens1 = text1.split(/\s+/);
  let tokens2 = text2.split(/\s+/);
  let common = tokens1.filter(value => tokens2.includes(value)).length;
  return common / Math.max(tokens1.length, tokens2.length);
}