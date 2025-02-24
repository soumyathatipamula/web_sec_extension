document.getElementById('scan').addEventListener('click', function() {
  chrome.tabs.executeScript({
    code: `
      let scripts = document.getElementsByTagName('script');
      let detected = [];
      for (let script of scripts) {
        if (script.innerHTML.includes('<script>') || script.innerHTML.includes('eval(')) {
          detected.push(script.innerHTML);
        }
      }
      document.getElementById('result').innerText = detected.length > 0 ? 'XSS detected!' : 'No XSS found.';
    `
  });
});