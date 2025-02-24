document.addEventListener('DOMContentLoaded', function() {
  let scripts = document.getElementsByTagName('script');
  for (let script of scripts) {
    let sanitizedScript = sanitizeScript(script.innerHTML);
    if (script.innerHTML !== sanitizedScript) {
      script.innerHTML = sanitizedScript;
      console.warn('XSS script sanitized:', script);
    }
  }
});

function sanitizeScript(code) {
  return code.replace(/<script.*?>.*?<\/script>/gi, "")
             .replace(/on\w+=\".*?\"/gi, "")
             .replace(/eval\(.+?\)/gi, "");
}
