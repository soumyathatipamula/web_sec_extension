// Load TensorFlow.js dynamically if not bundled



if (typeof tf === "undefined") {
    const script = document.createElement("script");
    script.src = "tf.min.js";
    script.onload = () => initModel();
    
    document.head.appendChild(script);
  } else {
    initModel();
  }
  
  // Refined regex patterns for initial filtering
  const xssPatterns = [
    /<script\b[^>]*>[\s\S]*?(alert|eval|setTimeout|document\.(cookie|write|location))[\s\S]*?<\/script>/i,
    /javascript:\s*(alert|eval|document\.(cookie|write|location))/i,
    /on\w+\s*=\s*["'](?:alert|eval|setTimeout|document\.(cookie|write|location))\(/i,
    /<iframe\b[^>]*src=['"]javascript:/i,
    /eval\s*\(\s*["'`][^"'`]*["'`]\s*\)/i,
    /(%[0-9A-Fa-f]{2}){3,}/i
  ];
  
  // Whitelist from chrome.storage
  let whitelist = [];
  chrome.storage.sync.get("whitelist", (data) => {
    whitelist = data.whitelist || [];
  });
  
  let cnnModel = null;
  
  // Initialize and load the CNN model
  async function initModel() {
    try {
      cnnModel = await tf.loadLayersModel(chrome.runtime.getURL("cnn/model.json"));
      console.log("CNN model loaded successfully");
      detectAndSanitize(); // Start detection after model loads
    } catch (error) {
      console.error("Error loading CNN model:", error);
      detectAndSanitize(); // Fallback to regex if model fails
    }
  }
  
  // Preprocess input for CNN (example: convert string to tensor)
  function preprocessInput(text) {
    // This depends on how your CNN was trained (e.g., tokenized text, character encoding)
    // Example: Convert text to a fixed-length array of character codes
    const maxLength = 100; // Adjust based on your model's input size
    const charCodes = text.split("").map(char => char.charCodeAt(0) || 0);
    const padded = charCodes.concat(Array(maxLength - charCodes.length).fill(0)).slice(0, maxLength);
    return tf.tensor2d([padded], [1, maxLength]);
  }
  
  // CNN-based classification
  async function classifyWithCNN(text) {
    if (!cnnModel) return false; // Fallback if model isn’t loaded
    const inputTensor = preprocessInput(text);
    const prediction = await cnnModel.predict(inputTensor).data();
    inputTensor.dispose(); // Clean up memory
    return prediction[0] > 0.5; // Assuming binary classification (malicious > 0.5)
  }
  
  // Sanitization function
  function sanitizeHTML(html) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, "text/html");
    const suspiciousElements = doc.querySelectorAll("script, [onload], [onerror], [onclick]");
    
    suspiciousElements.forEach(element => {
      const content = element.outerHTML;
      if (isMalicious(content) && !isWhitelisted(content)) {
        element.remove();
      }
    });
    return doc.body.innerHTML;
  }
  
  async function isMalicious(content) {
    const regexMalicious = xssPatterns.some(pattern => pattern.test(content));
    const cnnMalicious = await classifyWithCNN(content);
    return regexMalicious || cnnMalicious; // Hybrid detection
  }
  
  function isWhitelisted(content) {
    return whitelist.some(rule => content.includes(rule));
  }
  
  async function detectAndSanitize() {
    const detectedAttacks = [];
    const urlParams = new URLSearchParams(window.location.search);
  
    // Scan URL parameters
    for (let [key, value] of urlParams) {
      if ((await isMalicious(value)) && !isWhitelisted(value)) {
        detectedAttacks.push({
          type: "Reflected XSS",
          effector: key,
          payload: value,
          url: window.location.href,
          time: new Date().toLocaleString()
        });
      }
    }
  
    // Scan and sanitize DOM
    const html = document.documentElement.outerHTML;
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, "text/html");
    const elements = doc.querySelectorAll("*");
  
    for (let element of elements) {
      const content = element.outerHTML;
      if ((await isMalicious(content)) && !isWhitelisted(content)) {
        detectedAttacks.push({
          type: "DOM XSS",
          effector: element.tagName,
          payload: content,
          url: window.location.href,
          time: new Date().toLocaleString()
        });
        element.remove();
      }
    }
  
    // Apply sanitization if needed and not whitelisted
    if (detectedAttacks.length > 0 && !whitelist.includes(window.location.hostname)) {
      document.body.innerHTML = doc.body.innerHTML;
      chrome.runtime.sendMessage({ action: "xssDetected", attacks: detectedAttacks });
    }
  }
  
  // Debounced detection
  const debounce = (fn, delay) => {
    let timeout;
    return () => {
      clearTimeout(timeout);
      timeout = setTimeout(fn, delay);
    };
  };
  
  const debouncedDetect = debounce(detectAndSanitize, 500);
  
  // Run on DOM changes (initial run triggered by initModel)
  new MutationObserver(debouncedDetect).observe(document.documentElement, {
    childList: true,
    subtree: true
  });