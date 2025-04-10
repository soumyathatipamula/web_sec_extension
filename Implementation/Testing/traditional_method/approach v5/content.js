// content.js (optional, can be removed if not needed)
function initialize() {
  console.log("Content script loaded, no XSS detection here.");
}

try {
  initialize();
} catch (error) {
  console.error("[Content Script Error]", error);
}