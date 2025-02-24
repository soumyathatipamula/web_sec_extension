const XSS_ATTACK_VECTORS = [
    { type: "TAG", pattern: /<script.*?>.*?<\/script>/gi, description: "Inline script injection" },
    { type: "TAG", pattern: /<svg[^>]*onload=.*?>/gi, description: "SVG-based attack" },
    { type: "ATTRIBUTE", pattern: /on\w+=/gi, description: "Event handler abuse (onerror, onload, etc.)" },
    { type: "ATTRIBUTE", pattern: /javascript:/gi, description: "JavaScript protocol abuse" },
    { type: "HTML5", pattern: /<video[^>]*onerror=.*?>/gi, description: "Video tag exploit" },
    { type: "HTML5", pattern: /<form[^>]*formaction=.*?>/gi, description: "Form action hijacking" },
    { type: "DOM", pattern: /document\.(cookie|write|location)/gi, description: "DOM-based attack" }
];

export { XSS_ATTACK_VECTORS };
