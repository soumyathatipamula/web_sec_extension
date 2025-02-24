if (typeof attackVectors === 'undefined') {
    var attackVectors = [
        /<script>.*?<\/script>/i,
        /javascript:/i,
        /on\w+\s*=\s*["'].*?["']/i,
        /<video\s+[^>]*onerror\s*=\s*["'].*?["'][^>]*>/i,
        /<form\s+[^>]*formaction\s*=\s*["'].*?["'][^>]*>/i,
        /<svg\s+[^>]*onload\s*=\s*["'].*?["'][^>]*>/i,
        /document\.(cookie|write|location)/i
    ];
}

function detectXSS() {
    let pageContent = document.body.innerHTML;
    let found = false;
    let matches = [];
    attackVectors.forEach((pattern) => {
        let matches = pageContent.match(pattern);
        if (matches) {
            found = true;
            console.log("Vachindhi chudu ra" + matches);
            // console.warn("Potential XSS Detected:", matches);
            highlightMatches(pattern);
        }
    });

    if (found) {
        alert("⚠️ XSS Attack Detected! Check console for"+ matches +"details.");
    }
}

function highlightMatches(pattern) {
    let matchedElements = [];
    let elements = document.body.querySelectorAll('*');
    elements.forEach(element => {
        console.log(element.tagName);
        // if (element.innerHTML.match(pattern)) {
        //     element.style.backgroundColor = "red";
        //     // console.log(element.tagName, element.innerHTML);
        // }
        if (pattern.test(element.innerHTML)) {
            matchedElements.push(element);
            // element.style.backgroundColor="red";
            console.log(element.tagName);
        }
    } 
);

matchedElements.pop().style.backgroundColor = "red";
matchedElements.pop().style.border = "2px solid yellow";
}



detectXSS();
