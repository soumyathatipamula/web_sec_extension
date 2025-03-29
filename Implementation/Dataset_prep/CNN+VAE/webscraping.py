import requests
from bs4 import BeautifulSoup
import random
import time
from collections import deque
from urllib.parse import urljoin, urlparse
import csv

# Comprehensive list of benign HTML tags
tags = [
    "a", "abbr", "address", "area", "article", "aside", "audio", "b", "bdi", "bdo",
    "blockquote", "body", "br", "button", "canvas", "caption", "cite", "code", "col",
    "colgroup", "data", "datalist", "dd", "del", "details", "dfn", "dialog", "div",
    "dl", "dt", "em", "embed", "fieldset", "figcaption", "figure", "footer", "form",
    "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hr", "html", "i", "iframe",
    "img", "input", "ins", "kbd", "label", "legend", "li", "link", "main", "map",
    "mark", "meta", "meter", "nav", "noscript", "object", "ol", "optgroup", "option",
    "output", "p", "param", "picture", "pre", "progress", "q", "rp", "rt", "ruby",
    "s", "samp", "script", "section", "select", "small", "source", "span", "strong",
    "style", "sub", "summary", "sup", "svg", "table", "tbody", "td", "template",
    "textarea", "tfoot", "th", "thead", "time", "title", "tr", "track", "u", "ul",
    "var", "video", "wbr"
]

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1'
]

# Optional proxy list (uncomment and fill if needed)
proxies_list = [
    # "http://your_proxy1:port",
    # "http://your_proxy2:port",
    # Add more proxies here
]

def scrape_benign_html_with_crawl(start_urls, target_samples=775974, max_depth=20):
    benign_samples = set()  # Use set for deduplication
    visited_urls = set()    # Track visited URLs
    queue = deque([(url, 0) for url in start_urls])  # (URL, depth)
    retries = 3
    base_delay = 1  # Base delay in seconds
    max_delay = 10  # Max delay on rate limits
    
    while queue and len(benign_samples) < target_samples:
        url, depth = queue.popleft()
        
        if url in visited_urls or depth > max_depth:
            continue
        
        visited_urls.add(url)
        print(f"Scraping {url} (Depth: {depth}, Samples: {len(benign_samples)})")
        
        for attempt in range(retries):
            try:
                headers = {'User-Agent': random.choice(user_agents)}
                proxies = {'http': random.choice(proxies_list), 'https': random.choice(proxies_list)} if proxies_list else None
                response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
                response.raise_for_status()
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract benign HTML snippets
                for tag in tags:
                    elements = soup.find_all(tag)
                    for elem in elements:
                        content = str(elem).replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
                        content = ' '.join(content.split())
                        if content and '<script' not in content.lower() and 'javascript:' not in content.lower():
                            benign_samples.add(content)
                
                # Collect links for crawling
                if depth < max_depth:
                    for link in soup.find_all('a', href=True):
                        absolute_url = urljoin(url, link['href'])
                        parsed_url = urlparse(absolute_url)
                        if (parsed_url.scheme in ['http', 'https'] and 
                            parsed_url.netloc == urlparse(url).netloc and 
                            absolute_url not in visited_urls):
                            queue.append((absolute_url, depth + 1))
                
                print(f"Collected {len(benign_samples)} samples so far...")
                time.sleep(random.uniform(base_delay, base_delay + 2))  # Polite delay
                break  # Exit retry loop on success
            
            except requests.exceptions.HTTPError as e:
                if response.status_code == 403:
                    print(f"403 Forbidden at {url}. Possible block. Retrying with delay...")
                    time.sleep(2 ** attempt * base_delay)
                elif response.status_code == 429:
                    print(f"429 Too Many Requests at {url}. Increasing delay to {max_delay} seconds...")
                    base_delay = min(base_delay + 2, max_delay)  # Increase delay up to max
                    time.sleep(base_delay * (2 ** attempt))
                else:
                    print(f"HTTP Error {response.status_code} at {url}: {e}")
                    break
                if attempt == retries - 1:
                    print(f"Max retries reached for {url}. Skipping...")
            
            except requests.exceptions.RequestException as e:
                print(f"Attempt {attempt + 1} failed for {url}: {e}")
                if attempt == retries - 1:
                    print(f"Max retries reached for {url}. Skipping...")
                time.sleep(2 ** attempt)  # Exponential backoff
            
            except Exception as e:
                print(f"General error processing {url}: {e}")
                break
    
    return list(benign_samples)

# Starting URLs
urls = [
    "https://www.google.com/", "https://www.youtube.com/", "https://www.facebook.com/",
    "https://www.twitter.com/", "https://www.instagram.com/", "https://www.linkedin.com/",
    "https://www.reddit.com/", "https://www.wikipedia.org/", "https://www.amazon.com/",
    "https://www.ebay.com/", "https://www.nytimes.com/", "https://www.bbc.com/",
    "https://www.cnn.com/", "https://www.reuters.com/", "https://www.nationalgeographic.com/",
    "https://www.w3schools.com/", "https://developer.mozilla.org/en-US/", "https://www.techcrunch.com/",
    "https://www.wired.com/", "https://www.scientificamerican.com/", "https://news.google.com/",
    "https://www.espn.com/", "https://www.nasa.gov/", "https://www.nature.com/",
    "https://www.economist.com/", "https://www.theguardian.com/international", "https://www.bloomberg.com/",
    "https://www.forbes.com/", "https://www.wsj.com/", "https://www.cnet.com/",
    "https://www.pcmag.com/", "https://www.tomshardware.com/", "https://www.techradar.com/",
    "https://www.engadget.com/", "https://arstechnica.com/", "https://digg.com/",
    "https://www.smashingmagazine.com/", "https://www.phoronix.com/", "https://www.imdb.com/",
    "https://www.rottentomatoes.com/", "https://www.goodreads.com/", "https://www.britannica.com/",
    "https://www.merriam-webster.com/", "https://www.dictionary.com/", "https://www.weather.com/",
    "https://www.accuweather.com/", "https://www.cdc.gov/", "https://www.who.int/",
    "https://www.nih.gov/", "https://www.fda.gov/", "https://www.irs.gov/",
    "https://www.census.gov/", "https://www.usps.com/", "https://www.fedex.com/",
    "https://www.ups.com/", "https://www.booking.com/", "https://www.expedia.com/",
    "https://www.airbnb.com/", "https://www.tripadvisor.com/", "https://www.yelp.com/",
    "https://www.zillow.com/", "https://www.realtor.com/", "https://www.autotrader.com/",
    "https://www.cars.com/", "https://www.craigslist.org/", "https://www.indeed.com/",
    "https://www.monster.com/", "https://www.glassdoor.com/", "https://www.quora.com/",
    "https://www.stackexchange.com/", "https://www.medium.com/", "https://www.vimeo.com/",
    "https://soundcloud.com/", "https://www.twitch.tv/", "https://www.deviantart.com/",
    "https://www.behance.net/", "https://dribbble.com/", "https://www.etsy.com/",
    "https://www.shopify.com/", "https://www.wordpress.org/", "https://www.joomla.org/",
    "https://www.drupal.org/", "https://www.python.org/", "https://www.java.com/",
    "https://www.microsoft.com/", "https://www.apple.com/", "https://www.oracle.com/",
    "https://www.ibm.com/", "https://www.intel.com/", "https://www.amd.com/",
    "https://www.nvidia.com/", "https://www.tesla.com/", "https://www.spacex.com/",
    "https://www.boeing.com/", "https://www.airbus.com/", "https://www.lego.com/",
    "https://www.mattel.com/", "https://www.nike.com/", "https://www.adidas.com/",
    "https://www.gap.com/", "https://www.hm.com/", "https://www.uniqlo.com/",
    "https://www.ikea.com/"
]

# Manual benign examples
manual_benign = [
    "<p>Hello world</p>",
    "<div class='content'>Hi</div>",
    "<img src='image.jpg' alt='pic'>",
    "<a href='https://example.com'>Link</a>",
    "<span style='color: blue'>Text</span>",
    "<h1>Title</h1>",
    "<h2>Subtitle</h2>",
    "<li>Item</li>",
    "<td>Data</td>",
    "<tr>Row</tr>",
    "<pre>code</pre>",
    "<code>print('hello')</code>",
    "<blockquote>quote</blockquote>"
]

# Scrape and crawl for benign samples
benign_samples = scrape_benign_html_with_crawl(urls, target_samples=775974, max_depth=20)
benign_samples.extend(manual_benign)

# Deduplicate and shuffle
benign_samples = list(set(benign_samples))  # Remove duplicates
random.shuffle(benign_samples)

# Adjust to target size
if len(benign_samples) < 775974:
    print(f"Warning: Only collected {len(benign_samples)} benign samples, short of 775,974.")
else:
    benign_samples = benign_samples[:775974]  # Limit to exact target

print(f"Collected {len(benign_samples)} benign samples")
for sample in benign_samples[:10]:
    print(sample)

# Save to text file
writer = csv.writer(open("benign_samples.csv", "w", newline=''))
for sample in benign_samples:
    writer.writerow([sample])  

print("Benign samples saved to 'benign_samples.csv'")