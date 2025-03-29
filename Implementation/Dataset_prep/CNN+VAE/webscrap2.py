import requests
from bs4 import BeautifulSoup
import random
import time
from collections import deque
from urllib.parse import urljoin, urlparse
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Reduced list of common benign HTML tags for faster parsing
tags = [
    "a", "div", "p", "img", "span", "h1", "h2", "h3", "li", "td", "tr", "ul", "ol",
    "form", "input", "button", "table", "thead", "tbody", "tfoot", "th"
]

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
]

# Optional proxy list (uncomment and fill if needed)
proxies_list = [
    # "http://your_proxy1:port",
    # "http://your_proxy2:port",
]

# Thread-safe set for samples and lock
benign_samples = set()
samples_lock = Lock()
visited_urls = set()
urls_lock = Lock()

def scrape_domain(start_url, target_samples=775974, max_pages_per_domain=20):
    domain_samples = set()
    queue = deque([(start_url, 0)])  # (URL, depth)
    domain = urlparse(start_url).netloc
    pages_crawled = 0
    retries = 3
    base_delay = 0.5  # Reduced base delay
    
    while queue and pages_crawled < max_pages_per_domain and len(benign_samples) < target_samples:
        url, _ = queue.popleft()
        
        with urls_lock:
            if url in visited_urls:
                continue
            visited_urls.add(url)
        
        pages_crawled += 1
        print(f"Scraping {url} (Domain: {domain}, Page {pages_crawled}/{max_pages_per_domain}, Total Samples: {len(benign_samples)})")
        
        for attempt in range(retries):
            try:
                headers = {'User-Agent': random.choice(user_agents)}
                proxies = {'http': random.choice(proxies_list), 'https': random.choice(proxies_list)} if proxies_list else None
                response = requests.get(url, headers=headers, proxies=proxies, timeout=5)
                response.raise_for_status()
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract benign HTML snippets
                for tag in tags:
                    elements = soup.find_all(tag)
                    for elem in elements:
                        content = str(elem).replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
                        content = ' '.join(content.split())
                        if content and '<script' not in content.lower() and 'javascript:' not in content.lower():
                            domain_samples.add(content)
                
                # Collect links for crawling
                if pages_crawled < max_pages_per_domain:
                    for link in soup.find_all('a', href=True):
                        absolute_url = urljoin(url, link['href'])
                        parsed_url = urlparse(absolute_url)
                        if (parsed_url.scheme in ['http', 'https'] and 
                            parsed_url.netloc == domain and 
                            absolute_url not in visited_urls and 
                            pages_crawled < max_pages_per_domain):
                            queue.append((absolute_url, 0))
                
                print(f"Domain {domain} collected {len(domain_samples)} samples this page")
                time.sleep(random.uniform(base_delay, base_delay + 0.5))  # Reduced delay
                break
            
            except requests.exceptions.HTTPError as e:
                if response.status_code == 403:
                    print(f"403 Forbidden at {url}. Retrying...")
                    time.sleep(2 ** attempt)
                elif response.status_code == 429:
                    print(f"429 Too Many Requests at {url}. Slowing down...")
                    base_delay = min(base_delay + 1, 5)
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
                time.sleep(2 ** attempt)
            
            except Exception as e:
                print(f"General error processing {url}: {e}")
                break
    
    with samples_lock:
        benign_samples.update(domain_samples)
    return domain_samples

def scrape_benign_html_with_crawl(start_urls, target_samples=775974, max_pages_per_domain=20, max_workers=10):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(scrape_domain, url, target_samples, max_pages_per_domain): url for url in start_urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                future.result()
                print(f"Finished crawling {url}. Total samples: {len(benign_samples)}")
                if len(benign_samples) >= target_samples:
                    executor.shutdown(wait=False)
                    break
            except Exception as e:
                print(f"Error crawling {url}: {e}")
    
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
benign_samples = scrape_benign_html_with_crawl(urls, target_samples=775974, max_pages_per_domain=20, max_workers=10)
benign_samples.extend(manual_benign)

# Deduplicate and shuffle
benign_samples = list(set(benign_samples))
random.shuffle(benign_samples)

# Adjust to target size
if len(benign_samples) < 775974:
    print(f"Warning: Only collected {len(benign_samples)} benign samples, short of 775,974.")
    # Optional: Add synthetic samples to reach target
    shortfall = 775974 - len(benign_samples)
    for i in range(shortfall):
        synthetic = f"<{random.choice(tags)}>{random.randint(1, 1000)} {random.choice(['text', 'data', 'content'])}</{random.choice(tags)}>"
        benign_samples.append(synthetic)
    print(f"Added {shortfall} synthetic samples to reach 775,974.")

print(f"Collected {len(benign_samples)} benign samples")
for sample in benign_samples[:10]:
    print(sample)

# Save to CSV file
with open("benign_samples.csv", "w", newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    for sample in benign_samples:
        writer.writerow([sample])
print("Benign samples saved to 'benign_samples.csv'")