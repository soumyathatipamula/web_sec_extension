import requests
from bs4 import BeautifulSoup
import random
import csv
import time

tags = [
    "a", "a2", "abbr", "acronym", "address", "animate", "animatemotion", "animatetransform",
    "applet", "area", "article", "aside", "audio", "audio2", "b", "bdi", "bdo", "big",
    "blink", "blockquote", "body", "br", "button", "canvas", "caption", "center", "cite",
    "code", "col", "colgroup", "command", "content", "custom tags", "data", "datalist",
    "dd", "del", "details", "dfn", "dialog", "dir", "div", "dl", "dt", "element", "em",
    "embed", "fieldset", "figcaption", "figure", "font", "footer", "form", "frame",
    "frameset", "h1", "head", "header", "hgroup", "hr", "html", "i", "iframe", "iframe2",
    "image", "image2", "image3", "img", "img2", "input", "input2", "input3", "input4",
    "ins", "kbd", "keygen", "label", "legend", "li", "link", "listing", "main", "map",
    "mark", "marquee", "menu", "menuitem", "meta", "meter", "multicol", "nav", "nextid",
    "nobr", "noembed", "noframes", "noscript", "object", "ol", "optgroup", "option",
    "output", "p", "param", "picture", "plaintext", "pre", "progress", "q", "rb", "rp",
    "rt", "rtc", "ruby", "s", "samp", "script", "section", "select", "set", "shadow",
    "slot", "small", "source", "spacer", "span", "strike", "strong", "style", "sub",
    "summary", "sup", "svg", "table", "tbody", "td", "template", "textarea", "tfoot",
    "th", "thead", "time", "title", "tr", "track", "tt", "u", "ul", "var", "video",
    "video2", "wbr", "xmp"
]

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1'
]

def scrape_benign_html(urls, max_samples=5000):
    benign_samples = []
    for url in urls:
        print(f"Scraping {url}")
        try:
            headers = {'User-Agent': random.choice(user_agents)}
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            for tag in tags:
                elements = soup.find_all(tag)
                for elem in elements:
                    content = str(elem).replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
                    content = ' '.join(content.split())
                    if len(content) <= 100 and content:
                        benign_samples.append(content)
            time.sleep(random.uniform(1, 3)) #delay between 1 and 3 seconds.
        except requests.exceptions.RequestException as e:
            print(f"Error scraping {url}: {e}")
        except Exception as e:
            print(f"General error processing {url}: {e}")
    return benign_samples

# Expanded URLs
urls = [
    "https://www.google.com/",
    "https://www.youtube.com/",
    "https://www.facebook.com/",
    "https://www.twitter.com/",
    "https://www.instagram.com/",
    "https://www.linkedin.com/",
    "https://www.reddit.com/",
    "https://www.wikipedia.org/",
    "https://www.amazon.com/",
    "https://www.ebay.com/",
    "https://www.nytimes.com/",
    "https://www.bbc.com/",
    "https://www.cnn.com/",
    "https://www.reuters.com/",
    "https://www.nationalgeographic.com/",
    "https://www.w3schools.com/",
    "https://developer.mozilla.org/en-US/",
    "https://www.techcrunch.com/",
    "https://www.wired.com/",
    "https://www.scientificamerican.com/",
    "https://news.google.com/",
    "https://www.espn.com/",
    "https://www.nasa.gov/",
    "https://www.nature.com/",
    "https://www.economist.com/",
    "https://www.theguardian.com/international",
    "https://www.bloomberg.com/",
    "https://www.forbes.com/",
    "https://www.wsj.com/",
    "https://www.cnet.com/",
    "https://www.pcmag.com/",
    "https://www.tomshardware.com/",
    "https://www.techradar.com/",
    "https://www.engadget.com/",
    "https://arstechnica.com/",
    "https://digg.com/",
    "https://www.smashingmagazine.com/",
    "https://www.phoronix.com/",
    "https://www.imdb.com/",
    "https://www.rottentomatoes.com/",
    "https://www.goodreads.com/",
    "https://www.britannica.com/",
    "https://www.merriam-webster.com/",
    "https://www.dictionary.com/",
    "https://www.weather.com/",
    "https://www.accuweather.com/",
    "https://www.cdc.gov/",
    "https://www.who.int/",
    "https://www.nih.gov/",
    "https://www.fda.gov/",
    "https://www.irs.gov/",
    "https://www.census.gov/",
    "https://www.usps.com/",
    "https://www.fedex.com/",
    "https://www.ups.com/",
    "https://www.booking.com/",
    "https://www.expedia.com/",
    "https://www.airbnb.com/",
    "https://www.tripadvisor.com/",
    "https://www.yelp.com/",
    "https://www.zillow.com/",
    "https://www.realtor.com/",
    "https://www.autotrader.com/",
    "https://www.cars.com/",
    "https://www.craigslist.org/",
    "https://www.indeed.com/",
    "https://www.monster.com/",
    "https://www.glassdoor.com/",
    "https://www.quora.com/",
    "https://www.stackexchange.com/",
    "https://www.medium.com/",
    "https://www.vimeo.com/",
    "https://soundcloud.com/",
    "https://www.twitch.tv/",
    "https://www.deviantart.com/",
    "https://www.behance.net/",
    "https://dribbble.com/",
    "https://www.etsy.com/",
    "https://www.shopify.com/",
    "https://www.wordpress.org/",
    "https://www.joomla.org/",
    "https://www.drupal.org/",
    "https://www.python.org/",
    "https://www.java.com/",
    "https://www.microsoft.com/",
    "https://www.apple.com/",
    "https://www.oracle.com/",
    "https://www.ibm.com/",
    "https://www.intel.com/",
    "https://www.amd.com/",
    "https://www.nvidia.com/",
    "https://www.tesla.com/",
    "https://www.spacex.com/",
    "https://www.boeing.com/",
    "https://www.airbus.com/",
    "https://www.lego.com/",
    "https://www.mattel.com/",
    "https://www.nike.com/",
    "https://www.adidas.com/",
    "https://www.gap.com/",
    "https://www.hm.com/",
    "https://www.uniqlo.com/",
    "https://www.ikea.com/"
]


# Manual examples
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

benign_samples = scrape_benign_html(urls, max_samples=10000)
benign_samples.extend(manual_benign)

# Shuffle and limit
random.shuffle(benign_samples)
# benign_samples = benign_samples[:10000]

print(f"Collected {len(benign_samples)} benign samples")
for sample in benign_samples[:10]:
    print(sample)

# Save to file
f = open("benign_samples.csv", "w", newline='', encoding='utf-8')

writer = csv.writer(f)

for sample in benign_samples:
    writer.writerow([sample])

f.close()