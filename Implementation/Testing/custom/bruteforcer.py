import requests
from bs4 import BeautifulSoup

def test_xss(url, vector):
  """
  Sends a request to the target URL with the given XSS vector, 
  analyzes the response, and returns True if XSS appears to be successful.

  Args:
    url: The URL of the vulnerable page.
    vector: The XSS payload to inject.

  Returns:
    True if XSS appears to be successful, False otherwise.
  """
  try:
    response = requests.get(url.format(vector))
    response.raise_for_status() 
    soup = BeautifulSoup(response.content, "html.parser")

    # Basic check for the presence of the injected script 
    # (adjust this based on the specific vector and expected behavior)
    if vector in str(soup): 
      return True 
  except requests.exceptions.RequestException as e:
    print(f"Error occurred: {e}")
  return False

# Load XSS vectors from the cheat sheet
with open("xss_vectors.txt", "r") as f:
  xss_vectors = f.readlines()

# URL of the vulnerable page (replace with the actual URL)
vulnerable_url = "http://your-test-website.com/vulnerable-page?input={}" 

for vector in xss_vectors:
  vector = vector.strip()  # Remove any leading/trailing whitespace
  if test_xss(vulnerable_url, vector):
    print(f"XSS successful with vector: {vector}")
  else:
    print(f"XSS not successful with vector: {vector}")