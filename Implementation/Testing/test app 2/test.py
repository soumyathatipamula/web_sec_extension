import requests
from bs4 import BeautifulSoup
import urllib.parse

def test_xss(url, vector, request_method="GET", data=None, target_element_id=None):
    try:
        encoded_vector = urllib.parse.quote(vector)
        if request_method == "GET":
            full_url = url + encoded_vector  # Already formatted in the calling function
            response = requests.get(full_url)
        elif request_method == "POST":
            response = requests.post(url, data=data)
        else:
            raise ValueError("Invalid request method")

        response.raise_for_status()  # Check for HTTP errors

        if target_element_id:
            soup = BeautifulSoup(response.content, "html.parser")
            target_element = soup.find(id=target_element_id)

            if target_element and encoded_vector in str(target_element):  # Check encoded vector
                return True  # XSS successful (encoded vector found in target)

            # Check for decoded vector if encoded is not found.
            if target_element and vector in str(target_element):  # Check decoded vector
                return True  # XSS successful (decoded vector found in target)

            return False #XSS not successful
        else:
            soup = BeautifulSoup(response.content, "html.parser")

            # Example checks (adapt these based on your vectors' effects)
            if "alert(" in str(soup):  # Basic alert check
                return True
            # Add more checks as needed (checking for specific elements, etc.)
            return False #XSS not successful

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False  # Return False on error

base_url = "http://127.0.0.1:5000/"

with open("xss_vectors.txt", "r") as f:
    xss_vectors = [line.strip() for line in f]

for vector in xss_vectors:
    # Reflected XSS (GET)
    reflected_url = base_url + "?user_input="
    reflected_url += urllib.parse.quote(vector)

    if test_xss(reflected_url, vector):
        print(f"Reflected XSS successful: {vector}")
    else:
        print(f"Reflected XSS NOT successful: {vector}")


    # Event Handler XSS (POST)
    event_handler_data = {"event_handler": vector}
    if test_xss(base_url, vector, request_method="POST", data=event_handler_data, target_element_id="event_handler_test"):
        print(f"Event Handler XSS successful: {vector}")
    else:
        print(f"Event Handler XSS NOT successful: {vector}")

    # Attribute XSS (POST)
    attribute_data = {"attribute": vector}
    if test_xss(base_url, vector, request_method="POST", data=attribute_data, target_element_id="attribute_test"):
        print(f"Attribute XSS successful: {vector}")
    else:
        print(f"Attribute XSS NOT successful: {vector}")

    # Tag XSS (POST)
    tag_data = {"tag": vector}
    if test_xss(base_url, vector, request_method="POST", data=tag_data, target_element_id="tag_test"):
        print(f"Tag XSS successful: {vector}")
    else:
        print(f"Tag XSS NOT successful: {vector}")