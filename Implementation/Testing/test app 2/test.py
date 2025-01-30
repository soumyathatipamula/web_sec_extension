# ... (imports and test_xss function as before)

vulnerable_url = "http://127.0.0.1:5000/?user_input={}"

# Add more URLs for other test cases
event_handler_url = "http://127.0.0.1:5000/?event_onclick={}&event_onmouseover={}&event_onerror={}"
attribute_url = "http://127.0.0.1:5000/?attr_href={}&attr_onfocus={}"
tag_url = "http://127.0.0.1:5000/?tag_script={}&tag_iframe={}"


with open("xss_vectors.txt", "r") as f:
    xss_vectors = [line.strip() for line in f]

for vector in xss_vectors:
    # Test reflected XSS
    if test_xss(vulnerable_url, vector):
        print(f"Reflected XSS successful with: {vector}")
    else:
        print(f"Reflected XSS NOT successful with: {vector}")

    # Test event handlers
    if test_xss(event_handler_url, vector, request_method="POST", data={"event_onclick": vector, "event_onmouseover": vector, "event_onerror": vector}):
        print(f"Event Handler XSS successful with: {vector}")
    else:
        print(f"Event Handler XSS NOT successful with: {vector}")

    # Test attributes
    if test_xss(attribute_url, vector, request_method="POST", data={"attr_href": vector, "attr_onfocus": vector}):
        print(f"Attribute XSS successful with: {vector}")
    else:
        print(f"Attribute XSS NOT successful with: {vector}")

    # Test tags
    if test_xss(tag_url, vector, request_method="POST", data={"tag_script": vector, "tag_iframe": vector}):
        print(f"Tag XSS successful with: {vector}")
    else:
        print(f"Tag XSS NOT successful with: {vector}")


def test_xss(url, vector, request_method="GET", data=None):  # Added request_method and data
    try:
        encoded_vector = urllib.parse.quote(vector)
        full_url = url.format(encoded_vector)

        if request_method == "GET":
            response = requests.get(full_url)
        elif request_method == "POST":
            response = requests.post(full_url, data=data)  # Use POST and send data
        else:
            raise ValueError("Invalid request method")

        # ... (rest of the test_xss function remains the same)