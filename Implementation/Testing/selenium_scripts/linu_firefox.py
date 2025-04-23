import os
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
# from selenium.webdriver.firefox.service import Service # Only needed if geckodriver not in PATH

# --- Step 5: Paste the FULL profile path you found in Step 4 here ---
profile_path = '/home/cse/firefox_selenium_profiles/tikmnc94.test' # <--- CHANGE THIS

# --- Configure Firefox Options ---
options = Options()
options.profile = profile_path

print(f"Attempting to use Firefox profile: {profile_path}")

# --- Initialize the WebDriver ---
driver = None
try:
    # Make sure geckodriver is in your PATH or uncomment and set Service path
    # service = Service(executable_path='/path/to/your/geckodriver')
    # driver = webdriver.Firefox(service=service, options=options)

    # If geckodriver is in PATH:
    driver = webdriver.Firefox(options=options)

    print("WebDriver initialized successfully with the specified profile.")

    # --- Your Selenium actions start here ---
    driver.get("https://www.google.com")
    print(f"Page Title: {driver.title}")
    # ... add your automation code ...

except Exception as e:
    print(f"An error occurred: {e}")
    if not os.path.exists(profile_path):
         print(f">>> Profile path check failed: {profile_path}")
    elif not os.path.isdir(profile_path):
         print(f">>> Profile path is not a directory: {profile_path}")


finally:
    # --- Clean up ---
    if driver:
        print("Quitting WebDriver.")
        driver.quit()
    else:
        print("WebDriver failed to initialize.")