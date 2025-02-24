from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# Read XSS payloads from cheatsheet file
with open('../../Cheatsheet/portswigger_cheatsheet.txt', 'r') as file:
    xss_payloads = [line.strip() for line in file.readlines()]

# Initialize the WebDriver (make sure to have the appropriate WebDriver in your PATH)
# Options for headless mode (optional but recommended)
options = webdriver.ChromeOptions()
# options.add_argument('--headless')  # Runs Chrome in the background
driver = webdriver.Chrome(options=options) # Pass the options to the driver

# DVWA credentials (consider storing these securely, not directly in the script)
DVWA_USER = 'admin'
DVWA_PASSWORD = 'password'
DVWA_URL = 'http://192.168.2.6/DVWA/'

# Function to log in to DVWA
def login_to_dvwa():
    driver.get(DVWA_URL + 'login.php')
    username_field = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.NAME, 'username'))
    )
    password_field = driver.find_element(By.NAME, 'password')
    login_button = driver.find_element(By.NAME, 'Login')

    username_field.send_keys(DVWA_USER)
    password_field.send_keys(DVWA_PASSWORD)
    login_button.click()

    # Verify successful login (optional but good practice)
    try:
      WebDriverWait(driver, 10).until(
          EC.presence_of_element_located((By.LINK_TEXT, 'Logout')) # Check for logout link
      )
      print("Successfully logged in.")

    except:
      print("Login failed.")
      driver.quit()
      exit() # Stop the script if login fails

    driver.get(DVWA_URL+"security.php")
    security_level_select = driver.find_element(By.NAME, 'security')
    security_level_select.send_keys('low')
    submit_button = driver.find_element(By.NAME, 'seclev_submit')
    submit_button.click()
    try:
        sec_info = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, 'system_info')))
        if "Security Level: low" in sec_info.text:
            print("Security level set to low.")
    except:
        print("Failed to set security level.")
        driver.quit()
        exit()
        

# Function to test XSS payloads
def test_xss_payloads():
    payload = "<script>alert(1)</script>"
    detected_results = []
    undetected_results = []
    driver.get(DVWA_URL + 'vulnerabilities/xss_r/')

    input_field = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.NAME, 'name'))
    )
    input_field.clear()
    input_field.send_keys(payload)
    input_field.send_keys(Keys.RETURN)

    # Use WebDriverWait for dynamic content
    try:
        alert = WebDriverWait(driver, 5).until( # Wait up to 5 seconds
            EC.alert_is_present() # Check for an alert
        )
        
        alert_text = alert.text
        print(alert_text)
        detected = True
        alert.accept() # Dismiss the alert
    except:
        detected = False
        alert_text = "No alert"

    result = f'Payload: {payload}\nDetected: {detected}\nAlert Text: {alert_text}\n'

    if detected:
        detected_results.append(result)
    else:
        undetected_results.append(result)

    driver.get(DVWA_URL + 'vulnerabilities/xss_r/') # Return to the page for next test

    return detected_results, undetected_results


# Main function
def main():
    login_to_dvwa()
    detected_results, undetected_results = test_xss_payloads()
    driver.quit()

    # Save results to files (improved file writing)
    def write_results(filename, results):
        with open(filename, 'w', encoding='utf-8') as file:  # Handle special characters
            file.write('\n'.join(results))

    write_results('xss-detected-results.txt', detected_results)
    write_results('xss-undetected-results.txt', undetected_results)

if __name__ == '__main__':
    main()