from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
from random import randint

# Read XSS payloads from cheatsheet file
with open('../../Cheatsheet/portswigger_cheatsheet.txt', 'r') as file:
    xss_payloads = [line.strip() for line in file.readlines()]

# Configure Chrome to load your extension
extension_path = "../xss_detector"  # Update this path
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument(f'--load-extension={extension_path}')

# Initialize WebDriver with extension
driver = webdriver.Chrome(options=chrome_options)

# DVWA configuration (update IP if needed)
DVWA_USER = 'admin'
DVWA_PASSWORD = 'password'
DVWA_URL = 'http://192.168.2.4/DVWA/'

# Function to log in and set security level
def login_and_set_security():
    # Log in to DVWA
    driver.get(DVWA_URL + 'login.php')
    username_field = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.NAME, 'username'))
    )
    password_field = driver.find_element(By.NAME, 'password')
    login_button = driver.find_element(By.NAME, 'Login')

    username_field.send_keys(DVWA_USER)
    password_field.send_keys(DVWA_PASSWORD)
    login_button.click()

    # Verify login success
    try:
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.LINK_TEXT, 'Logout'))
        )
        print("✅ Logged in successfully.")
    except:
        print("❌ Login failed.")
        driver.quit()
        exit()

    # Set security level to "low"
    driver.get(DVWA_URL + "security.php")
    security_level = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.NAME, 'security'))
    )
    security_level.send_keys('low')
    driver.find_element(By.NAME, 'seclev_submit').click()

    # Confirm security level
    try:
        WebDriverWait(driver, 10).until(
            EC.text_to_be_present_in_element((By.ID, 'system_info'), 'Security Level: low')
        )
        print("✅ Security level set to 'low'.")
    except:
        print("❌ Failed to set security level.")
        driver.quit()
        exit()

# Function to handle unexpected alerts
def handle_alert():
    try:
        alert = driver.switch_to.alert
        alert.accept()
        print("✅ Alert accepted.")
    except:
        print("❌ No alert present.")

# Function to check extension's XSS logs
def get_extension_logs():
    handle_alert()  # Handle any unexpected alerts before getting logs

    value = driver.execute_script("""
                    request = indexedDB.open('xssLogs');
""")
    if value:
        return value
    else:
        return []

# Function to test XSS payloads
def test_xss_payloads():
    detected_results = []
    undetected_results = []
    
    for payload in range(1):
        driver.get(DVWA_URL + 'vulnerabilities/xss_r/')
        
        # Submit payload
        input_field = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.NAME, 'name'))
        )
        input_field.clear()
        input_field.send_keys(f"<script>alert('{randint(0,10000000)}')</script>")
        input_field.send_keys(Keys.RETURN)
        
        # Wait for extension to detect
        # time.sleep(2)  # Adjust based on extension's response time
        # Check extension logs
        logs = get_extension_logs()
        print(logs)
        detected = any(log['payload'] == payload for log in logs)
        
        # Record results
        result = f'Payload: {payload}\nDetected: {detected}\n'
        if detected:
            detected_results.append(result)
            print(f"✅ Detected: {payload}")
        else:
            undetected_results.append(result)
            print(f"❌ Missed: {payload}")

        # Clear storage for next test
        driver.execute_script("chrome.storage.local.set({ xssLogs: [] });")

    return detected_results, undetected_results

# Main function
def main():
    login_and_set_security()
    detected, undetected = test_xss_payloads()
    driver.quit()

    # Save results
    with open('xss-detected.txt', 'w') as f:
        f.writelines(detected)
    with open('xss-undetected.txt', 'w') as f:
        f.writelines(undetected)

if __name__ == '__main__':
    main()