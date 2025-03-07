from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import time
from random import randint

# Read XSS payloads from cheatsheet file (if needed)
with open('../../Cheatsheet/portswigger_cheatsheet.txt', 'r') as file:
    xss_payloads = [line.strip() for line in file.readlines()]

# Configure Chrome to load your extension
extension_path = "/Users/nithin/college/web_sec_extension/Implementation/Testing/xss_detector with indexed db"  # Update this path
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument(f'--load-extension={extension_path}')

# Initialize WebDriver with extension and logging capabilities
driver = webdriver.Chrome(options=chrome_options)

# DVWA configuration (update IP if needed)
DVWA_USER = 'admin'
DVWA_PASSWORD = 'password'
DVWA_URL = 'http://192.168.1.113/DVWA/'

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

def handle_alert():
    try:
        alert = driver.switch_to.alert
        alert.accept()
        print("✅ Alert accepted.")
    except:
        # No alert to handle
        print("❌ No alert to handle.")

def get_extension_logs():
    handle_alert()  # Handle any unexpected alerts before getting logs
    print("Waiting for extension to store payload...")
    # time.sleep(2)  # Wait for the extension to store the payload

    logs = driver.execute_async_script("""
        var callback = arguments[arguemnts.length - 1];
        var request = indexedDB.open('xssLogs', 1);  // Ensure the version matches the existing version
        request.onsuccess = (event) =>  {
            var db = event.target.result;
            var transaction = db.transaction(['xssLogs'], 'readonly');
            var objectStore = transaction.objectStore('xssLogs');
            var data = [];
            var cursorRequest = objectStore.openCursor();
            cursorRequest.onsuccess = function(event) {
                cursor = cursorRequest.result;
                if(cursor) {
                    data.push(cursor.value);
                    cursor.continue();
                }
                else{
                    callback(data);
                }
            };
            cursorRequest.onerror = function(event) {
                console.log("Error getting all records:", event.target.error);
                callback([]);
            };
        };
        request.onerror = function(event) {
            console.log("Error opening IndexedDB:", event.target.error);
            callback([]);
        };
    """)
    print("logs code executed")

    return logs

def test_xss_payloads():
    detected_results = []
    undetected_results = []
    
    # Here, we test one payload. You can adjust the range if needed.
    for _ in range(1):
        driver.get(DVWA_URL + 'vulnerabilities/xss_r/')
        
        # Generate a unique XSS payload
        random_number = randint(0, 10000000)
        payload = f"<script>alert('{random_number}')</script>"
        
        # Submit payload
        input_field = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.NAME, 'name'))
        )
        input_field.clear()
        input_field.send_keys(payload)
        input_field.send_keys(Keys.RETURN)
        
        # Wait a few seconds for the extension to detect and store the payload
        # Retrieve logs from IndexedDB using the extension's storage
        logs = get_extension_logs()
        print("IndexedDB logs:", logs)
        
        # Depending on how your extension sends data, records may be stored as objects or raw strings.
        # Adjust the check accordingly:
        detected = any(
            (isinstance(log, dict) and log.get('payload') == payload) or (log == payload)
            for log in logs
        )
        
        result = f'Payload: {payload}\nDetected: {detected}\n'
        if detected:
            detected_results.append(result)
            print(f"✅ Detected payload: {payload}")
        else:
            undetected_results.append(result)
            print(f"❌ Missed payload: {payload}")

    return detected_results, undetected_results

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
