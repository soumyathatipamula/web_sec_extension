from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# Global variable to track if an alert was handled
alert_handled = False 

# Read XSS payloads from cheatsheet file (ignoring blank lines)
with open('../../Cheatsheet/portswigger_cheatsheet.txt', 'r') as file:
    xss_payloads = [line.strip() for line in file if line.strip()]

# Configure Chrome to load your extension
extension_path = "/Users/nithin/college/web_sec_extension/Implementation/Testing/xss_detector with indexed db"  # Update this path if needed
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument(f'--load-extension={extension_path}')

# Initialize WebDriver with extension
driver = webdriver.Chrome(options=chrome_options)

# DVWA configuration (update IP if needed)
DVWA_USER = 'admin'
DVWA_PASSWORD = 'password'
DVWA_URL = 'http://192.168.29.27/DVWA/'

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
    except Exception as e:
        print("❌ Login failed.", e)
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
    except Exception as e:
        print("❌ Failed to set security level.", e)
        driver.quit()
        exit()

def handle_alert():
    global alert_handled
    try:
        WebDriverWait(driver, 3).until(EC.alert_is_present())
        alert = driver.switch_to.alert
        alert.accept()
        alert_handled = True
        print("✅ Alert accepted.")
        driver.execute_script("window.alert = function(){};")
    except Exception as e:
        alert_handled = False
        print("❌ No alert to handle.")

def get_extension_logs():
    # Handle any unexpected alerts before retrieving logs
    handle_alert()
    
    # Get the extension ID by navigating to chrome://extensions
    driver.get("chrome://extensions")
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "extensions-manager"))
    )
    script = """
        return document.querySelector("extensions-manager")
               .shadowRoot.querySelector("extensions-item-list")
               .shadowRoot.querySelector("extensions-item")
               .getAttribute("id");
    """
    extension_id = driver.execute_script(script)
    print("Extension ID:", extension_id)

    # Open the extension popup page using the retrieved extension id
    driver.get(f"chrome-extension://{extension_id}/popup.html")
    
    # Wait for the log list element (ID "log-list" as per popup.html)
    log_list_elem = WebDriverWait(driver, 20).until(
        EC.presence_of_element_located((By.ID, "log-list"))
    )
    logs_text = log_list_elem.text
    print("Extension logs retrieved.")

    # Optional: Clear logs from IndexedDB after retrieval
    driver.execute_script("""
        let request = indexedDB.open("xssLogs", 1);
        request.onsuccess = () => {
            let db = request.result;
            let transaction = db.transaction("xssLogs", "readwrite");
            let store = transaction.objectStore("xssLogs");
            store.clear();
        };
    """)
    return logs_text

def test_xss_payloads():
    detected_results = []
    undetected_results = []
    
    print("\n\nStarting XSS payload tests...\n\n")
    
    for _ in range(1):
        # print(f"Attack vector {i+1}: {payload}")
        driver.get(DVWA_URL + 'vulnerabilities/xss_r/')
        
        # Submit the payload in the vulnerable field
        input_field = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.NAME, 'name'))
        )
        input_field.clear()
        input_field.send_keys("hi")
        input_field.send_keys(Keys.RETURN)
        
        # Wait briefly for the payload to be processed and logged
        time.sleep(2)
        
        # Retrieve logs from the extension's popup (IndexedDB)
        logs = get_extension_logs()
        print("IndexedDB logs:", logs)
        
        result = f'Payload: {payload} | Detected logs: {logs} | Alert handled: {alert_handled}\n'
        if payload in logs:
            detected_results.append(result)
            print(f"✅ Detected payload: {payload}")
        else:
            undetected_results.append(result)
            print(f"❌ Missed payload: {payload}")
        
        print("\n--------------------------------------------------------------------------------------------------------------------------------\n")
    
    return detected_results, undetected_results

def main():
    login_and_set_security()
    detected, undetected = test_xss_payloads()
    driver.quit()
    
    # Save results to files
    with open('xss-detected.txt', 'w') as f:
        f.writelines(detected)
    with open('xss-undetected.txt', 'w') as f:
        f.writelines(undetected)

if __name__ == '__main__':
    main()
