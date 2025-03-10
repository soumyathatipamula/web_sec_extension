from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.chrome.options import Options
import time
from random import randint

alert = False 

# Read XSS payloads from cheatsheet file (if needed)
with open('../../Cheatsheet/portswigger_cheatsheet.txt', 'r') as file:
    xss_payloads = [line.strip() for line in file.readlines()]

# Configure Chrome to load your extension
extension_path = "/Users/nithin/college/web_sec_extension/Implementation/Testing/xss_detector with indexed db"  # Update this path
chrome_options = webdriver.ChromeOptions()
# chrome_options.add_argument("--headless")
# driver = webdriver.Chrome(options=chrome_options)
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
    global alert
    try:
        WebDriverWait(driver, 1).until(EC.alert_is_present())
        alert = driver.switch_to.alert
        alert.accept()
        alert = True
        print("✅ Alert accepted.")
    except:
        # No alert to handle
        alert = False
        print("❌ No alert to handle.")

def get_extension_logs():
    handle_alert()  # Handle any unexpected alerts before getting logs
    
    #getting the extension id
    driver.get("chrome://extensions") #Opening the extension manager
    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "extensions-manager")))
    script = """
        return document.querySelector("extensions-manager")
               .shadowRoot.querySelector("extensions-item-list")
               .shadowRoot.querySelector("extensions-item")
               .getAttribute("id")
    """
    extension_id = driver.execute_script(script)

    #Verifying with extension id
    driver.get(f"chrome-extension://{extension_id}/popup.html")

    # Wait till extension detects the payload
    log_list = ""
    try :
        log_list = WebDriverWait(driver, 1).until(EC.presence_of_element_located((By.ID, "payload")))
    except:
        print("No logs detected")
        return ""

    driver.execute_script("""
    var logs = [];

    let request = indexedDB.open("xssLogs", 1);

    request.onsuccess = () => {
        let db = request.result;
        let transaction = db.transaction("xssLogs", "readwrite");
        let store = transaction.objectStore("xssLogs");

        store.clear();
    }
    """)

    return log_list.text

def HTML_convertion(text):
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    driver = webdriver.Chrome(options=chrome_options)
    # Open a blank page so that we have a DOM to work with.
    driver.get("data:text/html,<html></html>")
    script = """
    var payload = arguments[0];
    var parser = new DOMParser();
    var doc = parser.parseFromString(payload, 'text/html');
    // Return the normalized outerHTML of the first element in the body
    return doc.body.firstChild.outerHTML;
    """
    converted_text =  driver.execute_script(script, text)
    driver.quit()
    return converted_text

def test_xss_payloads():
    detected_results = []
    undetected_results = []
    
    print("\n\nStarting XSS payload tests...\n\n")

    for i, payload in (enumerate(xss_payloads)):
        detected_payload = ""
        print(f"Attack vector {i+1}")
        driver.get(DVWA_URL + 'vulnerabilities/xss_r/')
        

        
        # Submit payload
        input_field = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.NAME, 'name'))
        )
        input_field.clear()
        input_field.send_keys(payload)
        input_field.send_keys(Keys.RETURN)
        
        # Retrieve logs from IndexedDB using the extension's storage
        logs = get_extension_logs()
        print("IndexedDB logs:", logs)
        
        # Depending on how your extension sends data, records may be stored as objects or raw strings.
        # Adjust the check accordingly:
        if logs:
            detected_payload = logs.split(": ")[1]
            converted_payload = HTML_convertion(payload)
            print("Converted payload:", converted_payload)
        
        result = f'Payload: {payload} | Detected: {detected_payload} | Alert: {alert}\n'
        # print(f"{logs} \n {converted_payload} \n {detected_payload.find(converted_payload)}")
        if logs :#and ((detected_payload.find(converted_payload)) != -1):
            detected_results.append(result)
            print(f"✅ Detected payload: {payload}")
        else:
            undetected_results.append(f'Payload: {payload} | Alert: {alert}\n')
            print(f"❌ Missed payload: {payload}")
        
        print("\n------------------------------------------------------------------------------------------\n")

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
