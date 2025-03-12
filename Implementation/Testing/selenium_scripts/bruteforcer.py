from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoAlertPresentException, TimeoutException
import time


is_alert = False 

#opening the files
detected_file = open('xss-detected(594:709]+xss_payloads[935:).txt', 'w')
undetected_file = open('xss-undetected(594:709]+xss_payloads[935:).txt', 'w')
cant_perform = open('cant-perform(594:709]+xss_payloads[935:).txt', 'w')

# Read XSS payloads from cheatsheet file (if needed)
with open('../../Cheatsheet/xss_vectors_kurobeats.txt', 'r') as file:
# with open('../../Cheatsheet/portswigger_cheatsheet.txt', 'r') as file:
# with open('./my_cheatsheet', 'r') as file:
    xss_payloads = [line.strip() for line in file.readlines()]

# Configure Chrome to load your extension
extension_path = "/Users/nithin/college/web_sec_extension/Implementation/Testing/xss_detector with indexed db"  # Update this path
chrome_options = webdriver.ChromeOptions()
# chrome_options.add_argument("--headless")
chrome_options.add_argument(f'--load-extension={extension_path}')

# Initialize WebDriver with extension
driver = webdriver.Chrome(options=chrome_options)

# driver.set_page_load_timeout(30)
# DVWA configuration (update IP if needed)
DVWA_USER = 'admin'
DVWA_PASSWORD = 'password'
DVWA_URL = 'http://192.168.29.156/DVWA/'

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

def handle_alert(payload):
    print("Handling alerts")
    global is_alert
    # while True:
    try:
        # Wait for an alert to appear (timeout: 1 second)
        WebDriverWait(driver, 4).until(EC.alert_is_present())
        alert = driver.switch_to.alert
        alert.accept()  # Close the alert
        is_alert = True
        print("✅ Alert accepted.")
    except NoAlertPresentException:
        # No alert found within the timeout, exit the loop
        print("❌ No more alerts to handle.")
        # break
    except TimeoutException:
        # No alert found within the timeout, exit the loop
        print("❌ timeoutexeption : No more alerts to handle.")
        # break
    except Exception as e:
        print("❌ other : No more alerts to handle.")
        cant_perform.write(f"{payload} | {e}")
        # break


def get_extension_logs(payload):
    global is_alert
    handle_alert(payload)  # Handle any unexpected alerts before getting logs
    
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
        log_list = WebDriverWait(driver, 2).until(EC.presence_of_element_located((By.ID, "payload")))
    except:
        print("No logs detected")
        return ""

    driver.execute_script("""
    let request = indexedDB.open("xssLogs", 1);

    request.onsuccess = () => {
        let db = request.result;
        let transaction = db.transaction("xssLogs", "readwrite");
        let store = transaction.objectStore("xssLogs");

        store.clear();
    }
    """)

    return log_list.text

def test_xss_payloads():
    global is_alert
    
    print("\n\nStarting XSS payload tests...\n\n")

    for i, payload in (enumerate(xss_payloads[594:709]+xss_payloads[935:], start=709)):
        try:
            is_alert = False
            print(f"Attack vector {i+1}")
            driver.get(DVWA_URL + 'vulnerabilities/xss_r/')
            
            # Submit payload
            input_field = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.NAME, 'name'))
            )
            input_field.clear()
            input_field.send_keys(payload)
            input_field.send_keys(Keys.RETURN)
            print("pressed ")
        # Retrieve logs from IndexedDB using the extension's storage
            logs = get_extension_logs(payload)
            print("IndexedDB logs:", logs)
        except Exception as e:
            cant_perform.write(f"{payload} | {e}")
        
        result = f'Payload: {payload} | Alert: {is_alert}\n'
        # print(f"{logs} \n {converted_payload} \n {detected_payload.find(converted_payload)}")
        if logs :#and ((detected_payload.find(converted_payload)) != -1):
            detected_file.write(result)
            print(f"✅ Detected payload: {payload}")
        else:
            undetected_file.write(result)
            print(f"❌ Missed payload: {payload}")
        
        print("\n------------------------------------------------------------------------------------------\n")

def main():
    login_and_set_security()
    test_xss_payloads()
    driver.quit()

if __name__ == '__main__':
    main()