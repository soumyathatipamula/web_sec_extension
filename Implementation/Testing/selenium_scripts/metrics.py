from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoAlertPresentException
from selenium.webdriver.common.keys import Keys
import os
import csv
import pandas

is_alert = False

# loading the xss payloads
xss = pandas.read_csv("../../Dataset_prep/CNN+VAE/base_xss_payloads.csv")
xss_payloads = xss["payload"].tolist()

extension_path = "../traditional_method/Major_project/Major_project.xpi"  # Update this path to your extension's .xpi file

firefox_options = webdriver.FirefoxOptions()
# firefox_options.add_argument("--headless")  # Run in headless mode (no GUI)
driver = webdriver.Firefox(options=firefox_options)
driver.install_addon(extension_path, temporary=True)


def get_extension_uuid():
    driver.get("about:debugging#/runtime/this-firefox")
    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "dt")))
    dt_elements = driver.find_elements(By.TAG_NAME, "dt")

    ext_id = None
    for dt in dt_elements:
        if dt.text.strip() == "Internal UUID":
            ext_id = dt.find_element(By.XPATH, "following-sibling::dd[1]").text
            break
    
    if ext_id is None:
        return 
    return ext_id

ext_id = get_extension_uuid()
print("Extension ID:", ext_id)
extension_url = f"moz-extension://{ext_id}/popup.html"
driver.get(extension_url)

def test_with_sudo():
    driver.get(sudo_url)
    email = driver.find_element(By.NAME, "email")
    email.send_keys("<script>alert('XSS')</script>")
    email.send_keys(Keys.RETURN)
    # driver.get(extension_url)
    print(get_extension_logs())
    driver.quit()

sudo_url = "https://sudo.co.il/xss/level0.php"

driver.get(extension_url)

DVWA_USER = 'admin'
DVWA_PASSWORD = 'password'
DVWA_URL = 'http://192.168.29.169/DVWA/'

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

logs = open("logs.csv", "w", newline='' )

writer = csv.writer(logs)
writer.writerow(["Payload", "Alert", "Detected"])

        

def handle_alert(payload):
    print("Handling alerts")
    global is_alert
    # while True:
    try:
        # Wait for an alert to appear (timeout: 1 second)
        WebDriverWait(driver, 2).until(EC.alert_is_present())
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
        writer.writerow([payload, is_alert, 2])
        # break

# def get_extension_logs(payload):
def get_extension_logs():
    global is_alert
    # handle_alert(payload)  # Handle any unexpected alerts before getting logs
    
    #getting the extension id
    driver.get(extension_url) #Opening the extension manager

    # Wait till extension detects the payload
    log_list = ""
    try :
        log_list = WebDriverWait(driver, 2).until(EC.presence_of_element_located((By.ID, "originalPayload")))
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

def test_xss_payloads_dvwa():
    global is_alert
    
    print("\n\nStarting XSS payload tests...\n\n")

    for i, payload in (enumerate(xss_payloads)):
        is_alert = False
        logs = ""
        try:
            print(f"Attack vector {i+1}")
            driver.get(DVWA_URL + 'vulnerabilities/xss_r/')
            
            # Submit payload
            input_field = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.NAME, 'name'))
            )
            input_field.clear()
            input_field.send_keys(payload)
            input_field.send_keys(Keys.RETURN)
            print("pressed")
        # Retrieve logs from IndexedDB using the extension's storage
            logs = get_extension_logs(payload)
            print("IndexedDB logs:", logs)
        except Exception as e:
            writer.writerow([payload, is_alert, 2])
        
        result = f'Payload: {payload} | Alert: {is_alert}\n'
        # print(f"{logs} \n {converted_payload} \n {detected_payload.find(converted_payload)}")
        if logs :#and ((detected_payload.find(converted_payload)) != -1):
            writer.writerow([payload, is_alert, 1])
            print(f"✅ Detected payload: {payload}")
        else:
            writer.writerow([payload, is_alert, 0])
            print(f"❌ Missed payload: {payload}")
        
        print("\n------------------------------------------------------------------------------------------\n")

def test_xss_payloads_sudo():
    global is_alert
    
    print("\n\nStarting XSS payload tests...\n\n")

    for i, payload in (enumerate(xss_payloads)):
        is_alert = False
        logs = ""
        try:
            print(f"Attack vector {i+1}")
            driver.get(sudo_url)
            print(payload)
            # Submit payload
            input_field = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.NAME, 'email'))
            )
            input_field.clear()
            input_field.send_keys(payload)
            input_field.send_keys(Keys.RETURN)
            print("pressed")
        # Retrieve logs from IndexedDB using the extension's storage
            logs = get_extension_logs(payload)
            print("IndexedDB logs:", logs)
        except Exception as e:
            writer.writerow([payload, is_alert, 2])
        
        # result = f'Payload: {payload} | Alert: {is_alert}\n'
        # print(f"{logs} \n {converted_payload} \n {detected_payload.find(converted_payload)}")
        if logs :#and ((detected_payload.find(converted_payload)) != -1):
            writer.writerow([payload, is_alert, 1])
            print(f"✅ Detected payload: {payload}")
        else:
            writer.writerow([payload, is_alert, 0])
            print(f"❌ Missed payload: {payload}")
        
        print("\n------------------------------------------------------------------------------------------\n")






def main():
    # login_and_set_security()
    # test_xss_payloads_dvwa()
    test_xss_payloads_sudo()
    # test_with_sudo()
    driver.quit()

if __name__ == '__main__':
    main()