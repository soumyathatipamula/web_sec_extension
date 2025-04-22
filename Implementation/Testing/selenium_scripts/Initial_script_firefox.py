#first install webdriver-manager using pip install webdriver-manager command
# selenium 4
from selenium import webdriver
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.firefox import GeckoDriverManager
import time

start_time = time.time()
driver = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()))
driver.get("https://www.google.com/")
# time.sleep(10)  # seconds




print("quiting")
driver.quit()
print("quited")
end_time = time.time()
print("Time taken to open and close the browser: ", end_time - start_time, "seconds")
print(f"{start_time} - {end_time}")