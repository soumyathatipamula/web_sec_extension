from selenium import webdriver
from selenium.webdriver.common.by import By

driver = webdriver.Chrome()
driver.get("https://www.selenium.dev/selenium/web/web-form.html")

title = driver.title
driver.implicitly_wait(5)
text_box = driver.find_element(By.NAME, "my-text")
submit_button = driver.find_element(By.CSS_SELECTOR, "button" )

text_box.send_keys ("Hello, World!")
submit_button.click()

message = driver.find_element(By.ID, "mesasge")
text = message.text
print(text)
driver.quit()
