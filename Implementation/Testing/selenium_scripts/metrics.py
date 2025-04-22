from selenium import webdriver
from selenium.webdriver.firefox.options import Options

def test_basic_options():
    options = Options()
    firefox_path = "/usr/bin/firefox"  # Replace this with the *exact* output of `which firefox`
    options.binary_location = firefox_path

    try:
        driver = webdriver.Firefox(options=options)
        print("Firefox started successfully!") # Add this line for confirmation
        # Your test logic here
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if 'driver' in locals() and driver is not None:
            driver.quit()

if __name__ == "__main__":
    test_basic_options()#