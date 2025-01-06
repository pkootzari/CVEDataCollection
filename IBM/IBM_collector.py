from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import os
import time
import json
import logger as lg
import requests
from tqdm import tqdm
import threading
import queue


THREATS_NUMBER = 2


logger = lg.generate_logger("IBM", "IBM.log")


# Define a custom exception
class RateLimitReached(Exception):
    def __init__(self, message=""):
        super().__init__(message)  # Initialize the base class with a message
        self.message = message


def if_file_exists(directory, filename):
    files_in_directory = os.listdir(directory)

    # Loop through each file and check if the specific file exists
    for file in files_in_directory:
        if file == filename:
            return True
    return False


def generate_url_queue(urls, output_directory):
    q = queue.Queue()
    
    existing_file_set = set(os.listdir(output_directory))
    for cve_id, url in urls.items():
        if f"{cve_id}.html" in existing_file_set:
            continue
        else:
            q.put((cve_id, url))
    
    return q


def collect_info(url_queue, output_dir, progress_bar):
    # Set up Chrome options
    chrome_options = Options()
    # chrome_options.add_argument("--headless")  # Run in headless mode (no browser UI)
    # chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    # Set up Chrome driver
    service = Service("chromedriver-linux64/chromedriver")  # Replace with the path to your ChromeDriver
    driver = webdriver.Chrome(service=service, options=chrome_options)

    input("Please login to IBM")

    working = True

    # for cve_id, url in list(urls.items())[start_index:end_index]:
    while not url_queue.empty():
        cve_id, url = url_queue.get(timeout=1)
        
        try:
            has_description, has_remedy = save_html(driver, cve_id, url, output_dir)
            if not has_description:
                logger.error(f"HTML file for {cve_id} doesn't have description")
            progress_bar.update(1)
        except RateLimitReached as e:
            working = False
            logger.error("Closed the Driver!")
            print("Closed the Driver!")
            driver.quit()
            break
        


def save_html(driver, cve_id, url, output_dir):
    """Fetch and save the rendered HTML content of a URL to a file."""
    
    try:
        # Load the page and wait for it to render
        logger.info(f"Requesting HTML content for {cve_id}")
        driver.get(url)

        title = driver.title
        if "Access Denied" in title:
            logger.error("Had to close the driver because it went in access denied mode!")
            print("Had to close the driver because it went in access denied mode!")
            raise RateLimitReached()

        time.sleep(5)  # Wait for JavaScript to finish (adjust as necessary)

        # elements = driver.find_elements(By.CSS_SELECTOR, "p.description:not([class*=' '])")
        # wait = WebDriverWait(driver, 15)
        # has_description = wait.until(
        #     lambda driver: 
        #         len(driver.find_elements(By.CSS_SELECTOR, "p.description:not([class*=' '])")) == 1 and  
        #         driver.find_element(By.CSS_SELECTOR, "p.description:not([class*=' '])").text.strip() != ""
        # )
        # has_remedy = wait.until(
        #     lambda driver: 
        #         len(driver.find_elements(By.CSS_SELECTOR, "p[class~='detailsline'][class~='description']")) == 1 and  
        #         driver.find_element(By.CSS_SELECTOR, "p[class~='detailsline'][class~='description']").text.strip() != ""
        # )

        description = driver.find_elements(By.CSS_SELECTOR, "p.description:not([class*=' '])")
        has_description = len(description) == 1 and description[0].text.strip() != ""
        # print(has_description, description.text)

        remedy = driver.find_elements(By.CSS_SELECTOR, "p[class~='detailsline'][class~='description']")
        has_remedy = len(remedy) == 1 and remedy[0].text.strip() != ""
        # print(has_remedy, remedy.text)

        # Get the rendered HTML content
        html_content = driver.page_source

        # Generate a valid filename from the URL
        filename = cve_id + ".html"
        filepath = os.path.join(output_dir, filename)

        # Save the HTML content to the file
        with open(filepath, "w", encoding="utf-8") as file:
            file.write(html_content)

        logger.info(f"Rendered HTML content saved to {filepath}")
        return has_description, has_remedy

    except RateLimitReached as e:
        logger.error("Rate Limit Reached")
        print("Rate Limit Reached")
        raise e
    except Exception as e:
        logger.error(f"Error fetching URL {url}: {e}")
        print(f"Error loading URL {url}: {e}")
        return False, False

    # finally:
    #     driver.quit()


def read_nvd_data_feed(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
    return data


def write_json(dict_input, filepath):
    with open(filepath, 'w') as file:
        json.dump(dict_input, file, indent=4)


def main():
    """Main function to demonstrate the usage of save_html."""

    # years = ["2024", "2023", "2022", "2021", "2020"]
    years = ["2024"]
    # remeber to fix the url array so that it starts from the beggining

    for year in years:
        # Directory to save HTML files
        output_dir = year
        os.makedirs(output_dir, exist_ok=True)

        logger.info(f"Staring collecting the information of CVEs for {year}")
        print(f"Staring collecting the information of CVEs for {year}")

        cve_list = read_nvd_data_feed(f'../nvdcve-1.1-{year}.json')
        cve_list = cve_list['CVE_Items']
        ids = [cve_list[i]['cve']['CVE_data_meta']['ID'] for i in range(len(cve_list))]
        urls = {cve_id: f"https://exchange.xforce.ibmcloud.com/vulnerabilities/{cve_id}/" for cve_id in ids}
        url_queue = generate_url_queue(urls, output_dir)
        queue_length = url_queue.qsize()

        print(f"url size is {len(urls)} but only {queue_length} of them are in the queue!")

        # Determine chunk size for each thread
        # chunk_size = len(urls) // THREATS_NUMBER
        # extra = len(urls) % THREATS_NUMBER  # Handle any remainder by distributing it

        # print(f"Chunck size: {chunk_size}, extras: {extra}")

        with tqdm(total=queue_length, desc="Urls", unit="number") as progress_bar:
            threads = []
            # start_idx = 0
            for i in range(THREATS_NUMBER):
                # end_idx = start_idx + chunk_size + (1 if i < extra else 0)  # Distribute the remainder
                thread = threading.Thread(target=collect_info, args=(url_queue, output_dir, progress_bar))
                threads.append(thread)
                thread.start()
                # print(f"Threat {i+1} started with index {start_idx} to {end_idx}")
                # start_idx = end_idx

            # Wait for all threads to complete
            for thread in threads:
                thread.join()


        # write_json(status, f"status{year}.json")
        logger.info(f"Finished collecting the information of CVEs for {year}")

        break


if __name__ == "__main__":
    main()
