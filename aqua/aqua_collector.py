from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
import os
import time
import json
import logger as lg
import requests
from tqdm import tqdm

# def save_html(url, output_dir):
#     """Fetch and save the rendered HTML content of a URL to a file."""
#     # Set up Chrome options
#     chrome_options = Options()
#     # chrome_options.add_argument("--headless")  # Run in headless mode (no browser UI)
#     # chrome_options.add_argument("--disable-gpu")
#     chrome_options.add_argument("--no-sandbox")

#     # Set up Chrome driver
#     service = Service("chromedriver-linux64/chromedriver")  # Replace with the path to your ChromeDriver
#     driver = webdriver.Chrome(service=service, options=chrome_options)

#     try:
#         # Load the page and wait for it to render
#         driver.get(url)
#         time.sleep(5)  # Wait for JavaScript to finish (adjust as necessary)

#         # Get the rendered HTML content
#         html_content = driver.page_source

#         # Generate a valid filename from the URL
#         filename =  "sele" + url.replace("https://", "").replace("http://", "").replace("/", "_") + ".html"
#         filepath = os.path.join(output_dir, filename)

#         # Save the HTML content to the file
#         with open(filepath, "w", encoding="utf-8") as file:
#             file.write(html_content)

#         print(f"Rendered HTML content saved to {filepath}")
#         return filepath

#     except Exception as e:
#         print(f"Error loading URL {url}: {e}")
#         return None

#     finally:
#         driver.quit()


logger = lg.generate_logger("aqua", "aqua.log")


def save_html(cve_id, url, output_dir):
    """Fetch and save the HTML content of a URL to a file."""
    try:
        # Fetch the HTML content
        response = requests.get(url)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        # Generate a valid filename from the URL
        filename = cve_id + ".html"
        filepath = os.path.join(output_dir, filename)

        # Save the HTML content to the file
        with open(filepath, "w", encoding="utf-8") as file:
            file.write(response.text)

        logger.info(f"HTML content saved to {filepath}")
        # print(f"HTML content saved to {filepath}")
        return filepath

    except requests.RequestException as e:
        logger.error(f"Error fetching URL {url}: {e}")
        print(f"Error fetching URL {url}: {e}")
        return None



def read_nvd_data_feed(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
    return data


def main():
    """Main function to demonstrate the usage of save_html."""

    years = ["2024", "2023", "2022", "2021", "2020"]

    for year in years:
        # Directory to save HTML files
        output_dir = year
        os.makedirs(output_dir, exist_ok=True)

        logger.info(f"Staring collecting the information of CVEs for {year}")
        print(f"Staring collecting the information of CVEs for {year}")

        cve_list = read_nvd_data_feed(f'../nvdcve-1.1-{year}.json')
        cve_list = cve_list['CVE_Items']
        ids = [cve_list[i]['cve']['CVE_data_meta']['ID'] for i in range(len(cve_list))]
        urls = {cve_id: f"https://avd.aquasec.com/nvd/{year}/{cve_id.lower()}/" for cve_id in ids}

        for cve_id, url in tqdm(urls.items()):
            save_html(cve_id, url, output_dir)

        logger.info(f"Finished collecting the information of CVEs for {year}")


if __name__ == "__main__":
    main()
