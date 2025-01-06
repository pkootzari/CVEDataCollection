import os
import json
from tqdm import tqdm
from bs4 import BeautifulSoup
from bs4 import Tag
import re


AGGREGATED_CVES_FOLDER = "CVES"
YEARS = ["2024", "2023", "2022", "2021", "2020"]


def clean_string(input_string):
    new_string = input_string.encode("ascii", "ignore").decode("ascii")
    new_string = re.sub(r'\s+', ' ', new_string).strip()
    return new_string


def read_json(filepath):
    try:
        # Try reading the file
        with open(filepath, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        # print(f"File '{filepath}' not found. Creating a new file...")
        # If the file doesn't exist, create it with default content
        with open(filepath, 'w') as file:
            json.dump({}, file)  # Creates an empty JSON object
        # Now try reading the file again
        with open(filepath, 'r') as file:
            data = json.load(file)
    return data


def write_json(dict_input, filepath):
    with open(filepath, 'w') as file:
        json.dump(dict_input, file, indent=4)


def aggregate_NVD():

    def extract_cve_id(complete_cve_record):
        ID = complete_cve_record['cve']['CVE_data_meta']['ID']
        return ID
    
    def extract_cve_english_description(complete_cve_record):
        ID = complete_cve_record['cve']['CVE_data_meta']['ID']
        description_data = complete_cve_record['cve']['description']['description_data']
        description = None
        for desc in description_data:
            if desc['lang'] == 'en':
                description = desc['value']
                break
        if description is None:
            print("no english description: ", ID)

        description = description.encode("ascii", "ignore").decode("ascii")
        description = re.sub(r'\s+', ' ', description).strip()
        return description
    
    def extract_cve_impact(complete_cve_record):
        return complete_cve_record['impact']

    for year in YEARS:
        print(f"Starting NVD data aggregation for year {year}")

        # create directory for the specific year in the result folder
        year_directory = os.path.join(AGGREGATED_CVES_FOLDER, year)
        os.makedirs(year_directory, exist_ok=True)
        
        nvd_feed = read_json(f'nvdcve-1.1-{year}.json')
        cve_items = nvd_feed['CVE_Items']
        for cve in tqdm(cve_items):
            cve_id = extract_cve_id(cve)
            try:
                cve_details_filename = os.path.join(year_directory, f"{cve_id}.json")
                cve_details = read_json(cve_details_filename)
                nvd_cve_detail = {
                    "ID": cve_id,
                    "description": extract_cve_english_description(cve),
                    "impact": extract_cve_impact(cve)
                }
                cve_details['nvd'] = nvd_cve_detail
                write_json(cve_details, cve_details_filename)
            except Exception as e:
                print(cve_id, e)
                raise e


def aggregate_aqua():
    AQUA_INFO_DIRECTORY = "aqua"

    def read_html_file_and_parse(filepath):
        with open(filepath, 'r', encoding='utf-8') as file:
            html_content = file.read()
        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
        return soup
    
    def extract_subtitle(parsed_html):
        headers = parsed_html.find_all("div", class_="header_title_wrap")
        if len(headers) != 1:
            print("There is a problem with finding the headers")
            raise Exception
        header = headers[0]
        subtitles = header.find_all("h2", class_="subtitle page_subtitle fadeInUp animationDelay_2")
        if len(subtitles) > 1:
            print("There is a problem with finding the subtitle in headers")
            raise Exception
        elif len(subtitles) == 0:
            return ""
        subtitle_text = subtitles[0].text
        return subtitle_text
    
    def extract_important_info(parsed_html):
        vul_contents = parsed_html.find_all("div", class_="content vulnerability_content")
        if len(vul_contents) != 1:
            print("something wrong with finding vul_content")
            raise Exception
        vul_content_div = vul_contents[0]

        important_info = {}
        current_info = "Basic Description"
        for child in vul_content_div.children:
            if current_info not in important_info:
                important_info[current_info] = []

            if isinstance(child, Tag) and child.name == "h3":
                current_info = child.text
                continue

            important_info[current_info].append(child.get_text())
        
        for key in important_info:
            important_info[key] = " ".join(important_info[key])
            important_info[key] = important_info[key].encode("ascii", "ignore").decode("ascii")
            important_info[key] = re.sub(r'\s+', ' ', important_info[key]).strip()
        return important_info

    for year in YEARS:
        print(f"Starting Aqua data aggregation for year {year}")
        
        # create directory for the specific year in the result folder
        year_directory = os.path.join(AGGREGATED_CVES_FOLDER, year)
        os.makedirs(year_directory, exist_ok=True)

        aqua_year_directory = os.path.join(AQUA_INFO_DIRECTORY, year)
        count = 0
        for filename in tqdm(os.listdir(aqua_year_directory)):
            filepath = os.path.join(aqua_year_directory, filename)  # Full path to the file
            # Check if it is a file (not a subdirectory)
            if (not os.path.isfile(filepath)):
                continue

            cve_id = filename.split(".")[0]
            cve_details_filename = os.path.join(year_directory, f"{cve_id}.json")
            cve_details = read_json(cve_details_filename)

            # read the HTML
            try:
                parsed_html = read_html_file_and_parse(filepath)
                subtitle = extract_subtitle(parsed_html)
                aqua_cve_details = extract_important_info(parsed_html)
                aqua_cve_details['subtitle'] = subtitle
            except Exception as e:
                print(cve_id, e)
                raise e

            cve_details['aqua'] = aqua_cve_details
            write_json(cve_details, cve_details_filename)
            count += 1
        print(f"finished {count} records for year {year}")
            

def aggregate_ubuntu():
    ubuntu_INFO_DIRECTORY = "ubuntu"

    for year in YEARS:
        print(f"Starting ubuntu data aggregation for year {year}")
        
        # create directory for the specific year in the result folder
        year_directory = os.path.join(AGGREGATED_CVES_FOLDER, year)
        os.makedirs(year_directory, exist_ok=True)

        ubuntu_year_directory = os.path.join(ubuntu_INFO_DIRECTORY, year)
        count = 0
        for filename in tqdm(os.listdir(ubuntu_year_directory)):
            filepath = os.path.join(ubuntu_year_directory, filename)  # Full path to the file
            # Check if it is a file (not a subdirectory)
            if (not os.path.isfile(filepath)):
                print("it wasn't a file")
                continue

            cve_id = filename.split(".")[0]
            cve_details_filename = os.path.join(year_directory, f"{cve_id}.json")
            cve_details = read_json(cve_details_filename)

            ubuntu_cve_record = read_json(filepath)
            ubuntu_cve_details = {
                "description": ubuntu_cve_record['Description'],
                "ubuntu_description": ubuntu_cve_record['UbuntuDescription'],
                "priority": ubuntu_cve_record['Priority']
            }

            for key in ubuntu_cve_details:
                ubuntu_cve_details[key] = clean_string(ubuntu_cve_details[key])

            cve_details['ubuntu'] = ubuntu_cve_details
            write_json(cve_details, cve_details_filename)
            count += 1
        print(f"finished {count} records for year {year}")


def aggregate_redhat():
    REDHAT_INFO_DIRECTORY = os.path.join("redhat", "api")

    for year in YEARS:
        print(f"Starting redhat data aggregation for year {year}")
        
        # create directory for the specific year in the result folder
        year_directory = os.path.join(AGGREGATED_CVES_FOLDER, year)
        os.makedirs(year_directory, exist_ok=True)

        redhat_year_directory = os.path.join(REDHAT_INFO_DIRECTORY, year)
        count = 0
        for filename in tqdm(os.listdir(redhat_year_directory)):
            filepath = os.path.join(redhat_year_directory, filename)  # Full path to the file
            # Check if it is a file (not a subdirectory)
            if (not os.path.isfile(filepath)):
                print("it wasn't a file")
                continue

            cve_id = filename.split(".")[0]
            cve_details_filename = os.path.join(year_directory, f"{cve_id}.json")
            cve_details = read_json(cve_details_filename)

            redhat_cve_record = read_json(filepath)
            if len(redhat_cve_record['details']) > 2:
                print(f"It had more than {len(redhat_cve_record['details'])} elements for details ", cve_id)
            redhat_cve_details = {
                "mitigation": redhat_cve_record['mitigation'] if 'mitigation' in redhat_cve_record else "",
                "severity": redhat_cve_record['threat_severity'],
                "bugzilla_description": redhat_cve_record['bugzilla']['description'],
                "cvss": redhat_cve_record['cvss'],
                "cvss3": redhat_cve_record['cvss3'],
                "first_description": redhat_cve_record['details'][0],
                "second_description": redhat_cve_record['details'][1] if len(redhat_cve_record['details']) > 1 else "",
                "redhat_statement":  redhat_cve_record['statement'],
                "cwe": redhat_cve_record['cwe']
            }

            for key in redhat_cve_details:
                if isinstance(redhat_cve_details[key], str):
                    redhat_cve_details[key] = clean_string(redhat_cve_details[key])

            cve_details['redhat'] = redhat_cve_details
            write_json(cve_details, cve_details_filename)
            count += 1
        print(f"finished {count} records for year {year}")

def aggregate_github_advisory():
    pass


def main():
    os.makedirs(AGGREGATED_CVES_FOLDER, exist_ok=True)
    # aggregate_NVD()
    # aggregate_aqua()
    # aggregate_redhat()
    aggregate_ubuntu()



if __name__ == "__main__":
    main()
