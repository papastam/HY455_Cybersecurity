import requests
import mysql.connector
from datetime import datetime, timedelta

nvd_api_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

def display_cve_list(cve_list, method="short"):
    if method != "short" and method != "long" and method != "full":
        print("Invalid method. Please use 'short' or 'long'.")
        return
    count=0
    for cve in cve_list:
        if type(cve) == dict:
            display_cve(cve, method)
        else:
            try:
                display_cve(cve_list[cve], method)
            except Exception as e:
                print(f"\033[00m\033[41m{e}\033[00m")
                print(f"\033[00m\033[41m{cve_list}\033[00m")
                return
        count += 1
    print(f"\033[00m\033[46mTotal CVEs: {count}\033[00m")

def display_cve(cve,method="short"):
    if "cve" in cve:
        cve = cve["cve"]

    if "cvssMetricV31" in cve["metrics"]:
        base_score = cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
    else:
        try:
            base_score = cve["metrics"][next(iter(cve["metrics"]))][0]['cvssData']["baseScore"]
        except:
            base_score = None
    try:
        if method == "short":
            print(f"\033[00m\033[45m{cve['id']}\033[00m\n")
        elif method == "long":
            print(f"\033[00m\033[45m{cve['id']}\033[00m\033[95m {cve['descriptions'][0]['value']}\n")
        elif method == "full":
            print(f"\033[00m\033[45m{cve['id']}\033[00m\033[95m {cve['descriptions'][0]['value']}\n")
            print(f"\033[04mSource Identifier:\033[00m\033[95m {cve['sourceIdentifier']}")
            print(f"\033[04mPublished:\033[00m\033[95m {cve['published']}")
            print(f"\033[04mLast Modified:\033[00m\033[95m {cve['lastModified']}")
            print(f"\033[04mBase Score:\033[00m\033[95m {base_score}")
            print(f"\033[04mWeaknesses:\033[00m\033[95m {cve['weaknesses']}")
            print(f"\033[04mConfigurations:\033[00m\033[95m {cve['configurations']}")
            print()
        else:
            print("Invalid method. Please use 'short' or 'long'.")
    except Exception as e:
        print("Invalid CVE format. Please use the CVE format from the database.")
        print(f"format: {cve}")
        print(f"error: {e}")

#display the count of CVEs, exploits, and host programs
def display_stats(conn):
    cursor = conn.cursor()

    # Count CVEs
    try:
        cursor.execute('SELECT COUNT(*) FROM cves')
        cve_count = cursor.fetchone()[0]
    except mysql.connector.errors.ProgrammingError:
        cve_count = 0

    # Count exploits
    try:
        cursor.execute('SELECT COUNT(*) FROM exploits')
        exploit_count = cursor.fetchone()[0]
    except mysql.connector.errors.ProgrammingError:
        exploit_count = 0
    
    # Count host programs
    try:
        cursor.execute('SELECT COUNT(*) FROM installed_programs')
        host_program_count = cursor.fetchone()[0]
    except mysql.connector.errors.ProgrammingError:
        host_program_count = 0

    print("\n\033[95m----------Database Statistics----------")
    print(f'CVEs: \033[00m\033[45m{cve_count}\033[00m\033[95m')
    print(f'Exploits: \033[00m\033[45m{exploit_count}\033[00m\033[95m')
    print(f'Host Programs: \033[00m\033[45m{host_program_count}\033[00m\033[95m')
    print("---------------------------------------\033[00m\n")

    cursor.close()

#drop all tables
def clear_db(conn):
    print("\033[31mAre you sure you want to drop all tables? This cannot be undone [Y/n]:")
    if input().lower() != 'y':
        print("\033[31mAborting...\033[00m")
        return
    print("\033[00m")

    cursor = conn.cursor()

    cursor.execute('DROP TABLE IF EXISTS cves')
    cursor.execute('DROP TABLE IF EXISTS exploits')
    cursor.execute('DROP TABLE IF EXISTS installed_programs')

    cursor.close()
    print("\033[41mAll tables dropped.\033[00m")


def query_cve(cve_id):
    response = requests.get(f'{nvd_api_url}?cveId={cve_id}')
    if response.status_code == 200:
        result = response.json()["vulnerabilities"][0]
    else:
        result = None
        print(f"API call error: {response.headers.message}")

    return result    

def query_cwe(cwe_id):
    result = []
    done = False
    startindex = 0
    count = 0 
    failcount=0

    while (not done) or (failcount >= 3):
        response = requests.get(f'{nvd_api_url}?cweId={cwe_id}&startIndex={2000*startindex}&resultsPerPage=2000')

        if response.status_code == 200:
            data = response.json()
            result += data["vulnerabilities"]
            count += data["resultsPerPage"]

            if data["resultsPerPage"] + data['startIndex']  < data["totalResults"]:
                startindex += 1
            else:
                done = True
        else:
            if failcount >= 3:
                break
            failcount += 1
            print(f"API call error: {response.headers.message}")
        
    return result, count

def query_cvsscore(cvsscore):
    result = []
    done = False
    startindex = 0
    count = 0 
    failcount=0

    while not done:
        response = requests.get(f'{nvd_api_url}?cvssV3Severity={cvsscore}&startIndex={2000*startindex}&resultsPerPage=2000')

        if response.status_code == 200:
            data = response.json()
            result += data["vulnerabilities"]
            count += data["resultsPerPage"]

            if data["resultsPerPage"] + data['startIndex'] < data["totalResults"]:
                startindex += 1
            else:
                done = True
        else:
            if failcount >=3:
                break

            failcount += 1
            print(f"API call error: {response.headers['message']}")

    return result, count

def query_product(product):
    result = []
    done = False
    startindex = 0
    count = 0 
    failcount=0

    # create CPE from vendor
    cpe = f"cpe:2.3:a:*:{product}"

    while (not done):
        response = requests.get(f'{nvd_api_url}?virtualMatchString={cpe}&startIndex={2000*startindex}&resultsPerPage=2000')

        if response.status_code == 200:
            data = response.json()
            result += data["vulnerabilities"]
            count += data["resultsPerPage"]

            if data["resultsPerPage"] + data['startIndex'] < data["totalResults"]:
                startindex += 1
            else:
                done = True
        else:
            if failcount >= 3:
                break
            failcount += 1
            print(f"API call error: {response.headers['message']}")

    return result, count

def query_published_date(conn, published_date_start, published_date_end):
    result = []
    count = 0
    failcount = 0
    dayslimit = timedelta(days=120)

    if not type(published_date_start) is datetime:
        published_date_start = datetime.strptime(published_date_start, "%Y-%m-%d") 

    if not type(published_date_end) is datetime:
        if published_date_end == 'now':
            published_date_end = datetime.now()
        else:
            published_date_end = datetime.strptime(published_date_end, "%Y-%m-%d")

    start_index = published_date_start
    end_index = published_date_start + dayslimit
    
    while end_index < published_date_end:
        startindex = 0
        done = False
        
        while (not done):
            print(f"\033[94mPulling Stats from \033[00m\033[44m{str(start_index)}\033[00m\033[94m to \033[00m\033[44m{str(end_index)}\033[00m\033[94m...\033[00m \033[33m(startIndex={str(startindex)}) ({str(count)} CVEs so far)\033[00m")
            response = requests.get(f'{nvd_api_url}?pubStartDate={start_index.strftime("%Y-%m-%dT%H:%M:%S%z")}&pubEndDate={end_index.strftime("%Y-%m-%dT%H:%M:%S%z")}&startIndex={2000*startindex}&resultsPerPage=2000')

            if response.status_code == 200:
                data = response.json()
                print(f"Got response with code {response.status_code}, results_per_page={data['resultsPerPage']}, start_index={data['startIndex']}, total_results={data ['totalResults']}")

                result += data["vulnerabilities"]
                count += data["resultsPerPage"]

                if data["resultsPerPage"] + data['startIndex'] < data["totalResults"]:
                    startindex += 1
                else:
                    done = True
            else:
                if failcount >= 3:
                    break
                failcount += 1
                print(f"API call error: {response.headers['message']}")
        
        start_index = end_index
        end_index = end_index + dayslimit

    return result, count

def query_installed_software(conn):
    cursor = conn.cursor()
    cursor.execute(f'SELECT * FROM installed_programs')
    result = cursor.fetchall()
    cursor.close()
    return result

def query_installed_date(conn, installed_date):
    cursor = conn.cursor()
    cursor.execute(f'SELECT * FROM installed_programs WHERE installed_date="{installed_date}"')
    result = cursor.fetchall()
    cursor.close()
    return result

def installed_software(conn):
    cursor = conn.cursor()
    cursor.execute(f'SELECT * FROM installed_programs')
    result = cursor.fetchall()
    cursor.close()
    return result

def generate_report(conn):
    cursor = conn.cursor()
    cursor.execute(f'SELECT * FROM cves')
    result = cursor.fetchall()
    cursor.close()
    return result