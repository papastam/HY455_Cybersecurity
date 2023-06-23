import requests
import mysql.connector
from datetime import datetime, timedelta
from time import sleep

# Database connection
connection= None

# NVD API URL
nvd_api_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

# Counters
count = 0
failed = 0
not_fetched = 0

# Print failed CVE to file
def print_failed_cve(cve_id,reason):
    with open('failed_CVE_imports.txt', 'a') as f:
        f.write(f"Failed cve import: {cve_id}, reason: {reason}\n")

# Function to initialize or recreate the CVEs table in the database
def initialize_database():
    print("\033[34mInitializing database...\033[00m")
    cursor = connection.cursor()

    drop_table_query = "DROP TABLE IF EXISTS cves"
    cursor.execute(drop_table_query)

    create_table_query = """
        CREATE TABLE cves (
            id INT AUTO_INCREMENT PRIMARY KEY,
            cve_id VARCHAR(255) NOT NULL,
            source_identifier VARCHAR(255) NOT NULL,
            published DATETIME NOT NULL,
            last_modified DATETIME NOT NULL,
            description TEXT ,
            base_score FLOAT ,
            weaknesses TEXT,
            configurations TEXT,
            refs TEXT
        )
    """
    cursor.execute(create_table_query)

    cursor.close()

# Fetch CVEs from NVD API for the last 120 days
def fetch_and_import_cves(start_date=datetime(1990,1,1,0,0,0,0), end_date=datetime.now()):
    print("\033[36mFetching CVEs from NVD API...\033[00m")
    days_limit = timedelta(days=100) #Not longer than 120 days
    itter_date = start_date

    global count
    global failed
    global not_fetched  

    while itter_date < end_date:

        if itter_date + days_limit > end_date:
            fraction_end_date = end_date
        else:
            fraction_end_date = itter_date + days_limit

        print(f"\033[94mPulling Stats from \033[00m\033[44m{str(itter_date)}\033[00m\033[94m to \033[00m\033[44m{str(fraction_end_date)}\033[00m\033[94m...\033[00m \033[33m({str(count)} CVEs so far)\033[00m")

        params = {
            'startIndex': '0',
            'resultsPerPage': '2000',
            'pubStartDate': itter_date.strftime('%Y-%m-%dT%H:%M:%S%z'),
            'pubEndDate': fraction_end_date.strftime('%Y-%m-%dT%H:%M:%S%z'),
        }

        response = requests.get(nvd_api_url, params=params)

        if response.status_code == 200:
            data = response.json()
            print(f"Got response with code {response.status_code}, results_per_page={data['resultsPerPage']}, start_index={data['startIndex']}, total_results={data ['totalResults']}")
            
            if data['totalResults'] > data["resultsPerPage"]:
                not_fetched += data['totalResults'] - data["resultsPerPage"]

            if 'vulnerabilities' in data:
                insert_cves(data['vulnerabilities'])
                count += len(data['vulnerabilities'])

        elif response.status_code != 200 and "message" in response.headers:
            print(f"\033[31mError fetching CVEs: {response.headers['message']}\033[00m")

        else:
            print(f"\033[31mError fetching CVEs: {response.__dict__}\033[00m")   

        print(f"\033[94mWaiting 10 seconds...\033[00m")
        sleep(10)

        itter_date = fraction_end_date

    print(f"\033[32m{count} CVEs fetched from NVD API.\033[00m")

def insert_cves(cves):
    print("Inserting CVEs into the database...")
    
    global count
    global failed

    for cve_ind in cves:
        try:
            cursor = connection.cursor()

            insert_query = "INSERT INTO cves (cve_id, source_identifier, published, last_modified, description, base_score, weaknesses, configurations, refs) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"

            cve = cve_ind["cve"]
            cve_id              = cve['id']
            source_identifier   = cve['sourceIdentifier']
            published           = cve['published']
            last_modified       = cve['lastModified']
            description         = cve['descriptions'][0]["value"]
            
            try:
                weaknesses          = str(cve['weaknesses'])
            except:
                weaknesses          = None

            try:
                configurations      = str(cve['configurations'])
            except:
                configurations      = None

            try:
                referances          = str(cve['references'])
            except:
                referances          = None

            if len(list(cve['metrics'].keys())) > 1:
                metric_version      = list(cve['metrics'].keys())[0]
                base_score          = cve['metrics'][metric_version][0]['cvssData']['baseScore']
            else:
                base_score          = None

            print(f"\033[32mInserting cve \033[00m\033[42m#{cve_id}\033[00m")
            
            values = (cve_id, source_identifier, published, last_modified, description, base_score, weaknesses, configurations, referances)
            cursor.execute(insert_query, values)

            connection.commit()
            cursor.close()

            count+=1
        except mysql.connector.errors.OperationalError as e:
            print("\033[31mError with MySQL connection, exiting...\033[00m")
            return count
        except Exception as e:
            print(f"\033[31mError inserting CVE: {e}\033[00m")
            print(f"\033[93mSkipping CVE {cve_id}\033[00m")
            print_failed_cve(cve_id, e)
            failed += 1

    return count

# Main function
def import_NVDs(conn, start_date=datetime(1990,1,1,0,0,0,0), end_date=datetime.now()):
    global connection 
    connection = conn

    # Initialize database
    initialize_database()

    #Clear failed CVEs file
    open('failed_CVE_imports.txt', 'w').close()

    # Fetch CVEs from NVD API and insert into database
    fetch_and_import_cves(start_date, end_date)

    print(f"\033[32m{count} CVEs imported into the database.\033[00m")
    print(f"\033[31m{failed} CVEs failed to import.\033[00m")
    print(f"\033[31m{not_fetched} CVEs not fetched.\033[00m")
