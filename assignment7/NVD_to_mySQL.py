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

# Variables
sleep_time = 5 #seconds
days_limit = timedelta(days=120) #Not longer than 120 days

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
            cve_id VARCHAR(255) PRIMARY KEY,
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
    itter_date = start_date

    global count
    global failed

    while itter_date < end_date:
        cleared_dates = False
        start_index=0
        while not cleared_dates:

            if itter_date + days_limit > end_date:
                fraction_end_date = end_date
            else:
                fraction_end_date = itter_date + days_limit

            print(f"\033[94mPulling Stats from \033[00m\033[44m{str(itter_date)}\033[00m\033[94m to \033[00m\033[44m{str(fraction_end_date)}\033[00m\033[94m...\033[00m \033[33m(startIndex={str(start_index)}) ({str(count)} CVEs so far)\033[00m")

            params = {
                'startIndex': start_index,
                'resultsPerPage': '2000',
                'pubStartDate': itter_date.strftime('%Y-%m-%dT%H:%M:%S%z'),
                'pubEndDate': fraction_end_date.strftime('%Y-%m-%dT%H:%M:%S%z'),
            }

            response = requests.get(nvd_api_url, params=params)

            if response.status_code == 200:
                data = response.json()
                print(f"Got response with code {response.status_code}, results_per_page={data['resultsPerPage']}, start_index={data['startIndex']}, total_results={data ['totalResults']}")
                
                if data["resultsPerPage"] + data['startIndex'] < data['totalResults']:
                    start_index += data["resultsPerPage"]
                else:
                    cleared_dates = True

                if 'vulnerabilities' in data:
                    insert_cves(data['vulnerabilities'])
                    count += len(data['vulnerabilities'])

            elif response.status_code != 200 and "message" in response.headers:
                print(f"\033[31mError fetching CVEs: {response.headers['message']}\033[00m")

            else:
                print(f"\033[31mError fetching CVEs: {response.__dict__}\033[00m")   

            if response.status_code == 200 and data['resultsPerPage'] > 1500:
                print(f"\033[94mNo need to sleep!\033[00m")
            else:
                print(f"\033[94mWaiting {sleep_time} seconds...\033[00m")
                sleep(sleep_time)

        itter_date = fraction_end_date

    print(f"\033[32m{count} CVEs fetched from NVD API.\033[00m")

def insert_cves(cves):
    print("Inserting CVEs into the database...")
    
    global count
    global failed

    cursor = connection.cursor()

    for cve_ind in cves:
        try:

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

            
            values = (cve_id, source_identifier, published, last_modified, description, base_score, weaknesses, configurations, referances)
            cursor.execute(insert_query, values)

            connection.commit()

            print(f"\033[32mInserted cve \033[00m\033[42m#{cve_id}\033[00m")
            count+=1
        except mysql.connector.errors.OperationalError as e:
            print("\033[31mError with MySQL connection, exiting...\033[00m")
            return count
        except Exception as e:
            print(f"\033[31mError inserting CVE{cve_id}: {e}. Retrying without the configuration field\033[00m")
            #add the failed CVE without the configurations field
            try:
                insert_query = "INSERT INTO cves (cve_id, source_identifier, published, last_modified, description, base_score, weaknesses, configurations, refs) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
                values = (cve_id, source_identifier, published, last_modified, description, base_score, weaknesses, None, referances)
                cursor.execute(insert_query, values)
                connection.commit()
                count+=1
                print(f"\033[32mInserted cve \033[00m\033[42m#{cve_id}\033[00m")
            except Exception as e:
                print(f"\033[31mError inserting CVE: {e}\033[00m")
                failed += 1
                print_failed_cve(cve_id,e)

    cursor.close()
            
    return count

# Main function
def import_NVDs(conn, start_date=datetime(1990,1,1,0,0,0,0), end_date=datetime.now()):
    script_start_time = datetime.now()
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

    script_end_time = datetime.now()

    print(f"\033[32mScript took {script_end_time - script_start_time} to run.\033[00m")
