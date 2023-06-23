from NVD_to_mySQL import import_NVDs
from exploitdb_to_mySQL import import_from_explotdb
from programs_to_mySQL import import_host_programs
from queries import *
import mysql.connector
from time import sleep
import datetime

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Pastroumas@123',
    'database': 'cve_db'
}

# Connect to the database
conn = mysql.connector.connect(**db_config)


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

def query_db():
    #Qeries menu
    while True:
        print("\n\033[96mWhat would you like to query?")
        print("      ------ CVEs ------")
        print("\033[00m\033[46m1.\033[00m\033[96m CVEs by CVE ID")
        print("\033[00m\033[46m2.\033[00m\033[96m CVEs by CVSScore")
        print("\033[00m\033[46m3.\033[00m\033[96m CVEs by product")
        print("\033[00m\033[46m4.\033[00m\033[96m CVEs by published date")
        print("      ------ Installed Software ------")
        print("\033[00m\033[46m5.\033[00m\033[96m Installed Software")
        print("\033[00m\033[46m6.\033[00m\033[96m Installed Software by installed date")
        print()
        print("\033[00m\033[46m7.\033[00m\033[96m Back")
        print()

        choice = input("\033[96mEnter your choice:")
        if choice == '1':
            cve_id = input("\033[96mEnter CVE ID:")
            print(f"\033[00m\033[46m Query results for {cve_id}:\033[00m")
            print(query_cve(conn, cve_id))
        elif choice == '2':
            cvsscore = input("\033[96mEnter CVSScore:")
            print(f"\033[00m\033[46m Query results for {cvsscore}:\033[00m")
            print(query_cvsscore(conn, cvsscore))
        elif choice == '3':
            product = input("\033[96mEnter product:")
            print(f"\033[00m\033[46m Query results for {product}:\033[00m")
            print(query_product(conn, product))
        elif choice == '4':
            published_date = input("\033[96mEnter published date:")
            print(f"\033[00m\033[46m Query results for {published_date}:\033[00m")
            print(query_published_date(conn, published_date))
        elif choice == '5':
            print(installed_software(conn))
        elif choice == '6':
            installed_date = input("\033[96mEnter installed date:")
            print(f"\033[00m\033[46m Query results for {installed_date}:\033[00m")
            print(query_installed_date(conn, installed_date))
        elif choice == '7':
            return
        else:
            print("\033[31mInvalid input.\033[00m")

        sleep(1)

def generate_report():
    pass

# The menu for the user to choose what to import
while True:
    print("\n\033[96mWhat would you like to do?")
    print("      ------ Imports ------")
    print("\033[00m\033[46m1.\033[00m\033[96m Import all CVEs from NVD database (this may take a while)")
    print("\033[00m\033[46m2.\033[00m\033[96m Import everything from ExploitDB")
    print("\033[00m\033[46m3.\033[00m\033[96m Import all Host Programs")
    print("\033[00m\033[46m4.\033[00m\033[96m Import all previous")
    print("     ------ DB options ------")
    print("\033[00m\033[46m5.\033[00m\033[96m Display Database Statistics")
    print("\033[00m\033[46m6.\033[00m\033[96m Drop all tables")
    print("\033[00m\033[46m7.\033[00m\033[96m Query Database")
    print()
    print("     -------- Report --------")
    print("\033[00m\033[46m8.\033[00m\033[96m Generate Report for Vaunerable Installed Programs")
    print()
    print("\033[00m\033[46m9.\033[00m\033[96m Exit")
    print()
    choice = input("Enter your choice: ")
    print("\033[00m")

    if choice == '1':
        import_NVDs(conn, start_date=datetime.datetime(2022,1,1))
    elif choice == '2':
        import_from_explotdb(conn)
    elif choice == '3':
        import_host_programs(conn)
    elif choice == '4':
        import_NVDs(conn,start_date=datetime.datetime(2022,1,1))
        import_from_explotdb(conn)
        import_host_programs(conn)
    elif choice == '5':
        display_stats(conn)
    elif choice == '6':
        clear_db(conn)
    elif choice == '7':
        query_db()
    elif choice == '8':
        generate_report()
    elif choice == '9':
        break
    else:
        print("Invalid choice. Please try again.")

    sleep(2)

print("Goodbye!")
conn.close()