from NVD_to_mySQL import import_NVDs
from exploitdb_to_mySQL import import_from_explotdb
from programs_to_mySQL import import_host_programs
from util_functions import *
import mysql.connector
from time import sleep
import datetime
from tabulate import tabulate

db_config = {
    'host': 'your_host',
    'user': 'your_user',
    'password': 'your_password',
    'database': 'your_database'
}

# Connect to the database
conn = mysql.connector.connect(**db_config)

def main_menu():
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
        print("     -------- Report --------")
        print("\033[00m\033[46m7.\033[00m\033[96m Queries")
        print("\033[00m\033[46m8.\033[00m\033[96m Generate Report for Vaunerable Installed Programs")
        print()
        print("\033[00m\033[46m9.\033[00m\033[96m Exit")
        print()
        choice = input("Enter your choice: ")
        print("\033[00m")

        if choice == '1':
            import_NVDs(conn)
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
            generate_report(conn)
        elif choice == '9':
            break
        else:
            print("Invalid choice. Please try again.")

        sleep(1)

    print("Goodbye!")
    conn.close()

def query_db():
    #Qeries menu
    while True:
        print("\n\033[34mWhat would you like to query?")
        print("      ------ CVEs ------")
        print("\033[00m\033[44m1.\033[00m\033[34m CVEs by CVE ID")
        print("\033[00m\033[44m2.\033[00m\033[34m CVEs by CWE ID")
        print("\033[00m\033[44m3.\033[00m\033[34m CVEs by CVSScore")
        print("\033[00m\033[44m4.\033[00m\033[34m CVEs by product")
        print("\033[00m\033[44m5.\033[00m\033[34m CVEs by published date")
        print("      ------ Installed Software ------")
        print("\033[00m\033[44m6.\033[00m\033[34m Installed Software")
        print("\033[00m\033[44m7.\033[00m\033[34m Installed Software by installed date")
        print()
        print("\033[00m\033[44m8.\033[00m\033[34m Back")
        print()

        choice = input("\033[34mEnter your choice:")
        if choice == '1':
            cwe_id = input("\033[96mEnter CVE ID:")
            print(f"\033[00m\033[46mQuery results for {cwe_id}:\033[00m")
            list = query_cve(cwe_id)
            display_cve(list,method="full")
        elif choice == '2':
            cwe_id = input("\033[96mEnter CWE ID:")
            print(f"\033[00m\033[46mQuery results for {cwe_id}:\033[00m")
            list, count = query_cwe(cwe_id)
            display_cve_list(list,method="long")
        elif choice == '3':
            cvsscore = input("\033[96mEnter CVSScore:")
            print(f"\033[00m\033[46mQuery results for {cvsscore}:\033[00m")
            list = query_cvsscore(conn, cvsscore)
            display_cve_list(list)
        elif choice == '4':
            product = input("\033[96mEnter product:")
            print(f"\033[00m\033[46mQuery results for {product}:\033[00m")
            list, count = query_product(product)
            display_cve_list(list)
        elif choice == '5':
            published_date_start = input("\033[96mEnter start published date (YYYY-MM-DD):")
            published_date_end = input("\033[96mEnter end published date (YYYY-MM-DD or \"now\"):")
            print(f"\033[00m\033[46mQuery results for {published_date_start} - {published_date_end}:\033[00m")
            list, count = query_published_date(conn, published_date_start, published_date_end)
            display_cve_list(list)
        elif choice == '6':
            list,count = query_installed_software(conn)
            
            print("\033[35m")
            print(tabulate(list, headers=["Program Name","Program Version"], tablefmt="pretty"))
            print("\033[00m")
        elif choice == '7':
            installed_date = input("\033[96mEnter installed date:")
            print(f"\033[00m\033[46mQuery results for {installed_date}:\033[00m")
            print(query_installed_date(conn, installed_date))
        elif choice == '8':
            return
        else:
            print("\033[31mInvalid input.\033[00m")

        sleep(1)

if __name__ == "__main__":
    main_menu()