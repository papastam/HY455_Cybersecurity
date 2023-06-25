import subprocess
import mysql.connector

def import_host_programs(conn):

    # Function to execute a command and capture its output
    def run_command(command):
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, error = process.communicate()
        return output.decode().strip()

    # Function to extract the installation date from the status output
    def extract_installation_date(package_name):
        file_path = run_command(f"dpkg-query -L {package_name} | grep /var/lib/dpkg/info/{package_name}.list")
        timestamp = run_command(f"stat -c %Y {file_path}")
        if timestamp:
            date_string = run_command(f"date -d @{timestamp} +'%Y-%m-%d'")
            return date_string
        return None

    cursor = conn.cursor()

    # Check if the table exists
    table_exists_query = "SHOW TABLES LIKE 'installed_programs'"
    cursor.execute(table_exists_query)
    table_exists = cursor.fetchone()

    # Drop the table if it exists
    if table_exists:
        drop_table_query = "DROP TABLE installed_programs"
        cursor.execute(drop_table_query)

    # Create the table
    create_table_query = '''
        CREATE TABLE installed_programs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            program_name VARCHAR(100) NOT NULL,
            program_version VARCHAR(50) NOT NULL,
            installation_date DATE
        )
    '''
    cursor.execute(create_table_query)

    # Get the list of installed packages and their installation dates
    installed_packages = run_command("dpkg-query -W -f='${Package} ${Version} ${Status}\n'")

    # Split the output into individual lines and insert into the database
    lines = installed_packages.split('\n')
    count = 0
    for line in lines:
        package_name, package_version, status = line.split(' ', 2)
        if status == "install ok installed":
            package_status_output = run_command(f"dpkg-query -s {package_name}")
            installation_date = extract_installation_date(package_status_output)
            if installation_date:
                insert_query = "INSERT INTO installed_programs (program_name, program_version, installation_date) VALUES (%s, %s, %s)"
                cursor.execute(insert_query, (package_name, package_version, installation_date))
            else:
                insert_query = "INSERT INTO installed_programs (program_name, program_version) VALUES (%s, %s)"
                cursor.execute(insert_query, (package_name, package_version))
            count+=1
            print("\033[92mInserted " + package_name + " " + package_version + "\033[0m")
        conn.commit()

    # Commit the changes and close the connection
    cursor.close()

    print("\033[34m" + "Inserted " + str(count) + " programs into the database" + "\033[0m")
