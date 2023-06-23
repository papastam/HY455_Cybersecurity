import subprocess
import mysql.connector

def import_host_programs(conn):
    
    # Function to execute a command and capture its output
    def run_command(command):
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, error = process.communicate()
        return output.decode().strip()

    # Get the list of installed programs and versions
    installed_programs = run_command("dpkg-query -W -f='${Package} ${Version}\n'")

    # Connect to the MySQL server
    cursor = conn.cursor()

    # Check if the table exists
    table_exists_query = "SHOW TABLES LIKE 'installed_programs'"
    cursor.execute(table_exists_query)
    table_exists = cursor.fetchone()

    # Clear the table if it exists
    if table_exists:
        clear_table_query = "TRUNCATE TABLE installed_programs"
        cursor.execute(clear_table_query)

    # Create a table to store the installed programs
    create_table_query = '''
        CREATE TABLE IF NOT EXISTS installed_programs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            program_name VARCHAR(100) NOT NULL,
            program_version VARCHAR(50) NOT NULL
        )
    '''
    cursor.execute(create_table_query)

    count = 0

    # Split the output into individual lines and insert into the database
    lines = installed_programs.split('\n')
    for line in lines:
        try:
            program_name, program_version = line.split(' ', 1)
            insert_query = "INSERT INTO installed_programs (program_name, program_version) VALUES (%s, %s)"
            cursor.execute(insert_query, (program_name, program_version))
            print("\033[92m" + "Program: " + program_name + " Version: " + program_version + "\033[0m")
            count += 1
        except Exception as e:
            print("\033[91m" + "Error: " + str(e) + "\033[0m")

    # Commit the changes and close the connection
    conn.commit()
    cursor.close()

    print("\033[34m" + "Inserted " + str(count) + " programs into the database" + "\033[0m")
