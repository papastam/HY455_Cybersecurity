

def query_cve(conn, cve_id):
    cursor = conn.cursor()
    cursor.execute(f'SELECT * FROM cves WHERE cve_id="{cve_id}"')
    result = cursor.fetchall()
    cursor.close()
    return result

def query_cvsscore(conn, cvsscore):
    cursor = conn.cursor()
    cursor.execute(f'SELECT * FROM cves WHERE base_score>"{cvsscore}"')
    result = cursor.fetchall()
    cursor.close()
    return result

def query_product(conn, product):
    cursor = conn.cursor()
    cursor.execute(f'SELECT * FROM cves WHERE product="{product}"')
    result = cursor.fetchall()
    cursor.close()
    return result

def query_published_date(conn, published_date):
    cursor = conn.cursor()
    cursor.execute(f'SELECT * FROM cves WHERE published_date="{published_date}"')
    result = cursor.fetchall()
    cursor.close()
    return result

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
