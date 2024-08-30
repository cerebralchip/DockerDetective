import datetime
import subprocess
import json
import psycopg2
from psycopg2.extras import execute_values
import concurrent.futures
import logging
import os

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database connection parameters
DB_PARAMS = {
    'dbname': 'dockerdetective',
    'user': 'dockerdetective',
    'password': 'dockerdetective',
    'host': 'localhost',
    'port': 5432
}

# Number of parallel processes
NUM_PROCESSES = 6

def get_unscanned_container():
    """
    Retrieves the name of an unscanned container from the database and marks it as 'in_progress'.

    Returns:
        str or None: The name of the unscanned container, or None if no unscanned containers are found.
    """
    with psycopg2.connect(**DB_PARAMS) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE images
                SET download_status = 'in_progress'
                WHERE image_name = (
                    SELECT image_name FROM images 
                    WHERE is_scanned = FALSE 
                      AND download_status = 'pending'
                    ORDER BY COALESCE(pull_count, 0) DESC 
                    LIMIT 1 FOR UPDATE SKIP LOCKED
                )
                RETURNING image_name
            """)
            result = cur.fetchone()
            if result:
                return result[0]
    return None

def pull_container(image_name):
    """
    Pulls a Docker container image from Docker Hub.

    Args:
        image_name (str): The name of the Docker image to pull.

    Returns:
        bool: True if the image was successfully pulled, False otherwise.
    """
    try:
        logging.info(f"Pulling {image_name}...")
        subprocess.run(['docker', 'pull', image_name], check=True, capture_output=True, text=True)
        logging.info(f"Successfully pulled {image_name}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Error pulling {image_name}: {e.stderr}")
        if 'manifest unknown' in e.stderr:
            update_download_status(image_name, 'manifest_unknown')
        else:
            update_download_status(image_name, 'download_failed')
        return False

def update_download_status(image_name, status):
    """
    Update the download status of an image in the database.

    Args:
        image_name (str): The name of the image.
        status (str): The download status to be updated.

    Returns:
        None
    """
    with psycopg2.connect(**DB_PARAMS) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE images 
                SET download_status = %s, 
                    is_scanned = TRUE,
                    last_scanned = NOW()
                WHERE image_name = %s
            """, (status, image_name))
        conn.commit()

def scan_container(image_name):
    """
    Scans a Docker container image using grype and returns the scan result in JSON format.

    Parameters:
    - image_name (str): The name of the Docker container image to be scanned.

    Returns:
    - dict: The scan result in JSON format.

    Raises:
    - subprocess.CalledProcessError: If an error occurs while running the 'grype' tool.

    """
    try:
        logging.info(f"Scanning {image_name} ...")
        result = subprocess.run(['grype', image_name, '-o', 'json'], capture_output=True, text=True, check=True)
        logging.info(f"Successfully scanned {image_name}")
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error scanning {image_name}: {e.stderr}")
        return None

def delete_container(image_name):
    """
    Deletes a Docker container with the specified image name.

    Args:
        image_name (str): The name of the Docker image to delete.

    Raises:
        subprocess.CalledProcessError: If an error occurs while deleting the container.

    Returns:
        None
    """
    try:
        subprocess.run(['docker', 'rmi', image_name], check=True, capture_output=True, text=True)
        logging.info(f"Successfully deleted {image_name}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error deleting {image_name}: {e.stderr}")

def parse_and_upload_scan_result(scan_result, image_name):
    """
    Parses the scan result and uploads the data to the database.
    Args:
        scan_result (dict): The scan result data.
        image_name (str): The name of the image.
    Returns:
        None
    Raises:
        Exception: If there is an error parsing and uploading the scan result.
    """
    pass
    with psycopg2.connect(**DB_PARAMS) as conn:
        try:
            with conn.cursor() as cur:
                # Update images table
                image_size = scan_result.get('source', {}).get('target', {}).get('imageSize')
                
                cur.execute("""
                    UPDATE images SET
                        image_size = %s,
                        is_scanned = TRUE,
                        last_scanned = NOW(),
                        download_status = 'success'
                    WHERE image_name = %s
                    RETURNING image_id
                """, (image_size, image_name,))
                image_id = cur.fetchone()[0]

                # Process vulnerabilities
                vulnerabilities = []
                packages = []
                image_vulnerabilities = []
                
                for match in scan_result.get('matches', []):
                    vuln = match.get('vulnerability', {})
                    artifact = match.get('artifact', {})
                    
                    # Vulnerability data
                    vuln_name = vuln.get('id')
                    severity = vuln.get('severity')
                    vulnerabilities.append((vuln_name, severity))
                    
                    # Package data
                    package_name = artifact.get('name')
                    package_version = artifact.get('version')
                    packages.append((package_name, package_version))
                    
                    # Image vulnerability relation data
                    fix_state = vuln.get('fix', {}).get('state')
                    image_vulnerabilities.append((image_id, vuln_name, package_name, package_version, fix_state))

                # Insert vulnerabilities
                execute_values(cur, """
                    INSERT INTO vulnerabilities (vulnerability_name, severity)
                    VALUES %s
                    ON CONFLICT (vulnerability_name) DO NOTHING
                """, vulnerabilities)

                # Insert packages
                execute_values(cur, """
                    INSERT INTO packages (name, version)
                    VALUES %s
                    ON CONFLICT (name, version) DO NOTHING
                """, packages)

                # Insert image_vulnerabilities
                for iv in image_vulnerabilities:
                    cur.execute("""
                        WITH vuln_id AS (
                            SELECT vulnerability_id FROM vulnerabilities WHERE vulnerability_name = %s
                        ), pkg_id AS (
                            SELECT package_id FROM packages WHERE name = %s AND version = %s
                        )
                        INSERT INTO image_vulnerabilities (image_id, vulnerability_id, package_id, fix_state)
                        SELECT %s, vuln_id.vulnerability_id, pkg_id.package_id, %s
                        FROM vuln_id, pkg_id
                        ON CONFLICT (image_id, vulnerability_id, package_id) DO NOTHING
                    """, (iv[1], iv[2], iv[3], iv[0], iv[4]))

                # Insert scan metadata
                vulnerability_counts = {}
                for vuln in vulnerabilities:
                    vulnerability_counts[vuln[1]] = vulnerability_counts.get(vuln[1], 0) + 1
                vulnerability_counts['total'] = sum(vulnerability_counts.values())
                
                cur.execute("""
                    INSERT INTO scan_metadata (
                        image_id, timestamp, total_vulnerabilities,
                        critical_count, high_count, medium_count, low_count, 
                        negligible_count, unknown_count
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    image_id,
                    datetime.datetime.now(),
                    vulnerability_counts.get('total', 0),
                    vulnerability_counts.get('Critical', 0),
                    vulnerability_counts.get('High', 0),
                    vulnerability_counts.get('Medium', 0),
                    vulnerability_counts.get('Low', 0),
                    vulnerability_counts.get('Negligible', 0), 
                    vulnerability_counts.get('Unknown', 0)
                ))

            conn.commit()
        except Exception as e:
            conn.rollback()
            logging.error(f"Error parsing and uploading scan result for {image_name}: {e}")
        else:
            logging.info(f"Successfully parsed and uploaded scan result for {image_name}")
            
def process_container():
    """
    Process a container by performing the following steps:
    1. Get the name of an unscanned container.
    2. If no unscanned container is found, return False.
    3. Pull the container image.
    4. Scan the container image.
    5. Delete the container image.
    6. If the scan result is available:
        - Parse and upload the scan result.
    7. If the scan result is not available:
        - Update the download status of the container to 'scan_failed'.
        - Log an error message.
    8. If there are download issues with the container:
        - Log an info message indicating that processing was skipped.
    9. Return True to indicate successful processing.
    Returns:
        bool: True if the container was processed successfully, False otherwise.
    """
    image_name = get_unscanned_container()
    if not image_name:
        return False

    if pull_container(image_name):
        scan_result = scan_container(image_name)
        delete_container(image_name)
        
        if scan_result:
            parse_and_upload_scan_result(scan_result, image_name)
        else:
            update_download_status(image_name, 'scan_failed')
            logging.error(f"Failed to scan {image_name}")
    else:
        # The download_status is already updated in pull_container function
        logging.info(f"Skipped processing for {image_name} due to download issues")
    
    return True

def main():
    """
    This function is the entry point of the DockerDetective application.
    It updates the grype database and processes containers using a process pool executor.
    Parameters:
    None
    Returns:
    None
    """
    # run command: grype db update before getting started
    subprocess.run(['grype', 'db', 'update'], check=True)
    
    with concurrent.futures.ProcessPoolExecutor(max_workers=NUM_PROCESSES) as executor:
        while True:
            futures = [executor.submit(process_container) for _ in range(NUM_PROCESSES)]
            if not any(future.result() for future in concurrent.futures.as_completed(futures)):
                break

if __name__ == "__main__":
    main()