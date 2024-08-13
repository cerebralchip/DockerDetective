import time
import psycopg2
from psycopg2.extras import RealDictCursor

# Source database connection parameters
SOURCE_DB_PARAMS = {
    "dbname": "dockerstudy",
    "user": "dockerstudy",
    "password": "dockerstudy",
    "host": "localhost",
    "port": "5432"
}

# Destination database connection parameters
DEST_DB_PARAMS = {
    "dbname": "dockerdetective",
    "user": "dockerdetective",
    "password": "dockerdetective",
    "host": "localhost",
    "port": "5432"
}

BATCH_SIZE = 100000 

def connect_to_db(params):
    return psycopg2.connect(**params)

def fetch_source_data(conn, offset, limit):
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT image_name, publisher, created_at, updated_at, short_description, pull_count
            FROM dockerstudy_image
            WHERE image_name IS NOT NULL
            ORDER BY image_name
            OFFSET %s LIMIT %s
        """, (offset, limit))
        return cur.fetchall()

def insert_destination_data(conn, data):
    with conn.cursor() as cur:
        cur.executemany("""
            INSERT INTO images (image_name, publisher, created_at, updated_at, short_description, pull_count)
            VALUES (%(image_name)s, %(publisher)s, %(created_at)s, %(updated_at)s, %(short_description)s, %(pull_count)s)
            ON CONFLICT DO NOTHING;
            
            UPDATE images SET
                publisher = %(publisher)s,
                created_at = %(created_at)s,
                updated_at = %(updated_at)s,
                short_description = %(short_description)s,
                pull_count = %(pull_count)s
            WHERE image_name = %(image_name)s
        """, data)
    conn.commit()

def get_total_count(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM dockerstudy_image WHERE image_name IS NOT NULL")
        return cur.fetchone()[0]

def main():
    source_conn = connect_to_db(SOURCE_DB_PARAMS)
    dest_conn = connect_to_db(DEST_DB_PARAMS)

    try:
        total_records = get_total_count(source_conn)
        print(f"Total records to process: {total_records}")

        offset = 0
        processed_records = 0
        start_time = time.time()

        while offset < total_records:
            print(f"Fetching batch starting at offset {offset}...")
            source_data = fetch_source_data(source_conn, offset, BATCH_SIZE)
            
            print(f"Inserting batch into destination database...")
            insert_destination_data(dest_conn, source_data)
            
            processed_records += len(source_data)
            offset += BATCH_SIZE

            elapsed_time = time.time() - start_time
            records_per_second = processed_records / elapsed_time
            estimated_total_time = total_records / records_per_second
            estimated_remaining_time = estimated_total_time - elapsed_time

            print(f"Processed {processed_records}/{total_records} records. "
                  f"Estimated time remaining: {estimated_remaining_time/60:.2f} minutes")

        print("Data migration completed successfully.")

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        source_conn.close()
        dest_conn.close()

if __name__ == "__main__":
    main()