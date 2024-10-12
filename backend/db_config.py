import psycopg2

def get_db_connection():
    conn = psycopg2.connect(
        dbname='hujdb',
        user='hujdb_owner',
        password='0gxdDPcj9NfG',
        host='ep-proud-term-a5qyatn7.us-east-2.aws.neon.tech',
        port='5432',
        sslmode='require'
    )
    return conn
