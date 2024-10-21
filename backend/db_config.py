import pg8000
import ssl

def get_db_connection():
    # Create an SSL context
    ssl_context = ssl.create_default_context()

    conn = pg8000.connect(
        database='hujdb',
        user='hujdb_owner',
        password='0gxdDPcj9NfG',
        host='ep-proud-term-a5qyatn7.us-east-2.aws.neon.tech',
        port=5432,                # Ensure port is an integer
        ssl_context=ssl_context   # Use ssl_context instead of ssl
    )
    return conn
