from flask import Flask
from db_config import get_db_connection

app = Flask(__name__)

@app.route('/')
def home():
    return "Flask server is running!"

@app.route('/test-db')
def test_db():
    try:
        conn = get_db_connection()
        return "Database connection successful!"
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    app.run(debug=True)
