import pymysql
from dotenv import load_dotenv
import os

load_dotenv()

def get_db_connection():
    try:
        connection = pymysql.connect(
            host=os.getenv('DB_HOST'),  
            user=os.getenv('DB_USER'),   
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME'),
            port=int(os.getenv('DB_PORT', '3306')), 
            cursorclass=pymysql.cursors.DictCursor,
            ssl=None, 
            connect_timeout=10  
        )
        print("✅ Connected to Google Cloud MySQL database.")
        return connection
    except pymysql.MySQLError as e:
        print(f"❌ Error while connecting to Google Cloud MySQL: {e}")
        return None