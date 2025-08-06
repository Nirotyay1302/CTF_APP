#!/usr/bin/env python3
"""
MySQL Database Setup Script for CTF Application
This script sets up the MySQL database, user, and permissions
"""

import mysql.connector
from mysql.connector import Error
import sys

def setup_mysql_database():
    """Setup MySQL database and user for CTF application"""
    
    # Database configuration
    DB_NAME = 'ctfdb'
    DB_USER = 'ctfuser'
    DB_PASSWORD = 'ctfpass123'
    DB_HOST = 'localhost'
    
    try:
        # Connect to MySQL as root (you'll need to provide root password)
        print("🔧 Connecting to MySQL as root...")
        print("⚠️  You may be prompted for your MySQL root password")
        
        connection = mysql.connector.connect(
            host=DB_HOST,
            user='root',
            password=input("Enter MySQL root password (or press Enter if no password): ").strip() or None
        )
        
        if connection.is_connected():
            cursor = connection.cursor()
            
            # Create database
            print(f"📦 Creating database '{DB_NAME}'...")
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
            print(f"✅ Database '{DB_NAME}' created successfully")
            
            # Create user
            print(f"👤 Creating user '{DB_USER}'...")
            cursor.execute(f"CREATE USER IF NOT EXISTS '{DB_USER}'@'localhost' IDENTIFIED BY '{DB_PASSWORD}'")
            print(f"✅ User '{DB_USER}' created successfully")
            
            # Grant privileges
            print(f"🔐 Granting privileges to '{DB_USER}'...")
            cursor.execute(f"GRANT ALL PRIVILEGES ON {DB_NAME}.* TO '{DB_USER}'@'localhost'")
            cursor.execute("FLUSH PRIVILEGES")
            print(f"✅ Privileges granted successfully")
            
            # Test connection with new user
            print("🧪 Testing connection with new user...")
            test_connection = mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )
            
            if test_connection.is_connected():
                print("✅ Connection test successful!")
                test_connection.close()
            
            print("\n🎉 MySQL setup completed successfully!")
            print(f"📊 Database: {DB_NAME}")
            print(f"👤 User: {DB_USER}")
            print(f"🔑 Password: {DB_PASSWORD}")
            print(f"🌐 Host: {DB_HOST}")
            
            return True
            
    except Error as e:
        print(f"❌ Error during MySQL setup: {e}")
        print("\n🔧 Manual Setup Instructions:")
        print("1. Open MySQL command line or MySQL Workbench")
        print("2. Run the following commands:")
        print(f"   CREATE DATABASE {DB_NAME};")
        print(f"   CREATE USER '{DB_USER}'@'localhost' IDENTIFIED BY '{DB_PASSWORD}';")
        print(f"   GRANT ALL PRIVILEGES ON {DB_NAME}.* TO '{DB_USER}'@'localhost';")
        print("   FLUSH PRIVILEGES;")
        return False
        
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

def test_mysql_connection():
    """Test connection to MySQL database"""
    
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='ctfuser',
            password='ctfpass123',
            database='ctfdb'
        )
        
        if connection.is_connected():
            print("✅ MySQL connection test successful!")
            connection.close()
            return True
            
    except Error as e:
        print(f"❌ MySQL connection test failed: {e}")
        return False

if __name__ == "__main__":
    print("🚀 MySQL Database Setup for CTF Application")
    print("=" * 50)
    
    # Setup database
    if setup_mysql_database():
        print("\n🧪 Testing connection...")
        test_mysql_connection()
    else:
        print("\n❌ Setup failed. Please check the manual instructions above.")
        sys.exit(1) 