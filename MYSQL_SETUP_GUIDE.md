# MySQL Setup Guide for CTF Application

This guide will help you set up MySQL database for your CTF (Capture The Flag) application.

## Prerequisites

1. **MySQL Server** - Make sure MySQL is installed and running on your system
2. **Python Dependencies** - Install required Python packages

## Step 1: Install MySQL Server

### Windows
1. Download MySQL Installer from [MySQL Downloads](https://dev.mysql.com/downloads/installer/)
2. Run the installer and follow the setup wizard
3. Choose "Developer Default" or "Server only" installation
4. Set a root password (remember this!)
5. Complete the installation

### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install mysql-server
sudo mysql_secure_installation
```

### macOS
```bash
brew install mysql
brew services start mysql
```

## Step 2: Install Python Dependencies

```bash
pip install PyMySQL mysql-connector-python
```

## Step 3: Setup Database and User

### Option A: Automated Setup (Recommended)

Run the setup script:
```bash
python setup_mysql.py
```

This script will:
- Create the `ctfdb` database
- Create user `ctfuser` with password `ctfpass123`
- Grant necessary permissions
- Test the connection

### Option B: Manual Setup

If the automated setup fails, you can set up manually:

1. **Connect to MySQL as root:**
   ```bash
   mysql -u root -p
   ```

2. **Create database and user:**
   ```sql
   CREATE DATABASE ctfdb;
   CREATE USER 'ctfuser'@'localhost' IDENTIFIED BY 'ctfpass123';
   GRANT ALL PRIVILEGES ON ctfdb.* TO 'ctfuser'@'localhost';
   FLUSH PRIVILEGES;
   EXIT;
   ```

## Step 4: Initialize Database Tables

Run the seeding script to create tables and add initial data:
```bash
python seed_mysql_database.py
```

This will:
- Create all necessary database tables
- Add an admin user (username: `admin`, password: `admin123`)
- Add sample challenges

## Step 5: Test the Application

Start the Flask application:
```bash
python app.py
```

The application should now connect to MySQL instead of SQLite.

## Database Configuration

The application is configured to use these MySQL settings:

- **Host:** localhost
- **Database:** ctfdb
- **User:** ctfuser
- **Password:** ctfpass123
- **Port:** 3306 (default)

## Troubleshooting

### Common Issues

1. **Connection Refused Error**
   - Make sure MySQL server is running
   - Check if MySQL is running on the correct port (3306)

2. **Access Denied Error**
   - Verify the username and password
   - Make sure the user has proper privileges

3. **Module Not Found Error**
   - Install PyMySQL: `pip install PyMySQL`
   - Install mysql-connector-python: `pip install mysql-connector-python`

4. **Database Doesn't Exist**
   - Run the setup script: `python setup_mysql.py`
   - Or create manually using the SQL commands above

### Useful MySQL Commands

```sql
-- Show databases
SHOW DATABASES;

-- Show users
SELECT User, Host FROM mysql.user;

-- Show tables in ctfdb
USE ctfdb;
SHOW TABLES;

-- Check user privileges
SHOW GRANTS FOR 'ctfuser'@'localhost';
```

### Reset Database

To completely reset the database:

```sql
DROP DATABASE ctfdb;
CREATE DATABASE ctfdb;
GRANT ALL PRIVILEGES ON ctfdb.* TO 'ctfuser'@'localhost';
FLUSH PRIVILEGES;
```

Then run the seeding script again:
```bash
python seed_mysql_database.py
```

## Security Notes

1. **Change Default Passwords** - Consider changing the default passwords in production
2. **Network Security** - Restrict MySQL access to localhost only
3. **Backup** - Regularly backup your database
4. **Environment Variables** - Use environment variables for sensitive data in production

## Production Deployment

For production deployment:

1. Use environment variables for database credentials
2. Set up proper MySQL security
3. Configure connection pooling
4. Set up automated backups
5. Monitor database performance

Example environment variables:
```bash
export MYSQL_HOST=localhost
export MYSQL_DATABASE=ctfdb
export MYSQL_USER=ctfuser
export MYSQL_PASSWORD=your_secure_password
```

## Support

If you encounter issues:

1. Check MySQL server status
2. Verify connection credentials
3. Review MySQL error logs
4. Test connection manually
5. Check Python package versions

For more help, refer to:
- [MySQL Documentation](https://dev.mysql.com/doc/)
- [PyMySQL Documentation](https://pymysql.readthedocs.io/)
- [Flask-SQLAlchemy Documentation](https://flask-sqlalchemy.palletsprojects.com/) 