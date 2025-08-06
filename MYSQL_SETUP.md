# MySQL Setup Guide for CTF Application

## Prerequisites
- MySQL Server installed and running
- MySQL root access

## Step 1: Set Up MySQL Database

### Option A: Using the Setup Script (Recommended)
```bash
python setup_mysql.py
```
This will prompt for your MySQL root password and create:
- Database: `ctfdb`
- User: `ctfuser`
- Password: `ctfpass123`

### Option B: Manual Setup
Connect to MySQL and run:
```sql
CREATE DATABASE ctfdb;
CREATE USER 'ctfuser'@'localhost' IDENTIFIED BY 'ctfpass123';
GRANT ALL PRIVILEGES ON ctfdb.* TO 'ctfuser'@'localhost';
FLUSH PRIVILEGES;
```

## Step 2: Initialize Database Tables
```bash
python app.py
```
This will create all necessary tables in the MySQL database.

## Step 3: Seed Initial Data
```bash
python seed_challenges.py
```
This will create:
- Admin user (admin/admin123)
- 6 sample challenges

## Step 4: Test the Application
1. Start the Flask app: `python app.py`
2. Visit: http://127.0.0.1:5000
3. Login as admin: admin/admin123
4. Create regular user accounts
5. Solve challenges and check scoreboard

## Database Configuration
The app is configured to use:
- **Host**: localhost
- **Database**: ctfdb
- **User**: ctfuser
- **Password**: ctfpass123
- **Driver**: PyMySQL

## Troubleshooting

### Connection Issues
- Ensure MySQL server is running
- Check if the database and user exist
- Verify the password is correct

### Permission Issues
- Make sure the user has proper privileges
- Try running as MySQL root if needed

### Port Issues
- Default MySQL port is 3306
- If using a different port, update the connection string

## Admin Access
- **Username**: admin
- **Password**: admin123
- **Email**: admin@ctf.local
- **Role**: admin

Use this account to:
- Add new challenges
- Manage existing challenges
- Monitor user activity 