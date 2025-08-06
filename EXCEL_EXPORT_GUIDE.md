# Excel Export Guide for CTF Application

## Overview
The Excel export functionality creates comprehensive reports of all database data, including user information, challenges, solve records, and analytics.

## Quick Start

### 1. Export All Data
```bash
python export_to_excel.py
```

This creates two Excel files:
- `ctf_database_report_YYYYMMDD_HHMMSS.xlsx` (Main report)
- `user_activity_report_YYYYMMDD_HHMMSS.xlsx` (Activity report)

## Main Report Sheets

### 📊 Users Sheet
**Columns:**
- User ID
- Username
- Email
- Role (admin/user)
- Challenges Solved
- Total Score
- Registration Date

**Use for:**
- User management
- Performance analysis
- Role distribution

### 🎯 Challenges Sheet
**Columns:**
- Challenge ID
- Title
- Description
- Points
- Times Solved
- Success Rate

**Use for:**
- Challenge difficulty analysis
- Popularity metrics
- Content optimization

### ✅ Solves Sheet
**Columns:**
- Solve ID
- User ID & Username
- Challenge ID & Title
- Points Earned
- Solved At (timestamp)

**Use for:**
- Detailed solve history
- Time-based analysis
- User progression tracking

### 🔍 Audit Logs Sheet
**Columns:**
- Log ID
- User
- Action
- Timestamp

**Use for:**
- Security monitoring
- User behavior analysis
- System activity tracking

### 🏆 Scoreboard Sheet
**Columns:**
- Rank
- Username
- Email
- Role
- Challenges Solved
- Total Score
- Solved Challenges (list)

**Use for:**
- Leaderboard management
- Competition results
- Performance rankings

### 📈 Summary Sheet
**Metrics:**
- Total Users
- Total Challenges
- Total Solves
- Total Audit Logs
- Admin vs Regular Users
- Average Score per User
- Most/Least Solved Challenges
- Report Generation Time

**Use for:**
- Executive summaries
- System overview
- Key performance indicators

## Activity Report

### 📊 User Activity Sheet
**Columns:**
- Username
- Email
- Role
- Total Solves
- Total Score
- First Solve (timestamp)
- Last Solve (timestamp)
- Activity Duration (hours)
- Average Time Between Solves

**Use for:**
- User engagement analysis
- Activity patterns
- Retention metrics

## Usage Examples

### 1. Generate Reports After CTF Event
```bash
# After the CTF competition ends
python export_to_excel.py
```

### 2. Regular Weekly Reports
```bash
# Schedule this to run weekly
python export_to_excel.py
```

### 3. Custom Analysis
You can modify the script to:
- Filter by date ranges
- Export specific user groups
- Create custom metrics
- Add charts and graphs

## Data Security

### ⚠️ Important Notes:
- **Passwords are NOT exported** (only hashed versions exist in database)
- **Encrypted flags are NOT exported** (only challenge metadata)
- **Personal data** (emails, usernames) are included
- Reports should be handled securely

### 🔒 Best Practices:
- Store reports in secure locations
- Share only necessary sheets
- Delete old reports regularly
- Use for analysis only, not public sharing

## Customization

### Adding New Metrics
Edit `export_to_excel.py` to add:
- Custom calculations
- New data fields
- Different time periods
- Filtered exports

### Example: Export Only Recent Activity
```python
# Add date filtering
from datetime import datetime, timedelta
recent_date = datetime.now() - timedelta(days=7)
recent_solves = Solve.query.filter(Solve.timestamp >= recent_date).all()
```

## Troubleshooting

### Common Issues:

1. **"No data found"**
   - Ensure database is populated
   - Run `python seed_challenges.py` first
   - Check MySQL connection

2. **"Permission denied"**
   - Check file write permissions
   - Close Excel files before running
   - Use different directory

3. **"Memory error"**
   - Database too large
   - Split exports by date ranges
   - Use database queries instead

### Performance Tips:
- Run exports during low-usage periods
- Consider incremental exports
- Use database indexes for large datasets
- Monitor file sizes

## Integration with Other Tools

### Import to Other Systems:
- **Google Sheets**: Upload Excel files
- **Tableau**: Connect to Excel data
- **Power BI**: Import Excel reports
- **Python Analysis**: Use pandas to read Excel files

### Automated Reporting:
```bash
# Add to cron job (Linux/Mac)
0 2 * * 0 /path/to/python /path/to/export_to_excel.py

# Windows Task Scheduler
# Create scheduled task to run weekly
```

## Support

For issues or customizations:
1. Check the error messages
2. Verify database connectivity
3. Ensure all dependencies are installed
4. Review the data structure

---

**Last Updated:** January 2025
**Version:** 1.0 