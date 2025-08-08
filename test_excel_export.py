#!/usr/bin/env python3
"""
Test Excel Export Functionality
Creates sample data and exports to Excel for testing
"""

from CTF_GAME import app, db, User, Challenge, Solve, AuditLog
from werkzeug.security import generate_password_hash
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import random

def create_sample_data():
    """Create sample data for testing Excel export"""
    
    print("🧪 Creating sample data for Excel export test...")
    
    # Create sample users
    users_data = [
        {'username': 'alice', 'email': 'alice@test.com', 'role': 'user'},
        {'username': 'bob', 'email': 'bob@test.com', 'role': 'user'},
        {'username': 'charlie', 'email': 'charlie@test.com', 'role': 'user'},
        {'username': 'diana', 'email': 'diana@test.com', 'role': 'user'},
        {'username': 'admin', 'email': 'admin@test.com', 'role': 'admin'},
    ]
    
    for user_data in users_data:
        existing_user = User.query.filter_by(username=user_data['username']).first()
        if not existing_user:
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                password_hash=generate_password_hash('password123'),
                role=user_data['role']
            )
            db.session.add(user)
            print(f"✅ Created user: {user_data['username']}")
    
    # Create sample challenges
    challenges_data = [
        {'title': 'Easy Web Challenge', 'description': 'Find the hidden flag', 'flag': 'flag{easy_web}', 'points': 10},
        {'title': 'Medium Crypto', 'description': 'Decode the message', 'flag': 'flag{medium_crypto}', 'points': 20},
        {'title': 'Hard Reverse', 'description': 'Reverse engineer this', 'flag': 'flag{hard_reverse}', 'points': 30},
        {'title': 'Steganography', 'description': 'Hidden in the image', 'flag': 'flag{stego}', 'points': 25},
    ]
    
    fernet = Fernet(Fernet.generate_key())
    for challenge_data in challenges_data:
        existing_challenge = Challenge.query.filter_by(title=challenge_data['title']).first()
        if not existing_challenge:
            challenge = Challenge(
                title=challenge_data['title'],
                description=challenge_data['description'],
                flag_encrypted=fernet.encrypt(challenge_data['flag'].encode()),
                points=challenge_data['points']
            )
            db.session.add(challenge)
            print(f"✅ Created challenge: {challenge_data['title']}")
    
    db.session.commit()
    
    # Create sample solves
    users = User.query.filter_by(role='user').all()
    challenges = Challenge.query.all()
    
    # Generate random solve data
    for user in users:
        # Each user solves 1-3 random challenges
        num_solves = random.randint(1, 3)
        solved_challenges = random.sample(challenges, num_solves)
        
        for i, challenge in enumerate(solved_challenges):
            # Create solve with timestamp spread over last 7 days
            solve_time = datetime.now() - timedelta(days=random.randint(0, 7), hours=random.randint(0, 23))
            
            solve = Solve(
                user_id=user.id,
                challenge_id=challenge.id,
                timestamp=solve_time
            )
            db.session.add(solve)
            
            # Create audit log for solve
            audit = AuditLog(
                user=user.username,
                action=f"Successfully solved challenge: {challenge.title}"
            )
            db.session.add(audit)
    
    # Create some failed attempts
    for user in users:
        for _ in range(random.randint(0, 2)):
            challenge = random.choice(challenges)
            audit = AuditLog(
                user=user.username,
                action=f"Failed attempt on challenge: {challenge.title}"
            )
            db.session.add(audit)
    
    db.session.commit()
    print("✅ Sample data created successfully!")

def test_excel_export():
    """Test the Excel export functionality"""
    
    print("\n📊 Testing Excel export...")
    
    try:
        # Import and run the export function
        from export_to_excel import create_excel_report, export_user_activity_report
        
        # Create main report
        main_report = create_excel_report()
        
        # Create activity report
        activity_report = export_user_activity_report()
        
        print(f"\n🎉 Excel export test successful!")
        print(f"📁 Main Report: {main_report}")
        print(f"📁 Activity Report: {activity_report}")
        
        return True
        
    except Exception as e:
        print(f"❌ Excel export test failed: {e}")
        return False

if __name__ == "__main__":
    with app.app_context():
        print("🚀 Starting Excel export test...")
        
        # Create sample data
        create_sample_data()
        
        # Test Excel export
        success = test_excel_export()
        
        if success:
            print("\n✅ All tests passed! Excel export is working correctly.")
            print("\n📋 You can now:")
            print("   • Open the generated Excel files")
            print("   • Review the different sheets")
            print("   • Analyze the sample data")
            print("   • Use this as a template for real data")
        else:
            print("\n❌ Tests failed. Check the error messages above.") 