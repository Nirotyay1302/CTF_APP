#!/usr/bin/env python3
"""
MySQL Database Seeding Script for CTF Application
Populates the database with initial challenges and admin user
"""

from CTF_GAME import app, db, User, Challenge, fernet
from werkzeug.security import generate_password_hash
from datetime import datetime

def create_admin_user():
    """Create admin user"""
    try:
        # Check if admin user already exists
        admin = User.query.filter_by(username='admin').first()
        if admin:
            print("✅ Admin user already exists")
            return admin
        
        # Create admin user
        admin = User(
            username='admin',
            email='mukherjeetojo4@gmail.com',
            password_hash=generate_password_hash('TOJO123'),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created successfully")
        return admin
        
    except Exception as e:
        print(f"❌ Error creating admin user: {e}")
        db.session.rollback()
        return None

def add_challenge(title, description, flag, points):
    """Add a challenge to the database"""
    try:
        # Check if challenge already exists
        existing = Challenge.query.filter_by(title=title).first()
        if existing:
            print(f"✅ Challenge '{title}' already exists")
            return existing
        
        # Encrypt the flag
        flag_encrypted = fernet.encrypt(flag.encode())
        
        # Create challenge
        challenge = Challenge(
            title=title,
            description=description,
            flag_encrypted=flag_encrypted,
            points=points
        )
        db.session.add(challenge)
        db.session.commit()
        print(f"✅ Challenge '{title}' added successfully")
        return challenge
        
    except Exception as e:
        print(f"❌ Error adding challenge '{title}': {e}")
        db.session.rollback()
        return None

def seed_database():
    """Seed the database with initial data"""
    print("🌱 Seeding MySQL database with initial data...")
    
    # Create admin user
    admin = create_admin_user()
    
    # Add sample challenges
    challenges = [
        {
            'title': 'Basic Web Challenge',
            'description': 'Find the flag hidden in the HTML comments. Look carefully at the page source!',
            'flag': 'CTF{web_basics_101}',
            'points': 50
        },
        {
            'title': 'Decode Me',
            'description': 'This text looks strange: VENH{web_basics_101}. Can you decode it?',
            'flag': 'CTF{base64_decoded}',
            'points': 75
        },
        {
            'title': 'Medium Crypto',
            'description': 'Decrypt this message: U2FsdGVkX1+QxJ8J8J8J8J8J8J8J8J8J8J8J8J8J8=',
            'flag': 'CTF{crypto_master}',
            'points': 100
        },
        {
            'title': 'Hard Reverse',
            'description': 'Reverse engineer this binary to find the flag. Use tools like Ghidra or IDA.',
            'flag': 'CTF{reverse_engineering}',
            'points': 150
        },
        {
            'title': 'Steganography',
            'description': 'There\'s a hidden message in this image. Use steganography tools to extract it.',
            'flag': 'CTF{hidden_in_plain_sight}',
            'points': 125
        },
        {
            'title': 'SQL Injection',
            'description': 'Find the SQL injection vulnerability in the login form.',
            'flag': 'CTF{sql_injection_master}',
            'points': 200
        }
    ]
    
    for challenge_data in challenges:
        add_challenge(**challenge_data)
    
    print("\n🎉 Database seeding completed!")
    print(f"📊 Total challenges: {Challenge.query.count()}")
    print(f"👥 Total users: {User.query.count()}")
    
    # Print admin credentials
    print("\n🔑 Admin Login Credentials:")
    print("Username: admin")
    print("Password: TOJO123")
    print("Email: mukherjeetojo4@gmail.com")

if __name__ == "__main__":
    with app.app_context():
        try:
            # Create all tables
            print("📋 Creating database tables...")
            db.create_all()
            print("✅ Tables created successfully")
            
            # Seed the database
            seed_database()
            
        except Exception as e:
            print(f"❌ Error during database setup: {e}")
            print("Make sure MySQL is running and the database is properly configured.") 