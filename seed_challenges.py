#!/usr/bin/env python3
"""
Seed Challenges Script for CTF Application
"""

from app import db, Challenge, fernet, app
from cryptography.fernet import Fernet

FERNET_KEY = b'DmxJF_crcWtbJwZw-cbz5LHKdr8oK8GwhociJmmL8ho='
fernet = Fernet(FERNET_KEY)

def add_challenge(title, description, flag, points):
    """Add a challenge to the database"""
    encrypted_flag = fernet.encrypt(flag.encode())
    challenge = Challenge(
        title=title,
        description=description,
        flag_encrypted=encrypted_flag,
        points=points
    )
    db.session.add(challenge)
    db.session.commit()
    print(f"✅ Added challenge: {title}")

def create_admin_user():
    """Create an admin user for managing challenges"""
    from app import User
    from werkzeug.security import generate_password_hash
    
    # Check if admin user already exists
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(
            username='admin',
            email='admin@ctf.local',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Created admin user:")
        print("   Username: admin")
        print("   Password: admin123")
        print("   Email: admin@ctf.local")
    else:
        print("ℹ️  Admin user already exists")

def seed_challenges():
    """Add initial challenges to the database"""
    
    challenges = [
        {
            "title": "Basic Web Challenge",
            "description": "Find the flag hidden in the HTML comments. Look carefully at the page source!",
            "flag": "flag{web_easy_123}",
            "points": 10
        },
        {
            "title": "Decode Me",
            "description": "This text looks strange: ZmxhZ3tzdXBlcl9iYXNlNjR9. Can you decode it?",
            "flag": "flag{super_base64}",
            "points": 20
        },
        {
            "title": "Crypto 101",
            "description": "Decrypt the message: U2ltcGxlIGNyeXB0bw==. Hint: It's base64 encoded!",
            "flag": "flag{simple_crypto}",
            "points": 15
        },
        {
            "title": "Reverse Engineering",
            "description": "What does this reversed text say? '3m4g_gn1rts_3ht_3srever'",
            "flag": "flag{reverse_this_string}",
            "points": 25
        },
        {
            "title": "Binary Challenge",
            "description": "Convert this binary to text: 01100110 01101100 01100001 01100111 01111011 01100010 01101001 01101110 01100001 01110010 01111001 01111101",
            "flag": "flag{binary}",
            "points": 30
        },
        {
            "title": "Hidden in Plain Sight",
            "description": "Sometimes the flag is right in front of you. Look at the page title!",
            "flag": "flag{hidden_in_title}",
            "points": 5
        },
        {
            "title": "Steganography Image",
            "description": "There's a hidden message in the image 'cs.jpg' in the static folder. Use steganography tools to extract it!",
            "flag": "flag{stego_image_found}",
            "points": 35
        },
        {
            "title": "SQL Injection",
            "description": "Find the SQL injection vulnerability in the login form and bypass authentication!",
            "flag": "flag{sql_injection_success}",
            "points": 40
        },
        {
            "title": "XSS Attack",
            "description": "Can you trigger a JavaScript alert on the feedback page?",
            "flag": "flag{xss_alert_triggered}",
            "points": 25
        },
        {
            "title": "Obfuscated JS",
            "description": "The flag is hidden in an obfuscated JavaScript file in the static folder. Deobfuscate it!",
            "flag": "flag{js_deobfuscated}",
            "points": 30
        },
        {
            "title": "Logic Puzzle",
            "description": "What is the next number in the sequence: 2, 6, 12, 20, ? (flag format: flag{number})",
            "flag": "flag{30}",
            "points": 15
        },
        {
            "title": "Trivia: CTF History",
            "description": "In which year was the first DEF CON CTF held? (flag format: flag{year})",
            "flag": "flag{1996}",
            "points": 10
        },
        {
            "title": "Forensics: PCAP Analysis",
            "description": "Analyze the provided PCAP file and find the flag in the HTTP traffic.",
            "flag": "flag{pcap_http_flag}",
            "points": 35
        },
        {
            "title": "Password Cracking",
            "description": "Crack the following hash: 5f4dcc3b5aa765d61d8327deb882cf99 (flag format: flag{plaintext})",
            "flag": "flag{password}",
            "points": 20
        },
        {
            "title": "Regex Master",
            "description": "Find a string that matches the regex: ^flag\{[a-z]{8}\}$ (flag format: flag{abcdefgh})",
            "flag": "flag{abcdefgh}",
            "points": 15
        },
        {
            "title": "Network Trivia",
            "description": "What port does HTTPS use by default? (flag format: flag{port})",
            "flag": "flag{443}",
            "points": 10
        },
        {
            "title": "Encoding Chain",
            "description": "The flag is base64, then hex, then reversed. Can you decode it? '3d7b67616c6627' (flag format: flag{...})",
            "flag": "flag{lag7d3}",
            "points": 25
        },
        {
            "title": "Zip Bomb",
            "description": "Download and analyze the zip file in the static folder. The flag is in the deepest file!",
            "flag": "flag{zip_bombed}",
            "points": 30
        },
        {
            "title": "Classic Caesar",
            "description": "Decrypt this Caesar cipher (shift 13): synt{fghqrag_rapbqvat}",
            "flag": "flag{student_encoding}",
            "points": 20
        },
        {
            "title": "Trivia: RFC 1918",
            "description": "Name one of the private IPv4 address ranges (flag format: flag{range})",
            "flag": "flag{10.0.0.0/8}",
            "points": 10
        }
    ]
    print("🌱 Seeding challenges...")
    for challenge_data in challenges:
        add_challenge(**challenge_data)
    print(f"✅ Added {len(challenges)} challenges to the database!")

if __name__ == "__main__":
    with app.app_context():
        print("🚀 Starting database seeding...")
        
        # Create admin user
        create_admin_user()
        
        # Seed challenges
        seed_challenges()
        
        print("\n🎉 Database seeding completed!")
        print("You can now:")
        print("1. Login as admin (admin/admin123) to add more challenges")
        print("2. Create regular user accounts to solve challenges")
        print("3. View the scoreboard at /scoreboard") 