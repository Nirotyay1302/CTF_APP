#!/usr/bin/env python3
"""
Test script to verify scoreboard functionality
"""

import requests
import json

def test_scoreboard():
    base_url = "http://127.0.0.1:5000"
    
    print("🧪 Testing scoreboard functionality...")
    
    try:
        # Test 1: Access scoreboard without login (should redirect to login)
        print("1. Testing scoreboard access without login...")
        response = requests.get(f"{base_url}/scoreboard", allow_redirects=False)
        print(f"   Status Code: {response.status_code}")
        if response.status_code == 302:
            print("   ✅ Correctly redirects to login when not authenticated")
        else:
            print("   ❌ Should redirect to login")
        
        # Test 2: Login and then access scoreboard
        print("\n2. Testing scoreboard access after login...")
        
        # Login first
        login_data = {
            "username": "admin",
            "password": "TOJO123"
        }
        
        session = requests.Session()
        login_response = session.post(f"{base_url}/login", data=login_data)
        
        if login_response.status_code == 302:
            print("   ✅ Login successful")
            
            # Now access scoreboard
            scoreboard_response = session.get(f"{base_url}/scoreboard")
            print(f"   Scoreboard Status Code: {scoreboard_response.status_code}")
            
            if scoreboard_response.status_code == 200:
                print("   ✅ Scoreboard accessible after login")
                
                # Check if scoreboard contains expected elements
                content = scoreboard_response.text
                if "CTF Scoreboard" in content:
                    print("   ✅ Scoreboard page loaded correctly")
                else:
                    print("   ❌ Scoreboard page content not found")
                    
                if "admin" in content:
                    print("   ✅ Admin user appears in scoreboard")
                else:
                    print("   ❌ Admin user not found in scoreboard")
                    
            else:
                print("   ❌ Could not access scoreboard after login")
        else:
            print("   ❌ Login failed")
        
        print("\n✅ Scoreboard tests completed!")
        
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to the server. Make sure the Flask app is running.")
    except Exception as e:
        print(f"❌ Error during testing: {e}")

def test_scoreboard_data():
    """Test scoreboard data structure"""
    print("\n📊 Testing scoreboard data structure...")
    
    try:
        from app import app, db, User, Challenge, Solve
        
        with app.app_context():
            # Get all users
            users = User.query.all()
            print(f"   Total users: {len(users)}")
            
            # Get all challenges
            challenges = Challenge.query.all()
            print(f"   Total challenges: {len(challenges)}")
            
            # Get all solves
            solves = Solve.query.all()
            print(f"   Total solves: {len(solves)}")
            
            # Calculate scores for each user
            for user in users:
                solve_count = Solve.query.filter_by(user_id=user.id).count()
                score = db.session.query(db.func.sum(Challenge.points)).join(Solve, Challenge.id == Solve.challenge_id).filter(Solve.user_id == user.id).scalar() or 0
                print(f"   {user.username}: {solve_count} solves, {score} points")
            
            print("✅ Scoreboard data structure test completed!")
            
    except Exception as e:
        print(f"❌ Error testing scoreboard data: {e}")

if __name__ == "__main__":
    test_scoreboard()
    test_scoreboard_data() 