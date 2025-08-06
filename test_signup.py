#!/usr/bin/env python3
"""
Simple test script to verify signup functionality
"""

import requests
import json

def test_signup():
    base_url = "http://127.0.0.1:5000"
    
    # Test data
    test_user = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpass123",
        "confirm_password": "testpass123"
    }
    
    print("Testing signup functionality...")
    
    try:
        # Test 1: Valid signup
        print("1. Testing valid signup...")
        response = requests.post(f"{base_url}/signup", data=test_user)
        print(f"   Status Code: {response.status_code}")
        print(f"   Response: {response.text[:200]}...")
        
        # Test 2: Password mismatch
        print("\n2. Testing password mismatch...")
        test_user["confirm_password"] = "wrongpassword"
        response = requests.post(f"{base_url}/signup", data=test_user)
        print(f"   Status Code: {response.status_code}")
        print(f"   Response: {response.text[:200]}...")
        
        # Test 3: Short password
        print("\n3. Testing short password...")
        test_user["password"] = "123"
        test_user["confirm_password"] = "123"
        response = requests.post(f"{base_url}/signup", data=test_user)
        print(f"   Status Code: {response.status_code}")
        print(f"   Response: {response.text[:200]}...")
        
        print("\n✅ Signup tests completed!")
        
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to the server. Make sure the Flask app is running.")
    except Exception as e:
        print(f"❌ Error during testing: {e}")

if __name__ == "__main__":
    test_signup() 