"""
CYSENT Authentication System - Test Script
This script tests all API endpoints to ensure everything is working correctly
"""

import requests
import json
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:5000/api"
TEST_USER = {
    "username": "testuser_" + datetime.now().strftime("%Y%m%d%H%M%S"),
    "email": f"test_{datetime.now().strftime('%Y%m%d%H%M%S')}@example.com",
    "password": "test123456"
}

print("=" * 60)
print("  CYSENT AUTHENTICATION SYSTEM - API TEST")
print("=" * 60)
print()

# Test 1: Health Check
print("Test 1: Health Check")
print("-" * 60)
try:
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    if response.status_code == 200:
        print("✓ Health check passed!")
    else:
        print("✗ Health check failed!")
except Exception as e:
    print(f"✗ Error: {e}")
    print("Make sure the backend server is running!")
    exit(1)

print()

# Test 2: Sign Up
print("Test 2: User Sign Up")
print("-" * 60)
print(f"Creating user: {TEST_USER['username']}")
try:
    response = requests.post(
        f"{BASE_URL}/signup",
        json=TEST_USER,
        headers={"Content-Type": "application/json"}
    )
    print(f"Status Code: {response.status_code}")
    data = response.json()
    print(f"Response: {json.dumps(data, indent=2)}")
    
    if response.status_code == 201 and data.get('success'):
        print("✓ Sign up successful!")
        token = data.get('token')
        print(f"Token received: {token[:20]}...")
    else:
        print(f"✗ Sign up failed: {data.get('message')}")
        exit(1)
except Exception as e:
    print(f"✗ Error: {e}")
    exit(1)

print()

# Test 3: Sign In with Email
print("Test 3: Sign In with Email")
print("-" * 60)
try:
    response = requests.post(
        f"{BASE_URL}/signin",
        json={
            "identifier": TEST_USER['email'],
            "password": TEST_USER['password']
        },
        headers={"Content-Type": "application/json"}
    )
    print(f"Status Code: {response.status_code}")
    data = response.json()
    print(f"Response: {json.dumps(data, indent=2)}")
    
    if response.status_code == 200 and data.get('success'):
        print("✓ Sign in with email successful!")
        token = data.get('token')
    else:
        print(f"✗ Sign in failed: {data.get('message')}")
        exit(1)
except Exception as e:
    print(f"✗ Error: {e}")
    exit(1)

print()

# Test 4: Sign In with Username
print("Test 4: Sign In with Username")
print("-" * 60)
try:
    response = requests.post(
        f"{BASE_URL}/signin",
        json={
            "identifier": TEST_USER['username'],
            "password": TEST_USER['password']
        },
        headers={"Content-Type": "application/json"}
    )
    print(f"Status Code: {response.status_code}")
    data = response.json()
    print(f"Response: {json.dumps(data, indent=2)}")
    
    if response.status_code == 200 and data.get('success'):
        print("✓ Sign in with username successful!")
        token = data.get('token')
    else:
        print(f"✗ Sign in failed: {data.get('message')}")
        exit(1)
except Exception as e:
    print(f"✗ Error: {e}")
    exit(1)

print()

# Test 5: Get Profile (Protected Route)
print("Test 5: Get Profile (Protected Route)")
print("-" * 60)
try:
    response = requests.get(
        f"{BASE_URL}/profile",
        headers={"Authorization": f"Bearer {token}"}
    )
    print(f"Status Code: {response.status_code}")
    data = response.json()
    print(f"Response: {json.dumps(data, indent=2)}")
    
    if response.status_code == 200 and data.get('success'):
        print("✓ Profile retrieval successful!")
    else:
        print(f"✗ Profile retrieval failed: {data.get('message')}")
except Exception as e:
    print(f"✗ Error: {e}")

print()

# Test 6: Invalid Login
print("Test 6: Invalid Login Attempt")
print("-" * 60)
try:
    response = requests.post(
        f"{BASE_URL}/signin",
        json={
            "identifier": TEST_USER['email'],
            "password": "wrongpassword"
        },
        headers={"Content-Type": "application/json"}
    )
    print(f"Status Code: {response.status_code}")
    data = response.json()
    print(f"Response: {json.dumps(data, indent=2)}")
    
    if response.status_code == 401 and not data.get('success'):
        print("✓ Invalid login correctly rejected!")
    else:
        print("✗ Security issue: Invalid login was accepted!")
except Exception as e:
    print(f"✗ Error: {e}")

print()

# Test 7: Duplicate Registration
print("Test 7: Duplicate Registration Attempt")
print("-" * 60)
try:
    response = requests.post(
        f"{BASE_URL}/signup",
        json=TEST_USER,
        headers={"Content-Type": "application/json"}
    )
    print(f"Status Code: {response.status_code}")
    data = response.json()
    print(f"Response: {json.dumps(data, indent=2)}")
    
    if response.status_code == 400 and not data.get('success'):
        print("✓ Duplicate registration correctly rejected!")
    else:
        print("✗ Security issue: Duplicate registration was accepted!")
except Exception as e:
    print(f"✗ Error: {e}")

print()

# Summary
print("=" * 60)
print("  TEST SUMMARY")
print("=" * 60)
print()
print("All tests completed!")
print(f"Test user created: {TEST_USER['username']}")
print(f"Test email: {TEST_USER['email']}")
print()
print("Next steps:")
print("1. Check MongoDB to verify the user was created")
print("2. Test the login page in your browser")
print("3. Try social login (after OAuth setup)")
print()
print("To clean up test data, run:")
print(f"  mongosh -> use cysent_db -> db.users.deleteOne({{email: '{TEST_USER['email']}'}})")
print()
print("=" * 60)
