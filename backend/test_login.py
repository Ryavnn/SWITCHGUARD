import requests
import json

BASE_URL = "http://127.0.0.1:8000"

def test_login(email, password):
    print(f"Testing login for {email}...")
    url = f"{BASE_URL}/api/auth/login"
    data = {"email": email, "password": password}
    
    try:
        response = requests.post(url, json=data)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            token = response.json().get("access_token")
            print("Successfully logged in! Token acquired.")
            
            # Test protected route
            print("\nTesting protected route /api/jobs...")
            headers = {"Authorization": f"Bearer {token}"}
            resp = requests.get(f"{BASE_URL}/api/jobs", headers=headers)
            print(f"Status Code: {resp.status_code}")
            print(f"Response Summary: {resp.text[:100]}...")
        else:
            print("Login failed.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_login("admin@test.com", "admin123")
