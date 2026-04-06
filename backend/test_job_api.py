import requests
import json

BASE_URL = "http://127.0.0.1:8000"

def get_token():
    url = f"{BASE_URL}/api/auth/login"
    data = {"email": "admin@test.com", "password": "admin123"}
    resp = requests.post(url, json=data)
    return resp.json().get("access_token")

def test_job_details(job_id):
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{BASE_URL}/api/jobs/{job_id}"
    
    print(f"Testing job details for {job_id}...")
    resp = requests.get(url, headers=headers)
    print(f"Status Code: {resp.status_code}")
    try:
        data = resp.json()
        print(f"Keys in response: {list(data.keys())}")
        if "job" in data:
            print(f"Job found: {data['job'].get('job_id')}")
        else:
            print("CRITICAL: 'job' key missing from response!")
            print(f"Full response: {data}")
    except Exception as e:
        print(f"Error parsing response: {e}")
        print(f"Raw response: {resp.text}")

if __name__ == "__main__":
    # Get a job ID first
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    jobs_resp = requests.get(f"{BASE_URL}/api/jobs", headers=headers)
    jobs = jobs_resp.json()
    if jobs:
        test_job_details(jobs[0]['job_id'])
    else:
        print("No jobs found to test.")
