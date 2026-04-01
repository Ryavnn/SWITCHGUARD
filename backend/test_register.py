from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

response = client.post(
    "/api/auth/register",
    json={"name": "Test User", "email": "unique123@test.com", "password": "password"}
)
print("Status:", response.status_code)
print("Response:", response.text)
