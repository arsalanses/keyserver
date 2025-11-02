from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import redis
import base64

app = FastAPI(title="Salt Keyserver (Email-based)")

r = redis.Redis(host='redis', port=6379, db=0)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SaltUpload(BaseModel):
    email: str
    salt: str

@app.post("/upload-salt")
def upload_salt(data: SaltUpload):
    r.set(data.email, data.salt)
    print(f"[Server] Salt stored for {data.email}")
    return {"status": "salt uploaded", "email": data.email}

@app.get("/salt/{email}")
def get_salt(email: str):
    salt_b64 = r.get(email)
    if not salt_b64:
        raise HTTPException(404, f"No salt for {email}")
    return {"email": email, "salt": salt_b64.decode()}

@app.get("/")
def home():
    return {"message": "Salt Keyserver", "endpoints": ["/upload-salt", "/salt/{email}"]}
