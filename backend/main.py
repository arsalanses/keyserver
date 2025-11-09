import redis
import base64
import string
import secrets
from typing import Optional
from fastapi import Request
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Salt Keyserver (Email-based)")

r = redis.Redis(host='keyserver-redis', port=6379, db=0)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SaltUpload(BaseModel):
    email: Optional[str] = None
    salt: str
    expires_in: Optional[int] = 300

@app.post("/upload-salt")
def upload_salt(data: SaltUpload):
    r.set(data.email, data.salt, ex=300)
    print(f"[Server] Salt stored for {data.email}")
    return {"status": "salt uploaded", "email": data.email}

@app.get("/salt/{email}")
def get_salt(email: str):
    salt_b64 = r.get(email)
    if not salt_b64:
        raise HTTPException(404, f"No salt for {email}")
    return {"email": email, "salt": salt_b64.decode()}

@app.get("/ttl/{email}")
def get_ttl(email: str):
    ttl = r.ttl(email)
    if ttl == -2:
        raise HTTPException(404, "No salt")
    return {"email": email, "seconds_left": ttl}

@app.post("/upload-salt-anon")
def upload_salt_anon(data: SaltUpload, request: Request):
    ex_time = data.expires_in

    path = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    r.set(f"salt:{path}", data.salt, ex=ex_time)
    url = f"{str(request.base_url).rstrip('/')}/s/{path}"
    return {"status": "ok", "url": url, "expires_in_seconds": ex_time, "expires_at": r.ttl(f"salt:{path}")}

@app.get("/s/{path}")
def get_salt_by_path(path: str):
    salt = r.get(f"salt:{path}")
    count_key = f"count:{path}"
    if not salt:
        raise HTTPException(404, "Not found or expired")
    views = r.incr(count_key)
    return {"salt": salt.decode(), "views": views, "expires_at": r.ttl(f"salt:{path}")}

@app.get("/")
def home():
    return {"message": "Salt Keyserver", "endpoints": ["/upload-salt", "/salt/{email}", "/ttl/{email}"]}
