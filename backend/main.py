import redis
import base64
import string
import secrets
from typing import Optional
from fastapi import Request
from pydantic import BaseModel
from transformers import pipeline
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Salt Keyserver")

r = redis.Redis(host='keyserver-redis', port=6379, db=0)
rr1 = redis.Redis(host='keyserver-redis-r1', port=6379, db=0)
generator = pipeline('text-generation', model='distilgpt2', max_length=100)   # Hugging Face + OpenAI lineage

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
    limit_counter: Optional[int] = 5

def ai_random_string(length: int = 20) -> str:
    prompt = "randomstring:"
    result = generator(prompt, max_length=length + 20, num_return_sequences=1)[0]['generated_text']
    print(f"result: {result}")

    clean = ''.join(c for c in result[len(prompt):] if c in string.ascii_letters + string.digits)
    
    return clean[:length]

@app.post("/upload-salt-anon")
def upload_salt_anon(data: SaltUpload, request: Request):
    ex_time = data.expires_in
    limit_counter = data.limit_counter

    # path = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    path = ai_random_string(15)

    r.set(f"salt:{path}", data.salt, ex=ex_time)
    r.set(f"limit_counter:{path}", data.limit_counter, ex=ex_time)

    url = f"{str(request.base_url).rstrip('/')}/s/{path}"

    return {"status": "ok", "url": url, "expires_in_seconds": ex_time, "expires_at": r.ttl(f"salt:{path}"), "limit_counter": data.limit_counter}

@app.get("/s/{path}")
def get_salt_by_path(path: str):
    salt = rr1.get(f"salt:{path}")
    if not salt:
        raise HTTPException(404, "Not found or expired")

    limit_counter = rr1.get(f"limit_counter:{path}")
    if int(limit_counter) < 1:
        raise HTTPException(404, "Not found or counter expired")

    limit_counter = r.decr(f"limit_counter:{path}")
    return {"salt": salt.decode(), "limit_counter": limit_counter, "expires_at": r.ttl(f"salt:{path}")}

@app.get("/")
def home():
    return {"message": "Keyserver"}
