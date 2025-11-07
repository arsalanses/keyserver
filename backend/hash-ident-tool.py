from fastapi import FastAPI, Request, Form
from fastapi.templating import Jinja2Templates
# from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import re

app = FastAPI(
    title="Hash Identifier Tool",
    description="Academic tool to identify cryptographic hash types",
    version="1.0"
)

# app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

HASH_DB = [
    {"name": "MD5", "length": 32, "regex": r"^[a-f0-9]{32}$", "example": "d41d8cd98f00b204e9800998ecf8427e"},
    {"name": "SHA-1", "length": 40, "regex": r"^[a-f0-9]{40}$", "example": "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
    {"name": "SHA-256", "length": 64, "regex": r"^[a-f0-9]{64}$", "example": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"name": "SHA-512", "length": 128, "regex": r"^[a-f0-9]{128}$", "example": "cf83e1357ee..."},
    {"name": "MySQL5", "regex": r"^\*[A-F0-9]{40}$", "example": "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"},
    {"name": "bcrypt", "regex": r"^\$2[aby]?\$\d{2}\$.{53}$", "example": "$2y$12$..." },
    {"name": "NTLM", "length": 32, "regex": r"^[a-f0-9]{32}$", "note": "Same as MD5, context-based"},
    {"name": "LM", "length": 32, "regex": r"^[a-f0-9]{32}$", "note": "Uppercase in practice"},
]

def identify_hash(hash_input: str):
    hash_input = hash_input.strip()
    results = []

    for h in HASH_DB:
        if "length" in h and len(hash_input) != h["length"]:
            continue
        if h["regex"] and re.match(h["regex"], hash_input, re.IGNORECASE):
            results.append(h)

    if not results:
        length = len(hash_input)
        possible = [h for h in HASH_DB if "length" in h and h["length"] == length]
        for p in possible:
            p["note"] = "Possible match by length"
            results.append(p)

    return results if results else [{"name": "Unknown", "note": "No match found"}]

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/identify", response_class=HTMLResponse)
async def identify(request: Request, hash_value: str = Form(...)):
    results = identify_hash(hash_value)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "hash_input": hash_value,
        "results": results
    })
