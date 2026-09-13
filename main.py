from fastapi import FastAPI, HTTPException, Header, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
from dotenv import load_dotenv
from google import genai
from google.genai import types
import os
import sqlite3
import hashlib
import secrets
import datetime
from courses import courses

load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "pathfinder.db"
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS chats (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        created_at TEXT NOT NULL,
        pinned INTEGER DEFAULT 0,
        archived INTEGER DEFAULT 0,
        unread INTEGER DEFAULT 0
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id TEXT NOT NULL,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()

init_db()

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return pwd_hash, salt

def verify_password(password, salt, stored_hash):
    check_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(check_hash, stored_hash)

def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid token")
    token = authorization.split(" ")[1]
    conn = get_db()
    row = conn.execute("SELECT user_id FROM tokens WHERE token=?", (token,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(401, "Invalid or expired token")
    return row["user_id"]

class AuthRequest(BaseModel):
    username: str
    password: str

class ChatMessageRequest(BaseModel):
    chat_id: str
    message: str

class ChatUpdateRequest(BaseModel):
    title: Optional[str] = None
    pinned: Optional[bool] = None
    archived: Optional[bool] = None
    unread: Optional[bool] = None

@app.post("/signup")
def signup(req: AuthRequest):
    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE username=?", (req.username,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(400, "Username already taken")
    pwd_hash, salt = hash_password(req.password)
    cur = conn.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                        (req.username, pwd_hash, salt))
    user_id = cur.lastrowid
    token = secrets.token_hex(32)
    conn.execute("INSERT INTO tokens (token, user_id) VALUES (?, ?)", (token, user_id))
    conn.commit()
    conn.close()
    return {"token": token, "username": req.username}

@app.post("/login")
def login(req: AuthRequest):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (req.username,)).fetchone()
    if not user or not verify_password(req.password, user["salt"], user["password_hash"]):
        conn.close()
        raise HTTPException(401, "Invalid username or password")
    token = secrets.token_hex(32)
    conn.execute("INSERT INTO tokens (token, user_id) VALUES (?, ?)", (token, user["id"]))
    conn.commit()
    conn.close()
    return {"token": token, "username": req.username}

@app.post("/chats")
def create_chat(user_id: int = Depends(get_current_user)):
    conn = get_db()
    chat_id = secrets.token_hex(8)
    conn.execute("INSERT INTO chats (id, user_id, title, created_at, pinned, archived, unread) VALUES (?, ?, ?, ?, 0, 0, 0)",
                 (chat_id, user_id, "New chat", datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return {"id": chat_id, "title": "New chat", "pinned": False, "archived": False, "unread": False}

@app.get("/chats")
def list_chats(user_id: int = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute(
        "SELECT id, title, created_at, pinned, archived, unread FROM chats WHERE user_id=? ORDER BY pinned DESC, created_at DESC",
        (user_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.patch("/chats/{chat_id}")
def update_chat(chat_id: str, req: ChatUpdateRequest, user_id: int = Depends(get_current_user)):
    conn = get_db()
    chat = conn.execute("SELECT * FROM chats WHERE id=? AND user_id=?", (chat_id, user_id)).fetchone()
    if not chat:
        conn.close()
        raise HTTPException(404, "Chat not found")
    if req.title is not None:
        conn.execute("UPDATE chats SET title=? WHERE id=?", (req.title, chat_id))
    if req.pinned is not None:
        conn.execute("UPDATE chats SET pinned=? WHERE id=?", (1 if req.pinned else 0, chat_id))
    if req.archived is not None:
        conn.execute("UPDATE chats SET archived=? WHERE id=?", (1 if req.archived else 0, chat_id))
    if req.unread is not None:
        conn.execute("UPDATE chats SET unread=? WHERE id=?", (1 if req.unread else 0, chat_id))
    conn.commit()
    conn.close()
    return {"updated": True}

@app.delete("/chats/{chat_id}")
def delete_chat(chat_id: str, user_id: int = Depends(get_current_user)):
    conn = get_db()
    chat = conn.execute("SELECT * FROM chats WHERE id=? AND user_id=?", (chat_id, user_id)).fetchone()
    if not chat:
        conn.close()
        raise HTTPException(404, "Chat not found")
    conn.execute("DELETE FROM messages WHERE chat_id=?", (chat_id,))
    conn.execute("DELETE FROM chats WHERE id=?", (chat_id,))
    conn.commit()
    conn.close()
    return {"deleted": True}

@app.get("/chats/{chat_id}/messages")
def get_messages(chat_id: str, user_id: int = Depends(get_current_user)):
    conn = get_db()
    chat = conn.execute("SELECT * FROM chats WHERE id=? AND user_id=?", (chat_id, user_id)).fetchone()
    if not chat:
        conn.close()
        raise HTTPException(404, "Chat not found")
    conn.execute("UPDATE chats SET unread=0 WHERE id=?", (chat_id,))
    conn.commit()
    rows = conn.execute("SELECT id, role, content FROM messages WHERE chat_id=? ORDER BY id ASC", (chat_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.delete("/messages/{message_id}")
def delete_message(message_id: int, user_id: int = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("""
        SELECT messages.id FROM messages
        JOIN chats ON messages.chat_id = chats.id
        WHERE messages.id=? AND chats.user_id=?
    """, (message_id, user_id)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Message not found")
    conn.execute("DELETE FROM messages WHERE id=?", (message_id,))
    conn.commit()
    conn.close()
    return {"deleted": True}

def build_prompt(conversation_text):
    return f"""
You are PathFinder, a friendly learning path advisor having a natural conversation.

Available courses (JSON):
{courses}

Full conversation so far:
{conversation_text}

Instructions:
- If the learner has only greeted you or hasn't shared their goal and skill level yet, DO NOT recommend courses. Instead, warmly introduce yourself in 1-2 sentences and ask what they want to learn.
- If they've shared a goal but not their current skill level (beginner/intermediate/advanced), ask that before recommending.
- Only recommend a learning path once you know BOTH their goal AND their current skill level.
- When you do recommend, use ONLY the courses listed above, in this format:
  **[Course Title]** — [one-line reason]
- Keep every response under 100 words.
- Sound natural and conversational, not like a report.
"""

@app.post("/chat")
def chat(req: ChatMessageRequest, user_id: int = Depends(get_current_user)):
    conn = get_db()
    chat_row = conn.execute("SELECT * FROM chats WHERE id=? AND user_id=?", (req.chat_id, user_id)).fetchone()
    if not chat_row:
        conn.close()
        raise HTTPException(404, "Chat not found")

    now = datetime.datetime.utcnow().isoformat()
    conn.execute("INSERT INTO messages (chat_id, role, content, created_at) VALUES (?, ?, ?, ?)",
                 (req.chat_id, "user", req.message, now))

    msg_count = conn.execute("SELECT COUNT(*) as c FROM messages WHERE chat_id=?", (req.chat_id,)).fetchone()["c"]
    if msg_count == 1:
        title = req.message[:28] + ("..." if len(req.message) > 28 else "")
        conn.execute("UPDATE chats SET title=? WHERE id=?", (title, req.chat_id))

    history_rows = conn.execute("SELECT role, content FROM messages WHERE chat_id=? ORDER BY id ASC",
                                 (req.chat_id,)).fetchall()
    conversation_text = "\n".join([f"{r['role']}: {r['content']}" for r in history_rows])

    prompt = build_prompt(conversation_text)
    response = client.models.generate_content(model="gemini-3.6-flash", contents=prompt)
    reply = response.text

    conn.execute("INSERT INTO messages (chat_id, role, content, created_at) VALUES (?, ?, ?, ?)",
                 (req.chat_id, "assistant", reply, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return {"reply": reply}

@app.post("/upload")
async def upload_file(
    chat_id: str = Form(...),
    message: str = Form(""),
    file: UploadFile = File(...),
    user_id: int = Depends(get_current_user)
):
    conn = get_db()
    chat_row = conn.execute("SELECT * FROM chats WHERE id=? AND user_id=?", (chat_id, user_id)).fetchone()
    if not chat_row:
        conn.close()
        raise HTTPException(404, "Chat not found")

    file_bytes = await file.read()
    saved_path = os.path.join(UPLOAD_DIR, f"{secrets.token_hex(6)}_{file.filename}")
    with open(saved_path, "wb") as f:
        f.write(file_bytes)

    user_note = message if message else f"[Uploaded file: {file.filename}]"
    conn.execute("INSERT INTO messages (chat_id, role, content, created_at) VALUES (?, ?, ?, ?)",
                 (chat_id, "user", user_note, datetime.datetime.utcnow().isoformat()))

    try:
        image_part = types.Part.from_bytes(data=file_bytes, mime_type=file.content_type)
        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=[image_part, message or "Please look at this and help me based on my learning goals."]
        )
        reply = response.text
    except Exception as e:
        reply = f"I received your file, but couldn't process it as an image ({str(e)}). Could you describe what's in it instead?"

    conn.execute("INSERT INTO messages (chat_id, role, content, created_at) VALUES (?, ?, ?, ?)",
                 (chat_id, "assistant", reply, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return {"reply": reply}

@app.get("/api/courses")
def get_courses():
    return courses

# Serve the frontend (static/index.html) for every route the API above doesn't
# already handle. This MUST be the last thing registered, and it must stay
# after every @app.get/@app.post route above it.
app.mount("/", StaticFiles(directory="static", html=True), name="static")
