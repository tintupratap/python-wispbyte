# app.py
import asyncio
import hashlib
import hmac
import secrets
from typing import Dict, Optional, Set

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    Request,
    Depends,
    HTTPException,
    status,
)
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, create_engine, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# -------------------------
# Simple DB (SQLite async)
# -------------------------
DATABASE_URL = "sqlite+aiosqlite:///./wispchat.db"
engine = create_async_engine(DATABASE_URL, echo=False, future=True)
AsyncSessionLocal = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True, nullable=False)
    pwd_hash = Column(String, nullable=False)
    token = Column(String, unique=True, index=True, nullable=False)

# -------------------------
# Utilities: hashing & token
# -------------------------
SALT = b"wispbyte-example-salt"  # replace/change to secure config in production

def hash_password(password: str) -> str:
    """Return hex digest of salted sha256 (simple example). Use bcrypt/argon2 in prod."""
    return hashlib.sha256(SALT + password.encode("utf-8")).hexdigest()

def verify_password(password: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_password(password), stored_hash)

def make_token() -> str:
    return secrets.token_urlsafe(32)

# -------------------------
# FastAPI app + DB init
# -------------------------
app = FastAPI(title="WispChat (single-port websocket chat)")

@app.on_event("startup")
async def startup() -> None:
    # create tables if not exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# Dependency to get DB session
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

# -------------------------
# REST: register / login
# -------------------------
class RegisterIn(BaseModel):
    username: str
    password: str

class LoginIn(BaseModel):
    username: str
    password: str

@app.post("/register")
async def register(data: RegisterIn, db: AsyncSession = Depends(get_db)):
    username = data.username.strip()
    if not username:
        raise HTTPException(400, "username required")
    stmt = select(User).where(User.username == username)
    r = await db.execute(stmt)
    existing = r.scalars().first()
    if existing:
        raise HTTPException(status_code=400, detail="username already taken")

    pwd_hash = hash_password(data.password)
    token = make_token()
    user = User(username=username, pwd_hash=pwd_hash, token=token)
    db.add(user)
    await db.commit()
    return {"username": username, "token": token}

@app.post("/login")
async def login(data: LoginIn, db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(User.username == data.username)
    r = await db.execute(stmt)
    user = r.scalars().first()
    if not user or not verify_password(data.password, user.pwd_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    return {"username": user.username, "token": user.token}

# -------------------------
# WebSocket connection manager
# -------------------------
class ConnectionManager:
    def __init__(self):
        # mapping websocket -> metadata dict (username or alias)
        self.active: Dict[WebSocket, Dict] = {}
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, meta: Dict):
        await websocket.accept()
        async with self.lock:
            self.active[websocket] = meta
        await self.broadcast_system(f"{meta.get('display')} joined the chat")

    async def disconnect(self, websocket: WebSocket):
        async with self.lock:
            meta = self.active.pop(websocket, None)
        if meta:
            await self.broadcast_system(f"{meta.get('display')} left the chat")

    async def send_personal(self, websocket: WebSocket, message: str):
        await websocket.send_json({"type": "message", "payload": message})

    async def broadcast(self, sender_meta: Dict, text: str):
        payload = {
            "type": "message",
            "from": sender_meta.get("display"),
            "user_id": sender_meta.get("user_id"),
            "text": text,
        }
        async with self.lock:
            webs = list(self.active.keys())
        coros = [ws.send_json(payload) for ws in webs]
        if coros:
            await asyncio.gather(*coros, return_exceptions=True)

    async def broadcast_system(self, text: str):
        payload = {"type": "system", "text": text}
        async with self.lock:
            webs = list(self.active.keys())
        coros = [ws.send_json(payload) for ws in webs]
        if coros:
            await asyncio.gather(*coros, return_exceptions=True)

manager = ConnectionManager()

# -------------------------
# Helper: validate token
# -------------------------
async def get_user_by_token(token: str, db: AsyncSession) -> Optional[User]:
    if not token:
        return None
    stmt = select(User).where(User.token == token)
    r = await db.execute(stmt)
    return r.scalars().first()

# -------------------------
# WebSocket endpoint
# -------------------------
# Clients should connect to: ws://<host>:8000/ws?token=<token>&alias=<alias>
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, request: Request, db: AsyncSession = Depends(get_db)):
    # read query params
    qs = dict(request.query_params)
    token = qs.get("token")
    alias = qs.get("alias")

    # authenticate if token provided, otherwise treat as anonymous alias
    user = await get_user_by_token(token, db) if token else None
    if user:
        display = user.username
        user_id = user.id
    else:
        # if no alias supplied, generate one
        if not alias or not alias.strip():
            alias = f"anon-{secrets.token_hex(3)}"
        display = alias
        user_id = None

    meta = {"display": display, "user_id": user_id}
    await manager.connect(websocket, meta)

    try:
        while True:
            data = await websocket.receive_json()
            # expected shape: {"text": "..."}
            text = data.get("text", "").strip()
            if not text:
                continue
            # a simple rate limiter could be added here
            await manager.broadcast(meta, text)
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as exc:
        # try to close socket gracefully
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
        await manager.disconnect(websocket)

# -------------------------
# Tiny web client UI (served on same port)
# -------------------------
INDEX_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>WispChat</title>
  <style>
    body { font-family: system-ui, Arial; max-width:900px; margin:20px auto; }
    #log { height: 60vh; border:1px solid #ddd; padding:8px; overflow:auto; }
    .msg { margin:4px 0; }
    .sys { color: gray; font-style: italic; }
  </style>
</head>
<body>
  <h2>WispChat (single-port WebSocket)</h2>

  <div>
    <label>Token (leave empty for anonymous): <input id=token size=40 placeholder="paste token here"></label><br>
    <label>Alias (for anonymous): <input id=alias placeholder="e.g. cool_cat"></label>
    <button id=connect>Connect</button>
  </div>

  <div id=log></div>

  <form id=form"">
    <input id=message size=80 autocomplete="off" placeholder="type message...">
    <button id=send type=button disabled>Send</button>
  </form>

<script>
let ws;
const log = (html, cls='msg') => {
  const d = document.getElementById('log');
  const el = document.createElement('div');
  el.className = cls;
  el.innerHTML = html;
  d.appendChild(el);
  d.scrollTop = d.scrollHeight;
};

document.getElementById('connect').onclick = () => {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.close();
    return;
  }
  const token = encodeURIComponent(document.getElementById('token').value.trim());
  const alias = encodeURIComponent(document.getElementById('alias').value.trim());
  const q = [];
  if (token) q.push('token=' + token);
  if (alias) q.push('alias=' + alias);
  const query = q.length ? '?' + q.join('&') : '';
  const proto = (location.protocol === 'https:') ? 'wss' : 'ws';
  const url = `${proto}://${location.host}/ws${query}`;
  ws = new WebSocket(url);

  ws.onopen = () => {
    log('<em>connected</em>', 'sys');
    document.getElementById('send').disabled = false;
  };
  ws.onclose = (e) => {
    log('<em>disconnected</em>', 'sys');
    document.getElementById('send').disabled = true;
  };
  ws.onerror = (e) => {
    log('<em>socket error</em>', 'sys');
  };
  ws.onmessage = (ev) => {
    try {
      const d = JSON.parse(ev.data);
      if (d.type === 'system') {
        log('<span class="sys">' + d.text + '</span>', 'sys');
      } else if (d.type === 'message') {
        log('<strong>' + (d.from||'unknown') + ':</strong> ' + d.text);
      } else {
        log(JSON.stringify(d));
      }
    } catch(err){
      log(ev.data);
    }
  };
};

document.getElementById('send').onclick = () => {
  const input = document.getElementById('message');
  if (!ws || ws.readyState !== WebSocket.OPEN) return alert('not connected');
  const txt = input.value.trim();
  if (!txt) return;
  ws.send(JSON.stringify({text: txt}));
  input.value = '';
};
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(INDEX_HTML)


# main.py
# ... (rest of the code I gave you stays the same)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=10000, reload=False)
