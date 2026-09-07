# ============================================================
# GreenBuck API — main.py
# FastAPI backend for the GreenBuck research project.
# Handles transaction CRUD and logs research metadata for
# every request via the timing log middleware.
# ============================================================

# ---- Imports ----
from contextlib import asynccontextmanager # For the lifespan context manager
from fastapi import FastAPI, HTTPException, Request # Web framework, error handling, request access
from pydantic import BaseModel # Request body validation via type hints
from typing import Optional # For nullable fields
from datetime import datetime, timezone, timedelta # Timestamps for the timing log
import asyncpg # Async PostgreSQL driver
import logging # Server-side error logging
import psutil # CPU utilization measurement per request
import uuid # Auto-generate request IDs if client doesn't send one
import time # High-resolution duration timing
import asyncio # For non-blocking sleep used by jitter and constant-rate mitigations
import random # Generates random delay values for the jitter mitigation
import os  # Read configuration from environment variables
import jwt  # PyJWT — encode/decode JSON Web Tokens
from argon2 import PasswordHasher  # Argon2id password hashing
from argon2.exceptions import VerifyMismatchError  # Raised on wrong password
from fastapi import Depends  # For the auth dependency on protected routes
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials  # Bearer token extraction
# ---- Logging Setup ----
# Configure Python's logger so we can write info and error messages
# that show up in the uvicorn console.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---- Auth Configuration ----
# SECRET_KEY signs the JWTs. In production this comes from an environment
# variable or secrets manager, never hardcoded. For this research
# instrument on an isolated network it lives here.
SECRET_KEY = os.environ["SECRET_KEY"]
JWT_ALGORITHM = "HS256"            # HMAC-SHA256, symmetric signing
TOKEN_EXPIRE_MINUTES = 30           # Access tokens expire after 30 minutes

# Argon2id password hasher (OWASP-recommended defaults).
ph = PasswordHasher()

# HTTPBearer extracts the "Authorization: Bearer <token>" header.
# auto_error=False lets us return our own 401 messages.
security = HTTPBearer(auto_error=False)


def hash_password(plain: str) -> str:
    """Hash a plaintext password with Argon2id. Salt is automatic."""
    return ph.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a stored Argon2id hash."""
    try:
        ph.verify(hashed, plain)
        return True
    except VerifyMismatchError:
        return False


def create_access_token(username: str) -> str:
    """Create a signed JWT carrying the username and an expiry."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Verify the Bearer token on protected routes. Returns the username
    from the token, or raises 401 if missing/invalid/expired."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ---- Database Pool (Global) ----
# This holds the asyncpg connection pool. Initialized at startup
# inside the lifespan function below. Shared across all routes.
pool: Optional[asyncpg.Pool] = None


# ---- Lifespan: Startup and Shutdown Hooks ----
# FastAPI calls this once when the server starts and once when it
# shuts down. We use it to create the database connection pool
# at startup and close it cleanly at shutdown.
@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    try: # Create a pool of 2-10 database connections shared by all requests.
        pool = await asyncpg.create_pool(
            database="greenbuck",
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASSWORD"],
            host="localhost",
            min_size=2,
            max_size=10,
        )
        logger.info("Database connection pool created")
    except Exception as e:
        logger.error(f"Failed to create database pool: {e}")
        raise # If the pool fails, the server should not start.
    yield # Server runs while paused here. After shutdown signal:
    if pool:
        await pool.close()
        logger.info("Database connection pool closed")

# ---- FastAPI App Instance ----
app = FastAPI(lifespan=lifespan)

# ============================================================
# Mitigation Middleware
# Applies server-side traffic shaping based on the X-Mitigation
# header. Three mitigations plus a no-op control:
#   - none: passthrough (control condition)
#   - padding: pads response to a fixed size
#   - jitter: random delay before response
#   - constant: fixed total response time regardless of work
# ============================================================

# Tunable mitigation parameters. These would be parameter-swept
# in a follow-up study; for this paper they are held constant.
PADDING_TARGET_BYTES = 4096   # All padded responses become 4KB
JITTER_MIN_MS = 0             # Lower bound for jitter delay
JITTER_MAX_MS = 50            # Upper bound for jitter delay
CONSTANT_RATE_TARGET_MS = 100 # Every response takes exactly this long


@app.middleware("http")
async def mitigation_middleware(request: Request, call_next):
    mitigation = request.headers.get("X-Mitigation", "none")

    # Track wall-clock time for constant-rate mitigation.
    start = time.perf_counter()

    # Process the actual request.
    response = await call_next(request)

    if mitigation == "none":
        # Control condition — no mitigation applied.
        return response

    elif mitigation == "jitter":
        # Random delay before sending response.
        delay_ms = random.uniform(JITTER_MIN_MS, JITTER_MAX_MS)
        await asyncio.sleep(delay_ms / 1000)
        return response

    elif mitigation == "constant":
        # Pad the total request time to a fixed target.
        elapsed_ms = (time.perf_counter() - start) * 1000
        remaining_ms = CONSTANT_RATE_TARGET_MS - elapsed_ms
        if remaining_ms > 0:
            await asyncio.sleep(remaining_ms / 1000)
        return response

    elif mitigation == "padding":
        # Pad the response body to a fixed size by reading the
        # body and appending whitespace until it reaches target.
        # Requires reading + reconstructing the response.
        body = b""
        async for chunk in response.body_iterator:
            body += chunk

        # Only pad if the body is valid JSON ending in } or ].
        # If it's smaller than target, inject a padding field.
        # If already at or above target, leave it alone.
        if body.endswith(b"}") and len(body) < PADDING_TARGET_BYTES:
            padding_needed = PADDING_TARGET_BYTES - len(body) - 14  # account for ', "_pad": ""'
            if padding_needed > 0:
                pad_str = b"x" * padding_needed
                body = body[:-1] + b',"_pad":"' + pad_str + b'"}'

        from fastapi import Response
        return Response(
            content=body,
            status_code=response.status_code,
            headers={k: v for k, v in response.headers.items() if k.lower() != "content-length"},
            media_type=response.media_type,
        )
    # Unknown mitigation value — treat as no-op.
    return response

# ============================================================
# Timing Log Middleware
# Stamps every request with research metadata and writes a row
# to the timing_log table. This is the primary research dataset.
# ============================================================
@app.middleware("http")
async def timing_middleware(request: Request, call_next):
    receive_time = datetime.now(timezone.utc) # Wall-clock time, UTC
    start = time.perf_counter() # Monotonic timer for accurate duration
    cpu_before = psutil.cpu_percent(interval=None) # CPU snapshot

    # Pull research metadata from request headers
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    action_type = request.headers.get("X-Action", "unknown")
    platform = request.headers.get("X-Platform", "unknown")
    encryption_mode = request.headers.get("X-Encryption", "none")
    mitigation_state = request.headers.get("X-Mitigation", "none")

    # Process the request
    response = await call_next(request)

    response_sent_time = datetime.now(timezone.utc)
    duration_ms = (time.perf_counter() - start) * 1000
    cpu_after = psutil.cpu_percent(interval=None)
    cpu_avg = (cpu_before + cpu_after) / 2
    # Write to timing_log (don't let logging errors break the response)
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO timing_log (
                    request_id, action_type, platform, encryption_mode,
                    mitigation_state, receive_time, response_sent_time,
                    duration_ms, cpu_utilization, endpoint, status_code
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                """,
                request_id,
                action_type,
                platform,
                encryption_mode,
                mitigation_state,
                receive_time,
                response_sent_time,
                duration_ms,
                cpu_avg,
                request.url.path,
                response.status_code,
            )
    except Exception as e:
        logger.error(f"Timing log write failed: {e}")

    # Echo request_id back in response for capture linkage
    response.headers["X-Request-ID"] = request_id
    return response




# ---- Data Models ----
# Pydantic validates incoming JSON against these types. Missing
# fields or wrong types cause FastAPI to return a 422 automatically.
class Transaction(BaseModel):
    amount: float
    category: str
    timestamp: str
    merchant: Optional[str] = None

class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

# ============================================================
# Routes
# ============================================================

# Health check / root endpoint. Useful to confirm the server is up.
@app.get("/")
async def root():
    return {"status": "GreenBuck API running"}

# Return all transactions, newest first.
@app.get("/transactions")
async def get_transactions(user: str = Depends(get_current_user)):
   # Acquire a connection from the pool, automatically released
   # when the 'async with' block exits.
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id, amount, category, timestamp, merchant FROM transactions ORDER BY id DESC"
            )
           # Convert asyncpg Records to plain dicts for clean JSON output.
            return {
                "transactions": [
                    {
                        "id": r["id"],
                        "amount": float(r["amount"]), # NUMERIC -> float
                        "category": r["category"],
                        "timestamp": r["timestamp"],
                        "merchant": r["merchant"],
                    }
                    for r in rows
                ]
            }
    except Exception as e:
        # Log the real error server-side, return generic 500 to client.
        logger.error(f"GET /transactions failed: {e}")
        raise HTTPException(status_code=500, detail="Database error")

# Create a new transaction. Returns the created record.
@app.post("/transactions", status_code=201)
async def create_transaction(transaction: Transaction, user: str = Depends(get_current_user)):
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO transactions (amount, category, timestamp, merchant)
                VALUES ($1, $2, $3, $4)
                RETURNING id, amount, category, timestamp, merchant
                """,
                transaction.amount,
                transaction.category,
                transaction.timestamp,
                transaction.merchant,
            )
            return {
                "id": row["id"],
                "amount": float(row["amount"]),
                "category": row["category"],
                "timestamp": row["timestamp"],
                "merchant": row["merchant"],
            }
    except Exception as e:
        logger.error(f"POST /transactions failed: {e}")
        raise HTTPException(status_code=500, detail="Database error")


# Register a new user. Hashes the password with Argon2id before storing.
@app.post("/auth/register", status_code=201)
async def register(req: RegisterRequest):
    try:
        hashed = hash_password(req.password)
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
                req.username,
                hashed,
            )
        return {"status": "registered", "username": req.username}
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=409, detail="Username already exists")
    except Exception as e:
        logger.error(f"POST /auth/register failed: {e}")
        raise HTTPException(status_code=500, detail="Registration error")


# Login. Verifies the password against the stored hash, issues a signed JWT.
@app.post("/auth/login", status_code=200)
async def login(req: LoginRequest):
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT username, password_hash FROM users WHERE username = $1",
                req.username,
            )
        # Same generic error whether the user is missing or the password is
        # wrong — avoids leaking which usernames exist.
        if row is None or not verify_password(req.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        token = create_access_token(req.username)
        return {"access_token": token, "token_type": "bearer"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"POST /auth/login failed: {e}")
        raise HTTPException(status_code=500, detail="Login error")


# Logout. Stateless JWT means the server holds no session — the client
# discards its token. Kept as a research action class.
@app.post("/auth/logout", status_code=200)
async def logout():
    return {"status": "logged_out"}

# Balance endpoint. Returns just a summary number rather than the full
# transaction list. Smaller response than /transactions for distinct traffic.
@app.get("/balance")
async def get_balance(user: str = Depends(get_current_user)):
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT COALESCE(SUM(amount), 0) AS total FROM transactions"
            )
            return {
                "balance": float(row["total"]),
                "as_of": datetime.now(timezone.utc).isoformat(),
            }
    except Exception as e:
        logger.error(f"GET /balance failed: {e}")
        raise HTTPException(status_code=500, detail="Database error")
