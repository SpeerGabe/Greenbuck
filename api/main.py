# ============================================================
# GreenBuck API — main.py
# FastAPI backend for the GreenBuck research project.
# Handles transaction CRUD and logs research metadata for
# every request via the timing log middleware.
# ============================================================

# ---- Imports ----
from contextlib import asynccontextmanager # For the lifespan context manager
from fastapi import FastAPI, HTTPException, Request, Response # Web framework, error handling, request access
from pydantic import BaseModel, ValidationError # Request body validation via type hints
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
from fastapi.responses import JSONResponse # For returning JSON error responses
import secrets       # generates the random IV
import base64        # encodes IV/ciphertext for JSON
from typing import Protocol # Defines the interface for cipher schemes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF # Key derivation function for AES key derivation
from cryptography.hazmat.primitives import hashes, padding as sym_padding # Cryptographic primitives for hashing and padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # Cryptographic primitives for symmetric encryption with AES-256-CDC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305 # for implementing AES-256-GCM and ChaCha20
import json # For serializing the encryption envelope to JSON
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey # X25519 key exchange for shared secret derivation
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat # For serializing public keys to bytes for transmission
from starlette.background import BackgroundTask # [CAPTURE FIX] runs the timing_log INSERT after the response is on the wire
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

# dummy password hash for timing attack mitigation. 
# This makes sure that the time taken to verify a password is roughly the same no matter whether the user exists or not
DUMMY_PASSWORD_HASH = ph.hash(secrets.token_hex(32)) # random 32-byte string hashed with Argon2id

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

# ---- Session Keys (Global) ----
# This holds the shared secret for each user session. In a real deployment, this would be stored in a secure session store or database, not in memory. For research purposes on an isolated network, we keep it simple.
session_keys: dict[str, dict] = {}

# ---- [CAPTURE FIX] Background CPU sampler (Global) ----
# The old code called psutil.cpu_percent(interval=None) twice inside every
# request and averaged the two. That value is meaningless: the "before" call
# measures the idle gap since the PREVIOUS request, /proc/stat only has 10 ms
# resolution so sub-millisecond windows come back as 0 / 50 / 100, and
# concurrent requests (the dashboard's Future.wait) reset each other's window.
# Instead, one background task samples system-wide CPU every 250 ms and each
# timing_log row records the latest sample. cpu_utilization therefore means
# "system CPU % over the ~250 ms before this request finished" — a usable
# load covariate — and the /proc/stat reads are off the request path.
CPU_SAMPLE_INTERVAL_S = 0.25
latest_cpu_percent: Optional[float] = None


async def _cpu_sampler():
    global latest_cpu_percent
    psutil.cpu_percent(interval=None)  # prime psutil; the first call always returns 0.0
    while True:
        await asyncio.sleep(CPU_SAMPLE_INTERVAL_S)
        latest_cpu_percent = psutil.cpu_percent(interval=None)


def research_header(request: Request, name: str, default: str) -> str:
    """[CAPTURE FIX] Read an X-* research label header.

    The client pads every label (X-Action, X-Encryption, X-Mitigation,
    X-Platform, X-Mode) to a fixed 16 characters with trailing '.' so the
    label's length can't show up in the encrypted request size. Strip that
    padding here. Unpadded values pass through unchanged, so old clients and
    curl still work.
    """
    return request.headers.get(name, default).rstrip(".")


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
    # [CAPTURE FIX] Start the CPU sampler and record the mitigation parameters
    # in the server log, so every collection session shows which values it ran with.
    sampler = asyncio.create_task(_cpu_sampler())
    logger.info(
        f"Mitigation params: padding={PADDING_TARGET_BYTES}B "
        f"jitter={JITTER_MIN_MS}-{JITTER_MAX_MS}ms constant={CONSTANT_RATE_TARGET_MS}ms"
    )
    yield # Server runs while paused here. After shutdown signal:
    sampler.cancel()
    if pool:
        await pool.close()
        logger.info("Database connection pool closed")

# ---- FastAPI App Instance ----
app = FastAPI(lifespan=lifespan)

# ---- Request Body Override Helper ----
async def _set_body(request: Request, body: bytes):
    # overrides the request's body stream so downstream handler see the decrypted plaintext
    request._body = body

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}
    request._receive = receive

async def _username_from_token(request: Request) -> Optional[str]:
    # extracts the username from the Bearer token in the request headers
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[7:]  # Remove "Bearer " prefix
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        return username
    except jwt.InvalidTokenError:
        return None

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
# [CAPTURE FIX] The old 100 ms target is shorter than login (~105-160 ms) and
# register (~295 ms) because both run Argon2id, so under "constant" those two
# actions still stood out. The target has to exceed the slowest request ON THE
# CAPTURE HOST, so it is now read from the environment (set it in run.sh after
# measuring; see the query in run.sh.example). 400 ms is a placeholder default.
CONSTANT_RATE_TARGET_MS = float(os.environ.get("CONSTANT_RATE_TARGET_MS", "400"))

# [CAPTURE FIX] Labels the server knows how to apply. Anything else is rejected
# with 400 instead of being silently treated as "none" while timing_log records
# the bogus label — a typo would otherwise create mislabeled data that looks valid.
VALID_MITIGATIONS = {"none", "padding", "jitter", "constant", "batching"}


@app.middleware("http")
async def mitigation_middleware(request: Request, call_next):
    mitigation = research_header(request, "X-Mitigation", "none")
    if mitigation not in VALID_MITIGATIONS:
        return JSONResponse(status_code=400, content={"detail": f"Unknown mitigation: {mitigation}"})

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
        else:
            # [CAPTURE FIX] A request slower than the target leaks its real
            # duration. Warn so an undersized target shows up during collection
            # instead of only during analysis.
            logger.warning(
                f"constant-rate overrun: {request.url.path} took {elapsed_ms:.1f} ms "
                f"> target {CONSTANT_RATE_TARGET_MS} ms"
            )
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
            # [CAPTURE FIX] The wrapper actually adds 10 net bytes: ,"_pad":" (9)
            # plus "} (2) minus the one } removed. The old "- 14" assumed spaces
            # that aren't in the string, so every response came out at 4092 B,
            # not the 4096 B the paper states (requests, padded by the client,
            # were already exactly 4096).
            padding_needed = PADDING_TARGET_BYTES - len(body) - 10
            if padding_needed > 0:
                pad_str = b"x" * padding_needed
                body = body[:-1] + b',"_pad":"' + pad_str + b'"}'

        if len(body) != PADDING_TARGET_BYTES:
            # [CAPTURE FIX] Padding fails open: a body already at or over the
            # target is sent at its real size. Warn so it's visible during
            # collection (this is how a growing transaction history broke padding).
            logger.warning(
                f"padding miss: {request.url.path} body is {len(body)} B, target {PADDING_TARGET_BYTES} B"
            )

        from fastapi import Response
        return Response(
            content=body,
            status_code=response.status_code,
            headers={k: v for k, v in response.headers.items() if k.lower() != "content-length"},
            media_type=response.media_type,
        )

    elif mitigation == "batching":
        # batching happens in the /batch endpoint
        return response
    # Unknown mitigation value — treat as no-op.
    return response

# ============================================================
# Encryption Middleware
# Decrypts incoming request bodies if the X-Encryption header is set.
# ============================================================
@app.middleware("http")
async def encryption_middleware(request: Request, call_next):
    scheme_name = research_header(request, "X-Encryption", "none")

    # [CAPTURE FIX] Reject unknown scheme names. Before, an unknown name fell
    # through the first check and was sent as PLAINTEXT, while timing_log still
    # recorded the bogus name as the encryption mode (verified: "AES-GCM" came
    # back unencrypted but was logged as "AES-GCM"). The 400 that was meant to
    # catch this sat after that check and could never run. The check now comes
    # before the auth whitelist, so auth rows can't carry a bogus label either.
    if scheme_name != "none" and scheme_name not in CIPHER_SCHEMES:
        return JSONResponse(status_code=400, content={"detail": f"Unsupported encryption scheme: {scheme_name}"})

    # whitelist of path that are sent by plaintext
    if request.url.path in ("/auth/login", "/auth/register", "/auth/logout"):
        return await call_next(request)

    if scheme_name == "none":
        return await call_next(request)

    scheme = CIPHER_SCHEMES[scheme_name]

    username = await _username_from_token(request)
    if not username or username not in session_keys:
        return JSONResponse(status_code=401, content={"detail": "No encryption session established: please login again"})

    keys = session_keys[username].get(scheme_name)
    if not keys:
        return JSONResponse(status_code=401, content={"detail": f"No session keys for scheme: {scheme_name}"})

    raw_body = await request.body()
    if raw_body:
        try:
            envelope = json.loads(raw_body)
            plaintext = scheme.decrypt(envelope, keys)
            await _set_body(request, plaintext)
        except Exception as e:
            logger.error(f"Decryption failed ({scheme_name}): {e}")
            return JSONResponse(status_code=400, content={"detail": "Decryption failed"})
        
    response = await call_next(request)

    if response.status_code >=400:
        return response
    
    response_body = b""
    async for chunk in response.body_iterator:
        response_body += chunk

    if response_body:
        try:
            response_envelope = scheme.encrypt(response_body, keys)
            encrypted_response = json.dumps(response_envelope).encode("utf-8")

            return Response(
                content = encrypted_response,
                status_code = response.status_code,
                headers = {k: v for k, v in response.headers.items() if k.lower() !="content-length"},
                media_type = "application/json"
            )
        except Exception as e:
            logger.error(f"Response encryption failed ({scheme_name}): {e}")
            return JSONResponse(status_code=500, content={"detail": "Response encryption error"})
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

    # Pull research metadata from request headers.
    # [CAPTURE FIX] research_header() strips the client's fixed-width padding.
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    run_id = request.headers.get("X-Run-ID")  # links rows to markers.jsonl
    action_type = research_header(request, "X-Action", "unknown")
    platform = research_header(request, "X-Platform", "unknown")
    encryption_mode = research_header(request, "X-Encryption", "none")
    mitigation_state = research_header(request, "X-Mitigation", "none")

    # Process the request
    response = await call_next(request)

    # duration_ms = server processing time: request received -> response ready
    # (includes decryption, the handler, mitigation delays and encryption).
    duration_ms = (time.perf_counter() - start) * 1000
    status_code = response.status_code
    endpoint = request.url.path
    cpu_sample = latest_cpu_percent  # [CAPTURE FIX] latest background sample, see _cpu_sampler
    # [CAPTURE FIX] For /batch, the endpoint stores which actions were inside the
    # bundle (otherwise the row only says "batch"). None for all other endpoints.
    batch_actions = getattr(request.state, "batch_actions", None)

    async def write_timing_row():
        # [CAPTURE FIX] This used to run BEFORE `return response`, so every
        # response was held on the server until the Postgres INSERT committed.
        # That added DB latency and variance to every packet timing the capture
        # sees, but none of it showed up in duration_ms. Verified by locking
        # timing_log: the client waited 1200 ms while duration_ms said 0.76 ms.
        # Starlette runs a response's BackgroundTask only after the last body
        # chunk has been sent, so the INSERT now happens after the response
        # is on the wire.
        #
        # response_sent_time is taken here, i.e. when the full response has been
        # handed to uvicorn for sending, which matches the column name. (It used
        # to be "response ready", which is what duration_ms already measures.)
        response_sent_time = datetime.now(timezone.utc)
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO timing_log (
                        request_id, action_type, platform, encryption_mode,
                        mitigation_state, receive_time, response_sent_time,
                        duration_ms, cpu_utilization, endpoint, status_code, run_id,
                        batch_actions
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                    """,
                    request_id,
                    action_type,
                    platform,
                    encryption_mode,
                    mitigation_state,
                    receive_time,
                    response_sent_time,
                    duration_ms,
                    cpu_sample,
                    endpoint,
                    status_code,
                    run_id,
                    batch_actions,
                )
        except Exception as e:
            logger.error(f"Timing log write failed: {e}")

    # Echo request_id back in response for capture linkage
    response.headers["X-Request-ID"] = request_id
    response.background = BackgroundTask(write_timing_row)  # [CAPTURE FIX] off the response path
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
    client_public_key: Optional[str] = None  # Base64-encoded X25519 public key for shared secret derivation

# ---- Batching routing
# batching requires a different approach than the other middlewares because it need to read the request body, which is a stream.
# We will read the body, parse it as JSON, and then create a new request for each transaction in the batch.
# each new request will be processed by the other middlewares and the route handler, and then we will collect the responses and return them as a list
# route handling logic are pulled into helpers as a result
async def fetch_transactions(user: str) -> dict:
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id, amount, category, timestamp, merchant From transactions WHERE username = $1 ORDER BY id DESC",
                user,
            )
        result = {
            "transactions": [
                {
                    "id": r["id"],
                    "amount": float(r["amount"]),
                    "category": r["category"],
                    "timestamp": r["timestamp"],
                    "merchant": r["merchant"],
                }
                for r in rows
            ]
        }
        return result
    except Exception as e:
        logger.error(f"fetch_transactions failed: {e}")
        raise HTTPException(status_code=500, detail="Database error")

async def insert_transaction(user: str, transaction: Transaction) -> dict:
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO transactions (amount, category, timestamp, merchant, username)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id, amount, category, timestamp, merchant
                """,
                transaction.amount,
                transaction.category,
                transaction.timestamp,
                transaction.merchant,
                user,
            )
        result = {
            "id": row["id"],
            "amount": float(row["amount"]),
            "category": row["category"],
            "timestamp": row["timestamp"],
            "merchant": row["merchant"],
        }
        return result
    except Exception as e:
        logger.error(f"insert_transaction failed: {e}")
        raise HTTPException(status_code=500, detail="Database error")

async def compute_balance(user: str) -> dict:
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT COALESCE(SUM(amount), 0) AS total FROM transactions WHERE username = $1",
                user,
            )
        result = {
            "balance": float(row["total"]),
            "as_of": datetime.now(timezone.utc).isoformat(),
        }
        return result
    except Exception as e:
        logger.error(f"compute_balance failed: {e}")
        raise HTTPException(status_code=500, detail="Database error")

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
    result = await fetch_transactions(user)
    return result

# Create a new transaction. Returns the created record.
@app.post("/transactions", status_code=201)
async def create_transaction(transaction: Transaction, user: str = Depends(get_current_user)):
    result = await insert_transaction(user, transaction)
    return result


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

        if row is not None:
            password_valid = verify_password(req.password, row["password_hash"])
        else:
            verify_password(req.password, DUMMY_PASSWORD_HASH)
            password_valid = False

        if row is None or not password_valid:
            raise HTTPException(status_code=401, detail="Invalid credientials")

        token = create_access_token(req.username)
        result = {"access_token": token, "token_type": "bearer"}

        if req.client_public_key:
            client_public_bytes = base64.b64decode(req.client_public_key)
            client_public_key = X25519PublicKey.from_public_bytes(client_public_bytes)

            server_private_key = X25519PrivateKey.generate()
            shared_secret = server_private_key.exchange(client_public_key)

            derived_keys = {name: scheme.derive_keys(shared_secret) for name, scheme in CIPHER_SCHEMES.items()}
            session_keys[req.username] = derived_keys

            server_public_bytes = server_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            result["server_public_key"] = base64.b64encode(server_public_bytes).decode()
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"POST /auth/login failed: {e}")
        raise HTTPException(status_code=500, detail="Login error")
# ---- Batching Middleware ----
# logic for batching and batching endpoint
class BatchItem(BaseModel):
    id: int
    action: str
    body: Optional[dict] = None

class BatchRequest(BaseModel):
    requests: list[BatchItem]

MAX_BATCH_SIZE = 20 # sync with client

async def _batch_view_history(user: str, body: Optional[dict]):
    result = await fetch_transactions(user)
    return 200, result

async def _batch_check_balance(user: str, body: Optional[dict]):
    result = await compute_balance(user)
    return 200, result

async def _batch_make_transfer(user: str, body: Optional[dict]):
    transaction = Transaction(**(body or {}))
    result = await insert_transaction(user, transaction)
    return 201, result

BATCH_ACTIONS = {
    "view_history": _batch_view_history,
    "check_balance": _batch_check_balance,
    "make_transfer": _batch_make_transfer,
}

@app.post("/batch")
async def batch(req: BatchRequest, request: Request, user: str = Depends(get_current_user)):
    # [CAPTURE FIX] Record the bundle's contents for timing_log (read by
    # timing_middleware via request.state). Without it, every batching-condition
    # row says action_type="batch" and nothing tells you what was inside.
    # Server-side only: nothing is added to the response.
    request.state.batch_actions = ",".join(item.action for item in req.requests)

    if len(req.requests) > MAX_BATCH_SIZE:
        raise HTTPException(status_code=413, detail="Batch too large")

    responses = []

    for item in req.requests:
        handler = BATCH_ACTIONS.get(item.action)
        if handler is None:
            # [NON-CAPTURE FIX] was `responses.eppend(...)`: AttributeError -> the
            # whole batch returned 500 instead of a per-item 400.
            responses.append({"id": item.id, "status": 400, "body": {"detail": f"Unknown action: {item.action}"}})
            continue
        try:
            status, body = await handler(user, item.body)
        except ValidationError:
            status, body = 422, {"detail": "Invalid request body"}
        except HTTPException as e:
            status, body = e.status_code, {"detail": e.detail}
        responses.append({"id": item.id, "status": status, "body": body})

    # Log summary of requests in bundle for logging
    actions = [item.action for item in req.requests]
    statuses = [response["status"] for response in responses]
    logger.info(f"BATCH user={user} size={len(actions)} action={actions} statuses = {statuses}")

    result = {"responses": responses}
    return result


# Logout. Stateless JWT means the server holds no session — the client
# discards its token. Kept as a research action class.
@app.post("/auth/logout", status_code=200)
async def logout():
    return {"status": "logged_out"}

# Balance endpoint. Returns just a summary number rather than the full
# transaction list. Smaller response than /transactions for distinct traffic.
@app.get("/balance")
async def get_balance(user: str = Depends(get_current_user)):
    result = await compute_balance(user)
    return result

class CipherScheme(Protocol):
    """Defines the interface for encryption schemes. Each scheme must implement
    key derivation, encryption, and decryption methods."""

    def derive_keys(self, shared_secret: bytes) -> dict:
        """Derive encryption keys from a shared secret."""
        ...

    def encrypt(self, plaintext: bytes, keys: dict) -> dict:
        """Encrypt plaintext using the derived keys."""
        ...

    def decrypt(self, envelope: dict, keys: dict) -> bytes:
        """Decrypt ciphertext using the derived keys."""
        ...

# aes-cbc scheme implementation. Uses HKDF to derive a 256-bit AES key from the shared secret.
class Aes256CbcScheme(CipherScheme):
    def derive_keys(self, shared_secret: bytes) -> dict:
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"greenbuck-aes-cbc",
        ).derive(shared_secret)
        return {"aes_key": derived}

    def encrypt(self, plaintext: bytes, keys: dict) -> dict:
        iv = secrets.token_bytes(16)
        # Pad plaintext to a multiple of 16 bytes since AES-CBC requires block alignment. Use PKCS7 padding.
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()

        encryptor = Cipher(algorithms.AES(keys["aes_key"]), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        
        envelope = {
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }
        return envelope
    
    def decrypt(self, envelope: dict, keys: dict) -> bytes:
        
        iv = base64.b64decode(envelope["iv"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        decryptor = Cipher(algorithms.AES(keys["aes_key"]), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        return plaintext

class AesGcmScheme(CipherScheme):
    def derive_keys(self, shared_secret: bytes) -> dict:
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"greenbuck-aes-gcm"
        ).derive(shared_secret)
        return {"aes_key": derived}

    def encrypt(self, plaintext: bytes, keys: dict) -> dict:
        nonce = secrets.token_bytes(12)

        aesgcm = AESGCM(keys["aes_key"])
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        envelope = {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }

        return envelope

    def decrypt(self, envelope: dict, keys: dict) -> bytes:
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])

        aesgcm = AESGCM(keys["aes_key"])
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext

class ChaCha20Poly1305Scheme(CipherScheme):
    def derive_keys(self, shared_secret: bytes) -> dict:
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"greenbuck-chacha20-poly1305",
        ).derive(shared_secret)
        return {"key": derived}
    
    def encrypt(self, plaintext: bytes, keys: dict) ->dict:
        nonce = secrets.token_bytes(12)

        chacha=ChaCha20Poly1305(keys["key"])
        ciphertext = chacha.encrypt(nonce, plaintext, None)

        envelope = {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode() 
        }

        return envelope

    def decrypt(self, envelope: dict, keys: dict) ->bytes:
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])

        chacha = ChaCha20Poly1305(keys["key"])
        plaintext = chacha.decrypt(nonce, ciphertext, None)
        return plaintext

CIPHER_SCHEMES: dict[str, CipherScheme] = {
    "aescbc": Aes256CbcScheme(),
    "aesgcm": AesGcmScheme(),
    "chacha20": ChaCha20Poly1305Scheme(),
}
