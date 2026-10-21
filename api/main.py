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
from starlette.background import BackgroundTask # Runs the timing_log INSERT after the response is sent
from http import HTTPStatus # Reason phrases uvicorn puts in the response status line
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

# ---- Background CPU sampler (Global) ----
# A background task samples system-wide CPU every 250 ms. Each timing_log row
# records the latest sample: system CPU % over the ~250 ms before the request
# finished.
CPU_SAMPLE_INTERVAL_S = 0.25
latest_cpu_percent: Optional[float] = None


async def _cpu_sampler():
    global latest_cpu_percent
    psutil.cpu_percent(interval=None)  # prime psutil; the first call always returns 0.0
    while True:
        await asyncio.sleep(CPU_SAMPLE_INTERVAL_S)
        latest_cpu_percent = psutil.cpu_percent(interval=None)


def research_header(request: Request, name: str, default: str) -> str:
    """Read an X-* research label header and strip the client's padding.

    The client pads every label (X-Action, X-Encryption, X-Mitigation,
    X-Platform, X-Mode) to 16 characters with trailing '.'. Unpadded values
    pass through unchanged.
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
    # Start the CPU sampler and log this session's mitigation parameters.
    sampler = asyncio.create_task(_cpu_sampler())
    logger.info(
        f"Mitigation params: padding={PADDING_PLAINTEXT_BYTES}B plaintext / {PADDING_TARGET_BYTES}B wire "
        f"random_padding=1-{RANDOM_PAD_MAX_BYTES}B body + 1-{RANDOM_HEADER_PAD_MAX_BYTES}B header "
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
# header. Five mitigations plus a no-op control:
#   - none: passthrough (control condition)
#   - padding: pads the plaintext response to PADDING_PLAINTEXT_BYTES
#     (wire_padding_middleware then pads the final body on the wire)
#   - random_padding: applied on the wire by wire_padding_middleware
#   - jitter: random delay before response
#   - constant: fixed total response time regardless of work
#   - batching: handled by the /batch endpoint
# ============================================================

# Tunable mitigation parameters. These would be parameter-swept
# in a follow-up study; for this paper they are held constant.
PADDING_PLAINTEXT_BYTES = 2048  # Plaintext bodies, before encryption
PADDING_TARGET_BYTES = 4096     # Final bodies on the wire (plaintext or encrypted envelope)
RANDOM_PAD_MAX_BYTES = 4096         # Random padding: 1..max filler bytes added to each body
RANDOM_HEADER_PAD_MAX_BYTES = 256   # Random padding: 1..max bytes in the X-Pad header
JITTER_MIN_MS = 0             # Lower bound for jitter delay
JITTER_MAX_MS = 50            # Upper bound for jitter delay
# Constant-rate target, read from the environment (default 400 ms). Must be
# above the slowest request on the capture host.
CONSTANT_RATE_TARGET_MS = float(os.environ.get("CONSTANT_RATE_TARGET_MS", "400"))

# Mitigation labels the server accepts. Anything else gets a 400.
VALID_MITIGATIONS = {"none", "padding", "random_padding", "jitter", "constant", "batching"}


def _filler_parts(body: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """Split a JSON object into (kept, prefix, suffix) so kept + prefix + filler + suffix
    is the same object with a `key` field holding the filler."""
    if body == b"{}":
        return b"", b'{"' + key + b'":"', b'"}'
    return body[:-1], b',"' + key + b'":"', b'"}'


def _insert_filler(body: bytes, n: int, key: bytes) -> bytes:
    """Add a `key` field holding n filler bytes to a JSON object.

    Returns the body unchanged if it isn't a JSON object or n <= 0.
    Same algorithm as insertFiller() in lib/services/mitigations/padding_mitigation.dart.
    """
    if not body.endswith(b"}") or n <= 0:
        return body
    kept, prefix, suffix = _filler_parts(body, key)
    return kept + prefix + b"x" * n + suffix


def _pad_json(body: bytes, target: int, key: bytes) -> bytes:
    """Add a `key` filler field to a JSON object so the body is exactly `target` bytes.

    Returns the body unchanged if it isn't a JSON object or is already too long.
    Same algorithm as padJson() in lib/services/mitigations/padding_mitigation.dart.
    """
    if not body.endswith(b"}"):
        return body
    kept, prefix, suffix = _filler_parts(body, key)
    return _insert_filler(body, target - len(kept) - len(prefix) - len(suffix), key)


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

    elif mitigation == "random_padding":
        # Applied on the wire by wire_padding_middleware.
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
            # Request took longer than the target; log it.
            logger.warning(
                f"constant-rate overrun: {request.url.path} took {elapsed_ms:.1f} ms "
                f"> target {CONSTANT_RATE_TARGET_MS} ms"
            )
        return response

    elif mitigation == "padding":
        # Pad the plaintext response body (before encryption) with a "_pad" key.
        # Requires reading + reconstructing the response.
        body = b""
        async for chunk in response.body_iterator:
            body += chunk

        body = _pad_json(body, PADDING_PLAINTEXT_BYTES, b"_pad")
        if len(body) != PADDING_PLAINTEXT_BYTES:
            # Body was already at or over the target and goes out at its real size; log it.
            logger.warning(
                f"padding miss: {request.url.path} plaintext is {len(body)} B, target {PADDING_PLAINTEXT_BYTES} B"
            )

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
# Every failure on an encrypted request (decryption, validation, handler
# error) returns the same 400, so nothing decrypted is echoed back and
# failures can't be told apart by status or body.
# ============================================================
def _encrypted_request_error() -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": "Request failed"})


@app.middleware("http")
async def encryption_middleware(request: Request, call_next):
    scheme_name = research_header(request, "X-Encryption", "none")

    # Reject unknown scheme names (checked before the auth whitelist).
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
            return _encrypted_request_error()

    response = await call_next(request)

    if response.status_code >=400:
        logger.warning(f"Encrypted request failed: {request.url.path} returned {response.status_code}")
        async for _ in response.body_iterator:  # drain the discarded response
            pass
        return _encrypted_request_error()

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
            return _encrypted_request_error()
    return response

# ============================================================
# Wire Padding Middleware
# Pads the final response body (plaintext, encrypted envelope or error)
# with a "_wpad" key and adds an X-Pad header. Sits outside the encryption
# middleware, so it sees the final body.
#   - padding: every body becomes PADDING_TARGET_BYTES and X-Pad evens out
#     the reason phrase in the status line ("OK" vs "Created"), so every
#     response is the same size. Also logs a warning if requests within one
#     run arrive at different sizes.
#   - random_padding: each body gets 1..RANDOM_PAD_MAX_BYTES filler bytes and
#     X-Pad is 1..RANDOM_HEADER_PAD_MAX_BYTES long, drawn per response.
# ============================================================
PADDING_REASON_WIDTH = 32  # reason phrase + X-Pad value, in bytes

# Request sizes seen under padding, per X-Run-ID.
padded_request_sizes: dict[str, set[int]] = {}


def _request_wire_size(request: Request) -> int:
    """Size of the HTTP request as received: request line, header lines, body."""
    scope = request.scope
    target = len(scope.get("raw_path") or scope["path"].encode())
    if scope.get("query_string"):
        target += 1 + len(scope["query_string"])
    request_line = len(scope["method"]) + 1 + target + 1 + len("HTTP/") + len(scope["http_version"]) + 2
    header_lines = sum(len(name) + 2 + len(value) + 2 for name, value in scope["headers"]) + 2
    return request_line + header_lines + int(request.headers.get("content-length") or 0)


@app.middleware("http")
async def wire_padding_middleware(request: Request, call_next):
    mitigation = research_header(request, "X-Mitigation", "none")
    if mitigation not in ("padding", "random_padding"):
        return await call_next(request)

    if mitigation == "padding":
        run_id = request.headers.get("X-Run-ID", "none")
        size = _request_wire_size(request)
        sizes = padded_request_sizes.setdefault(run_id, set())
        if size not in sizes:
            sizes.add(size)
            if len(sizes) > 1:
                logger.warning(
                    f"padding: request sizes differ in run {run_id}: {sorted(sizes)} B "
                    f"({request.method} {request.url.path} is {size} B)"
                )

    response = await call_next(request)

    body = b""
    async for chunk in response.body_iterator:
        body += chunk
    headers = {k: v for k, v in response.headers.items() if k.lower() != "content-length"}

    if mitigation == "padding":
        body = _pad_json(body, PADDING_TARGET_BYTES, b"_wpad")
        if len(body) != PADDING_TARGET_BYTES:
            logger.warning(
                f"padding miss: {request.url.path} wire body is {len(body)} B, target {PADDING_TARGET_BYTES} B"
            )
        phrase = HTTPStatus(response.status_code).phrase
        headers["X-Pad"] = "x" * max(1, PADDING_REASON_WIDTH - len(phrase))
    else:
        body = _insert_filler(body, 1 + secrets.randbelow(RANDOM_PAD_MAX_BYTES), b"_wpad")
        headers["X-Pad"] = "x" * (1 + secrets.randbelow(RANDOM_HEADER_PAD_MAX_BYTES))

    return Response(
        content=body,
        status_code=response.status_code,
        headers=headers,
        media_type=response.media_type,
    )

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
    # research_header() strips the client's fixed-width padding.
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
    cpu_sample = latest_cpu_percent  # latest background sample, see _cpu_sampler
    # For /batch: the actions inside the bundle (set by the endpoint). None otherwise.
    batch_actions = getattr(request.state, "batch_actions", None)

    async def write_timing_row():
        # Runs as a BackgroundTask, after the last body chunk has been sent.
        # response_sent_time is taken here: when the full response has been
        # handed to uvicorn for sending.
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
    response.background = BackgroundTask(write_timing_row)  # INSERT runs after the response is sent
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
        # Hash in a worker thread so Argon2id doesn't block the event loop.
        hashed = await asyncio.to_thread(hash_password, req.password)
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

        # Verify in a worker thread so Argon2id doesn't block the event loop.
        if row is not None:
            password_valid = await asyncio.to_thread(verify_password, req.password, row["password_hash"])
        else:
            await asyncio.to_thread(verify_password, req.password, DUMMY_PASSWORD_HASH)
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
    # Record the bundle's actions for timing_log (read by timing_middleware via
    # request.state). Not added to the response.
    request.state.batch_actions = ",".join(item.action for item in req.requests)

    if len(req.requests) > MAX_BATCH_SIZE:
        raise HTTPException(status_code=413, detail="Batch too large")

    responses = []

    for item in req.requests:
        handler = BATCH_ACTIONS.get(item.action)
        if handler is None:
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
