import os
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from supabase import create_client, Client
from functools import wraps

# FastAPI metadata for OpenAPI docs
app = FastAPI(
    title="Notes API",
    version="1.0.0",
    description="Backend API for a Fullstack Notes Application using FastAPI and Supabase (auth, notes CRUD)",
    openapi_tags=[
        {"name": "auth", "description": "User authentication endpoints"},
        {"name": "notes", "description": "CRUD for personal notes"},
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Should be restricted for production use
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Supabase client setup
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise Exception("Missing Supabase config in environment.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

#
# Utility functions
#
def get_user_from_token(token: str):
    """
    Helper: Validate a JWT with Supabase and get user info
    """
    try:
        # This will verify the JWT with Supabase
        user_response = supabase.auth.get_user(token)
        if not user_response or not user_response.user:
            return None
        return user_response.user
    except Exception:
        return None


def require_auth(func):
    @wraps(func)
    async def wrapper(*args, token: str = Depends(oauth2_scheme), **kwargs):
        user = get_user_from_token(token)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid auth token")
        kwargs["user"] = user
        return await func(*args, **kwargs)
    return wrapper

#
# Pydantic Models
#

class UserRegister(BaseModel):
    email: EmailStr = Field(..., description="Email address for registration.")
    password: str = Field(..., min_length=6, description="Password (at least 6 chars).")

class UserLogin(BaseModel):
    email: EmailStr = Field(..., description="User email for login.")
    password: str = Field(..., description="Password for login.")

class AuthResponse(BaseModel):
    access_token: str = Field(..., description="Supabase JWT access token.")
    token_type: str = Field(default="bearer")

class SessionResponse(BaseModel):
    user_id: str
    email: EmailStr

class NoteIn(BaseModel):
    title: str = Field(..., description="Title of the note.")
    content: str = Field(..., description="Note content.")

class NoteOut(NoteIn):
    id: int
    user_id: str

class NoteUpdate(BaseModel):
    title: Optional[str] = Field(None, description="Updated title.")
    content: Optional[str] = Field(None, description="Updated content.")

#
# API endpoints
#

@app.get("/", tags=["health"])
def health_check():
    """
    Health check route for deployment/monitoring.
    """
    return {"message": "Healthy"}

# PUBLIC_INTERFACE
@app.post("/register", tags=["auth"], response_model=AuthResponse, summary="User Registration")
def register_user(payload: UserRegister):
    """
    Registers a new user with Supabase Auth.

    Parameters:
        payload: UserRegister - Registration data (email, password)

    Returns:
        AuthResponse - JWT access token
    """
    try:
        res = supabase.auth.sign_up({
            "email": payload.email,
            "password": payload.password
        })
        if not res or not res.session or not res.session.access_token:
            raise HTTPException(status_code=400, detail="Registration failed")
        return AuthResponse(access_token=res.session.access_token, token_type="bearer")
    except Exception:
        raise HTTPException(status_code=400, detail="Registration error")

# PUBLIC_INTERFACE
@app.post("/login", tags=["auth"], response_model=AuthResponse, summary="User Login")
def login_user(payload: UserLogin):
    """
    Logs a user in via Supabase Auth.

    Parameters:
        payload: UserLogin - Login credentials

    Returns:
        AuthResponse - JWT access token
    """
    try:
        res = supabase.auth.sign_in_with_password({
            "email": payload.email,
            "password": payload.password
        })
        if not res or not res.session or not res.session.access_token:
            raise HTTPException(status_code=401, detail="Incorrect email or password")
        return AuthResponse(access_token=res.session.access_token, token_type="bearer")
    except Exception:
        raise HTTPException(status_code=401, detail="Login error")

# PUBLIC_INTERFACE
@app.get("/session", tags=["auth"], response_model=SessionResponse, summary="Session Verification")
@require_auth
async def get_session(user):
    """
    Returns info about the current session (user id and email).

    Returns:
        SessionResponse - user_id and email.
    """
    return SessionResponse(user_id=user["id"], email=user["email"])

#
# Notes CRUD (all authenticated)
#

# PUBLIC_INTERFACE
@app.get("/notes", response_model=List[NoteOut], tags=["notes"], summary="List All Notes", description="List all notes for the authenticated user.")
@require_auth
async def list_notes(user):
    """
    Get all notes belonging to the authenticated user.

    Returns a list of notes (id, title, content, user_id).
    """
    try:
        result = supabase.table("notes").select("*").eq("user_id", user["id"]).order("id", desc=True).execute()
        notes = result.data if result and hasattr(result, "data") else []
        return notes
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to fetch notes.")

# PUBLIC_INTERFACE
@app.post("/notes", response_model=NoteOut, tags=["notes"], summary="Create Note", description="Create a new note for the authenticated user.")
@require_auth
async def create_note(note: NoteIn, user):
    """
    Add a note belonging to the authenticated user.

    Parameters:
        note: NoteIn - note fields

    Returns:
        Created note (includes id, title, content, user_id)
    """
    try:
        insert_data = {
            "title": note.title,
            "content": note.content,
            "user_id": user["id"],
        }
        result = supabase.table("notes").insert(insert_data).execute()
        if result and hasattr(result, "data") and result.data:
            return result.data[0]
        raise HTTPException(status_code=400, detail="Creating note failed.")
    except Exception:
        raise HTTPException(status_code=400, detail="Creating note failed.")

# PUBLIC_INTERFACE
@app.get("/notes/{note_id}", response_model=NoteOut, tags=["notes"], summary="Get Note", description="Get a specific note by ID for the authenticated user.")
@require_auth
async def get_note(note_id: int, user):
    """
    Get a note by id for the authenticated user.

    Parameters:
        note_id: int - ID of note

    Returns:
        NoteOut - requested note
    """
    try:
        result = supabase.table("notes").select("*").eq("id", note_id).eq("user_id", user["id"]).single().execute()
        if result and hasattr(result, "data") and result.data:
            return result.data
        raise HTTPException(status_code=404, detail="Note not found.")
    except Exception:
        raise HTTPException(status_code=404, detail="Note not found.")

# PUBLIC_INTERFACE
@app.put("/notes/{note_id}", response_model=NoteOut, tags=["notes"], summary="Update Note", description="Update a note by ID for the authenticated user.")
@require_auth
async def update_note(note_id: int, note: NoteUpdate, user):
    """
    Update a note by id for the authenticated user.

    Parameters:
        note_id: int - ID of note
        note: NoteUpdate - fields to update

    Returns:
        NoteOut - updated note
    """
    try:
        # Only update non-null fields
        update_data = {k: v for k, v in note.model_dump().items() if v is not None}
        if not update_data:
            raise HTTPException(status_code=400, detail="No data to update.")
        result = supabase.table("notes")\
            .update(update_data)\
            .eq("id", note_id)\
            .eq("user_id", user["id"])\
            .execute()
        if result and hasattr(result, "data") and result.data:
            return result.data[0]
        raise HTTPException(status_code=404, detail="Note not found or update forbidden.")
    except Exception:
        raise HTTPException(status_code=404, detail="Note not found or update forbidden.")

# PUBLIC_INTERFACE
@app.delete("/notes/{note_id}", tags=["notes"], summary="Delete Note", description="Delete a note by ID for the authenticated user.")
@require_auth
async def delete_note(note_id: int, user):
    """
    Delete a note by id for the authenticated user.

    Parameters:
        note_id: int - ID of note

    Returns:
        { "detail": "Note deleted" } or 404 if not found
    """
    try:
        result = supabase.table("notes")\
            .delete()\
            .eq("id", note_id)\
            .eq("user_id", user["id"])\
            .execute()
        if result and hasattr(result, "data") and len(result.data) > 0:
            return {"detail": "Note deleted"}
        else:
            raise HTTPException(status_code=404, detail="Note not found or forbidden.")
    except Exception:
        raise HTTPException(status_code=404, detail="Note not found or forbidden.")

