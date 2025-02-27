import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class UserCreateModel(BaseModel):
    first_name: str = Field(max_length=32)
    last_name: str = Field(max_length=32)
    username: str = Field(max_length=32)
    email: str = Field(max_length=64)
    password: str = Field(min_length=6)


class UserModel(BaseModel):
    uid: uuid.UUID
    username: str
    email: str
    first_name: str
    last_name: str
    is_verified: bool
    password_hash: str = Field(exclude=True)
    created_at: datetime
    updated_at: datetime
