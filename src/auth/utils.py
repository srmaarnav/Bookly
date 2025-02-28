import logging
import uuid
from datetime import datetime, timedelta

import jwt
from passlib.context import CryptContext

from src.config import Config

password_context = CryptContext(schemes=["bcrypt"])

ACCESS_TOKEN_EXPIRY = 3600


def generate_password_hash(password: str) -> str:
    return password_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_context.verify(plain_password, hashed_password)


def create_access_tokens(
    user_data: dict, expiry: timedelta = None, refresh: bool = False
):
    payload = {}
    payload["user"] = user_data
    payload["exp"] = datetime.now() + (
        expiry if expiry is not None else timedelta(seconds=ACCESS_TOKEN_EXPIRY)
    )
    payload["jti"] = str(uuid.uuid4())
    payload["refresh"] = refresh

    token = jwt.encode(
        payload=payload, key=Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM
    )

    return token


def decode_access_token(token: str) -> dict:
    try:
        token_data = jwt.decode(
            jwt=token, key=Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM]
        )
        return token_data
    except jwt.PyJWTError as e:
        logging.exception(e)
        return None
