from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.auth.routes import auth_router
from src.books.routes import book_router
from src.db.main import init_db


@asynccontextmanager
async def life_span(app: FastAPI):
    print(f"Starting application server.")
    await init_db()
    yield
    print(f"Stopping application server.")


version = "v1"

app = FastAPI(
    title="Bookly",
    description="A REST API for book review web service.",
    version=version,
    lifespan=life_span,
)

app.include_router(auth_router, prefix=f"/api/{version}/auth", tags=["auth"])
app.include_router(book_router, prefix=f"/api/{version}/books", tags=["books"])
