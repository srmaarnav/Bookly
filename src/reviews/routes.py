from fastapi import APIRouter, Depends
from sqlmodel.ext.asyncio.session import AsyncSession

from src.auth.dependecies import get_current_user
from src.db.main import get_session
from src.db.models import User
from src.reviews.schemas import ReviewCreateModel
from src.reviews.service import ReviewService

review_router = APIRouter()

review_service = ReviewService()


@review_router.post("/book/{book_uid}")
async def add_review_to_book(
    book_uid: str,
    review_data: ReviewCreateModel,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    new_review = await review_service.add_new_review(
        user_email=current_user.email,
        review_data=review_data,
        book_uid=book_uid,
        session=session,
    )

    return new_review
