from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
from .. import schemas, models, database, hashing
from ..token import create_access_token 
from ..schemas import Token  


ACCESS_TOKEN_EXPIRE_MINUTES = 30
router = APIRouter()

@router.post("/login", response_model=Token)
def login(request:OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.email == request.username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Invalid Credentials")

    if not hashing.verify(request.password, user.password):
     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incorrect password")


    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )

    return Token(access_token=access_token, token_type="bearer")
