from sqlalchemy.orm import Session
from models.user_authentication import UserAuthentication
from models.user import User

def find_user(db: Session, provider: str, provider_user_id: str):
    return (db.query(UserAuthentication)
               .filter(UserAuthentication.provider_user_id == provider_user_id)
               .filter(UserAuthentication.provider == provider)
               .first())

def create_user(db: Session, provider: str, provider_user_id: str, user_name: str):
    db_user = User(**{"name": user_name})
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    db_user_auth = UserAuthentication(**{"provider": provider, "provider_user_id": provider_user_id, "user_id": db_user.id})
    db.add(db_user_auth)
    db.commit()

    return db_user