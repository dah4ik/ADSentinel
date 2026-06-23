from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

from config.settings import settings


engine = create_engine(
    settings.DATABASE_URL,
    connect_args={
        "check_same_thread": False
    } if settings.DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def init_db():
    from database import models

    Base.metadata.create_all(
        bind=engine
    )


def get_db_session():
    db = SessionLocal()

    try:
        return db

    except Exception:
        db.close()
        raise