from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from pathlib import Path
from app.core.config import settings

sqlite_path = Path(settings.sqlite_path)
sqlite_path.parent.mkdir(parents=True, exist_ok=True)
DATABASE_URL = "sqlite+aiosqlite:///" + str(sqlite_path)

engine = create_async_engine(DATABASE_URL, echo=False, future=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

class Base(DeclarativeBase):
    pass

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
