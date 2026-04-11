from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DATABASE_URL = "sqlite+aiosqlite:///fullauth_sqlalchemy_demo.db"
engine = create_async_engine(DATABASE_URL)
session_maker = async_sessionmaker(engine, expire_on_commit=False)
