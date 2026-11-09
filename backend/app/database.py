from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(settings.DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def ensure_migrations():
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            for sql in [
                "ALTER TABLE devices ADD COLUMN trust_level VARCHAR(20) DEFAULT 'MEDIUM'",
                "ALTER TABLE devices ADD COLUMN device_source VARCHAR(20) DEFAULT 'SIMULATED'",
                "ALTER TABLE devices ADD COLUMN is_registered BOOLEAN DEFAULT 1",
                "ALTER TABLE traffic_records ADD COLUMN data_source VARCHAR(20) DEFAULT 'SIMULATED'",
                "ALTER TABLE security_events ADD COLUMN occurrence_count INTEGER DEFAULT 1",
                "ALTER TABLE security_events ADD COLUMN last_seen DATETIME",
                "ALTER TABLE alerts ADD COLUMN occurrence_count INTEGER DEFAULT 1",
                "ALTER TABLE alerts ADD COLUMN last_seen DATETIME",
                "ALTER TABLE alerts ADD COLUMN event_type VARCHAR(100)",
                "ALTER TABLE alerts ADD COLUMN detection_method VARCHAR(30) DEFAULT 'RULE'",
                "ALTER TABLE alerts ADD COLUMN detected_by VARCHAR(30) DEFAULT 'rule'"
            ]:
                try:
                    conn.execute(text(sql))
                    conn.commit()
                except Exception:
                    pass
    except Exception:
        pass

ensure_migrations()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
