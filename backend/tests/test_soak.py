import pytest
from app.database import SessionLocal
from app.utils.seed_data import seed_database
from app.simulation.traffic_generator import traffic_generator
from app.models.alert import Alert

@pytest.fixture(autouse=True)
def setup_clean_db():
    db = SessionLocal()
    seed_database(db, force_reset=True)
    db.close()
    yield

def test_soak_normal_traffic_zero_alerts():
    """60 consecutive ticks of NORMAL scenario traffic must produce 0 alerts."""
    db = SessionLocal()
    initial_alerts = db.query(Alert).count()
    assert initial_alerts == 0

    total_records = 0
    for tick in range(60):
        records = traffic_generator.generate_tick(db, scenario="NORMAL")
        total_records += len(records)

    alert_count = db.query(Alert).count()
    db.close()

    assert alert_count == 0, f"Expected 0 alerts in NORMAL soak test, but found {alert_count} alerts across {total_records} flows."

def test_soak_light_traffic_zero_alerts():
    """60 consecutive ticks of LIGHT scenario traffic must produce 0 alerts."""
    db = SessionLocal()
    initial_alerts = db.query(Alert).count()
    assert initial_alerts == 0

    total_records = 0
    for tick in range(60):
        records = traffic_generator.generate_tick(db, scenario="LIGHT")
        total_records += len(records)

    alert_count = db.query(Alert).count()
    db.close()

    assert alert_count == 0, f"Expected 0 alerts in LIGHT soak test, but found {alert_count} alerts across {total_records} flows."

def test_soak_busy_traffic_zero_alerts():
    """60 consecutive ticks of BUSY scenario traffic must produce 0 alerts."""
    db = SessionLocal()
    initial_alerts = db.query(Alert).count()
    assert initial_alerts == 0

    total_records = 0
    for tick in range(60):
        records = traffic_generator.generate_tick(db, scenario="BUSY")
        total_records += len(records)

    alert_count = db.query(Alert).count()
    db.close()

    assert alert_count == 0, f"Expected 0 alerts in BUSY soak test, but found {alert_count} alerts across {total_records} flows."
