import re
import ipaddress
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.device import Device
from app.models.connection import NetworkConnection
from app.models.user import User
from app.services.auth_service import require_admin, require_analyst_or_admin
from app.utils.time_utils import utcnow
from app.schemas.device import DeviceCreate, DeviceUpdate, DeviceResponse, RiskBreakdownResponse
from app.services.health_calculator import calculate_device_risk_breakdown
from app.digital_twin.twin_engine import digital_twin, sync_state_on_change

router = APIRouter(prefix="/api/devices", tags=["Devices"])

@router.get("", response_model=List[DeviceResponse])
def get_devices(
    search: Optional[str] = None,
    status: Optional[str] = None,
    criticality: Optional[str] = None,
    device_type: Optional[str] = None,
    device_source: Optional[str] = None,
    is_registered: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """Retrieve all monitored/simulated network devices with optional filtering."""
    query = db.query(Device)
    if search:
        s = f"%{search}%"
        query = query.filter(
            (Device.device_name.ilike(s)) |
            (Device.ip_address.ilike(s)) |
            (Device.mac_address.ilike(s))
        )
    if status:
        query = query.filter(Device.status == status.upper())
    if criticality:
        query = query.filter(Device.criticality == criticality.upper())
    if device_type:
        query = query.filter(Device.device_type.ilike(f"%{device_type}%"))
    if device_source:
        query = query.filter(Device.device_source == device_source.upper())
    if is_registered is not None:
        query = query.filter(Device.is_registered == is_registered)

    return query.order_by(Device.id).all()

@router.get("/{device_id}", response_model=DeviceResponse)
def get_device(device_id: int, db: Session = Depends(get_db)):
    """Retrieve details of a specific device."""
    dev = db.query(Device).filter(Device.id == device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    return dev

@router.get("/{device_id}/risk-breakdown", response_model=RiskBreakdownResponse)
def get_device_risk_breakdown(device_id: int, db: Session = Depends(get_db)):
    """Retrieve mathematical risk breakdown and explanatory factors for a device."""
    dev = db.query(Device).filter(Device.id == device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    return calculate_device_risk_breakdown(dev, db)

@router.post("", response_model=DeviceResponse)
def create_device(
    dev_in: DeviceCreate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Task 3: Add a new simulated device to the network inventory (Admin Only).
    Validates IP format, MAC format, duplicate name, IP, and MAC.
    Attaches the device to Core-Switch-01 and synchronizes with Digital Twin.
    """
    # 1. Validate IP format
    clean_ip = dev_in.ip_address.strip()
    try:
        ipaddress.ip_address(clean_ip)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid IP address format: '{clean_ip}'. Must be a valid IPv4 address (e.g., 192.168.1.55)."
        )

    # 2. Validate MAC address format
    clean_mac = dev_in.mac_address.strip()
    mac_regex = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    if not re.match(mac_regex, clean_mac):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid MAC address format: '{clean_mac}'. Expected format: 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E."
        )

    # 3. Check for duplicates
    clean_name = dev_in.device_name.strip()
    if not clean_name:
        raise HTTPException(status_code=400, detail="Device name cannot be empty.")

    if db.query(Device).filter(func.lower(Device.device_name) == clean_name.lower()).first():
        raise HTTPException(status_code=400, detail=f"Device with name '{clean_name}' already exists.")
    if db.query(Device).filter(Device.ip_address == clean_ip).first():
        raise HTTPException(status_code=400, detail=f"Device with IP address '{clean_ip}' already exists.")
    if db.query(Device).filter(func.lower(Device.mac_address) == clean_mac.lower()).first():
        raise HTTPException(status_code=400, detail=f"Device with MAC address '{clean_mac}' already exists.")

    # 4. Validate and map trust level (strictly LOW, MEDIUM, HIGH, UNTRUSTED)
    valid_trust_levels = {"UNTRUSTED", "LOW", "MEDIUM", "HIGH"}
    trust_lvl = dev_in.trust_level.upper() if dev_in.trust_level else "MEDIUM"
    if trust_lvl not in valid_trust_levels:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid trust_level '{dev_in.trust_level}'. Must be one of: {', '.join(sorted(valid_trust_levels))}"
        )

    trust_map = {"UNTRUSTED": 20.0, "LOW": 50.0, "MEDIUM": 80.0, "HIGH": 95.0}
    crit = dev_in.criticality.upper()
    init_trust = dev_in.trust_score if dev_in.trust_score != 100.0 else trust_map.get(trust_lvl, 80.0)

    new_device = Device(
        device_name=clean_name,
        ip_address=clean_ip,
        mac_address=clean_mac,
        device_type=dev_in.device_type,
        os_type=dev_in.os_type or "Linux",
        criticality=crit,
        trust_level=trust_lvl,
        status=dev_in.status.upper(),
        trust_score=init_trust,
        risk_score=20.0,
        first_seen=utcnow(),
        last_seen=utcnow()
    )
    db.add(new_device)
    db.flush()

    # 5. Automatically connect to Switch (Task 3: Attach it to the switch)
    switch = db.query(Device).filter(Device.device_name.in_(["Switch", "Core-Switch-01"])).first()
    if not switch:
        switch = db.query(Device).filter(Device.device_type == "Switch").first()
    if switch and new_device.id != switch.id:
        conn1 = NetworkConnection(
            source_device_id=new_device.id,
            destination_device_id=switch.id,
            protocol="ETHERNET",
            source_port=0,
            destination_port=0,
            packet_count=10,
            bytes_transferred=640,
            timestamp=utcnow()
        )
        conn2 = NetworkConnection(
            source_device_id=switch.id,
            destination_device_id=new_device.id,
            protocol="ETHERNET",
            source_port=0,
            destination_port=0,
            packet_count=10,
            bytes_transferred=640,
            timestamp=utcnow()
        )
        db.add_all([conn1, conn2])

    db.commit()
    db.refresh(new_device)

    # 6. Core Task 3: Centralized state sync (DB, Graph, Dashboard/Health, Audit Log)
    sync_state_on_change(
        db=db,
        affected_device_ips=[new_device.ip_address],
        action="CREATE_DEVICE",
        details=f"Device {new_device.device_name} ({new_device.ip_address}) created and attached to Switch by {admin.username}",
        username=admin.username,
        user_id=admin.id
    )

    return new_device

@router.patch("/{device_id}", response_model=DeviceResponse)
def update_device(
    device_id: int,
    dev_in: DeviceUpdate,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Update device properties (criticality, status, trust score, isolation). Requires Analyst or Admin role."""
    dev = db.query(Device).filter(Device.id == device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")

    if dev_in.device_name is not None:
        dev.device_name = dev_in.device_name
    if dev_in.criticality is not None:
        dev.criticality = dev_in.criticality.upper()
    if dev_in.status is not None:
        dev.status = dev_in.status.upper()
    if dev_in.trust_score is not None:
        dev.trust_score = dev_in.trust_score
    if dev_in.is_isolated is not None:
        dev.is_isolated = dev_in.is_isolated

    dev.last_seen = utcnow()
    db.commit()
    db.refresh(dev)

    # Core Task 3: Centralized state sync
    sync_state_on_change(
        db=db,
        affected_device_ips=[dev.ip_address],
        action="UPDATE_DEVICE",
        details=f"Device {dev.device_name} ({dev.ip_address}) updated by {current_user.username}",
        username=current_user.username,
        user_id=current_user.id
    )
    return dev

@router.delete("/{device_id}")
def delete_device(
    device_id: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Remove a device and its connections from the network. Requires Admin role."""
    dev = db.query(Device).filter(Device.id == device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")

    dev_name = dev.device_name
    dev_ip = dev.ip_address

    db.query(NetworkConnection).filter(
        (NetworkConnection.source_device_id == device_id) |
        (NetworkConnection.destination_device_id == device_id)
    ).delete()
    db.delete(dev)
    db.commit()

    # Core Task 3: Centralized state sync
    sync_state_on_change(
        db=db,
        affected_device_ips=None,
        action="DELETE_DEVICE",
        details=f"Device {dev_name} ({dev_ip}) deleted by {admin.username}",
        username=admin.username,
        user_id=admin.id
    )
    return {"message": f"Device {dev_name} deleted successfully."}
