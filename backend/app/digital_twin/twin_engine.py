import time
import logging
from typing import Dict, List, Any, Optional, Set
import networkx as nx
from sqlalchemy.orm import Session

from app.models.device import Device
from app.models.connection import NetworkConnection
from app.models.traffic import TrafficRecord
from app.models.simulation import SimulationRun, AttackPath
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.services.health_calculator import calculate_device_risk_breakdown, calculate_network_health
from app.services.audit_service import log_audit_event
from app.config import settings

logger = logging.getLogger("netguardian.twin")

class DigitalTwinEngine:
    """
    Phase 5 Digital Twin Engine:
    In-memory living NetworkX graph representation of the physical and logical network state.
    Synchronized with database, differentiates structural links vs observed communication edges,
    and enables safe 'What-If' attack path and blast radius analysis.
    """
    def __init__(self):
        self.graph = nx.Graph()
        self.last_sync_time: float = 0.0
        self.is_synchronized: bool = False

    def sync_from_database(self, db: Session):
        """
        Synchronize the NetworkX graph with database devices and connections (Task 1 & Task 3).
        Creates nodes with full metadata and distinct structural links vs observed edges.
        """
        self.graph.clear()

        # 1. Load all devices as nodes
        devices = db.query(Device).all()
        dev_by_name = {}
        dev_by_id = {}

        for d in devices:
            self.graph.add_node(
                d.device_name,
                id=d.id,
                ip=d.ip_address,
                mac=d.mac_address,
                device_type=d.device_type,
                os_type=d.os_type,
                status=d.status,
                criticality=d.criticality or "MEDIUM",
                trust_level=d.trust_level or "MEDIUM",
                risk_score=d.risk_score or 0.0,
                trust_score=d.trust_score if d.trust_score is not None else 100.0,
                is_isolated=d.is_isolated or False,
                device_source=getattr(d, "device_source", "SIMULATED"),
                is_registered=getattr(d, "is_registered", True)
            )
            dev_by_name[d.device_name] = d
            dev_by_id[d.id] = d

        # 2. Build Structural Infrastructure Baseline Links (Task 1: Show structural links)
        # Find key infrastructure nodes
        internet_node = next((d.device_name for d in devices if "internet" in (d.device_type or "").lower() or "internet" in d.device_name.lower()), None)
        router_node = next((d.device_name for d in devices if "router" in (d.device_type or "").lower() or "router" in d.device_name.lower()), None)
        switch_node = next((d.device_name for d in devices if "switch" in (d.device_type or "").lower() or "switch" in d.device_name.lower()), None)
        server_node = next((d.device_name for d in devices if d.device_name in ["Server", "App-Server"] or "server" in (d.device_type or "").lower()), None)
        db_node = next((d.device_name for d in devices if d.device_name in ["Database", "DB-Server"] or "database" in (d.device_type or "").lower()), None)

        # Internet <-> Router structural link
        if internet_node and router_node and internet_node in self.graph and router_node in self.graph:
            self.graph.add_edge(
                internet_node, router_node,
                edge_type="structural",
                protocol="IP",
                source_port=0,
                destination_port=0,
                bytes=0,
                trust_level="HIGH",
                active=True
            )

        # Router <-> Switch structural link
        if router_node and switch_node and router_node in self.graph and switch_node in self.graph:
            self.graph.add_edge(
                router_node, switch_node,
                edge_type="structural",
                protocol="ETHERNET",
                source_port=0,
                destination_port=0,
                bytes=0,
                trust_level="HIGH",
                active=True
            )

        # Switch <-> Endpoints & Servers structural links
        if switch_node and switch_node in self.graph:
            for d in devices:
                name = d.device_name
                if name in [internet_node, router_node, switch_node, db_node]:
                    continue
                if name in self.graph:
                    is_active = not (d.is_isolated or self.graph.nodes[switch_node].get("is_isolated", False))
                    self.graph.add_edge(
                        switch_node, name,
                        edge_type="structural",
                        protocol="ETHERNET",
                        source_port=0,
                        destination_port=0,
                        bytes=0,
                        trust_level=d.trust_level or "MEDIUM",
                        active=is_active
                    )

        # Server <-> Database structural link (protected backend link)
        if server_node and db_node and server_node in self.graph and db_node in self.graph:
            srv_iso = self.graph.nodes[server_node].get("is_isolated", False)
            db_iso = self.graph.nodes[db_node].get("is_isolated", False)
            self.graph.add_edge(
                server_node, db_node,
                edge_type="structural",
                protocol="TCP",
                source_port=0,
                destination_port=5432,
                bytes=0,
                trust_level="CRITICAL",
                active=not (srv_iso or db_iso)
            )

        # 3. Load Observed Application Communication Edges (Task 1: Observed communication edges)
        conns = db.query(NetworkConnection).all()
        for c in conns:
            src_dev = dev_by_id.get(c.source_device_id)
            dst_dev = dev_by_id.get(c.destination_device_id)
            if not src_dev or not dst_dev:
                continue

            src_name = src_dev.device_name
            dst_name = dst_dev.device_name

            if src_name in self.graph and dst_name in self.graph:
                src_isolated = self.graph.nodes[src_name].get("is_isolated", False)
                dst_isolated = self.graph.nodes[dst_name].get("is_isolated", False)
                is_active = not (src_isolated or dst_isolated)

                # Determine if this connection is observed application traffic
                is_app_traffic = (
                    (c.destination_port or 0) > 0 or
                    (c.protocol or "").upper() not in ["ETHERNET", "NONE", ""] or
                    (c.bytes_transferred or 0) > 0
                )
                edge_type = "observed" if is_app_traffic else "structural"

                # If an edge already exists (e.g. baseline structural link), keep structural type
                # while overlaying observed protocol, port, and byte traffic
                if self.graph.has_edge(src_name, dst_name):
                    existing = self.graph[src_name][dst_name]
                    existing["protocol"] = c.protocol or existing.get("protocol", "TCP")
                    if c.destination_port:
                        existing["destination_port"] = c.destination_port
                    existing["bytes"] = max(existing.get("bytes", 0), c.bytes_transferred or 0)
                    existing["active"] = is_active
                else:
                    self.graph.add_edge(
                        src_name,
                        dst_name,
                        edge_type="observed",
                        protocol=c.protocol or "TCP",
                        source_port=c.source_port or 0,
                        destination_port=c.destination_port or 80,
                        bytes=c.bytes_transferred or 0,
                        trust_level=dst_dev.trust_level or "MEDIUM",
                        active=is_active
                    )

        self.last_sync_time = time.time()
        self.is_synchronized = True

    def check_sync_status(self, db: Optional[Session] = None) -> str:
        """
        Strong real-time state comparison between database and in-memory graph (Item 4).
        Compares:
        1. Device counts and device IDs
        2. Operational status and risk scores per device
        3. Structural topology links
        Returns 'OUT OF SYNC' if any attribute diverges, else 'SYNCHRONIZED'.
        """
        if not self.is_synchronized:
            return "OUT OF SYNC"
        if db is None:
            return "SYNCHRONIZED"

        try:
            db_devices = db.query(Device).all()
            # 1. Compare device counts
            if len(db_devices) != len(self.graph.nodes):
                return "OUT OF SYNC"

            # 2. Compare device IDs, status, and risk scores
            for d in db_devices:
                if d.device_name not in self.graph:
                    return "OUT OF SYNC"
                node = self.graph.nodes[d.device_name]
                if node.get("id") != d.id:
                    return "OUT OF SYNC"
                if (node.get("status") or "").upper() != (d.status or "").upper():
                    return "OUT OF SYNC"
                # Compare risk score (round to 1 decimal)
                graph_risk = round(node.get("risk_score", 0.0), 1)
                db_risk = round(d.risk_score or 0.0, 1)
                if graph_risk != db_risk:
                    return "OUT OF SYNC"

            # 3. Check structural links in graph
            structural_edges = [
                (u, v) for u, v, data in self.graph.edges(data=True)
                if data.get("edge_type") == "structural"
            ]
            if len(structural_edges) == 0:
                return "OUT OF SYNC"

            # Check that Switch is structurally linked to its endpoints
            switch_node = next((d.device_name for d in db_devices if "switch" in (d.device_type or "").lower() or "switch" in d.device_name.lower()), None)
            if switch_node and switch_node in self.graph:
                for d in db_devices:
                    if d.device_name in ["Internet", "Router", "Database", switch_node]:
                        continue
                    if not self.graph.has_edge(switch_node, d.device_name):
                        return "OUT OF SYNC"

            return "SYNCHRONIZED"
        except Exception as e:
            logger.warning(f"Failed to check sync status against DB: {e}")
            return "OUT OF SYNC"

    def get_topology(self, db: Optional[Session] = None) -> Dict[str, Any]:
        """
        Export serialized graph nodes and edges for frontend visualization.
        Differentiates structural vs observed edges and includes real sync status.
        """
        nodes = []
        for name, data in self.graph.nodes(data=True):
            nodes.append({
                "id": data.get("id"),
                "name": name,
                "ip": data.get("ip"),
                "mac": data.get("mac"),
                "type": data.get("device_type"),
                "os": data.get("os_type"),
                "status": data.get("status"),
                "criticality": data.get("criticality", "MEDIUM"),
                "trust_level": data.get("trust_level", "MEDIUM"),
                "risk_score": round(data.get("risk_score", 0.0), 1),
                "trust_score": round(data.get("trust_score", 100.0), 1),
                "is_isolated": data.get("is_isolated", False),
                "device_source": data.get("device_source", "SIMULATED"),
                "is_registered": data.get("is_registered", True)
            })

        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append({
                "source": u,
                "target": v,
                "protocol": data.get("protocol", "TCP"),
                "port": data.get("destination_port", 0),
                "bytes": data.get("bytes", 0),
                "active": data.get("active", True),
                "edge_type": data.get("edge_type", "structural"),
                "trust_level": data.get("trust_level", "MEDIUM")
            })

        sync_state = self.check_sync_status(db)

        return {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "last_sync": self.last_sync_time,
            "state": sync_state,
            "mode": getattr(settings, "SYSTEM_MODE", "SIMULATION"),
            "data_tag": "SIMULATED" if getattr(settings, "SYSTEM_MODE", "SIMULATION") == "SIMULATION" else "OBSERVED"
        }

    def simulate_what_if_compromise(
        self,
        source_device_name: str,
        db: Session,
        scenario: str = "COMPROMISED_HOST"
    ) -> Dict[str, Any]:
        """
        Phase 6 Task 1 & 2: Safe 'What-If' attack graph traversal.
        It must NOT attack or probe anything. It only traverses the Digital Twin graph.
        Use structural links only, and exclude offline or isolated nodes and the Internet node.
        Prioritizes paths that reach critical assets.
        """
        start_time = time.time()

        if source_device_name not in self.graph:
            dev = db.query(Device).filter(Device.device_name == source_device_name).first()
            if not dev:
                raise ValueError(f"Device {source_device_name} not found in Digital Twin.")
            self.sync_from_database(db)

        src_data = self.graph.nodes.get(source_device_name, {})
        src_status = (src_data.get("status") or "ONLINE").upper()
        src_isolated = src_data.get("is_isolated", False) or src_status == "ISOLATED"
        src_offline = src_status == "OFFLINE"

        # Acceptance check: An isolated or offline source returns "no reachable systems" without an error.
        if src_isolated or src_offline:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            sim_run = SimulationRun(
                simulation_type=scenario,
                target_device=source_device_name,
                result=f"HYPOTHETICAL: Source device {source_device_name} is {'isolated' if src_isolated else 'offline'}. 0 reachable systems.",
                risk_level="LOW",
                path_risk_score=0.0,
                critical_assets_reached=0
            )
            db.add(sim_run)
            db.commit()

            return {
                "simulation_id": sim_run.id,
                "target_device": source_device_name,
                "source_device": source_device_name,
                "target_ip": src_data.get("ip", "N/A"),
                "scenario": scenario,
                "scenario_text": f"{source_device_name} is hypothetically compromised",
                "potential_reach_path": [],
                "path_display": f"No reachable systems ({'Isolated' if src_isolated else 'Offline'})",
                "reachable_systems": [],
                "reachable_nodes": [],
                "reachable_nodes_count": 0,
                "reachable_count": 0,
                "hop_count": 0,
                "path_length": 0,
                "critical_asset_reached": "NO",
                "is_critical_asset_reached": False,
                "critical_assets_at_risk": [],
                "simulated_risk_level": "LOW",
                "simulated_risk_score": 0.0,
                "path_risk_score": 0.0,
                "max_path_risk": 0.0,
                "attack_paths": [],
                "attack_path": [],
                "score_breakdown": {
                    "Source Risk": 0.0,
                    "Target Criticality": 0.0,
                    "Hops": 0.0,
                    "Trust": 0.0
                },
                "breakdown": {
                    "source_risk": {"value": 0.0, "weight": 0.30, "points": 0.0},
                    "target_criticality": {"category": "NONE", "value": 0.0, "weight": 0.35, "points": 0.0},
                    "hop_factor": {"hops": 0, "value": 0.0, "weight": 0.15, "points": 0.0},
                    "path_trust": {"average_trust": 0.0, "weight": 0.20, "points": 0.0},
                    "total_simulated_risk": 0.0,
                    "level": "LOW"
                },
                "recommended_controls": [
                    "Restrict unnecessary communication",
                    "Review trust relationships",
                    "Isolate the suspicious endpoint",
                    "Monitor server connections"
                ],
                "recommendations": [
                    "Restrict unnecessary communication",
                    "Review trust relationships",
                    "Isolate the suspicious endpoint",
                    "Monitor server connections"
                ],
                "is_hypothetical": True,
                "label": "HYPOTHETICAL",
                "execution_time_ms": elapsed_ms
            }

        # Build structural traversal graph:
        # Exclude: offline nodes, isolated nodes, and the Internet node.
        # Include: structural links only (edge_type == "structural" and active != False).
        structural_graph = nx.Graph()
        allowed_nodes: Set[str] = set()

        for node_name, data in self.graph.nodes(data=True):
            if "internet" in node_name.lower() or data.get("device_type", "").lower() == "internet":
                continue
            st = (data.get("status") or "ONLINE").upper()
            if st in ["OFFLINE", "ISOLATED"] or data.get("is_isolated", False):
                continue
            structural_graph.add_node(node_name, **data)
            allowed_nodes.add(node_name)

        for u, v, data in self.graph.edges(data=True):
            if u in allowed_nodes and v in allowed_nodes:
                if data.get("edge_type") == "structural" and data.get("active", True) is not False:
                    structural_graph.add_edge(u, v, **data)

        # Traverse reachable systems via BFS/connected component
        if source_device_name in structural_graph:
            reachable_nodes = sorted([
                n for n in nx.node_connected_component(structural_graph, source_device_name)
                if n != source_device_name
            ])
        else:
            reachable_nodes = []

        src_risk = float(src_data.get("risk_score", 0.0))
        crit_values = {"LOW": 20.0, "MEDIUM": 45.0, "HIGH": 70.0, "CRITICAL": 95.0}
        attack_paths_list: List[Dict[str, Any]] = []

        for target in reachable_nodes:
            target_data = structural_graph.nodes[target]
            target_crit = (target_data.get("criticality") or "MEDIUM").upper()
            target_crit_val = crit_values.get(target_crit, 45.0)

            try:
                path = nx.shortest_path(structural_graph, source=source_device_name, target=target)
                hop_count = len(path) - 1

                # Task 3 Formula:
                # Hop factor = max(0, 100 - 20 * (hops - 1))
                hop_factor = max(0.0, 100.0 - 20.0 * (hop_count - 1))

                # Average implicit trust along the path
                avg_trust = sum(float(structural_graph.nodes[n].get("trust_score", 80.0)) for n in path) / len(path)

                src_risk_pts = round(0.30 * src_risk, 2)
                tgt_crit_pts = round(0.35 * target_crit_val, 2)
                hop_pts = round(0.15 * hop_factor, 2)
                trust_pts = round(0.20 * avg_trust, 2)

                path_risk = round(src_risk_pts + tgt_crit_pts + hop_pts + trust_pts, 2)

                # Levels: LOW below 30, MEDIUM below 55, HIGH below 80, CRITICAL 80 or more
                if path_risk >= 80.0:
                    sim_lvl = "CRITICAL"
                elif path_risk >= 55.0:
                    sim_lvl = "HIGH"
                elif path_risk >= 30.0:
                    sim_lvl = "MEDIUM"
                else:
                    sim_lvl = "LOW"

                attack_paths_list.append({
                    "source_node": source_device_name,
                    "destination_node": target,
                    "path": path,
                    "hop_count": hop_count,
                    "risk": path_risk,
                    "simulated_risk_level": sim_lvl,
                    "target_criticality": target_crit,
                    "target_criticality_val": target_crit_val,
                    "hop_factor": hop_factor,
                    "average_trust": round(avg_trust, 2),
                    "score_breakdown": {
                        "Source Risk": src_risk_pts,
                        "Target Criticality": tgt_crit_pts,
                        "Hops": hop_pts,
                        "Trust": trust_pts
                    },
                    "breakdown": {
                        "source_risk": {"value": src_risk, "weight": 0.30, "points": src_risk_pts},
                        "target_criticality": {"category": target_crit, "value": target_crit_val, "weight": 0.35, "points": tgt_crit_pts},
                        "hop_factor": {"hops": hop_count, "value": hop_factor, "weight": 0.15, "points": hop_pts},
                        "path_trust": {"average_trust": round(avg_trust, 2), "weight": 0.20, "points": trust_pts},
                        "total_simulated_risk": path_risk,
                        "level": sim_lvl
                    },
                    "contains_critical_asset": target_crit == "CRITICAL"
                })
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

        # Prioritize paths that reach critical assets:
        # Sort key: (1 if target is CRITICAL else 0, target_crit_val, risk) descending
        attack_paths_list.sort(
            key=lambda x: (
                1 if x["target_criticality"] == "CRITICAL" else 0,
                x["target_criticality_val"],
                x["risk"]
            ),
            reverse=True
        )

        critical_assets = [p["destination_node"] for p in attack_paths_list if p["target_criticality"] == "CRITICAL"]
        has_critical = len(critical_assets) > 0

        if attack_paths_list:
            primary_path_obj = attack_paths_list[0]
            primary_path = primary_path_obj["path"]
            primary_hops = primary_path_obj["hop_count"]
            primary_risk = primary_path_obj["risk"]
            primary_level = primary_path_obj["simulated_risk_level"]
            primary_breakdown = primary_path_obj["score_breakdown"]
            primary_breakdown_detail = primary_path_obj["breakdown"]
            path_display = " → ".join(primary_path)
        else:
            primary_path = []
            primary_hops = 0
            primary_risk = 0.0
            primary_level = "LOW"
            primary_breakdown = {"Source Risk": 0.0, "Target Criticality": 0.0, "Hops": 0.0, "Trust": 0.0}
            primary_breakdown_detail = {
                "source_risk": {"value": 0.0, "weight": 0.30, "points": 0.0},
                "target_criticality": {"category": "NONE", "value": 0.0, "weight": 0.35, "points": 0.0},
                "hop_factor": {"hops": 0, "value": 0.0, "weight": 0.15, "points": 0.0},
                "path_trust": {"average_trust": 0.0, "weight": 0.20, "points": 0.0},
                "total_simulated_risk": 0.0,
                "level": "LOW"
            }
            path_display = "No reachable systems"

        # Ordered step list with numbered nodes and text labels as well as color
        attack_path_steps = []
        for step_idx, node_name in enumerate(primary_path, 1):
            n_data = structural_graph.nodes.get(node_name, {})
            crit = (n_data.get("criticality") or "MEDIUM").upper()
            is_crit = crit == "CRITICAL"
            if step_idx == 1:
                role_label = "COMPROMISED ORIGIN"
            elif step_idx == len(primary_path) and is_crit:
                role_label = "CRITICAL TARGET"
            elif is_crit:
                role_label = "CRITICAL ASSET"
            elif n_data.get("device_type") == "Server":
                role_label = "CORE SERVER"
            elif n_data.get("device_type") == "Switch":
                role_label = "LATERAL HOP"
            else:
                role_label = f"LATERAL HOP {step_idx - 1}"

            attack_path_steps.append({
                "step": step_idx,
                "node": node_name,
                "name": node_name,
                "device_name": node_name,
                "ip_address": n_data.get("ip", "N/A"),
                "device_type": n_data.get("device_type", "Unknown"),
                "criticality": crit,
                "is_critical": is_crit,
                "trust_score": n_data.get("trust_score", 80.0),
                "role_label": role_label
            })

        # Task 2: Recommended Controls
        recommended_controls = [
            "Restrict unnecessary communication",
            "Review trust relationships",
            "Isolate the suspicious endpoint",
            "Monitor server connections"
        ]

        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        # Task 7: Save in simulation_runs and attack_paths with HYPOTHETICAL label
        sim_run = SimulationRun(
            simulation_type=scenario,
            target_device=source_device_name,
            result=f"HYPOTHETICAL: Traversed {len(reachable_nodes)} systems. Primary path: {path_display}",
            risk_level=primary_level,
            path_risk_score=primary_risk,
            critical_assets_reached=1 if has_critical else 0
        )
        db.add(sim_run)
        db.flush()

        for ap in attack_paths_list[:5]:
            db_path = AttackPath(
                simulation_id=sim_run.id,
                source_node=ap["source_node"],
                destination_node=ap["destination_node"],
                path=ap["path"],
                hop_count=ap["hop_count"],
                risk=ap["risk"]
            )
            db.add(db_path)
        db.commit()

        return {
            "simulation_id": sim_run.id,
            "target_device": source_device_name,
            "source_device": source_device_name,
            "target_ip": src_data.get("ip", "N/A"),
            "scenario": scenario,
            "scenario_text": f"{source_device_name} is hypothetically compromised",
            "potential_reach_path": primary_path,
            "path_display": path_display,
            "reachable_systems": reachable_nodes,
            "reachable_nodes": reachable_nodes,
            "reachable_nodes_count": len(reachable_nodes),
            "reachable_count": len(reachable_nodes),
            "hop_count": primary_hops,
            "path_length": primary_hops,
            "critical_asset_reached": "YES" if has_critical else "NO",
            "is_critical_asset_reached": has_critical,
            "critical_assets_at_risk": critical_assets,
            "simulated_risk_level": primary_level,
            "simulated_risk_score": primary_risk,
            "path_risk_score": primary_risk,
            "max_path_risk": primary_risk,
            "attack_paths": attack_paths_list,
            "attack_path": attack_path_steps,
            "score_breakdown": primary_breakdown,
            "breakdown": primary_breakdown_detail,
            "recommended_controls": recommended_controls,
            "recommendations": recommended_controls,
            "is_hypothetical": True,
            "label": "HYPOTHETICAL",
            "execution_time_ms": elapsed_ms
        }

    def simulate_isolation(self, target_device_name: str, db: Session) -> Dict[str, Any]:
        """
        Phase 6 Task 5: Execute Simulated Isolation on a node in the Digital Twin:
        - Changes the SIMULATED topology only
        - The device's links are cut in the twin
        - Related open events become Contained
        - Risk and health are recalculated
        - Device stops generating simulated traffic
        - Shows exact message: "SIMULATED ACTION — [device] isolated. Potential attack path interrupted. No real network changes were performed."
        - Provides Before and After comparison
        """
        device = db.query(Device).filter(Device.device_name == target_device_name).first()
        if not device:
            raise ValueError(f"Device {target_device_name} not found in database.")

        # Capture Before state
        before_sim = self.simulate_what_if_compromise(target_device_name, db)
        reach_before_count = before_sim.get("reachable_nodes_count", 0)
        reach_before_systems = before_sim.get("reachable_systems", [])
        risk_before = before_sim.get("path_risk_score", 0.0)
        crit_before = before_sim.get("critical_asset_reached", "NO")

        # 1. Update device state in DB
        device.is_isolated = True
        device.status = "ISOLATED"

        # 2. Related open events become Contained
        open_alerts = db.query(Alert).filter(
            (Alert.source_ip == device.ip_address) | (Alert.destination_ip == device.ip_address),
            Alert.status.in_(["NEW", "INVESTIGATING"])
        ).all()
        for a in open_alerts:
            a.status = "CONTAINED"

        open_events = db.query(SecurityEvent).filter(
            (SecurityEvent.source_device.in_([device.ip_address, device.device_name])) |
            (SecurityEvent.destination_device.in_([device.ip_address, device.device_name])),
            SecurityEvent.status.in_(["NEW", "INVESTIGATING"])
        ).all()
        for ev in open_events:
            ev.status = "CONTAINED"

        # 3. Recalculate transparent risk breakdown with isolation containment
        breakdown = calculate_device_risk_breakdown(device, db)
        device.risk_score = breakdown["risk_score"]
        device.trust_score = breakdown["trust_score"]
        db.commit()

        # 4. Update in-memory twin graph: sever logical links
        severed_count = 0
        if target_device_name in self.graph:
            self.graph.nodes[target_device_name]["is_isolated"] = True
            self.graph.nodes[target_device_name]["status"] = "ISOLATED"
            self.graph.nodes[target_device_name]["risk_score"] = device.risk_score
            self.graph.nodes[target_device_name]["trust_score"] = device.trust_score

            for neighbor in list(self.graph.neighbors(target_device_name)):
                self.graph[target_device_name][neighbor]["active"] = False
                severed_count += 1

        # 5. Recompute network health (alerts contained -> health improves)
        health = calculate_network_health(db)

        # 6. Audit log
        log_audit_event(
            db=db,
            action="SIMULATE_ISOLATION",
            details=f"SIMULATED ACTION: {device.device_name} isolated in Digital Twin. All {severed_count} logical connections severed."
        )

        exact_message = f"SIMULATED ACTION — {device.device_name} isolated. Potential attack path interrupted. No real network changes were performed."

        return {
            "target_device_id": device.id,
            "device_name": device.device_name,
            "ip_address": device.ip_address,
            "is_isolated": True,
            "status": "ISOLATED",
            "edges_severed": severed_count,
            "reachability_before": reach_before_count,
            "reachability_after": 0,
            "simulated_risk_before": risk_before,
            "simulated_risk_after": 0.0,
            "risk_reduction_percentage": 100.0 if reach_before_count > 0 else 0.0,
            "health_score_after": health["health_score"],
            "message": exact_message,
            "before_after_comparison": {
                "before": {
                    "reachable_count": reach_before_count,
                    "reachable_systems": reach_before_systems,
                    "simulated_risk": risk_before,
                    "critical_asset_reached": crit_before
                },
                "after": {
                    "reachable_count": 0,
                    "reachable_systems": [],
                    "simulated_risk": 0.0,
                    "critical_asset_reached": "NO"
                },
                "risk_reduction_percentage": 100.0 if reach_before_count > 0 else 0.0
            }
        }

    def restore_isolation(self, target_device_name: str, db: Session) -> Dict[str, Any]:
        """
        Phase 6 Task 5: Restore isolated node back to online operational state in Digital Twin.
        Re-establishes structural links, recalculates risk and health, and logs audit event.
        """
        device = db.query(Device).filter(Device.device_name == target_device_name).first()
        if not device:
            raise ValueError(f"Device {target_device_name} not found.")

        device.is_isolated = False
        device.status = "ONLINE"
        breakdown = calculate_device_risk_breakdown(device, db)
        device.risk_score = breakdown["risk_score"]
        device.trust_score = breakdown["trust_score"]
        db.commit()

        # Re-sync twin from database so all links are restored
        self.sync_from_database(db)

        # Recalculate health
        health = calculate_network_health(db)

        log_audit_event(
            db=db,
            action="RESTORE_ISOLATION",
            details=f"SIMULATED ACTION: {device.device_name} restored to active Digital Twin network."
        )

        return {
            "target_device_id": device.id,
            "device_name": target_device_name,
            "is_isolated": False,
            "status": "ONLINE",
            "risk_score": device.risk_score,
            "trust_score": device.trust_score,
            "health_score": health["health_score"],
            "message": f"SIMULATED ACTION — {device.device_name} restored. Links re-established in Digital Twin."
        }

# Global singleton Digital Twin instance
digital_twin = DigitalTwinEngine()

def sync_state_on_change(
    db: Session,
    affected_device_ips: Optional[List[str]] = None,
    action: str = "STATE_CHANGE",
    details: str = "",
    username: str = "system",
    user_id: Optional[int] = None,
    ip_address: str = "127.0.0.1"
) -> Dict[str, Any]:
    """
    Central 5-Step Synchronization Rule (Phase 5 Task 3):
    On any device, connection, or event change:
    1. Update database (recalculate affected device risk/trust, recover device status if threats resolved)
    2. Update graph (digital_twin.sync_from_database)
    3. Update dashboard / recompute network health
    4. Recalculate affected risk
    5. Record important change in audit log
    """
    # Ensure any pending attribute changes on models in the session (e.g. alert status) are flushed to DB
    db.flush()

    # 1. Update database: recalculate affected devices
    if affected_device_ips:
        devices = db.query(Device).filter(Device.ip_address.in_(affected_device_ips)).all()
    else:
        devices = db.query(Device).all()

    for dev in devices:
        # Check active unresolved alerts
        active_alerts_count = db.query(Alert).filter(
            (Alert.source_ip == dev.ip_address) | (Alert.destination_ip == dev.ip_address),
            Alert.status.in_(["NEW", "INVESTIGATING"])
        ).count()

        # If device was SUSPICIOUS and all alerts are resolved/false-positive, recover to ONLINE
        if dev.status == "SUSPICIOUS" and active_alerts_count == 0:
            dev.status = "ONLINE"
            # Clear anomalous traffic flags for this device now that threats are resolved
            db.query(TrafficRecord).filter(TrafficRecord.source_ip == dev.ip_address).update({"is_anomalous": 0})

        breakdown = calculate_device_risk_breakdown(dev, db)
        dev.risk_score = breakdown["risk_score"]
        dev.trust_score = breakdown["trust_score"]

    db.flush()

    # 2. Update graph
    digital_twin.sync_from_database(db)

    # 3. Update dashboard / health calculation
    health = calculate_network_health(db)

    # 4. Commit changes
    db.commit()

    # 5. Record important change in audit log
    if details:
        try:
            log_audit_event(
                db=db,
                action=action,
                user_id=user_id,
                username=username,
                ip_address=ip_address,
                details=details
            )
            db.commit()
        except Exception as e:
            logger.warning(f"Failed to record audit event in sync_state_on_change: {e}")

    return {
        "status": "SYNCHRONIZED",
        "nodes_count": len(digital_twin.graph.nodes),
        "edges_count": len(digital_twin.graph.edges),
        "health": health
    }
