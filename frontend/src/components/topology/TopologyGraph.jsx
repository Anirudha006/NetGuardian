import React, { useRef, useEffect, useState } from 'react';
import { ZoomIn, ZoomOut, RefreshCw } from 'lucide-react';

const NODE_COLORS = {
  normal:   { fill: '#ecfdf5', stroke: '#059669', text: '#065f46', dot: '#059669' },
  warning:  { fill: '#fef9c3', stroke: '#ca8a04', text: '#713f12', dot: '#d97706' },
  critical: { fill: '#fef2f2', stroke: '#dc2626', text: '#991b1b', dot: '#dc2626' },
  offline:  { fill: '#f8fafc', stroke: '#cbd5e1', text: '#94a3b8', dot: '#cbd5e1' },
  selected: { fill: '#dbeafe', stroke: '#2563eb', text: '#1d4ed8', dot: '#2563eb' },
};

const TYPE_ICONS = {
  router: '⬡',
  switch: '⊞',
  server: '▣',
  database: '⊕',
  workstation: '□',
  laptop: '⊟',
  printer: '▨',
  phone: '◯',
  camera: '◉',
  internet: '⊗',
  unregistered: '❓',
  default: '○',
};

function getNodeStatus(node) {
  if (node.status === 'OFFLINE') return 'offline';
  if ((node.risk_score || 0) >= 75 || node.status === 'CRITICAL' || node.status === 'COMPROMISED') return 'critical';
  if ((node.risk_score || 0) >= 40 || node.status === 'SUSPICIOUS') return 'warning';
  return 'normal';
}

function computeLayout(nodes) {
  const positioned = {};
  const levels = {
    internet: 0,
    router: 1,
    switch: 2,
    server: 3,
    workstation: 3,
    laptop: 3,
    printer: 3,
    phone: 3,
    mobile: 3,
    camera: 3,
    iot: 3,
    database: 4,
  };

  const byLevel = { 0: [], 1: [], 2: [], 3: [], 4: [] };
  nodes.forEach(n => {
    const rawType = (n.device_type || n.type || '').toLowerCase();
    const lvl = levels[rawType] !== undefined ? levels[rawType] : 3;
    byLevel[lvl].push(n);
  });

  const lvl3Count = byLevel[3].length;
  // Calculate grid wrapping for Level 3 to prevent any node overlap
  const rowsPerCol = lvl3Count <= 8 ? Math.max(1, lvl3Count) : Math.max(6, Math.min(10, Math.ceil(Math.sqrt(lvl3Count * 1.1))));
  const colsNeeded = Math.max(1, Math.ceil(lvl3Count / rowsPerCol));

  const yGap = lvl3Count > 25 ? 54 : 64;
  const xGap = lvl3Count > 25 ? 68 : 80;

  const totalHeight = Math.max(540, (rowsPerCol * yGap) + 120);
  const lvl3BaseX = 480;
  const dbX = lvl3BaseX + (colsNeeded * xGap) + 100;
  const totalWidth = Math.max(880, dbX + 100);

  const levelX = {
    0: 70,
    1: 200,
    2: 340,
    3: lvl3BaseX,
    4: dbX
  };

  [0, 1, 2, 4].forEach(lvl => {
    const ns = byLevel[lvl];
    const x = levelX[lvl];
    const count = ns.length;
    if (count === 1) {
      const key = ns[0].id ?? ns[0].name;
      const coords = { x, y: totalHeight / 2 };
      positioned[key] = coords;
      if (ns[0].id) positioned[ns[0].id] = coords;
      if (ns[0].name) positioned[ns[0].name] = coords;
    } else {
      ns.forEach((n, i) => {
        const key = n.id ?? n.name;
        const coords = { x, y: 70 + (i / Math.max(1, count - 1)) * (totalHeight - 140) };
        positioned[key] = coords;
        if (n.id) positioned[n.id] = coords;
        if (n.name) positioned[n.name] = coords;
      });
    }
  });

  // Level 3 grid placement (multi-column wrapping)
  byLevel[3].forEach((n, i) => {
    const key = n.id ?? n.name;
    let coords;
    if (lvl3Count <= 8) {
      coords = {
        x: lvl3BaseX,
        y: 80 + (i / Math.max(1, lvl3Count - 1)) * (totalHeight - 160)
      };
    } else {
      const col = Math.floor(i / rowsPerCol);
      const row = i % rowsPerCol;
      coords = {
        x: lvl3BaseX + col * xGap,
        y: 65 + row * yGap
      };
    }
    positioned[key] = coords;
    if (n.id) positioned[n.id] = coords;
    if (n.name) positioned[n.name] = coords;
  });

  return { positioned, totalWidth, totalHeight };
}

export default function TopologyGraph({ nodes = [], edges = [], selectedNode, onSelectNode, height = 520 }) {
  const svgRef = useRef(null);
  const [layout, setLayout] = useState({ positioned: {}, totalWidth: 880, totalHeight: 520 });
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(null);
  const [hovered, setHovered] = useState(null);

  useEffect(() => {
    setLayout(computeLayout(nodes));
  }, [nodes.map(n => n.id).join(','), nodes.length]);

  const { positioned: positions, totalWidth: W, totalHeight: H } = layout;

  const handleNodeClick = (node) => {
    onSelectNode && onSelectNode(node === selectedNode ? null : node);
  };

  const isDense = nodes.length > 25;
  const defaultRadius = isDense ? 16 : 22;

  const selectedId = selectedNode?.id || selectedNode?.device_id || selectedNode?.name || selectedNode?.device_name;

  const fitView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  return (
    <div className="topology-canvas" style={{ height, userSelect: 'none', position: 'relative' }}>
      {/* Toolbar */}
      <div style={{ position: 'absolute', top: 10, right: 10, display: 'flex', gap: 6, zIndex: 10 }}>
        <button onClick={() => setZoom(z => Math.min(z + 0.2, 2.5))} className="btn btn-secondary btn-sm" title="Zoom In"><ZoomIn size={13} /></button>
        <button onClick={() => setZoom(z => Math.max(z - 0.2, 0.4))} className="btn btn-secondary btn-sm" title="Zoom Out"><ZoomOut size={13} /></button>
        <button onClick={fitView} className="btn btn-secondary btn-sm" title="Fit to View">Fit</button>
        <button onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }} className="btn btn-secondary btn-sm" title="Reset"><RefreshCw size={13} /></button>
      </div>

      {/* Legend (Task 1: Differentiate structural links vs observed communication edges) */}
      <div style={{
        position: 'absolute', bottom: 10, left: 10,
        display: 'flex', gap: 10, fontSize: '0.65rem', color: '#475569', fontWeight: 600,
        zIndex: 10, flexWrap: 'wrap', background: 'rgba(255,255,255,0.92)',
        padding: '5px 10px', borderRadius: 6, border: '1px solid #cbd5e1', boxShadow: '0 1px 3px rgba(0,0,0,0.06)'
      }}>
        <span>🟢 Normal</span>
        <span>🟡 Warning</span>
        <span>🔴 Critical</span>
        <span>⚫ Offline</span>
        <span style={{ borderLeft: '1px solid #cbd5e1', paddingLeft: 8, color: '#64748b' }}>── Structural Link</span>
        <span style={{ color: '#6366f1' }}>- - - Observed Traffic</span>
      </div>

      <svg
        ref={svgRef}
        width="100%" height={H}
        viewBox={`${-pan.x / zoom} ${-pan.y / zoom} ${W / zoom} ${H / zoom}`}
        style={{ cursor: dragging ? 'grabbing' : 'grab', display: 'block' }}
        onWheel={(e) => {
          e.preventDefault();
          const factor = e.deltaY < 0 ? 1.1 : 0.9;
          setZoom(z => Math.max(0.35, Math.min(2.5, z * factor)));
        }}
        onMouseMove={(e) => {
          if (dragging === 'pan') {
            setPan(p => ({ x: p.x + e.movementX, y: p.y + e.movementY }));
          }
        }}
        onMouseDown={() => setDragging('pan')}
        onMouseUp={() => setDragging(null)}
        onMouseLeave={() => setDragging(null)}
      >
        <defs>
          <marker id="arrow-ng" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L9,3 z" fill="#94a3b8" />
          </marker>
          <marker id="arrow-obs" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L9,3 z" fill="#6366f1" />
          </marker>
          <marker id="arrow-sel" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L9,3 z" fill="#2563eb" />
          </marker>
        </defs>

        {/* Edges (Task 1: Show structural links and observed communication edges differently) */}
        {edges.map((edge, i) => {
          const src = positions[edge.source] || positions[edge.source_id];
          const tgt = positions[edge.target] || positions[edge.target_id];
          if (!src || !tgt) return null;
          const isSel = selectedId && (
            edge.source === selectedId || edge.target === selectedId ||
            edge.source_id === selectedId || edge.target_id === selectedId
          );
          const isObserved = edge.edge_type === 'observed' || (edge.port > 0 && edge.protocol !== 'ETHERNET');

          return (
            <g key={i}>
              <line
                x1={src.x} y1={src.y}
                x2={tgt.x} y2={tgt.y}
                stroke={isSel ? '#2563eb' : isObserved ? '#6366f1' : '#94a3b8'}
                strokeWidth={isSel ? 2.5 : isObserved ? 2 : 1.5}
                strokeDasharray={isObserved ? '5 4' : 'none'}
                markerEnd={isSel ? 'url(#arrow-sel)' : isObserved ? 'url(#arrow-obs)' : 'url(#arrow-ng)'}
                opacity={isSel ? 1 : isObserved ? 0.9 : 0.75}
              />
            </g>
          );
        })}

        {/* Nodes */}
        {nodes.map(node => {
          const pos = positions[node.id] || positions[node.name];
          if (!pos) return null;
          const status = getNodeStatus(node);
          const isSelected = selectedId && (node.id === selectedId || node.name === selectedId || node.device_name === selectedId);
          const colors = isSelected ? NODE_COLORS.selected : NODE_COLORS[status];
          const rawType = (node.device_type || node.type || 'workstation').toLowerCase();
          const icon = TYPE_ICONS[rawType] || TYPE_ICONS.default;
          const r = rawType === 'router' || rawType === 'switch' ? (isDense ? 20 : 26) : defaultRadius;
          const dName = node.device_name || node.name || 'Device';
          const dIp = node.ip_address || node.ip || '—';
          const isSuspicious = node.status === 'SUSPICIOUS' || (node.risk_score || 0) >= 40;
          const isCompromised = node.status === 'COMPROMISED' || (node.risk_score || 0) >= 75;

          return (
            <g
              key={node.id || node.name}
              data-testid="topology-node"
              data-node-name={dName}
              transform={`translate(${pos.x}, ${pos.y})`}
              onClick={() => handleNodeClick(node)}
              onMouseEnter={() => setHovered(node.id || node.name)}
              onMouseLeave={() => setHovered(null)}
              style={{ cursor: 'pointer' }}
            >
              {/* Task 7: Suspicious nodes text label badge */}
              {(isSuspicious || isCompromised) && (
                <g transform={`translate(0, ${-(r + 15)})`} data-testid="suspicious-badge">
                  <rect
                    x={-42}
                    y={-8}
                    width={84}
                    height={15}
                    rx={4}
                    fill={isCompromised ? '#fef2f2' : '#fef9c3'}
                    stroke={isCompromised ? '#ef4444' : '#eab308'}
                    strokeWidth={1}
                  />
                  <text
                    x={0}
                    y={3}
                    textAnchor="middle"
                    fontSize={8}
                    fontWeight="800"
                    fill={isCompromised ? '#b91c1c' : '#854d0e'}
                    style={{ userSelect: 'none' }}
                  >
                    {isCompromised ? '🚨 COMPROMISED' : '⚠️ SUSPICIOUS'}
                  </text>
                </g>
              )}

              {/* Shadow */}
              <circle cx={0} cy={2} r={r + 2} fill="rgba(0,0,0,0.08)" />

              {/* Node circle */}
              <circle
                cx={0} cy={0} r={r}
                fill={colors.fill}
                stroke={colors.stroke}
                strokeWidth={isSelected ? 2.5 : 1.5}
              />

              {/* Risk ring if elevated */}
              {(node.risk_score || 0) >= 40 && (
                <circle cx={0} cy={0} r={r + 4} fill="none"
                  stroke={status === 'critical' ? '#dc2626' : '#d97706'}
                  strokeWidth={1.5}
                  strokeDasharray="3 2"
                  opacity={0.7}
                />
              )}

              {/* Icon */}
              <text x={0} y={-3} textAnchor="middle" dominantBaseline="middle"
                fontSize={r * 0.75} fill={colors.text} style={{ userSelect: 'none', fontFamily: 'serif' }}>
                {icon}
              </text>

              {/* Status dot */}
              <circle cx={r - 4} cy={-(r - 4)} r={4} fill={colors.dot} stroke="white" strokeWidth={1.5} />

              {/* Label */}
              <text x={0} y={r + (isDense ? 11 : 14)} textAnchor="middle"
                fontSize={isDense ? 8 : 10} fill="#334155" fontWeight="600" style={{ userSelect: 'none' }}>
                {dName.length > (isDense ? 10 : 13) ? dName.slice(0, isDense ? 9 : 12) + '…' : dName}
              </text>
              <text x={0} y={r + (isDense ? 19 : 25)} textAnchor="middle"
                fontSize={isDense ? 7 : 8} fill="#94a3b8" style={{ userSelect: 'none' }}>
                {dIp}
              </text>

              {/* Hover tooltip */}
              {hovered === (node.id || node.name) && (
                <g transform={`translate(${r + 8}, -30)`} style={{ pointerEvents: 'none' }}>
                  <rect x={0} y={0} width={140} height={52} rx={6} fill="white" stroke="#e2e8f0" strokeWidth={1} filter="drop-shadow(0 2px 6px rgba(0,0,0,0.1))" />
                  <text x={8} y={16} fontSize={10} fill="#0f172a" fontWeight="700">{dName}</text>
                  <text x={8} y={29} fontSize={9} fill="#64748b">Risk: {node.risk_score ?? 0}/100</text>
                  <text x={8} y={42} fontSize={9} fill="#64748b">Status: {node.status || 'ONLINE'}</text>
                </g>
              )}
            </g>
          );
        })}
      </svg>

      {nodes.length === 0 && (
        <div className="empty-state" style={{ position: 'absolute', inset: 0, background: 'transparent' }}>
          <div className="empty-state-icon">🌐</div>
          <div className="empty-state-title">No network topology yet</div>
          <div className="empty-state-sub">Click "Sync Twin" to synchronize the virtual network topology.</div>
        </div>
      )}
    </div>
  );
}
