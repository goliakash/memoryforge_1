/**
 * HINDSIGHT ORGANIZATIONAL MEMORY - SYNAPTIC GRAPH VISUALIZER
 * Interactive HTML5 Canvas Force-Directed Knowledge Network
 */

class MemoryGraphVisualizer {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    
    this.nodes = [];
    this.links = [];
    this.nodeMap = new Map();
    
    this.width = this.canvas.clientWidth || 800;
    this.height = this.canvas.clientHeight || 500;
    this.scale = 1;
    this.panX = 0;
    this.panY = 0;
    
    this.hoveredNode = null;
    this.selectedNode = null;
    this.draggedNode = null;
    
    this.pulses = []; // Animated synaptic signals traveling along links
    this.animationFrame = null;
    
    this.initCanvas();
    this.bindEvents();
  }

  initCanvas() {
    const dpr = window.devicePixelRatio || 1;
    this.width = this.canvas.parentElement.clientWidth;
    this.height = this.canvas.parentElement.clientHeight || 520;
    this.canvas.width = this.width * dpr;
    this.canvas.height = this.height * dpr;
    this.ctx.scale(dpr, dpr);
  }

  loadData(graphData) {
    if (!graphData || !graphData.nodes) return;

    this.nodeMap.clear();
    const existingPos = new Map(this.nodes.map(n => [n.id, { x: n.x, y: n.y }]));

    this.nodes = graphData.nodes.map((n, i) => {
      const prev = existingPos.get(n.id);
      const angle = (i / graphData.nodes.length) * Math.PI * 2;
      const radius = 120 + Math.random() * 100;
      
      const node = {
        ...n,
        x: prev ? prev.x : (this.width / 2) + Math.cos(angle) * radius,
        y: prev ? prev.y : (this.height / 2) + Math.sin(angle) * radius,
        vx: 0,
        vy: 0,
        radius: this.getNodeRadius(n.type),
        color: this.getNodeColor(n.type),
      };
      this.nodeMap.set(n.id, node);
      return node;
    });

    this.links = graphData.links.map(l => ({
      ...l,
      sourceNode: this.nodeMap.get(l.source),
      targetNode: this.nodeMap.get(l.target),
    })).filter(l => l.sourceNode && l.targetNode);

    // Spawn synaptic transmission pulses
    this.pulses = [];
    for (let i = 0; i < Math.min(8, this.links.length); i++) {
      this.spawnPulse();
    }

    if (!this.animationFrame) {
      this.animate();
    }
  }

  spawnPulse() {
    if (this.links.length === 0) return;
    const link = this.links[Math.floor(Math.random() * this.links.length)];
    this.pulses.push({
      link: link,
      progress: Math.random(),
      speed: 0.005 + Math.random() * 0.008,
      color: '#00f0ff'
    });
  }

  getNodeRadius(type) {
    switch (type) {
      case 'INCIDENT': return 16;
      case 'ROOT_CAUSE': return 13;
      case 'CONTROL': return 14;
      case 'REMEDIATION': return 12;
      case 'EVIDENCE': return 11;
      default: return 12;
    }
  }

  getNodeColor(type) {
    switch (type) {
      case 'INCIDENT': return '#00c8ff';     // Cyber Cyan
      case 'ROOT_CAUSE': return '#c084fc';   // Violet
      case 'CONTROL': return '#00ff88';      // Emerald Green
      case 'REMEDIATION': return '#fbbf24';  // Amber
      case 'EVIDENCE': return '#38bdf8';     // Light Sky
      default: return '#94a3b8';
    }
  }

  updatePhysics() {
    const kRepel = 2200;
    const kSpring = 0.04;
    const springLength = 95;
    const damping = 0.88;

    // Node repulsion
    for (let i = 0; i < this.nodes.length; i++) {
      const n1 = this.nodes[i];
      for (let j = i + 1; j < this.nodes.length; j++) {
        const n2 = this.nodes[j];
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        if (dist < 280) {
          const force = kRepel / (dist * dist);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          n1.vx -= fx;
          n1.vy -= fy;
          n2.vx += fx;
          n2.vy += fy;
        }
      }
    }

    // Link spring attraction
    for (const link of this.links) {
      const s = link.sourceNode;
      const t = link.targetNode;
      const dx = t.x - s.x;
      const dy = t.y - s.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = (dist - springLength) * kSpring;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      s.vx += fx;
      s.vy += fy;
      t.vx -= fx;
      t.vy -= fy;
    }

    // Center gravitation and position update
    const centerX = this.width / 2;
    const centerY = this.height / 2;

    for (const node of this.nodes) {
      if (node === this.draggedNode) continue;

      // Gentle pull towards canvas center
      node.vx += (centerX - node.x) * 0.0015;
      node.vy += (centerY - node.y) * 0.0015;

      node.vx *= damping;
      node.vy *= damping;

      node.x += node.vx;
      node.y += node.vy;

      // Bounds
      node.x = Math.max(30, Math.min(this.width - 30, node.x));
      node.y = Math.max(30, Math.min(this.height - 30, node.y));
    }

    // Update synaptic transmission pulses
    for (let i = 0; i < this.pulses.length; i++) {
      const p = this.pulses[i];
      p.progress += p.speed;
      if (p.progress >= 1.0) {
        p.progress = 0;
        p.link = this.links[Math.floor(Math.random() * this.links.length)];
      }
    }
  }

  draw() {
    this.ctx.clearRect(0, 0, this.width, this.height);
    this.ctx.save();
    this.ctx.translate(this.panX, this.panY);
    this.ctx.scale(this.scale, this.scale);

    // 1. Draw Links
    for (const link of this.links) {
      const s = link.sourceNode;
      const t = link.targetNode;
      const isResembles = link.relationship === 'RESEMBLES';

      this.ctx.beginPath();
      this.ctx.moveTo(s.x, s.y);
      this.ctx.lineTo(t.x, t.y);

      if (isResembles) {
        this.ctx.setLineDash([5, 5]);
        this.ctx.strokeStyle = 'rgba(217, 70, 239, 0.6)';
        this.ctx.lineWidth = 2;
      } else {
        this.ctx.setLineDash([]);
        this.ctx.strokeStyle = 'rgba(0, 240, 255, 0.18)';
        this.ctx.lineWidth = 1.2;
      }
      this.ctx.stroke();
    }

    // 2. Draw Synaptic Transmission Pulses
    for (const p of this.pulses) {
      if (!p.link || !p.link.sourceNode || !p.link.targetNode) continue;
      const s = p.link.sourceNode;
      const t = p.link.targetNode;
      const px = s.x + (t.x - s.x) * p.progress;
      const py = s.y + (t.y - s.y) * p.progress;

      this.ctx.beginPath();
      this.ctx.arc(px, py, 3, 0, Math.PI * 2);
      this.ctx.fillStyle = p.color;
      this.ctx.shadowColor = p.color;
      this.ctx.shadowBlur = 8;
      this.ctx.fill();
      this.ctx.shadowBlur = 0;
    }

    // 3. Draw Nodes
    for (const node of this.nodes) {
      const isHovered = this.hoveredNode === node;
      const isSelected = this.selectedNode === node;

      // Glow halo on hover or select
      if (isHovered || isSelected) {
        this.ctx.beginPath();
        this.ctx.arc(node.x, node.y, node.radius + 6, 0, Math.PI * 2);
        this.ctx.fillStyle = isSelected ? 'rgba(217, 70, 239, 0.35)' : 'rgba(0, 240, 255, 0.25)';
        this.ctx.fill();
      }

      // Main Node Circle
      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      this.ctx.fillStyle = node.color;
      this.ctx.shadowColor = node.color;
      this.ctx.shadowBlur = isHovered ? 14 : 6;
      this.ctx.fill();
      this.ctx.shadowBlur = 0;

      // Inner subtle border
      this.ctx.lineWidth = 2;
      this.ctx.strokeStyle = '#07090e';
      this.ctx.stroke();

      // Node Label
      this.ctx.font = isHovered ? '600 11px Outfit, sans-serif' : '500 10px Outfit, sans-serif';
      this.ctx.fillStyle = isHovered ? '#ffffff' : '#94a3b8';
      this.ctx.textAlign = 'center';
      
      const labelText = node.label.length > 20 ? node.label.substring(0, 18) + '...' : node.label;
      this.ctx.fillText(labelText, node.x, node.y + node.radius + 13);
    }

    this.ctx.restore();
  }

  animate() {
    this.updatePhysics();
    this.draw();
    this.animationFrame = requestAnimationFrame(() => this.animate());
  }

  bindEvents() {
    let isDragging = false;
    let startX = 0;
    let startY = 0;

    window.addEventListener('resize', () => this.initCanvas());

    this.canvas.addEventListener('mousemove', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = (e.clientX - rect.left - this.panX) / this.scale;
      const mouseY = (e.clientY - rect.top - this.panY) / this.scale;

      if (this.draggedNode) {
        this.draggedNode.x = mouseX;
        this.draggedNode.y = mouseY;
        return;
      }

      let found = null;
      for (const node of this.nodes) {
        const dx = node.x - mouseX;
        const dy = node.y - mouseY;
        if (dx * dx + dy * dy <= (node.radius + 6) * (node.radius + 6)) {
          found = node;
          break;
        }
      }

      this.hoveredNode = found;
      this.canvas.style.cursor = found ? 'pointer' : 'default';
    });

    this.canvas.addEventListener('mousedown', (e) => {
      if (this.hoveredNode) {
        this.draggedNode = this.hoveredNode;
        this.selectedNode = this.hoveredNode;
        this.onNodeClick(this.hoveredNode);
      }
    });

    window.addEventListener('mouseup', () => {
      this.draggedNode = null;
    });

    // Zoom Buttons
    const btnZoomIn = document.getElementById('btnGraphZoomIn');
    const btnZoomOut = document.getElementById('btnGraphZoomOut');
    const btnReset = document.getElementById('btnGraphReset');

    if (btnZoomIn) btnZoomIn.addEventListener('click', () => { this.scale = Math.min(2.5, this.scale * 1.2); });
    if (btnZoomOut) btnZoomOut.addEventListener('click', () => { this.scale = Math.max(0.4, this.scale / 1.2); });
    if (btnReset) btnReset.addEventListener('click', () => {
      this.scale = 1;
      this.panX = 0;
      this.panY = 0;
    });
  }

  onNodeClick(node) {
    const detailBox = document.getElementById('graphNodeDetail');
    if (!detailBox) return;

    detailBox.innerHTML = `
      <div style="background: rgba(13, 20, 36, 0.95); border: 1px solid ${node.color}; padding: 1rem; border-radius: 8px;">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
          <span style="color: ${node.color}; font-size: 0.72rem; font-weight: 700; text-transform: uppercase;">${node.type} NODE</span>
          <span style="font-family: monospace; font-size: 0.75rem; color: #64748b;">${node.id}</span>
        </div>
        <div style="font-weight: 700; font-size: 1rem; color: #ffffff; margin-bottom: 0.4rem;">${node.label}</div>
        <div style="font-size: 0.82rem; color: #cbd5e1; line-height: 1.4;">
          ${Object.entries(node.details || {}).map(([k, v]) => `<div><strong>${k}:</strong> ${typeof v === 'object' ? JSON.stringify(v) : v}</div>`).join('')}
        </div>
      </div>
    `;
  }
}
