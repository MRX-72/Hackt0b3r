"use strict";
// Sentinel console. Everything that came from the network is written with textContent only.
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const h = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  };
  const pad = (n, w = 2) => String(n).padStart(w, "0");
  const hhmmss = (t) => { const d = new Date(t * 1000); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
  const stamp = (t) => { const d = new Date(t * 1000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${hhmmss(t)}`; };
  const num = (n) => Number(n).toLocaleString("en-US");
  const KNOWN = new Set(["tcp", "udp", "icmp"]);
  const MAX_ROWS = 300;
  const FLAG_MS = 60000;  // rows from a host stay red this long after its alert
  const state = { paused: false, flagged: new Map(), filter: "" };
  const isFlagged = (mac) => (state.flagged.get(mac) || 0) > Date.now();

  // Two clicks to do something destructive or outward-facing: the first arms the button, the
  // second (within 4 s) does it. Returns a function that disarms and resets the label.
  function twoStep(btn, idle, action) {
    let timer = null;
    const disarm = () => { clearTimeout(timer); btn.classList.remove("armed"); btn.textContent = idle(); };
    btn.addEventListener("click", () => {
      if (btn.classList.contains("armed")) { disarm(); action(); return; }
      btn.classList.add("armed"); btn.textContent = "CONFIRM?";
      timer = setTimeout(disarm, 4000);
    });
    return disarm;
  }
  async function post(path, body) {
    return fetch(path, {
      method: "POST", headers: { "Content-Type": "application/json", "X-Sentinel": "1" }, body: JSON.stringify(body),
    });
  }

  // ---------------------------------------------------------------------------- topology
  // Star around this machine (the gateway): one spoke per device, brighter = more recent traffic.
  const PRIVATE = /^(10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|fe80|fc|fd)/i;
  const LOOPBACK = /^(127\.|::1$)/;
  const SLOTS = 12, IDLE_MS = 90000, PORT_RING = 8;
  class Topology {
    constructor(canvas) {
      this.canvas = canvas; this.ctx = canvas.getContext("2d");
      this.nodes = new Map(); this.slots = new Array(SLOTS).fill(null); this.ports = new Map();
      this.self = { macs: new Set(), heat: 0 }; this.hidden = 0; this.dirty = true;
      new ResizeObserver(() => this.resize()).observe(canvas.parentElement);
      this.resize();
      setInterval(() => this.tick(), 500);
    }
    resize() {
      const r = this.canvas.parentElement.getBoundingClientRect(), dpr = window.devicePixelRatio || 1;
      this.w = r.width; this.h = r.height;
      this.canvas.width = Math.max(1, Math.round(r.width * dpr)); this.canvas.height = Math.max(1, Math.round(r.height * dpr));
      this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0); this.dirty = true;
    }
    slotFor(key) {
      if (key === "INTERNET") { this.slots[0] = this.slots[0] || key; return 0; }
      const free = this.slots.findIndex((v, i) => i > 0 && v === null);
      if (free < 0) return -1;
      this.slots[free] = key; return free;
    }
    touch(key, mac) {
      let n = this.nodes.get(key);
      if (!n) {
        const slot = this.slotFor(key);
        if (slot < 0) { this.hidden++; return null; }
        n = { key, slot, heat: 0, last: 0, macs: new Set() }; this.nodes.set(key, n);
      }
      n.heat += 1; n.last = Date.now(); if (mac) n.macs.add(mac);
      return n;
    }
    add(ev) {
      if (ev.k !== "f") return;
      const a = LOOPBACK.test(ev.s), b = LOOPBACK.test(ev.d);
      if (a && b) {  // traffic inside this machine: show which service ports are busy
        const port = (ev.sp || 0) > (ev.dp || 0) ? ev.dp : ev.sp;
        const p = this.ports.get(port) || { heat: 0, last: 0 };
        p.heat += 1; p.last = Date.now(); this.ports.set(port, p);
        this.self.heat += 1; this.self.macs.add(ev.m);
      } else {
        for (const [ip, mac] of [[ev.s, ev.m], [ev.d, null]]) {
          if (LOOPBACK.test(ip)) { this.self.heat += 1; if (mac) this.self.macs.add(mac); continue; }
          this.touch(PRIVATE.test(ip) ? ip : "INTERNET", mac);
        }
      }
      this.dirty = true;
    }
    tick() {
      const now = Date.now();
      for (const [key, n] of this.nodes) {
        n.heat *= 0.8;
        if (now - n.last > IDLE_MS) { this.slots[n.slot] = null; this.nodes.delete(key); this.dirty = true; }
      }
      for (const [port, p] of this.ports) {
        p.heat *= 0.8;
        if (now - p.last > 20000) { this.ports.delete(port); this.dirty = true; }
      }
      this.self.heat *= 0.8;
      if (this.dirty || this.nodes.size || this.ports.size) { this.draw(); this.dirty = false; }
      $("#topo-sub").textContent = `${this.nodes.size} device${this.nodes.size === 1 ? "" : "s"}`
        + (this.hidden ? ` (+${this.hidden} not shown)` : "");
    }
    flagged(macs) { return [...macs].some((m) => isFlagged(m)); }
    draw() {
      const g = this.ctx, w = this.w, h = this.h, cx = w / 2, cy = h / 2 + 4;
      const radius = Math.max(40, Math.min(w / 2 - 120, h / 2 - 46));
      g.clearRect(0, 0, w, h);
      g.font = "12px ui-monospace, Menlo, monospace"; g.textBaseline = "middle";
      const pos = (slot) => { const a = -Math.PI / 2 + (slot / SLOTS) * Math.PI * 2; return [cx + Math.cos(a) * radius, cy + Math.sin(a) * radius, a]; };
      for (const n of this.nodes.values()) {  // spokes first, so nodes sit on top
        const [x, y] = pos(n.slot), heat = Math.min(1, n.heat / 40);
        g.strokeStyle = heat > 0.02 ? `rgba(91,141,184,${0.28 + 0.6 * heat})` : "#14181c";
        g.lineWidth = 1 + 2 * heat; g.beginPath(); g.moveTo(cx, cy); g.lineTo(x, y); g.stroke();
      }
      g.lineWidth = 1;
      const bad = this.flagged(this.self.macs);
      const portList = [...this.ports.entries()].sort((a, b) => b[1].heat - a[1].heat).slice(0, PORT_RING);
      portList.forEach(([port, p], i) => {  // service ports of this machine, evenly spaced on a ring
        const a = -Math.PI / 2 + (i / PORT_RING) * Math.PI * 2, x = cx + Math.cos(a) * 54, y = cy + Math.sin(a) * 54;
        const on = Math.min(1, p.heat / 20);
        g.strokeStyle = "#14181c"; g.beginPath(); g.moveTo(cx, cy); g.lineTo(x, y); g.stroke();
        g.fillStyle = "#08090b"; g.fillRect(x - 5, y - 5, 10, 10);
        g.strokeStyle = on > 0.05 ? "#5b8db8" : "#3b4652"; g.strokeRect(x - 4.5, y - 4.5, 9, 9);
        if (on > 0.05) { g.fillStyle = "#5b8db8"; g.globalAlpha = 0.4 + 0.6 * on; g.fillRect(x - 2.5, y - 2.5, 5, 5); g.globalAlpha = 1; }
        g.fillStyle = on > 0.05 ? "#9fb4c7" : "#5d6772"; g.textAlign = Math.cos(a) > 0.3 ? "left" : Math.cos(a) < -0.3 ? "right" : "center";
        const lx = x + Math.cos(a) * 11, ly = y + Math.sin(a) * 11 + (Math.abs(Math.cos(a)) <= 0.3 ? Math.sin(a) * 4 : 0);
        g.fillText(":" + port, lx, ly);
      });
      g.fillStyle = bad ? "#2a1819" : "#0d1013"; g.strokeStyle = bad ? "#c4403f" : "#4b5864";
      g.fillRect(cx - 10, cy - 10, 20, 20); g.strokeRect(cx - 9.5, cy - 9.5, 19, 19);
      g.fillStyle = bad ? "#c4403f" : "#9aa7b4"; g.fillRect(cx - 3, cy - 3, 6, 6);
      g.textAlign = "center"; g.fillStyle = bad ? "#c4403f" : "#7b8794";
      g.fillText("THIS HOST", cx, cy + (portList.length ? 20 : 26));
      for (const n of this.nodes.values()) {
        const [x, y, a] = pos(n.slot), bad2 = this.flagged(n.macs), live = Date.now() - n.last < 1500;
        g.fillStyle = bad2 ? "#2a1819" : "#0d1013"; g.strokeStyle = bad2 ? "#c4403f" : live ? "#7f95aa" : "#3b4652";
        g.fillRect(x - 7, y - 7, 14, 14); g.strokeRect(x - 6.5, y - 6.5, 13, 13);
        g.fillStyle = bad2 ? "#c4403f" : "#9aa7b4";
        const right = Math.cos(a) > 0.35, left = Math.cos(a) < -0.35;
        g.textAlign = right ? "left" : left ? "right" : "center";
        g.fillText(n.key.length > 15 ? n.key.slice(0, 14) + "…" : n.key, x + (right ? 13 : left ? -13 : 0), y + (right || left ? 0 : Math.sin(a) > 0 ? 18 : -18));
      }
    }
  }

  // ---------------------------------------------------------------------------- rate chart
  class RateView {
    constructor(canvas) {
      this.canvas = canvas; this.ctx = canvas.getContext("2d"); this.buckets = new Array(60).fill(0);
      new ResizeObserver(() => this.resize()).observe(canvas.parentElement);
      this.resize();
      setInterval(() => { this.buckets.shift(); this.buckets.push(0); this.draw(); }, 1000);
    }
    resize() {
      const r = this.canvas.parentElement.getBoundingClientRect(), dpr = window.devicePixelRatio || 1;
      this.w = r.width; this.h = r.height;
      this.canvas.width = Math.max(1, Math.round(r.width * dpr)); this.canvas.height = Math.max(1, Math.round(r.height * dpr));
      this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0); this.draw();
    }
    add(n) { this.buckets[this.buckets.length - 1] += n; }
    draw() {
      const g = this.ctx, w = this.w, h = this.h, top = 18, bottom = h - 6, max = Math.max(10, ...this.buckets);
      g.clearRect(0, 0, w, h);
      g.strokeStyle = "#1c232a"; g.beginPath();
      for (let i = 0; i <= 3; i++) { const y = Math.round(top + ((bottom - top) * i) / 3) + 0.5; g.moveTo(0, y); g.lineTo(w, y); }
      g.stroke();
      const bw = (w - 52) / this.buckets.length;
      this.buckets.forEach((v, i) => {
        const bh = ((bottom - top) * v) / max;
        g.fillStyle = i === this.buckets.length - 1 ? "#8aa9c4" : "#5b8db8";
        g.fillRect(44 + i * bw, bottom - bh, Math.max(1, bw - 1), bh);
      });
      g.fillStyle = "#4d5762"; g.font = "10px ui-monospace, Menlo, monospace"; g.textAlign = "right";
      g.fillText(num(max), 38, top + 4); g.fillText("0", 38, bottom);
    }
  }

  // ---------------------------------------------------------------------------- live view
  const rate = new RateView($("#rate")), topo = new Topology($("#topo"));
  const body = $("#pkts tbody");

  const kind = (ev) => ev.k === "f" ? ev.p : ev.k;
  function packetRow(ev) {
    const tr = h("tr", isFlagged(ev.m) ? "flag fresh" : "fresh");
    const c = (text, cls) => tr.appendChild(h("td", cls, text));
    const ep = (ip, port) => (port ? `${ip}:${port}` : ip);
    c(hhmmss(ev.t));
    if (ev.k === "f") {
      c(ep(ev.s, ev.sp)); c(ep(ev.d, ev.dp)); c(ev.p.toUpperCase(), "p-" + (KNOWN.has(ev.p) ? ev.p : "other"));
      c(ev.f); c(num(ev.b), "r"); c(ev.q ? "dns? " + ev.q : "");
    } else if (ev.k === "arp") {
      c(ev.s); c(ev.d); c("ARP", "p-other"); c(""); c(""); c(ev.op === "request" ? "who-has" : "is-at");
    } else if (ev.k === "dhcp") {
      c(ev.s); c(""); c("DHCP", "p-other"); c(""); c(""); c(ev.m);
    } else {
      c(ev.s); c(""); c("MDNS", "p-other"); c(""); c(""); c(ev.n);
    }
    tr.dataset.k = tr.textContent.toLowerCase();
    tr.hidden = !matches(tr);
    return tr;
  }

  const matches = (tr) => !state.filter || tr.dataset.k.includes(state.filter);
  function countShown() {
    let n = 0;
    for (const tr of body.rows) if (!tr.hidden) n++;
    $("#p-count").textContent = `${n} shown`;
  }
  $("#p-filter").addEventListener("input", (e) => {
    state.filter = e.target.value.trim().toLowerCase();
    for (const tr of body.rows) tr.hidden = !matches(tr);
    countShown();
  });

  function onBatch(msg) {
    rate.add(msg.n);
    if (state.paused) return;
    const frag = document.createDocumentFragment();
    msg.events.forEach((ev) => { topo.add(ev); frag.prepend(packetRow(ev)); });
    body.prepend(frag);
    while (body.rows.length > MAX_ROWS) body.deleteRow(body.rows.length - 1);
    countShown();
  }

  const alerts = $("#alerts");
  function showNone() { if (!alerts.children.length) alerts.appendChild(h("div", "none", "NO ALERTS THIS SESSION")); }
  function addAlert(a) {
    const first = alerts.firstChild;
    if (first && first.className === "none") alerts.removeChild(first);
    state.flagged.set(a.mac, Date.now() + FLAG_MS);
    const row = h("div", "alert " + a.label);
    row.appendChild(h("span", "sev " + a.label, a.label));
    row.appendChild(h("span", "t", hhmmss(a.t)));
    const text = h("div");
    text.appendChild(h("span", "h", a.headline));
    text.appendChild(h("span", "c", a.chain.join(" > ") + "   " + a.incident));
    row.appendChild(text);
    row.addEventListener("click", () => { $("#f-text").value = a.incident; setLabel(""); show("history"); });
    alerts.prepend(row);
    while (alerts.children.length > 200) alerts.removeChild(alerts.lastChild);
    if (!$("#history").hidden) history.reload();
  }

  $("#clear").addEventListener("click", () => { alerts.replaceChildren(); showNone(); });
  $("#pause").addEventListener("click", togglePause);
  function togglePause() {
    state.paused = !state.paused;
    $("#pause").textContent = state.paused ? "RESUME" : "PAUSE";
    $("#pkts").classList.toggle("paused", state.paused);
  }

  function setStatus(s) {
    $("#s-cap").textContent = s.capture === "off" ? "OFF" : s.capture.toUpperCase();
    $("#s-pps").textContent = num(s.pps);
    $("#s-events").textContent = num(s.events);
    $("#s-crit").textContent = num(s.counts.CRITICAL); $("#s-high").textContent = num(s.counts.HIGH); $("#s-med").textContent = num(s.counts.MEDIUM);
    $("#h-db").textContent = "DB " + s.database;
    if (s.state !== "running") $("#s-cap").textContent = s.state.toUpperCase();
  }
  function link(ok, text) {
    $("#led").className = "led" + (ok ? "" : " off"); $("#s-link").textContent = text;
  }

  function connect() {
    const es = new EventSource("/api/stream");
    es.addEventListener("hello", (e) => {
      const m = JSON.parse(e.data); setStatus(m); link(true, "LIVE");
      alerts.replaceChildren(); showNone(); m.recent.forEach(addAlert);
    });
    es.addEventListener("batch", (e) => onBatch(JSON.parse(e.data)));
    es.addEventListener("alert", (e) => addAlert(JSON.parse(e.data)));
    es.addEventListener("status", (e) => setStatus(JSON.parse(e.data)));
    es.onerror = () => link(false, "RECONNECTING");
  }

  // ---------------------------------------------------------------------------- history view
  const history = (() => {
    const f = { label: "", range: "", source: "", text: "", offset: 0, limit: 100 };
    let rows = [], total = 0, selected = null, timer = null;
    const picked = new Set();
    const tbody = $("#hist tbody");

    function params(withPaging) {
      const q = new URLSearchParams();
      if (f.label) q.set("label", f.label);
      if (f.source) q.set("source", f.source);
      if (f.text) q.set("text", f.text);
      if (f.range) q.set("since", String(Date.now() / 1000 - Number(f.range)));
      if (withPaging) { q.set("limit", String(f.limit)); q.set("offset", String(f.offset)); }
      return q.toString();
    }

    function renderRows() {
      tbody.replaceChildren();
      rows.forEach((r) => {
        const tr = h("tr", r.id === selected ? "sel" : "");
        const box = h("input"), pick = h("td");
        box.type = "checkbox"; box.checked = picked.has(r.id);
        box.addEventListener("click", (e) => e.stopPropagation());
        box.addEventListener("change", () => { box.checked ? picked.add(r.id) : picked.delete(r.id); syncPicked(); });
        pick.appendChild(box);
        const sev = h("td"); sev.appendChild(h("span", "sev " + r.label, r.label)); 
        tr.append(pick, h("td", "", stamp(r.ts)), sev, h("td", "", r.detector), h("td", "", r.technique),
          h("td", "", r.host_ip), h("td", "", r.target_ip || ""), h("td", "", r.headline), h("td", "dim", r.source.toUpperCase()));
        tr.addEventListener("click", () => select(r.id));
        tbody.appendChild(tr);
      });
      $("#h-empty").hidden = rows.length > 0;
      $("#hist").hidden = rows.length === 0;
      const from = rows.length ? f.offset + 1 : 0;
      $("#h-range").textContent = `${from}-${f.offset + rows.length} OF ${num(total)}`;
      $("#prev").disabled = f.offset === 0; $("#next").disabled = f.offset + rows.length >= total;
    }

    async function removeIds(ids) {
      const res = await post("/api/history/delete", { ids });
      if (!res.ok) return;
      ids.forEach((id) => picked.delete(id));
      if (ids.includes(selected)) { selected = null; select(null); }
      syncPicked(); await reload();
    }
    const delBtn = $("#del"), delLabel = () => `DELETE SELECTED (${picked.size})`;
    const resetDel = twoStep(delBtn, delLabel, () => removeIds([...picked]));
    function syncPicked() {
      delBtn.hidden = picked.size === 0; resetDel();
      $("#pick-all").checked = rows.length > 0 && rows.every((r) => picked.has(r.id));
    }
    $("#pick-all").addEventListener("change", (e) => {
      rows.forEach((r) => (e.target.checked ? picked.add(r.id) : picked.delete(r.id)));
      renderRows(); syncPicked();
    });

    function setCounts(counts) {
      let all = 0;
      for (const k of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) { const n = counts[k] || 0; all += n; $("#c-" + k).textContent = num(n); }
      $("#c-all").textContent = num(all);
    }

    async function reload() {
      try {
        const res = await fetch("/api/history?" + params(true), { cache: "no-store" });
        if (!res.ok) return;
        const data = await res.json();
        rows = data.rows; total = data.total; setCounts(data.counts);
        for (const id of [...picked]) if (!rows.some((r) => r.id === id)) picked.delete(id);
        syncPicked();
        $("#export").href = "/api/history.csv?" + params(false);
        renderRows();
      } catch (_) { /* server restarting: the next reload will catch up */ }
    }

    function kv(parent, k, v) { parent.append(h("span", "k", k), h("span", "v", v)); }
    function select(id) {
      selected = id; renderRows();
      const r = rows.find((x) => x.id === id), d = $("#d-body");
      d.replaceChildren();
      if (!r) { d.appendChild(h("div", "empty", "SELECT AN ENTRY")); return; }
      const head = h("div", "d-head");
      head.append(h("span", "sev " + r.label, r.label), h("div", "d-title", r.headline));
      const grid = h("div", "d-grid");
      kv(grid, "TIME", stamp(r.ts)); kv(grid, "LOGGED", stamp(r.logged_at)); kv(grid, "SOURCE", r.source.toUpperCase());
      kv(grid, "DETECTOR", r.detector); kv(grid, "TECHNIQUE", r.technique); kv(grid, "DEVICE", `${r.host_ip}  ${r.host_mac}`);
      kv(grid, "TARGET", r.target_ip || "-"); kv(grid, "CHAIN", r.chain.join(" > "));
      kv(grid, "SCORE", r.score.toFixed(2)); kv(grid, "CONFIDENCE", r.confidence.toFixed(2)); kv(grid, "INCIDENT", r.incident_id);
      d.append(head, grid);
      for (const [k, v] of [["WHAT HAPPENED", r.what_happened], ["LIKELY CAUSE", r.likely_cause], ["SUGGESTED ACTION", r.action]]) {
        const sec = h("div", "d-sec"); sec.append(h("div", "k", k), h("p", "", v)); d.appendChild(sec);
      }
      const ev = h("div", "d-sec"), table = h("div", "d-ev");
      ev.appendChild(h("div", "k", "EVIDENCE"));
      Object.entries(r.evidence).sort().forEach(([k, v]) => { table.append(h("span", "", k), h("span", "", Number.isInteger(v) ? num(v) : v.toFixed(2))); });
      ev.appendChild(table); d.appendChild(ev);
      const act = h("div", "d-actions"), del = h("button", "ghost danger", "DELETE THIS ENTRY");
      twoStep(del, () => "DELETE THIS ENTRY", () => removeIds([r.id]));
      act.appendChild(del); d.appendChild(act);
    }

    function setLabelUi(v) {
      f.label = v; f.offset = 0;
      document.querySelectorAll("#f-label button").forEach((b) => b.classList.toggle("on", b.dataset.v === v));
    }
    document.querySelectorAll("#f-label button").forEach((b) => b.addEventListener("click", () => { setLabelUi(b.dataset.v); reload(); }));
    $("#f-range").addEventListener("change", (e) => { f.range = e.target.value; f.offset = 0; reload(); });
    $("#f-source").addEventListener("change", (e) => { f.source = e.target.value; f.offset = 0; reload(); });
    $("#f-text").addEventListener("input", (e) => { f.text = e.target.value.trim(); f.offset = 0; clearTimeout(timer); timer = setTimeout(reload, 250); });
    $("#reload").addEventListener("click", reload);
    $("#prev").addEventListener("click", () => { f.offset = Math.max(0, f.offset - f.limit); reload(); });
    $("#next").addEventListener("click", () => { f.offset += f.limit; reload(); });
    return { reload, setLabelUi, syncText: () => { f.text = $("#f-text").value.trim(); f.offset = 0; } };
  })();
  function setLabel(v) { history.setLabelUi(v); }

  // ---------------------------------------------------------------------------- tabs, keys
  function show(name) {
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("on", t.dataset.tab === name));
    document.querySelectorAll(".view").forEach((v) => { v.hidden = v.id !== name; });
    if (name === "history") { history.syncText(); history.reload(); }
    document.dispatchEvent(new CustomEvent("sentinel:tab", { detail: name }));
  }
  function openHistory(text) { $("#f-text").value = text; setLabel(""); show("history"); }
  window.sentinelUi = { $, h, stamp, hhmmss, num, twoStep, post, openHistory };
  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => show(t.dataset.tab)));
  document.addEventListener("keydown", (e) => {
    if (e.target.tagName === "INPUT" || e.target.tagName === "SELECT" || e.metaKey || e.ctrlKey) return;
    if (e.key === "1") show("live");
    else if (e.key === "2") show("history");
    else if (e.key === "3") show("notifications");
    else if (e.key === "4") show("devices");
    else if (e.key === "5") show("health");
    else if (e.key === "p") togglePause();
    else if (e.key === "/") { e.preventDefault(); if ($("#live").hidden) { show("history"); $("#f-text").focus(); } else $("#p-filter").focus(); }
  });
  setInterval(() => { if (!$("#history").hidden) history.reload(); }, 10000);

  showNone();
  connect();
})();
