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
  const COLOR = { tcp: "#5b8db8", udp: "#6a9a8e", icmp: "#b8993b", other: "#7b8794", flag: "#c4403f" };
  const PRIVATE = /^(10\.|192\.168\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|fe80|fc|fd|::1)/i;
  const MAX_ROWS = 140;
  const MAX_PARTICLES = 700;
  const FLIGHT_MS = 700;
  const state = { paused: false, flagged: new Set() };

  // ---------------------------------------------------------------------------- network view
  class NetView {
    constructor(canvas) {
      this.canvas = canvas; this.ctx = canvas.getContext("2d");
      this.nodes = new Map(); this.parts = []; this.edges = new Map(); this.w = 0; this.h = 0;
      new ResizeObserver(() => this.resize()).observe(canvas.parentElement);
      this.resize();
      requestAnimationFrame((t) => this.frame(t));
    }
    resize() {
      const r = this.canvas.parentElement.getBoundingClientRect(), dpr = window.devicePixelRatio || 1;
      this.w = r.width; this.h = r.height;
      this.canvas.width = Math.max(1, Math.round(r.width * dpr)); this.canvas.height = Math.max(1, Math.round(r.height * dpr));
      this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    place(key, i) {
      if (key === "INTERNET") return [0.8, -0.66];
      if (i === 0) return [0, 0];
      const a = i * 2.39996 + 0.5, r = Math.min(0.8, 0.36 + 0.14 * Math.sqrt(i));
      return [Math.cos(a) * r, Math.sin(a) * r * 0.85];
    }
    node(ip, mac) {
      const key = PRIVATE.test(ip) ? ip : "INTERNET";
      let n = this.nodes.get(key);
      if (!n) {
        n = { key, label: key, last: 0, macs: new Set(), sats: new Map(), pos: this.place(key, this.nodes.size) };
        this.nodes.set(key, n);
      }
      if (mac) n.macs.add(mac);
      return n;
    }
    xy(n) { return [this.w / 2 + n.pos[0] * (this.w / 2 - 80), this.h / 2 + n.pos[1] * (this.h / 2 - 54)]; }
    satSlot(n, port, now) {
      let s = n.sats.get(port);
      if (!s) {
        const used = new Set([...n.sats.values()].map((v) => v.slot));
        let slot = [...Array(10).keys()].find((i) => !used.has(i));
        if (slot === undefined) {
          const oldest = [...n.sats.entries()].sort((a, b) => a[1].last - b[1].last)[0];
          slot = oldest[1].slot; n.sats.delete(oldest[0]);
        }
        s = { slot, port, last: now }; n.sats.set(port, s);
      }
      s.last = now;
      return s;
    }
    satXY(n, s) {
      const [x, y] = this.xy(n), a = (s.slot / 10) * Math.PI * 2 - Math.PI / 2;
      return [x + Math.cos(a) * 62, y + Math.sin(a) * 62];
    }
    flagged(n) { return [...n.macs].some((m) => state.flagged.has(m)); }
    add(ev, delay) {
      if (ev.k !== "f") return;
      const now = performance.now(), a = this.node(ev.s, ev.m), b = this.node(ev.d);
      a.last = b.last = now;
      const flag = state.flagged.has(ev.m);
      const color = flag ? COLOR.flag : COLOR[ev.p] || COLOR.other;
      let from = { n: a }, to = { n: b };
      if (a === b) {  // traffic on one host: show it travelling to / from the service port
        const client = (ev.sp || 0) > (ev.dp || 0), port = client ? ev.dp : ev.sp;
        const s = this.satSlot(a, port || 0, now);
        if (client) to = { n: a, s }; else from = { n: a, s };
        if (client) from = { n: a }; else to = { n: a };
      } else {
        this.edges.set(a.key + ">" + b.key, now);
      }
      if (this.parts.length > MAX_PARTICLES) this.parts.splice(0, this.parts.length - MAX_PARTICLES);
      this.parts.push({ from, to, t0: now + delay, color });
    }
    pt(end) { return end.s ? this.satXY(end.n, end.s) : this.xy(end.n); }
    frame(now) {
      const g = this.ctx, w = this.w, h = this.h;
      g.clearRect(0, 0, w, h);
      g.strokeStyle = "#161b20"; g.lineWidth = 1; g.beginPath();
      for (let x = 0; x < w; x += 32) { g.moveTo(x + 0.5, 0); g.lineTo(x + 0.5, h); }
      for (let y = 0; y < h; y += 32) { g.moveTo(0, y + 0.5); g.lineTo(w, y + 0.5); }
      g.stroke();
      for (const [key, t] of this.edges) {
        const age = now - t;
        if (age > 6000) { this.edges.delete(key); continue; }
        const [ak, bk] = key.split(">"), a = this.nodes.get(ak), b = this.nodes.get(bk);
        const [x1, y1] = this.xy(a), [x2, y2] = this.xy(b);
        g.strokeStyle = `rgba(91,141,184,${0.38 * (1 - age / 6000)})`; g.beginPath(); g.moveTo(x1, y1); g.lineTo(x2, y2); g.stroke();
      }
      g.font = "10px ui-monospace, Menlo, monospace"; g.textAlign = "center";
      for (const n of this.nodes.values()) {
        const [x, y] = this.xy(n), bad = this.flagged(n), live = now - n.last < 500;
        for (const [port, s] of n.sats) {
          const age = now - s.last;
          if (age > 8000) { n.sats.delete(port); continue; }
          const [sx, sy] = this.satXY(n, s), on = age < 500;
          g.strokeStyle = on ? "#5b8db8" : "#2f3943"; g.strokeRect(sx - 4.5, sy - 4.5, 9, 9);
          if (on) { g.fillStyle = "#5b8db8"; g.fillRect(sx - 2, sy - 2, 4, 4); }
          g.fillStyle = on ? "#9fb4c7" : "#4d5762"; g.fillText(":" + port, sx, sy + (sy < y ? -9 : 17));
        }
        g.fillStyle = bad ? "#2a1819" : "#1b2127"; g.strokeStyle = bad ? "#c4403f" : "#3b4652";
        g.fillRect(x - 8, y - 8, 16, 16); g.strokeRect(x - 7.5, y - 7.5, 15, 15);
        if (live) { g.fillStyle = bad ? "#c4403f" : "#8a99a8"; g.fillRect(x - 3, y - 3, 6, 6); }
        g.fillStyle = bad ? "#c4403f" : "#7b8794"; g.fillText(n.label, x, y + 23);
      }
      this.parts = this.parts.filter((p) => now - p.t0 < FLIGHT_MS);
      for (const p of this.parts) {
        const k = (now - p.t0) / FLIGHT_MS;
        if (k < 0) continue;
        const [x1, y1] = this.pt(p.from), [x2, y2] = this.pt(p.to);
        const x = x1 + (x2 - x1) * k, y = y1 + (y2 - y1) * k, k0 = Math.max(0, k - 0.1);
        g.strokeStyle = p.color; g.globalAlpha = 0.45; g.beginPath();
        g.moveTo(x1 + (x2 - x1) * k0, y1 + (y2 - y1) * k0); g.lineTo(x, y); g.stroke();
        g.globalAlpha = 1; g.fillStyle = p.color; g.fillRect(x - 2, y - 2, 4, 4);
      }
      requestAnimationFrame((t) => this.frame(t));
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
  const net = new NetView($("#net")), rate = new RateView($("#rate"));
  const body = $("#pkts tbody");

  const kind = (ev) => ev.k === "f" ? ev.p : ev.k;
  function packetRow(ev) {
    const tr = h("tr", state.flagged.has(ev.m) ? "flag" : "");
    const c = (text, cls) => tr.appendChild(h("td", cls, text));
    const ep = (ip, port) => (port ? `${ip}:${port}` : ip);
    c(hhmmss(ev.t));
    if (ev.k === "f") {
      c(ep(ev.s, ev.sp)); c(ep(ev.d, ev.dp)); c(ev.p.toUpperCase(), "p-" + (COLOR[ev.p] ? ev.p : "other"));
      c(ev.f); c(num(ev.b), "r"); c(ev.q ? "dns? " + ev.q : "");
    } else if (ev.k === "arp") {
      c(ev.s); c(ev.d); c("ARP", "p-other"); c(""); c(""); c(ev.op === "request" ? "who-has" : "is-at");
    } else if (ev.k === "dhcp") {
      c(ev.s); c(""); c("DHCP", "p-other"); c(""); c(""); c(ev.m);
    } else {
      c(ev.s); c(""); c("MDNS", "p-other"); c(""); c(""); c(ev.n);
    }
    return tr;
  }

  function onBatch(msg) {
    rate.add(msg.n);
    if (state.paused) return;
    const gap = 100 / Math.max(1, msg.events.length), frag = document.createDocumentFragment();
    msg.events.forEach((ev, i) => { net.add(ev, i * gap); frag.prepend(packetRow(ev)); });
    body.prepend(frag);
    while (body.rows.length > MAX_ROWS) body.deleteRow(body.rows.length - 1);
  }

  const alerts = $("#alerts");
  function showNone() { if (!alerts.children.length) alerts.appendChild(h("div", "none", "NO ALERTS THIS SESSION")); }
  function addAlert(a) {
    const first = alerts.firstChild;
    if (first && first.className === "none") alerts.removeChild(first);
    state.flagged.add(a.mac);
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
    $("#net-sub").textContent = state.paused ? "paused" : "packets in flight";
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
        const sev = h("td"); sev.appendChild(h("span", "sev " + r.label, r.label)); 
        tr.append(h("td", "", stamp(r.ts)), sev, h("td", "", r.detector), h("td", "", r.technique),
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
    $("#live").hidden = name !== "live"; $("#history").hidden = name !== "history";
    if (name === "history") { history.syncText(); history.reload(); }
  }
  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => show(t.dataset.tab)));
  document.addEventListener("keydown", (e) => {
    if (e.target.tagName === "INPUT" || e.target.tagName === "SELECT" || e.metaKey || e.ctrlKey) return;
    if (e.key === "1") show("live");
    else if (e.key === "2") show("history");
    else if (e.key === "p") togglePause();
    else if (e.key === "/") { show("history"); e.preventDefault(); $("#f-text").focus(); }
  });
  setInterval(() => { if (!$("#history").hidden) history.reload(); }, 10000);

  showNone();
  connect();
})();
