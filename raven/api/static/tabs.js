"use strict";
// NOTIFICATIONS, DEVICES and HEALTH tabs. Text from the network or from files is only ever written
// with textContent (through h()); there is no HTML building anywhere in this file.
(() => {
  const { $, h, stamp, num, twoStep, post, openHistory } = window.ravenUi;
  const bytes = (n) => {
    if (n < 1024) return `${n} B`;
    const u = ["KB", "MB", "GB", "TB"]; let v = n / 1024, i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
  };
  const ago = (s) => (s < 90 ? `${Math.round(s)} s` : s < 5400 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`);
  const get = async (url) => { try { const r = await fetch(url, { cache: "no-store" }); return r.ok ? await r.json() : null; } catch (_) { return null; } };
  const tag = (cls, text) => h("span", "tag " + cls, text);
  const sev = (label) => (label ? h("span", "sev " + label, label) : h("span", "dim", "-"));
  const kv = (parent, k, v, cls) => { parent.append(h("span", "k", k)); const e = h("span", "v" + (cls ? " " + cls : ""), v); parent.append(e); return e; };
  const visible = (id) => !$("#" + id).hidden;
  const CHANNELS = ["slack", "discord", "telegram"];

  // ---------------------------------------------------------------------------- notifications
  const notifications = (() => {
    const f = { channel: "", status: "", offset: 0, limit: 100 };
    let rows = [], total = 0, selected = null, config = {};
    const testOut = {};  // last test result per channel, kept across refreshes
    const tbody = $("#ntab tbody");

    function cards(counts) {
      const box = $("#n-cards"); box.replaceChildren();
      const creds = config.credentials || {}, listed = new Set(config.channels || []);
      for (const ch of CHANNELS) {
        const c = counts[ch] || {}, card = h("div", "chan");
        const state = !creds[ch] ? ["NO CREDENTIALS", "off"] : !listed.has(ch) ? ["NOT IN CONFIG", "off"] : ["READY", "ok"];
        const head = h("div", "chan-head"); head.append(h("span", "chan-name", ch.toUpperCase()), tag(state[1], state[0]));
        const stats = h("div", "chan-stats");
        for (const k of ["sent", "failed", "skipped"]) { stats.append(h("span", "n " + k, num(c[k] || 0)), h("span", "l", k)); }
        const foot = h("div", "chan-foot"); foot.append(h("span", "dim", "last 24 h"));
        const btn = h("button", "ghost", "SEND TEST"), out = h("span", "dim chan-out", testOut[ch] || "");
        btn.disabled = !creds[ch];
        twoStep(btn, () => "SEND TEST", async () => {
          btn.disabled = true; testOut[ch] = out.textContent = "sending...";
          const res = await post("/api/notifications/test", { channel: ch });
          const j = await res.json().catch(() => ({}));
          testOut[ch] = out.textContent = res.ok ? `${j.status}: ${j.detail}` : j.error || "request refused";
          btn.disabled = false;
        });
        foot.append(btn);
        card.append(head, stats, foot, out);
        box.appendChild(card);
      }
      const armed = $("#n-armed");
      armed.textContent = !config.enabled ? "notifications are OFF in config.toml"
        : config.armed ? "ARMED: this run sends alerts" : "NOT ARMED: start with -n to send alerts";
      armed.className = "sub " + (config.enabled && config.armed ? "okc" : "warnc");
    }

    function render() {
      tbody.replaceChildren();
      rows.forEach((r) => {
        const tr = h("tr", r.id === selected ? "sel" : "");
        const st = h("td"); st.appendChild(tag(r.status, r.status.toUpperCase()));
        const sv = h("td"); sv.appendChild(sev(r.label));
        tr.append(h("td", "", stamp(r.ts)), h("td", "", r.channel), st, sv, h("td", "", r.headline || "(incident removed)"), h("td", "dim", r.error || ""));
        tr.addEventListener("click", () => select(r.id));
        tbody.appendChild(tr);
      });
      $("#n-empty").hidden = rows.length > 0; $("#ntab").hidden = rows.length === 0;
      $("#n-empty").textContent = !config.enabled ? "NOTIFICATIONS ARE OFF IN CONFIG.TOML"
        : !config.armed ? "NOTHING SENT: THIS RUN WAS STARTED WITHOUT -N" : "NO NOTIFICATIONS YET";
      const from = rows.length ? f.offset + 1 : 0;
      $("#n-range").textContent = `${from}-${f.offset + rows.length} OF ${num(total)}`;
      $("#n-prev").disabled = f.offset === 0; $("#n-next").disabled = f.offset + rows.length >= total;
    }

    function select(id) {
      selected = id; render();
      const r = rows.find((x) => x.id === id), d = $("#n-detail"); d.replaceChildren();
      if (!r) { d.appendChild(h("div", "empty", "SELECT A NOTIFICATION")); return; }
      const head = h("div", "d-head"); head.append(tag(r.status, r.status.toUpperCase()), h("div", "d-title", r.headline || "(incident removed)"));
      const grid = h("div", "d-grid");
      kv(grid, "TIME", stamp(r.ts)); kv(grid, "CHANNEL", r.channel); kv(grid, "SEVERITY", r.label || "-"); kv(grid, "INCIDENT", r.incident_id);
      d.append(head, grid);
      const why = h("div", "d-sec");
      why.append(h("div", "k", "OUTCOME"), h("p", "", r.error || (r.status === "sent" ? "Delivered." : "No detail recorded.")));
      d.appendChild(why);
      const act = h("div", "d-actions"), open = h("button", "ghost", "OPEN IN HISTORY");
      open.addEventListener("click", () => openHistory(r.incident_id));
      act.appendChild(open); d.appendChild(act);
    }

    async function reload() {
      const q = new URLSearchParams({ limit: String(f.limit), offset: String(f.offset) });
      if (f.channel) q.set("channel", f.channel); if (f.status) q.set("status", f.status);
      const data = await get("/api/notifications?" + q);
      if (!data) return;
      rows = data.rows; total = data.total; config = data.config || {};
      if (!document.querySelector("#n-cards .armed")) cards(data.counts || {});  // never rebuild a button mid-confirm
      render();
    }
    const seg = (id, key) => document.querySelectorAll(`#${id} button`).forEach((b) => b.addEventListener("click", () => {
      f[key] = b.dataset.v; f.offset = 0;
      document.querySelectorAll(`#${id} button`).forEach((x) => x.classList.toggle("on", x === b)); reload();
    }));
    seg("n-channel", "channel"); seg("n-status", "status");
    $("#n-reload").addEventListener("click", reload);
    $("#n-prev").addEventListener("click", () => { f.offset = Math.max(0, f.offset - f.limit); reload(); });
    $("#n-next").addEventListener("click", () => { f.offset += f.limit; reload(); });
    return { reload };
  })();

  // ---------------------------------------------------------------------------- devices
  const devices = (() => {
    let list = [], now = 0, selected = null, query = "";
    const tbody = $("#dtab tbody");
    const label = (d) => d.name || d.mac;
    const active = (d) => now - d.last_seen < 60;

    function render() {
      const q = query.toLowerCase();
      const shown = list.filter((d) => !q || [d.name || "", d.mac, ...d.ips].some((s) => s.toLowerCase().includes(q)));
      tbody.replaceChildren();
      shown.forEach((d) => {
        const tr = h("tr", d.mac === selected ? "sel" : "");
        const dot = h("td"); dot.appendChild(h("span", "dot " + (active(d) ? "on" : "")));
        const name = h("td"); name.append(h("span", d.name ? "bright" : "", label(d)), ...(d.name ? [h("span", "dim", "  " + d.mac)] : []));
        const al = h("td"); al.append(...(d.alerts ? [sev(d.worst_label), h("span", "dim", `  ${d.alerts}`)] : [h("span", "dim", "-")]));
        tr.append(dot, name, h("td", "", d.ips.slice(0, 3).join("  ") + (d.ips.length > 3 ? " ..." : "")), h("td", "", stamp(d.last_seen)),
          h("td", "r", num(d.packets)), h("td", "r", bytes(d.bytes_out)), h("td", "r", bytes(d.bytes_in)), al);
        tr.addEventListener("click", () => select(d.mac));
        tbody.appendChild(tr);
      });
      $("#dv-empty").hidden = shown.length > 0; $("#dtab").hidden = shown.length === 0;
      $("#dv-count").textContent = `${list.length} device${list.length === 1 ? "" : "s"}, ${list.filter(active).length} active`;
    }

    async function select(mac) {
      selected = mac; render();
      const d = $("#dv-detail"), data = await get("/api/devices/" + encodeURIComponent(mac));
      d.replaceChildren();
      if (!data) { d.appendChild(h("div", "empty", "NOT FOUND")); return; }
      const dev = data.device;
      const head = h("div", "d-head"); head.append(h("div", "d-title", label(dev)));
      const edit = h("div", "d-edit"), input = h("input"), save = h("button", "ghost", "SAVE NAME");
      input.type = "text"; input.maxLength = 40; input.placeholder = "NAME THIS DEVICE"; input.value = dev.name || "";
      input.spellcheck = false; input.autocomplete = "off";
      save.addEventListener("click", async () => {
        const res = await post("/api/devices/name", { mac: dev.mac, name: input.value });
        if (res.ok) { await reload(); select(dev.mac); }
      });
      edit.append(input, save); head.appendChild(edit);
      const grid = h("div", "d-grid");
      kv(grid, "MAC", dev.mac); kv(grid, "ADDRESSES", dev.ips.join("  ") || "-");
      kv(grid, "FIRST SEEN", stamp(dev.first_seen)); kv(grid, "LAST SEEN", stamp(dev.last_seen) + (active(dev) ? "  (active)" : ""));
      kv(grid, "PACKETS", num(dev.packets)); kv(grid, "SENT", bytes(dev.bytes_out)); kv(grid, "RECEIVED", bytes(dev.bytes_in));
      kv(grid, "ALERTS", String(dev.alerts));
      d.append(head, grid);
      const sec = h("div", "d-sec"); sec.appendChild(h("div", "k", "RECENT ALERTS"));
      if (!data.alerts.length) sec.appendChild(h("p", "dim", "None recorded for this device."));
      data.alerts.forEach((a) => {
        const row = h("div", "mini"); row.append(sev(a.label), h("span", "dim", stamp(a.ts)), h("span", "", a.headline));
        row.addEventListener("click", () => openHistory(a.incident_id));
        sec.appendChild(row);
      });
      d.appendChild(sec);
    }

    async function reload() {
      const data = await get("/api/devices");
      if (!data) return;
      list = data.devices; now = data.now; render();
    }
    $("#dv-text").addEventListener("input", (e) => { query = e.target.value.trim(); render(); });
    $("#dv-reload").addEventListener("click", reload);
    return { reload };
  })();

  // ---------------------------------------------------------------------------- health
  const health = (() => {
    function card(title, fill) {
      const c = h("section", "hcard"); c.appendChild(h("div", "hcard-title", title));
      const g = h("div", "d-grid"); fill(g); c.appendChild(g); return c;
    }
    const yes = (b) => (b ? "yes" : "no");
    function render(data) {
      const box = $("#hl-cards"); box.replaceChildren();
      const rt = data.runtime, cfg = data.config || {}, db = data.database;
      const quiet = rt.seconds_since_event, live = rt.capture.startsWith("live");
      box.append(
        card("CAPTURE", (g) => {
          kv(g, "SOURCE", rt.capture); kv(g, "STATE", rt.state, rt.state.startsWith("error") ? "badc" : rt.state === "running" ? "okc" : "");
          kv(g, "UP FOR", ago(rt.uptime)); kv(g, "EVENTS", num(rt.events));
          kv(g, "DROPPED", num(rt.dropped || 0), rt.dropped ? "warnc" : ""); kv(g, "PACKETS/S", String(rt.pps));
          kv(g, "LAST EVENT", quiet === null ? "none yet" : `${ago(quiet)} ago`, live && (quiet === null || quiet > 30) ? "warnc" : "");
          if (cfg.capture) kv(g, "CONFIG IFACE", `${cfg.capture.interface}  (snaplen ${cfg.capture.snaplen})`);
        }),
        card("DETECTORS", (g) => {
          const d = cfg.detectors || {};
          kv(g, "RULES", (d.rules || []).join(", ")); kv(g, "WINDOWS", (d.windows || []).join(", ") + " s");
          kv(g, "COOLDOWN", `${d.cooldown_seconds} s`); kv(g, "DNS N-GRAM", d.ngram_dns ? "on" : "off", d.ngram_dns ? "okc" : "dim");
          kv(g, "FOREST", d.isolation_forest ? `on  (threshold ${d.if_threshold}, warm-up ${d.if_min_samples})` : "off", d.isolation_forest ? "okc" : "dim");
        }),
        card("NOTIFICATIONS", (g) => {
          const n = cfg.notify || {};
          kv(g, "ENABLED", yes(n.enabled), n.enabled ? "okc" : "warnc"); kv(g, "ARMED (-n)", yes(n.armed), n.armed ? "okc" : "warnc");
          for (const ch of CHANNELS) kv(g, ch.toUpperCase(), `${(n.channels || []).includes(ch) ? "listed" : "not listed"}, ${(n.credentials || {})[ch] ? "credentials set" : "no credentials"}`);
          kv(g, "MIN SEVERITY", String(n.min_severity)); kv(g, "RATE LIMIT", `${n.max_per_minute} / min / channel`);
        }),
        card("LLM", (g) => {
          const l = cfg.llm || {};
          kv(g, "ENABLED", yes(l.enabled), l.enabled ? "okc" : "dim"); kv(g, "RUNTIME", l.runtime || "-"); kv(g, "MODEL", l.model || "-");
        }),
        card("DATABASE", (g) => {
          kv(g, "FILE", db.path); kv(g, "SIZE", bytes(db.bytes)); kv(g, "HISTORY", num(db.history)); kv(g, "ALERTS", num(db.alerts));
          kv(g, "DEVICES", num(db.devices)); kv(g, "DELIVERIES", num(db.deliveries));
          kv(g, "INCIDENTS", Object.entries(db.incidents).map(([k, v]) => `${v} ${k}`).join(", ") || "none");
        }),
        card("VERSION", (g) => { kv(g, "RAVEN", cfg.version || "-"); kv(g, "PYTHON", cfg.python || "-"); }),
      );
      const checks = h("section", "hcard wide"); checks.appendChild(h("div", "hcard-title", "CHECKS  (raven doctor)"));
      (data.checks || []).forEach((c) => {
        const row = h("div", "check"); row.append(h("span", "ck " + (c.ok ? "okc" : "badc"), c.ok ? "OK" : "FAIL"), h("span", "cname", c.name), h("span", "dim", c.detail));
        checks.appendChild(row);
      });
      box.appendChild(checks);
      $("#hl-sub").textContent = `refreshed ${stamp(Date.now() / 1000)}`;
    }
    async function reload() { const data = await get("/api/health"); if (data) render(data); }
    $("#hl-reload").addEventListener("click", reload);
    return { reload };
  })();

  // ---------------------------------------------------------------------------- wiring
  document.addEventListener("raven:tab", (e) => {
    if (e.detail === "notifications") notifications.reload();
    else if (e.detail === "devices") devices.reload();
    else if (e.detail === "health") health.reload();
  });
  setInterval(() => {
    if (visible("notifications")) notifications.reload();
    if (visible("devices")) devices.reload();
    if (visible("health")) health.reload();
  }, 5000);
})();
