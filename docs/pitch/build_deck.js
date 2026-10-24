// Builds Raven_Pitch.pptx. Setup: npm install pptxgenjs react react-dom react-icons sharp
// Run: node build_deck.js [outfile]   (screenshots: assets/live.png, assets/history_c.png)
// Every number on a slide comes from this repository's tests, docs/ABLATION.md, demo.md or the
// screenshots (a real run of `raven ui` against loopback attacks).
const path = require("path");
const pptxgen = require("pptxgenjs");
const React = require("react");
const RDS = require("react-dom/server");
const sharp = require("sharp");
const fa = require("react-icons/fa");

const T = {
  bg: "0D1013", bar: "0A0C0F", panel: "12161A", raise: "181D22", line: "232A31", line2: "2F3943",
  text: "CBD2D9", bright: "E6EAEE", dim: "7B8794", faint: "4D5762",
  crit: "C4403F", high: "C9702D", med: "B8993B", low: "4F86B3", ok: "5A9E84", tcp: "5B8DB8",
};
const SANS = "Calibri", MONO = "Courier New";

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.33 x 7.5 in
pres.title = "Raven: network security for places with no security team";
pres.author = "Raven";
pres.theme = { headFontFace: SANS, bodyFontFace: SANS };
const W = 13.33;

pres.defineSlideMaster({ title: "TITLE", background: { color: T.bg }, objects: [] });
pres.defineSlideMaster({
  title: "CONTENT",
  background: { color: T.bg },
  objects: [
    { rect: { x: 0, y: 7.1, w: W, h: 0.4, fill: { color: T.bar }, line: { color: T.bar, width: 0 } } },
    { rect: { x: 0.6, y: 7.17, w: 0.12, h: 0.12, fill: { color: T.crit }, line: { color: T.crit, width: 0 } } },
    { text: { text: "RAVEN", options: { x: 0.82, y: 7.1, w: 3, h: 0.28, fontFace: MONO, fontSize: 10, bold: true, color: T.dim, charSpacing: 4, margin: 0, valign: "middle" } } },
    {
      placeholder: {
        options: {
          name: "title", type: "title", x: 0.6, y: 0.62, w: 12.1, h: 0.95, fontFace: SANS,
          fontSize: 28, bold: true, color: T.bright, align: "left", valign: "top", margin: 0,
        },
        text: "",
      },
    },
  ],
  slideNumber: { x: 12.0, y: 7.1, w: 0.75, h: 0.28, fontFace: MONO, fontSize: 10, color: T.dim, align: "right" },
});

async function icon(Comp, color, size = 256) {
  const svg = RDS.renderToStaticMarkup(React.createElement(Comp, { color: "#" + color, size: String(size) }));
  return "image/png;base64," + (await sharp(Buffer.from(svg)).png().toBuffer()).toString("base64");
}
const text = (s, t, o) => s.addText(t, { isTextBox: true, margin: 0, fontFace: SANS, color: T.text, ...o });
const rect = (s, x, y, w, h, fill, line, name = "box") =>
  s.addShape(pres.ShapeType.rect, {
    x, y, w, h, fill: fill ? { color: fill } : { type: "none" },
    line: line ? { color: line, width: 1 } : { type: "none" }, objectName: name,
  });
const hline = (s, x, y, w, color = T.line2, width = 1) =>
  s.addShape(pres.ShapeType.line, { x, y, w, h: 0, line: { color, width }, objectName: "rule" });
const vline = (s, x, y, h, color = T.line2, width = 1) =>
  s.addShape(pres.ShapeType.line, { x, y, w: 0, h, line: { color, width }, objectName: "rule" });
const arrow = (s, x1, y, x2, color = T.faint) =>
  s.addShape(pres.ShapeType.line, { x: x1, y, w: x2 - x1, h: 0, line: { color, width: 2, endArrowType: "triangle" }, objectName: "arrow" });
let kickerCount = 0;
const kicker = (s, label) =>
  text(s, `${String(++kickerCount).padStart(2, "0")}  /  ${label}`, { x: 0.6, y: 0.3, w: 8, h: 0.28, fontFace: MONO, fontSize: 11, bold: true, color: T.crit, charSpacing: 3 });
const chip = (s, x, y, w, t, color, o = {}) => {
  rect(s, x, y, w, o.h || 0.3, null, color, "chip");
  text(s, t, { x, y, w, h: o.h || 0.3, fontFace: MONO, fontSize: o.size || 10, bold: true, color, align: "center", valign: "middle", charSpacing: 1 });
};
const iconBox = async (s, x, y, d, Comp, color) => {
  rect(s, x, y, d, d, T.raise, T.line2, "icon-box");
  const p = d * 0.27;
  s.addImage({ data: await icon(Comp, color), x: x + p, y: y + p, w: d - 2 * p, h: d - 2 * p, altText: "icon" });
};
const content = (title, notes) => {
  const s = pres.addSlide({ masterName: "CONTENT" });
  s.addText(title, { placeholder: "title" });
  s.addNotes(notes);
  return s;
};
const mono = (s, t, o) => text(s, t, { fontFace: MONO, ...o });
const label = (s, t, x, y, w, color = T.dim) =>
  mono(s, t, { x, y, w, h: 0.25, fontSize: 10, bold: true, color, charSpacing: 3 });
const panelTitle = (s, t, x, y, w) => {
  rect(s, x, y, w, 0.4, T.bar, T.line, "panel-head");
  label(s, t, x + 0.15, y + 0.08, w - 0.3);
};

async function build() {
  // ------------------------------------------------------------------ 1 title
  {
    const s = pres.addSlide({ masterName: "TITLE" });
    s.addNotes(
      "One-line promise: network security for places with no security team. Raven runs on the gateway Mac, " +
        "spots port scans, password guessing, malware check-ins, DNS tunnelling and unusual traffic, explains each in " +
        "plain English, keeps a permanent history, and can alert Slack, Discord or Telegram. The screenshot on the right is the real console during a live test on this Mac."
    );
    rect(s, 0, 0, 0.18, 7.5, T.crit, null, "edge");
    mono(s, "NETWORK ANOMALY DETECTOR", { x: 0.7, y: 1.2, w: 6, h: 0.3, fontSize: 12, bold: true, color: T.crit, charSpacing: 5 });
    text(s, "Raven", { x: 0.7, y: 1.6, w: 6, h: 1.2, fontSize: 66, bold: true, color: T.bright, valign: "middle" });
    text(s, "Network security for places with no security team.", { x: 0.7, y: 2.9, w: 5.6, h: 1.1, fontSize: 24, color: T.text });
    const stats = [["5", "detectors, rules and\nstatistical"], ["462", "automated tests"], ["4 / 4", "live attacks caught\non loopback"]];
    stats.forEach(([n, l], i) => {
      const x = 0.7 + i * 1.95;
      hline(s, x, 4.75, 1.7, T.line2);
      mono(s, n, { x, y: 4.85, w: 1.8, h: 0.55, fontSize: 28, bold: true, color: T.bright });
      text(s, l, { x, y: 5.45, w: 1.8, h: 0.6, fontSize: 12, color: T.dim });
    });
    mono(s, "Runs on one Mac. No cloud. No account.", { x: 0.7, y: 6.6, w: 6, h: 0.3, fontSize: 12, color: T.dim });
    const iw = 6.6, ih = iw * (1620 / 2880);
    rect(s, 6.45, 1.8 - 0.06, iw + 0.12, ih + 0.12, T.panel, T.line2, "frame");
    s.addImage({ path: path.join(__dirname, "assets", "live.png"), x: 6.51, y: 1.8, w: iw, h: ih, altText: "Raven web console during a live port scan, brute force, beacon and DNS tunnel test: packet monitor, topology and four CRITICAL alerts" });
    mono(s, "REAL SCREENSHOT: LIVE TEST ON LOOPBACK", { x: 6.51, y: 1.8 + ih + 0.2, w: 6.6, h: 0.25, fontSize: 9, color: T.faint, charSpacing: 2 });
  }

  // ------------------------------------------------------------------ 2 problem
  {
    const s = content(
      "Small networks are attacked like big ones. Nobody is watching.",
      "The gap: schools, labs and small offices have the same exposure as a company but no analyst. Commercial tools assume a security operations team. " +
        "The attacks themselves are quiet: a scan or a password-guessing run looks like background noise unless something is counting."
    );
    kicker(s, "THE PROBLEM");
    const cards = [
      [fa.FaUserSlash, "No security staff", "The admin is also the help desk. Nobody reads logs, and alerts nobody understands get ignored."],
      [fa.FaServer, "Tools built for a SOC", "Enterprise products assume analysts, a SIEM and a budget. Small teams cannot run or afford them."],
      [fa.FaEyeSlash, "Attacks hide in the noise", "A port scan, password guessing, a malware check-in: each is ordinary traffic until something counts it."],
    ];
    for (let i = 0; i < 3; i++) {
      const x = 0.6 + i * 4.1;
      rect(s, x, 1.95, 3.85, 3.3, T.panel, T.line, "card");
      await iconBox(s, x + 0.3, 2.25, 0.7, cards[i][0], T.crit);
      text(s, cards[i][1], { x: x + 0.3, y: 3.2, w: 3.3, h: 0.5, fontSize: 21, bold: true, color: T.bright });
      text(s, cards[i][2], { x: x + 0.3, y: 3.8, w: 3.3, h: 1.3, fontSize: 15, color: T.text, valign: "top" });
    }
    rect(s, 0.6, 5.6, 12.15, 1.0, T.raise, T.line2, "callout");
    rect(s, 0.6, 5.6, 0.08, 1.0, T.crit, null, "callout-edge");
    text(s, [{ text: "Raven: ", options: { bold: true, color: T.bright } }, { text: "one Mac on the gateway watches the traffic, spots the pattern, and tells the admin in plain English what to look at.", options: {} }],
      { x: 0.95, y: 5.6, w: 11.5, h: 1.0, fontSize: 19, valign: "middle" });
  }

  // ------------------------------------------------------------------ 3 how it works
  {
    const s = content(
      "From packets to a plain-English alert in six steps",
      "Walk left to right. Capture reads packets with tcpdump or from a pcap file. Features count what each device did over 10 seconds, 5 minutes and 1 hour. " +
        "Detectors are readable rules plus two statistical models. Correlation joins alerts on the same device into an incident with an attack chain. " +
        "Explain writes the words, from templates or an optional local LLM. Deliver puts it on the console, in the permanent history and, if enabled, on Slack, Discord or Telegram. " +
        "The key safety point is the bar underneath: network text is sanitised before any LLM, alert or screen sees it."
    );
    kicker(s, "HOW IT WORKS");
    const steps = [
      [fa.FaNetworkWired, "Capture", "tcpdump live,\nor any .pcap"],
      [fa.FaChartBar, "Count", "per device over\n10 s, 5 min, 1 h"],
      [fa.FaSearch, "Detect", "5 detectors:\nrules + 2 models"],
      [fa.FaLink, "Correlate", "one incident per\ndevice, ATT&CK chain"],
      [fa.FaCommentDots, "Explain", "plain English:\ntemplates or local LLM"],
      [fa.FaBell, "Deliver", "console, history,\nSlack/Discord/Telegram"],
    ];
    const bw = 1.78, gap = 0.294;
    for (let i = 0; i < steps.length; i++) {
      const x = 0.6 + i * (bw + gap);
      rect(s, x, 2.0, bw, 2.3, T.panel, T.line, "step");
      await iconBox(s, x + 0.2, 2.2, 0.62, steps[i][0], i === 2 ? T.crit : T.tcp);
      mono(s, String(i + 1), { x: x + bw - 0.5, y: 2.22, w: 0.3, h: 0.3, fontSize: 14, bold: true, color: T.faint, align: "right" });
      text(s, steps[i][1], { x: x + 0.2, y: 3.05, w: bw - 0.3, h: 0.4, fontSize: 18, bold: true, color: T.bright });
      text(s, steps[i][2], { x: x + 0.2, y: 3.5, w: bw - 0.3, h: 0.9, fontSize: 12.5, color: T.dim, valign: "top" });
      if (i < steps.length - 1) arrow(s, x + bw + 0.03, 3.27, x + bw + gap - 0.03);
    }
    // gate bar under explain + deliver
    const gx = 0.6 + 4 * (bw + gap);
    rect(s, 0.6, 4.95, 12.15, 0.75, T.raise, T.line2, "gate");
    rect(s, 0.6, 4.95, 0.08, 0.75, T.high, null, "gate-edge");
    text(s, [{ text: "Sanitiser gate:  ", options: { bold: true, color: T.high } }, { text: "DNS names and hostnames come from the network, so they are treated as hostile. They are cleaned before any LLM, notification or screen sees them, and the console only ever shows them as plain text.", options: {} }],
      { x: 0.95, y: 4.95, w: 11.6, h: 0.75, fontSize: 14, valign: "middle" });
    rect(s, 0.6, 5.95, 12.15, 0.75, T.raise, T.line2, "gate2");
    rect(s, 0.6, 5.95, 0.08, 0.75, T.ok, null, "gate2-edge");
    text(s, [{ text: "LLMs never decide:  ", options: { bold: true, color: T.ok } }, { text: "detection is rules and statistics. A local model, if you turn one on, only rewrites the wording, and its output is fact-checked against the evidence.", options: {} }],
      { x: 0.95, y: 5.95, w: 11.6, h: 0.75, fontSize: 14, valign: "middle" });
  }

  // ------------------------------------------------------------------ 4 detectors
  {
    const s = content(
      "Five detectors, each tied to an ATT&CK technique",
      "Each card shows what the detector looks for and the real evidence recorded in the live loopback test (numbers from demo.md and docs/ABLATION.md). " +
        "The first four are rules with thresholds you can read and tune. The fifth, unusual behaviour, is statistical and says only 'unusual', never a named attack."
    );
    kicker(s, "WHAT IT DETECTS");
    const d = [
      ["Port scan", "T1046", T.crit, "One device probing many ports or hosts, fast or slow.", "400 ports in about 1 s, 99.75% failed"],
      ["Brute force", "T1110", T.crit, "Many connections to SSH, RDP, SMB or FTP that mostly complete.", "21 logins to port 2222, all completed"],
      ["Beaconing", "T1071.001", T.crit, "One server contacted at suspiciously regular intervals.", "13 check-ins every 1.0003 s, jitter 0.2%"],
      ["DNS tunnelling", "T1071.004", T.crit, "Long, random-looking lookups under one domain. An n-gram model scores how random the names look.", "14 TXT lookups, 67 characters, 4.5 bits/char"],
      ["Unusual behaviour", "statistical", T.med, "An Isolation Forest learns your network's normal, then flags volume far beyond it.", "bulk upload: bytes_out 263x the baseline"],
    ];
    const pos = [[0.6, 1.8], [4.7, 1.8], [8.8, 1.8], [0.6, 4.35], [4.7, 4.35]];
    d.forEach(([name, tech, color, what, ev], i) => {
      const [x, y] = pos[i];
      rect(s, x, y, 3.95, 2.35, T.panel, T.line, "card");
      rect(s, x, y, 3.95, 0.07, color, null, "card-top");
      text(s, name, { x: x + 0.25, y: y + 0.25, w: 2.3, h: 0.4, fontSize: 19, bold: true, color: T.bright });
      chip(s, x + 2.6, y + 0.3, 1.15, tech, i === 4 ? T.med : T.dim);
      text(s, what, { x: x + 0.25, y: y + 0.8, w: 3.5, h: 0.85, fontSize: 13, color: T.text, valign: "top" });
      hline(s, x + 0.25, y + 1.68, 3.45, T.line);
      mono(s, ev, { x: x + 0.25, y: y + 1.76, w: 3.5, h: 0.5, fontSize: 11, color: T.tcp, valign: "top" });
    });
    // legend card in the last slot
    rect(s, 8.8, 4.35, 3.95, 2.35, null, T.line2, "note");
    label(s, "WHY THE STATISTICAL ONE IS CAPPED", 9.05, 4.55, 3.5, T.med);
    text(s, "It only knows \"unusual\", not \"attack\". Its alerts are capped at MEDIUM, carry no ATT&CK technique, and are hidden while a named attack is already active on that device.", { x: 9.05, y: 4.95, w: 3.5, h: 1.6, fontSize: 13, color: T.text, valign: "top" });
  }

  // ------------------------------------------------------------------ 5 live console
  {
    const s = content(
      "A local console that shows what is happening, now",
      "This is a real screenshot, not a mock-up: the console during the live loopback test with all four attacks run. " +
        "1: the packet monitor, newest first, filterable; packets from a flagged device turn red for a minute. 2: topology around this host, with service ports as small boxes, so a scan shows up as ports lighting up. " +
        "3: the alert stack, every CRITICAL stays visible. 4: packets per second. It listens on 127.0.0.1 only, with a one-time token."
    );
    kicker(s, "THE LIVE CONSOLE");
    const iw = 8.3, ih = iw * (1620 / 2880);
    rect(s, 0.6 - 0.05, 1.75 - 0.05, iw + 0.1, ih + 0.1, T.panel, T.line2, "frame");
    s.addImage({ path: path.join(__dirname, "assets", "live.png"), x: 0.6, y: 1.75, w: iw, h: ih, altText: "Live tab of the Raven console" });
    // numbered markers on the screenshot (coordinates are fractions of the image)
    const mk = [[0.215, 0.077], [0.975, 0.077], [0.975, 0.505], [0.2, 0.845]];
    mk.forEach(([fx, fy], i) => {
      const cx = 0.6 + fx * iw, cy = 1.75 + fy * ih;
      rect(s, cx - 0.17, cy - 0.17, 0.34, 0.34, T.crit, T.bg, "marker");
      mono(s, String(i + 1), { x: cx - 0.17, y: cy - 0.17, w: 0.34, h: 0.34, fontSize: 12, bold: true, color: "FFFFFF", align: "center", valign: "middle" });
    });
    const items = [
      ["Packet monitor", "Every packet event, newest first, with a filter box. A flagged device shows red for a minute."],
      ["Network topology", "This host in the middle, devices around it, service ports as small boxes. A scan lights up the ports."],
      ["Alert stack", "Every CRITICAL stays on screen with its headline and ATT&CK chain."],
      ["Packets per second", "The last 60 seconds, so a burst stands out."],
    ];
    items.forEach(([h, b], i) => {
      const y = 1.75 + i * 1.18;
      rect(s, 9.3, y + 0.03, 0.34, 0.34, T.crit, null, "marker");
      mono(s, String(i + 1), { x: 9.3, y: y + 0.03, w: 0.34, h: 0.34, fontSize: 12, bold: true, color: "FFFFFF", align: "center", valign: "middle" });
      text(s, h, { x: 9.8, y, w: 3.0, h: 0.4, fontSize: 16, bold: true, color: T.bright });
      text(s, b, { x: 9.8, y: y + 0.4, w: 3.0, h: 0.75, fontSize: 12, color: T.dim, valign: "top" });
    });
    mono(s, "Listens on 127.0.0.1 only. Token needed once. Strict content-security policy.", { x: 0.6, y: 6.55, w: 12, h: 0.3, fontSize: 11, color: T.faint });
  }

  // ------------------------------------------------------------------ 6 history
  {
    const s = content(
      "A permanent history you can search, export and clean up",
      "Every detection is written to a SQLite database in the user's folder, so it survives restarts. The History tab filters by severity, time and source, searches headline, address, technique or incident id, " +
        "opens the full explanation and the numbers behind it, exports CSV, and deletes chosen entries (two clicks to confirm, each deletion recorded in an audit log). The same data is available in the terminal with 'raven history'."
    );
    kicker(s, "THE HISTORY");
    const iw = 8.75, ih = iw * (1620 / 2880);
    rect(s, 0.55, 1.7, iw + 0.1, ih + 0.1, T.panel, T.line2, "frame");
    s.addImage({ path: path.join(__dirname, "assets", "history.png"), x: 0.6, y: 1.75, w: iw, h: ih, altText: "History tab with four CRITICAL detections and the detail pane open on a beaconing alert" });
    const pts = [
      ["Survives restarts", "SQLite in ~/.raven. The same history from any folder."],
      ["Find anything", "Filter by severity, time, source. Search headline, IP, technique or incident."],
      ["See why", "Plain-English explanation plus the numbers that triggered it."],
      ["Take it with you", "CSV export, or raven history --json for scripts."],
      ["Stay in control", "Delete chosen entries; every deletion is audited."],
    ];
    pts.forEach(([h, b], i) => {
      const y = 1.7 + i * 0.98;
      vline(s, 9.65, y, 0.8, T.crit, 2);
      text(s, h, { x: 9.9, y, w: 2.9, h: 0.35, fontSize: 15, bold: true, color: T.bright });
      text(s, b, { x: 9.9, y: y + 0.35, w: 2.9, h: 0.5, fontSize: 11.5, color: T.dim, valign: "top" });
    });
  }

  // ------------------------------------------------------------------ console tabs with screenshots
  const shotSlide = async (title, notes, label, file, alt, points) => {
    const s = content(title, notes);
    kicker(s, label);
    const iw = 8.75, ih = iw * (1620 / 2880);
    rect(s, 0.55, 1.7, iw + 0.1, ih + 0.1, T.panel, T.line2, "frame");
    s.addImage({ path: path.join(__dirname, "assets", file), x: 0.6, y: 1.75, w: iw, h: ih, altText: alt });
    points.forEach(([h, b], i) => {
      const y = 1.7 + i * 0.98;
      vline(s, 9.65, y, 0.8, T.crit, 2);
      text(s, h, { x: 9.9, y, w: 2.9, h: 0.35, fontSize: 15, bold: true, color: T.bright });
      text(s, b, { x: 9.9, y: y + 0.35, w: 2.9, h: 0.55, fontSize: 11.5, color: T.dim, valign: "top" });
    });
    return s;
  };
  await shotSlide(
    "Know what was sent, and what failed",
    "The Notifications tab shows the three channels with their state: ready, no credentials, or not listed in the config, and sent, failed and skipped counts for the last 24 hours. " +
      "The banner says whether this run is armed: alerts only go out when the run was started with the notify flag and notifications are enabled. Below is the delivery log: every attempt with the headline and severity it carried and, for a failure, a short reason such as HTTP 500, never a URL or a token. " +
      "The test button sends one clearly marked sample message to the real channel after a second click, so you can prove delivery before an attack happens. In this screenshot the notification transport was a fake that failed one Slack message on purpose to show a failure row, so nothing was sent anywhere.",
    "NOTIFICATIONS", "notifications.png",
    "Notifications tab: three channel cards with counts, the armed banner and a delivery log with one failed row",
    [
      ["Channel status", "Ready, no credentials or not in config, with 24 h counts."],
      ["Armed or not", "A banner says whether this run will actually send alerts."],
      ["A log of every send", "Headline, severity and, for failures, the reason."],
      ["Prove delivery", "SEND TEST sends one marked message, after a second click."],
      ["Nothing sensitive", "Reasons never contain URLs or tokens."],
    ]
  );
  await shotSlide(
    "Every device, with its alert record",
    "The Devices tab is the inventory of what the capture has seen, by MAC address: addresses, last seen, packets, bytes sent and received, and how many alerts each device has with the worst severity. " +
      "It is stored in the database, so it survives restarts. Select a device to see its recent alerts and give it a name; names are typed by the admin and never taken from network data. " +
      "Broadcast and multicast addresses are not devices and are skipped. One limit: a device is a MAC, so machines behind a router show up as the router.",
    "DEVICES", "devices.png",
    "Devices tab: eight devices, one named Lab laptop with four CRITICAL alerts and its detail pane",
    [
      ["What the capture has seen", "By MAC: addresses, last seen, packets, bytes in and out."],
      ["Survives restarts", "Stored in the database, not just in memory."],
      ["Alerts per device", "Worst severity and recent alerts; click to open in History."],
      ["Name it", "Your label, saved and audited, never from network data."],
      ["No noise", "Broadcast and multicast addresses are left out."],
    ]
  );
  await shotSlide(
    "Is it healthy? One page answers",
    "The Health tab answers whether the capture is alive and how the run is set up. Capture shows the source, state, uptime and how long ago the last packet arrived, in amber if a live capture has been silent. " +
      "Detectors lists the rules, windows, cooldown and the two statistical models with their thresholds. Notifications and the LLM show setup, with credentials only as set or not set. " +
      "Database shows size and counts. Underneath are the same checks as the doctor command, including whether the LLM server has the model, refreshed every few seconds.",
    "HEALTH", "health.png",
    "Health tab: capture, detectors, notifications, LLM, database and version cards with the doctor checks listed below",
    [
      ["Is capture alive", "Source, state, uptime and the age of the last packet."],
      ["What is switched on", "Rules, windows, thresholds and both statistical models."],
      ["Setup at a glance", "Alerts armed? Which LLM model? Credentials: set or not."],
      ["The database", "Size and counts of history, devices and deliveries."],
      ["Checks built in", "The same checks as raven doctor, refreshed live."],
    ]
  );

  // ------------------------------------------------------------------ 7 windows
  {
    const s = content(
      "Fast attacks and slow ones: three clocks, not one",
      "A single short window misses a patient attacker who probes slowly. Raven counts over 10 seconds, 5 minutes and 1 hour. " +
        "The default scan thresholds are 20 distinct ports in 10 seconds, 15 in 5 minutes and 60 in an hour. Expressed as a probing rate, that is the chart: " +
        "a scan must go faster than 120 probes a minute to trip the short clock, but the 5-minute clock catches 3 a minute and the 1-hour clock catches 1 a minute. " +
        "In the live loopback test a fast scan was CRITICAL through the 10-second window and a scan of one probe per second was HIGH through the 5-minute window."
    );
    kicker(s, "MULTI-TIMESCALE WINDOWS");
    mono(s, "SLOWEST PORT SCAN EACH CLOCK STILL CATCHES  (default thresholds, probes per minute)", { x: 0.6, y: 1.8, w: 12, h: 0.3, fontSize: 11, bold: true, color: T.dim, charSpacing: 2 });
    const rows = [
      ["10 s window", "20 ports in 10 s", 120, T.crit, "fast scan: CRITICAL in the live test"],
      ["5 min window", "15 ports in 5 min", 3, T.high, "slow scan, 1 probe/s: HIGH in the live test"],
      ["1 hour window", "60 ports in 1 hour", 1, T.med, "low-and-slow: one probe a minute"],
    ];
    const x0 = 3.2, maxW = 7.4;
    rows.forEach(([name, thr, v, color, note], i) => {
      const y = 2.35 + i * 1.3;
      text(s, name, { x: 0.6, y, w: 2.5, h: 0.4, fontSize: 18, bold: true, color: T.bright, valign: "middle" });
      mono(s, thr, { x: 0.6, y: y + 0.42, w: 2.5, h: 0.3, fontSize: 11, color: T.dim });
      rect(s, x0, y + 0.05, maxW, 0.62, T.panel, T.line, "track");
      const bw = Math.max(0.12, Math.sqrt(v / 120) * maxW); // square-root scale so the slow clocks stay visible
      rect(s, x0, y + 0.05, bw, 0.62, color, null, "bar");
      mono(s, `${v} / min`, { x: x0 + bw + 0.15, y: y + 0.05, w: 1.5, h: 0.62, fontSize: 16, bold: true, color: T.bright, valign: "middle" });
      text(s, note, { x: x0, y: y + 0.72, w: maxW, h: 0.3, fontSize: 12, color: T.dim });
    });
    mono(s, "bar length uses a square-root scale", { x: 0.6, y: 6.2, w: 6, h: 0.25, fontSize: 9, color: T.faint });
    rect(s, 0.6, 6.45, 12.15, 0.5, T.raise, T.line2, "callout");
    text(s, "One short window sees only the fast attacker. Three clocks also catch the patient one.", { x: 0.85, y: 6.45, w: 11.7, h: 0.5, fontSize: 14, color: T.bright, valign: "middle" });
  }

  // ------------------------------------------------------------------ 8 statistical layer
  {
    const s = content(
      "Two statistical models catch what the rules miss",
      "Our own rule says a model ships enabled only if an ablation shows it adds something without raising false alarms on normal traffic. docs/ABLATION.md has the details; the data is synthetic. " +
        "Left: a slow DNS tunnel with short names, 10 queries in 5 minutes, 20-character base32 labels. Only one rule signal fired, entropy 3.88, and two are needed, so the rules alone missed it. " +
        "The n-gram model scores how pronounceable a name is. Ordinary names land at 2.5 to 3.5 bits per character, random ones at 5.4 and above; this tunnel scored 5.69, the second signal, so it was caught. " +
        "Right: a 20-second bulk upload after 40 minutes of normal browsing. No rule covers volume. The Isolation Forest learned the network's normal, and bytes out was 263 times anything it had seen. " +
        "Be upfront about limits: synthetic traffic, a small built-in word list, a 35-minute warm-up, and the real-network false-alarm rate is not yet known."
    );
    kicker(s, "STATISTICAL DETECTORS");
    // left: n-gram
    panelTitle(s, "DNS N-GRAM  /  HOW RANDOM DOES A NAME LOOK?", 0.6, 1.75, 5.95);
    rect(s, 0.6, 2.15, 5.95, 3.55, T.panel, T.line, "panel");
    const sx = 1.0, sw = 5.1, lo = 2, hi = 6.5;
    const px = (v) => sx + ((v - lo) / (hi - lo)) * sw;
    mono(s, "average bits per character (higher = more random)", { x: sx, y: 2.3, w: sw, h: 0.25, fontSize: 10, color: T.dim });
    hline(s, sx, 4.05, sw, T.line2);
    for (const v of [2, 3, 4, 5, 6]) { mono(s, String(v), { x: px(v) - 0.15, y: 4.1, w: 0.3, h: 0.25, fontSize: 10, color: T.faint, align: "center" }); vline(s, px(v), 3.98, 0.07, T.line2); }
    rect(s, px(2.5), 3.1, px(3.5) - px(2.5), 0.7, T.ok, null, "band-ok");
    rect(s, px(5.4), 3.1, px(6.0) - px(5.4), 0.7, T.crit, null, "band-bad");
    text(s, "ordinary names", { x: px(2.5) - 0.3, y: 2.7, w: 1.9, h: 0.3, fontSize: 12, color: T.ok, bold: true });
    text(s, "random names", { x: px(5.4) - 0.05, y: 2.7, w: 1.5, h: 0.3, fontSize: 12, color: T.crit, bold: true });
    vline(s, px(4.8), 2.65, 1.4, T.bright, 2);
    mono(s, "threshold 4.8", { x: px(4.8) - 0.7, y: 4.4, w: 1.4, h: 0.25, fontSize: 10, color: T.bright, align: "center" });
    vline(s, px(5.69), 3.0, 0.9, T.high, 2);
    mono(s, "this tunnel: 5.69", { x: px(5.69) - 1.2, y: 4.75, w: 1.8, h: 0.25, fontSize: 10, bold: true, color: T.high, align: "center" });
    chip(s, 0.85, 5.15, 2.3, "RULES ALONE: MISSED", T.crit, { h: 0.34, size: 10 });
    chip(s, 3.3, 5.15, 2.9, "WITH N-GRAM: CAUGHT", T.ok, { h: 0.34, size: 10 });
    // right: forest
    panelTitle(s, "ISOLATION FOREST  /  IS THIS NORMAL?", 6.8, 1.75, 5.95);
    rect(s, 6.8, 2.15, 5.95, 3.55, T.panel, T.line, "panel");
    const stepsF = [["40 min", "of normal browsing\nby 3 devices", T.tcp], ["learns", "what normal looks like\non this network", T.tcp], ["20 s upload", "864 KB per 10 s,\none long connection", T.high]];
    stepsF.forEach(([h, b, c], i) => {
      const x = 7.05 + i * 1.95;
      mono(s, h, { x, y: 2.4, w: 1.8, h: 0.35, fontSize: 15, bold: true, color: c });
      text(s, b, { x, y: 2.8, w: 1.75, h: 0.7, fontSize: 11.5, color: T.dim, valign: "top" });
      if (i < 2) arrow(s, x + 1.55, 2.58, x + 1.9);
    });
    hline(s, 7.05, 3.75, 5.45, T.line);
    mono(s, "bytes out in one 10 s window", { x: 7.05, y: 3.85, w: 5, h: 0.25, fontSize: 10, color: T.dim });
    rect(s, 7.05, 4.2, 0.16, 0.34, T.tcp, null, "bar-normal");
    mono(s, "largest ever seen: about 3,300 B", { x: 7.35, y: 4.2, w: 5, h: 0.34, fontSize: 11, color: T.dim, valign: "middle" });
    rect(s, 7.05, 4.65, 5.45, 0.34, T.high, null, "bar-upload");
    mono(s, "the upload: 863,784 B  =  263x", { x: 7.15, y: 4.65, w: 5.2, h: 0.34, fontSize: 11, bold: true, color: "0D1013", valign: "middle" });
    chip(s, 7.05, 5.15, 2.3, "RULES ALONE: MISSED", T.crit, { h: 0.34, size: 10 });
    chip(s, 9.5, 5.15, 2.9, "WITH FOREST: CAUGHT", T.ok, { h: 0.34, size: 10 });
    rect(s, 0.6, 5.95, 12.15, 0.8, T.raise, T.line2, "honest");
    rect(s, 0.6, 5.95, 0.08, 0.8, T.med, null, "honest-edge");
    text(s, [{ text: "Measured on synthetic traffic only. ", options: { bold: true, color: T.med } }, { text: "Both are on by default and switchable. Normal traffic raised nothing in the 12-network benign test; the false-alarm rate on a real network is not yet known.", options: {} }],
      { x: 0.95, y: 5.95, w: 11.6, h: 0.8, fontSize: 13.5, valign: "middle" });
  }

  // ------------------------------------------------------------------ 9 measured results
  {
    const s = content(
      "Tested live: all four attacks caught, the control stayed quiet",
      "These come from the live loopback test in demo.md: Raven captured lo0 on this Mac with only the 10-second window while the four attack scripts ran against 127.0.0.1. " +
        "Bars show seconds from attack start to alert. The DNS tunnel was fastest, 1.7 s; the beacon needed about 12 s because it needs ten check-ins one second apart. " +
        "The control, ordinary web browsing, raised nothing. Stability: port scan, brute force, DNS and the control were right in about 15 live runs each; the beacon missed 2 of 21 early attempts because the attack started before tcpdump was capturing, and after the driver waited for tcpdump it was 4 of 4. " +
        "Real beacons check in every 30 to 300 seconds, so they need minutes, not seconds."
    );
    kicker(s, "MEASURED, NOT CLAIMED");
    mono(s, "SECONDS FROM ATTACK START TO ALERT  (live, loopback, 10 s window)", { x: 0.6, y: 1.8, w: 9, h: 0.3, fontSize: 11, bold: true, color: T.dim, charSpacing: 2 });
    const data = [["DNS tunnel", 1.7, "T1071.004"], ["Brute force", 8.5, "T1110"], ["Port scan", 8.9, "T1046"], ["Beaconing", 12.1, "T1071.001"]];
    const x0 = 2.7, maxW = 5.6, scale = maxW / 16;
    data.forEach(([n, v, t], i) => {
      const y = 2.3 + i * 0.95;
      text(s, n, { x: 0.6, y, w: 2.0, h: 0.6, fontSize: 17, bold: true, color: T.bright, valign: "middle" });
      rect(s, x0, y + 0.05, maxW, 0.5, T.panel, T.line, "track");
      rect(s, x0, y + 0.05, v * scale, 0.5, T.crit, null, "bar");
      mono(s, `${v} s`, { x: x0 + v * scale + 0.12, y: y + 0.05, w: 1, h: 0.5, fontSize: 15, bold: true, color: T.bright, valign: "middle" });
    });
    hline(s, x0, 6.15, maxW, T.line2);
    [0, 5, 10].forEach((v) => mono(s, String(v), { x: x0 + v * scale - 0.2, y: 6.2, w: 0.4, h: 0.25, fontSize: 10, color: T.faint, align: "center" }));
    // right: control + stats
    rect(s, 9.1, 2.3, 3.65, 1.65, T.panel, T.line, "stat");
    mono(s, "0", { x: 9.35, y: 2.4, w: 1.5, h: 0.9, fontSize: 48, bold: true, color: T.ok, valign: "middle" });
    text(s, "alerts from the control:\nordinary web browsing", { x: 9.35, y: 3.25, w: 3.2, h: 0.6, fontSize: 12.5, color: T.dim, valign: "top" });
    rect(s, 9.1, 4.15, 3.65, 1.65, T.panel, T.line, "stat");
    mono(s, "4 / 4", { x: 9.35, y: 4.25, w: 3, h: 0.9, fontSize: 40, bold: true, color: T.bright, valign: "middle" });
    text(s, "beacon runs caught once the\ncapture was confirmed running", { x: 9.35, y: 5.1, w: 3.2, h: 0.6, fontSize: 12.5, color: T.dim, valign: "top" });
    mono(s, "Detectors run on a 10 s grid, so an alert lands within one grid step of the threshold being crossed.", { x: 0.6, y: 6.6, w: 12.1, h: 0.3, fontSize: 10, color: T.faint });
  }

  // ------------------------------------------------------------------ 10 quiet by design
  {
    const s = content(
      "Quiet by design: false alarms are what make people stop reading alerts",
      "A detector that cries wolf gets ignored, so every rule has a guard. DNS tunnelling needs two independent signals. A domain looked up by three or more devices is a shared service, not one machine's C2. " +
        "A destination that many hosts contact is not a beacon. After an alert the same detector stays quiet for that device for five minutes. The Isolation Forest only alerts when a count or volume is more than double anything in its baseline; without that guard it raised false alarms on our benign test networks, which is why the guard exists. " +
        "The result so far: 12 seeded benign networks of eight devices for 40 minutes raised nothing. Again: synthetic data, real-network rate unknown."
    );
    kicker(s, "FALSE-ALARM CONTROL");
    const guards = [
      [fa.FaCheckDouble, "Two signals, not one", "DNS tunnelling needs two independent signals to agree."],
      [fa.FaUsers, "Shared services are not C2", "A destination or domain that 3+ devices use is treated as a shared service."],
      [fa.FaHourglassHalf, "Cooldown", "Once a detector fires for a device it stays quiet for 5 minutes. No alert storms."],
      [fa.FaRulerHorizontal, "Statistical guard", "The forest only fires when a value is over 2x anything in its baseline."],
      [fa.FaListUl, "Your allow-lists", "trusted_ips, allowed destinations and ignored domains, in one config file."],
    ];
    for (let i = 0; i < guards.length; i++) {
      const y = 1.8 + i * 0.98;
      await iconBox(s, 0.6, y, 0.66, guards[i][0], T.ok);
      text(s, guards[i][1], { x: 1.5, y: y - 0.02, w: 4.6, h: 0.35, fontSize: 16, bold: true, color: T.bright });
      text(s, guards[i][2], { x: 1.5, y: y + 0.33, w: 4.7, h: 0.5, fontSize: 12, color: T.dim, valign: "top" });
    }
    rect(s, 6.9, 1.8, 5.85, 4.8, T.panel, T.line, "stat-panel");
    label(s, "BENIGN TEST SUITE (SYNTHETIC)", 7.2, 2.0, 5.3);
    mono(s, "0", { x: 7.2, y: 2.35, w: 2.2, h: 1.4, fontSize: 90, bold: true, color: T.ok, valign: "middle" });
    text(s, "alerts", { x: 9.35, y: 3.1, w: 2, h: 0.5, fontSize: 22, color: T.bright, valign: "middle" });
    hline(s, 7.2, 4.0, 5.25, T.line);
    text(s, "12 seeded networks, 8 devices each, 40 minutes of browsing, shared-service polling, refused connections and hashed CDN names. All with both statistical models on.", { x: 7.2, y: 4.15, w: 5.25, h: 1.2, fontSize: 13.5, color: T.text, valign: "top" });
    rect(s, 7.2, 5.55, 5.25, 0.8, T.raise, T.line2, "honest");
    text(s, "Real-network false-alarm rate: not yet measured. A one-day check is on the verification list.", { x: 7.4, y: 5.55, w: 4.9, h: 0.8, fontSize: 12, color: T.med, valign: "middle" });
  }

  // ------------------------------------------------------------------ 11 explanations
  {
    const s = content(
      "Alerts an admin can act on, not raw numbers",
      "Left is what the detector actually recorded: only numbers. Right is what the admin reads, taken from the real History detail in the screenshot: a headline, what happened, the likely cause and a suggested action. " +
        "The text comes from fixed templates, so it is always available and always matches the evidence. If you run a local model, Ollama or llama.cpp, it rewrites the wording from the same sanitised fields. " +
        "Its output is checked against the evidence: invented numbers, addresses or techniques cause the template to be used instead. The model can only pick an action from a fixed list."
    );
    kicker(s, "EXPLANATIONS");
    panelTitle(s, "WHAT THE DETECTOR RECORDED", 0.6, 1.8, 5.2);
    rect(s, 0.6, 2.2, 5.2, 3.0, T.panel, T.line, "panel");
    mono(s, ["detector      beaconing", "technique     T1071.001", "dst_port      8080", "count         16", "mean_interval  1.0003 s", "interval_cv   0.0023", "mean_bytes    ~1 KB"].join("\n"),
      { x: 0.85, y: 2.4, w: 4.8, h: 2.6, fontSize: 13, color: T.tcp, valign: "top", paraSpaceAfter: 4 });
    arrow(s, 5.95, 3.7, 6.55, T.crit);
    panelTitle(s, "WHAT THE ADMIN READS", 6.7, 1.8, 6.05);
    rect(s, 6.7, 2.2, 6.05, 3.0, T.panel, T.line, "panel");
    rect(s, 6.95, 2.4, 1.15, 0.3, T.crit, null, "sev");
    mono(s, "CRITICAL", { x: 6.95, y: 2.4, w: 1.15, h: 0.3, fontSize: 11, bold: true, color: "FFFFFF", align: "center", valign: "middle" });
    text(s, "Device contacts one server at fixed intervals", { x: 6.95, y: 2.8, w: 5.6, h: 0.4, fontSize: 17, bold: true, color: T.bright });
    text(s, [
      { text: "What happened  ", options: { bold: true, color: T.dim } }, { text: "The device connected to the same server 16 times, about every 1.0 seconds, with very little variation.", options: { breakLine: true } },
      { text: "Likely cause  ", options: { bold: true, color: T.dim } }, { text: "Regular small connections can be malware checking in, or a legitimate sync tool.", options: { breakLine: true } },
      { text: "Suggested action  ", options: { bold: true, color: T.dim } }, { text: "Check what this device is running and whether it should be doing this.", options: {} },
    ], { x: 6.95, y: 3.3, w: 5.6, h: 1.8, fontSize: 12.5, valign: "top", paraSpaceAfter: 6 });
    const g = [[fa.FaFileAlt, "Templates first", "Always available, always matches the evidence."], [fa.FaRobot, "Optional local LLM", "Ollama or llama.cpp, on your machine. Tried with Gemma (e2b) through Ollama."], [fa.FaShieldAlt, "Fact-checked", "Invented facts are rejected; the template is used instead."]];
    for (let i = 0; i < 3; i++) {
      const x = 0.6 + i * 4.1;
      await iconBox(s, x, 5.55, 0.6, g[i][0], T.tcp);
      text(s, g[i][1], { x: x + 0.8, y: 5.52, w: 3.1, h: 0.35, fontSize: 15, bold: true, color: T.bright });
      text(s, g[i][2], { x: x + 0.8, y: 5.9, w: 3.1, h: 0.7, fontSize: 12, color: T.dim, valign: "top" });
    }
  }

  // ------------------------------------------------------------------ 12 notifications
  {
    const s = content(
      "Alerts where the admin already is",
      "Notifications are opt-in and off by default. Slack and Discord use webhooks, Telegram a bot token and chat id; keys live in a private file, never in the config or logs. " +
        "Policies stop alert fatigue: a severity floor, de-duplication, a per-channel rate limit, retries with back-off and a circuit breaker that pauses a failing channel. " +
        "Messages carry only a sanitised summary: device, technique, score and advice, never packet data. Be honest about status: delivery is tested against fakes; sending to real Slack, Discord and Telegram is on the verification list."
    );
    kicker(s, "NOTIFICATIONS");
    const ch = [[fa.FaSlack, "Slack", "incoming webhook"], [fa.FaDiscord, "Discord", "webhook"], [fa.FaTelegram, "Telegram", "bot token + chat id"]];
    for (let i = 0; i < 3; i++) {
      const x = 0.6 + i * 2.1;
      rect(s, x, 1.85, 1.9, 2.1, T.panel, T.line, "card");
      s.addImage({ data: await icon(ch[i][0], "E6EAEE"), x: x + 0.6, y: 2.1, w: 0.7, h: 0.7, altText: ch[i][1] });
      text(s, ch[i][1], { x, y: 2.95, w: 1.9, h: 0.4, fontSize: 17, bold: true, color: T.bright, align: "center" });
      mono(s, ch[i][2], { x, y: 3.4, w: 1.9, h: 0.4, fontSize: 10, color: T.dim, align: "center" });
    }
    // sample message
    panelTitle(s, "WHAT ARRIVES", 7.1, 1.85, 5.65);
    rect(s, 7.1, 2.25, 5.65, 1.7, T.panel, T.line, "panel");
    mono(s, "[CRITICAL] Device is probing many network ports", { x: 7.3, y: 2.4, w: 5.3, h: 0.3, fontSize: 12, bold: true, color: T.crit });
    text(s, "Device 192.168.2.30 tried 400 different ports on 192.168.2.20 within 10 seconds, and 99% of the attempts failed. Check what this device is running, or disconnect it if you do not recognise this.", { x: 7.3, y: 2.78, w: 5.3, h: 1.1, fontSize: 12, color: T.text, valign: "top" });
    label(s, "POLICIES THAT PREVENT ALERT FATIGUE", 0.6, 4.35, 8);
    const pol = [["severity floor", "default 0.6"], ["de-duplication", "one per chain step"], ["rate limit", "10 / min / channel"], ["retry + back-off", "2 retries"], ["circuit breaker", "3 failures, 5 min off"]];
    pol.forEach(([a, b], i) => {
      const x = 0.6 + i * 2.45;
      rect(s, x, 4.75, 2.3, 1.0, T.panel, T.line, "policy");
      text(s, a, { x: x + 0.18, y: 4.85, w: 2.0, h: 0.35, fontSize: 14, bold: true, color: T.bright });
      mono(s, b, { x: x + 0.18, y: 5.25, w: 2.0, h: 0.35, fontSize: 10.5, color: T.dim });
    });
    rect(s, 0.6, 6.05, 12.15, 0.65, T.raise, T.line2, "honest");
    rect(s, 0.6, 6.05, 0.08, 0.65, T.med, null, "honest-edge");
    text(s, [{ text: "Opt-in, off by default. ", options: { bold: true, color: T.bright } }, { text: "Keys stay in a private file. Messages never contain packet data. Delivery is tested against fakes; real-channel delivery is still to be confirmed.", options: {} }],
      { x: 0.95, y: 6.05, w: 11.6, h: 0.65, fontSize: 12.5, valign: "middle" });
  }

  // ------------------------------------------------------------------ 13 security
  {
    const s = content(
      "A security tool has to be safe to run",
      "Five points. One: strings from the network are hostile and go through one sanitiser. Two: the console is local only, with a token, a strict content-security policy and no way for network text to become markup; the test suite fails if code that builds HTML from strings is added. " +
        "Three: Raven only observes and alerts; it never blocks or changes the network. Four: secrets are in a mode 600 file and never printed. Five: the demo attack scripts refuse any target except loopback. " +
        "Also mention the delete and history paths are validated and audited, and that automated security review found and we fixed a symlink issue in the sudo file-ownership code."
    );
    kicker(s, "SECURITY BY DESIGN");
    const rows = [
      [fa.FaBug, "Network text is hostile", "DNS names and hostnames pass one sanitiser before any LLM, alert or screen. The console shows them as plain text only."],
      [fa.FaLock, "A locked-down console", "127.0.0.1 only, per-run token, strict content-security policy, no inline scripts, and a test that fails if HTML is built from strings."],
      [fa.FaBan, "Observe and alert only", "Raven never blocks, changes firewall rules or touches the network. A human decides what to do."],
      [fa.FaKey, "Secrets stay private", "Webhook URLs and tokens live in a mode 600 file, are never printed or logged, and errors never leak URLs."],
      [fa.FaBullseye, "Attack scripts stay home", "The demo attacks refuse any target except loopback. Own machine only."],
    ];
    for (let i = 0; i < rows.length; i++) {
      const y = 1.8 + i * 0.99;
      await iconBox(s, 0.6, y, 0.7, rows[i][0], T.crit);
      text(s, rows[i][1], { x: 1.55, y: y - 0.03, w: 6.0, h: 0.4, fontSize: 17, bold: true, color: T.bright });
      text(s, rows[i][2], { x: 1.55, y: y + 0.36, w: 6.1, h: 0.6, fontSize: 12.5, color: T.dim, valign: "top" });
    }
    rect(s, 8.2, 1.8, 4.55, 4.85, T.panel, T.line, "stat-panel");
    label(s, "SECURITY TEST GROUP", 8.5, 2.0, 4);
    mono(s, "85", { x: 8.5, y: 2.3, w: 2.0, h: 1.2, fontSize: 72, bold: true, color: T.ok, valign: "middle" });
    text(s, "tests that must\nnever be empty", { x: 10.4, y: 2.55, w: 2.2, h: 0.7, fontSize: 14, color: T.text, valign: "middle" });
    hline(s, 8.5, 3.7, 3.95, T.line);
    text(s, "They cover hostile DNS names, hostile history filters, SQL text in searches, spreadsheet-formula export, cross-site delete, rename and test-send requests, and planted symlinks.", { x: 8.5, y: 3.85, w: 3.95, h: 1.4, fontSize: 12.5, color: T.text, valign: "top" });
    rect(s, 8.5, 5.35, 3.95, 1.1, T.raise, T.line2, "found");
    text(s, [{ text: "Found and fixed: ", options: { bold: true, color: T.med } }, { text: "an automated review flagged a symlink risk in the sudo file-ownership code; it is fixed and tested.", options: {} }],
      { x: 8.65, y: 5.35, w: 3.7, h: 1.1, fontSize: 12, valign: "middle" });
  }

  // ------------------------------------------------------------------ 14 who + where
  {
    const s = content(
      "Who it is for, and where it sits",
      "Raven sees what crosses the interface it captures, so it belongs on the gateway: a Mac sharing its connection, where clients appear on bridge100. On a normal laptop on Wi-Fi it only sees that laptop's own traffic. " +
        "Be clear about the audience: small teams, schools and labs with no analyst, and people learning detection. It is not an enterprise product, not an intrusion prevention system, and does not read encrypted content."
    );
    kicker(s, "WHO AND WHERE");
    // diagram
    const dy = 2.0;
    rect(s, 0.6, dy + 0.6, 1.9, 1.1, T.panel, T.line2, "node");
    await iconBox(s, 0.85, dy + 0.75, 0.5, fa.FaGlobe, T.dim);
    text(s, "Internet", { x: 1.45, y: dy + 0.6, w: 1.0, h: 1.1, fontSize: 14, bold: true, color: T.bright, valign: "middle" });
    arrow(s, 2.55, dy + 1.15, 3.35);
    rect(s, 3.4, dy + 0.3, 3.1, 1.7, T.panel, T.crit, "gateway");
    await iconBox(s, 3.65, dy + 0.5, 0.55, fa.FaShieldAlt, T.crit);
    text(s, "Gateway Mac", { x: 4.35, y: dy + 0.45, w: 2.1, h: 0.4, fontSize: 16, bold: true, color: T.bright });
    mono(s, "Internet Sharing\nbridge100", { x: 4.35, y: dy + 0.85, w: 2.1, h: 0.5, fontSize: 10, color: T.dim });
    text(s, "runs Raven", { x: 3.65, y: dy + 1.45, w: 2.7, h: 0.4, fontSize: 14, bold: true, color: T.crit });
    arrow(s, 6.55, dy + 1.15, 7.35);
    const devs = [[fa.FaLaptop, "Laptops"], [fa.FaMobileAlt, "Phones"], [fa.FaPrint, "Printers, IoT"]];
    devs.forEach(([ic, n], i) => {
      const y = dy + i * 0.78;
      rect(s, 7.4, y, 2.1, 0.66, T.panel, T.line2, "node");
    });
    for (let i = 0; i < 3; i++) {
      const y = dy + i * 0.78;
      s.addImage({ data: await icon(devs[i][0], "7B8794"), x: 7.55, y: y + 0.15, w: 0.36, h: 0.36, altText: devs[i][1] });
      text(s, devs[i][1], { x: 8.05, y, w: 1.4, h: 0.66, fontSize: 13, color: T.text, valign: "middle" });
    }
    mono(s, "Sees all traffic that crosses the gateway.\nOn a plain laptop on Wi-Fi it sees only that laptop.", { x: 0.6, y: 4.5, w: 9, h: 0.6, fontSize: 11, color: T.faint });
    // audiences
    rect(s, 10.0, 2.0, 2.75, 3.1, T.panel, T.line, "who");
    label(s, "FOR", 10.2, 2.15, 2, T.ok);
    text(s, "Small teams\nSchools and colleges\nLabs and home offices\nStudents learning detection", { x: 10.2, y: 2.5, w: 2.4, h: 1.2, fontSize: 12.5, color: T.text, valign: "top", paraSpaceAfter: 3 });
    label(s, "NOT FOR", 10.2, 3.85, 2, T.crit);
    text(s, "Enterprise scale\nAutomatic blocking\nReading encrypted traffic", { x: 10.2, y: 4.2, w: 2.4, h: 0.85, fontSize: 12.5, color: T.dim, valign: "top", paraSpaceAfter: 3 });
    // how it is used
    label(s, "HOW IT IS USED", 0.6, 5.4, 6);
    const use = [["1", "Install on the gateway Mac"], ["2", "Watch the console, or just wait for alerts"], ["3", "Open History to review what happened"]];
    use.forEach(([n, t], i) => {
      const x = 0.6 + i * 4.1;
      rect(s, x, 5.8, 0.42, 0.42, T.crit, null, "num");
      mono(s, n, { x, y: 5.8, w: 0.42, h: 0.42, fontSize: 14, bold: true, color: "FFFFFF", align: "center", valign: "middle" });
      text(s, t, { x: x + 0.6, y: 5.8, w: 3.3, h: 0.42, fontSize: 14, color: T.text, valign: "middle" });
    });
  }

  // ------------------------------------------------------------------ 15 run it
  {
    const s = content(
      "From clone to first detection in five minutes",
      "Three blocks. Install uses uv, which fetches Python itself. The quick start needs no network at all: it builds a synthetic capture with one of each attack and replays it. " +
        "'Attack yourself' runs the four attacks against your own loopback while the console watches, so you can show the detection live. The demo config uses a 10-second window and keeps demo data out of your real history. " +
        "Everything is in the README and USER_GUIDE."
    );
    kicker(s, "RUN IT");
    const blocks = [
      ["1  INSTALL", ["brew install uv", "git clone https://github.com/MRX-72/Hackt0b3r.git raven && cd raven", "uv tool install .", "raven init && raven doctor"]],
      ["2  QUICK START  (no network needed)", ["uv run python tools/make_demo_pcap.py demo.pcap", "raven replay demo.pcap", "raven ui --replay demo.pcap", "raven history"]],
      ["3  ATTACK YOURSELF  (two terminals)", ["# terminal 1: the monitor", "raven --config examples/demo-10s.toml ui --iface lo0", "# terminal 2: the attacks, on your own machine only", "uv run python tools/demo_attacks.py"]],
    ];
    blocks.forEach(([h, lines], i) => {
      const y = 1.8 + i * 1.7;
      rect(s, 0.6, y, 12.15, 1.55, T.panel, T.line, "term");
      rect(s, 0.6, y, 12.15, 0.38, T.bar, T.line, "term-bar");
      mono(s, h, { x: 0.8, y: y + 0.06, w: 8, h: 0.26, fontSize: 11, bold: true, color: T.dim, charSpacing: 2 });
      mono(s, lines.map((l) => (l.startsWith("#") ? l : "$ " + l)).join("\n"), { x: 0.85, y: y + 0.45, w: 11.5, h: 1.05, fontSize: 12.5, color: T.bright, valign: "top", paraSpaceAfter: 2 });
    });
  }

  // ------------------------------------------------------------------ 16 close
  {
    const s = pres.addSlide({ masterName: "TITLE" });
    s.addNotes("Close on the promise and the call to action: try it in five minutes with no network. Offer to run the live attack demo now. Questions.");
    rect(s, 0, 0, 0.18, 7.5, T.crit, null, "edge");
    mono(s, "TRY IT TODAY", { x: 0.8, y: 1.5, w: 6, h: 0.3, fontSize: 12, bold: true, color: T.crit, charSpacing: 5 });
    text(s, "See it catch an attack on your own machine.", { x: 0.8, y: 1.95, w: 7.2, h: 1.9, fontSize: 40, bold: true, color: T.bright, valign: "top" });
    text(s, "Five minutes, no network needed, nothing leaves your Mac.", { x: 0.8, y: 4.0, w: 7, h: 0.5, fontSize: 18, color: T.text });
    rect(s, 8.6, 1.9, 4.2, 2.3, T.panel, T.line2, "term");
    mono(s, "$ uv tool install .\n$ raven init\n$ uv run python \\\n    tools/demo_attacks.py", { x: 8.85, y: 2.15, w: 3.8, h: 1.9, fontSize: 14, color: T.bright, valign: "top", paraSpaceAfter: 6 });
    mono(s, "README.md  ·  USER_GUIDE.md  ·  docs/ABLATION.md", { x: 0.8, y: 6.5, w: 9, h: 0.3, fontSize: 12, color: T.dim });
    mono(s, "Questions?", { x: 8.6, y: 4.5, w: 4.2, h: 0.5, fontSize: 24, bold: true, color: T.crit });
  }

  const out = process.argv[2] || path.join(__dirname, "Raven_Pitch.pptx");
  await pres.writeFile({ fileName: out });
  console.log("wrote", out);
}

build();
