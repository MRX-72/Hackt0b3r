// Builds Sentinel_Pitch.pptx. Run: cd docs/pitch && npm install && node build_deck.js
// Facts in the deck come from the repository's tests and live localhost runs (see demo.md).
const path = require("path");
const pptxgen = require("pptxgenjs");
const React = require("react");
const RDS = require("react-dom/server");
const sharp = require("sharp");
const fa = require("react-icons/fa");
const { applyTheme } = require(
  process.env.PPTX_SKILL_DIR
    ? path.join(process.env.PPTX_SKILL_DIR, "scripts/apply_theme.js")
    : "./apply_theme.js"
);

const THEME = {
  name: "Sentinel",
  headFontFace: "Cambria",
  bodyFontFace: "Calibri",
  colors: {
    dk1: "0B1B2B", lt1: "FFFFFF", dk2: "16324F", lt2: "EEF2F6",
    accent1: "E5383B", accent2: "F4A261", accent3: "2EC4B6", accent4: "5C7CFA",
    accent5: "8D99AE", accent6: "3A506B", hlink: "5C7CFA", folHlink: "8D99AE",
  },
};
const H = THEME.colors; // hex values, for chart options that cannot take scheme colors

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.33 x 7.5 in
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
pres.title = "Sentinel: network security for places with no security team";
pres.author = "Sentinel";
const C = pres.SchemeColor;
const W = 13.33;

pres.defineSlideMaster({
  title: "DARK",
  background: { color: H.dk1 },
  objects: [],
  slideNumber: undefined,
});
pres.defineSlideMaster({
  title: "CONTENT",
  background: { color: H.lt1 },
  objects: [
    {
      placeholder: {
        options: {
          name: "title", type: "title", x: 0.6, y: 0.35, w: 12.1, h: 0.9,
          fontSize: 34, bold: true, color: C.text1, align: "left", valign: "middle", margin: 0,
        },
        text: "",
      },
    },
    {
      text: {
        text: "Sentinel", options: {
          x: 0.6, y: 7.05, w: 3, h: 0.3, fontSize: 11, color: C.accent5, margin: 0,
        },
      },
    },
  ],
  slideNumber: { x: 12.2, y: 7.05, w: 0.6, h: 0.3, fontSize: 11, color: C.accent5, align: "right" },
});

async function icon(Comp, color, size = 256) {
  const svg = RDS.renderToStaticMarkup(React.createElement(Comp, { color: "#" + color, size: String(size) }));
  const buf = await sharp(Buffer.from(svg)).png().toBuffer();
  return "image/png;base64," + buf.toString("base64");
}

const text = (slide, t, o) => slide.addText(t, { isTextBox: true, margin: 0, ...o });
const card = (slide, x, y, w, h, o = {}) =>
  slide.addShape(pres.ShapeType.roundRect, {
    x, y, w, h, rectRadius: 0.08, fill: { color: o.fill || C.background2 }, line: { type: "none" },
    objectName: o.name || "card",
  });
const chip = (slide, x, y, w, h, t, fill, color = C.background1, size = 12) => {
  slide.addShape(pres.ShapeType.roundRect, {
    x, y, w, h, rectRadius: h / 2, fill: { color: fill }, line: { type: "none" }, objectName: "chip",
  });
  text(slide, t, { x, y, w, h, fontSize: size, bold: true, color, align: "center", valign: "middle" });
};
const arrow = (slide, x1, y, x2, color = C.accent5) =>
  slide.addShape(pres.ShapeType.line, {
    x: x1, y, w: x2 - x1, h: 0, line: { color, width: 2.5, endArrowType: "triangle" }, objectName: "arrow",
  });
const arrowDown = (slide, x, y1, y2, color = C.accent5) =>
  slide.addShape(pres.ShapeType.line, {
    x, y: y1, w: 0, h: y2 - y1, line: { color, width: 2.5, endArrowType: "triangle" }, objectName: "arrow",
  });
const circleIcon = async (slide, x, y, d, Comp, bg, fg = "FFFFFF") => {
  slide.addShape(pres.ShapeType.ellipse, { x, y, w: d, h: d, fill: { color: bg }, line: { type: "none" }, objectName: "icon-bg" });
  const pad = d * 0.25;
  slide.addImage({ data: await icon(Comp, fg), x: x + pad, y: y + pad, w: d - 2 * pad, h: d - 2 * pad, altText: "icon" });
};
const content = (title, notes) => {
  const s = pres.addSlide({ masterName: "CONTENT" });
  s.addText(title, { placeholder: "title" });
  s.addNotes(notes);
  return s;
};

const chartText = { fontFace: "+mn-lt" };
const chartBase = (title) => ({
  showTitle: true, title, titleFontSize: 14, titleColor: H.dk2, titleFontFace: "+mn-lt",
  catAxisLabelFontSize: 14, catAxisLabelColor: H.dk1, catAxisLabelFontFace: "+mn-lt",
  valAxisLabelFontSize: 12, valAxisLabelColor: H.accent6, valAxisLabelFontFace: "+mn-lt",
  valGridLine: { color: "D9E0E8", size: 0.5 }, catGridLine: { style: "none" },
  dataLabelFontSize: 13, dataLabelFontBold: true, dataLabelColor: H.dk1, dataLabelFontFace: "+mn-lt",
  legendFontSize: 12, legendColor: H.dk1, legendFontFace: "+mn-lt",
});

const IMAGE_CHARTS = process.env.CHARTS === "image"; // Keynote does not draw pptxgenjs charts
function addChart(slide, type, data, opts, png, alt) {
  if (IMAGE_CHARTS) {
    slide.addImage({ path: path.join(__dirname, png), x: opts.x, y: opts.y, w: opts.w, h: opts.h, altText: alt });
  } else {
    slide.addChart(type, data, opts);
  }
}

async function build() {
  // ---------------------------------------------------------------- 1 title
  {
    const s = pres.addSlide({ masterName: "DARK" });
    s.addNotes(
      "Open with the one-line promise: network security for places with no security team. " +
        "Sentinel runs on the gateway Mac, spots scans, password guessing, malware check-ins and DNS tunnelling, " +
        "explains them in plain English and alerts you on Slack, Discord or Telegram."
    );
    // radar rings
    const cx = 10.3, cy = 3.75;
    [3.6, 2.6, 1.6].forEach((d, i) =>
      s.addShape(pres.ShapeType.ellipse, {
        x: cx - d / 2, y: cy - d / 2, w: d, h: d, fill: { type: "none" },
        line: { color: C.accent6, width: 1.5 - i * 0.25 }, objectName: "radar-ring",
      })
    );
    s.addShape(pres.ShapeType.ellipse, { x: cx - 0.55, y: cy - 0.55, w: 1.1, h: 1.1, fill: { color: C.accent1 }, line: { type: "none" }, objectName: "radar-core" });
    s.addImage({ data: await icon(fa.FaShieldAlt, "FFFFFF"), x: cx - 0.3, y: cy - 0.3, w: 0.6, h: 0.6, altText: "shield" });
    [[8.9, 2.4], [11.5, 2.9], [9.4, 5.2], [11.8, 4.9]].forEach(([x, y], i) =>
      s.addShape(pres.ShapeType.ellipse, { x, y, w: 0.18, h: 0.18, fill: { color: i === 1 ? C.accent2 : C.accent3 }, line: { type: "none" }, objectName: "radar-dot" })
    );
    text(s, "SENTINEL", { x: 0.8, y: 1.55, w: 7.5, h: 1.2, fontSize: 66, bold: true, fontFace: "Cambria", color: C.background1, valign: "middle" });
    text(s, "Network security for places with no security team", { x: 0.8, y: 2.85, w: 7.2, h: 1.2, fontSize: 28, color: C.accent3, valign: "top" });
    text(s, "Catches scans, brute force, malware beacons and DNS tunnels. Explains them in plain English. Alerts you on Slack, Discord or Telegram.", {
      x: 0.8, y: 4.35, w: 7.0, h: 1.2, fontSize: 18, color: C.accent5, valign: "top",
    });
    chip(s, 0.8, 6.05, 2.5, 0.42, "Runs on one gateway Mac", C.accent6, C.background1, 13);
    chip(s, 3.5, 6.05, 2.2, 0.42, "Local-first", C.accent6, C.background1, 13);
    chip(s, 5.9, 6.05, 2.2, 0.42, "Observe only", C.accent6, C.background1, 13);
  }

  // ---------------------------------------------------------------- 2 problem
  {
    const s = content(
      "Small networks, no one watching",
      "The problem: a college lab, a small office or a home lab has an IT generalist at best, not a security team. " +
        "Enterprise tools assume analysts, tuning and budget. And raw network traffic is just noise until someone tells a story from it."
    );
    const items = [
      [fa.FaUserSlash, C.accent1, "No security team", "An IT generalist at best. Nobody reads logs or reviews traffic."],
      [fa.FaBuilding, C.accent2, "Enterprise tools don't fit", "IDS and SIEM products need analysts, tuning and a budget."],
      [fa.FaBell, C.accent4, "Traffic is just noise", "A port scan or a malware check-in looks like ordinary packets."],
    ];
    for (let i = 0; i < 3; i++) {
      const x = 0.6 + i * 4.1;
      card(s, x, 1.6, 3.8, 3.5);
      await circleIcon(s, x + 0.35, 1.95, 0.95, items[i][0], items[i][1]);
      text(s, items[i][2], { x: x + 0.35, y: 3.1, w: 3.2, h: 0.5, fontSize: 22, bold: true, color: C.text1 });
      text(s, items[i][3], { x: x + 0.35, y: 3.7, w: 3.2, h: 1.3, fontSize: 18, color: C.accent6, valign: "top" });
    }
    s.addShape(pres.ShapeType.roundRect, { x: 0.6, y: 5.5, w: 12.1, h: 1.1, rectRadius: 0.08, fill: { color: C.text1 }, line: { type: "none" }, objectName: "banner" });
    text(s, "The result: attackers can scan, guess passwords and phone home for days without anyone noticing.", {
      x: 0.95, y: 5.5, w: 11.4, h: 1.1, fontSize: 22, bold: true, color: C.background1, valign: "middle",
    });
  }

  // ---------------------------------------------------------------- 3 what it is
  {
    const s = content(
      "Sentinel watches the gateway for you",
      "One Mac sits where all traffic crosses (for example the Internet-Sharing gateway). Sentinel observes passively. " +
        "It never blocks anything. When something looks wrong you get a plain-English alert, in the terminal and on chat."
    );
    const nodes = [
      [fa.FaLaptop, C.accent4, "Your devices", "laptops, phones, printers, lab PCs"],
      [fa.FaShieldAlt, C.accent1, "Gateway Mac + Sentinel", "captures and analyses traffic"],
      [fa.FaBell, C.accent3, "You, in plain English", "live dashboard + Slack / Discord / Telegram"],
    ];
    const xs = [0.6, 4.95, 9.3];
    for (let i = 0; i < 3; i++) {
      card(s, xs[i], 1.65, 3.45, 2.9);
      await circleIcon(s, xs[i] + 1.2, 1.95, 1.05, nodes[i][0], nodes[i][1]);
      text(s, nodes[i][2], { x: xs[i] + 0.2, y: 3.15, w: 3.05, h: 0.5, fontSize: 20, bold: true, color: C.text1, align: "center" });
      text(s, nodes[i][3], { x: xs[i] + 0.2, y: 3.7, w: 3.05, h: 0.7, fontSize: 15, color: C.accent6, align: "center", valign: "top" });
    }
    arrow(s, 4.1, 3.1, 4.9);
    arrow(s, 8.45, 3.1, 9.25);
    const facts = [
      ["Passive", "observes only, never blocks"],
      ["Local-first", "only alert summaries you choose leave the network"],
      ["Plain English", "“192.168.2.30 tried 400 ports in 10 seconds”"],
    ];
    for (let i = 0; i < 3; i++) {
      const x = 0.6 + i * 4.1;
      text(s, facts[i][0], { x, y: 4.95, w: 3.8, h: 0.45, fontSize: 20, bold: true, color: C.accent1 });
      text(s, facts[i][1], { x, y: 5.45, w: 3.8, h: 1.0, fontSize: 16, color: C.text1, valign: "top" });
    }
  }

  // ---------------------------------------------------------------- 4 who for
  {
    const s = content(
      "Built for networks without a SOC",
      "Who it is for: small teams and offices, college labs and classrooms, and home labs or IT generalists. " +
        "Who it is not for: enterprises needing scale and active blocking. Sentinel is a prioritisation assistant, not an IPS."
    );
    const who = [
      [fa.FaUsers, C.accent4, "Small teams & offices", "10 to 100 devices, one person who 'does IT'. Wants to know when something is wrong, without a dashboard farm."],
      [fa.FaSchool, C.accent3, "College labs & classrooms", "Shared machines, curious students, exam weeks. Wants scans and brute force flagged the moment they start."],
      [fa.FaHome, C.accent2, "Home labs & power users", "A gateway Mac, a pile of IoT gadgets. Wants a quiet watchdog that speaks plainly."],
    ];
    for (let i = 0; i < 3; i++) {
      const x = 0.6 + i * 4.1;
      card(s, x, 1.6, 3.8, 3.9);
      await circleIcon(s, x + 0.35, 1.95, 0.95, who[i][0], who[i][1]);
      text(s, who[i][2], { x: x + 0.35, y: 3.1, w: 3.2, h: 0.8, fontSize: 21, bold: true, color: C.text1, valign: "top" });
      text(s, who[i][3], { x: x + 0.35, y: 3.95, w: 3.2, h: 1.45, fontSize: 15, color: C.accent6, valign: "top" });
    }
    text(s, "Not for:", { x: 0.6, y: 5.95, w: 1.2, h: 0.45, fontSize: 17, bold: true, color: C.accent1, valign: "middle" });
    text(s, "enterprise-scale monitoring, or active blocking (it observes and advises, it is not an IPS).", {
      x: 1.75, y: 5.95, w: 10.9, h: 0.45, fontSize: 17, color: C.text1, valign: "middle",
    });
  }

  // ---------------------------------------------------------------- 5 noise to story (chart)
  {
    const s = content(
      "Thousands of packets, one story",
      "From the live four-attack demo on localhost: about 2,300 packets were seen, four alerts were raised, and the admin sees one incident whose chain tells the story: scan, then password guessing, then malware check-ins, then DNS tunnelling."
    );
    addChart(
      s, pres.charts.BAR,
      [{ name: "Count", labels: ["Packets seen", "Alerts raised", "Incident reported"], values: [2325, 4, 1] }],
      {
        x: 0.6, y: 1.5, w: 6.6, h: 5.2, barDir: "col", barGapWidthPct: 60,
        chartColors: [H.accent5, H.accent2, H.accent1], valAxisLogScaleBase: 10, valAxisMinVal: 1, valAxisMaxVal: 10000,
        showLegend: false, showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "#,##0",
        ...chartBase("Live demo run (log scale)"),
      },
      "chart_noise.png",
      "Bar chart: 2,325 packets, 4 alerts, 1 incident (log scale)"
    );
    card(s, 7.6, 1.6, 5.1, 5.0);
    text(s, "What the admin sees", { x: 7.95, y: 1.85, w: 4.4, h: 0.5, fontSize: 20, bold: true, color: C.text1 });
    const steps = [
      ["Port scan", "T1046", C.accent1],
      ["Repeated logins", "T1110", C.accent1],
      ["Malware check-ins", "T1071.001", C.accent1],
      ["DNS tunnelling", "T1071.004", C.accent1],
    ];
    steps.forEach((st, i) => {
      const y = 2.55 + i * 0.95;
      chip(s, 7.95, y, 1.45, 0.5, st[1], st[2], C.background1, 13);
      text(s, st[0], { x: 9.6, y, w: 2.9, h: 0.5, fontSize: 18, bold: true, color: C.text1, valign: "middle" });
      if (i < 3) arrowDown(s, 8.675, y + 0.52, y + 0.92);
    });
    text(s, "One device, one growing incident, four red alerts", { x: 7.95, y: 6.25, w: 4.5, h: 0.3, fontSize: 13, color: C.accent6, valign: "middle" });
  }

  // ---------------------------------------------------------------- 6 pipeline
  {
    const s = content(
      "From packets to a plain-English alert",
      "Walk left to right. Capture and parse are deterministic. Three time windows (10 seconds, 5 minutes, 1 hour) turn packets into per-device features. " +
        "Detectors raise alerts, correlation turns alerts into one incident tagged with MITRE ATT&CK, an LLM or a template writes the explanation, and the alert goes to the terminal and chat."
    );
    const stages = [
      ["Capture", "tcpdump or a pcap file", C.accent3],
      ["Parse", "flows, DNS names", C.accent3],
      ["Windows", "10 s · 5 min · 1 h", C.accent3],
      ["Detect", "rules, timing, ML", C.accent4],
      ["Correlate", "incident + ATT&CK", C.accent3],
      ["Explain", "LLM or template", C.accent2],
      ["Alert", "CLI · chat", C.accent1],
    ];
    const bw = 1.55, gap = 0.21;
    stages.forEach((st, i) => {
      const x = 0.6 + i * (bw + gap);
      s.addShape(pres.ShapeType.roundRect, { x, y: 2.1, w: bw, h: 1.35, rectRadius: 0.1, fill: { color: st[2] }, line: { type: "none" }, objectName: "stage" });
      text(s, st[0], { x, y: 2.1, w: bw, h: 1.35, fontSize: 19, bold: true, color: C.background1, align: "center", valign: "middle" });
      text(s, st[1], { x: x - 0.05, y: 3.6, w: bw + 0.1, h: 0.7, fontSize: 13, color: C.accent6, align: "center", valign: "top" });
      if (i < stages.length - 1) arrow(s, x + bw + 0.01, 2.78, x + bw + gap - 0.01, C.accent5);
    });
    // legend
    const leg = [["Deterministic", C.accent3], ["ML detectors (roadmap)", C.accent4], ["LLM wording only", C.accent2], ["Delivery", C.accent1]];
    leg.forEach((l, i) => {
      const x = 0.6 + i * 3.1;
      s.addShape(pres.ShapeType.ellipse, { x, y: 4.82, w: 0.28, h: 0.28, fill: { color: l[1] }, line: { type: "none" }, objectName: "legend-dot" });
      text(s, l[0], { x: x + 0.4, y: 4.75, w: 2.5, h: 0.42, fontSize: 16, color: C.text1, valign: "middle" });
    });
    card(s, 0.6, 5.5, 12.1, 1.3);
    text(s, "Key rule: detection is never decided by an LLM. Rules and statistics decide; the model only writes the words.", {
      x: 0.95, y: 5.5, w: 11.4, h: 1.3, fontSize: 20, bold: true, color: C.text1, valign: "middle",
    });
  }

  // ---------------------------------------------------------------- 7 detector cascade
  {
    const s = content(
      "A cascade of detectors, one job each",
      "Be precise about status. Built and running today: static rules, periodicity analysis for beaconing, and the pluggable LLM that writes the alert text (Gemma 4 E2B is the intended default model, served by Ollama or llama.cpp). " +
        "The Isolation Forest per-device baseline, the n-gram domain-name model and the autoencoder are designed and specified but are the roadmap, not shipped yet."
    );
    const rows = [
      [fa.FaTools, "Static rules", "Port scans, brute force, DNS entropy / length / TXT signals", "BUILT", C.accent3],
      [fa.FaHeartbeat, "Periodicity analysis", "Beaconing: how regular are the connection intervals (jitter)?", "BUILT", C.accent3],
      [fa.FaBrain, "Isolation Forest", "Per-device 'unusual for this device' baseline", "ROADMAP", C.accent4],
      [fa.FaFileAlt, "n-gram model", "Random-looking domain names (DGA, tunnel payloads)", "ROADMAP", C.accent4],
      [fa.FaNetworkWired, "Autoencoder", "Second opinion: traffic the model cannot reconstruct", "ROADMAP", C.accent4],
      [fa.FaRobot, "LLM – Gemma 4 E2B (default target)", "Writes the alert in plain English; never decides", "BUILT · PLUGGABLE", C.accent2],
    ];
    for (let i = 0; i < rows.length; i++) {
      const y = 1.5 + i * 0.86;
      card(s, 0.6, y, 12.1, 0.74);
      await circleIcon(s, 0.75, y + 0.09, 0.56, rows[i][0], rows[i][4]);
      text(s, rows[i][1], { x: 1.55, y, w: 3.7, h: 0.74, fontSize: 17, bold: true, color: C.text1, valign: "middle" });
      text(s, rows[i][2], { x: 5.3, y, w: 5.0, h: 0.74, fontSize: 14, color: C.accent6, valign: "middle" });
      chip(s, 10.45, y + 0.15, 2.1, 0.44, rows[i][3], rows[i][4], rows[i][4] === C.accent2 ? C.text1 : C.background1, 12);
    }
    text(s, "Agreement between detectors raises confidence; one detector alone lowers it.", {
      x: 0.6, y: 6.7, w: 12.1, h: 0.3, fontSize: 14, italic: true, color: C.accent6,
    });
  }

  // ---------------------------------------------------------------- 8 four attacks
  {
    const s = content(
      "Four attack patterns caught today",
      "Each card shows what the detector looks for in a single 10-second window and what we measured in the live localhost demo. " +
        "Port scan: hundreds of ports, almost all closed. Brute force: many accepted connections to a login service. Beaconing: connections at near-perfectly regular intervals. DNS tunnelling: long random names to one domain."
    );
    const cards = [
      [fa.FaSearch, C.accent1, "Port scan", "T1046", "20+ ports or hosts, 60%+ of attempts fail", "Demo: 400 ports, 99.75% failed"],
      [fa.FaKey, C.accent2, "Brute force", "T1110", "8+ connections to a login service, mostly accepted", "Demo: 21 logins to port 2222"],
      [fa.FaHeartbeat, C.accent4, "Beaconing", "T1071.001", "10+ accepted connections, jitter under 15%", "Demo: 13 check-ins, 1.0003 s apart"],
      [fa.FaGlobe, C.accent3, "DNS tunnel", "T1071.004", "10+ lookups with 2 of 4 signals: entropy, length, subdomains, TXT", "Demo: 14 TXT lookups, names 67 chars"],
    ];
    for (let i = 0; i < 4; i++) {
      const col = i % 2, row = Math.floor(i / 2);
      const x = 0.6 + col * 6.15, y = 1.55 + row * 2.8;
      card(s, x, y, 5.95, 2.6);
      await circleIcon(s, x + 0.3, y + 0.3, 0.9, cards[i][0], cards[i][1]);
      text(s, cards[i][2], { x: x + 1.4, y: y + 0.28, w: 2.9, h: 0.5, fontSize: 22, bold: true, color: C.text1 });
      chip(s, x + 4.4, y + 0.33, 1.3, 0.4, cards[i][3], C.accent6, C.background1, 12);
      text(s, cards[i][4], { x: x + 1.4, y: y + 0.85, w: 4.3, h: 0.8, fontSize: 15, color: C.accent6, valign: "top" });
      text(s, cards[i][5], { x: x + 0.3, y: y + 1.85, w: 5.4, h: 0.5, fontSize: 17, bold: true, color: C.accent1, valign: "middle" });
    }
  }

  // ---------------------------------------------------------------- 9 three clocks (chart)
  {
    const s = content(
      "Three clocks catch fast and slow attackers",
      "Sentinel looks at every device over 10 seconds, 5 minutes and 1 hour at the same time. A fast scan (400 ports in a second) trips all of them. " +
        "A patient scanner sending four probes a minute never trips the 10-second window: it only touches about one port there. But over five minutes it has touched about twenty ports, and over an hour about two hundred and forty, so the longer windows catch it. " +
        "This is verified by an automated test that fails if only the 10-second window is enabled."
    );
    const cats = ["10 seconds", "5 minutes", "1 hour"];
    addChart(
      s, pres.charts.BAR,
      [
        { name: "Alert threshold", labels: cats, values: [20, 15, 60] },
        { name: "Fast scan: 400 ports in 1 s", labels: cats, values: [400, 400, 400] },
        { name: "Slow scan: 4 probes a minute", labels: cats, values: [1, 20, 240] },
      ],
      {
        x: 0.6, y: 1.5, w: 8.0, h: 5.3, barDir: "col", barGrouping: "clustered", barGapWidthPct: 50,
        chartColors: [H.accent2, H.accent1, H.accent3], valAxisLogScaleBase: 10, valAxisMinVal: 1, valAxisMaxVal: 1000,
        showLegend: true, legendPos: "b", showValue: true, dataLabelPosition: "outEnd",
        ...chartBase("Distinct ports probed per window (log scale)"),
      },
      "chart_clocks.png",
      "Bar chart: ports probed per 10 s, 5 min and 1 h window for fast and slow scans vs the alert threshold"
    );
    card(s, 8.95, 1.6, 3.75, 5.0);
    text(s, "Why it matters", { x: 9.25, y: 1.85, w: 3.2, h: 0.5, fontSize: 20, bold: true, color: C.text1 });
    text(s, [
      { text: "A slow scan stays under the 10 s threshold: about 1 port.", options: { bullet: true, breakLine: true } },
      { text: "The 5 min and 1 h windows see 20 and 240 ports and fire.", options: { bullet: true, breakLine: true } },
      { text: "Fast attacks are caught within seconds; slow ones still get caught.", options: { bullet: true } },
    ], { x: 9.25, y: 2.45, w: 3.25, h: 3.9, fontSize: 16, color: C.text1, valign: "top", paraSpaceAfter: 10 });
  }

  // ---------------------------------------------------------------- 10 results (chart + tiles)
  {
    const s = content(
      "Tested live: attacks caught, noise silent",
      "These are measured. In a live localhost run with only the 10-second window enabled and notifications off, all four attacks were detected and the control (ordinary web traffic) raised nothing. " +
        "Alert time depends on where the 10-second evaluation grid falls, so individual runs ranged from about 1 to 12 seconds. " +
        "The tiles on the right come from the automated test suite: a 12-seed soak of random benign networks produced no alerts, and short attack bursts were caught at all 12 phases of the grid."
    );
    addChart(
      s, pres.charts.BAR,
      [{ name: "Seconds", labels: ["DNS tunnel", "Brute force", "Port scan", "Beaconing"], values: [1.7, 8.5, 8.9, 12.1] }],
      {
        x: 0.6, y: 1.5, w: 6.4, h: 5.2, barDir: "bar", barGapWidthPct: 50, chartColors: [H.accent1],
        showLegend: false, showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0.0",
        valAxisMinVal: 0, valAxisMaxVal: 15, ...chartBase("Seconds until the alert (reference live run)"),
      },
      "chart_results.png",
      "Bar chart: seconds until the alert for each attack in the live run"
    );
    const tiles = [
      ["4 / 4", "attacks detected live", C.accent1],
      ["0", "alerts on normal web traffic", C.accent3],
      ["48 / 48", "grid-phase checks passed", C.accent4],
      ["0", "false alarms, 12 benign networks", C.accent2],
    ];
    tiles.forEach((t, i) => {
      const col = i % 2, row = Math.floor(i / 2);
      const x = 7.3 + col * 2.75, y = 1.6 + row * 2.45;
      card(s, x, y, 2.55, 2.3);
      text(s, t[0], { x: x + 0.1, y: y + 0.3, w: 2.35, h: 1.0, fontSize: 40, bold: true, color: t[2], align: "center", valign: "middle" });
      text(s, t[1], { x: x + 0.2, y: y + 1.35, w: 2.15, h: 0.85, fontSize: 15, color: C.text1, align: "center", valign: "top" });
    });
    text(s, "Localhost run, 10-second window only, notifications off. Alert time varies with the 10 s grid.", {
      x: 7.3, y: 6.5, w: 5.4, h: 0.45, fontSize: 12, color: C.accent6, valign: "top",
    });
  }

  // ---------------------------------------------------------------- 11 dashboard mock
  {
    const s = content(
      "Criticals stay pinned on top",
      "This is the live dashboard, started with watch -d. Every CRITICAL alert gets its own pinned line the moment it is reported and stays there, newest on top, so it can never scroll away in the traffic. " +
        "The CRIT counter in the header counts each one. The grey traffic below is a sliding window that fills the rest of the terminal and adapts when you resize it. q quits, c clears the pins."
    );
    const x0 = 0.6, y0 = 1.5, w0 = 8.3, h0 = 5.25;
    s.addShape(pres.ShapeType.roundRect, { x: x0, y: y0, w: w0, h: h0, rectRadius: 0.08, fill: { color: C.text1 }, line: { color: C.accent6, width: 1 }, objectName: "terminal" });
    const mono = { fontFace: "Courier New", fontSize: 12 };
    // header bar (reverse video)
    s.addShape(pres.ShapeType.rect, { x: x0 + 0.12, y: y0 + 0.12, w: w0 - 0.24, h: 0.34, fill: { color: C.background2 }, line: { type: "none" }, objectName: "term-header" });
    text(s, "SENTINEL | watch lo0 | 01:12 | events 4183 | CRIT 4 | q quit  c clear", { x: x0 + 0.2, y: y0 + 0.12, w: w0 - 0.4, h: 0.34, color: C.text1, valign: "middle", ...mono });
    text(s, "PINNED: CRITICAL ALERTS (4)  every one stays; newest on top", { x: x0 + 0.2, y: y0 + 0.58, w: w0 - 0.4, h: 0.32, bold: true, color: C.accent1, valign: "middle", ...mono });
    const pins = [
      ["23:52:00", "Unusual DNS requests that may hide data"],
      ["23:51:40", "Device contacts one server at fixed intervals"],
      ["23:51:10", "Repeated login attempts against a service"],
      ["23:51:00", "Device is probing many network ports"],
    ];
    pins.forEach((p, i) => {
      const y = y0 + 0.96 + i * 0.36;
      s.addShape(pres.ShapeType.rect, { x: x0 + 0.2, y, w: 1.55, h: 0.32, fill: { color: C.accent1 }, line: { type: "none" }, objectName: "badge" });
      text(s, "CRITICAL 1.00", { x: x0 + 0.2, y, w: 1.55, h: 0.32, bold: true, color: C.background1, align: "center", valign: "middle", ...mono });
      text(s, p[0] + "  " + p[1], { x: x0 + 1.9, y, w: w0 - 2.1, h: 0.32, bold: true, color: C.accent1, valign: "middle", ...mono, fontSize: 11 });
    });
    text(s, "RECENT TRAFFIC (sliding window)", { x: x0 + 0.2, y: y0 + 2.5, w: w0 - 0.4, h: 0.32, bold: true, color: C.background1, valign: "middle", ...mono });
    const traffic = [
      "23:52:01.220 127.0.0.1:55012 -> 127.0.0.1:53 udp  dns? x7k2...",
      "23:52:01.331 127.0.0.1:55013 -> 127.0.0.1:53 udp  dns? q9m4...",
      "23:52:01.442 127.0.0.1:55014 -> 127.0.0.1:53 udp  dns? b3zt...",
      "23:52:01.553 127.0.0.1:55015 -> 127.0.0.1:53 udp  dns? h8w1...",
      "23:52:01.664 127.0.0.1:55016 -> 127.0.0.1:53 udp  dns? n5r6...",
      "23:52:01.775 127.0.0.1:55017 -> 127.0.0.1:53 udp  dns? c2v0...",
      "23:52:01.886 127.0.0.1:55018 -> 127.0.0.1:53 udp  dns? p4d8...",
    ];
    traffic.forEach((t, i) =>
      text(s, t, { x: x0 + 0.2, y: y0 + 2.86 + i * 0.31, w: w0 - 0.4, h: 0.3, color: C.accent5, valign: "middle", ...mono, fontSize: 11 })
    );
    const callouts = [
      ["Pinned", "Every critical alert stacks, newest on top, and stays until you clear it."],
      ["Counter", "CRIT goes up by one for each critical alert."],
      ["Sliding window", "Recent traffic fills the rest of the screen and adapts to the terminal size."],
    ];
    callouts.forEach((c, i) => {
      const y = 1.6 + i * 1.75;
      s.addShape(pres.ShapeType.ellipse, { x: 9.3, y, w: 0.6, h: 0.6, fill: { color: C.accent1 }, line: { type: "none" }, objectName: "num" });
      text(s, String(i + 1), { x: 9.3, y, w: 0.6, h: 0.6, fontSize: 20, bold: true, color: C.background1, align: "center", valign: "middle" });
      text(s, c[0], { x: 10.1, y: y - 0.02, w: 2.6, h: 0.4, fontSize: 19, bold: true, color: C.text1, valign: "middle" });
      text(s, c[1], { x: 10.1, y: y + 0.42, w: 2.6, h: 1.1, fontSize: 14, color: C.accent6, valign: "top" });
    });
  }

  // ---------------------------------------------------------------- 12 alert path
  {
    const s = content(
      "From incident to Slack, safely",
      "How an alert is made. The incident goes through a sanitizer, so hostile text from the network such as DNS names never reaches the model or chat. " +
        "A local LLM, Gemma 4 E2B as the default target served through Ollama or llama.cpp, writes the explanation as structured JSON. " +
        "A faithfulness check rejects any number, IP address or technique that is not in the evidence, and then Sentinel falls back to built-in template text. " +
        "The result goes to Slack, Discord and Telegram, with retries, a circuit breaker and rate limits. Mentions are disabled."
    );
    const steps = [
      ["Incident", "from the rules", C.accent6],
      ["Sanitizer", "only validated numbers and addresses pass", C.accent3],
      ["Gemma 4 E2B", "local LLM via Ollama or llama.cpp", C.accent2],
      ["Faithfulness check", "numbers, IPs, techniques must match evidence", C.accent3],
    ];
    const bw = 2.1, gap = 0.35;
    steps.forEach((st, i) => {
      const x = 0.6 + i * (bw + gap);
      s.addShape(pres.ShapeType.roundRect, { x, y: 1.6, w: bw, h: 1.15, rectRadius: 0.1, fill: { color: st[2] }, line: { type: "none" }, objectName: "step" });
      text(s, st[0], { x, y: 1.6, w: bw, h: 1.15, fontSize: 18, bold: true, color: st[2] === C.accent2 ? C.text1 : C.background1, align: "center", valign: "middle" });
      text(s, st[1], { x: x - 0.05, y: 2.85, w: bw + 0.1, h: 0.75, fontSize: 13, color: C.accent6, align: "center", valign: "top" });
      arrow(s, x + bw + 0.02, 2.18, x + bw + gap - 0.02);
    });
    // channels
    const chx = 0.6 + 4 * (bw + gap);
    const chans = [[fa.FaSlack, "Slack"], [fa.FaDiscord, "Discord"], [fa.FaTelegramPlane, "Telegram"]];
    for (let i = 0; i < 3; i++) {
      const y = 1.5 + i * 0.72;
      s.addShape(pres.ShapeType.roundRect, { x: chx, y, w: 2.3, h: 0.6, rectRadius: 0.1, fill: { color: C.text1 }, line: { type: "none" }, objectName: "channel" });
      s.addImage({ data: await icon(chans[i][0], "FFFFFF"), x: chx + 0.15, y: y + 0.12, w: 0.36, h: 0.36, altText: chans[i][1] });
      text(s, chans[i][1], { x: chx + 0.65, y, w: 1.6, h: 0.6, fontSize: 17, bold: true, color: C.background1, valign: "middle" });
    }
    // fallback
    card(s, 0.6, 3.75, 4.15, 0.95, { fill: C.background2 });
    text(s, "Model off, slow or wrong?", { x: 0.85, y: 3.78, w: 3.8, h: 0.4, fontSize: 15, bold: true, color: C.accent1, valign: "middle" });
    text(s, "Built-in template text, same facts", { x: 0.85, y: 4.2, w: 3.8, h: 0.4, fontSize: 15, color: C.text1, valign: "middle" });
    // sample message
    card(s, 5.0, 3.75, 7.7, 2.95, { fill: C.background2 });
    chip(s, 5.3, 4.0, 1.5, 0.4, "CRITICAL", C.accent1, C.background1, 13);
    text(s, "Device is probing many network ports", { x: 6.95, y: 4.0, w: 5.6, h: 0.4, fontSize: 18, bold: true, color: C.text1, valign: "middle" });
    text(s, "192.168.2.30 tried 400 different ports on 192.168.2.20 within 10 seconds, and 100% of the attempts failed.", {
      x: 5.3, y: 4.6, w: 7.2, h: 0.8, fontSize: 15, color: C.text1, valign: "top",
    });
    text(s, "Suggested: if you do not recognise this activity, disconnect the device.", {
      x: 5.3, y: 5.45, w: 7.2, h: 0.5, fontSize: 15, color: C.accent6, valign: "top",
    });
    text(s, "T1046 Network Service Discovery · Confidence 100%", { x: 5.3, y: 6.1, w: 7.2, h: 0.4, fontSize: 13, color: C.accent5, valign: "middle" });
    text(s, "Retries, circuit breaker, rate limits and disabled @mentions on every channel.", {
      x: 0.6, y: 4.9, w: 4.15, h: 1.6, fontSize: 14, color: C.accent6, valign: "top",
    });
  }

  // ---------------------------------------------------------------- 13 safety
  {
    const s = content(
      "Safe by design",
      "This is a security product, so it treats the network as hostile. It only observes. DNS names and host names can be crafted by an attacker, so they never reach the LLM, chat or the screen unescaped. " +
        "No payloads are stored. Secrets live in a private file. Every sentence the model writes is checked against the evidence."
    );
    const tiles = [
      [fa.FaEye, C.accent3, "Observe only", "Never blocks or changes the network."],
      [fa.FaLock, C.accent4, "Hostile-text proof", "Network strings never reach the LLM, chat or terminal unescaped."],
      [fa.FaDatabase, C.accent2, "No payloads", "Stores alerts and summaries, not packet contents."],
      [fa.FaKey, C.accent1, "Secrets stay private", "Webhook URLs and tokens in a chmod 600 file, never printed."],
      [fa.FaServer, C.accent3, "Local-first", "The LLM runs on your machine; only alerts you choose leave."],
      [fa.FaCheckCircle, C.accent4, "Claims are checked", "Model text is rejected if it invents a number, IP or technique."],
    ];
    for (let i = 0; i < 6; i++) {
      const col = i % 3, row = Math.floor(i / 3);
      const x = 0.6 + col * 4.1, y = 1.55 + row * 2.7;
      card(s, x, y, 3.8, 2.5);
      await circleIcon(s, x + 0.3, y + 0.3, 0.8, tiles[i][0], tiles[i][1]);
      text(s, tiles[i][2], { x: x + 1.3, y: y + 0.3, w: 2.35, h: 0.8, fontSize: 19, bold: true, color: C.text1, valign: "middle" });
      text(s, tiles[i][3], { x: x + 0.3, y: y + 1.3, w: 3.25, h: 1.1, fontSize: 17, color: C.accent6, valign: "top" });
    }
  }

  // ---------------------------------------------------------------- 14 how to run
  {
    const s = content(
      "How to run it",
      "Five commands. Install, check, start the monitor in one console, launch the attacks in a second console, and review the incidents. " +
        "To get chat alerts, fill secrets.env and add -n. To get LLM-written text, enable the [llm] section and run sentinel llm test. Everything runs on localhost for the demo. For repeated rehearsals of the same attack use --config demo-10s.toml, which shortens the alert cooldown."
    );
    const steps = [
      ["Install", "make bootstrap"],
      ["Check", "uv run sentinel doctor"],
      ["Monitor", "uv run sentinel watch --iface lo0 -d"],
      ["Attack (2nd console)", "uv run python tools/demo_attacks.py"],
      ["Review", "uv run sentinel incidents"],
    ];
    steps.forEach((st, i) => {
      const y = 1.55 + i * 1.02;
      s.addShape(pres.ShapeType.ellipse, { x: 0.6, y: y + 0.1, w: 0.62, h: 0.62, fill: { color: C.accent1 }, line: { type: "none" }, objectName: "num" });
      text(s, String(i + 1), { x: 0.6, y: y + 0.1, w: 0.62, h: 0.62, fontSize: 20, bold: true, color: C.background1, align: "center", valign: "middle" });
      text(s, st[0], { x: 1.45, y, w: 2.5, h: 0.82, fontSize: 17, bold: true, color: C.text1, valign: "middle" });
      s.addShape(pres.ShapeType.roundRect, { x: 3.9, y: y + 0.06, w: 5.2, h: 0.7, rectRadius: 0.06, fill: { color: C.text1 }, line: { type: "none" }, objectName: "code" });
      text(s, st[1], { x: 4.05, y: y + 0.06, w: 4.95, h: 0.7, fontFace: "Courier New", fontSize: 14, color: C.accent3, valign: "middle" });
    });
    card(s, 9.4, 1.55, 3.3, 5.0);
    text(s, "Optional add-ons", { x: 9.65, y: 1.75, w: 2.9, h: 0.45, fontSize: 19, bold: true, color: C.text1 });
    text(s, [
      { text: "Chat alerts: fill secrets.env, add -n", options: { bullet: true, breakLine: true } },
      { text: "LLM text: enable [llm], run sentinel llm test", options: { bullet: true, breakLine: true } },
      { text: "Offline demo: sentinel replay demo.pcap -d", options: { bullet: true, breakLine: true } },
      { text: "Narrated attacks: demo_attacks.py", options: { bullet: true } },
    ], { x: 9.65, y: 2.35, w: 2.9, h: 4.0, fontSize: 15, color: C.accent6, valign: "top", paraSpaceAfter: 10 });
  }

  // ---------------------------------------------------------------- 15 how it's meant to be used
  {
    const s = content(
      "How it's meant to be used",
      "The daily loop. Install it on the gateway once. Leave the dashboard or the background monitor running. When an alert arrives on chat, look at the incident, then acknowledge, dismiss or resolve it. " +
        "If a legitimate device keeps alerting, add it to the allow-lists so the next alert means something."
    );
    const loop = [
      [fa.FaServer, C.accent4, "Install", "on the gateway Mac"],
      [fa.FaEye, C.accent3, "Watch", "dashboard or background"],
      [fa.FaBell, C.accent1, "Get alerted", "Slack, Discord, Telegram"],
      [fa.FaCheckCircle, C.accent2, "Triage", "ack, dismiss, resolve"],
      [fa.FaTools, C.accent6, "Tune", "allow-lists for known-good"],
    ];
    const bw = 2.1, gap = 0.4;
    for (let i = 0; i < 5; i++) {
      const x = 0.6 + i * (bw + gap);
      card(s, x, 1.6, bw, 2.5);
      await circleIcon(s, x + 0.55, 1.85, 1.0, loop[i][0], loop[i][1]);
      text(s, loop[i][2], { x, y: 3.0, w: bw, h: 0.45, fontSize: 19, bold: true, color: C.text1, align: "center" });
      text(s, loop[i][3], { x: x + 0.1, y: 3.45, w: bw - 0.2, h: 0.55, fontSize: 13, color: C.accent6, align: "center", valign: "top" });
      if (i < 4) arrow(s, x + bw + 0.02, 2.85, x + bw + gap - 0.02);
    }
    // return path
    s.addShape(pres.ShapeType.line, { x: 0.6 + 4 * (bw + gap) + bw / 2, y: 4.1, w: 0, h: 0.45, line: { color: C.accent5, width: 2.5 }, objectName: "loop-line" });
    s.addShape(pres.ShapeType.line, { x: 0.6 + bw / 2 + (bw + gap), y: 4.55, w: 3 * (bw + gap), h: 0, flipH: true, line: { color: C.accent5, width: 2.5 }, objectName: "loop-line" });
    arrowDown(s, 0.6 + bw / 2 + (bw + gap), 4.55, 4.12);
    text(s, "repeat", { x: 5.5, y: 4.62, w: 2.3, h: 0.35, fontSize: 13, italic: true, color: C.accent6, align: "center" });
    const modes = [
      ["Replay a capture", "sentinel replay file.pcap"],
      ["Watch live", "sentinel watch --iface en0"],
      ["Full-screen dashboard", "add -d"],
      ["Send alerts", "add -n"],
    ];
    modes.forEach((m, i) => {
      const x = 0.6 + i * 3.08;
      card(s, x, 5.3, 2.9, 1.35);
      text(s, m[0], { x: x + 0.2, y: 5.4, w: 2.5, h: 0.5, fontSize: 16, bold: true, color: C.text1, valign: "middle" });
      text(s, m[1], { x: x + 0.2, y: 5.95, w: 2.5, h: 0.5, fontFace: "Courier New", fontSize: 12, color: C.accent1, valign: "middle" });
    });
  }

  // ---------------------------------------------------------------- 16 status
  {
    const s = content(
      "Where it stands today",
      "Be upfront. Verified: the detectors, the CLI and the dashboard work on real loopback traffic, backed by a large automated test suite. " +
        "Built but not yet exercised for real: delivery to real Slack, Discord and Telegram accounts, a real Gemma 4 E2B model server, and capture on a gateway with other devices. " +
        "Next: the ML detectors (Isolation Forest, n-gram, autoencoder), ARP spoofing, rogue DHCP, canary tripwires and a web interface."
    );
    const cols = [
      ["Verified", C.accent3, [
        "Live capture on localhost",
        "4 attack patterns + a silent control",
        "Pinned live dashboard",
        "327 automated tests, all passing",
      ]],
      ["Built, awaiting a real-world run", C.accent2, [
        "Slack, Discord, Telegram delivery",
        "Gemma 4 E2B via Ollama / llama.cpp",
        "Gateway capture with other devices",
      ]],
      ["Next", C.accent4, [
        "Isolation Forest baselines",
        "n-gram domain model",
        "Autoencoder second opinion",
        "ARP spoofing, rogue DHCP, canary",
        "Web interface",
      ]],
    ];
    cols.forEach((c, i) => {
      const x = 0.6 + i * 4.1;
      card(s, x, 1.6, 3.8, 5.0);
      s.addShape(pres.ShapeType.roundRect, { x, y: 1.6, w: 3.8, h: 0.75, rectRadius: 0.08, fill: { color: c[1] }, line: { type: "none" }, objectName: "col-head" });
      text(s, c[0], { x: x + 0.2, y: 1.6, w: 3.4, h: 0.75, fontSize: 18, bold: true, color: c[1] === C.accent2 ? C.text1 : C.background1, valign: "middle" });
      text(s, c[2].map((t, k) => ({ text: t, options: { bullet: true, breakLine: k < c[2].length - 1 } })), {
        x: x + 0.25, y: 2.6, w: 3.35, h: 3.8, fontSize: 18, color: C.text1, valign: "top", paraSpaceAfter: 14,
      });
    });
  }

  // ---------------------------------------------------------------- 17 closing
  {
    const s = pres.addSlide({ masterName: "DARK" });
    s.addNotes("Close with the demo: start the dashboard in one console, run the narrated attack script in the other, and let the pinned red alerts do the talking.");
    const cx = 10.6, cy = 3.75;
    [3.2, 2.2, 1.2].forEach((d, i) =>
      s.addShape(pres.ShapeType.ellipse, { x: cx - d / 2, y: cy - d / 2, w: d, h: d, fill: { type: "none" }, line: { color: C.accent6, width: 1.5 - i * 0.3 }, objectName: "radar-ring" })
    );
    s.addShape(pres.ShapeType.ellipse, { x: cx - 0.4, y: cy - 0.4, w: 0.8, h: 0.8, fill: { color: C.accent1 }, line: { type: "none" }, objectName: "radar-core" });
    s.addImage({ data: await icon(fa.FaPlay, "FFFFFF"), x: cx - 0.17, y: cy - 0.2, w: 0.4, h: 0.4, altText: "play" });
    text(s, "Demo time", { x: 0.8, y: 1.8, w: 8, h: 1.3, fontSize: 60, bold: true, fontFace: "Cambria", color: C.background1, valign: "middle" });
    text(s, "Watch four attacks turn into four red alerts, live.", { x: 0.8, y: 3.2, w: 8, h: 0.8, fontSize: 24, color: C.accent3, valign: "top" });
    s.addShape(pres.ShapeType.roundRect, { x: 0.8, y: 4.5, w: 7.6, h: 0.75, rectRadius: 0.06, fill: { color: C.accent6 }, line: { type: "none" }, objectName: "code" });
    text(s, "uv run sentinel watch --iface lo0 -d", { x: 1.0, y: 4.5, w: 7.3, h: 0.75, fontFace: "Courier New", fontSize: 15, color: C.background1, valign: "middle" });
    s.addShape(pres.ShapeType.roundRect, { x: 0.8, y: 5.4, w: 7.6, h: 0.75, rectRadius: 0.06, fill: { color: C.accent6 }, line: { type: "none" }, objectName: "code" });
    text(s, "uv run python tools/demo_attacks.py", { x: 1.0, y: 5.4, w: 7.3, h: 0.75, fontFace: "Courier New", fontSize: 15, color: C.background1, valign: "middle" });
  }

  const out = path.join(__dirname, IMAGE_CHARTS ? "Sentinel_Pitch_Keynote_safe.pptx" : "Sentinel_Pitch.pptx");
  await pres.writeFile({ fileName: out });
  await applyTheme(out, THEME);
  console.log("wrote", out);
}

build().catch((e) => {
  console.error(e);
  process.exit(1);
});
