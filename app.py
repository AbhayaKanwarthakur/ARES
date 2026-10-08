"""Adaptive Security Agent - SOC dashboard.   Run:  streamlit run app.py

Everything here is a SIMULATION: traffic is synthetic, the 'demo app' runs in-process,
and every defensive action is recorded in a local SQLite table. No network is touched.
"""
import html
import json
import os
import time

import pandas as pd
import streamlit as st

from agent.detector import MODEL_PATH, ensure_model
from agent.learner import adaptation_stats, pending_count, retrain
from agent.memory import Memory
from agent.pipeline import run_agent
from agent.simulator import KINDS, LOG_PATH, DemoApp, generate_events, new_batch_id, new_ip

st.set_page_config(page_title="Adaptive Security Agent - SOC", layout="wide")

CSS = """
<style>
.block-container{padding-top:1.2rem}
:root{color-scheme:light;--green-900:#14532d;--green-800:#166534;--green-700:#15803d;--green-600:#16a34a;--green-100:#dcfce7;--green-50:#f0fdf4;--ink:#173322;--muted:#5d7565;--line:#d8e6dc;--canvas:#f5faf6}
.stApp,[data-testid="stAppViewContainer"]{background:var(--canvas);color:var(--ink)}
[data-testid="stHeader"]{background:transparent}
[data-testid="stSidebar"]{background:var(--green-50);border-right:1px solid var(--line)}
.block-container{color:var(--ink)}
.hdr{display:flex;align-items:center;gap:14px;margin-bottom:6px}
.hdr h1{margin:0;font-size:1.6rem;color:var(--green-900)}
.live{display:inline-flex;align-items:center;gap:7px;color:var(--green-800);font-size:.8rem;border:1px solid #86c99b;border-radius:20px;padding:4px 10px;background:#fff}
.live:before{content:"";width:7px;height:7px;border-radius:50%;background:var(--green-600)}
.kpi{background:#fff;color:var(--ink);border:1px solid var(--line);border-top:3px solid var(--green-600);border-radius:8px;padding:10px 14px;height:112px;min-height:112px;box-sizing:border-box;overflow:hidden;box-shadow:0 1px 3px #14532d0c}
.kpi-l{font-size:.68rem;letter-spacing:1.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kpi-v{font-size:1.35rem;font-weight:700;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kpi-v--long{font-size:.98rem}
.kpi-s{font-size:.72rem;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.stHorizontalBlock:has(.kpi){display:grid!important;grid-template-columns:repeat(auto-fit,minmax(min(100%,150px),1fr));gap:12px}
.stHorizontalBlock:has(.kpi)>[data-testid="stColumn"]{width:auto!important;min-width:0!important;flex:none!important;padding:0!important}
@media(max-width:600px){.stHorizontalBlock:has(.kpi){grid-template-columns:1fr}}
.step{background:#fff;color:var(--ink);border:1px solid var(--line);border-left:4px solid var(--green-600);border-radius:6px;padding:8px 14px}
.step-detect{border-left-color:#65a30d}.step-analyze{border-left-color:#15803d}.step-decide{border-left-color:#84cc16}
.step-defend{border-left-color:#16a34a}.step-memory{border-left-color:#4d7c0f}.step-learn{border-left-color:#22c55e}
.step-retrain{border-left-color:#14532d}
.step-t{font-weight:700;letter-spacing:.5px;font-size:.88rem}
.step ul{margin:4px 0 2px 18px;padding:0;font-size:.82rem;color:var(--ink)}
.arrow{height:8px;width:0;border-left:2px solid #86c99b;margin:0 auto}
.tl{background:#fff;color:var(--ink);border:1px solid var(--line);border-left:5px solid var(--green-600);border-radius:6px;padding:8px 14px;margin-bottom:8px}
.tl-h{font-weight:700;margin-bottom:2px}.tl-l{font-size:.85rem;color:var(--muted)}
.tag{font-size:.65rem;border-radius:10px;padding:1px 8px;margin-left:8px;border:1px solid currentColor}
.cmp{background:#fff;border:1px solid var(--line);border-radius:8px;padding:12px 16px}
.stButton>button{border-color:#86c99b;color:var(--green-800);background:#fff}
.stButton>button:hover{border-color:var(--green-700);color:var(--green-900);background:var(--green-50)}
button[kind="primary"],[data-testid="stBaseButton-primary"]{background:var(--green-700);border-color:var(--green-700);color:#fff}
button[kind="primary"]:hover,[data-testid="stBaseButton-primary"]:hover{background:var(--green-800);border-color:var(--green-800);color:#fff}
</style>
"""
RISK_COLOR = {"HIGH": "#dc2626", "MEDIUM": "#ca8a04", "LOW": "#15803d"}
PATH_COLOR = {"FULL_ANALYSIS": "#14532d", "STANDARD": "#65a30d", "FAST_MEMORY": "#16a34a", "BASELINE": "#64776b"}
esc = lambda x: html.escape(str(x))


def kpi(label, value, sub="", color="#e6edf3"):
    value = str(value)
    value_class = " kpi-v--long" if len(value) > 12 else ""
    return (f'<div class="kpi"><div class="kpi-l">{label}</div>'
            f'<div class="kpi-v{value_class}" title="{esc(value)}" style="color:{color}">{esc(value)}</div>'
            f'<div class="kpi-s" title="{esc(sub)}">{esc(sub)}</div></div>')


def steps_html(steps):
    out = []
    for i, s in enumerate(steps):
        lis = "".join(f"<li>{esc(l)}</li>" for l in s["lines"] if l)
        out.append(f'<div class="step step-{s["key"]}"><div class="step-t">{esc(s["title"])}</div><ul>{lis}</ul></div>')
        if i < len(steps) - 1:
            out.append('<div class="arrow" aria-hidden="true"></div>')
    return "".join(out)


def timeline_html(rows):
    cards = []
    for r in rows:
        tl = json.loads(r["timeline"]) if isinstance(r["timeline"], str) else []
        col = PATH_COLOR.get(r["path"], "#888")
        lines = "".join(f'<div class="tl-l">{esc(l)}</div>' for l in tl)
        cards.append(f'<div class="tl" style="border-left-color:{col}"><div class="tl-h">Attack #{r["id"]}'
                     f'<span class="tag" style="color:{col}">{esc(r["path"])}</span></div>{lines}</div>')
    return "".join(cards)


# --------------------------------------------------------------------------- setup
if not os.path.exists(MODEL_PATH):
    with st.spinner("First run: generating the synthetic dataset and training the baseline model..."):
        ensure_model()
mem = Memory()
ss = st.session_state
for k, v in {"last": None, "last_events": None, "last_ip": None, "last_kind": None, "flash": None}.items():
    ss.setdefault(k, v)
st.markdown(CSS, unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## Controls")
    pace = st.toggle("Show agent 'thinking' delay", value=True,
                     help="Cosmetic pacing so the audience can follow each step. Turn off for raw speed.")
    every = st.slider("Auto-retrain model every N labelled experiences (0 = off)", 0, 30, 10)
    st.caption(f"Pending labelled experiences: **{pending_count(mem)}**")
    if st.button("Retrain model now"):
        res = retrain(mem, "manual")
        ss.flash = ("Retrained: holdout accuracy %.1f%%, experiences %.0f%% -> %.0f%%" %
                    (100 * res["holdout_acc"], 100 * res["exp_acc_before"], 100 * res["exp_acc_after"])
                    if res else "No labelled experiences yet - run some attacks first.")
        st.rerun()
    st.divider()
    sure = st.checkbox("Yes, wipe memory and model")
    if st.button("Reset memory and model") and sure:
        mem.reset()
        for f in (LOG_PATH, MODEL_PATH):
            if os.path.exists(f):
                os.remove(f)
        ensure_model()
        ss.last = ss.last_events = ss.last_ip = None
        ss.flash = "Memory wiped and baseline model re-trained."
        st.rerun()
    st.caption("All attacks are synthetic and run inside a local in-process sandbox. "
               "Defences are simulated (a SQLite table). Nothing leaves this machine.")

st.markdown('<div class="hdr"><h1>ADAPTIVE SECURITY AGENT</h1><span class="live">SOC LIVE</span></div>', unsafe_allow_html=True)
if ss.flash:
    st.success(ss.flash)
    ss.flash = None

# --------------------------------------------------------------------------- KPI row
li = mem.latest_incident()
stats = adaptation_stats(mem)
cols = st.columns(6)
if li:
    rc = RISK_COLOR.get(li["risk"], "#e6edf3")
    cells = [("THREAT LEVEL", li["risk"], f"score {li['risk_score']:.0f}/100", rc),
             ("ATTACK TYPE", li["attack_type"], f"pattern: {li['pattern_name'] or '-'}", "#e6edf3"),
             ("CONFIDENCE", f"{li['final_conf']:.0%}", f"raw model {li['model_conf']:.0%}", "#00e5ff"),
             ("SOURCE", li["source_ip"], f"{stats['attacks']} attacks seen", "#e6edf3"),
             ("ACTION", li["action"], ("Contained" if li["success"] else "Not contained") + " (simulated)", "#15803d"),
             ("LEARNING STATUS", li["learning_status"], f"path: {li['path']}", PATH_COLOR.get(li["path"], "#e6edf3"))]
else:
    cells = [(l, "-", "no events yet", "#8b98a9") for l in
             ["THREAT LEVEL", "ATTACK TYPE", "CONFIDENCE", "SOURCE", "ACTION", "LEARNING STATUS"]]
for c, (l, v, s, col) in zip(cols, cells):
    c.markdown(kpi(l, v, s, col), unsafe_allow_html=True)
st.write("")

tab_lab, tab_tl, tab_an, tab_mem = st.tabs(["Demo Attack Lab", "Learning Timeline", "Analytics & Adaptation", "Memory"])

# --------------------------------------------------------------------------- attack launcher
def launch(kind, n, intensity, variation, mutated, reuse_ip, area):
    ip = ss.last_ip if (reuse_ip and ss.last_ip) else new_ip()
    ss.last_ip, ss.last_kind = ip, kind
    bid = new_batch_id()
    events = generate_events(kind, n, intensity, variation, ip, mutated)
    app = DemoApp(mem)
    with area:
        st.markdown(f"#### Running **{kind}**{' (modified variant)' if mutated else ''} - {n} events, "
                    f"intensity {intensity}, variation {variation:.0%}, source `{ip}`")
        prog, feed, rows = st.progress(0.0, text="Local demo app receiving traffic..."), st.empty(), []
        delay = min(0.15, 2.5 / max(1, len(events)))
        for i, ev in enumerate(app.stream(events, bid)):          # events appear one by one, and are logged live
            rows.append({"t(s)": ev["t"], "source": ev["src_ip"], "port": ev["dst_port"], "proto": ev["protocol"],
                         "event": ev["event_type"], "user": ev["username"], "outcome": ev["outcome"],
                         "payload": ev["payload_len"], "pps": ev["pps"]})
            feed.dataframe(pd.DataFrame(rows[-10:]), hide_index=True)
            prog.progress((i + 1) / len(events), text=f"Event {i + 1}/{len(events)} written to security.log")
            time.sleep(delay)
        chain, shown = st.empty(), []

        def on_step(s):
            shown.append(s)
            chain.markdown(steps_html(shown), unsafe_allow_html=True)
            if pace:
                time.sleep(0.45)

        ss.last = run_agent(mem, bid, kind, deliberate=pace, on_step=on_step, retrain_every=every)
    ss.last_events = pd.DataFrame(rows)
    st.rerun()


DEFAULT_N = {"Brute Force": 12, "Port Scan": 25, "SQL Injection": 10, "DDoS": 15, "Novel Attack": 10,
             "Normal Traffic": 12, "Suspicious Login": 10, "Unknown Suspicious": 12}

with tab_lab:
    st.markdown("### Demo Attack Lab")
    st.caption("Safe, controlled, local-only. Each button generates synthetic events, feeds them to a sandbox demo app, "
               "and the agent reacts. Use the same button twice to see the agent recognise a repeat.")
    request = None
    buttons = [("Simulate Brute Force", "Brute Force"), ("Simulate Port Scan", "Port Scan"),
               ("Simulate SQL Injection Attempt", "SQL Injection"), ("Simulate DDoS-like Traffic Spike", "DDoS"),
               ("Simulate Unknown/Novel Attack", "Novel Attack"), ("Generate Normal Traffic", "Normal Traffic")]
    reuse = st.checkbox("Reuse the previous attacker IP (shows the simulated blocklist protecting the app)")
    bcols = st.columns(6)
    for c, (label, kind) in zip(bcols, buttons):
        if c.button(label, key="btn_" + kind):
            request = dict(kind=kind, n=DEFAULT_N[kind], intensity=5, variation=0.15, mutated=False)

    st.markdown("#### Attack Replay")
    r1, r2, r3, r4 = st.columns(4)
    rkind = r1.selectbox("Attack type", KINDS, index=KINDS.index("Brute Force"))
    rint = r2.slider("Intensity", 1, 10, 5)
    rn = r3.slider("Number of events", 5, 60, 20)
    rvar = r4.slider("Variation level", 0, 100, 15, format="%d%%")
    r5, r6 = st.columns([1, 1])
    rmut = r5.checkbox("Apply structural modification (slower / different port / obfuscated)")
    if r6.button("RUN ATTACK", type="primary"):
        request = dict(kind=rkind, n=rn, intensity=rint, variation=rvar / 100, mutated=rmut)
    if st.button("Inject new attack (modified variant of the last attack)"):
        inj = ss.last_kind if ss.last_kind not in (None, "Normal Traffic") else "Brute Force"
        request = dict(kind=inj, n=15, intensity=5, variation=0.3, mutated=True)

    live = st.container()
    if request:
        launch(**request, reuse_ip=reuse, area=live)      # ends with st.rerun()

    steps = ss.last["steps"] if ss.last else (json.loads(li["steps"]) if li and isinstance(li["steps"], str) else None)
    if steps:
        st.markdown("#### Attack chain (last run)")
        st.markdown(steps_html(steps), unsafe_allow_html=True)
        if ss.last_events is not None:
            with st.expander("Raw events from the last run"):
                st.dataframe(ss.last_events, hide_index=True)

# --------------------------------------------------------------------------- learning timeline
with tab_tl:
    st.markdown("### Learning Timeline")
    df = mem.incidents_df()
    if df.empty:
        st.info("No attacks yet. Go to the Demo Attack Lab and click a button.")
    else:
        pats = [p for p in mem.patterns() if p["count"] >= 2]
        if pats:
            pats.sort(key=lambda p: (not p["base_type"].startswith("Novel-"), -p["id"]))
            st.markdown("#### First encounter vs latest encounter")
            sel = st.selectbox("Pattern", [p["name"] for p in pats])
            p = next(x for x in pats if x["name"] == sel)
            inc = mem.incidents_for_pattern(p["id"])
            a, b = inc[0], inc[-1]
            ca, cb = st.columns(2)
            for col, r, title in ((ca, a, "FIRST ENCOUNTER"), (cb, b, f"ENCOUNTER #{len(inc)} (latest)")):
                col.markdown(f"**{title}** - incident #{r['id']}")
                col.metric("Classified as", r["attack_type"])
            ca.metric("Confidence", f"{a['final_conf']:.0%}")
            cb.metric("Confidence", f"{b['final_conf']:.0%}", f"{(b['final_conf'] - a['final_conf']) * 100:+.0f} pts")
            ca.metric("Analysis steps", a["analysis_steps"])
            cb.metric("Analysis steps", b["analysis_steps"], b["analysis_steps"] - a["analysis_steps"], delta_color="inverse")
            ca.metric("Path", a["path"])
            cb.metric("Path", b["path"])
            ca.metric("Response", a["action"])
            cb.metric("Response", b["action"])
            st.caption("Confidence for an unknown attack is the agent's confidence that it is malicious; after it is learned, "
                       "it is the learned pattern's confidence. Steps = how much analysis the agent had to do.")
        st.markdown("#### Event-by-event log")
        rows = df.tail(15).to_dict("records")
        st.markdown(timeline_html(rows), unsafe_allow_html=True)

# --------------------------------------------------------------------------- analytics
with tab_an:
    st.markdown("### Analytics & Adaptation")
    st.info("**Three kinds of adaptation - only the last changes the ML model:**  "
            "1. *Memory* (attack fingerprints remembered)  2. *Rules* (response preferences learned from outcomes)  "
            "3. *Model retraining* (Random Forest re-fit on new labelled experiences).")
    df = mem.incidents_df()
    m1, m2, m3 = st.columns(3)
    with m1:
        st.markdown("##### 1. Memory adaptation")
        st.metric("Patterns learned", stats["patterns"])
        st.metric("Patterns reinforced (seen ≥ 2x)", stats["reinforced"])
        st.metric("Recognised from memory (fast path)", f"{stats['fast_rate']:.0%}")
    with m2:
        st.markdown("##### 2. Rule adaptation")
        st.metric("Response success rate (simulated)", f"{stats['success_rate']:.0%}")
        ast = mem.action_stats_df()
        if not ast.empty:
            ast["success rate"] = (ast["successes"] / ast["tries"]).map("{:.0%}".format)
            st.dataframe(ast, hide_index=True)
    with m3:
        st.markdown("##### 3. Model retraining")
        st.metric("Retraining runs", stats["retrains"])
        st.metric("Labelled experiences pending", stats["pending"])
        log = mem.model_log_df()
        if not log.empty:
            last = log.iloc[-1]
            st.caption(f"Last: {last['ts']} - holdout acc {last['holdout_acc']:.1%}; experiences "
                       f"{last['exp_acc_before']:.0%} -> {last['exp_acc_after']:.0%} (in-sample)")
        else:
            st.caption("Model weights are still the original baseline.")
    if stats["steps_first"] is not None:
        i1, i2 = st.columns(2)
        i1.metric("Avg analysis steps: first attacks → latest", f"{stats['steps_last']:.1f}",
                  f"{stats['steps_last'] - stats['steps_first']:+.1f} vs first", delta_color="inverse")
        i2.metric("Avg confidence: first attacks → latest", f"{stats['conf_last']:.0%}",
                  f"{(stats['conf_last'] - stats['conf_first']) * 100:+.0f} pts")
    if not df.empty:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Attacks over time**")
            st.bar_chart(df.assign(n=1).pivot_table(index="id", columns="attack_type", values="n", aggfunc="sum").fillna(0))
        with c2:
            st.markdown("**Attack categories**")
            st.bar_chart(df["attack_type"].value_counts())
        c3, c4 = st.columns(2)
        with c3:
            st.markdown("**Detection confidence (raw model vs memory-adjusted)**")
            st.line_chart(df.set_index("id")[["model_conf", "final_conf"]].rename(
                columns={"model_conf": "raw model", "final_conf": "final (with memory)"}))
        with c4:
            st.markdown("**Learned patterns (times seen)**")
            pt = pd.DataFrame(mem.patterns())
            if not pt.empty:
                st.bar_chart(pt.set_index("name")["count"])
        st.markdown("**Analysis steps per incident (lower = faster decision)**")
        st.bar_chart(df.set_index("id")["analysis_steps"])

# --------------------------------------------------------------------------- memory
with tab_mem:
    st.markdown("### Persistent Memory")
    st.caption("Stored in data/memory.db - survives restarting the app.")
    df = mem.incidents_df()
    st.markdown("**Learned patterns**")
    pt = pd.DataFrame(mem.patterns())
    if not pt.empty:
        pt["success rate"] = (pt["successes"] / pt["tries"]).map("{:.0%}".format)
        st.dataframe(pt[["name", "base_type", "count", "confidence", "success rate", "action", "description",
                         "first_seen", "last_seen"]], hide_index=True)
    st.markdown("**Attack history**")
    if not df.empty:
        st.dataframe(df[["id", "ts", "source_ip", "attack_type", "model_conf", "final_conf", "risk", "action", "success",
                         "path", "similarity", "pattern_name", "analysis_steps", "decision_ms", "result"]].iloc[::-1],
                     hide_index=True)
    st.markdown("**Active simulated defences**")
    st.dataframe(mem.defenses_df(), hide_index=True)
