"""Streamlit dashboard. UI only: all simulation logic lives in the cids package.

Run:  streamlit run app.py
"""
from __future__ import annotations

import math

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from cids.config import SimConfig, make_node_ids
from cids.experiments import EXPERIMENTS, run_experiments, summarise
from cids.reporting import frames, metrics_frame, result_json
from cids.simulation import APPROACH_LABELS, APPROACHES, SimResult, run_simulation

TEAL, AMBER, RED, GREY, INK = "#3FB8AF", "#F2A541", "#E5484D", "#6B7A90", "#DCE6F2"
STATUS_COLOR = {"honest": TEAL, "malicious": AMBER, "offline": GREY}
APPROACH_COLOR = {APPROACH_LABELS["local_only"]: GREY, APPROACH_LABELS["majority"]: AMBER,
                  APPROACH_LABELS["trust_aware"]: TEAL}

st.set_page_config(page_title="CIDS between socket nodes", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Barlow:wght@400;500;600&family=Barlow+Semi+Condensed:wght@600;700&display=swap');
html, body, [class*="css"], .stMarkdown, .stDataFrame, button, input { font-family: 'Barlow', system-ui, sans-serif; }
h1, h2, h3 { font-family: 'Barlow Semi Condensed', 'Barlow', sans-serif !important; letter-spacing: .01em; }
h1 { font-size: 2.1rem !important; margin-bottom: .1rem !important; }
[data-testid="stMetric"] { background: #15263D; border-left: 3px solid #3FB8AF;
  padding: .7rem 1rem; border-radius: 4px; }
[data-testid="stMetricLabel"] p { color: #9FB1C7; font-size: .85rem; }
.subtle { color: #9FB1C7; font-size: .95rem; margin-top: -.3rem; }
.legend span { display: inline-block; margin-right: 1.2rem; font-size: .9rem; }
.dot { display:inline-block; width:.7rem; height:.7rem; border-radius:50%; margin-right:.35rem; vertical-align:middle; }
</style>""", unsafe_allow_html=True)


# ---------------------------------------------------------------- helpers
def show_df(df: pd.DataFrame, **kw) -> None:
    try:
        st.dataframe(df, width="stretch", hide_index=True, **kw)
    except Exception:  # older Streamlit versions
        st.dataframe(df, use_container_width=True, hide_index=True, **kw)


def show_fig(fig: go.Figure) -> None:
    fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                      plot_bgcolor="rgba(0,0,0,0)", font=dict(family="Barlow, sans-serif", color=INK),
                      margin=dict(l=10, r=10, t=40, b=10))
    try:
        st.plotly_chart(fig, width="stretch")
    except Exception:
        st.plotly_chart(fig, use_container_width=True)


def fmt(v, digits: int = 3) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "n/a"
    return f"{v:.{digits}f}" if isinstance(v, float) else str(v)


def topology_figure(res: SimResult) -> go.Figure:
    nodes = res.nodes
    n = len(nodes)
    pos = {nd["node"]: (math.cos(2 * math.pi * i / n + math.pi / 2),
                        math.sin(2 * math.pi * i / n + math.pi / 2)) for i, nd in enumerate(nodes)}
    links = {(l["src"], l["dst"]): l for l in res.links}
    fig = go.Figure()
    done = set()
    for (a, b) in links:
        if (b, a) in done:
            continue
        done.add((a, b))
        l1, l2 = links[(a, b)], links.get((b, a), {"sent": 0, "failed": 0, "attempts": 0})
        sent, failed = l1["sent"] + l2["sent"], l1["failed"] + l2["failed"]
        color = RED if sent == 0 and failed > 0 else (AMBER if failed else TEAL)
        if sent == 0 and failed == 0:
            color = GREY
        fig.add_trace(go.Scatter(
            x=[pos[a][0], pos[b][0]], y=[pos[a][1], pos[b][1]], mode="lines",
            line=dict(color=color, width=1 + min(6, sent / 25), dash="dot" if sent == 0 else "solid"),
            hoverinfo="text", text=f"{a} ↔ {b}: {sent} delivered, {failed} failed", showlegend=False))
    fig.add_trace(go.Scatter(
        x=[pos[nd["node"]][0] for nd in nodes], y=[pos[nd["node"]][1] for nd in nodes],
        mode="markers+text", text=[nd["node"] for nd in nodes], textposition="middle center",
        textfont=dict(color="#0E1A2B", size=14),
        marker=dict(size=46, color=[STATUS_COLOR[nd["status"]] for nd in nodes],
                    line=dict(color=INK, width=1)),
        hovertext=[f"{nd['node']} ({nd['status']}) port {nd['port']}<br>events {nd['events_seen']}, "
                   f"alerts sent {nd['alerts_sent']}<br>valid in {nd['received_valid']}, "
                   f"rejected {nd['rejected']}" for nd in nodes],
        hoverinfo="text", showlegend=False))
    fig.update_xaxes(visible=False, range=[-1.4, 1.4])
    fig.update_yaxes(visible=False, range=[-1.3, 1.3], scaleanchor="x")
    fig.update_layout(height=380, title="Node topology (127.0.0.1, one TCP port per node)")
    return fig


def incident_table(res: SimResult) -> pd.DataFrame:
    first = {(d["approach"], d["target_id"], d["event_type"]): d["first_round"] for d in res.detections}
    rows = []
    for inc in res.incidents:
        row = {"incident": inc["incident_id"], "scenario": inc["kind"].replace("_", " "),
               "truth": "attack" if inc["is_attack"] else "benign",
               "target": inc["target_id"], "type": inc["event_type"],
               "start": inc["start"], "seen by": inc["observers"]}
        for a in APPROACHES:
            r = first.get((a, inc["target_id"], inc["event_type"]))
            row[APPROACH_LABELS[a]] = "—" if r is None else f"flagged t={r}"
        rows.append(row)
    return pd.DataFrame(rows)


# ---------------------------------------------------------------- sidebar
st.sidebar.header("Simulation settings")
num_nodes = st.sidebar.slider("IDS nodes", 2, 12, 4,
                              help="Each node is an asyncio TCP server on its own localhost port.")
ids = make_node_ids(num_nodes)
with st.sidebar.form("settings"):
    seed = st.number_input("Random seed", 0, 1_000_000, 42, step=1)
    duration = st.slider("Duration (simulated seconds)", 20, 300, 60, step=5)
    with st.expander("Event mix", expanded=False):
        n_conc = st.slider("Concentrated high-rate attacks", 0, 10, 1)
        n_dist = st.slider("Distributed attacks", 0, 10, 1)
        n_low = st.slider("Low-rate distributed attacks", 0, 10, 1)
        n_benign = st.slider("Benign look-alike bursts", 0, 10, 2)
        bg_rate = st.slider("Background events per node per second", 0.0, 20.0, 3.0, 0.5)
    with st.expander("Local detection", expanded=False):
        det_win = st.slider("Detection window (s)", 1, 30, 10)
        weak = st.slider("Weak alert threshold (events)", 1, 10, 2)
        strong = st.slider("Strong local threshold (events)", 2, 30, 8)
    with st.expander("Collaboration and trust", expanded=True):
        corr_win = st.slider("Correlation window (s)", 1, 30, 12)
        quorum = st.slider("Quorum threshold (weighted support)", 0.1, 4.0, 0.9, 0.05)
        min_src = st.slider("Minimum independent sources", 1, num_nodes, min(2, num_nodes))
        init_trust = st.slider("Initial peer trust", 0.0, 1.0, 0.5, 0.05)
        reward = st.slider("Trust reward (corroborated)", 0.0, 0.5, 0.05, 0.01)
        penalty = st.slider("Trust penalty (uncorroborated)", 0.0, 0.5, 0.10, 0.01)
        inv_pen = st.slider("Penalty for invalid signed messages", 0.0, 0.5, 0.15, 0.01)
        min_trust = st.slider("Ignore peers below trust", 0.0, 1.0, 0.2, 0.05)
    with st.expander("Message security", expanded=False):
        max_age = st.slider("Max message age (s)", 1, 30, 5)
        max_frame = st.select_slider("Max frame size (bytes)", [1024, 2048, 4096, 8192, 16384, 65536], 8192)
    with st.expander("Faults and attacks", expanded=True):
        offline = st.multiselect("Offline nodes", ids, [])
        off_from = st.slider("Offline from second", 0, 300, 0)
        malicious = st.multiselect("Misleading (malicious) nodes", ids, [])
        dup = st.slider("Duplicate flooding factor", 1, 10, 1)
        replay = st.checkbox("Replay attacker", False)
        invalid = st.checkbox("Invalid / malformed messages", False)
        delay = st.slider("Extra network delay (s)", 0, 15, 0)
        drop = st.slider("Message loss rate", 0.0, 0.9, 0.0, 0.05)
    run_clicked = st.form_submit_button("Run simulation", type="primary")

cfg = SimConfig(num_nodes=num_nodes, seed=int(seed), duration=duration, n_concentrated=n_conc,
                n_distributed=n_dist, n_low_rate=n_low, n_benign_lookalike=n_benign,
                background_rate=bg_rate, detection_window=det_win, weak_threshold=weak,
                strong_threshold=strong, correlation_window=corr_win, quorum_threshold=quorum,
                min_sources=min_src, initial_trust=init_trust, trust_reward=reward,
                trust_penalty=penalty, invalid_penalty=inv_pen, min_trust_to_count=min_trust,
                max_message_age=max_age, max_frame_bytes=max_frame, offline_nodes=offline,
                offline_from=off_from, malicious_nodes=malicious, duplicate_factor=dup,
                replay_attack=replay, invalid_messages=invalid, delay_rounds=delay, drop_rate=drop)

# ---------------------------------------------------------------- header
st.title("Collaborative Intrusion Detection Between Socket Nodes")
st.markdown('<p class="subtle">Independent IDS nodes share signed alerts over TCP, weigh each '
            'other by earned trust, and decide together. Synthetic, isolated lab simulation.</p>',
            unsafe_allow_html=True)

if run_clicked:
    try:
        cfg.validate()
    except ValueError as e:
        st.error(f"These settings can't run: {e}")
    else:
        bar = st.progress(0.0, text="Starting nodes…")
        feed = st.empty()

        def on_progress(done: int, total: int, snap: dict) -> None:
            if done % 3 and done != total:
                return
            bar.progress(done / total, text=f"t = {done}/{total} s · {snap['alerts']} alerts sent · "
                                            f"{snap['rejected']} rejected · {snap['flagged']} flagged")
            if snap["recent"]:
                feed.dataframe(pd.DataFrame(snap["recent"])[
                    ["round", "sender", "target_id", "event_type", "confidence", "severity"]],
                    hide_index=True)

        st.session_state["result"] = run_simulation(cfg, on_progress)
        bar.empty()
        feed.empty()

res: SimResult | None = st.session_state.get("result")
if res is None:
    st.info("Choose settings in the sidebar and press **Run simulation**. Nodes start on free "
            "localhost ports and are shut down when the run ends.")
    st.stop()

tables = frames(res)
mt = metrics_frame(res)
trust_row = mt[mt["approach"] == APPROACH_LABELS["trust_aware"]].iloc[0]

k = st.columns(5)
k[0].metric("Synthetic events", f"{res.events_total:,}")
k[1].metric("Alerts delivered", f"{res.comm['messages_received_valid']:,}")
k[2].metric("Messages rejected", f"{res.comm['messages_rejected']:,}")
k[3].metric("Trust-aware F1", fmt(trust_row["f1"], 2))
k[4].metric("Run time", f"{res.wall_seconds:.2f} s")
for note in res.notes:
    st.caption(f"⚠ {note}")

tabs = st.tabs(["Overview", "Alert feed", "Decisions", "Trust", "Security",
                "Baseline comparison", "Experiments", "Export"])

with tabs[0]:
    c1, c2 = st.columns([1, 1.2])
    with c1:
        show_fig(topology_figure(res))
        st.markdown(f'<div class="legend"><span><i class="dot" style="background:{TEAL}"></i>honest</span>'
                    f'<span><i class="dot" style="background:{AMBER}"></i>misleading</span>'
                    f'<span><i class="dot" style="background:{GREY}"></i>offline</span></div>',
                    unsafe_allow_html=True)
    with c2:
        st.subheader("Injected incidents and who caught them")
        show_df(incident_table(res))
        st.subheader("Per-node activity")
        show_df(tables["nodes"])

with tabs[1]:
    rec = tables["messages_received"]
    if rec.empty:
        st.info("No messages were received in this run.")
    else:
        c1, c2 = st.columns(2)
        who = c1.multiselect("Receiving node", sorted(rec["receiver"].unique()))
        only_rej = c2.toggle("Only rejected messages", False)
        view = rec if not who else rec[rec["receiver"].isin(who)]
        if only_rej:
            view = view[view["evidence"].str.startswith("REJECTED")]
        show_df(view.sort_values("round", ascending=False), height=420)
    with st.expander("Alerts each node sent"):
        show_df(tables["alerts_sent"])

with tabs[2]:
    st.markdown("Each node scores every correlated target: **support = Σ trust(sender) × confidence** "
                f"over distinct senders, flagged when support ≥ {res.config['quorum_threshold']} with "
                f"at least {res.config['min_sources']} sources, or when its own detector is strong.")
    dec = tables["decisions"]
    if dec.empty:
        st.info("No correlated evidence formed in this run.")
    else:
        node_pick = st.selectbox("Viewpoint node", sorted(dec["node_id"].unique()))
        d = dec[dec["node_id"] == node_pick].sort_values("round", ascending=False)
        d = d.assign(verdict=d["verdict"].map({True: "INTRUSION", False: "no intrusion"}))
        show_df(d[["round", "target_id", "event_type", "verdict", "score", "sources", "explanation"]],
                height=380)
    with st.expander("Correlation log (why evidence was grouped, updated or rejected)"):
        show_df(tables["correlation_log"])

with tabs[3]:
    th = tables["trust_history"]
    viewer = st.selectbox("Trust as seen by", [n["node"] for n in res.nodes], key="trust_view")
    t = th[th["node"] == viewer].sort_values("round")
    if not t.empty:
        fig = px.line(t, x="round", y="new", color="peer", line_shape="hv", markers=True,
                      hover_data=["reason"], labels={"new": "trust", "round": "time (s)"},
                      title=f"Peer trust held by {viewer}")
        fig.update_yaxes(range=[-0.05, 1.05])
        show_fig(fig)
    matrix = pd.DataFrame({n["node"]: n["trust_given"] for n in res.nodes}).T
    matrix = matrix.reindex(index=[n["node"] for n in res.nodes], columns=[n["node"] for n in res.nodes])
    fig = px.imshow(matrix, text_auto=".2f", zmin=0, zmax=1, color_continuous_scale=[RED, AMBER, TEAL],
                    labels=dict(x="peer", y="held by", color="trust"), title="Final trust matrix")
    show_fig(fig)
    with st.expander("Every trust update and its reason"):
        show_df(th[th["reason"] != "initial"].sort_values(["round", "node"]))

with tabs[4]:
    rej = res.comm["rejections_by_reason"]
    c1, c2 = st.columns(2)
    with c1:
        if rej:
            fig = px.bar(x=list(rej), y=list(rej.values()), labels={"x": "reason", "y": "messages"},
                         title="Rejected before reaching correlation", color_discrete_sequence=[RED])
            show_fig(fig)
        else:
            st.success("No messages were rejected. Turn on the replay attacker, invalid messages "
                       "or duplicate flooding to test validation.")
    with c2:
        cm = res.comm
        st.metric("Peer availability", fmt(cm["peer_availability"], 3))
        st.metric("Failed sends (peer unreachable)", cm["send_failures"])
        st.metric("Messages lost (loss rate)", cm["messages_dropped"])
        st.metric("Reconnections", cm["reconnects"])
    if res.attacks_injected:
        st.subheader("Attacker traffic sent to nodes")
        show_df(pd.DataFrame(res.attacks_injected))
    st.subheader("Link statistics")
    show_df(tables["links"])

with tabs[5]:
    long = mt.melt(id_vars="approach", value_vars=["precision", "recall", "f1", "fpr"],
                   var_name="metric", value_name="value")
    fig = px.bar(long, x="metric", y="value", color="approach", barmode="group",
                 color_discrete_map=APPROACH_COLOR, title="Same events, same messages, three decision rules")
    fig.update_yaxes(range=[0, 1.05])
    show_fig(fig)
    c1, c2 = st.columns(2)
    with c1:
        fig = px.bar(mt, x="approach", y="mean_latency_s", color="approach",
                     color_discrete_map=APPROACH_COLOR, title="Mean detection latency (s)")
        fig.update_layout(showlegend=False)
        show_fig(fig)
    with c2:
        show_df(mt.round(3))
        cm = res.comm
        st.caption(f"Communication cost: {cm['messages_sent']} messages, {cm['bytes_sent']:,} bytes, "
                   f"average {fmt(cm['avg_message_bytes'], 1)} bytes per message. "
                   f"CPU {res.resources['cpu_seconds']} s, peak Python memory "
                   f"{res.resources['peak_python_memory_mb']} MB (environment-dependent).")
    st.caption("Unit of evaluation: every (target, event type) seen or alerted during the run. "
               "An approach flags a unit if any honest online node flags it. n/a = undefined (zero denominator).")

with tabs[6]:
    st.markdown("Runs named experiments over several seeds using the current sidebar settings as the base.")
    names = st.multiselect("Experiments", list(EXPERIMENTS), list(EXPERIMENTS)[:7])
    n_seeds = st.slider("Seeds per experiment", 1, 10, 3)
    if st.button("Run experiments", disabled=not names):
        try:
            cfg.validate()
        except ValueError as e:
            st.error(f"These settings can't run: {e}")
        else:
            bar = st.progress(0.0)
            df = run_experiments(cfg.replace(offline_nodes=[], malicious_nodes=[]), names,
                                 list(range(int(seed), int(seed) + n_seeds)),
                                 lambda i, n, label: bar.progress(i / n, text=label))
            bar.empty()
            st.session_state["exp_raw"] = df
            st.session_state["exp_sum"] = summarise(df)
    if "exp_sum" in st.session_state:
        s = st.session_state["exp_sum"]
        s = s.assign(label=s["experiment"] + s["variant"].map(lambda v: f" ({v})" if v else ""))
        fig = px.bar(s, x="label", y="f1_mean", error_y="f1_std", color="approach", barmode="group",
                     color_discrete_map=APPROACH_COLOR, title="F1 per experiment (mean ± std across seeds)",
                     labels={"label": "", "f1_mean": "F1"})
        show_fig(fig)
        show_df(s.drop(columns=["label"]).round(3))
        c1, c2 = st.columns(2)
        c1.download_button("Download raw results (CSV)", st.session_state["exp_raw"].to_csv(index=False),
                           "experiments_raw.csv", "text/csv")
        c2.download_button("Download summary (CSV)", st.session_state["exp_sum"].to_csv(index=False),
                           "experiments_summary.csv", "text/csv")

with tabs[7]:
    st.markdown("Download this run for your report.")
    st.download_button("Full run log (JSON)", result_json(res), "run_log.json", "application/json")
    cols = st.columns(3)
    for i, (name, df) in enumerate(tables.items()):
        cols[i % 3].download_button(f"{name}.csv", df.to_csv(index=False), f"{name}.csv",
                                    "text/csv", key=f"dl_{name}")
