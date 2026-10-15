"""
Reusable Cybersecurity UI Components
Includes SOC Telemetry Header, Breadcrumbs, Terminal Feed, Sidebar Footer, and KPI Cards.
"""
import datetime
from typing import Dict, Any, List

def render_soc_header(active_module: str = "Command Center"):
    """Renders the top operational header with status pill and UTC time."""
    import streamlit as st
    utc_now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    st.markdown(f"""
    <div class="soc-header">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px;">
            <div>
                <div class="soc-title">
                    <span>🛡️</span> DATA PRIVACY GUARDIAN <span style="color:#00f2fe; font-size: 18px; font-weight:600;">[SOC-COMMAND]</span>
                </div>
                <div class="soc-badge">● AIR-GAPPED &bull; LOCAL PRIVACY DEFENSE &bull; {active_module.upper()}</div>
            </div>
            <div style="text-align: right; font-family: 'Consolas', monospace; font-size: 12px; color: #94a3b8;">
                <div style="color: #00f2fe; font-weight: 600;">LIVE SYSTEM MONITOR</div>
                <div>{utc_now}</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_terminal_feed(events: List[Dict[str, Any]]):
    """Renders a terminal-style recent activity and scan log."""
    import streamlit as st
    if not events:
        st.markdown("""
        <div class="terminal-feed">
            <span class="feed-time">[IDLE]</span> <span class="feed-info">System listening. Standby for scan execution.</span>
        </div>
        """, unsafe_allow_html=True)
        return

    feed_lines = []
    for ev in events[:8]:
        ts = ev.get("timestamp", "")
        name = ev.get("source_name", "Unknown")
        stype = ev.get("source_type", "Target")
        score = ev.get("risk_score", 0.0)
        
        tag_cls = "feed-crit" if score >= 65 else ("feed-warn" if score >= 35 else "feed-info")
        feed_lines.append(
            f"<div><span class='feed-time'>[{ts}]</span> <span class='{tag_cls}'>[AUDIT-{ev.get('status','DONE').upper()}]</span> "
            f"Target: <b>{name}</b> ({stype}) &mdash; Residual Risk Score: <b>{score}</b></div>"
        )

    st.markdown(f"""
    <div class="terminal-feed">
        {''.join(feed_lines)}
    </div>
    """, unsafe_allow_html=True)


def render_sidebar_footer():
    """Renders engine status, air-gapped indicator, version badge, and session reset button."""
    import streamlit as st
    st.sidebar.markdown("---")
    st.sidebar.markdown("""
    <div style="background: rgba(13, 27, 42, 0.8); border: 1px solid #1e3a5f; border-radius: 8px; padding: 10px; font-size: 11px; font-family: 'Consolas', monospace;">
        <div style="color: #10b981; font-weight: 700; margin-bottom: 4px;">● AIR-GAPPED OPERATIONAL</div>
        <div style="color: #94a3b8;">CORE: <span style="color: #f8fafc;">v2.0.0-SOC</span></div>
        <div style="color: #94a3b8;">ISOLATION: <span style="color: #00f2fe;">100% OFFLINE</span></div>
    </div>
    """, unsafe_allow_html=True)
    
    if st.sidebar.button("🧹 Clear Session Cache", use_container_width=True, key="ui2_clear_session_btn"):
        for k in list(st.session_state.keys()):
            if k not in ["USE_NEW_UI", "ui2_bg_fx"]:
                del st.session_state[k]
        st.sidebar.success("Session state cleared.")
        st.rerun()
