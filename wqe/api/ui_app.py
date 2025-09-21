# ui_app.py
import os
from typing import Dict, List, Any

import requests
import streamlit as st
from dotenv import load_dotenv

# ---------- base ----------
load_dotenv()
API_URL = os.getenv("API_URL", "http://localhost:8000").rstrip("/")

st.set_page_config(
    page_title="Security Log Analyzer",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------- helpers ----------
def http_get(path: str, params: Dict[str, Any] | None = None, timeout: float = 10):
    try:
        r = requests.get(f"{API_URL}{path}", params=params, timeout=timeout)
        if r.headers.get("content-type", "").startswith("application/json"):
            return r.status_code, r.json()
        return r.status_code, {}
    except Exception as e:
        return 599, {"error": str(e)}

def http_post(path: str, json: Dict[str, Any], timeout: float = 30):
    try:
        r = requests.post(f"{API_URL}{path}", json=json, timeout=timeout)
        if r.headers.get("content-type", "").startswith("application/json"):
            return r.status_code, r.json()
        return r.status_code, {}
    except Exception as e:
        return 599, {"error": str(e)}

@st.cache_data(ttl=30)
def get_stats() -> Dict[str, Any]:
    code, data = http_get("/api/v1/stats")
    return data if code == 200 else {}

@st.cache_data(ttl=20)
def get_recent_anomalies(limit: int = 5, time_range: str = "24h") -> List[Dict[str, Any]]:
    code, data = http_get("/api/v1/anomalies/search", params={"limit": limit, "time_range": time_range})
    if code == 200 and isinstance(data, dict):
        return data.get("anomalies", []) or []
    return []

def chat_send(message: str, history: List[Dict[str, str]]) -> Dict[str, Any]:
    payload = {"message": message, "chat_history": history}
    code, data = http_post("/api/v1/chat", payload)
    if code == 200:
        return {"ok": True, "response": data.get("response", "Нет ответа")}
    return {"ok": False, "response": f"Ошибка API ({code}): {data.get('error') or 'см. логи backend'}"}

def backend_status() -> str:
    # сначала пробуем /health, если есть
    code, _ = http_get("/health", timeout=3)
    if code == 200:
        return "🟢 Backend OK"
    # fallback — /stats
    code, _ = http_get("/api/v1/stats", timeout=3)
    return "🟢 Backend OK" if code == 200 else "🔴 Backend недоступен"

# ---------- state ----------
if "chat_history" not in st.session_state:
    st.session_state.chat_history: List[Dict[str, str]] = []

# ---------- header ----------
col_left, col_right = st.columns([0.8, 0.2])
with col_left:
    st.markdown("<h1 style='margin:0'>🔒 Security Analyzer AI</h1>", unsafe_allow_html=True)
with col_right:
    st.caption(backend_status())

st.divider()

# ---------- top metrics ----------
stats = get_stats()
logs_total = int(stats.get("logs", {}).get("total_unique", 0) or 0)
anom_total = int(stats.get("anomalies", {}).get("total", 0) or 0)
threat_pct = (anom_total / logs_total * 100) if logs_total else 0.0

m1, m2, m3 = st.columns(3)
m1.metric("📊 Уникальных логов", f"{logs_total}")
m2.metric("🚨 Всего аномалий", f"{anom_total}")
m3.metric("📈 Уровень угроз", f"{threat_pct:.1f}%")

# ---------- quick actions ----------
st.subheader("⚡ Быстрые команды")
q1, q2, q3, q4 = st.columns(4)
if q1.button("Покажи статистику логов"):
    msg = "Покажи статистику логов за последние 24 часа"
    st.session_state.chat_history.append({"role": "user", "content": msg})
    res = chat_send(msg, st.session_state.chat_history)
    st.session_state.chat_history.append({"role": "assistant", "content": res["response"]})
    st.experimental_rerun()
if q2.button("Какие аномалии найдены?"):
    msg = "Какие аномалии найдены за последние 24 часа?"
    st.session_state.chat_history.append({"role": "user", "content": msg})
    res = chat_send(msg, st.session_state.chat_history)
    st.session_state.chat_history.append({"role": "assistant", "content": res["response"]})
    st.experimental_rerun()
if q3.button("Топ источников по ошибкам"):
    msg = "Покажи топ источников по ошибкам/alert за последние 24 часа"
    st.session_state.chat_history.append({"role": "user", "content": msg})
    res = chat_send(msg, st.session_state.chat_history)
    st.session_state.chat_history.append({"role": "assistant", "content": res["response"]})
    st.experimental_rerun()
if q4.button("Рекомендации по безопасности"):
    msg = "Дай рекомендации по безопасности на основе последних логов"
    st.session_state.chat_history.append({"role": "user", "content": msg})
    res = chat_send(msg, st.session_state.chat_history)
    st.session_state.chat_history.append({"role": "assistant", "content": res["response"]})
    st.experimental_rerun()

st.divider()

# ---------- chat ----------
st.subheader("💬 Чат с ассистентом")
if not st.session_state.chat_history:
    st.info("Спросите меня о логах, угрозах, аномалиях или о текущем состоянии системы.")

# вывод истории (используем встроенные chat-компоненты)
for item in st.session_state.chat_history[-100:]:
    with st.chat_message("user" if item["role"] == "user" else "assistant"):
        st.markdown(item["content"])

# ввод
user_msg = st.chat_input("Ваше сообщение…")
if user_msg:
    st.session_state.chat_history.append({"role": "user", "content": user_msg})
    with st.chat_message("assistant"):
        with st.spinner("Думаю…"):
            res = chat_send(user_msg, st.session_state.chat_history)
            st.session_state.chat_history.append({"role": "assistant", "content": res["response"]})
            st.markdown(res["response"])

st.markdown(
    "<div style='height:8px'></div>",
    unsafe_allow_html=True,
)

# ---------- recent anomalies ----------
anoms = get_recent_anomalies(limit=5, time_range="24h")
if anoms:
    st.subheader("🔍 Последние аномалии (24ч)")
    for a in anoms:
        with st.container(border=True):
            c1, c2, c3 = st.columns([3, 1, 1])
            c1.write(f"**{a.get('bert_class', 'Неизвестно')}**")
            c1.caption(f"Источник: {a.get('source', 'N/A')}")
            try:
                conf = float(a.get("confidence", 0))
            except Exception:
                conf = 0.0
            c2.metric("Уверенность", f"{conf:.2f}")
            sev = (a.get("severity") or "unknown").lower()
            if sev == "high":
                c3.error("Высокая")
            elif sev == "medium":
                c3.warning("Средняя")
            elif sev == "low":
                c3.info("Низкая")
            else:
                c3.write("—")

st.divider()

# ---------- footer ----------
cols = st.columns([1,1,1,3])
with cols[0]:
    if st.button("🔄 Обновить метрики"):
        get_stats.clear(); get_recent_anomalies.clear()
        st.experimental_rerun()
with cols[1]:
    if st.button("🧹 Очистить чат"):
        st.session_state.chat_history = []
        st.experimental_rerun()
with cols[2]:
    st.caption(f"API: {API_URL}")
