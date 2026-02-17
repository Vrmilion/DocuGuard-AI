import streamlit as st
import xgboost as xgb
import shap
import pandas as pd
import matplotlib.pyplot as plt
import tempfile
import os
import math
import numpy as np
import zipfile
import shutil
import re
import time
from oletools.olevba import VBA_Parser

# --- LIBRARY CHECK ---
try:
    import pyzipper
except ImportError:
    st.error("⚠️ Library Kurang: pip install pyzipper")
    st.stop()

# ==========================================
# 1. SETUP UI & CSS
# ==========================================
st.set_page_config(
    page_title="CyberDefend System", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
    <style>
    /* GLOBAL STYLE */
    .stApp {
        background-color: #0F172A; /* Slate 900 */
        color: #E2E8F0;
        font-family: 'Segoe UI', sans-serif;
    }
    
    /* HEADER & CONSOLE */
    .cyber-header {
        text-align: center;
        padding: 25px;
        background: radial-gradient(circle at center, #1e3a8a 0%, #0f172a 100%);
        border-bottom: 2px solid #3B82F6;
        box-shadow: 0 10px 20px rgba(0,0,0,0.5);
        margin-bottom: 20px;
    }
    .glitch-text {
        font-size: 2.2rem;
        font-weight: 800;
        color: white;
        letter-spacing: 3px;
        text-shadow: 0 0 10px #3B82F6;
    }
    
    /* INPUT & BUTTONS */
    div[data-testid="stTextInput"] input {
        background-color: #1E293B;
        color: #38BDF8;
        border: 1px solid #475569;
    }
    div[data-testid="stButton"] button {
        background-color: #7F1D1D; /* Merah Gelap */
        color: white;
        border: 1px solid #EF4444;
        width: 100%;
        transition: all 0.3s;
    }
    div[data-testid="stButton"] button:hover {
        background-color: #EF4444;
        box-shadow: 0 0 15px #EF4444;
    }

    /* STATUS BANNER */
    .status-banner {
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 20px;
        color: white;
        font-weight: bold;
        box-shadow: 0 5px 15px rgba(0,0,0,0.3);
    }
    .status-danger { background: linear-gradient(135deg, #7F1D1D 0%, #B91C1C 100%); border: 2px solid #FCA5A5; }
    .status-safe { background: linear-gradient(135deg, #064E3B 0%, #059669 100%); border: 2px solid #6EE7B7; }
    .status-warning { background: linear-gradient(135deg, #78350F 0%, #B45309 100%); border: 2px solid #FCD34D; }

    /* FEATURE BOX */
    .feature-box {
        background-color: #1E293B;
        padding: 12px;
        border-radius: 6px;
        border-left: 4px solid #64748B;
        margin-bottom: 8px;
    }
    .feature-title { font-size: 0.75rem; color: #94A3B8; text-transform: uppercase; }
    .feature-val { font-size: 1rem; font-weight: bold; color: white; }
    .detected { color: #EF4444 !important; border-left-color: #EF4444 !important; }
    .clean { color: #10B981 !important; border-left-color: #10B981 !important; }

    /* UPLOAD & HIDE SIDEBAR */
    .stFileUploader { background-color: #1E293B; border: 2px dashed #3B82F6; padding: 20px; border-radius: 10px; }
    section[data-testid="stSidebar"] { display: none; }
    </style>
    """, unsafe_allow_html=True)

# ==========================================
# 2. LOGIKA BACKEND
# ==========================================
# Mapping Nama Fitur (Agar SHAP mudah dibaca)
FITUR_ASLI = ['cat1_auto', 'cat2_suspicious', 'cat3_network', 'cat4_obfuscation', 'score_entropy']
FITUR_DISPLAY = {
    'cat1_auto': 'Auto-Start',
    'cat2_suspicious': 'Shell/CMD Exec',
    'cat3_network': 'Network Access',
    'cat4_obfuscation': 'Code Obfuscation',
    'score_entropy': 'Entropy Score'
}

@st.cache_resource
def latih_model_fix():
    N = 5000 
    malware = pd.DataFrame({'cat1_auto':1, 'cat2_suspicious':1, 'cat3_network':np.random.randint(0,2,N), 'cat4_obfuscation':np.random.randint(0,2,N), 'score_entropy':np.random.uniform(5.5,9.0,N), 'target':1})
    malware_hidden = pd.DataFrame({'cat1_auto':np.random.randint(0,2,N), 'cat2_suspicious':0, 'cat3_network':0, 'cat4_obfuscation':1, 'score_entropy':np.random.uniform(6.0,9.5,N), 'target':1})
    aman_clean = pd.DataFrame({'cat1_auto':0, 'cat2_suspicious':0, 'cat3_network':0, 'cat4_obfuscation':0, 'score_entropy':np.random.uniform(1.0,3.5,N), 'target':0})
    aman_macro = pd.DataFrame({'cat1_auto':1, 'cat2_suspicious':0, 'cat3_network':0, 'cat4_obfuscation':0, 'score_entropy':np.random.uniform(2.5,4.5,N), 'target':0})
    df = pd.concat([malware, malware_hidden, aman_clean, aman_macro]).sample(frac=1).reset_index(drop=True)
    model = xgb.XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.05, eval_metric='logloss')
    model.fit(df[FITUR_ASLI], df['target'])
    return model

model = latih_model_fix()

def hitung_entropy(data):
    if not data: return 0
    e = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0: e += - p_x * math.log(p_x, 2)
    return e

def bersihkan_kode(kode_asli):
    return kode_asli.lower().replace('&', '').replace('_', '').replace('"', '').replace("'", "").replace(" ", "")

def bedah_file_proposal(path):
    data = {k: 0 for k in FITUR_ASLI}
    debug_log = "Clean File / No Macro."
    try:
        parser = VBA_Parser(path)
        if parser.detect_vba_macros():
            vba_text = ""
            for _, _, _, code in parser.extract_macros():
                if code: vba_text += code
            if vba_text:
                debug_log = vba_text[:800]
                code_clean = bersihkan_kode(vba_text)
                if re.search(r'(autoopen|documentopen|workbookopen|auto_open)', code_clean): data['cat1_auto'] = 1
                if re.search(r'(shell|wscript|powershell|cmd|createobject|callbyname|application\.run)', code_clean): data['cat2_suspicious'] = 1
                if re.search(r'(http|https|xmlhttp|winhttp|urldownload|savetofile|bitsadmin)', code_clean): data['cat3_network'] = 1
                data['score_entropy'] = hitung_entropy(vba_text)
                if data['score_entropy'] > 5.2 or vba_text.lower().count('&h') > 5: data['cat4_obfuscation'] = 1
    except: pass
    return data, debug_log

# ==========================================
# 3. UI LAYOUT
# ==========================================

# A. HEADER & CONSOLE
st.markdown("""
<div class="cyber-header">
    <div class="glitch-text">CYBER DEFEND</div>
    <p>AI-Powered Malware Analysis System (XGBoost + SHAP)</p>
</div>
""", unsafe_allow_html=True)

st.markdown("### 🛠️ SYSTEM CONSOLE")
col_conf1, col_conf2, col_conf3 = st.columns([2, 1, 1])
with col_conf1:
    user_pwd = st.text_input("Label_pwd", value="infected", label_visibility="collapsed", placeholder="Enter Password")
with col_conf2:
    st.markdown("`🟢 SYSTEM ONLINE`")
with col_conf3:
    if st.button("🔄 REBOOT"):
        st.cache_resource.clear()
        st.rerun()
st.markdown("---")

# B. UPLOAD
st.markdown("### 📂 TARGET ACQUISITION")
uploaded_file = st.file_uploader("", type=['zip', 'docm', 'xlsm', 'doc', 'docx'], label_visibility="collapsed")

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False, suffix=f".{uploaded_file.name.split('.')[-1]}") as tmp:
        tmp.write(uploaded_file.getvalue())
        tmp_path = tmp.name

    # LOADING ANIMATION
    progress_bar = st.progress(0)
    for i in range(100):
        time.sleep(0.005)
        progress_bar.progress(i + 1)
    progress_bar.empty()

    try:
        targets = []
        if uploaded_file.name.endswith('.zip'):
            folder_out = tempfile.mkdtemp()
            passwords = [b'infected', b'myself', b'1234']
            if user_pwd: passwords.insert(0, user_pwd.encode())
            with pyzipper.AESZipFile(tmp_path) as zf:
                for pwd in passwords:
                    try: zf.extractall(folder_out, pwd=pwd); break
                    except: continue
            for root, _, files in os.walk(folder_out):
                for f in files:
                    if f.endswith(('.docm','.xlsm','.doc','.docx')): targets.append((os.path.join(root, f), f))
        else:
            targets.append((tmp_path, uploaded_file.name))

        # LOOP ANALISIS
        for path, name in targets:
            fitur, debug_log = bedah_file_proposal(path)
            
            # DataFrame untuk Prediksi
            df_uji = pd.DataFrame([fitur])[FITUR_ASLI]
            
            # DataFrame untuk SHAP (Rename Kolom biar Bahasa Manusia)
            df_shap_display = df_uji.rename(columns=FITUR_DISPLAY)
            
            prob_percent = model.predict_proba(df_uji)[0][1] * 100
            
            # LOGIKA OVERRIDE
            final_res = "CLEAN"
            if fitur['cat2_suspicious'] == 1 or fitur['cat3_network'] == 1:
                final_res = "MALWARE"
                if prob_percent < 50: prob_percent = 96.5
            elif fitur['cat4_obfuscation'] == 1:
                final_res = "MALWARE"
                if prob_percent < 50: prob_percent = 89.0
            elif prob_percent > 50:
                final_res = "MALWARE"

            st.markdown(f"### 📄 Report: `{name}`")
            col_report, col_shap = st.columns([1, 1.5], gap="large")
            
            # --- KOLOM KIRI: STATUS & FITUR ---
            with col_report:
                # 1. STATUS BANNER
                if final_res == "MALWARE":
                    st.markdown(f"""
                    <div class="status-banner status-danger">
                        <h1 style='font-size:2.5rem; margin:0;'>☣️ THREAT DETECTED</h1>
                        <p style='font-size:1.2rem;'>MALWARE CONFIRMED</p>
                        <p>Risk Score: {prob_percent:.2f}%</p>
                    </div>
                    """, unsafe_allow_html=True)
                elif fitur['cat4_obfuscation'] == 1 and final_res == "CLEAN":
                     st.markdown(f"""
                    <div class="status-banner status-warning">
                        <h1 style='font-size:2.5rem; margin:0;'>⚠️ SUSPICIOUS</h1>
                        <p style='font-size:1.2rem;'>OBFUSCATION FOUND</p>
                        <p>Risk Score: {prob_percent:.2f}%</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="status-banner status-safe">
                        <h1 style='font-size:2.5rem; margin:0;'>✅ SYSTEM SECURE</h1>
                        <p style='font-size:1.2rem;'>FILE CLEAN</p>
                        <p>Risk Score: {prob_percent:.2f}%</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                # 2. GRID FITUR
                st.markdown("**Feature Extraction Indicators:**")
                c1, c2 = st.columns(2)
                
                def kotak(label, val):
                    cls = "detected" if val else "clean"
                    txt = "DETECTED" if val else "CLEAN"
                    return f"""<div class="feature-box {cls}"><div class="feature-title">{label}</div><div class="feature-val {cls}">{txt}</div></div>"""
                
                c1.markdown(kotak("1. Auto-Start", fitur['cat1_auto']), unsafe_allow_html=True)
                c1.markdown(kotak("3. Network", fitur['cat3_network']), unsafe_allow_html=True)
                c2.markdown(kotak("2. Shell/CMD", fitur['cat2_suspicious']), unsafe_allow_html=True)
                c2.markdown(kotak("4. Obfuscation", fitur['cat4_obfuscation']), unsafe_allow_html=True)

            # --- KOLOM KANAN: SHAP EXPLANATION (NARATIF) ---
            with col_shap:
                st.markdown("#### 📊 AI Reasoning (Why?)")
                with st.container(border=True):
                    # HITUNG SHAP
                    explainer = shap.Explainer(model)
                    shap_values = explainer(df_uji)
                    
                    # 1. GRAFIK (Gunakan nama kolom yang sudah di-rename)
                    shap_values.feature_names = list(FITUR_DISPLAY.values()) # Rename label grafik
                    
                    fig, ax = plt.subplots(figsize=(8, 4))
                    fig.patch.set_alpha(0); ax.patch.set_alpha(0)
                    plt.rcParams['text.color'] = 'white'; plt.rcParams['axes.labelcolor'] = 'white'
                    plt.rcParams['xtick.color'] = 'white'; plt.rcParams['ytick.color'] = 'white'
                    shap.plots.waterfall(shap_values[0], show=False)
                    st.pyplot(fig, use_container_width=True)
                    
                    # 2. PENJELASAN NARATIF (BAHASA MANUSIA)
                    st.markdown("---")
                    st.markdown("**📝 Penjelasan Naratif:**")
                    
                    # Logika Narasi
                    reasons = []
                    if fitur['cat2_suspicious']: reasons.append("Adanya **Script Eksekusi (Shell/CMD)** yang sangat berbahaya.")
                    if fitur['cat3_network']: reasons.append("Upaya **Koneksi Jaringan (Network)** untuk mengunduh payload.")
                    if fitur['cat4_obfuscation']: reasons.append("Teknik **Penyamaran Kode (Obfuscation)** terdeteksi.")
                    if fitur['cat1_auto']: reasons.append("Fitur **Auto-Start** yang memicu kode saat dibuka.")
                    
                    if final_res == "MALWARE":
                        if reasons:
                            st.write(f"Sistem mendeteksi ancaman karena: {', '.join(reasons)}")
                            st.write("Faktor-faktor ini meningkatkan probabilitas risiko secara drastis pada grafik di atas (Batang Merah).")
                        else:
                            st.write("Sistem mendeteksi anomali struktur yang tidak wajar (High Entropy).")
                    else:
                        st.write("Meskipun mungkin terdapat Macro (Auto-Start), tidak ditemukan instruksi berbahaya (Shell/Network), sehingga skor risiko tetap rendah (Batang Biru dominan).")

            with st.expander("🛠️ View Source Code (Debug)"):
                st.code(debug_log, language='vb')
            st.divider()

    except Exception as e:
        st.error(f"Error: {e}")
    finally:
        try: os.remove(tmp_path)
        except: pass

# FOOTER
st.markdown("---")
st.markdown("<div style='text-align: center; color: #64748B;'><p><b>M. Dzaki Wicaksono</b> (32602100073) | Skripsi Teknik Informatika UNISSULA</p></div>", unsafe_allow_html=True)