import streamlit as st
import requests
import time
import urllib.parse

# Configuración visual de la página web
st.set_page_config(page_title="Sistema Recon OSINT", page_icon="🕵️‍♂️", layout="centered")

st.title("🕵️‍♂️ Sistema Recon OSINT — Web Global")
st.write("Versión optimizada en la nube basada en el motor avanzado de Claude.")

# Cuadro de texto en la web para escribir el nombre
objetivo = st.text_input("👤 Introduce el nombre de usuario o alias a rastrear:", "").strip()

if st.button("🚀 Iniciar Rastreo Avanzado"):
    if not objetivo:
        st.warning("❌ Por favor, introduce un término de búsqueda.")
    else:
        st.write(f"📡 Escaneando bases de datos globales para: **{objetivo}**...")
        
        # El motor completo de Claude adaptado a la web
        PLATAFORMAS = {
            "GitHub":      {"url": "https://github.com{}", "metodo": "status"},
            "GitLab":      {"url": "https://gitlab.com{}", "metodo": "status"},
            "Reddit":      {"url": "https://reddit.com{}", "metodo": "status"},
            "Instagram":   {"url": "https://instagram.com{}/", "metodo": "status"},
            "TikTok":      {"url": "https://tiktok.com@{}", "metodo": "status"},
            "Pinterest":   {"url": "https://pinterest.com{}/", "metodo": "status"},
            "YouTube":     {"url": "https://youtube.com@{}", "metodo": "status"},
            "Twitch":      {"url": "https://decapi.me{}", "metodo": "ausente", "marca": "User not found", "real_url": "https://twitch.tv{}"},
            "Spotify":     {"url": "https://spotify.com{}", "metodo": "status"},
            "Steam":       {"url": "https://steamcommunity.com{}", "metodo": "ausente", "marca": "The specified profile could not be found"},
            "Duolingo":    {"url": "https://duolingo.com{}", "metodo": "ausente", "marca": '"users":[]', "real_url": "https://duolingo.com{}"},
            "Medium":      {"url": "https://medium.com@{}", "metodo": "status"},
            "Telegram":    {"url": "https://t.me{}", "metodo": "presente", "marca": "tgme_page_title"},
            "SoundCloud":  {"url": "https://soundcloud.com{}", "metodo": "status"},
            "Vimeo":       {"url": "https://vimeo.com{}", "metodo": "status"},
            "Behance":     {"url": "https://behance.net{}", "metodo": "status"},
            "Chess.com":   {"url": "https://chess.com{}", "metodo": "status", "real_url": "https://chess.com{}"},
            "Lichess":     {"url": "https://lichess.org{}", "metodo": "status", "real_url": "https://lichess.org{}"},
            "Linktree":    {"url": "https://linktr.ee{}", "metodo": "status"},
            "Snapchat":    {"url": "https://snapchat.com{}", "metodo": "status"},
        }
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        barra_progreso = st.progress(0)
        total = len(PLATAFORMAS)
        encontrados = 0
        
        with st.expander("📋 Dossier de Resultados Activos", expanded=True):
            for i, (nombre, config) in enumerate(PLATAFORMAS.items()):
                url_check = config["url"].format(objetivo)
                url_final = config.get("real_url", config["url"]).format(objetivo)
                
                try:
                    resp = requests.get(url_check, headers=headers, timeout=5)
                    metodo = config["metodo"]
                    existe = False
                    
                    if metodo == "status" and resp.status_code == 200:
                        existe = True
                    elif metodo in ("ausente", "presente") and resp.status_code == 200:
                        marca_en_texto = config["marca"] in resp.text
                        existe = (not marca_en_texto) if metodo == "ausente" else marca_en_texto
                        
                    if existe:
                        st.markdown(f"✅ **[ENCONTRADO]** {nombre}: [{url_final}]({url_final})")
                        encontrados += 1
                    else:
                        st.write(f"❌ [No detectado] {nombre}")
                except:
                    st.write(f"⚠️ [Error de Conexión] {nombre}")
                
                barra_progreso.progress((i + 1) / total)
                time.sleep(0.05)
                
        st.success(f"📊 Extracción finalizada. {encontrados} canales confirmados en la red.")
