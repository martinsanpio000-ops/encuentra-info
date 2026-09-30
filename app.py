#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auditoría de Identidad Digital — app.py (Streamlit Cloud)
============================================================
Comprueba si TU alias/usuario existe en plataformas que responden
de forma fiable a peticiones desde servidores en la nube (GitHub,
GitLab, Gravatar/WordPress, Reddit, YouTube), y ofrece un enlace de
desambiguación manual en DuckDuckGo para revisar el resto de la web
tú mismo.

No hace scraping agresivo ni parsea perfiles en busca de datos
personales expuestos de terceros: solo confirma existencia (200/404)
de TU propio alias, con manejo de errores que nunca cuelga la app.

Requisitos (requirements.txt):
    streamlit
    requests
"""

import time
import urllib.parse

import requests
import streamlit as st

# ----------------------------------------------------------------------------
# CONFIGURACIÓN
# ----------------------------------------------------------------------------

TIMEOUT = 6

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
}

ENCONTRADO = "found"
NO_ENCONTRADO = "not_found"
BLOQUEADO = "blocked"

# Plataformas elegidas porque suelen responder de forma estable a
# peticiones automatizadas desde IPs de servidores en la nube
# (a diferencia de Instagram, X o TikTok, que bloquean agresivamente
# el tráfico de datacenter).
PLATAFORMAS = {
    "GitHub": {
        "url": "https://github.com/{}",
        "metodo": "status",
    },
    "GitLab": {
        "url": "https://gitlab.com/{}",
        "metodo": "status",
    },
    "Gravatar / WordPress": {
        "url": "https://gravatar.com/{}",
        "metodo": "status",
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{}",
        "check": "https://www.reddit.com/user/{}/about.json",
        "metodo": "status",
    },
    "YouTube": {
        "url": "https://www.youtube.com/@{}",
        "metodo": "status",
    },
}

# ----------------------------------------------------------------------------
# LÓGICA DE COMPROBACIÓN (blindada contra cuelgues)
# ----------------------------------------------------------------------------

def comprobar_plataforma(nombre, config, usuario):
    """
    Comprueba una plataforma. Nunca lanza excepciones hacia fuera:
    cualquier fallo de red se traduce en estado BLOQUEADO con un
    mensaje claro, para que la interfaz nunca se quede colgada ni
    muestre un traceback en rojo/rosa.
    """
    url_perfil = config["url"].format(usuario)
    url_check = config.get("check", config["url"]).format(usuario)

    try:
        resp = requests.get(
            url_check, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True
        )
    except requests.exceptions.Timeout:
        return nombre, BLOQUEADO, url_perfil, "Tiempo de espera agotado"
    except requests.exceptions.ConnectionError:
        return nombre, BLOQUEADO, url_perfil, "No se pudo conectar"
    except requests.exceptions.TooManyRedirects:
        return nombre, BLOQUEADO, url_perfil, "Demasiadas redirecciones"
    except requests.exceptions.RequestException as exc:
        return nombre, BLOQUEADO, url_perfil, f"{type(exc).__name__}"

    codigo = resp.status_code

    # Bloqueos típicos de firewall / anti-bot / límite de peticiones
    if codigo in (401, 403, 429) or codigo >= 500:
        return nombre, BLOQUEADO, url_perfil, f"HTTP {codigo}"

    if codigo == 200:
        return nombre, ENCONTRADO, url_perfil, ""
    if codigo == 404:
        return nombre, NO_ENCONTRADO, url_perfil, ""

    return nombre, BLOQUEADO, url_perfil, f"HTTP {codigo} inesperado"


def enlace_duckduckgo(usuario):
    """Construye un enlace de búsqueda manual para desambiguación."""
    consulta = f'"{usuario}"'
    return "https://duckduckgo.com/?q=" + urllib.parse.quote(consulta)


# ----------------------------------------------------------------------------
# INTERFAZ STREAMLIT
# ----------------------------------------------------------------------------

st.set_page_config(
    page_title="Auditoría de Identidad Digital",
    page_icon="🛡️",
    layout="centered",
)

# --- Estilos: modo oscuro nativo reforzado con CSS ligero ---
st.markdown(
    """
    <style>
    .stApp {
        background-color: #1e1f26;
        color: #e8e8e8;
    }
    div[data-testid="stMetric"] {
        background-color: #2a2c38;
        border-radius: 10px;
        padding: 10px;
    }
    .resultado-fila {
        padding: 10px 14px;
        border-radius: 8px;
        margin-bottom: 8px;
        background-color: #2a2c38;
    }
    a { color: #4fc3f7 !important; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ Auditoría de Identidad Digital")
st.caption(
    "Comprueba tu propia huella digital en plataformas que responden de forma "
    "estable desde servidores en la nube. Para el resto de la web, usa el "
    "enlace de desambiguación manual en DuckDuckGo."
)

usuario = st.text_input("👤 Tu alias o nombre de usuario", placeholder="ej: juanperez_92")

col_buscar, col_ddg = st.columns([2, 1])
buscar = col_buscar.button("🔎 Iniciar comprobación", use_container_width=True, type="primary")

if usuario.strip():
    col_ddg.link_button(
        "🌐 Desambiguar en DuckDuckGo",
        enlace_duckduckgo(usuario.strip()),
        use_container_width=True,
    )
else:
    col_ddg.button("🌐 Desambiguar en DuckDuckGo", disabled=True, use_container_width=True)

st.divider()

if buscar:
    usuario_limpio = usuario.strip().lstrip("@")

    if not usuario_limpio:
        st.warning("⚠️ Introduce un nombre de usuario antes de buscar.")
    else:
        total = len(PLATAFORMAS)
        barra = st.progress(0, text="Iniciando comprobación...")
        contenedor_resultados = st.container()

        resultados = []
        for i, (nombre, config) in enumerate(PLATAFORMAS.items(), start=1):
            barra.progress(i / total, text=f"Comprobando {nombre}...")
            resultado = comprobar_plataforma(nombre, config, usuario_limpio)
            resultados.append(resultado)
            time.sleep(0.15)  # pausa cortés, no es evasión, solo throttling suave

        barra.progress(1.0, text="Comprobación finalizada.")
        time.sleep(0.3)
        barra.empty()

        encontrados = sum(1 for r in resultados if r[1] == ENCONTRADO)
        no_encontrados = sum(1 for r in resultados if r[1] == NO_ENCONTRADO)
        bloqueados = sum(1 for r in resultados if r[1] == BLOQUEADO)

        c1, c2, c3 = st.columns(3)
        c1.metric("✅ Encontrados", encontrados)
        c2.metric("❌ No encontrados", no_encontrados)
        c3.metric("⚠️ Red protegida", bloqueados)

        st.subheader("📋 Resultados")
        with contenedor_resultados:
            for nombre, estado, url, detalle in resultados:
                if estado == ENCONTRADO:
                    st.markdown(
                        f'<div class="resultado-fila">✅ <b>{nombre}</b> — '
                        f'<a href="{url}" target="_blank">{url}</a></div>',
                        unsafe_allow_html=True,
                    )
                elif estado == NO_ENCONTRADO:
                    st.markdown(
                        f'<div class="resultado-fila">❌ <b>{nombre}</b> — No encontrado</div>',
                        unsafe_allow_html=True,
                    )
                else:  # BLOQUEADO
                    st.markdown(
                        f'<div class="resultado-fila">⚠️ <b>{nombre}</b> — '
                        f'Red protegida / Requiere verificación manual '
                        f'<span style="color:#8a8d9f;">({detalle})</span></div>',
                        unsafe_allow_html=True,
                    )

        if bloqueados:
            st.info(
                "Algunas plataformas bloquean peticiones automatizadas desde "
                "servidores en la nube (firewalls anti-bot). Para esas, revisa "
                "manualmente tu perfil o usa el botón de DuckDuckGo de arriba."
            )
else:
    st.caption("Introduce tu alias y pulsa **Iniciar comprobación** para empezar.")
