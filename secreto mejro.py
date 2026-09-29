#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auditoría OSINT Personal
=========================
Herramienta para comprobar tu propia huella digital:
  1) Existencia de perfiles con tu alias en +30 plataformas públicas.
  2) Menciones de tu alias o nombre en prensa/blogs (búsqueda simple en DuckDuckGo).
  3) Exportación de resultados a CSV y JSON para tu propio registro.

Uso previsto: auditar y proteger TU PROPIA información. No usar sobre
terceros sin su consentimiento explícito.

Requisitos:
    pip install requests tqdm

Uso:
    python auditoria_osint.py
"""

import csv
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
from tqdm import tqdm

# ----------------------------------------------------------------------------
# CONFIGURACIÓN
# ----------------------------------------------------------------------------

TIMEOUT = 5
MAX_HILOS = 10
CARPETA_INFORMES = "Informes_OSINT"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

ENCONTRADO = "found"
NO_ENCONTRADO = "not_found"
ERROR = "error"

# metodo:
#   "status"  -> 200 = existe, 404 = no existe
#   "ausente" -> 200 y el texto 'marca' NO aparece = existe
#   "presente"-> 200 y el texto 'marca' SÍ aparece = existe
PLATAFORMAS = {
    "GitHub":       {"url": "https://github.com/{}", "metodo": "status"},
    "GitLab":       {"url": "https://gitlab.com/{}", "metodo": "status"},
    "Reddit":       {"url": "https://www.reddit.com/user/{}",
                     "check": "https://www.reddit.com/user/{}/about.json",
                     "metodo": "status"},
    "Instagram":    {"url": "https://www.instagram.com/{}/", "metodo": "status", "aviso": True},
    "Twitter / X":  {"url": "https://x.com/{}", "metodo": "status", "aviso": True},
    "TikTok":       {"url": "https://www.tiktok.com/@{}", "metodo": "status"},
    "Pinterest":    {"url": "https://www.pinterest.com/{}/", "metodo": "status"},
    "YouTube":      {"url": "https://www.youtube.com/@{}", "metodo": "status"},
    "Twitch":       {"url": "https://www.twitch.tv/{}",
                     "check": "https://decapi.me/twitch/id/{}",
                     "metodo": "ausente", "marca": "User not found"},
    "Spotify":      {"url": "https://open.spotify.com/user/{}", "metodo": "status", "aviso": True},
    "Steam":        {"url": "https://steamcommunity.com/id/{}",
                     "metodo": "ausente",
                     "marca": "The specified profile could not be found"},
    "Duolingo":     {"url": "https://www.duolingo.com/profile/{}",
                     "check": "https://www.duolingo.com/2017-06-30/users?username={}",
                     "metodo": "ausente", "marca": '"users":[]'},
    "Medium":       {"url": "https://medium.com/@{}", "metodo": "status"},
    "Dev.to":       {"url": "https://dev.to/{}", "metodo": "status"},
    "Telegram":     {"url": "https://t.me/{}", "metodo": "presente", "marca": "tgme_page_title"},
    "SoundCloud":   {"url": "https://soundcloud.com/{}", "metodo": "status"},
    "Vimeo":        {"url": "https://vimeo.com/{}", "metodo": "status"},
    "Behance":      {"url": "https://www.behance.net/{}", "metodo": "status"},
    "Dribbble":     {"url": "https://dribbble.com/{}", "metodo": "status"},
    "Chess.com":    {"url": "https://www.chess.com/member/{}",
                     "check": "https://api.chess.com/pub/player/{}",
                     "metodo": "status"},
    "Lichess":      {"url": "https://lichess.org/@/{}",
                     "check": "https://lichess.org/api/user/{}",
                     "metodo": "status"},
    "Hacker News":  {"url": "https://news.ycombinator.com/user?id={}",
                     "metodo": "ausente", "marca": "No such user."},
    "Keybase":      {"url": "https://keybase.io/{}", "metodo": "status"},
    "Patreon":      {"url": "https://www.patreon.com/{}", "metodo": "status"},
    "Replit":       {"url": "https://replit.com/@{}", "metodo": "status"},
    "Linktree":     {"url": "https://linktr.ee/{}", "metodo": "status"},
    "Snapchat":     {"url": "https://www.snapchat.com/add/{}", "metodo": "status"},
    "Flickr":       {"url": "https://www.flickr.com/people/{}", "metodo": "status"},
    "Tumblr":       {"url": "https://{}.tumblr.com", "metodo": "status"},
    "About.me":     {"url": "https://about.me/{}", "metodo": "status"},
    "Codepen":      {"url": "https://codepen.io/{}", "metodo": "status"},
    "Kaggle":       {"url": "https://www.kaggle.com/{}", "metodo": "status"},
    "HackerRank":   {"url": "https://www.hackerrank.com/{}", "metodo": "status"},
    "Product Hunt": {"url": "https://www.producthunt.com/@{}", "metodo": "status"},
    "Letterboxd":   {"url": "https://letterboxd.com/{}/", "metodo": "status"},
    "VSCO":         {"url": "https://vsco.co/{}", "metodo": "status"},
    "Slideshare":   {"url": "https://www.slideshare.net/{}", "metodo": "status"},
    "Roblox":       {"url": "https://www.roblox.com/user.aspx?username={}", "metodo": "status"},
}

# ----------------------------------------------------------------------------
# UTILIDADES DE INTERFAZ
# ----------------------------------------------------------------------------

def limpiar_pantalla():
    os.system("cls" if os.name == "nt" else "clear")


def mostrar_banner():
    print("=" * 62)
    print("🛡️   AUDITORÍA OSINT PERSONAL — Conoce tu huella digital")
    print("=" * 62)
    print()


def pedir_alias():
    patron = re.compile(r"^[A-Za-z0-9._-]{1,30}$")
    while True:
        alias = input("👤 Introduce TU alias/usuario a auditar: ").strip().lstrip("@")
        if patron.match(alias):
            return alias
        print("   ⚠️  Usa solo letras, números, '.', '_' o '-' (máx. 30).\n")


def pedir_nombre_real():
    nombre = input("🪪  Introduce TU nombre y apellidos (opcional, Enter para omitir): ").strip()
    return nombre


def menu_principal():
    mostrar_banner()
    print("¿Qué quieres auditar?\n")
    print("  [1] Solo perfiles en redes sociales")
    print("  [2] Solo menciones públicas (prensa/blogs) de tu alias o nombre")
    print("  [3] Auditoría completa (redes + menciones)")
    print()
    while True:
        opcion = input("Elige una opción (1/2/3): ").strip()
        if opcion in ("1", "2", "3"):
            return opcion
        print("   ⚠️  Opción no válida.\n")


# ----------------------------------------------------------------------------
# MÓDULO 1: PERFILES EN REDES SOCIALES
# ----------------------------------------------------------------------------

def comprobar_plataforma(nombre, config, usuario, sesion):
    url_perfil = config["url"].format(usuario)
    url_check = config.get("check", config["url"]).format(usuario)

    try:
        resp = sesion.get(url_check, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
    except requests.exceptions.Timeout:
        return nombre, ERROR, url_perfil, "Tiempo de espera agotado"
    except requests.exceptions.ConnectionError:
        return nombre, ERROR, url_perfil, "No se pudo conectar"
    except requests.exceptions.TooManyRedirects:
        return nombre, ERROR, url_perfil, "Demasiadas redirecciones"
    except requests.exceptions.RequestException as exc:
        return nombre, ERROR, url_perfil, f"Error: {type(exc).__name__}"

    codigo = resp.status_code
    metodo = config["metodo"]

    if codigo in (401, 403, 429) or codigo >= 500:
        return nombre, ERROR, url_perfil, f"Respuesta HTTP {codigo}"

    if metodo == "status":
        if codigo == 200:
            return nombre, ENCONTRADO, url_perfil, ""
        if codigo == 404:
            return nombre, NO_ENCONTRADO, url_perfil, ""
        return nombre, ERROR, url_perfil, f"Respuesta HTTP {codigo}"

    if metodo in ("ausente", "presente"):
        if codigo == 404:
            return nombre, NO_ENCONTRADO, url_perfil, ""
        if codigo != 200:
            return nombre, ERROR, url_perfil, f"Respuesta HTTP {codigo}"
        marca_en_texto = config["marca"] in resp.text
        existe = (not marca_en_texto) if metodo == "ausente" else marca_en_texto
        return nombre, (ENCONTRADO if existe else NO_ENCONTRADO), url_perfil, ""

    return nombre, ERROR, url_perfil, "Método de comprobación desconocido"


def escanear_redes_sociales(usuario):
    resultados = []
    with requests.Session() as sesion, ThreadPoolExecutor(max_workers=MAX_HILOS) as pool:
        futuros = {
            pool.submit(comprobar_plataforma, nombre, cfg, usuario, sesion): nombre
            for nombre, cfg in PLATAFORMAS.items()
        }
        barra = tqdm(as_completed(futuros), total=len(futuros),
                     desc="🔎 Escaneando plataformas", ncols=70)
        for futuro in barra:
            resultados.append(futuro.result())
    return sorted(resultados, key=lambda r: r[0].lower())


def mostrar_resultados_redes(usuario, resultados):
    print(f"\n📋 Perfiles para: {usuario}\n")
    for nombre, estado, url, detalle in resultados:
        aviso = " *" if PLATAFORMAS[nombre].get("aviso") else ""
        if estado == ENCONTRADO:
            print(f"✅ {nombre + aviso:<15} {url}")
        elif estado == NO_ENCONTRADO:
            print(f"❌ {nombre + aviso:<15} No encontrado")
        else:
            print(f"⚠️  {nombre + aviso:<15} Error de conexión ({detalle})")

    encontrados = sum(1 for r in resultados if r[1] == ENCONTRADO)
    no_enc = sum(1 for r in resultados if r[1] == NO_ENCONTRADO)
    errores = sum(1 for r in resultados if r[1] == ERROR)
    print("\n" + "-" * 62)
    print(f"✅ Encontrados: {encontrados}   ❌ No encontrados: {no_enc}   ⚠️  Errores: {errores}")
    print("* Plataforma que puede responder igual exista o no el perfil (revisar manualmente).")
    print("-" * 62)


# ----------------------------------------------------------------------------
# MÓDULO 2: MENCIONES PÚBLICAS (DuckDuckGo HTML)
# ----------------------------------------------------------------------------

def buscar_menciones(consulta, max_resultados=15):
    """
    Busca menciones públicas de una consulta (alias o nombre) usando
    el endpoint HTML de DuckDuckGo. Sin técnicas de evasión agresivas:
    una única petición, cabecera estándar, uso informativo.
    """
    url = "https://html.duckduckgo.com/html/"
    try:
        resp = requests.post(
            url,
            data={"q": consulta},
            headers=HEADERS,
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
    except requests.exceptions.RequestException as exc:
        print(f"⚠️  No se pudo consultar el buscador: {type(exc).__name__}")
        return []

    # Extracción simple con regex: enlaces y fragmentos de texto (snippets)
    bloques_resultado = re.findall(
        r'<a rel="nofollow" class="result__a" href="(.*?)".*?>(.*?)</a>.*?'
        r'<a class="result__snippet".*?>(.*?)</a>',
        resp.text, re.DOTALL,
    )

    def limpiar_html(texto):
        texto = re.sub(r"<.*?>", "", texto)
        return re.sub(r"\s+", " ", texto).strip()

    resultados = []
    for enlace, titulo, snippet in bloques_resultado[:max_resultados]:
        resultados.append({
            "titulo": limpiar_html(titulo),
            "url": enlace,
            "snippet": limpiar_html(snippet),
        })
    return resultados


def mostrar_menciones(consulta, resultados):
    print(f"\n📰 Menciones públicas para: \"{consulta}\"\n")
    if not resultados:
        print("   (Sin resultados o el buscador no devolvió contenido parseable)")
        return
    for i, r in enumerate(resultados, start=1):
        print(f"{i}. 🔗 {r['titulo']}")
        print(f"   {r['url']}")
        if r["snippet"]:
            print(f"   📝 {r['snippet']}")
        print()


def modulo_menciones(alias, nombre_real):
    todas = {}
    consultas = [alias]
    if nombre_real:
        consultas.append(f'"{nombre_real}"')

    for consulta in consultas:
        resultados = buscar_menciones(consulta)
        mostrar_menciones(consulta, resultados)
        todas[consulta] = resultados
        time.sleep(1.5)  # pausa cortés entre consultas al buscador
    return todas


# ----------------------------------------------------------------------------
# MÓDULO 3: EXPORTACIÓN DE INFORME
# ----------------------------------------------------------------------------

def guardar_informe(alias, nombre_real, resultados_redes, resultados_menciones):
    os.makedirs(CARPETA_INFORMES, exist_ok=True)
    marca_tiempo = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"auditoria_{alias}_{marca_tiempo}"

    # --- JSON completo ---
    informe = {
        "alias": alias,
        "nombre_real": nombre_real or None,
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "perfiles": [
            {"plataforma": n, "estado": e, "url": u, "detalle": d}
            for n, e, u, d in (resultados_redes or [])
        ],
        "menciones": resultados_menciones or {},
    }
    ruta_json = os.path.join(CARPETA_INFORMES, base + ".json")
    with open(ruta_json, "w", encoding="utf-8") as f:
        json.dump(informe, f, ensure_ascii=False, indent=2)

    # --- CSV solo de perfiles (más fácil de abrir en Excel) ---
    ruta_csv = os.path.join(CARPETA_INFORMES, base + "_perfiles.csv")
    if resultados_redes:
        with open(ruta_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Plataforma", "Estado", "URL", "Detalle"])
            for n, e, u, d in resultados_redes:
                writer.writerow([n, e, u, d])

    print("\n💾 Informe guardado en:")
    print(f"   📄 {ruta_json}")
    if resultados_redes:
        print(f"   📄 {ruta_csv}")


# ----------------------------------------------------------------------------
# FLUJO PRINCIPAL
# ----------------------------------------------------------------------------

def main():
    limpiar_pantalla()
    opcion = menu_principal()
    print()
    alias = pedir_alias()
    nombre_real = ""
    if opcion in ("2", "3"):
        nombre_real = pedir_nombre_real()

    resultados_redes = None
    resultados_menciones = None

    if opcion in ("1", "3"):
        print()
        resultados_redes = escanear_redes_sociales(alias)

    if opcion in ("2", "3"):
        resultados_menciones = modulo_menciones(alias, nombre_real)

    limpiar_pantalla()
    mostrar_banner()
    if resultados_redes is not None:
        mostrar_resultados_redes(alias, resultados_redes)
    if resultados_menciones is not None:
        for consulta, res in resultados_menciones.items():
            mostrar_menciones(consulta, res)

    guardar_informe(alias, nombre_real, resultados_redes, resultados_menciones)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Auditoría cancelada por el usuario.")
        sys.exit(0)