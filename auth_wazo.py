"""
Integración de autenticación con Wazo (wazo-auth) — VOXDEI
-------------------------------------------------------------
Wazo emite tokens OPACOS con expiración (no JWT): el token es solo un
identificador, y wazo-auth guarda su estado real del lado del
servidor (válido / revocado / expirado). Por eso se comporta más
como una sesión de base de datos que como un JWT autocontenido -- hay
que preguntarle a wazo-auth si el token sigue siendo válido, no se
puede verificar solo localmente.

Flujo:
  1. POST /0.1/token a wazo-auth, con Basic Auth (usuario:contraseña
     REALES de Wazo) -> wazo-auth responde con un token + metadata.
  2. VOXDEI guarda ESE TOKEN en la sesión de Flask (nunca la
     contraseña).
  3. revalidate_token() permite re-confirmar contra wazo-auth que el
     token sigue vivo -- no se llama en cada request por costo de red,
     se deja disponible para usarla antes de acciones sensibles.
  4. El ROL de VOXDEI (SuperAdmin/Admin/Operador) NO viene de Wazo.
     Wazo solo confirma identidad; la autorización por rol se mapea
     aquí mismo, en WAZO_ROLE_MAP. Es el patrón "autenticación externa,
     autorización local" -- común cuando el IdP no conoce los roles
     de la aplicación que lo consume.

ADVERTENCIA HONESTA: no tengo un servidor Wazo real contra el cual
probar esto desde este entorno, así que lo siguiente está escrito
siguiendo la documentación oficial de la REST API de wazo-auth, pero
NO está probado end-to-end como sí hice con el resto de VOXDEI. Antes
de confiar en esto:
  1. Haz un login de prueba manual (curl de abajo) contra tu Wazo real.
  2. Compara el JSON que te regresa contra lo que este código espera
     (payload["token"], payload["metadata"], etc.)
  3. Si tu versión de Wazo devuelve campos distintos, dime exactamente
     qué te regresó y ajusto el parseo.

  curl -X POST https://TU_WAZO:9497/0.1/token \
       -u "usuario:contraseña" \
       -H "Content-Type: application/json" \
       -d '{"backend": "wazo_user", "expiration": 3600}'
"""

import os

import requests

WAZO_AUTH_HOST = os.environ.get("WAZO_AUTH_HOST", "localhost")
WAZO_AUTH_PORT = os.environ.get("WAZO_AUTH_PORT", "9497")
# Wazo usa HTTPS por default. Si tu wazo-auth queda detrás de un proxy
# que ya termina TLS (hablas HTTP en la red interna), o para pruebas
# locales, cambia esto a "http" con WAZO_AUTH_SCHEME=http.
WAZO_AUTH_SCHEME = os.environ.get("WAZO_AUTH_SCHEME", "https")
WAZO_VERIFY_SSL = os.environ.get("WAZO_VERIFY_SSL", "true").lower() == "true"
WAZO_BACKEND = os.environ.get("WAZO_AUTH_BACKEND", "wazo_user")
WAZO_TOKEN_EXPIRATION = int(os.environ.get("WAZO_TOKEN_EXPIRATION", "3600"))  # segundos

WAZO_BASE_URL = f"{WAZO_AUTH_SCHEME}://{WAZO_AUTH_HOST}:{WAZO_AUTH_PORT}/0.1"

# ---- PLACEHOLDER: autorización local (usuario de Wazo -> rol de VOXDEI) ----
# Ajusta esto a tus usuarios reales de Wazo. Si prefieres gestionar
# roles desde el propio Wazo (grupos o metadata del usuario) en vez de
# aquí, dímelo y lo cambiamos por una consulta a wazo-auth en vez de
# este diccionario fijo.
WAZO_ROLE_MAP = {
    # "usuario.wazo": "SuperAdmin" | "Admin" | "Operador"
}
WAZO_DEFAULT_ROLE = None  # None = si el usuario no está en el mapa, se le niega el acceso a VOXDEI


class WazoAuthError(Exception):
    """Credenciales inválidas, wazo-auth inalcanzable, o usuario sin rol mapeado."""
    pass


def wazo_login(username, password):
    """Pide un token a wazo-auth con las credenciales dadas.

    Devuelve (token, voxdei_role, wazo_payload) si todo sale bien.
    Lanza WazoAuthError en cualquier otro caso (mensaje pensado para
    mostrarse directo en el formulario de login)."""
    try:
        resp = requests.post(
            f"{WAZO_BASE_URL}/token",
            auth=(username, password),
            json={"backend": WAZO_BACKEND, "expiration": WAZO_TOKEN_EXPIRATION},
            verify=WAZO_VERIFY_SSL,
            timeout=5,
        )
    except requests.RequestException as e:
        raise WazoAuthError(
            f"No se pudo contactar a wazo-auth en {WAZO_AUTH_HOST}:{WAZO_AUTH_PORT}: {e}"
        )

    if resp.status_code != 200:
        raise WazoAuthError("Usuario o contraseña incorrectos (rechazado por wazo-auth).")

    try:
        payload = resp.json().get("data", {})
    except ValueError:
        raise WazoAuthError("wazo-auth respondió 200 pero el cuerpo no es JSON válido.")

    token = payload.get("token")
    if not token:
        raise WazoAuthError(
            "wazo-auth respondió 200 pero sin campo 'token' -- revisa el formato real de tu versión "
            "(ver advertencia al inicio de auth_wazo.py)."
        )

    role = WAZO_ROLE_MAP.get(username, WAZO_DEFAULT_ROLE)
    if role is None:
        raise WazoAuthError(
            f"'{username}' autenticó correctamente en Wazo, pero no tiene un rol asignado en VOXDEI "
            f"(agrega '{username}' a WAZO_ROLE_MAP en auth_wazo.py)."
        )

    return token, role, payload


def revalidate_token(token):
    """Confirma contra wazo-auth que el token sigue vivo (no expiró,
    no fue revocado). No se usa en cada request por el costo de red
    extra -- llámala antes de una acción sensible si quieres estar
    seguro de que la sesión sigue siendo válida en este momento."""
    try:
        resp = requests.get(f"{WAZO_BASE_URL}/token/{token}", verify=WAZO_VERIFY_SSL, timeout=5)
        return resp.status_code == 200
    except requests.RequestException:
        return False


def wazo_logout(token):
    """Revoca el token en wazo-auth (cierra la sesión del lado del
    servidor, no solo la cookie local de Flask)."""
    try:
        requests.delete(f"{WAZO_BASE_URL}/token/{token}", verify=WAZO_VERIFY_SSL, timeout=5)
    except requests.RequestException:
        pass  # si no se pudo revocar remotamente, igual limpiamos la sesión local
