"""Monitor de calificaciones: Telegram sin mostrar valores y estado cifrado."""
import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet, InvalidToken


class MonitorError(Exception):
    """Mensaje apto para registros públicos, sin URLs ni credenciales."""


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class Page(HTMLParser):
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.inputs = {}
        self.form_action = None
        self.tables = []
        self.depth = 0
        self.rows = self.row = self.cell = None
        self.year_select = False
        self.option = None
        self.selected_year = None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and self.form_action is None:
            self.form_action = attrs.get("action", "")
        if tag == "input" and attrs.get("name"):
            self.inputs[attrs["name"]] = attrs.get("value", "")
        if tag == "select":
            self.year_select = attrs.get("id") == "content_ddAño"
        if tag == "option" and self.year_select and "selected" in attrs:
            self.option = []
        if tag == "table":
            self.depth += 1
            if self.depth == 1:
                self.rows = []
        if self.depth == 1:
            if tag == "tr":
                self.row = []
            elif tag in ("td", "th") and self.row is not None:
                self.cell = []

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)
        if self.option is not None:
            self.option.append(data)

    def handle_endtag(self, tag):
        if tag == "option" and self.option is not None:
            self.selected_year = "".join(self.option).strip()
            self.option = None
        if tag == "select":
            self.year_select = False
        if self.depth == 1:
            if tag in ("td", "th") and self.cell is not None:
                self.row.append(" ".join("".join(self.cell).split()))
                self.cell = None
            elif tag == "tr" and self.row is not None:
                self.rows.append(self.row)
                self.row = None
            elif tag == "table":
                self.tables.append(self.rows)
                self.rows = None
        if tag == "table":
            self.depth -= 1


def parse_grades(html, year):
    """Compatible con las huellas del monitor anterior; no devuelve notas legibles."""
    page = Page(html)
    if page.selected_year != str(year):
        raise MonitorError("El portal no muestra el ciclo lectivo actual.")
    tables = [t for t in page.tables if t and t[0] and t[0][0] == "Docente" and "C1_TP1" in t[0]]
    if len(tables) != 1:
        raise MonitorError("No se reconoce la tabla de calificaciones.")
    headers = tables[0][0]
    if len(set(headers)) != len(headers):
        raise MonitorError("La tabla contiene columnas duplicadas.")
    subject = None
    fields = {}
    subjects = []
    for row in tables[0][1:]:
        if not row:
            continue
        if len(row) == 1:
            subject = row[0]
            continue
        if not subject or len(row) != len(headers):
            raise MonitorError("Cambió la estructura de las calificaciones.")
        values = [None if value in ("", "-", "S/C") else value for value in row[1:]]
        cells = {digest(column): {"pendiente": value is None, "huella": digest(canonical(value))}
                 for column, value in zip(headers[1:], values)}
        subjects.append({"id": digest(canonical([str(year), subject, row[0]])),
                         "materia": subject, "docente": row[0], "huella": digest(canonical(values)),
                         "celdas": cells})
        for column, value in zip(headers[1:], values):
            key = canonical([str(year), subject, row[0], column])
            if key in fields:
                raise MonitorError("Hay casilleros duplicados.")
            fields[key] = value
    if not fields:
        raise MonitorError("La tabla está vacía. Se conserva la referencia anterior.")
    keys = sorted(fields)
    return {"tabla": digest(canonical([[key, fields[key]] for key in keys])),
            "estructura": digest(canonical(keys)), "subjects": subjects}


@dataclass(frozen=True)
class Config:
    portal: str
    document: str
    password: str
    bot_token: str
    chat_id: str
    state_key: str

    @classmethod
    def from_env(cls):
        names = ("PORTAL_URL", "AUSTRALIS_DOCUMENTO", "AUSTRALIS_PASSWORD", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "STATE_KEY")
        if any(not os.environ.get(name, "").strip() for name in names):
            raise MonitorError("Falta configurar alguno de los secretos del monitor.")
        cfg = cls(*(os.environ[name].strip() for name in names))
        url = urlparse(cfg.portal)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise MonitorError("La dirección privada del portal no es válida.")
        if not re.fullmatch(r"\d+:[A-Za-z0-9_-]{20,}", cfg.bot_token) or not cfg.chat_id.isdecimal():
            raise MonitorError("El bot o el chat privado de Telegram no están configurados correctamente.")
        try:
            Fernet(cfg.state_key.encode())
        except (ValueError, TypeError):
            raise MonitorError("La clave de cifrado no es válida.") from None
        return cfg

    @property
    def origin(self):
        url = urlparse(self.portal)
        return f"{url.scheme}://{url.netloc}"


class OnlyOrigin(HTTPRedirectHandler):
    def __init__(self, origin):
        super().__init__()
        self.origin = origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urlparse(newurl)
        if f"{url.scheme}://{url.netloc}" != self.origin:
            raise MonitorError("Se bloqueó una redirección fuera del servicio autorizado.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_page(opener, request):
    try:
        with opener.open(request, timeout=30) as response:
            return response.read().decode(response.headers.get_content_charset() or "utf-8"), response.geturl()
    except MonitorError:
        raise
    except Exception:
        raise MonitorError("No se pudo consultar el portal. La referencia anterior se conserva.") from None


def fetch_grades(cfg, year):
    opener = build_opener(HTTPCookieProcessor(CookieJar()), OnlyOrigin(cfg.origin))
    login = cfg.origin + "/Login.aspx"
    html, _ = read_page(opener, login)
    form = Page(html)
    if "txUsuario" not in form.inputs or "txContraseña" not in form.inputs:
        raise MonitorError("No se reconoce el formulario de ingreso.")
    action = urljoin(login, form.form_action or login)
    url = urlparse(action)
    if f"{url.scheme}://{url.netloc}" != cfg.origin:
        raise MonitorError("El formulario no corresponde al portal autorizado.")
    payload = dict(form.inputs)
    payload.update({"txUsuario": cfg.document, "txContraseña": cfg.password})
    request = Request(action, data=urlencode(payload).encode(), headers={
        "Content-Type": "application/x-www-form-urlencoded", "Referer": login})
    _, destination = read_page(opener, request)
    if urlparse(destination).path.lower().endswith("login.aspx"):
        raise MonitorError("No se pudo iniciar sesión en el colegio.")
    html, destination = read_page(opener, cfg.portal)
    if any(part in destination.lower() for part in ("login.aspx", "sesionexpirada.aspx")):
        raise MonitorError("El portal no mantuvo la sesión.")
    return parse_grades(html, year)


def telegram_api(cfg, method, payload):
    # Rechaza redirecciones para que la clave no viaje a otra dirección.
    opener = build_opener(OnlyOrigin("https://api.telegram.org"))
    request = Request("https://api.telegram.org/bot" + cfg.bot_token + "/" + method,
                      data=canonical(payload).encode(),
                      headers={"Content-Type": "application/json"})
    try:
        with opener.open(request, timeout=30) as response:
            result = json.load(response)
        if not result.get("ok"):
            raise ValueError("No confirmado")
        return result.get("result")
    except Exception:
        raise MonitorError("Telegram no confirmó el envío. La referencia anterior se conserva.") from None


def telegram(cfg, text):
    return telegram_api(cfg, "sendMessage", {
        "chat_id": cfg.chat_id, "text": text, "disable_web_page_preview": True})


def change_types(previous, subject):
    """Clasifica casilleros a partir de huellas y de si estaban pendientes."""
    old = previous.get("celdas", {}).get(subject["id"])
    if not isinstance(old, dict) or set(old) != set(subject["celdas"]):
        return "Calificación actualizada"
    changes = set()
    for key, cell in subject["celdas"].items():
        before = old[key]
        if before == cell:
            continue
        if before["pendiente"] and not cell["pendiente"]:
            changes.add("Nota nueva")
        elif not before["pendiente"] and cell["pendiente"]:
            changes.add("Nota retirada")
        elif before["huella"] != cell["huella"]:
            changes.add("Nota corregida")
    return "; ".join(sorted(changes)) or "Calificación actualizada"


class EncryptedStore:
    def __init__(self, path, key):
        self.path = Path(path)
        self.cipher = Fernet(key.encode())

    def read(self):
        if not self.path.exists():
            return None
        try:
            return json.loads(self.cipher.decrypt(self.path.read_bytes()))
        except (InvalidToken, ValueError, OSError, TypeError):
            raise MonitorError("No se pudo verificar el estado cifrado. No se reemplazará.") from None

    def write(self, value):
        temp = self.path.with_suffix(".tmp")
        temp.write_bytes(self.cipher.encrypt(canonical(value).encode()))
        temp.replace(self.path)


def valid_reference(value):
    return (isinstance(value, dict) and value.get("version") == 1 and
            isinstance(value.get("year"), str) and isinstance(value.get("materias"), dict) and
            all(isinstance(value.get(k), str) and re.fullmatch(r"[a-f0-9]{64}", value[k]) for k in ("tabla", "estructura")))


def run_once(cfg, store, confirm=False, now=None):
    now = now or datetime.now(timezone.utc)
    previous = store.read()
    if previous is None and os.environ.get("INITIAL_STATE"):
        try:
            previous = json.loads(os.environ["INITIAL_STATE"])
        except ValueError:
            raise MonitorError("La referencia inicial privada no es válida.") from None
    if previous is not None and not valid_reference(previous):
        raise MonitorError("La referencia previa no es válida. Se requiere revisión.")
    year = str(now.astimezone(ZoneInfo("America/Argentina/Buenos_Aires")).year)
    current = fetch_grades(cfg, year)
    first = previous is None or previous["year"] != year
    if not first and previous["estructura"] != current["estructura"]:
        raise MonitorError("Cambió la estructura de materias o columnas. Se requiere revisión.")
    changed = not first and previous["tabla"] != current["tabla"]
    changes = [] if first else [m for m in current["subjects"] if previous["materias"].get(m["id"]) != m["huella"]]
    if changed and not changes:
        raise MonitorError("La tabla cambió de manera inesperada. Se conserva la referencia.")
    if confirm:
        telegram(cfg, "✅ Monitor conectado desde GitHub. Los avisos indican materia y docente, sin la calificación.\n\n" + cfg.portal)
    if first and not confirm:
        telegram(cfg, "✅ Primera lectura guardada desde GitHub. Te avisaré cuando cambien las calificaciones.\n\n" + cfg.portal)
    if changed:
        detail = "\n\n".join("Materia: " + m["materia"] + "\nDocente: " + m["docente"] +
                             "\nCambio: " + change_types(previous, m) for m in changes)
        message = "📚 Se actualizaron las calificaciones de:\n\n" + detail + "\n\nRevisá el portal:\n" + cfg.portal
        # Una tabla inesperadamente enorme debe fallar antes de enviar o avanzar.
        if len(message) > 3900:
            raise MonitorError("El aviso es demasiado extenso. Se conserva la referencia.")
        telegram(cfg, message)
    saved_at = (previous or {}).get("last_saved")
    try:
        keepalive = not saved_at or now - datetime.fromisoformat(saved_at) >= timedelta(days=7)
    except (ValueError, TypeError):
        keepalive = True
    if first or changed or keepalive or not store.path.exists() or "celdas" not in previous:
        store.write({"version": 1, "year": year, "tabla": current["tabla"], "estructura": current["estructura"],
                     "materias": {m["id"]: m["huella"] for m in current["subjects"]},
                     "celdas": {m["id"]: m["celdas"] for m in current["subjects"]},
                     "last_saved": now.isoformat()})
    print("Revisión completada. Aviso enviado." if changed else "Revisión completada sin cambios pendientes.")


def status_message(health):
    def local_time(value):
        if not value:
            return "Todavía no registrada"
        try:
            stamp = datetime.fromisoformat(value)
            if stamp.tzinfo is None:
                raise ValueError("Fecha sin zona")
            return stamp.astimezone(ZoneInfo("America/Argentina/Buenos_Aires")).strftime("%d/%m/%Y %H:%M:%S")
        except (TypeError, ValueError):
            return "No disponible"
    result = "✅ La última revisión terminó bien." if health.get("last_result") == "ok" else \
             "⚠️ La última revisión no se pudo completar. Conservo la referencia anterior."
    return (result + "\n\nÚltimo intento: " + local_time(health.get("last_attempt")) +
            "\nÚltima revisión exitosa: " + local_time(health.get("last_ok")) +
            "\nHora de Argentina.\n\nProgramado cada 5 minutos; GitHub puede demorarse." +
            "\nLos avisos muestran materia y docente, sin la calificación.")


def process_commands(cfg, store, health):
    cursor = store.read() or {}
    offset = cursor.get("next_update", 0)
    if not isinstance(offset, int) or offset < 0:
        raise MonitorError("El cursor privado de Telegram no es válido.")
    updates = telegram_api(cfg, "getUpdates", {
        "offset": offset, "limit": 100, "timeout": 1, "allowed_updates": ["message"]})
    if not isinstance(updates, list):
        raise MonitorError("Telegram no devolvió una lista de mensajes válida.")
    requested = None
    next_update = offset
    for update in updates:
        if not isinstance(update, dict) or not isinstance(update.get("update_id"), int):
            raise MonitorError("Telegram devolvió un identificador de mensaje inválido.")
        if update["update_id"] < offset:
            continue
        next_update = max(next_update, update["update_id"] + 1)
        message = update.get("message") or {}
        chat = message.get("chat") or {}
        sender = message.get("from") or {}
        # Nunca responder a grupos, otros usuarios ni mensajes reenviados.
        if (chat.get("type") != "private" or str(chat.get("id")) != cfg.chat_id or
                str(sender.get("id")) != cfg.chat_id or sender.get("is_bot") or
                "forward_origin" in message):
            continue
        command = str(message.get("text", "")).strip().split(maxsplit=1)
        if command and command[0].split("@", 1)[0].lower() in ("/estado", "/start", "/ayuda"):
            requested = command[0].lower()
    if requested:
        telegram(cfg, status_message(health))
    # Solo IDs numéricos cifrados; nunca se guardan mensajes ni nombres de Telegram.
    if next_update != offset:
        store.write({"next_update": next_update})


def configure_commands(cfg):
    telegram_api(cfg, "setMyCommands", {"commands": [
        {"command": "estado", "description": "Ver la última revisión del colegio"},
        {"command": "ayuda", "description": "Ver cómo funciona el monitor"}],
        "scope": {"type": "chat", "chat_id": cfg.chat_id}})


def run_cycle(cfg, confirm=False, setup_commands=False, send_status=False, now=None):
    now = now or datetime.now(timezone.utc)
    health_store = EncryptedStore("health.enc", cfg.state_key)
    health = health_store.read() or {}
    error = None
    try:
        run_once(cfg, EncryptedStore("state.enc", cfg.state_key), confirm=confirm, now=now)
    except MonitorError as caught:
        error = caught
    health["last_attempt"] = now.isoformat()
    health["last_result"] = "error" if error else "ok"
    if not error:
        health["last_ok"] = now.isoformat()
    else:
        try:
            last = datetime.fromisoformat(health.get("last_error", "1970-01-01T00:00:00+00:00"))
            if now - last >= timedelta(hours=24):
                telegram(cfg, "⚠️ El monitor de notas necesita revisión. No pude completar una comprobación; conservé la referencia anterior. Revisá GitHub Actions.")
                health["last_error"] = now.isoformat()
        except Exception:
            pass
    health_store.write(health)
    try:
        if setup_commands:
            configure_commands(cfg)
        process_commands(cfg, EncryptedStore("commands.enc", cfg.state_key), health)
        if send_status:
            telegram(cfg, status_message(health))
    except MonitorError as caught:
        if error is None:
            error = caught
    if error:
        raise error


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", action="store_true", help="Envía una confirmación de conexión.")
    parser.add_argument("--setup-commands", action="store_true", help="Configura el menú del chat privado.")
    parser.add_argument("--send-status", action="store_true", help="Comprueba el envío del estado actual.")
    args = parser.parse_args()
    run_cycle(Config.from_env(), confirm=args.confirm, setup_commands=args.setup_commands,
              send_status=args.send_status)


if __name__ == "__main__":
    try:
        main()
    except MonitorError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("No se completó la revisión. Consultá la configuración privada y el estado de los servicios.", file=sys.stderr)
        sys.exit(1)
