"""Señal vacía a un supervisor externo; nunca envía notas ni registros."""
import os
import re
import sys
import time
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("Redirección rechazada")


def ping(url, opener=None, sleep=time.sleep):
    if not re.fullmatch(r"https://hc-ping\.com/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", url):
        raise ValueError("La dirección privada de supervisión no es válida.")
    opener = opener or build_opener(NoRedirect())
    for attempt in range(3):
        try:
            with opener.open(Request(url, data=b"", method="POST"), timeout=10) as response:
                if response.status != 200:
                    raise ValueError("Respuesta no confirmada")
                response.read(100)
            return
        except Exception:
            if attempt == 2:
                raise ValueError("El supervisor independiente no confirmó la señal.") from None
            sleep(2)


def main():
    url = os.environ.get("HEALTHCHECKS_PING_URL", "").strip()
    if not url:
        print("Supervisión independiente pendiente de configurar.")
        return
    ping(url)
    print("Supervisión independiente notificada.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("No se pudo confirmar la supervisión independiente.", file=sys.stderr)
        sys.exit(1)
