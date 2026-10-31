# Avisos de calificaciones por Telegram

Monitor de una tabla anual de calificaciones de un portal ASP.NET, ejecutado en GitHub Actions. Informa la materia y el docente asociado, sin mostrar la calificación. No necesita Google Apps Script ni una computadora encendida.

## Datos privados

El repositorio solo contiene código genérico, pruebas con datos inventados y estado cifrado. Las credenciales, el destinatario y la dirección del portal se configuran en **Settings → Secrets and variables → Actions**:

| Secreto | Valor |
| --- | --- |
| PORTAL_URL | Dirección HTTPS de la tabla anual |
| AUSTRALIS_DOCUMENTO | Usuario del portal |
| AUSTRALIS_PASSWORD | Contraseña del portal |
| TELEGRAM_BOT_TOKEN | Clave del bot de Telegram |
| TELEGRAM_CHAT_ID | Identificador del chat privado autorizado |
| STATE_KEY | Clave Fernet aleatoria, generada una sola vez |
| INITIAL_STATE | Opcional: referencia previa exportada del monitor anterior, sin valores de notas |

No subir secretos como archivos, ni escribirlos en el código o los registros. La clave STATE_KEY debe conservarse: cambiarla sin volver a cifrar el estado impide leerlo. El estado guarda huellas de las notas; los archivos state.enc y health.enc se cifran con autenticación mediante Fernet. Las materias y docentes solo se leen en memoria y aparecen en el aviso privado que corresponde.

## Activación

1. Configurar los secretos en el repositorio del propietario. El proyecto no ejecuta código de pull requests ni eventos externos.
2. Ejecutar manualmente **Avisos de calificaciones**, con **confirm** activado. Debe terminar correctamente, enviar la confirmación privada y guardar state.enc.
3. Antes de desactivar un monitor anterior, comprobar esas tres cosas.
4. Crear la variable de repositorio **MONITOR_ENABLED=true**. Sin ella, las ejecuciones programadas quedan inactivas; las manuales siguen disponibles.

El activador solicita una revisión cada 5 minutos, a los minutos 2, 7, 12, etc. de cada hora. GitHub puede demorar o descartar ejecuciones programadas; no garantiza latencia ni disponibilidad. En repositorios públicos puede desactivar el cron por inactividad. El estado se renueva al menos una vez por semana para conservar actividad del repositorio; también conviene supervisar las ejecuciones. Para pausar, cambiar MONITOR_ENABLED a false o deshabilitar el workflow.

## Funcionamiento

Cada revisión inicia sesión en el portal, valida el ciclo actual en Buenos Aires y compara la tabla con la referencia cifrada. Una primera lectura sin referencia solo establece la base. Los avisos posteriores mencionan únicamente las materias y docentes que cambiaron. Los valores de las notas no se incluyen ni en Telegram ni en los registros de GitHub.

No se confirma quién realizó la carga: se informa el docente que figura en la fila del portal. Cambios en las materias o columnas detienen la actualización para revisión. Guion, vacío y S/C se consideran pendientes equivalentes. También se detectan correcciones o retiros de notas.

Si falla el portal o Telegram, no avanza la referencia de notas. Se intenta enviar un aviso de error por Telegram una vez cada 24 horas; los fallos también quedan en Actions. Si el envío fue aceptado pero falla su respuesta o el guardado posterior en GitHub, podría repetirse un aviso. Las revisiones concurrentes se serializan.

Las ejecuciones estándar de Actions en repositorios públicos son gratuitas; los privados tienen una cuota de cómputo y almacenamiento. No habilitar cargos adicionales sin revisar el presupuesto. No se publican artefactos con datos ni se utiliza caché para almacenar la referencia.

## Pruebas

`python -m pip install -r requirements.txt`

`python -m unittest discover -s tests -v`

Referencias: [Programación en GitHub](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule), [costos](https://docs.github.com/en/billing/concepts/product-billing/github-actions), [Fernet](https://cryptography.io/en/latest/fernet/).
