# PHP2Shell — Defensive Vulnerability Assessment

**Grupo Oruss / División 81** · Python 3.9+ · MIT · Sin dependencias externas

Herramienta de **inventario y priorización preventiva** para las alertas **CVE-2026-109618** y **CVE-2026-109619** (dos vulnerabilidades de PHP, CVSS v4.0 9.2). No ejecuta exploits, no envía payloads RCE, no prueba intrusión, no modifica servidores y no hace fuerza bruta.

> **Estado inicial (21 de octubre de 2026, antes de las 14:00 UTC):** PHP ha anunciado las correcciones, pero **todavía no ha publicado oficialmente la matriz de versiones afectadas/corregidas**. Por diseño, `advisory.json` comienza sin umbrales. Cualquier herramienta que asegure por ahora que una versión concreta es explotable excede la evidencia publicada por el fabricante. **Actualizar esta matriz tras la publicación oficial**.

## Funcionalidades

- **HTTP autorizado**: una o varias URLs, solicitudes `HEAD` y, si no hay indicador PHP, `GET` sin inspeccionar el cuerpo; detecta versiones PHP explícitas en encabezados HTTP.
- **Local**: detecta versiones instaladas del PHP CLI en ubicaciones habituales; **el CLI puede diferir de PHP-FPM, Apache, contenedores o paneles**.
- **Inventario externo autenticado**: importa un CSV con las columnas `asset`, `php_version` y opcionalmente `distro_package`, `notes`.
- **Clasificación conservadora**: `EOL_UNSUPPORTED`, `PENDING_VENDOR_MATRIX`, `NO_VERSION_OBSERVED`, `BELOW_OFFICIAL_FIX`, `MEETS_UPSTREAM_VERSION` y otros.
- **Exportación** a CSV (compatible con Excel) y JSON para informes técnicos o incorporación a pipelines de verificación.
- Sin API keys ni bibliotecas de terceros.

## Ejecución en Windows / GitHub Desktop

Abrir PowerShell en la carpeta del repositorio. Se necesita Python 3.9 o posterior.

```powershell
py -3 php2shell_assess.py --url https://app-cliente-autorizada.example/ --out reports/cliente-01
py -3 php2shell_assess.py --urls-file examples/targets.txt --out reports/lote-qa
py -3 php2shell_assess.py --inventory-csv examples/inventory.csv --out reports/inventario
py -3 php2shell_assess.py --local --out reports/equipo-local
py -3 php2shell_assess.py --php-version 8.4.26 --asset servidor-qa --out reports/servidor-qa
py -3 -m unittest discover -s tests -v
```

En Linux/macOS sustituir `py -3` por `python3`.

**Advertencia**: las URLs en `examples/targets.txt` y `examples/inventory.csv` son ficticias; sustituirlas solo por activos con autorización. Antes de la ejecución de muestras HTTP se deben reemplazar los destinos de ejemplo.

## Cómo funciona la clasificación

| Estado | Interpretación |
|---|---|
| `EOL_UNSUPPORTED` | Rama fuera de soporte upstream (PHP 8.1 o anterior); requiere migración y revisión de soporte de terceros. No confirma esos CVE. |
| `PENDING_VENDOR_MATRIX` | PHP 8.2–8.5 observado, pendientes rangos exactos o publicación validada de la matriz. No confirma vulnerabilidad. |
| `NO_VERSION_OBSERVED` | HTTP no reveló versión; **no significa que no se ejecute PHP**. |
| `BELOW_OFFICIAL_FIX` | Versión upstream debajo del corte **solo cuando** `advisory.json` dispone de umbrales oficiales verificados. Revisar backports. |
| `MEETS_UPSTREAM_VERSION` | Igual o superior al umbral upstream configurado; verificar versión real del runtime e integridad del paquete. **No significa “100 % seguro”**. |
| `PROBE_ERROR` / `INPUT_ERROR` | No se ha podido completar la comprobación; revisar error. |

La versión del servidor puede ocultarse, falsificarse o ser la de un proxy; los productos WordPress, Drupal, Joomla o Laravel **no bastan para determinar la versión efectiva de PHP**. Las pruebas deben contrastarse con el inventario del servidor, contenedor o panel del proveedor.

## Actualización tras la publicación del fabricante

1. Revisar la página oficial PHP y el anuncio de seguridad de cada rama; no usar versiones difundidas en redes como prueba suficiente.
2. Editar `advisory.json`: cambiar `release_status` a `"published"` e introducir los umbrales oficiales en `minimum_fixed_versions` solo para ramas verificadas, por ejemplo: `"8.4": "8.4.XX"` (**sustituir XX por la versión publicada oficialmente; no copiar literalmente**).
3. Rellenar `vendor_fix_reference` con el URL HTTPS oficial de las correcciones.
4. Volver a ejecutar contra el inventario o los servicios. Comprobar **backports de distribuciones** y que los procesos activos se hayan reiniciado tras la actualización.
5. Si una versión se muestra corregida por un backport, documentar la evidencia de ese paquete en `distro_package`/`notes` y verificar con el proveedor; el script no da por seguros automáticamente los paquetes backporteados.

La clasificación por cortes **no equivale a una prueba de explotación ni confirma que cada producto resulte alcanzable remotamente**. Si el proveedor identifica condiciones adicionales por SAPI, módulo, configuración o plataforma, es preciso aplicar esos criterios aparte antes de afirmar exposición.

## Seguridad y alcance

- Utilizar únicamente en activos propios o autorizados. `HEAD`/`GET`, sin autenticación, sin formularios ni pruebas de explotación.
- Limita la ejecución a 2000 URLs por lote, incorpora pausa (`--delay`) y timeout (`--timeout`).
- Sigue redirecciones únicamente dentro del **mismo hostname**; no inspecciona el cuerpo HTTP.
- Certificados TLS se validan por defecto. `--insecure` solo para entornos controlados en que se acepte expresamente este riesgo.
- El control de versiones en Git **no debe contener inventarios de clientes ni informes**. La carpeta `reports/` se excluye con `.gitignore`.
- Considerar protección de la información al transferir resultados y durante la notificación a clientes.

## Fuentes primarias

- [Anuncio del equipo PHP — 20 oct 2026](https://www.php.net/archive/2026.php#2026-10-20-1)
- [PHP: ramas soportadas](https://www.php.net/supported-versions.php)
- [PHP: fin de vida (EOL)](https://www.php.net/eol.php)
- [CERT-EU, aviso 2026-018](https://www.cert.europa.eu/publications/security-advisories/2026-018/)

## Publicación mediante GitHub Desktop

1. Extraer la carpeta `php2shell-assessment` (no publicar el ZIP dentro del repositorio).
2. En **GitHub Desktop → File → Add local repository → Choose**, seleccionar la carpeta. Si no existe `.git`, elegir **Create a repository**.
3. Verificar `.gitignore`, `advisory.json`, script, tests y README.
4. `Commit to main` → `Publish repository`. Elegir **Private** inicialmente si todavía está pendiente una revisión interna.
5. No activar una campaña pública hasta contrastar la matriz oficial y comprobar el funcionamiento con activos de prueba.

## Licencia

MIT © 2026 Grupo Oruss. Herramienta defensiva; se proporciona sin garantía.
