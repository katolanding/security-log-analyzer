# Security Log Analyzer

Herramienta educativa en Python para analizar registros de autenticación SSH (`sshd`) de forma local.

## Funciones

- Cuenta accesos SSH exitosos y fallidos.
- Agrupa intentos fallidos por dirección IP y nombre de usuario.
- Marca IPs con un número configurable de fallos.
- Exporta informes JSON.
- Funciona sin dependencias externas ni conexiones a Internet.

> **Alcance:** un umbral de fallos no demuestra que una dirección IP sea maliciosa. Solo genera una señal para revisión. No bloquea conexiones ni sustituye un SIEM.

## Requisitos

Python 3.10 o superior.

## Uso

```bash
python src/analyzer.py samples/auth.log --threshold 5
python src/analyzer.py samples/auth.log --threshold 3 --json report.json
```

## Pruebas

```bash
python -m unittest discover -s tests -v
```

## Estructura

```
src/analyzer.py         # Parser, estadísticas y CLI
tests/test_analyzer.py  # Pruebas unitarias
samples/auth.log        # Eventos ficticios, sin datos personales
```

## Privacidad

Los logs pueden incluir direcciones IP y nombres de usuario reales. No subas registros de producción a GitHub. Los datos de ejemplo utilizan direcciones reservadas para documentación (`192.0.2.0/24`, `198.51.100.0/24` y `203.0.113.0/24`).

## Próximas mejoras

- Detección de patrones temporales y eventos por hora.
- Compatibilidad con formatos adicionales de registro.
- Interfaz web y visualizaciones.

## Autoría

Proyecto de portafolio en desarrollo. Documenta las modificaciones que realices y comprende cada componente antes de presentarlo en entrevistas.
