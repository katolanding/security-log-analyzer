# Security Log Analyzer

[![Python Tests](https://github.com/katolanding/security-log-analyzer/actions/workflows/python-tests.yml/badge.svg)](https://github.com/katolanding/security-log-analyzer/actions/workflows/python-tests.yml)

Herramienta educativa en **Python** para analizar localmente registros de autenticación SSH (`sshd`). No requiere dependencias externas ni conexión a Internet.

## ¿Qué hace?

- Cuenta accesos SSH exitosos y fallidos.
- Agrupa intentos fallidos por dirección IP y usuario objetivo.
- Marca las IP que alcanzan un umbral de fallos configurable.
- Genera informes locales en JSON.

> **Alcance:** una IP marcada necesita investigación; alcanzar un umbral no demuestra actividad maliciosa. La herramienta no bloquea conexiones y no sustituye un SIEM.

## Demostración

Con Python 3.10 o superior, desde la raíz del repositorio:

```bash
python src/analyzer.py samples/auth.log --threshold 5
```

**Salida esperada con el archivo de ejemplo incluido:**

```text
Events: 7 | Failed: 6 | Successful: 1
Suspicious IPs (>= 5 failures):
  192.0.2.10: 5 failures
```

`192.0.2.10` pertenece a un rango reservado para documentación; los registros de `samples/auth.log` son ficticios.

### Exportar un informe JSON

```bash
python src/analyzer.py samples/auth.log --threshold 5 --json report.json
```

El archivo `report.json` contendrá los recuentos, las IP agrupadas y el umbral aplicado. No subas informes de producción ni registros con datos personales.

## Pruebas automatizadas

```bash
python -m unittest discover -s tests -v
```

El repositorio incluye **tres pruebas unitarias** y un flujo de GitHub Actions; la última ejecución consultada el **12 de noviembre de 2026** terminó correctamente. Consulta el estado vigente en la insignia superior.

## Estructura

```text
src/analyzer.py            Análisis de eventos y línea de comandos
tests/test_analyzer.py     Pruebas unitarias
samples/auth.log           Eventos ficticios de ejemplo
.github/workflows/         Integración continua
```

## Limitaciones y mejoras futuras

- Detección de patrones por intervalo de tiempo.
- Compatibilidad con otros formatos de registros.
- Visualización de tendencias sin exponer registros sensibles.

## Autoría y aprendizaje

Proyecto de portafolio con foco de aprendizaje en ciberseguridad.
