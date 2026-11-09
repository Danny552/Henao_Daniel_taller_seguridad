# Taller individual: Seguridad en Messenger

Implementación simplificada (en memoria, sin red) de dos algoritmos de mensajería segura:

- **A1** `a1_cadena.py`: cadena de claves simétrica con HKDF y borrado de claves usadas.
- **A2** `a2_ratchet.py`: Double Ratchet reducido de 6 mensajes con X25519.

Se usa únicamente la biblioteca estándar `cryptography`; no hay criptografía implementada desde cero. No se usan datos reales de usuarios (Ley 1581 de 2012) ni se prueban aplicaciones o servicios de terceros.

## Requisitos

Python 3.11 o superior.

## Instalar dependencias y ejecutar las pruebas

```bash
python -m venv .venv
source .venv/bin/activate        # En Windows: .venv\Scripts\activate
pip install cryptography pytest
python -m pytest -q
```

Al terminar, las pruebas generan automáticamente `resultados.csv` y `log_pruebas.json` en esta carpeta.

## Contenido

| Archivo | Descripción |
|---|---|
| `ficha.md` | Ficha del concepto (E2EE y forward secrecy) |
| `a1_cadena.py`, `test_a1.py` | Algoritmo A1 y sus pruebas (A1-01 a A1-04) |
| `a2_ratchet.py`, `test_a2.py` | Algoritmo A2 y sus pruebas (A2-01 a A2-05) |
| `conftest.py` | Configuración de pytest: genera el CSV y el JSON al terminar |
| `resultados.csv`, `log_pruebas.json` | Resultados de la última ejecución |
| `informe.md` | Informe corto |

Las funciones de prueba se llaman `test_A1_01_...`, `test_A2_04_...`, etc.: el identificador de la tabla (`A2-04`) con guion bajo, porque Python no admite guiones en nombres de función.
