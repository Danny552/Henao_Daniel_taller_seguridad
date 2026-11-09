"""Registro de resultados: al terminar pytest escribe resultados.csv y log_pruebas.json."""
import csv
import json
import re
from pathlib import Path

import pytest

ENCABEZADO = ["id_prueba", "algoritmo", "propiedad", "descripcion",
              "esperado", "obtenido", "estado", "comentario"]

PLANTILLA = [
    ("A1-01", "A1", "determinismo", "Misma cadena e índice producen la misma clave", "misma clave"),
    ("A1-02", "A1", "unicidad", "10 claves de mensaje distintas", "10 claves distintas"),
    ("A1-03", "A1", "cifrado", "Cifrar y descifrar 10 mensajes", "10/10 correctos"),
    ("A1-04", "A1", "borrado", "Clave usada y luego borrada no se recupera", "no recuperable"),
    ("A2-01", "A2", "descifrado", "Descifrar los 6 mensajes", "6/6 correctos"),
    ("A2-02", "A2", "integridad", "Un byte alterado del ciphertext", "rechazado"),
    ("A2-03", "A2", "repetición", "Mensaje reenviado", "rechazado"),
    ("A2-04", "A2", "forward secrecy", "Estado robado tras mensaje 3 no descifra mensaje 1", "no descifrable"),
    ("A2-05", "A2", "post-compromise", "Estado robado antes del cambio de dirección no descifra tras él", "no descifrable"),
]
ESPERADO = {fila[0]: fila[4] for fila in PLANTILLA}
resultados: dict[str, dict] = {}


def id_desde_nombre(nombre: str):
    """'...test_A2_04_forward' -> 'A2-04' (None si no corresponde)."""
    m = re.search(r"test_(A\d)_(\d\d)", nombre)
    return f"{m.group(1)}-{m.group(2)}" if m else None


def _registrar(id_prueba: str, obtenido: str, comentario: str = "") -> None:
    """Guarda el resultado real y falla la prueba si no coincide con lo esperado."""
    esperado = ESPERADO[id_prueba]
    estado = "OK" if obtenido == esperado else "FALLA"
    resultados[id_prueba] = {"obtenido": obtenido, "estado": estado, "comentario": comentario}
    assert estado == "OK", f"{id_prueba}: esperado={esperado!r}, obtenido={obtenido!r}"


def registrar_error(id_prueba: str, detalle: str) -> None:
    resultados.setdefault(id_prueba, {
        "obtenido": "error en la prueba", "estado": "FALLA", "comentario": detalle})


def escribir_salidas(directorio) -> None:
    d = Path(directorio)
    with open(d / "resultados.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(ENCABEZADO)
        for id_, alg, prop, desc, esp in PLANTILLA:
            r = resultados.get(id_, {})
            w.writerow([id_, alg, prop, desc, esp, r.get("obtenido", ""),
                        r.get("estado", ""), r.get("comentario", "")])
    log = [{"prueba": id_, "esperado": ESPERADO[id_], "obtenido": r["obtenido"],
            "estado": r["estado"]}
           for id_, *_ in PLANTILLA if (r := resultados.get(id_))]
    with open(d / "log_pruebas.json", "w", encoding="utf-8") as f:
        json.dump(log, f, ensure_ascii=False, indent=2)
        f.write("\n")


@pytest.fixture
def registrar():
    return _registrar


def pytest_runtest_logreport(report):
    if report.failed:
        id_prueba = id_desde_nombre(report.nodeid)
        if id_prueba:
            registrar_error(id_prueba, f"excepción durante {report.when}")


def pytest_sessionfinish(session, exitstatus):
    escribir_salidas(Path(__file__).parent)
