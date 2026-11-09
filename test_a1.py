"""Pruebas de A1 (cadena de claves simétrica). Una función por fila de la tabla."""
import os

from a1_cadena import CadenaSimetrica, cifrar, derivar_clave, descifrar


def test_A1_01_determinismo(registrar):
    cadena = os.urandom(32)
    misma = derivar_clave(cadena, 5) == derivar_clave(cadena, 5)
    otra_cadena = derivar_clave(os.urandom(32), 5) != derivar_clave(cadena, 5)
    registrar("A1-01", "misma clave" if misma and otra_cadena else "claves distintas",
              "Además, otra cadena con el mismo índice da otra clave.")


def test_A1_02_unicidad(registrar):
    cadena = os.urandom(32)
    por_indice = {derivar_clave(cadena, i) for i in range(10)}
    c = CadenaSimetrica(cadena)
    por_cadena = set()
    for _ in range(10):
        _, k = c.siguiente()
        por_cadena.add(bytes(k))
        c.descartar(k)
    n = min(len(por_indice), len(por_cadena))
    registrar("A1-02", f"{n} claves distintas",
              "Se probó derivar_clave con índices 0-9 y la cadena que avanza.")


def test_A1_03_cifrado(registrar):
    cadena = os.urandom(32)
    emisor, receptor = CadenaSimetrica(cadena), CadenaSimetrica(cadena)
    correctos = 0
    for i in range(10):
        texto = f"mensaje de prueba {i} con acentos: ñandú"
        _, cifrado = emisor.cifrar_siguiente(texto)
        if receptor.descifrar_siguiente(cifrado).decode("utf-8") == texto:
            correctos += 1
    # Una clave equivocada no debe descifrar.
    try:
        descifrar(os.urandom(32), cifrado)
        clave_mala_acepta = True
    except Exception:
        clave_mala_acepta = False
    assert not clave_mala_acepta
    registrar("A1-03", f"{correctos}/10 correctos",
              "Emisor y receptor parten de la misma cadena; una clave ajena no descifra.")


def test_A1_04_borrado(registrar):
    c = CadenaSimetrica(os.urandom(32))
    _, clave = c.siguiente()
    copia_para_comparar = bytes(clave)   # solo la prueba conserva esta copia
    cifrado = cifrar(clave, "secreto")
    c.descartar(clave)
    borrada = all(b == 0 for b in clave)
    # Atacante con el estado actual de la cadena intenta recuperar la clave 0.
    estado = c.estado_actual()
    candidatos = {estado} | {derivar_clave(estado, i) for i in range(1000)}
    recuperada = copia_para_comparar in candidatos
    # Y no puede descifrar el mensaje viejo con ninguno de los candidatos.
    descifra = False
    for cand in candidatos:
        try:
            descifrar(cand, cifrado)
            descifra = True
        except Exception:
            pass
    resultado = "no recuperable" if borrada and not recuperada and not descifra else "recuperable"
    registrar("A1-04", resultado,
              "Buffer puesto en ceros; ni el estado de la cadena ni 1000 derivaciones lo recuperan.")
