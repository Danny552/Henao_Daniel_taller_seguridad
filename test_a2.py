"""Pruebas de A2 (Double Ratchet reducido). Una función por fila de la tabla."""
from dataclasses import replace

from a2_ratchet import (Mensaje, MensajeRechazado, Ratchet, crear_sesion, dh,
                        kdf_ck, kdf_rk, _descifrar)

TEXTOS = [f"mensaje {i}" for i in range(1, 7)]


def escenario():
    """Alice envía 1-3, Bob responde 4-6 (un cambio de dirección).

    Devuelve los mensajes del canal y los estados robados en distintos momentos.
    """
    alice, bob = crear_sesion()
    s = {"alice": alice, "bob": bob, "msgs": [], "claros": []}
    s["bob_inicial"] = bob.exportar_estado()
    for t in TEXTOS[:3]:
        m = alice.enviar(t)
        s["msgs"].append(m)
        s["claros"].append(bob.recibir(m))
    s["bob_tras3"] = bob.exportar_estado()      # antes del cambio de dirección
    s["alice_tras3"] = alice.exportar_estado()
    for t in TEXTOS[3:]:
        m = bob.enviar(t)
        s["msgs"].append(m)
        s["claros"].append(alice.recibir(m))
    return s


def atacante_descifra(estado: dict, mensaje: Mensaje, ventana: int = 20) -> bool:
    """Intenta descifrar `mensaje` con un estado robado. True si lo logra."""
    try:                                   # 1) comportarse como el receptor
        Ratchet.desde_estado(estado).recibir(mensaje)
        return True
    except MensajeRechazado:
        pass
    candidatas = [estado[k] for k in ("cks", "ckr", "rk") if estado.get(k)]
    if estado.get("dhs_priv") and estado.get("dhr") is not None:
        rk2, ck2 = kdf_rk(estado["rk"], dh(estado["dhs_priv"], mensaje.dh))
        candidatas += [ck2, rk2]
    for ck in candidatas:                  # 2) probar cadenas hacia adelante
        for _ in range(ventana):
            ck, mk = kdf_ck(ck)
            for clave in (mk, ck):
                try:
                    _descifrar(clave, mensaje)
                    return True
                except Exception:
                    pass
    return False


def test_A2_01_descifrado(registrar):
    s = escenario()
    correctos = sum(1 for claro, t in zip(s["claros"], TEXTOS) if claro.decode() == t)
    nuevo_par = s["msgs"][3].dh != s["msgs"][2].dh   # m4 usa un par X25519 nuevo
    assert nuevo_par
    registrar("A2-01", f"{correctos}/6 correctos",
              "Cambio de dirección en el mensaje 4 con nuevo par X25519: True.")


def test_A2_02_integridad(registrar):
    alice, bob = crear_sesion()
    m = alice.enviar("mensaje íntegro")
    posicion = len(m.cifrado) // 2
    alterado = bytearray(m.cifrado)
    alterado[posicion] ^= 0x01                       # un solo byte cambiado
    rechazado = False
    try:
        bob.recibir(replace(m, cifrado=bytes(alterado)))
    except MensajeRechazado:
        rechazado = True
    cabecera_rechazada = False
    try:
        bob.recibir(replace(m, n=m.n + 1))           # cabecera alterada
    except MensajeRechazado:
        cabecera_rechazada = True
    original_ok = bob.recibir(m) == "mensaje íntegro".encode()  # el estado no se dañó
    resultado = "rechazado" if rechazado and cabecera_rechazada and original_ok else "aceptado"
    registrar("A2-02", resultado,
              "También se rechaza la cabecera alterada y el mensaje original sigue descifrando.")


def test_A2_03_repeticion(registrar):
    s = escenario()
    rechazos = 0
    for receptor, m in ((s["bob"], s["msgs"][0]), (s["alice"], s["msgs"][3])):
        try:
            receptor.recibir(m)        # reenvío de un mensaje ya consumido
        except MensajeRechazado:
            rechazos += 1
    registrar("A2-03", "rechazado" if rechazos == 2 else "aceptado",
              "Se reenviaron el mensaje 1 (a Bob) y el 4 (a Alice); ambos rechazados.")


def test_A2_04_forward_secrecy(registrar):
    s = escenario()
    m1, m2 = s["msgs"][0], s["msgs"][1]
    # Control: el atacante funciona si el estado es anterior al mensaje 1.
    assert atacante_descifra(s["bob_inicial"], m1)
    fallos = [not atacante_descifra(est, m)
              for est in (s["bob_tras3"], s["alice_tras3"]) for m in (m1, m2)]
    registrar("A2-04", "no descifrable" if all(fallos) else "descifrable",
              "Se robó el estado de Bob y de Alice tras el mensaje 3; control con estado previo sí descifra.")


def test_A2_05_post_compromise(registrar):
    s = escenario()
    posteriores = s["msgs"][3:]            # mensajes 4, 5 y 6
    # Control: el estado de Alice (que no genera la clave nueva) sí descifra el 4.
    control_alice = atacante_descifra(s["alice_tras3"], posteriores[0])
    fallos = [not atacante_descifra(s["bob_tras3"], m) for m in posteriores]
    registrar("A2-05", "no descifrable" if all(fallos) else "descifrable",
              "Estado de Bob robado antes de su cambio de dirección; no descifra los mensajes 4-6. "
              f"Control: el estado de Alice, que aún no renovó su par, sí descifra el 4: {control_alice}.")
