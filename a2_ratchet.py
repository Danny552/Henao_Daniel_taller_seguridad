"""A2. Double Ratchet reducido (6 mensajes, un solo proceso, sin red).

Versión simplificada del algoritmo Double Ratchet de Signal:
  * Trinquete de Diffie-Hellman (X25519): cada vez que cambia la dirección de
    la conversación se genera un nuevo par de claves y se renueva la clave raíz.
  * Trinquete simétrico: dentro de cada dirección, una cadena de claves
    (HMAC-SHA256) produce una clave de mensaje por mensaje.
  * Cifrado autenticado ChaCha20-Poly1305 con la cabecera como datos asociados.

Se usan solo primitivas estándar de `cryptography` y de la biblioteca estándar
de Python. No hay X3DH: el secreto inicial compartido se simula en memoria.
"""
import copy
import hmac
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAX_SALTO = 10  # máximo de mensajes perdidos que se toleran en una cadena


class MensajeRechazado(Exception):
    """El mensaje se rechaza: alterado, repetido, fuera de rango o inválido."""


@dataclass(frozen=True)
class Mensaje:
    dh: bytes        # clave pública X25519 del emisor (32 bytes)
    pn: int          # longitud de la cadena de envío anterior
    n: int           # número de mensaje en la cadena actual
    cifrado: bytes   # texto cifrado + etiqueta de autenticación

    def cabecera(self) -> bytes:
        return self.dh + self.pn.to_bytes(4, "big") + self.n.to_bytes(4, "big")


# ---------------------------------------------------------------- primitivas
def generar_par() -> tuple[bytes, bytes]:
    """Nuevo par X25519 como (privada, pública) en bytes crudos."""
    priv = X25519PrivateKey.generate()
    return (
        priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
        priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ),
    )


def dh(privada: bytes, publica: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(privada).exchange(
        X25519PublicKey.from_public_bytes(publica)
    )


def kdf_rk(rk: bytes, dh_salida: bytes) -> tuple[bytes, bytes]:
    """(clave raíz, salida DH) -> (nueva clave raíz, nueva clave de cadena)."""
    out = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=rk,
        info=b"taller-seguridad/a2/raiz",
    ).derive(dh_salida)
    return out[:32], out[32:]


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """clave de cadena -> (siguiente clave de cadena, clave de mensaje)."""
    return (
        hmac.new(ck, b"\x02", "sha256").digest(),
        hmac.new(ck, b"\x01", "sha256").digest(),
    )


def _clave_y_nonce(mk: bytes) -> tuple[bytes, bytes]:
    out = HKDF(
        algorithm=hashes.SHA256(), length=44, salt=None,
        info=b"taller-seguridad/a2/mensaje",
    ).derive(mk)
    return out[:32], out[32:]


def _cifrar(mk: bytes, texto: bytes, cabecera: bytes) -> bytes:
    clave, nonce = _clave_y_nonce(mk)
    return ChaCha20Poly1305(clave).encrypt(nonce, texto, cabecera)


def _descifrar(mk: bytes, mensaje: Mensaje) -> bytes:
    clave, nonce = _clave_y_nonce(mk)
    return ChaCha20Poly1305(clave).decrypt(nonce, mensaje.cifrado, mensaje.cabecera())


# ------------------------------------------------------------------- Ratchet
class Ratchet:
    """Un participante de la conversación.

    Iniciador (Alice): Ratchet(secreto, pub_remota=<pública inicial de Bob>)
    Receptor  (Bob):   Ratchet(secreto, par_local=<par inicial de Bob>)
    """

    def __init__(self, secreto_compartido: bytes, *, par_local=None, pub_remota=None):
        if len(secreto_compartido) != 32:
            raise ValueError("el secreto compartido debe tener 32 bytes")
        self.rk = secreto_compartido
        self.dhs_priv, self.dhs_pub = par_local if par_local else (None, None)
        self.dhr = pub_remota
        self.cks = None            # cadena de envío
        self.ckr = None            # cadena de recepción
        self.ns = 0                # mensajes enviados en la cadena actual
        self.nr = 0                # mensajes recibidos en la cadena actual
        self.pn = 0                # longitud de la cadena de envío anterior
        self.omitidas = {}         # (dh, n) -> clave de mensaje no usada aún
        self.debe_cambiar = False  # hay que renovar el par antes de enviar

    # -- estado (para simular el robo de estado en las pruebas) --
    def exportar_estado(self) -> dict:
        return copy.deepcopy(self.__dict__)

    @classmethod
    def desde_estado(cls, estado: dict) -> "Ratchet":
        r = cls.__new__(cls)
        r.__dict__.update(copy.deepcopy(estado))
        return r

    @property
    def clave_publica(self) -> bytes:
        return self.dhs_pub

    # -- cambio de dirección: nuevo par X25519 + nueva cadena de envío --
    def cambiar_direccion(self) -> None:
        if self.dhr is None:
            raise RuntimeError("no se conoce la clave pública del otro participante")
        self.pn = self.ns
        self.ns = 0
        self.dhs_priv, self.dhs_pub = generar_par()
        self.rk, self.cks = kdf_rk(self.rk, dh(self.dhs_priv, self.dhr))
        self.debe_cambiar = False

    def enviar(self, texto: str | bytes) -> Mensaje:
        if self.cks is None or self.debe_cambiar:
            self.cambiar_direccion()
        datos = texto.encode("utf-8") if isinstance(texto, str) else texto
        self.cks, mk = kdf_ck(self.cks)
        mensaje = Mensaje(self.dhs_pub, self.pn, self.ns, b"")
        self.ns += 1
        cifrado = _cifrar(mk, datos, mensaje.cabecera())
        return Mensaje(mensaje.dh, mensaje.pn, mensaje.n, cifrado)

    def recibir(self, mensaje: Mensaje) -> bytes:
        """Descifra un mensaje. Si falla, el estado queda como estaba."""
        respaldo = copy.deepcopy(self.__dict__)
        try:
            return self._recibir(mensaje)
        except (InvalidTag, ValueError, KeyError, TypeError) as error:
            self.__dict__.clear()
            self.__dict__.update(respaldo)
            raise MensajeRechazado(f"mensaje rechazado: {type(error).__name__}") from error
        except MensajeRechazado:
            self.__dict__.clear()
            self.__dict__.update(respaldo)
            raise

    def _recibir(self, m: Mensaje) -> bytes:
        guardada = self.omitidas.pop((m.dh, m.n), None)
        if guardada is not None:
            return _descifrar(guardada, m)
        if m.dh != self.dhr:
            self._omitir(m.pn)  # guarda claves pendientes de la cadena anterior
            self.rk, self.ckr = kdf_rk(self.rk, dh(self.dhs_priv, m.dh))
            self.dhr = m.dh
            self.nr = 0
            self.debe_cambiar = True
        if m.n < self.nr:
            raise MensajeRechazado("mensaje repetido o ya consumido")
        self._omitir(m.n)
        self.ckr, mk = kdf_ck(self.ckr)
        self.nr += 1
        return _descifrar(mk, m)

    def _omitir(self, hasta: int) -> None:
        if self.ckr is None:
            return
        if hasta - self.nr > MAX_SALTO:
            raise MensajeRechazado("demasiados mensajes omitidos")
        while self.nr < hasta:
            self.ckr, mk = kdf_ck(self.ckr)
            self.omitidas[(self.dhr, self.nr)] = mk
            self.nr += 1


def crear_sesion() -> tuple[Ratchet, Ratchet]:
    """Crea (alice, bob) en memoria con un secreto inicial simulado.

    Sustituye al acuerdo inicial X3DH de Signal, que está fuera del alcance.
    """
    secreto = os.urandom(32)
    par_bob = generar_par()
    alice = Ratchet(secreto, pub_remota=par_bob[1])
    bob = Ratchet(secreto, par_local=par_bob)
    return alice, bob
